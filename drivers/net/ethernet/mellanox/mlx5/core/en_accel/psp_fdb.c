// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

/* PSP decryption in the FDB, for "psp decap mode tunnel" tc rules on the
 * uplink (en/tc/act/psp.c) and for tc rules with flower PSP matches.
 *
 * While there are such rules, PSP packets from the uplink are decrypted
 * before the tc tables, the same way as eswitch IPsec:
 *
 *   decrypt table (FDB_CRYPTO_INGRESS, level 0)
 *     from uplink, UDP dport 1000 -> CRYPTO_DECRYPT, check table
 *     miss                        -> tc chain 0
 *   check table (level 1)
 *     psp_syndrome OK             -> count, tc chain 0
 *     psp_syndrome ICV_FAIL       -> count, drop
 *     anything else               -> count, drop
 *
 * The device derives the key from the SPI, so there is one decrypt rule
 * for all associations. The tc rule then removes the outer headers and
 * trailer (DEL_PSP_TUNNEL) and forwards.
 *
 * tc rules can also match the SPI and the version ("flower psp_spi",
 * "psp_ver"): the device parses the PSP header into misc_parameters_6.
 * It does so whether or not the packet was decrypted, so these rules hold
 * the decryption tables too.
 */

#include "fs_core.h"
#include "eswitch.h"
#include "lib/fs_chains.h"
#include "en.h"
#include "en_rep.h"
#include "en_accel/psp.h"

enum {
	MLX5E_PSP_FDB_RX_FT_LEVEL,
	MLX5E_PSP_FDB_RX_CHK_FT_LEVEL,
};

/* In FDB_CRYPTO_EGRESS, next to the IPsec Tx tables. The host Tx table
 * forwards to the Tx counting table, which must be at a higher level.
 */
enum {
	MLX5E_PSP_FDB_HOST_TX_FT_LEVEL,
	MLX5E_PSP_FDB_TX_FT_LEVEL,
};

enum {
	MLX5E_PSP_SYNDROME_OK = 0,
	MLX5E_PSP_SYNDROME_ICV_FAIL = 1,
};

struct mlx5e_psp_fdb_rx {
	refcount_t refcnt;
	struct mlx5_flow_table *pass_ft;	/* tc chain 0, prio 1 */

	struct mlx5_flow_table *ft;
	struct mlx5_flow_group *miss_group;
	struct mlx5_flow_handle *miss_rule;
	struct mlx5_flow_handle *rule;

	struct mlx5_flow_table *chk_ft;
	struct mlx5_flow_group *chk_miss_group;
	struct mlx5_flow_handle *chk_miss_rule;
	struct mlx5_flow_handle *ok_rule;
	struct mlx5_flow_handle *auth_fail_rule;

	struct mlx5_fc *ok_counter;
	struct mlx5_fc *auth_fail_counter;
	struct mlx5_fc *bad_counter;
};

static struct mlx5_flow_table *
psp_fdb_ft_create(struct mlx5_flow_namespace *ns, int prio, int level)
{
	struct mlx5_flow_table_attr ft_attr = {};

	ft_attr.max_fte = 4;
	ft_attr.level = level;
	ft_attr.prio = prio;
	ft_attr.autogroup.num_reserved_entries = 1;
	ft_attr.autogroup.max_num_groups = 2;
	return mlx5_create_auto_grouped_flow_table(ns, &ft_attr);
}

/* A catch-all rule in the reserved last entry of an auto grouped table */
static int psp_fdb_miss_create(struct mlx5_flow_table *ft,
			       struct mlx5_flow_act *flow_act,
			       struct mlx5_flow_destination *dest, int num_dest,
			       struct mlx5_flow_group **group,
			       struct mlx5_flow_handle **rule)
{
	int inlen = MLX5_ST_SZ_BYTES(create_flow_group_in);
	struct mlx5_flow_spec *spec;
	u32 *flow_group_in;
	int err = 0;

	flow_group_in = kvzalloc(inlen, GFP_KERNEL);
	spec = kvzalloc_obj(*spec);
	if (!flow_group_in || !spec) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(create_flow_group_in, flow_group_in, start_flow_index,
		 ft->max_fte - 1);
	MLX5_SET(create_flow_group_in, flow_group_in, end_flow_index,
		 ft->max_fte - 1);
	*group = mlx5_create_flow_group(ft, flow_group_in);
	if (IS_ERR(*group)) {
		err = PTR_ERR(*group);
		goto out;
	}

	*rule = mlx5_add_flow_rules(ft, spec, flow_act, dest, num_dest);
	if (IS_ERR(*rule)) {
		err = PTR_ERR(*rule);
		mlx5_destroy_flow_group(*group);
	}
out:
	kvfree(flow_group_in);
	kvfree(spec);
	return err;
}

static void psp_fdb_syndrome_match(struct mlx5_flow_spec *spec, u8 syndrome)
{
	spec->match_criteria_enable |= MLX5_MATCH_MISC_PARAMETERS_2;
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria,
			 misc_parameters_2.psp_syndrome);
	MLX5_SET(fte_match_param, spec->match_value,
		 misc_parameters_2.psp_syndrome, syndrome);
}

static void psp_fdb_rx_destroy(struct mlx5_eswitch *esw,
			       struct mlx5e_psp_fdb_rx *rx)
{
	struct mlx5_core_dev *mdev = esw->dev;

	if (!IS_ERR_OR_NULL(rx->rule))
		mlx5_del_flow_rules(rx->rule);
	/* The check table goes first: without the decrypt table it would be
	 * the FDB root.
	 */
	if (!IS_ERR_OR_NULL(rx->auth_fail_rule))
		mlx5_del_flow_rules(rx->auth_fail_rule);
	if (!IS_ERR_OR_NULL(rx->ok_rule))
		mlx5_del_flow_rules(rx->ok_rule);
	if (!IS_ERR_OR_NULL(rx->chk_miss_rule)) {
		mlx5_del_flow_rules(rx->chk_miss_rule);
		mlx5_destroy_flow_group(rx->chk_miss_group);
	}
	if (!IS_ERR_OR_NULL(rx->chk_ft))
		mlx5_destroy_flow_table(rx->chk_ft);

	if (!IS_ERR_OR_NULL(rx->miss_rule)) {
		mlx5_del_flow_rules(rx->miss_rule);
		mlx5_destroy_flow_group(rx->miss_group);
	}
	if (!IS_ERR_OR_NULL(rx->ft))
		mlx5_destroy_flow_table(rx->ft);

	if (!IS_ERR_OR_NULL(rx->bad_counter))
		mlx5_fc_destroy(mdev, rx->bad_counter);
	if (!IS_ERR_OR_NULL(rx->auth_fail_counter))
		mlx5_fc_destroy(mdev, rx->auth_fail_counter);
	if (!IS_ERR_OR_NULL(rx->ok_counter))
		mlx5_fc_destroy(mdev, rx->ok_counter);

	if (!IS_ERR_OR_NULL(rx->pass_ft))
		mlx5_chains_put_table(esw_chains(esw), 0, 1, 0);

	kfree(rx);
}

static struct mlx5e_psp_fdb_rx *psp_fdb_rx_create(struct mlx5_eswitch *esw)
{
	struct mlx5_core_dev *mdev = esw->dev;
	struct mlx5_flow_destination dest[2] = {};
	struct mlx5_flow_namespace *ns;
	struct mlx5_flow_act flow_act;
	struct mlx5e_psp_fdb_rx *rx;
	struct mlx5_flow_spec *spec;
	int err;

	ns = mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_FDB);
	if (!ns)
		return ERR_PTR(-EOPNOTSUPP);

	rx = kzalloc_obj(*rx);
	spec = kvzalloc_obj(*spec);
	if (!rx || !spec) {
		kfree(rx);
		kvfree(spec);
		return ERR_PTR(-ENOMEM);
	}
	refcount_set(&rx->refcnt, 1);

	rx->pass_ft = mlx5_chains_get_table(esw_chains(esw), 0, 1, 0);
	if (IS_ERR(rx->pass_ft)) {
		err = PTR_ERR(rx->pass_ft);
		goto err;
	}

	rx->ok_counter = mlx5_fc_create(mdev, false);
	if (IS_ERR(rx->ok_counter)) {
		err = PTR_ERR(rx->ok_counter);
		goto err;
	}
	rx->auth_fail_counter = mlx5_fc_create(mdev, false);
	if (IS_ERR(rx->auth_fail_counter)) {
		err = PTR_ERR(rx->auth_fail_counter);
		goto err;
	}
	rx->bad_counter = mlx5_fc_create(mdev, false);
	if (IS_ERR(rx->bad_counter)) {
		err = PTR_ERR(rx->bad_counter);
		goto err;
	}

	/* The decrypt table becomes the FDB root. It must exist before the
	 * check table, which would otherwise be the root and drop everything,
	 * and the decrypt rule comes last.
	 */
	rx->ft = psp_fdb_ft_create(ns, FDB_CRYPTO_INGRESS,
				   MLX5E_PSP_FDB_RX_FT_LEVEL);
	if (IS_ERR(rx->ft)) {
		err = PTR_ERR(rx->ft);
		goto err;
	}

	memset(&flow_act, 0, sizeof(flow_act));
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	dest[0].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest[0].ft = rx->pass_ft;
	err = psp_fdb_miss_create(rx->ft, &flow_act, dest, 1,
				  &rx->miss_group, &rx->miss_rule);
	if (err)
		goto err;

	/* Check table */
	rx->chk_ft = psp_fdb_ft_create(ns, FDB_CRYPTO_INGRESS,
				       MLX5E_PSP_FDB_RX_CHK_FT_LEVEL);
	if (IS_ERR(rx->chk_ft)) {
		err = PTR_ERR(rx->chk_ft);
		goto err;
	}

	memset(&flow_act, 0, sizeof(flow_act));
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_DROP |
			  MLX5_FLOW_CONTEXT_ACTION_COUNT;
	dest[0].type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
	dest[0].counter = rx->bad_counter;
	err = psp_fdb_miss_create(rx->chk_ft, &flow_act, dest, 1,
				  &rx->chk_miss_group, &rx->chk_miss_rule);
	if (err)
		goto err;

	memset(spec, 0, sizeof(*spec));
	psp_fdb_syndrome_match(spec, MLX5E_PSP_SYNDROME_OK);
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
			  MLX5_FLOW_CONTEXT_ACTION_COUNT;
	dest[0].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest[0].ft = rx->pass_ft;
	dest[1].type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
	dest[1].counter = rx->ok_counter;
	rx->ok_rule = mlx5_add_flow_rules(rx->chk_ft, spec, &flow_act, dest, 2);
	if (IS_ERR(rx->ok_rule)) {
		err = PTR_ERR(rx->ok_rule);
		goto err;
	}

	memset(spec, 0, sizeof(*spec));
	psp_fdb_syndrome_match(spec, MLX5E_PSP_SYNDROME_ICV_FAIL);
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_DROP |
			  MLX5_FLOW_CONTEXT_ACTION_COUNT;
	dest[0].type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
	dest[0].counter = rx->auth_fail_counter;
	rx->auth_fail_rule = mlx5_add_flow_rules(rx->chk_ft, spec, &flow_act,
						 dest, 1);
	if (IS_ERR(rx->auth_fail_rule)) {
		err = PTR_ERR(rx->auth_fail_rule);
		goto err;
	}

	memset(spec, 0, sizeof(*spec));
	mlx5_esw_set_spec_source_port(esw, MLX5_VPORT_UPLINK, spec);
	spec->match_criteria_enable |= MLX5_MATCH_OUTER_HEADERS;
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria,
			 outer_headers.ip_protocol);
	MLX5_SET(fte_match_param, spec->match_value,
		 outer_headers.ip_protocol, IPPROTO_UDP);
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria,
			 outer_headers.udp_dport);
	MLX5_SET(fte_match_param, spec->match_value,
		 outer_headers.udp_dport, PSP_DEFAULT_UDP_PORT);
	if (MLX5_CAP_ESW_FLOWTABLE(mdev, flow_source))
		spec->flow_context.flow_source =
			MLX5_FLOW_CONTEXT_FLOW_SOURCE_UPLINK;

	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_CRYPTO_DECRYPT |
			  MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	flow_act.crypto.type = MLX5_FLOW_CONTEXT_ENCRYPT_DECRYPT_TYPE_PSP;
	dest[0].type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest[0].ft = rx->chk_ft;
	rx->rule = mlx5_add_flow_rules(rx->ft, spec, &flow_act, dest, 1);
	if (IS_ERR(rx->rule)) {
		err = PTR_ERR(rx->rule);
		goto err;
	}

	kvfree(spec);
	return rx;

err:
	mlx5_core_warn(mdev, "Failed to create PSP FDB Rx tables: %d\n", err);
	kvfree(spec);
	psp_fdb_rx_destroy(esw, rx);
	return ERR_PTR(err);
}

/* Take a reference on the FDB decryption tables, creating them if needed.
 * priv is the uplink's.
 */
int mlx5e_psp_fdb_rx_get(struct mlx5e_priv *priv)
{
	struct mlx5e_psp *psp = priv->psp;
	struct mlx5e_psp_fdb_rx *rx;
	int err = 0;

	if (!psp)
		return -EOPNOTSUPP;

	mutex_lock(&psp->fdb_rx_lock);
	if (psp->fdb_rx) {
		refcount_inc(&psp->fdb_rx->refcnt);
		goto out;
	}

	rx = psp_fdb_rx_create(priv->mdev->priv.eswitch);
	if (IS_ERR(rx))
		err = PTR_ERR(rx);
	else
		psp->fdb_rx = rx;
out:
	mutex_unlock(&psp->fdb_rx_lock);
	return err;
}

static void psp_fdb_rx_add_stats(struct mlx5_core_dev *mdev,
				 struct mlx5e_psp_fdb_rx *rx,
				 struct mlx5e_psp_stats *stats)
{
	u64 pkts, bytes;

	if (!mlx5_fc_query(mdev, rx->ok_counter, &pkts, &bytes)) {
		stats->psp_rx_pkts += pkts;
		stats->psp_rx_bytes += bytes;
	}
	if (!mlx5_fc_query(mdev, rx->auth_fail_counter, &pkts, &bytes)) {
		stats->psp_rx_pkts_auth_fail += pkts;
		stats->psp_rx_bytes_auth_fail += bytes;
	}
	if (!mlx5_fc_query(mdev, rx->bad_counter, &pkts, &bytes)) {
		stats->psp_rx_pkts_drop += pkts;
		stats->psp_rx_bytes_drop += bytes;
	}
}

void mlx5e_psp_fdb_rx_put(struct mlx5e_priv *priv)
{
	struct mlx5e_psp *psp = priv->psp;

	mutex_lock(&psp->fdb_rx_lock);
	if (refcount_dec_and_test(&psp->fdb_rx->refcnt)) {
		/* The device stats must not go back to zero */
		psp_fdb_rx_add_stats(priv->mdev, psp->fdb_rx,
				     &psp->fdb_rx_stats);
		psp_fdb_rx_destroy(priv->mdev->priv.eswitch, psp->fdb_rx);
		psp->fdb_rx = NULL;
	}
	mutex_unlock(&psp->fdb_rx_lock);
}

/* PSP Tx counting: tc encap rules (en/tc/act/psp.c) encrypt and add the PSP
 * tunnel, then forward here instead of to the uplink, so that the device
 * counts what it encrypted, as the check table counts what it decrypted:
 *
 *   tx table (FDB_CRYPTO_EGRESS)
 *     any -> count, uplink
 */
struct mlx5e_psp_fdb_tx {
	refcount_t refcnt;
	struct mlx5_flow_table *ft;
	struct mlx5_flow_group *group;
	struct mlx5_flow_handle *rule;
	struct mlx5_fc *counter;
};

static void psp_fdb_tx_destroy(struct mlx5_core_dev *mdev,
			       struct mlx5e_psp_fdb_tx *tx)
{
	if (!IS_ERR_OR_NULL(tx->rule)) {
		mlx5_del_flow_rules(tx->rule);
		mlx5_destroy_flow_group(tx->group);
	}
	if (!IS_ERR_OR_NULL(tx->ft))
		mlx5_destroy_flow_table(tx->ft);
	if (!IS_ERR_OR_NULL(tx->counter))
		mlx5_fc_destroy(mdev, tx->counter);
	kfree(tx);
}

static struct mlx5e_psp_fdb_tx *psp_fdb_tx_create(struct mlx5_eswitch *esw)
{
	struct mlx5_core_dev *mdev = esw->dev;
	struct mlx5_flow_destination dest[2] = {};
	struct mlx5_flow_act flow_act = {};
	struct mlx5_flow_namespace *ns;
	struct mlx5e_psp_fdb_tx *tx;
	int err;

	ns = mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_FDB);
	if (!ns)
		return ERR_PTR(-EOPNOTSUPP);

	tx = kzalloc_obj(*tx);
	if (!tx)
		return ERR_PTR(-ENOMEM);
	refcount_set(&tx->refcnt, 1);

	tx->counter = mlx5_fc_create(mdev, false);
	if (IS_ERR(tx->counter)) {
		err = PTR_ERR(tx->counter);
		goto err;
	}

	tx->ft = psp_fdb_ft_create(ns, FDB_CRYPTO_EGRESS,
				   MLX5E_PSP_FDB_TX_FT_LEVEL);
	if (IS_ERR(tx->ft)) {
		err = PTR_ERR(tx->ft);
		goto err;
	}

	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
			  MLX5_FLOW_CONTEXT_ACTION_COUNT;
	dest[0].type = MLX5_FLOW_DESTINATION_TYPE_VPORT;
	dest[0].vport.num = MLX5_VPORT_UPLINK;
	if (MLX5_CAP_ESW(mdev, merged_eswitch)) {
		dest[0].vport.vhca_id = MLX5_CAP_GEN(mdev, vhca_id);
		dest[0].vport.flags |= MLX5_FLOW_DEST_VPORT_VHCA_ID;
	}
	dest[1].type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
	dest[1].counter = tx->counter;
	err = psp_fdb_miss_create(tx->ft, &flow_act, dest, 2,
				  &tx->group, &tx->rule);
	if (err)
		goto err;

	return tx;

err:
	mlx5_core_warn(mdev, "Failed to create PSP FDB Tx table: %d\n", err);
	psp_fdb_tx_destroy(mdev, tx);
	return ERR_PTR(err);
}

static void psp_fdb_tx_add_stats(struct mlx5_core_dev *mdev,
				 struct mlx5e_psp_fdb_tx *tx,
				 struct mlx5e_psp_stats *stats)
{
	u64 pkts, bytes;

	if (!mlx5_fc_query(mdev, tx->counter, &pkts, &bytes)) {
		stats->psp_tx_pkts += pkts;
		stats->psp_tx_bytes += bytes;
	}
}

/* Take a reference on the FDB Tx counting table, creating it if needed, and
 * return it for a tc encap rule to forward to. priv is the uplink's.
 */
struct mlx5_flow_table *mlx5e_psp_fdb_tx_get(struct mlx5e_priv *priv)
{
	struct mlx5e_psp *psp = priv->psp;
	struct mlx5e_psp_fdb_tx *tx;
	struct mlx5_flow_table *ft;

	if (!psp)
		return ERR_PTR(-EOPNOTSUPP);

	mutex_lock(&psp->fdb_rx_lock);
	tx = psp->fdb_tx;
	if (tx) {
		refcount_inc(&tx->refcnt);
	} else {
		tx = psp_fdb_tx_create(priv->mdev->priv.eswitch);
		if (IS_ERR(tx)) {
			ft = ERR_CAST(tx);
			goto out;
		}
		psp->fdb_tx = tx;
	}
	ft = tx->ft;
out:
	mutex_unlock(&psp->fdb_rx_lock);
	return ft;
}

void mlx5e_psp_fdb_tx_put(struct mlx5e_priv *priv)
{
	struct mlx5e_psp *psp = priv->psp;

	mutex_lock(&psp->fdb_rx_lock);
	if (refcount_dec_and_test(&psp->fdb_tx->refcnt)) {
		/* The device stats must not go back to zero */
		psp_fdb_tx_add_stats(priv->mdev, psp->fdb_tx,
				     &psp->fdb_rx_stats);
		psp_fdb_tx_destroy(priv->mdev, psp->fdb_tx);
		psp->fdb_tx = NULL;
	}
	mutex_unlock(&psp->fdb_rx_lock);
}

/* Host PSP Tx in switchdev mode, the FDB counterpart of the NIC Tx table of
 * legacy mode. Like eswitch IPsec, the uplink representor's send-to-vport rule
 * forwards here (eswitch_offloads.c). For a PSP packet the driver has already
 * inserted the UDP + PSP headers and put the key object id, never 0, in the
 * WQE metadata, which CRYPTO_ENCRYPT without an object id uses, as in NIC
 * mode. The FDB can't match the metadata (metadata_reg_a), so like the NIC
 * Tx table this matches UDP dport 1000. Everything else goes on to the
 * eswitch IPsec Tx tables, if there are any, or to the uplink:
 *
 *   host tx table (FDB_CRYPTO_EGRESS)
 *     UDP dport 1000 -> encrypt, tx counting table
 *     miss           -> the IPsec Tx policy table, or the uplink
 */
struct mlx5e_psp_fdb_host_tx {
	struct mlx5_flow_table *ft;
	struct mlx5_flow_group *miss_group;
	struct mlx5_flow_handle *miss_rule;
	struct mlx5_flow_handle *rule;
	struct mlx5_flow_table *tx_ft;	/* referenced */
	struct mlx5_flow_destination next;
};

static void psp_fdb_host_tx_next(struct mlx5_eswitch *esw,
				 struct mlx5_flow_destination *dest)
{
	struct mlx5_core_dev *mdev = esw->dev;

	memset(dest, 0, sizeof(*dest));
	if (esw->offloads.ft_ipsec_tx_pol) {
		dest->type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
		dest->ft = esw->offloads.ft_ipsec_tx_pol;
		return;
	}
	dest->type = MLX5_FLOW_DESTINATION_TYPE_VPORT;
	dest->vport.num = MLX5_VPORT_UPLINK;
	if (MLX5_CAP_ESW(mdev, merged_eswitch)) {
		dest->vport.vhca_id = MLX5_CAP_GEN(mdev, vhca_id);
		dest->vport.flags |= MLX5_FLOW_DEST_VPORT_VHCA_ID;
	}
}

static void psp_fdb_host_tx_free(struct mlx5e_priv *priv,
				 struct mlx5e_psp_fdb_host_tx *htx)
{
	if (!IS_ERR_OR_NULL(htx->rule))
		mlx5_del_flow_rules(htx->rule);
	if (!IS_ERR_OR_NULL(htx->miss_rule)) {
		mlx5_del_flow_rules(htx->miss_rule);
		mlx5_destroy_flow_group(htx->miss_group);
	}
	if (!IS_ERR_OR_NULL(htx->ft))
		mlx5_destroy_flow_table(htx->ft);
	if (!IS_ERR_OR_NULL(htx->tx_ft))
		mlx5e_psp_fdb_tx_put(priv);
	kfree(htx);
}

/* priv is the uplink's. Called before its send queues exist. */
int mlx5e_psp_fdb_host_tx_create(struct mlx5e_priv *priv)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_flow_destination dest = {};
	struct mlx5_flow_act flow_act = {};
	struct mlx5e_psp_fdb_host_tx *htx;
	struct mlx5_flow_namespace *ns;
	struct mlx5_flow_spec *spec;
	int err;

	ns = mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_FDB);
	if (!ns)
		return -EOPNOTSUPP;

	htx = kzalloc_obj(*htx);
	if (!htx)
		return -ENOMEM;
	spec = kvzalloc_obj(*spec);
	if (!spec) {
		kfree(htx);
		return -ENOMEM;
	}

	htx->tx_ft = mlx5e_psp_fdb_tx_get(priv);
	if (IS_ERR(htx->tx_ft)) {
		err = PTR_ERR(htx->tx_ft);
		goto err;
	}

	htx->ft = psp_fdb_ft_create(ns, FDB_CRYPTO_EGRESS,
				    MLX5E_PSP_FDB_HOST_TX_FT_LEVEL);
	if (IS_ERR(htx->ft)) {
		err = PTR_ERR(htx->ft);
		goto err;
	}

	/* Under the lock against mlx5e_psp_fdb_host_tx_update_next() */
	mutex_lock(&priv->psp->fdb_rx_lock);
	psp_fdb_host_tx_next(esw, &htx->next);

	/* The IPsec Tx policy table is at the same level */
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	flow_act.flags = FLOW_ACT_IGNORE_FLOW_LEVEL;
	dest = htx->next;
	err = psp_fdb_miss_create(htx->ft, &flow_act, &dest, 1,
				  &htx->miss_group, &htx->miss_rule);
	if (err)
		goto err_unlock;

	/* Match like the NIC Tx table: the driver inserted UDP + PSP */
	spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria,
			 outer_headers.ip_protocol);
	MLX5_SET(fte_match_param, spec->match_value, outer_headers.ip_protocol,
		 IPPROTO_UDP);
	MLX5_SET_TO_ONES(fte_match_param, spec->match_criteria,
			 outer_headers.udp_dport);
	MLX5_SET(fte_match_param, spec->match_value, outer_headers.udp_dport,
		 PSP_DEFAULT_UDP_PORT);
	memset(&flow_act, 0, sizeof(flow_act));
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_CRYPTO_ENCRYPT |
			  MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	flow_act.crypto.type = MLX5_FLOW_CONTEXT_ENCRYPT_DECRYPT_TYPE_PSP;
	memset(&dest, 0, sizeof(dest));
	dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
	dest.ft = htx->tx_ft;
	htx->rule = mlx5_add_flow_rules(htx->ft, spec, &flow_act, &dest, 1);
	if (IS_ERR(htx->rule)) {
		err = PTR_ERR(htx->rule);
		goto err_unlock;
	}

	kvfree(spec);
	priv->psp->fdb_host_tx = htx;
	esw->offloads.ft_psp_host_tx = htx->ft;
	mutex_unlock(&priv->psp->fdb_rx_lock);
	return 0;

err_unlock:
	mutex_unlock(&priv->psp->fdb_rx_lock);
err:
	mlx5_core_warn(mdev, "Failed to create PSP FDB host Tx table: %d\n", err);
	kvfree(spec);
	psp_fdb_host_tx_free(priv, htx);
	return err;
}

/* After the uplink's send queues, and their send-to-vport rules, are gone */
void mlx5e_psp_fdb_host_tx_destroy(struct mlx5e_priv *priv)
{
	struct mlx5e_psp_fdb_host_tx *htx;

	mutex_lock(&priv->psp->fdb_rx_lock);
	htx = priv->psp->fdb_host_tx;
	priv->mdev->priv.eswitch->offloads.ft_psp_host_tx = NULL;
	priv->psp->fdb_host_tx = NULL;
	mutex_unlock(&priv->psp->fdb_rx_lock);

	if (htx)
		psp_fdb_host_tx_free(priv, htx);
}

/* The eswitch IPsec Tx tables came or went (ipsec_esw_tx_ft_policy_set()):
 * send what isn't PSP there, or to the uplink.
 */
void mlx5e_psp_fdb_host_tx_update_next(struct mlx5_core_dev *mdev)
{
	struct mlx5_eswitch *esw = mdev->priv.eswitch;
	struct mlx5e_rep_priv *uplink_rpriv;
	struct mlx5_flow_destination next;
	struct mlx5e_psp_fdb_host_tx *htx;
	struct mlx5e_priv *priv;

	uplink_rpriv = mlx5_eswitch_get_uplink_priv(esw, REP_ETH);
	if (!uplink_rpriv || !uplink_rpriv->netdev)
		return;
	priv = netdev_priv(uplink_rpriv->netdev);
	if (!priv->psp)
		return;

	mutex_lock(&priv->psp->fdb_rx_lock);
	htx = priv->psp->fdb_host_tx;
	if (htx) {
		psp_fdb_host_tx_next(esw, &next);
		if (mlx5_modify_rule_destination(htx->miss_rule, &next,
						 &htx->next))
			mlx5_core_warn(mdev, "PSP: failed to update the host Tx table for IPsec\n");
		else
			htx->next = next;
	}
	mutex_unlock(&priv->psp->fdb_rx_lock);
}

void mlx5e_psp_fdb_rx_get_stats(struct mlx5e_priv *priv,
				struct mlx5e_psp_stats *stats)
{
	struct mlx5e_psp *psp = priv->psp;

	mutex_lock(&psp->fdb_rx_lock);
	*stats = psp->fdb_rx_stats;
	if (psp->fdb_rx)
		psp_fdb_rx_add_stats(priv->mdev, psp->fdb_rx, stats);
	if (psp->fdb_tx)
		psp_fdb_tx_add_stats(priv->mdev, psp->fdb_tx, stats);
	mutex_unlock(&psp->fdb_rx_lock);
}

/* flower PSP matches in an FDB rule on the uplink. priv is the uplink's. */
int mlx5e_psp_fdb_match(struct mlx5e_priv *priv, struct mlx5_flow_spec *spec,
			const struct flow_dissector_key_psp *key,
			const struct flow_dissector_key_psp *mask,
			struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	void *headers_c, *headers_v;
	void *misc6_c, *misc6_v;
	u32 c, v;

	if (!mlx5e_psp_fdb_steering_ok(mdev)) {
		NL_SET_ERR_MSG_MOD(extack, "PSP offload in switchdev requires flow_steering_mode dmfs");
		return -EOPNOTSUPP;
	}
	if (!priv->psp || !priv->psp->psd || !mlx5e_is_uplink_rep(priv)) {
		NL_SET_ERR_MSG_MOD(extack, "PSP matches are only offloaded on the uplink, with PSP enabled");
		return -EOPNOTSUPP;
	}
	if (!MLX5_CAP_ESW_FT_FIELD_SUPPORT_2(mdev, psp_header)) {
		NL_SET_ERR_MSG_MOD(extack, "Matching the PSP header is not supported by the device");
		return -EOPNOTSUPP;
	}
	/* Only this device's decrypted packets get to its FDB */
	if (mask->dev_id && key->dev_id != priv->psp->psd->id) {
		NL_SET_ERR_MSG_MOD(extack, "psp_dev is not the uplink's PSP device");
		return -EOPNOTSUPP;
	}

	/* The PSP matches only match decrypted packets, as in software. Only
	 * those get to the tc tables with UDP destination port 1000, the
	 * decrypt check table drops the others.
	 */
	headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				 outer_headers);
	headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				 outer_headers);

	/* Here ip_proto and dst_port match the outer headers, which for PSP
	 * are UDP to port 1000. Don't change a rule which asks for others.
	 */
	c = MLX5_GET(fte_match_set_lyr_2_4, headers_c, ip_protocol);
	v = MLX5_GET(fte_match_set_lyr_2_4, headers_v, ip_protocol);
	if ((IPPROTO_UDP & c) != (v & c)) {
		NL_SET_ERR_MSG_MOD(extack, "PSP matches imply ip_proto udp");
		return -EOPNOTSUPP;
	}
	c = MLX5_GET(fte_match_set_lyr_2_4, headers_c, udp_dport);
	v = MLX5_GET(fte_match_set_lyr_2_4, headers_v, udp_dport);
	if ((PSP_DEFAULT_UDP_PORT & c) != (v & c)) {
		NL_SET_ERR_MSG_MOD(extack, "PSP matches imply UDP dst_port 1000");
		return -EOPNOTSUPP;
	}

	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, ip_protocol);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol, IPPROTO_UDP);
	MLX5_SET_TO_ONES(fte_match_set_lyr_2_4, headers_c, udp_dport);
	MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_dport,
		 PSP_DEFAULT_UDP_PORT);
	spec->match_criteria_enable |= MLX5_MATCH_OUTER_HEADERS;

	if (!mask->spi && !mask->version)
		return 0;

	misc6_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
			       misc_parameters_6);
	misc6_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
			       misc_parameters_6);
	MLX5_SET(fte_match_set_misc6, misc6_c, psp_spi, be32_to_cpu(mask->spi));
	MLX5_SET(fte_match_set_misc6, misc6_v, psp_spi,
		 be32_to_cpu(key->spi & mask->spi));
	MLX5_SET(fte_match_set_misc6, misc6_c, psp_version, mask->version);
	MLX5_SET(fte_match_set_misc6, misc6_v, psp_version,
		 key->version & mask->version);
	spec->match_criteria_enable |= MLX5_MATCH_MISC_PARAMETERS_6;

	return 0;
}
