// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

/* PSP tunnel mode encap:
 *
 *   tunnel_key set src_ip A dst_ip B [dst_port P] \
 *   psp encap assoc ID mode tunnel \
 *   mirred egress redirect dev UPLINK
 *
 * becomes one FDB rule that encrypts with the association's key and adds
 * the outer headers (en/tc_tun_psp.c). The association's SPI and version
 * and the inner protocol are encoded in the tunnel ID, so each gets its own
 * encap entry.
 *
 * And decap, on the uplink:
 *
 *   flower ... ip_proto udp dst_port 1000 \
 *   psp decap mode tunnel \
 *   vlan push_eth dst_mac M src_mac M2 \
 *   mirred egress redirect dev REP
 *
 * The packet has already been decrypted by the time it gets to the tc tables
 * (en_accel/psp_fdb.c), and the rule strips the outer headers and trailer
 * and writes the new L2 header. The inner packet is assumed to be IPv6.
 */

#include <linux/bitfield.h>
#include <net/psp/functions.h>
#include <uapi/linux/tc_act/tc_psp.h>
#include "act.h"
#include "en/tc_priv.h"
#include "en/tc_tun.h"
#include "en_accel/psp.h"

static bool
tc_act_can_offload_psp_encap(struct mlx5e_tc_act_parse_state *parse_state,
			     const struct flow_action_entry *act,
			     int act_index,
			     struct mlx5_flow_attr *attr)
{
	struct netlink_ext_ack *extack = parse_state->extack;
	struct mlx5e_priv *priv = parse_state->flow->priv;

	if (act->psp.mode != TCA_PSP_MODE_TUNNEL) {
		NL_SET_ERR_MSG_MOD(extack, "Only psp tunnel mode can be offloaded");
		return false;
	}

	if (!mlx5e_psp_fdb_steering_ok(priv->mdev)) {
		NL_SET_ERR_MSG_MOD(extack, "PSP offload in switchdev requires flow_steering_mode dmfs");
		return false;
	}

	if (!MLX5_CAP_ESW_FLOWTABLE_FDB(priv->mdev, psp_encrypt) ||
	    !MLX5_CAP_ESW_FLOWTABLE_FDB(priv->mdev,
					reformat_l2_to_l3_psp_tunnel)) {
		NL_SET_ERR_MSG_MOD(extack, "Device doesn't support psp tunnel encap");
		return false;
	}

	return true;
}

/* The PSP next header for the inner packet, which the rule matches: IPv4
 * or IPv6. Not mlx5e_tc_get_ip_version(), which takes ARP for IPv4.
 */
static u8 tc_act_psp_encap_nexthdr(struct mlx5_flow_spec *spec)
{
	void *headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				       outer_headers);

	switch (MLX5_GET(fte_match_set_lyr_2_4, headers_v, ip_version)) {
	case 4:
		return IPPROTO_IPIP;
	case 6:
		return IPPROTO_IPV6;
	}
	switch (MLX5_GET(fte_match_set_lyr_2_4, headers_v, ethertype)) {
	case ETH_P_IP:
		return IPPROTO_IPIP;
	case ETH_P_IPV6:
		return IPPROTO_IPV6;
	}
	return 0;
}

static int
tc_act_parse_psp_encap(struct mlx5e_tc_act_parse_state *parse_state,
		       const struct flow_action_entry *act,
		       struct mlx5e_priv *priv,
		       struct mlx5_flow_attr *attr)
{
	struct ip_tunnel_info *tun_info = &parse_state->psp_tun_info;
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	struct netlink_ext_ack *extack = parse_state->extack;
	struct psp_assoc *pas = act->psp.pas;
	struct net_device *uplink_dev;
	struct mlx5_flow_table *tx_ft;
	u32 key_id;
	u8 nexthdr;

	if (!parse_state->encap || !parse_state->tun_info) {
		NL_SET_ERR_MSG_MOD(extack, "psp encap must follow tunnel_key set");
		return -EOPNOTSUPP;
	}
	if (parse_state->tun_info->options_len) {
		NL_SET_ERR_MSG_MOD(extack, "Tunnel options are not supported with psp");
		return -EOPNOTSUPP;
	}
	if (attr->psp_pas) {
		NL_SET_ERR_MSG_MOD(extack, "Only one psp encap per rule is supported");
		return -EOPNOTSUPP;
	}

	nexthdr = tc_act_psp_encap_nexthdr(&attr->parse_attr->spec);
	if (!nexthdr) {
		NL_SET_ERR_MSG_MOD(extack, "psp tunnel encap requires matching on protocol ip or ipv6");
		return -EOPNOTSUPP;
	}

	uplink_dev = mlx5_eswitch_uplink_get_proto_dev(esw, REP_ETH);
	if (!uplink_dev ||
	    mlx5e_psp_tx_key_id(netdev_priv(uplink_dev), pas, &key_id)) {
		NL_SET_ERR_MSG_MOD(extack, "psp association doesn't belong to the uplink's PSP device");
		return -EOPNOTSUPP;
	}

	*tun_info = *parse_state->tun_info;
	tun_info->key.tun_id =
		cpu_to_be64(FIELD_PREP(MLX5E_PSP_TUN_ID_SPI,
				       be32_to_cpu(pas->tx.spi)) |
			    FIELD_PREP(MLX5E_PSP_TUN_ID_VERSION, pas->version) |
			    FIELD_PREP(MLX5E_PSP_TUN_ID_NEXTHDR, nexthdr));
	if (!tun_info->key.tp_dst)
		tun_info->key.tp_dst = htons(PSP_DEFAULT_UDP_PORT);
	parse_state->tun_info = tun_info;

	tx_ft = mlx5e_psp_fdb_tx_get(netdev_priv(uplink_dev));
	if (IS_ERR(tx_ft)) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to set up PSP Tx counting in the FDB");
		return PTR_ERR(tx_ft);
	}
	attr->esw_attr->psp_tx_ft = tx_ft;

	attr->psp_pas = psp_assoc_hold(pas);
	attr->crypto_obj_id = key_id;
	attr->action |= MLX5_FLOW_CONTEXT_ACTION_CRYPTO_ENCRYPT;

	return 0;
}

static int
tc_act_post_parse_psp_encap(struct mlx5e_tc_act_parse_state *parse_state,
			    struct mlx5e_priv *priv,
			    struct mlx5_flow_attr *attr)
{
	struct mlx5_esw_flow_attr *esw_attr = attr->esw_attr;

	/* The encap entry is looked up via the mirred dest */
	if (esw_attr->out_count != 1 ||
	    !(esw_attr->dests[0].flags & MLX5_ESW_DEST_ENCAP)) {
		NL_SET_ERR_MSG_MOD(parse_state->extack,
				   "psp encap must be followed by exactly one mirred to the uplink");
		return -EOPNOTSUPP;
	}

	return 0;
}

static bool
tc_act_can_offload_psp_decap(struct mlx5e_tc_act_parse_state *parse_state,
			     const struct flow_action_entry *act,
			     int act_index,
			     struct mlx5_flow_attr *attr)
{
	struct netlink_ext_ack *extack = parse_state->extack;
	struct mlx5e_priv *priv = parse_state->flow->priv;

	if (act->psp.mode != TCA_PSP_MODE_TUNNEL) {
		NL_SET_ERR_MSG_MOD(extack, "Only psp tunnel mode can be offloaded");
		return false;
	}

	if (!mlx5e_psp_fdb_steering_ok(priv->mdev)) {
		NL_SET_ERR_MSG_MOD(extack, "PSP offload in switchdev requires flow_steering_mode dmfs");
		return false;
	}

	if (!MLX5_CAP_ESW_FLOWTABLE_FDB(priv->mdev, psp_decrypt) ||
	    !MLX5_CAP_ESW_FLOWTABLE_FDB(priv->mdev,
					reformat_l3_psp_tunnel_to_l2)) {
		NL_SET_ERR_MSG_MOD(extack, "Device doesn't support psp tunnel decap");
		return false;
	}

	if (!mlx5e_is_uplink_rep(priv) || !priv->psp) {
		NL_SET_ERR_MSG_MOD(extack, "psp decap is only supported on the uplink, with PSP enabled");
		return false;
	}

	if (act_index) {
		NL_SET_ERR_MSG_MOD(extack, "psp decap must be the first action");
		return false;
	}

	return true;
}

static int
tc_act_parse_psp_decap(struct mlx5e_tc_act_parse_state *parse_state,
		       const struct flow_action_entry *act,
		       struct mlx5e_priv *priv,
		       struct mlx5_flow_attr *attr)
{
	struct netlink_ext_ack *extack = parse_state->extack;
	int err;

	if (attr->psp_decap) {
		NL_SET_ERR_MSG_MOD(extack, "Only one psp decap per rule is supported");
		return -EOPNOTSUPP;
	}

	err = mlx5e_psp_fdb_rx_get(priv);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to set up PSP decryption in the FDB");
		return err;
	}
	attr->psp_decap = true;

	attr->esw_attr->eth.h_proto = htons(ETH_P_IPV6);
	attr->action |= MLX5_FLOW_CONTEXT_ACTION_PACKET_REFORMAT;
	flow_flag_set(parse_state->flow, L3_TO_L2_DECAP);

	return 0;
}

struct mlx5e_tc_act mlx5e_tc_act_psp_decap = {
	.can_offload = tc_act_can_offload_psp_decap,
	.parse_action = tc_act_parse_psp_decap,
};

struct mlx5e_tc_act mlx5e_tc_act_psp_encap = {
	.can_offload = tc_act_can_offload_psp_encap,
	.parse_action = tc_act_parse_psp_encap,
	.post_parse = tc_act_post_parse_psp_encap,
};
