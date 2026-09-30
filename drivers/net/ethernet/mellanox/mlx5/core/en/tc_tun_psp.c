// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

/* PSP tunnel mode encap in the FDB, for "tunnel_key set ... psp encap
 * mode tunnel ... mirred" (en/tc/act/psp.c). Unlike the other tunnel types
 * there is no tunnel netdev: the flow redirects to the uplink, and the
 * PSP association (SPI, version) and inner protocol are encoded in the
 * tunnel ID by the psp action. The encryption key goes in the FTE.
 */

#include <linux/bitfield.h>
#include <net/psp/types.h>
#include "en/tc_tun.h"

static bool can_offload(struct mlx5e_priv *priv)
{
	return MLX5_CAP_ESW_FLOWTABLE_FDB(priv->mdev,
					  reformat_l2_to_l3_psp_tunnel);
}

static int calc_hlen(struct mlx5e_encap_entry *e)
{
	return sizeof(struct udphdr) + PSP_HDR_SIZE;
}

static int init_encap_attr(struct net_device *tunnel_dev,
			   struct mlx5e_priv *priv,
			   struct mlx5e_encap_entry *e,
			   struct netlink_ext_ack *extack)
{
	e->tunnel = &psp_tunnel;
	e->reformat_type = MLX5_REFORMAT_TYPE_ADD_PSP_TUNNEL;
	/* ICV size in dwords, as for L2_TO_L3_ESP_TUNNEL. Firmware (28.48)
	 * rejects anything but 4.
	 */
	e->reformat_param_0 = PSP_TRL_SIZE / 4;
	return 0;
}

static int generate_ip_tun_hdr(char buf[], __u8 *ip_proto,
			       struct mlx5e_encap_entry *e)
{
	const struct ip_tunnel_key *tun_key = &e->tun_info->key;
	u64 id = be64_to_cpu(tun_key->tun_id);
	struct udphdr *udp = (struct udphdr *)buf;
	struct psphdr *psph = (struct psphdr *)(udp + 1);

	*ip_proto = IPPROTO_UDP;

	/* The device fills in the length (and the checksum, if any) */
	udp->source = tun_key->tp_src;
	udp->dest = tun_key->tp_dst;

	psph->nexthdr = FIELD_GET(MLX5E_PSP_TUN_ID_NEXTHDR, id);
	psph->hdrlen = PSP_HDRLEN_NOOPT;
	psph->crypt_offset = 0;
	psph->verfl = FIELD_PREP(PSPHDR_VERFL_VERSION,
				 FIELD_GET(MLX5E_PSP_TUN_ID_VERSION, id)) |
		      PSPHDR_VERFL_ONE;
	psph->spi = cpu_to_be32(FIELD_GET(MLX5E_PSP_TUN_ID_SPI, id));
	/* The IV is filled in per packet */
	psph->iv = 0;

	return 0;
}

struct mlx5e_tc_tunnel psp_tunnel = {
	.tunnel_type          = MLX5E_TC_TUNNEL_TYPE_PSP,
	.match_level          = MLX5_MATCH_L4,
	.can_offload          = can_offload,
	.calc_hlen            = calc_hlen,
	.init_encap_attr      = init_encap_attr,
	.generate_ip_tun_hdr  = generate_ip_tun_hdr,
	.encap_info_equal     = mlx5e_tc_tun_encap_info_equal_generic,
};
