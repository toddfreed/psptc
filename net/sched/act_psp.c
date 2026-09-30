// SPDX-License-Identifier: GPL-2.0
/*
 * tc action that attaches a PSP association to packets.
 *
 * encap: attach a tx association referenced by its ID, as a METADATA_PSP dst.
 *        The PSP device's netdev encrypts the packet on transmit. In
 *        software, egress only: like tunnel mode, encap on ingress is
 *        hardware offload only.
 * decap: drop the PSP Rx state (SKB_EXT_PSP) of a decrypted packet. It
 *        takes no association. a rule which should only take the packets
 *        of one association matches its properties against psp packet header
 *        fields (flower psp_spi / psp_ver / psp_dev).
 */

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/dst.h>
#include <net/inet_timewait_sock.h>
#include <net/ip.h>
#include <net/netlink.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>
#include <net/psp/functions.h>
#include <net/tc_act/tc_psp.h>

static struct tc_action_ops act_psp_ops;

/* The device inserts UDP + PSP between the IP header and the transport
 * header, so the transport header must be right by the time the packet
 * gets there. On a forwarded packet it may not be. Transport mode doesn't
 * support IP fragments or IPv6 extension headers.
 */
static bool tcf_psp_set_transport_header(struct sk_buff *skb)
{
	unsigned int off = skb_network_offset(skb);
	const struct iphdr *iph;
	unsigned int hlen, len;

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		if (!pskb_may_pull(skb, off + sizeof(*iph)))
			return false;
		iph = ip_hdr(skb);
		if (iph->version != 4 || iph->ihl < 5 || ip_is_fragment(iph))
			return false;
		hlen = iph->ihl * 4;
		len = ntohs(iph->tot_len);
		if (!pskb_may_pull(skb, off + hlen))
			return false;
		break;
	case htons(ETH_P_IPV6):
		if (!pskb_may_pull(skb, off + sizeof(struct ipv6hdr)))
			return false;
		if (ipv6_hdr(skb)->version != 6 ||
		    ipv6_ext_hdr(ipv6_hdr(skb)->nexthdr))
			return false;
		hlen = sizeof(struct ipv6hdr);
		len = hlen + ntohs(ipv6_hdr(skb)->payload_len);
		break;
	default:
		return false;
	}

	/* The device takes the length of the payload from the packet: it must
	 * hold the IP length, and L2 padding, e.g. of a minimum size frame,
	 * must not be encrypted as payload. A GSO skb's header doesn't always
	 * carry its length (BIG TCP).
	 */
	if (!skb_is_gso(skb)) {
		if (len < hlen || skb->len - off < len)
			return false;
		if (pskb_trim_rcsum(skb, off + len))
			return false;
	}

	skb_set_transport_header(skb, off + hlen);
	return true;
}

/* The socket of the packet has its own encryption offload, kTLS or PSP:
 * sk_validate_xmit_skb() then applies the socket's validator instead of
 * checking the association.
 */
static bool tcf_psp_sk_offload(const struct sk_buff *skb)
{
#ifdef CONFIG_SOCK_VALIDATE_XMIT
	struct sock *sk = skb->sk;

	if (!sk)
		return false;
	if (sk_fullsock(sk))
		return !!READ_ONCE(sk->sk_validate_xmit_skb);
	return sk_is_inet(sk) && sk->sk_state == TCP_TIME_WAIT &&
	       inet_twsk(sk)->tw_validate_xmit_skb;
#else
	return false;
#endif
}

static int tcf_psp_drop(struct tcf_psp *p, struct sk_buff *skb,
			enum skb_drop_reason reason)
{
	tcf_action_inc_drop_qstats(&p->common);
	tcf_set_drop_reason(skb, reason);
	return TC_ACT_SHOT;
}

static int tcf_psp_act(struct sk_buff *skb, const struct tc_action *a,
		       struct tcf_result *res)
{
	struct tcf_psp *p = to_psp(a);
	struct tcf_psp_params *params;

	params = rcu_dereference_bh(p->params);

	tcf_lastuse_update(&p->tcf_tm);
	tcf_action_update_bstats(&p->common, skb);

	switch (params->psp_action) {
	case TCA_PSP_ACT_ENCAP:
		/* Encap on ingress is hardware offload only, like tunnel
		 * mode: the packet would go through the stack with nothing
		 * but its dst, which routing, netfilter or a redirect may
		 * replace, to keep it from leaving in clear text
		 */
		if (unlikely(skb_at_tc_ingress(skb)))
			return tcf_psp_drop(p, skb, SKB_DROP_REASON_PSP_OUTPUT);
		/* PSP on a tunnel isn't supported: the encap would overwrite
		 * the inner headers which the device's tunnel offloads use
		 */
		if (unlikely(skb->encapsulation))
			return tcf_psp_drop(p, skb, SKB_DROP_REASON_PSP_OUTPUT);
		/* Don't mix the association with another encryption
		 * offload: the packet is already marked decrypted, or its
		 * socket has an offload of its own
		 */
		if (unlikely(skb_is_decrypted(skb) || tcf_psp_sk_offload(skb)))
			return tcf_psp_drop(p, skb, SKB_DROP_REASON_PSP_OUTPUT);
		if (unlikely(!tcf_psp_set_transport_header(skb)))
			return tcf_psp_drop(p, skb, SKB_DROP_REASON_PSP_OUTPUT);
		skb_dst_drop(skb);
		skb_dst_set(skb, dst_clone(&params->md->dst));
		/* Must be encrypted: sk_validate_xmit_skb() drops it unless
		 * it still carries the association when it is transmitted
		 */
		skb->decrypted = 1;
		break;
	case TCA_PSP_ACT_DECAP:
		/* Only a packet the device decrypted: on transmit,
		 * skb->decrypted means "device, please encrypt", which decap
		 * must not undo.
		 */
		if (!skb_ext_find(skb, SKB_EXT_PSP))
			break;
		skb_ext_del(skb, SKB_EXT_PSP);
		skb->decrypted = 0;
		break;
	}

	return params->action;
}

static const struct nla_policy psp_policy[TCA_PSP_MAX + 1] = {
	[TCA_PSP_PARMS]		= NLA_POLICY_EXACT_LEN(sizeof(struct tc_psp)),
	[TCA_PSP_ACTION]	= NLA_POLICY_RANGE(NLA_U32, TCA_PSP_ACT_ENCAP,
						   TCA_PSP_ACT_DECAP),
	[TCA_PSP_ASSOC_ID]	= NLA_POLICY_MIN(NLA_U32, 1),
};

static void tcf_psp_release_params_rcu(struct rcu_head *head)
{
	struct tcf_psp_params *params = container_of(head, typeof(*params),
						     rcu);

	if (params->md)
		dst_release(&params->md->dst);
	kfree(params);
}

static void tcf_psp_release_params(struct tcf_psp_params *params)
{
	if (params)
		call_rcu(&params->rcu, tcf_psp_release_params_rcu);
}

static struct metadata_dst *
tcf_psp_md_create(struct net *net, struct nlattr *id_attr,
		  struct netlink_ext_ack *extack)
{
	struct metadata_dst *md;
	struct psp_assoc *pas;

	pas = psp_assoc_get_by_id(net, nla_get_u32(id_attr));
	if (!pas) {
		NL_SET_ERR_MSG_ATTR(extack, id_attr,
				    "PSP association not found");
		return ERR_PTR(-ENOENT);
	}
	if (!psp_assoc_is_tx(pas)) {
		NL_SET_ERR_MSG_ATTR(extack, id_attr,
				    "encap needs a Tx association (assoc-add)");
		psp_assoc_put(pas);
		return ERR_PTR(-EINVAL);
	}

	md = metadata_dst_alloc(0, METADATA_PSP, GFP_KERNEL);
	if (!md) {
		psp_assoc_put(pas);
		return ERR_PTR(-ENOMEM);
	}
	/* The dst now owns the reference on the association */
	md->u.psp_info.pas = pas;

	return md;
}

static int tcf_psp_init(struct net *net, struct nlattr *nla,
			struct nlattr *est, struct tc_action **a,
			struct tcf_proto *tp, u32 flags,
			struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, act_psp_ops.net_id);
	bool bind = flags & TCA_ACT_FLAGS_BIND;
	struct nlattr *tb[TCA_PSP_MAX + 1];
	struct tcf_psp_params *params_new;
	struct metadata_dst *md = NULL;
	struct tcf_chain *goto_ch = NULL;
	struct tc_psp *parm;
	bool exists = false;
	int ret = 0, err;
	struct tcf_psp *p;
	u32 psp_action;
	u32 index;

	if (!nla) {
		NL_SET_ERR_MSG(extack, "PSP action requires attributes");
		return -EINVAL;
	}

	err = nla_parse_nested(tb, TCA_PSP_MAX, nla, psp_policy, extack);
	if (err < 0)
		return err;

	if (!tb[TCA_PSP_PARMS]) {
		NL_SET_ERR_MSG(extack, "Missing PSP action parameters");
		return -EINVAL;
	}

	parm = nla_data(tb[TCA_PSP_PARMS]);
	index = parm->index;
	err = tcf_idr_check_alloc(tn, &index, a, bind);
	if (err < 0)
		return err;
	exists = err;
	if (exists && bind)
		return ACT_P_BOUND;

	if (NL_REQ_ATTR_CHECK(extack, nla, tb, TCA_PSP_ACTION)) {
		NL_SET_ERR_MSG(extack, "Missing PSP action, encap or decap");
		ret = -EINVAL;
		goto err_out;
	}
	psp_action = nla_get_u32(tb[TCA_PSP_ACTION]);

	switch (psp_action) {
	case TCA_PSP_ACT_ENCAP:
		if (NL_REQ_ATTR_CHECK(extack, nla, tb, TCA_PSP_ASSOC_ID)) {
			NL_SET_ERR_MSG(extack, "Missing PSP association ID");
			ret = -EINVAL;
			goto err_out;
		}
		md = tcf_psp_md_create(net, tb[TCA_PSP_ASSOC_ID], extack);
		if (IS_ERR(md)) {
			ret = PTR_ERR(md);
			md = NULL;
			goto err_out;
		}
		break;
	case TCA_PSP_ACT_DECAP:
		if (tb[TCA_PSP_ASSOC_ID]) {
			NL_SET_ERR_MSG_ATTR(extack, tb[TCA_PSP_ASSOC_ID],
					    "decap takes no PSP association");
			ret = -EINVAL;
			goto err_out;
		}
		break;
	}

	if (!exists) {
		ret = tcf_idr_create_from_flags(tn, index, est, a,
						&act_psp_ops, bind, flags);
		if (ret)
			goto release_md;

		ret = ACT_P_CREATED;
	} else if (!(flags & TCA_ACT_FLAGS_REPLACE)) {
		NL_SET_ERR_MSG(extack, "PSP action already exists");
		ret = -EEXIST;
		goto release_md;
	}

	err = tcf_action_check_ctrlact(parm->action, tp, &goto_ch, extack);
	if (err < 0) {
		ret = err;
		exists = true;
		goto release_md;
	}
	p = to_psp(*a);

	params_new = kzalloc_obj(*params_new);
	if (!params_new) {
		ret = -ENOMEM;
		exists = true;
		goto put_chain;
	}
	params_new->action = parm->action;
	params_new->psp_action = psp_action;
	params_new->md = md;

	spin_lock_bh(&p->tcf_lock);
	goto_ch = tcf_action_set_ctrlact(*a, parm->action, goto_ch);
	params_new = rcu_replace_pointer(p->params, params_new,
					 lockdep_is_held(&p->tcf_lock));
	spin_unlock_bh(&p->tcf_lock);

	tcf_psp_release_params(params_new);
	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);

	return ret;

put_chain:
	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);
release_md:
	if (md)
		dst_release(&md->dst);
err_out:
	if (exists)
		tcf_idr_release(*a, bind);
	else
		tcf_idr_cleanup(tn, index);
	return ret;
}

static void tcf_psp_cleanup(struct tc_action *a)
{
	struct tcf_psp *p = to_psp(a);

	tcf_psp_release_params(rcu_dereference_protected(p->params, 1));
}

static int tcf_psp_dump(struct sk_buff *skb, struct tc_action *a,
			int bind, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_psp *p = to_psp(a);
	struct tcf_psp_params *params;
	struct tc_psp opt = {
		.index    = p->tcf_index,
		.refcnt   = refcount_read(&p->tcf_refcnt) - ref,
		.bindcnt  = atomic_read(&p->tcf_bindcnt) - bind,
	};
	struct tcf_t t;

	rcu_read_lock();
	params = rcu_dereference(p->params);
	opt.action = params->action;

	if (nla_put(skb, TCA_PSP_PARMS, sizeof(opt), &opt) ||
	    nla_put_u32(skb, TCA_PSP_ACTION, params->psp_action))
		goto nla_put_failure;

	if (params->md &&
	    nla_put_u32(skb, TCA_PSP_ASSOC_ID, params->md->u.psp_info.pas->id))
		goto nla_put_failure;

	tcf_tm_dump(&t, &p->tcf_tm);
	if (nla_put_64bit(skb, TCA_PSP_TM, sizeof(t), &t, TCA_PSP_PAD))
		goto nla_put_failure;
	rcu_read_unlock();

	return skb->len;

nla_put_failure:
	rcu_read_unlock();
	nlmsg_trim(skb, b);
	return -1;
}

static void tcf_psp_stats_update(struct tc_action *a, u64 bytes, u64 packets,
				 u64 drops, u64 lastuse, bool hw)
{
	struct tcf_psp *p = to_psp(a);
	struct tcf_t *tm = &p->tcf_tm;

	tcf_action_update_stats(a, bytes, packets, drops, hw);
	tm->lastuse = max_t(u64, tm->lastuse, lastuse);
}

static void tcf_psp_offload_destructor(void *priv)
{
	psp_assoc_put(priv);
}

static int tcf_psp_offload_act_setup(struct tc_action *act, void *entry_data,
				     u32 *index_inc, bool bind,
				     struct netlink_ext_ack *extack)
{
	struct tcf_psp *p = to_psp(act);
	struct tcf_psp_params *params;
	enum flow_action_id id;
	struct psp_assoc *pas;

	rcu_read_lock();
	params = rcu_dereference(p->params);
	id = params->psp_action == TCA_PSP_ACT_ENCAP ? FLOW_ACTION_PSP_ENCAP :
						       FLOW_ACTION_PSP_DECAP;
	pas = params->md ? params->md->u.psp_info.pas : NULL;
	if (pas && bind)
		psp_assoc_hold(pas);
	rcu_read_unlock();

	if (bind) {
		struct flow_action_entry *entry = entry_data;

		entry->id = id;
		entry->psp.pas = pas;
		if (pas) {
			entry->destructor = tcf_psp_offload_destructor;
			entry->destructor_priv = pas;
		}
		*index_inc = 1;
	} else {
		struct flow_offload_action *fl_action = entry_data;

		fl_action->id = id;
	}

	return 0;
}

static struct tc_action_ops act_psp_ops = {
	.kind		=	"psp",
	.id		=	TCA_ID_PSP,
	.owner		=	THIS_MODULE,
	.act		=	tcf_psp_act,
	.dump		=	tcf_psp_dump,
	.init		=	tcf_psp_init,
	.cleanup	=	tcf_psp_cleanup,
	.stats_update	=	tcf_psp_stats_update,
	.offload_act_setup =	tcf_psp_offload_act_setup,
	.size		=	sizeof(struct tcf_psp),
};
MODULE_ALIAS_NET_ACT("psp");

static __net_init int psp_init_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, act_psp_ops.net_id);

	return tc_action_net_init(net, tn, &act_psp_ops);
}

static void __net_exit psp_exit_net(struct list_head *net_list)
{
	tc_action_net_exit(net_list, act_psp_ops.net_id);
}

static struct pernet_operations psp_net_ops = {
	.init = psp_init_net,
	.exit_batch = psp_exit_net,
	.id   = &act_psp_ops.net_id,
	.size = sizeof(struct tc_action_net),
};

static int __init psp_init_module(void)
{
	return tcf_register_action(&act_psp_ops, &psp_net_ops);
}

static void __exit psp_cleanup_module(void)
{
	tcf_unregister_action(&act_psp_ops, &psp_net_ops);
}

module_init(psp_init_module);
module_exit(psp_cleanup_module);

MODULE_DESCRIPTION("PSP encryption tc action");
MODULE_LICENSE("GPL");
