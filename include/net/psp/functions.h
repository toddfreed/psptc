/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __NET_PSP_HELPERS_H
#define __NET_PSP_HELPERS_H

#include <linux/skbuff.h>
#include <linux/rcupdate.h>
#include <linux/udp.h>
#include <net/dst_metadata.h>
#include <net/gso.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/psp/types.h>

struct inet_timewait_sock;

/* Driver-facing API */
struct psp_dev *
psp_dev_create(struct net_device *netdev, struct psp_dev_ops *psd_ops,
	       struct psp_dev_caps *psd_caps, void *priv_ptr);
void psp_dev_unregister(struct psp_dev *psd);
bool psp_dev_encapsulate(struct net *net, struct sk_buff *skb, __be32 spi,
			 u8 ver, __be16 sport);
int psp_dev_rcv(struct sk_buff *skb, u16 dev_id, u8 generation, bool strip_icv);

/* Kernel-facing API */
#if IS_ENABLED(CONFIG_INET_PSP)
void psp_assoc_put(struct psp_assoc *pas);
struct psp_assoc *psp_assoc_get_by_id(struct net *net, u32 id);

/* An association from the ID registry is either a Tx one, from assoc-add,
 * or an Rx one, from rx-spi-alloc. PSP SPIs are never 0.
 */
static inline bool psp_assoc_is_tx(const struct psp_assoc *pas)
{
	DEBUG_NET_WARN_ON_ONCE(!pas->id);    /* only socket-less ones */
	return pas->tx.spi != 0;
}

unsigned int psp_key_size(u32 version);
void psp_sk_assoc_free(struct sock *sk);
void psp_twsk_init(struct inet_timewait_sock *tw, const struct sock *sk);
void psp_twsk_assoc_free(struct inet_timewait_sock *tw);
void psp_reply_set_decrypted(const struct sock *sk, struct sk_buff *skb);

static inline struct psp_assoc *psp_sk_assoc(const struct sock *sk)
{
	return rcu_dereference_check(sk->psp_assoc, lockdep_sock_is_held(sk));
}

static inline void
psp_enqueue_set_decrypted(struct sock *sk, struct sk_buff *skb)
{
	struct psp_assoc *pas;

	pas = psp_sk_assoc(sk);
	if (pas && pas->tx.spi)
		skb->decrypted = 1;
}

static inline unsigned long
__psp_skb_coalesce_diff(const struct sk_buff *one, const struct sk_buff *two,
			unsigned long diffs)
{
	struct psp_skb_ext *a, *b;

	a = skb_ext_find(one, SKB_EXT_PSP);
	b = skb_ext_find(two, SKB_EXT_PSP);

	diffs |= (!!a) ^ (!!b);
	if (!diffs && unlikely(a))
		diffs |= memcmp(a, b, sizeof(*a));
	return diffs;
}

static inline bool
psp_is_allowed_nondata(struct sk_buff *skb, struct psp_assoc *pas)
{
	bool fin = !!(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN);
	u32 end_seq = TCP_SKB_CB(skb)->end_seq;
	u32 seq = TCP_SKB_CB(skb)->seq;
	bool pure_fin;

	pure_fin = fin && end_seq - seq == 1;

	return seq == end_seq || (pure_fin && seq == pas->upgrade_seq);
}

static inline bool
psp_pse_matches_pas(struct psp_skb_ext *pse, struct psp_assoc *pas)
{
	return pse && pas->rx.spi == pse->spi &&
	       pas->generation == pse->generation &&
	       pas->version == pse->version &&
	       pas->dev_id == pse->dev_id;
}

static inline enum skb_drop_reason
__psp_sk_rx_policy_check(struct sk_buff *skb, struct psp_assoc *pas)
{
	struct psp_skb_ext *pse = skb_ext_find(skb, SKB_EXT_PSP);

	if (!pas)
		return pse ? SKB_DROP_REASON_PSP_INPUT : 0;

	if (likely(psp_pse_matches_pas(pse, pas))) {
		if (unlikely(!pas->peer_tx))
			pas->peer_tx = 1;

		return 0;
	}

	if (!pse) {
		if (!pas->tx.spi ||
		    (!pas->peer_tx && psp_is_allowed_nondata(skb, pas)))
			return 0;
	}

	return SKB_DROP_REASON_PSP_INPUT;
}

static inline enum skb_drop_reason
psp_sk_rx_policy_check(struct sock *sk, struct sk_buff *skb)
{
	return __psp_sk_rx_policy_check(skb, psp_sk_assoc(sk));
}

static inline enum skb_drop_reason
psp_twsk_rx_policy_check(struct inet_timewait_sock *tw, struct sk_buff *skb)
{
	return __psp_sk_rx_policy_check(skb, rcu_dereference(tw->psp_assoc));
}

static inline struct psp_assoc *psp_sk_get_assoc_rcu(const struct sock *sk)
{
	struct psp_assoc *pas;
	int state;

	state = READ_ONCE(sk->sk_state);
	if (!sk_is_inet(sk) || state == TCP_NEW_SYN_RECV)
		return NULL;

	pas = state == TCP_TIME_WAIT ?
		      rcu_dereference(inet_twsk(sk)->psp_assoc) :
		      rcu_dereference(sk->psp_assoc);
	return pas;
}

static inline struct psp_assoc *psp_skb_md_assoc(const struct sk_buff *skb)
{
	struct metadata_dst *md_dst = skb_metadata_dst(skb);

	if (md_dst && md_dst->type == METADATA_PSP)
		return md_dst->u.psp_info.pas;

	return NULL;
}

static inline struct psp_assoc *psp_skb_get_assoc_rcu(struct sk_buff *skb)
{
	struct psp_assoc *pas;

	pas = psp_skb_md_assoc(skb);
	if (pas)
		return pas;

	if (!skb->decrypted || !skb->sk)
		return NULL;

	return psp_sk_get_assoc_rcu(skb->sk);
}

/**
 * psp_xmit_md() - validate psp association attached as a metadata dst
 * @skb: packet about to be queued for transmission
 * @dev: device it is queued on
 *
 * If the skb has a psp association attached as metadata dst, this indicates
 * intent to transmit encrypted, which will only happen when transmit on
 * the main netdev of its psp device.
 *
 * Also check that the packet will still fit @dev's MTU once the device has
 * added the PSP encapsulation. Sockets leave room for it (psp_sk_overhead()),
 * whoever attached the association may not have.
 *
 * returns:
 *   0 if @skb carries no psp association
 *   1 if it does and the dst must be kept for the driver
 *  -EINVAL if the packet must be dropped, @dev isn't of its psp device
 *  -EMSGSIZE if the packet must be dropped, too big once encapsulated
 */
static inline int psp_xmit_md(const struct sk_buff *skb,
			      const struct net_device *dev)
{
	unsigned int psp_encap = sizeof(struct udphdr) + PSP_HDR_SIZE +
				 PSP_TRL_SIZE;
	struct psp_assoc *pas = psp_skb_md_assoc(skb);
	unsigned int mtu;

	if (likely(!pas))
		return 0;

	if (rcu_access_pointer(dev->psp_dev) != pas->psd ||
	    dev != pas->psd->main_netdev)
		return -EINVAL;

	mtu = READ_ONCE(dev->mtu);
	if (mtu <= psp_encap)
		return -EMSGSIZE;
	mtu -= psp_encap;
	if (skb_is_gso(skb)) {
		if (!skb_gso_validate_network_len(skb, mtu))
			return -EMSGSIZE;
	} else if (skb->len - skb_network_offset(skb) > mtu) {
		return -EMSGSIZE;
	}

	return 1;
}

static inline unsigned int psp_sk_overhead(const struct sock *sk)
{
	int psp_encap = sizeof(struct udphdr) + PSP_HDR_SIZE + PSP_TRL_SIZE;
	struct psp_assoc *pas = psp_sk_assoc(sk);

	return pas && pas->tx.spi ? psp_encap : 0;
}
#else
static inline void psp_assoc_put(struct psp_assoc *pas) { }

static inline struct psp_assoc *psp_assoc_get_by_id(struct net *net, u32 id)
{
	return NULL;
}

static inline int psp_xmit_md(const struct sk_buff *skb,
			      const struct net_device *dev)
{
	return 0;
}

static inline void psp_sk_assoc_free(struct sock *sk) { }
static inline void
psp_twsk_init(struct inet_timewait_sock *tw, const struct sock *sk) { }
static inline void psp_twsk_assoc_free(struct inet_timewait_sock *tw) { }
static inline void
psp_reply_set_decrypted(const struct sock *sk, struct sk_buff *skb) { }

static inline struct psp_assoc *psp_sk_assoc(const struct sock *sk)
{
	return NULL;
}

static inline void
psp_enqueue_set_decrypted(struct sock *sk, struct sk_buff *skb) { }

static inline unsigned long
__psp_skb_coalesce_diff(const struct sk_buff *one, const struct sk_buff *two,
			unsigned long diffs)
{
	return diffs;
}

static inline enum skb_drop_reason
psp_sk_rx_policy_check(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static inline enum skb_drop_reason
psp_twsk_rx_policy_check(struct inet_timewait_sock *tw, struct sk_buff *skb)
{
	return 0;
}

static inline struct psp_assoc *psp_skb_get_assoc_rcu(struct sk_buff *skb)
{
	return NULL;
}

static inline unsigned int psp_sk_overhead(const struct sock *sk)
{
	return 0;
}
#endif

static inline unsigned long
psp_skb_coalesce_diff(const struct sk_buff *one, const struct sk_buff *two)
{
	return __psp_skb_coalesce_diff(one, two, 0);
}

#endif /* __NET_PSP_HELPERS_H */
