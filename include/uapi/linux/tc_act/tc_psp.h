/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_TC_PSP_H
#define __LINUX_TC_PSP_H

#include <linux/pkt_cls.h>

#define TCA_PSP_ACT_ENCAP	1	/* attach a PSP association */
#define TCA_PSP_ACT_DECAP	2	/* drop PSP Rx state */

/* transport: udp+psp inserted between l3 and l4 headers; l4 and
 *            remainder is encrypted
 * tunnel:    new ip+udp+psp encloses original l3 and remainder ; l3 and
 *            remainder is encrypted. the outer addresses from a
 *            preceding tunnel_key set. hardware offload only.
 */
enum {
	TCA_PSP_MODE_TRANSPORT,
	TCA_PSP_MODE_TUNNEL,
	__TCA_PSP_MODE_MAX,
};
#define TCA_PSP_MODE_MAX (__TCA_PSP_MODE_MAX - 1)

struct tc_psp {
	tc_gen;
};

enum {
	TCA_PSP_UNSPEC,
	TCA_PSP_TM,
	TCA_PSP_PARMS,
	TCA_PSP_PAD,
	TCA_PSP_ACTION,		/* u32, TCA_PSP_ACT_* */
	TCA_PSP_ASSOC_ID,	/* u32, encap only: Tx association ID from
				 * the PSP netlink family (assoc-add)
				 */
	TCA_PSP_MODE,		/* u8, TCA_PSP_MODE_*, default transport */
	__TCA_PSP_MAX,
};

#define TCA_PSP_MAX (__TCA_PSP_MAX - 1)

#endif
