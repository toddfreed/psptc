/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_TC_PSP_H
#define __LINUX_TC_PSP_H

#include <linux/pkt_cls.h>

#define TCA_PSP_ACT_ENCAP	1	/* attach a PSP association */
#define TCA_PSP_ACT_DECAP	2	/* drop PSP Rx state */

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
	__TCA_PSP_MAX,
};

#define TCA_PSP_MAX (__TCA_PSP_MAX - 1)

#endif
