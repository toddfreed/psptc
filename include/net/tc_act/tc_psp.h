/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NET_TC_PSP_H
#define __NET_TC_PSP_H

#include <net/act_api.h>
#include <net/dst_metadata.h>
#include <linux/tc_act/tc_psp.h>

struct tcf_psp_params {
	struct rcu_head		rcu;
	int			action;
	int			psp_action;
	struct metadata_dst	*md;
};

struct tcf_psp {
	struct tc_action		common;
	struct tcf_psp_params __rcu	*params;
};

#define to_psp(a) ((struct tcf_psp *)a)

#endif /* __NET_TC_PSP_H */
