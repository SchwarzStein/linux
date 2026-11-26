/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LWFP_H
#define _LINUX_LWFP_H

#include <linux/types.h>

struct pt_regs;

/* Requires CONFIG_PERF_EVENTS and CONFIG_HAVE_HW_BREAKPOINT. */
int lwfp_report_extended_event(struct pt_regs *regs, u64 supported_flags);

#endif
