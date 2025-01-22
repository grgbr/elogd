/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_LOG_H
#define _ELOGD_LOG_H

#include "common.h"

struct elogd_intern;

extern struct elogd_intern *
elogd_log_the_intern(void)
	__elogd_nothrow __leaf __warn_result;

extern int
elogd_log_parse_std(struct elog_parse * __restrict parse,
                    const char * __restrict        arg)
	__elogd_nonull(1) __elogd_nothrow __leaf __warn_result;

extern int
elogd_log_parse_intern(struct elog_parse * __restrict parse,
                       const char * __restrict        arg)
	__elogd_nonull(1) __elogd_nothrow __leaf __warn_result;

extern void
elogd_log_init_parse(struct elog_parse * __restrict stdlog_parse,
                     struct elog_parse * __restrict intlog_parse)
	__elogd_nonull(1, 2) __elogd_nothrow __leaf;

extern void
elogd_log_fini_parse(struct elog_parse * __restrict stdlog_parse,
                     struct elog_parse * __restrict intlog_parse)
	__elogd_nonull(1, 2) __elogd_nothrow __leaf;

extern int
elogd_log_enable(void) __leaf __warn_result;

#endif /* _ELOGD_LOG_H */
