/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_BUILTIN_H
#define _ELOGD_BUILTIN_H

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif /* !defined(_GNU_SOURCE) */

#include "elogd/config.h"
#include <elog/elog.h>

#if defined(CONFIG_ELOGD_ASSERT)

#include <stroll/assert.h>

#define __elogd_nonull(_arg_index, ...)
#define __elogd_pure
#define __elogd_const
#define __elogd_nothrow
#define elogd_assert(_expr) \
	stroll_assert(program_invocation_short_name, _expr)

#else  /* !defined(CONFIG_ELOGD_ASSERT) */

#define __elogd_nonull(_arg_index, ...) __nonull(_arg_index, ## __VA_ARGS__)
#define __elogd_pure                    __pure
#define __elogd_const                   __const
#define __elogd_nothrow                 __nothrow
#define elogd_assert(_expr)             do { } while (0)

#endif /* defined(CONFIG_ELOGD_ASSERT) */

extern pid_t         elogd_pid;

extern struct elog * elogd_logger;

extern void
elogd_log_init(struct elog * __restrict logger)
	__elogd_nonull(1) __elogd_nothrow __leaf;

extern void
elogd_log_fini(void);

extern int
elogd_parse_stdlog(const char * __restrict             arg,
                   struct elog_parse * __restrict      parse,
                   struct elog_stdio_conf * __restrict config)
	__elog_nonull(1, 2, 3) __elogd_nothrow __leaf __warn_result;

extern int
elogd_parse_path(const char * __restrict  arg,
                 const char * __restrict  kind,
                 const char ** __restrict path)
	__elog_nonull(1, 2, 3) __elogd_nothrow __leaf __warn_result;

extern int
elogd_parse_group_name(const char * __restrict  arg,
                       const char * __restrict  kind,
                       const char ** __restrict name)
	__elog_nonull(1, 2, 3) __elogd_nothrow __leaf __warn_result;

extern void
elogd_parse_init(struct elog_parse * __restrict      parse,
                 struct elog_stdio_conf * __restrict config)
	__elog_nonull(1, 2) __elogd_nothrow __leaf;

static inline __elog_nonull(1) __elogd_nothrow
void
elogd_parse_fini(struct elog_parse *__restrict parse)
{
	elog_fini_parse(parse);
}

#endif /* _ELOGD_BUILTIN_H */
