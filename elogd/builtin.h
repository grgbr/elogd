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
#include <stdio.h>

/* Pathname to directory where volatile internal state data are stored. */
#define ELOGD_RUNSTATEDIR_DPATH \
	CONFIG_ELOGD_RUNSTATEDIR "/elogd"
#define ELOGD_RUNSTATEDIR_PATH \
	compile_eval(sizeof(CONFIG_ELOGD_RUNSTATEDIR) > 1, \
	             ELOGD_RUNSTATEDIR_DPATH, \
	             "CONFIG_ELOGD_RUNSTATEDIR string empty")

/* Pathname to the kernel log ring-buffer character device file. */
#define ELOGD_KERN_DPATH       "/dev/kmsg"

#define ELOGD_KERN_MAJOR       (1)
#define ELOGD_KERN_MINOR       (11)

#define ELOGD_USER \
	compile_eval(sizeof(CONFIG_ELOGD_USER) > 1, \
	             CONFIG_ELOGD_USER, \
	             "CONFIG_ELOGD_USER string empty")

#define ELOGD_STORE_GROUP \
	compile_eval(sizeof(CONFIG_ELOGD_STORE_GROUP) > 1, \
	             CONFIG_ELOGD_STORE_GROUP, \
	             "CONFIG_ELOGD_STORE_GROUP string empty")

#define ELOGD_RUNSTATEDIR_GROUP \
	compile_eval(sizeof(CONFIG_ELOGD_RUNSTATEDIR_GROUP) > 1, \
	             CONFIG_ELOGD_RUNSTATEDIR_GROUP, \
	             "CONFIG_ELOGD_RUNSTATEDIR_GROUP string empty")

#if defined(CONFIG_ELOGD_DEBUG)
#define ELOGD_USAGE_DEBUG_LEVEL "|debug"
#else  /* !defined(CONFIG_ELOGD_DEBUG) */
#define ELOGD_USAGE_DEBUG_LEVEL
#endif /* defined(CONFIG_ELOGD_DEBUG) */
#define ELOGD_USAGE_LEVEL \
	"Where:\n" \
	"    LEVEL := none|dflt|emerg|alert|crit|err|warn|notice|info" \
	ELOGD_USAGE_DEBUG_LEVEL

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

#define elogd_early_log(_format, ...) \
	(void)fprintf(stderr, \
	              "%s: " _format "\n", \
	              program_invocation_short_name, \
	              ## __VA_ARGS__)

extern pid_t         elogd_pid;

extern struct elog * elogd_logger;

static inline __elogd_nonull(2) __printf(2, 3) __elogd_nothrow
void
elogd_log(enum elog_severity severity, const char * __restrict format, ...)
{
	elogd_assert(elogd_pid > 0);
	elogd_assert(format);
	elogd_assert(format[0]);

	if (elogd_logger) {
		va_list args;

		va_start(args, format);
		elog_vlog(elogd_logger, severity, format, args);
		va_end(args);
	}
}

#define elogd_err(_format, ...) \
	elogd_log(ELOG_ERR_SEVERITY, _format, ## __VA_ARGS__)

#define elogd_warn(_format, ...) \
	elogd_log(ELOG_WARNING_SEVERITY, _format, ## __VA_ARGS__)

#define elogd_notice(_format, ...) \
	elogd_log(ELOG_NOTICE_SEVERITY, _format, ## __VA_ARGS__)

#define elogd_info(_format, ...) \
	elogd_log(ELOG_INFO_SEVERITY, _format, ## __VA_ARGS__)

#if defined(CONFIG_ELOGD_DEBUG)

#define elogd_debug(_format, ...) \
	elogd_log(ELOG_DEBUG_SEVERITY, _format, ## __VA_ARGS__)

#else  /* !defined(CONFIG_ELOGD_DEBUG) */

#define elogd_debug(_format, ...)

#endif /* defined(CONFIG_ELOGD_DEBUG) */

extern int
elogd_parse_stdlog(const char * __restrict             arg,
                   struct elog_parse * __restrict      parse,
                   struct elog_stdio_conf * __restrict config)
	__elog_nonull(1, 2, 3) __elogd_nothrow __leaf __warn_result;

extern ssize_t
elogd_parse_path(const char * __restrict  arg,
                 const char * __restrict  kind,
                 const char ** __restrict path)
	__elog_nonull(1, 2, 3) __elogd_nothrow __leaf __warn_result;

extern int
elogd_parse_rundir_path(const char * __restrict  arg,
                        const char ** __restrict path,
                        size_t * __restrict      length)
	__elog_nonull(1, 2, 3) __elogd_nothrow __warn_result;

extern int
elogd_parse_user_name(const char * __restrict  arg,
                      const char ** __restrict user)
	__elog_nonull(1, 2) __elogd_nothrow __leaf __warn_result;

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

#if defined(CONFIG_ELOGD_DEBUG)

static inline __elogd_nonull(1)
void
elogd_destroy_logger(struct elog * __restrict logger)
{
	elogd_assert(logger);
	elogd_assert(elogd_pid > 0);

	elog_destroy(logger);
}

#else  /* !defined(CONFIG_ELOGD_DEBUG) */

static inline __elogd_nonull(1)
void
elogd_destroy_logger(struct elog * __restrict logger)
{
	elogd_assert(logger);
	elogd_assert(elogd_pid > 0);

	elog_fini(logger);
}

#endif /* defined(CONFIG_ELOGD_DEBUG) */

static inline
void
elogd_log_fini(void)
{
	elogd_assert(elogd_pid > 0);

	if (elogd_logger)
		elogd_destroy_logger(elogd_logger);
}

extern ssize_t
elogd_make_path(char ** __restrict      result,
                const char * __restrict dir_path,
                size_t                  dir_len,
                const char * __restrict file_name,
                size_t                  file_len)
	__elogd_nonull(1, 2, 4) __elogd_nothrow __leaf __warn_result;

extern int
elogd_make_lock_path(char ** __restrict      result,
                     const char * __restrict path,
                     size_t                  length)
	__elogd_nonull(1, 2) __elogd_nothrow __warn_result;

extern int
elogd_lock(const char * __restrict path) __elogd_nonull(1);

extern void
elogd_unlock(void);

#endif /* _ELOGD_BUILTIN_H */
