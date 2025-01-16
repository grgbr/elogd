/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_LOG_H
#define _ELOGD_LOG_H

#include "common.h"

#define elogd_early_err(_format, ...) \
	{ \
		if (elogd_conf.stdlog.super.severity >= ELOG_ERR_SEVERITY) \
			fprintf(stderr, \
			        "%s: {   err} " _format "\n", \
			        program_invocation_short_name, \
			        ## __VA_ARGS__); \
	}

#define elogd_early_warn(_format, ...) \
	{ \
		if (elogd_conf.stdlog.super.severity >= ELOG_WARNING_SEVERITY) \
			fprintf(stderr, \
			        "%s: {  warn} " _format "\n", \
			        program_invocation_short_name, \
			        ## __VA_ARGS__); \
	}

#define elogd_early_info(_format, ...) \
	{ \
		if (elogd_conf.stdlog.super.severity >= ELOG_INFO_SEVERITY) \
			fprintf(stderr, \
			        "%s: {  info} " _format "\n", \
			        program_invocation_short_name, \
			        ## __VA_ARGS__); \
	}

#if defined(CONFIG_ELOGD_DEBUG)

#define elogd_early_debug(_format, ...) \
	{ \
		if (elogd_conf.stdlog.super.severity >= ELOG_DEBUG_SEVERITY) \
			fprintf(stderr, \
			        "%s: { debug} " _format "\n", \
			        program_invocation_short_name, \
			        ## __VA_ARGS__); \
	}

#else  /* !defined(CONFIG_ELOGD_DEBUG) */

#define elogd_early_debug(_format, ...)

#endif /* defined(CONFIG_ELOGD_DEBUG) */

extern struct elog_multi elogd_logger;

#define elogd_err(_format, ...) \
	elog_err(&elogd_logger, _format, ## __VA_ARGS__)

#define elogd_warn(_format, ...) \
	elog_warn(&elogd_logger, _format, ## __VA_ARGS__)

#define elogd_notice(_format, ...) \
	elog_notice(&elogd_logger, _format, ## __VA_ARGS__)

#define elogd_info(_format, ...) \
	elog_info(&elogd_logger, _format, ## __VA_ARGS__)

#if defined(CONFIG_ELOGD_DEBUG)

#define elogd_debug(_format, ...) \
	elog_debug(&elogd_logger, _format, ## __VA_ARGS__)

#else  /* !defined(CONFIG_ELOGD_DEBUG) */

#define elogd_debug(_format, ...)

#endif /* defined(CONFIG_ELOGD_DEBUG) */

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

extern void
elogd_log_fini(void) __leaf;

#endif /* _ELOGD_LOG_H */
