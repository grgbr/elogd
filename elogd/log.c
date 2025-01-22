/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "log.h"
#include "intern.h"

static struct elogd_intern * elogd_intlog;

struct elogd_intern *
elogd_log_the_intern(void)
{
	elogd_assert_conf();
	elogd_assert(elogd_pid > 0);

	return elogd_intlog;
}

int
elogd_log_parse_std(struct elog_parse * __restrict parse,
                    const char * __restrict        arg)
{
	elogd_assert(elogd_pid > 0);
	elogd_assert(parse);

	if (arg)
		return elogd_parse_stdlog(arg, parse, &elogd_conf.stdlog);

	elogd_conf.stdlog.super.severity = -1;

	return 0;
}

int
elogd_log_parse_intern(struct elog_parse * __restrict parse,
                       const char * __restrict        arg)

{
	elogd_assert(elogd_pid > 0);
	elogd_assert(parse);

	if (arg) {
		if (elog_parse_severity(parse, &elogd_conf.intlog, arg)) {
			elogd_early_log("%s.", parse->error);
			return EXIT_FAILURE;
		}

#if !defined(CONFIG_ELOGD_DEBUG)
		if (elogd_conf.intlog.severity >= ELOG_DEBUG_SEVERITY) {
			elogd_early_log("unexpected internal log severity.");
			return EXIT_FAILURE;
		}
#endif /* !defined(CONFIG_ELOGD_DEBUG) */
	}
	else
		elogd_conf.intlog.severity = -1;

	return EXIT_SUCCESS;
}

void
elogd_log_init_parse(struct elog_parse * __restrict stdlog_parse,
                     struct elog_parse * __restrict intlog_parse)
{
	elogd_assert(stdlog_parse);
	elogd_assert(intlog_parse);

	static const struct elog_conf intlog_dflt = {
		.severity = CONFIG_ELOGD_INTLOG_SEVERITY
	};

	elogd_parse_init(stdlog_parse, &elogd_conf.stdlog);
	elog_init_parse(intlog_parse, &elogd_conf.intlog, &intlog_dflt);
}

void
elogd_log_fini_parse(struct elog_parse * __restrict stdlog_parse,
                     struct elog_parse * __restrict intlog_parse)
{
	elogd_assert(elogd_pid > 0);
	elogd_assert(stdlog_parse);
	elogd_assert(intlog_parse);

	elog_fini_parse(intlog_parse);
	elogd_parse_fini(stdlog_parse);
}

int
elogd_log_enable(void)
{
	elogd_assert_conf();
	elogd_assert(elogd_pid > 0);
	elogd_assert((elogd_conf.stdlog.super.severity >= 0) ||
	             (elogd_conf.intlog.severity >= 0));

	elog_setup(ELOG_DFLT_TAG, elogd_pid);

	if ((elogd_conf.stdlog.super.severity >= 0) &&
	    (elogd_conf.intlog.severity >= 0)) {
#if defined(CONFIG_ELOGD_DEBUG)
		elogd_logger = (struct elog *)elog_create_multi(elog_destroy);
#else  /* !defined(CONFIG_ELOGD_DEBUG) */
		elogd_logger = (struct elog *)elog_create_multi(elog_fini);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
		if (!elogd_logger)
			return -ENOMEM;
	}

	if (elogd_conf.stdlog.super.severity >= 0) {
		struct elog * stdlog;

		stdlog = (struct elog *)elog_create_stdio(&elogd_conf.stdlog);
		if (!stdlog)
			goto fini;

		if (!elogd_logger) {
			elogd_logger = stdlog;
			return 0;
		}

		if (elog_register_multi_sublog(
			(struct elog_multi *)elogd_logger, stdlog)) {
			elogd_destroy_logger(stdlog);
			goto fini;
		}
	}

	if (elogd_conf.intlog.severity >= 0) {
		elogd_intlog = elogd_intern_create();
		if (!elogd_intlog)
			goto fini;

		if (!elogd_logger) {
			elogd_logger = (struct elog *)elogd_intlog;
			return 0;
		}

		if (elog_register_multi_sublog(
			(struct elog_multi *)elogd_logger,
			(struct elog *)elogd_intlog)) {
			elogd_destroy_logger((struct elog *)elogd_intlog);
			goto fini;
		}
	}

	return 0;

fini:
	elogd_log_fini();

	return -ENOMEM;
}
