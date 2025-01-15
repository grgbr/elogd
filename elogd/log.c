/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "log.h"
#include "intern.h"

struct elog_multi                   elogd_logger;

static const struct elog_stdio_conf elogd_stdlog_dflt = {
	.super.severity = CONFIG_ELOGD_STDLOG_SEVERITY,
	.format         = ELOG_TAG_FMT | ELOG_SEVERITY_FMT
};

static struct elogd_intern *        elogd_intlog;
static const struct elog_conf       elogd_intlog_dflt = {
	.severity = CONFIG_ELOGD_INTLOG_SEVERITY
};

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

	if (arg) {
		if (elog_parse_stdio_severity(parse, &elogd_conf.stdlog, arg)) {
			elogd_early_err("%s.\n", parse->error);
			return EXIT_FAILURE;
		}

#if !defined(CONFIG_ELOGD_DEBUG)
		if (elogd_conf.stdlog.super.severity >= ELOG_DEBUG_SEVERITY) {
			elogd_early_err("unexpected stdio log severity.\n");
			return EXIT_FAILURE;
		}
#endif /* !defined(CONFIG_ELOGD_DEBUG) */
	}
	else
		elogd_conf.stdlog.super.severity = -1;

	return EXIT_SUCCESS;
}

int
elogd_log_parse_intern(struct elog_parse * __restrict parse,
                       const char * __restrict        arg)

{
	elogd_assert(elogd_pid > 0);
	elogd_assert(parse);

	if (arg) {
		if (elog_parse_severity(parse, &elogd_conf.intlog, arg)) {
			elogd_early_err("%s.\n", parse->error);
			return EXIT_FAILURE;
		}

#if !defined(CONFIG_ELOGD_DEBUG)
		if (elogd_conf.intlog.severity >= ELOG_DEBUG_SEVERITY) {
			elogd_early_err("unexpected internal log severity.\n");
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
	elogd_assert(elogd_pid > 0);
	elogd_assert(stdlog_parse);
	elogd_assert(intlog_parse);

	elog_init_stdio_parse(stdlog_parse,
	                      &elogd_conf.stdlog,
	                      &elogd_stdlog_dflt);
	elog_init_parse(intlog_parse,
	                &elogd_conf.intlog,
	                &elogd_intlog_dflt);
}

void
elogd_log_fini_parse(struct elog_parse * __restrict stdlog_parse,
                     struct elog_parse * __restrict intlog_parse)
{
	elogd_assert(elogd_pid > 0);
	elogd_assert(stdlog_parse);
	elogd_assert(intlog_parse);

	elog_fini_parse(stdlog_parse);
	elog_fini_parse(intlog_parse);
}

int
elogd_log_enable(void)
{
	elogd_assert_conf();
	elogd_assert(elogd_pid > 0);

	elog_setup(ELOG_DFLT_TAG, elogd_pid);

#if defined(CONFIG_ELOGD_DEBUG)
	elog_init_multi(&elogd_logger, elog_destroy);
#else  /* !defined(CONFIG_ELOGD_DEBUG) */
	elog_init_multi(&elogd_logger, elog_fini);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	if (elogd_conf.stdlog.super.severity >= 0) {
		struct elog * stdlog;

		stdlog = elog_create_stdio(&elogd_conf.stdlog);
		if (!stdlog)
			return -ENOMEM;

		if (elog_register_multi_sublog(&elogd_logger, stdlog)) {
#if defined(CONFIG_ELOGD_DEBUG)
			elog_destroy(stdlog);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
			return -ENOMEM;
		}
	}

	if (elogd_conf.intlog.severity >= 0) {
		struct elogd_intern * intlog;

		intlog = elogd_intern_create();
		if (!intlog)
			goto fini;

		if (elog_register_multi_sublog(&elogd_logger,
		                               (struct elog *)intlog)) {
#if defined(CONFIG_ELOGD_DEBUG)
			elog_destroy((struct elog *)intlog);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
			goto fini;
		}

		elogd_intlog = intlog;
	}

	return 0;

fini:
	elog_fini((struct elog *)&elogd_logger);

	return -ENOMEM;
}

void
elogd_log_fini(void)
{
	elogd_assert_conf();
	elogd_assert(elogd_pid > 0);

	elog_fini((struct elog *)&elogd_logger);
}
