/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "log.h"
#include "intern.h"

struct elog_multi                   elogd_logger;

static struct elog_stdio            elogd_stdlog;
static const struct elog_stdio_conf elogd_stdlog_dflt = {
	.super.severity = CONFIG_ELOGD_STDLOG_SEVERITY,
	.format         = ELOG_TAG_FMT | ELOG_SEVERITY_FMT
};

static struct elogd_intern          elogd_intlog;
static const struct elog_conf       elogd_intlog_dflt = {
	.severity = CONFIG_ELOGD_INTERN_SEVERITY
};

struct elogd_intern *
elogd_log_the_intern(void)
{
	return &elogd_intlog;
}

int
elogd_log_parse_std(struct elog_parse * __restrict parse,
                    const char * __restrict        arg)
{
	elogd_assert(parse);
	elogd_assert(arg);

	if (elog_parse_stdio_severity(parse, &elogd_conf.stdlog, arg)) {
		elogd_early_err("%s.\n", parse->error);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int
elogd_log_parse_intern(struct elog_parse * __restrict parse,
                       const char * __restrict        arg)

{
	elogd_assert(parse);
	elogd_assert(arg);

	if (elog_parse_severity(parse, &elogd_conf.intlog, arg)) {
		elogd_early_err("%s.\n", parse->error);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

void
elogd_log_init_parse(struct elog_parse * __restrict stdlog_parse,
                     struct elog_parse * __restrict intlog_parse)
{
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
	int err __unused;

	/*
	 * Cannot fail here since severity has been validated by
	 * elogd_log_parse_std() other configuration options are hard coded
	 * as default values.
	 */
	err = elog_realize_parse(stdlog_parse,
	                         (struct elog_conf *)&elogd_conf.stdlog);
	assert(!err);

	/*
	 * Cannot fail here since severity has been validated by
	 * elogd_log_parse_intern() other configuration options are hard coded
	 * as default values.
	 */
	err = elog_realize_parse(intlog_parse,
	                         (struct elog_conf *)&elogd_conf.intlog);
	assert(!err);

	elog_fini_parse(stdlog_parse);
	elog_fini_parse(intlog_parse);
}

int
elogd_log_enable(void)
{
	elog_setup(ELOG_DFLT_TAG, elogd_pid);

	elog_init_multi(&elogd_logger, elog_fini);

	elog_init_stdio(&elogd_stdlog, &elogd_conf.stdlog);
	if (elog_register_multi_sublog(&elogd_logger,
	                               (struct elog *)&elogd_stdlog))
		goto fini_multi;

	elogd_intern_init(&elogd_intlog);
	if (elog_register_multi_sublog(&elogd_logger,
	                               (struct elog *)&elogd_intlog))
		goto fini_multi;

	return 0;

fini_multi:
	elog_fini((struct elog *)&elogd_logger);

	return -ENOMEM;
}

void
elogd_log_fini(void)
{
	elog_fini((struct elog *)&elogd_logger);
}
