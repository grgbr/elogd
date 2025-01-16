/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "intern.h"
#include "log.h"
#include <utils/time.h>

static __elogd_nonull(2) __printf(2, 0)
struct elogd_line *
elogd_intern_create_line(enum elog_severity      severity,
                         const char * __restrict format,
                         va_list                 args)
{
	elogd_assert_conf();
	elogd_assert(severity <= elogd_conf.intlog.severity);
	elogd_assert(elogd_pid > 0);
	elogd_assert(format);

	struct elogd_line * line;
	int                 ret;

	line = elogd_line_create();
	if (!line)
		return NULL;

	ret = vsnprintf(line->data, sizeof(line->data), format, args);
	if (ret <= 0)
		goto release;
	ret = (int)stroll_min((size_t)ret, sizeof(line->data) - 2);
	line->data[ret++] = '\n';
	line->data[ret] = '\0';

	utime_boot_now(&line->tstamp);
	line->facility = LOG_SYSLOG;
	line->severity = severity;
	line->tag_len = sizeof("elogd") - 1;
	line->tag = "elogd";
	line->pid = elogd_pid;

	line->vector[ELOGD_LINE_MSG_IOVEC].iov_base = (void *)line->data;
	line->vector[ELOGD_LINE_MSG_IOVEC].iov_len = (size_t)ret;

	return line;

release:
	elogd_line_destroy(line);

	return NULL;
}

static __elogd_nonull(1, 3) __printf(3, 0)
void
elogd_intern_vlog(struct elog * __restrict logger,
                  enum elog_severity       severity,
                  const char * __restrict  format,
                  va_list                  args)
{
	elogd_assert_conf();
	elogd_assert(elogd_pid > 0);
	elogd_assert(logger);
	elogd_assert((severity == ELOG_CURRENT_SEVERITY) ||
	             !(severity & ~LOG_PRIMASK));
	elogd_assert(format);

	struct elogd_intern * intern = (struct elogd_intern *)logger;

	if (!intern->on)
		return;

	if (severity == ELOG_CURRENT_SEVERITY)
		severity = elogd_conf.intlog.severity;

	if (severity <= elogd_conf.intlog.severity) {
		if (!elogd_queue_full(&intern->queue)) {
			struct elogd_line * line;

			line = elogd_intern_create_line(severity, format, args);
			if (line)
				elogd_nqueue(&intern->queue, line);
		}
	}
}

static __elogd_nonull(1)
void
elogd_intern_close(struct elog * __restrict logger)
{
	elogd_assert_conf();
	elogd_assert(elogd_pid > 0);
	elogd_assert(logger);

	const struct elogd_intern * intern = (const struct elogd_intern *)
	                                     logger;

	elogd_early_debug("closing internal queue...");

	elogd_queue_fini(&intern->queue);
}

static const struct elog_ops elogd_intern_ops = {
	.vlog  = elogd_intern_vlog,
	.close = elogd_intern_close
};

struct elogd_intern *
elogd_intern_create(void)
{
	elogd_assert_conf();
	elogd_assert(elogd_pid > 0);

	struct elogd_intern * intern;

	intern = malloc(sizeof(*intern));
	if (!intern) {
		errno = -ENOMEM;
		return NULL;
	}

	elogd_early_debug("initializing internal queue...");

	intern->elog.ops = &elogd_intern_ops;
	intern->on = true;
	elogd_queue_init(&intern->queue, elogd_conf.intlog_fetch);

	elogd_info("internal queue initialized.");

	return intern;
}
