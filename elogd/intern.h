/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_INTERN_H
#define _ELOGD_INTERN_H

#include "common.h"

/*
 * eLogd internal message source.
 *
 * Meant to process and queue internal eLogd messages.
 */
struct elogd_intern {
	/*
	 * Act as an elog object so that it may be included into a
	 * `struct elog_multi' logging chain.
	 */
	struct elog        elog;
	/* Wether we are stopped or not... */
	bool               on;
	/* Queue of internal eLogd messages. */
	struct elogd_queue queue;
};

static inline __elogd_nonull(1) __elogd_pure __elogd_nothrow __returns_nonull
struct elogd_queue *
elogd_intern_queue(const struct elogd_intern * __restrict intern)
{
	elogd_assert(intern);

STROLL_IGNORE_WARN("-Wcast-qual")
	return (struct elogd_queue *)&intern->queue;
STROLL_RESTORE_WARN
}

static inline __elogd_nonull(1) __elogd_pure __elogd_nothrow
bool
elogd_intern_alive(const struct elogd_intern * __restrict intern)
{
	elogd_assert(intern);

	return !elogd_queue_empty(&intern->queue);
}

static inline __elogd_nonull(1) __elogd_nothrow
void
elogd_intern_stop(struct elogd_intern * __restrict intern)
{
	elogd_assert(intern);

	intern->on = false;
}

extern struct elogd_intern *
elogd_intern_create(void) __elogd_nothrow __leaf __warn_result;

#endif /* _ELOGD_INTERN_H */
