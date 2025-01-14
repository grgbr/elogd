/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_INTERN_H
#define _ELOGD_INTERN_H

#include "common.h"

/* Internal message queue processor. */
struct elogd_intern {
	struct elog        elog;
	bool               on;
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

extern void
elogd_intern_init(struct elogd_intern * __restrict intern)
	__elogd_nonull(1) __leaf;

#endif /* _ELOGD_INTERN_H */
