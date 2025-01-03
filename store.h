/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_STORE_H
#define _ELOGD_STORE_H

#include "common.h"

/* Logging output store file processor. */
struct elogd_store {
	int    fd;
	size_t size;
	int    dir;
	char * base;
};

extern void
elogd_store_flush(struct elogd_store * __restrict store,
                  struct elogd_queue * __restrict queue)
	__elogd_nonull(1, 2) __leaf;

extern int
elogd_store_open(struct elogd_store * __restrict store)
	__elogd_nonull(1) __leaf __warn_result;

extern void
elogd_store_close(struct elogd_store * __restrict store)
	__elogd_nonull(1) __leaf;

#endif /* _ELOGD_STORE_H */
