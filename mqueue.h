/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_MQUEUE_H
#define _ELOGD_MQUEUE_H

#include "common.h"
#include <utils/poll.h>

/* POSIX message queue service processor. */
struct elogd_mqueue {
	struct elogd_queue  queue;
	struct upoll_worker work;
	mqd_t               fd;
};

extern int
elogd_mqueue_open(struct elogd_mqueue * __restrict mqueue,
                  const struct upoll * __restrict  poll)
	__elogd_nonull(1, 2) __leaf __warn_result;

extern void
elogd_mqueue_close(const struct elogd_mqueue * __restrict mqueue,
                   const struct upoll * __restrict        poll)
	__elogd_nonull(1, 2) __leaf;

#endif /* _ELOGD_MQUEUE_H */
