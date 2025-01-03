/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_KMSG_H
#define _ELOGD_KMSG_H

#include "common.h"
#include <utils/poll.h>

/* Kernel ring-buffer processor. */
struct elogd_kmsg {
	struct elogd_queue  queue;
	struct upoll_worker work;
	int                 dev_fd;
	uint64_t *          seqno;
	int                 stat_fd;
};

extern int
elogd_kmsg_open(struct elogd_kmsg * __restrict  kmsg,
                const struct upoll * __restrict poll)
	__elogd_nonull(1, 2) __leaf;

extern void
elogd_kmsg_close(const struct elogd_kmsg * __restrict kmsg,
                 const struct upoll * __restrict      poll)
	__elogd_nonull(1, 2) __leaf;

#endif /* _ELOGD_KMSG_H */
