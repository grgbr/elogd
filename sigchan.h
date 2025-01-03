/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_SIGCHAN_H
#define _ELOGD_SIGCHAN_H

#include <utils/poll.h>

struct elogd_sigchan {
	struct upoll_worker work;
	int                 fd;
};

extern int
elogd_sigchan_open(struct elogd_sigchan * __restrict chan,
                   const struct upoll * __restrict   poll)
	__elogd_nonull(1, 2) __leaf;

extern void
elogd_sigchan_close(const struct elogd_sigchan * __restrict chan,
                    const struct upoll * __restrict         poll)
	__elogd_nonull(1, 2) __leaf;

#endif /* _ELOGD_SIGCHAN_H */
