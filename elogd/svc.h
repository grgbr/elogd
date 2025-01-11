/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_SVC_H
#define _ELOGD_SVC_H

#include "common.h"
#include <utils/poll.h>
#include <utils/unsk.h>

/* Syslog service processor. */
struct elogd_svc {
	struct elogd_queue      queue;
	struct upoll_worker     work;
	struct unsk_svc         unsk;
	struct elogd_pipeline * pipe;
};

extern int
elogd_svc_open(struct elogd_svc * __restrict      svc,
               struct elogd_pipeline * __restrict pipe,
               const struct upoll * __restrict    poll)
	__elogd_nonull(1, 2, 3) __leaf __warn_result;

extern void
elogd_svc_close(const struct elogd_svc * __restrict svc,
                const struct upoll * __restrict     poll)
	__elogd_nonull(1, 2) __leaf;

#endif /* _ELOGD_SVC_H */
