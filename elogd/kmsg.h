/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_KMSG_H
#define _ELOGD_KMSG_H

#include "common.h"

struct elogd_kmsg;
struct elogd_pipe;
struct upoll;

extern struct elogd_kmsg *
elogd_kmsg_create(struct elogd_pipe * __restrict  pipe,
                  const struct upoll * __restrict poll)
	__elogd_nonull(1, 2) __leaf __warn_result;

extern void
elogd_kmsg_destroy(struct elogd_kmsg * __restrict  kmsg,
                   const struct upoll * __restrict poll)
	__elogd_nonull(1, 2) __leaf;

#endif /* _ELOGD_KMSG_H */
