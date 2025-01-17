/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_KERN_H
#define _ELOGD_KERN_H

#include "common.h"

struct elogd_kern;
struct elogd_pipe;
struct upoll;

extern struct elogd_kern *
elogd_kern_create(struct elogd_pipe * __restrict  pipe,
                  const struct upoll * __restrict poll)
	__elogd_nonull(1, 2) __leaf __warn_result;

extern void
elogd_kern_destroy(struct elogd_kern * __restrict  kern,
                   const struct upoll * __restrict poll)
	__elogd_nonull(1, 2) __leaf;

#endif /* _ELOGD_KERN_H */
