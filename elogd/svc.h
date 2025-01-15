/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_SVC_H
#define _ELOGD_SVC_H

#include "common.h"

struct elogd_svc;
struct elogd_pipe;
struct upoll;

extern struct elogd_svc *
elogd_svc_create(struct elogd_pipe * __restrict  pipe,
                 const struct upoll * __restrict poll)
	__elogd_nonull(1, 2) __leaf __warn_result;

extern void
elogd_svc_destroy(struct elogd_svc * __restrict  svc,
                  const struct upoll * __restrict poll)
	__elogd_nonull(1, 2) __leaf;

#endif /* _ELOGD_SVC_H */
