/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_SOCK_H
#define _ELOGD_SOCK_H

#include "common.h"

struct elogd_sock;
struct elogd_pipe;
struct upoll;

extern struct elogd_sock *
elogd_sock_create(struct elogd_pipe * __restrict  pipe,
                  const struct upoll * __restrict poll)
	__elogd_nonull(1, 2) __leaf __warn_result;

extern void
elogd_sock_destroy(struct elogd_sock * __restrict  sock,
                   const struct upoll * __restrict poll)
	__elogd_nonull(1, 2) __leaf;

#endif /* _ELOGD_SOCK_H */
