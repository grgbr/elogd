/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_PIPE_H
#define _ELOGD_PIPE_H

#include "common.h"
#include "store.h"

struct elogd_kmsg;
struct elogd_svc;
struct elogd_intern;
struct upoll;

#if defined(CONFIG_ELOGD_MQUEUE)
struct elogd_mqueue;
#endif /* defined(CONFIG_ELOGD_MQUEUE) */

#define ELOGD_PIPE_POLL_NR (3U)

/*
 * High-level pipeline object muxing pollable message sources into a single
 * output queue.
 */
struct elogd_pipe {
	/* Count of active message queues. */
	unsigned int          cnt;
	/*
	 * Array of active message queues: 1 array slot for each "pollable"
	 * input message source queue + 1 for internal message source
	 * + 1 for output queue.
	 */
	struct elogd_queue *  alive[ELOGD_PIPE_POLL_NR + 2];
	/* Output message queue used as input to message store. */
	struct elogd_queue    outq;
	/* Kernel ring-buffer pollable message source. */
	struct elogd_kmsg *   kmsg;
	/* Syslog socket based service pollable message source. */
	struct elogd_svc *    svc;
#if defined(CONFIG_ELOGD_MQUEUE)
	/* POSIX message queue based service pollable message source. */
	struct elogd_mqueue * mqueue;
#endif /* defined(CONFIG_ELOGD_MQUEUE) */
	/* Internal message source. */
	struct elogd_intern * intern;
	/* Output message store. */
	struct elogd_store    store;
};

extern void
elogd_pipe_on_alive(struct elogd_pipe * __restrict  pipe,
                    struct elogd_queue * __restrict queue)
	__elogd_nonull(1, 2) __elogd_nothrow __leaf;

extern bool
elogd_pipe_process_starting(struct elogd_pipe * __restrict pipe)
	__elogd_nonull(1) __elogd_nothrow;

extern int
elogd_pipe_process_timeout(const struct elogd_pipe * __restrict pipe)
	__elogd_nonull(1) __elogd_nothrow __leaf;

extern void
elogd_pipe_process_running(struct elogd_pipe * __restrict pipe)
	__elogd_nonull(1) __elogd_nothrow;

extern int
elogd_pipe_stop(struct elogd_pipe * __restrict pipe)
	__elogd_nonull(1) __elogd_nothrow;

extern int
elogd_pipe_open(struct elogd_pipe * __restrict  pipe,
                unsigned int                    nr,
                const struct upoll * __restrict poll)
	__elogd_nonull(1, 3);

extern void
elogd_pipe_close(struct elogd_pipe * __restrict  pipe,
                 const struct upoll * __restrict poll)
	__elogd_nonull(1, 2) __leaf;

#endif /* _ELOGD_PIPE_H */
