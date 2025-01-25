/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "pipe.h"
#include "log.h"
#include "sock.h"
#include "kern.h"
#include "mqueue.h"
#include "intern.h"
#include <utils/time.h>

#if defined(CONFIG_ELOGD_MQUEUE)

#define elogd_pipe_has_mqueue(_pipe) \
	(!!((_pipe)->mqueue))

#else /* !defined(CONFIG_ELOGD_MQUEUE) */

#define elogd_pipe_has_mqueue(_pipe) \
	(0)

#endif /* defined(CONFIG_ELOGD_MQUEUE) */

#define elogd_pipe_assert(_pipe) \
	elogd_assert(_pipe); \
	elogd_assert((_pipe)->kern || \
	             (_pipe)->sock || \
	             elogd_pipe_has_mqueue(_pipe))

/* Reset active message queue tracking logic. */
static __elogd_nonull(1)
void
elogd_pipe_reset_alive(struct elogd_pipe * __restrict pipe)
{
	elogd_pipe_assert(pipe);

	/* Reset count of active queues. */
	pipe->cnt = 0;

	if (!elogd_queue_empty(&pipe->outq))
		/*
		 * Output message queue contains partially processed messages:
		 * mark it as active.
		 */
		elogd_pipe_on_alive(pipe, &pipe->outq);

	if (pipe->intern && elogd_intern_alive(pipe->intern))
		/*
		 * Internal message queue contains partially processed messages:
		 * mark it as active.
		 */
		elogd_pipe_on_alive(pipe, elogd_intern_queue(pipe->intern));
}

/*
 * Merge active queue messages according to time ordering into output message
 * queue.
 * All active queues already contain messages (pre)sorted according to time
 * ordering.
 */
static __elogd_nonull(1)
void
elogd_pipe_merge_queues(struct elogd_pipe * __restrict pipe)
{
	elogd_pipe_assert(pipe);
	elogd_assert(pipe->cnt);
	elogd_assert(pipe->alive[0]);

	if (pipe->alive[0] != &pipe->outq) {
		/*
		 * Output queue is not alive, i.e., empty. Move messages from
		 * first active source queue into it.
		 */
		elogd_assert(elogd_queue_empty(&pipe->outq));
		elogd_assert(!elogd_queue_empty(pipe->alive[0]));

		elogd_queue_move(&pipe->outq, pipe->alive[0]);
	}

	if (pipe->cnt > 1) {
		/*
		 * Merging is required since more that 1 queue are active.
		 * Make the output queue the resulting merged queue, placing it
		 * at first slot position in the `alive' array, then do the
		 * merge.
		 */
		pipe->alive[0] = &pipe->outq;
		elogd_queue_kwmerge(pipe->alive, pipe->cnt);
	}
}

static __elogd_nonull(1, 2)
void
elogd_realtime_offset(struct timespec * __restrict real,
                      struct timespec * __restrict boot)
{
	elogd_assert(real);
	elogd_assert(boot);

	utime_boot_now(boot);
	utime_realtime_now(real);

	int ret __unused;

	ret = utime_tspec_sub(real, boot);
	elogd_assert(ret >= 0);
#if 0
	if (utime_tspec_after(real, boot)) {
		int ret __unused;

		ret = utime_tspec_sub(real, boot);
		elogd_assert(ret >= 0);
	}
	else {
		real->tv_sec = 0;
		real->tv_nsec = 0;
	}
#endif
}

static __elogd_nonull(1)
void
elogd_pipe_flush_outq(struct elogd_pipe * __restrict pipe)
{
	elogd_pipe_assert(pipe);

	struct stroll_dlist_node * node;
	struct timespec            real;
	struct timespec            boot;

	elogd_realtime_offset(&real, &boot);

	elogd_queue_foreach_node(&pipe->outq, node)
		elogd_line_fill_rfc3164(elogd_line_from_node(node), &real);
}

static __elogd_nonull(1)
unsigned int
elogd_pipe_fulfill_outq(struct elogd_pipe * __restrict pipe)
{
	elogd_pipe_assert(pipe);

	unsigned int cnt = 0;

	if (!elogd_queue_full(&pipe->outq)) {
		struct timespec real;
		struct timespec boot;

		elogd_realtime_offset(&real, &boot);

		if (utime_tspec_sub_sec(&boot, (int)elogd_conf.delay) >= 0) {
			struct stroll_dlist_node * node;

			elogd_queue_foreach_node(&pipe->outq, node) {
				struct elogd_line * line =
					elogd_line_from_node(node);

				if (utime_tspec_after(&line->tstamp, &boot))
					break;

				elogd_line_fill_rfc3164(line, &real);
				cnt++;
			}
		}
	}
	else {
		/*
		 * Output queue is full: prepare as many messages as we
		 * can for later submission to message store.
		 */
		elogd_pipe_flush_outq(pipe);
		cnt = elogd_queue_busy_count(&pipe->outq);
	}

	return cnt;
}

/*
 * Mark a message queue as active, i.e., containing messages that have not yet
 * travelled to the message store.
 */
void
elogd_pipe_on_alive(struct elogd_pipe * __restrict  pipe,
                    struct elogd_queue * __restrict queue)
{
	elogd_pipe_assert(pipe);
	elogd_assert(queue);

	pipe->alive[pipe->cnt++] = queue;
}

bool
elogd_pipe_process_starting(struct elogd_pipe * __restrict pipe)
{
	elogd_pipe_assert(pipe);

	bool started = false;

	if (pipe->cnt)
		elogd_pipe_merge_queues(pipe);

	if (((pipe->cnt == 1) && (pipe->alive[0] == &pipe->outq)) ||
	    elogd_queue_full(&pipe->outq)) {
		elogd_assert(!elogd_queue_empty(&pipe->outq));

		unsigned int cnt;

		cnt = elogd_pipe_fulfill_outq(pipe);
		if (cnt)
			elogd_store_write(&pipe->store, &pipe->outq, cnt);

		started = true;
	}

	elogd_pipe_reset_alive(pipe);

	return started;
}

int
elogd_pipe_process_timeout(const struct elogd_pipe * __restrict pipe)
{
	elogd_pipe_assert(pipe);

	if (elogd_queue_empty(&pipe->outq))
		/* Tell caller to wait forever... */
		return -1;

	if (!elogd_queue_full(&pipe->outq)) {
		struct timespec tstamp;
		struct timespec now;

		tstamp = elogd_queue_peek(&pipe->outq)->tstamp;
		utime_tspec_add_sec_clamp(&tstamp, (int)elogd_conf.delay);
		utime_boot_now(&now);
		if (utime_tspec_sub(&tstamp, &now) <= 0)
			/* There is at least 1 message to store now. */
			return 0;

		/*
		 * Return line timestamp - current time expressed as
		 * milliseconds.
		 */
		return utime_msec_from_tspec_upper_clamp(&tstamp);
	}
	else
		/* Output queue is full: tell caller not to wait. */
		return 0;
}

void
elogd_pipe_process_running(struct elogd_pipe * __restrict pipe)
{
	elogd_pipe_assert(pipe);

	if (pipe->cnt) {
		unsigned int cnt;

		elogd_pipe_merge_queues(pipe);

		cnt = elogd_pipe_fulfill_outq(pipe);
		if (cnt)
			elogd_store_write(&pipe->store, &pipe->outq, cnt);

		elogd_pipe_reset_alive(pipe);
	}
}

int
elogd_pipe_stop(struct elogd_pipe * __restrict pipe)
{
	elogd_pipe_assert(pipe);

	int ret = 0;

	elogd_pipe_reset_alive(pipe);

	if (pipe->cnt)
		elogd_pipe_merge_queues(pipe);

	elogd_pipe_flush_outq(pipe);
	while (true) {
		unsigned int cnt;

		cnt = elogd_queue_busy_count(&pipe->outq);
		if (!cnt)
			break;

		ret = elogd_store_write(&pipe->store, &pipe->outq, cnt);
		if (ret)
			break;
	}

	if (pipe->intern)
		elogd_intern_stop(pipe->intern);

	return ret;
}

#if defined(CONFIG_ELOGD_MQUEUE)

static __elogd_nonull(1)
int
elogd_pipe_create_mqueue(struct elogd_pipe * __restrict  pipe,
                         const struct upoll * __restrict poll)
{
	elogd_assert(pipe);
	elogd_assert(poll);

	if (elogd_conf.mqueue_on) {
		pipe->mqueue = elogd_mqueue_create(pipe, poll);
		if (!pipe->mqueue)
			return -errno;
	}
	else
		pipe->mqueue = NULL;

	return 0;
}

static __elogd_nonull(1, 2)
void
elogd_pipe_destroy_mqueue(struct elogd_pipe * __restrict  pipe,
                          const struct upoll * __restrict poll)
{
	elogd_pipe_assert(pipe);
	elogd_assert(poll);

	if (pipe->mqueue)
		elogd_mqueue_destroy(pipe->mqueue, poll);
}

#else /* !defined(CONFIG_ELOGD_MQUEUE) */

static inline __elogd_nonull(1)
int
elogd_pipe_create_mqueue(struct elogd_pipe * __restrict  pipe __unused,
                         const struct upoll * __restrict poll __unused)
{
	elogd_assert(pipe);
	elogd_assert(poll);

	return 0;
}

static inline __elogd_nonull(1, 2)
void
elogd_pipe_destroy_mqueue(struct elogd_pipe * __restrict  pipe __unused,
                          const struct upoll * __restrict poll __unused)
{
	elogd_pipe_assert(pipe);
	elogd_assert(poll);
}

#endif

int
elogd_pipe_open(struct elogd_pipe * __restrict  pipe,
                unsigned int                    nr,
                const struct upoll * __restrict poll)
{
	elogd_assert(pipe);
	elogd_assert(nr);
	elogd_assert(poll);

	int err;

	/*
	 * Make sure that active queues handling is properly initialized since
	 * notifications may be sent at data channel opening time (e.g.,
	 * elogd_kern_open()).
	 */
	pipe->cnt = 0;
	memset(pipe->alive, 0, sizeof(pipe->alive));

	elogd_queue_init(&pipe->outq, nr);

	if (elogd_conf.sock_on) {
		pipe->sock = elogd_sock_create(pipe, poll);
		if (!pipe->sock) {
			err = -errno;
			goto fini_queue;
		}
	}
	else
		pipe->sock = NULL;

	if (elogd_conf.kern_on) {
		pipe->kern = elogd_kern_create(pipe, poll);
		if (!pipe->kern) {
			err = -errno;
			goto destroy_sock;
		}
	}
	else
		pipe->kern = NULL;

	err = elogd_pipe_create_mqueue(pipe, poll);
	if (err)
		goto destroy_kern;

	pipe->intern = elogd_log_the_intern();

	err = elogd_store_open(&pipe->store);
	if (err)
		goto destroy_mqueue;

	/*
	 * Some queue may have switched to active state at opening time. Make
	 * sure that these are drained into output queue.
	 */
	if (pipe->cnt) {
		elogd_pipe_merge_queues(pipe);
		elogd_pipe_reset_alive(pipe);
	}

	elogd_info("pipeline initialized with %u lines of %u bytes each.",
	           nr,
	           ELOGD_LINE_MAX_LEN);

	return 0;

destroy_mqueue:
	elogd_pipe_destroy_mqueue(pipe, poll);
destroy_kern:
	if (pipe->kern)
		elogd_kern_destroy(pipe->kern, poll);
destroy_sock:
	if (pipe->sock)
		elogd_sock_destroy(pipe->sock, poll);
fini_queue:
	elogd_queue_fini(&pipe->outq);

	return err;
}

void
elogd_pipe_close(struct elogd_pipe * __restrict  pipe,
                 const struct upoll * __restrict poll)
{
	elogd_pipe_assert(pipe);
	elogd_assert(poll);

	elogd_debug("closing pipeline...");

	elogd_store_close(&pipe->store);

	elogd_pipe_destroy_mqueue(pipe, poll);
	if (pipe->kern)
		elogd_kern_destroy(pipe->kern, poll);
	if (pipe->sock)
		elogd_sock_destroy(pipe->sock, poll);

	elogd_queue_fini(&pipe->outq);
}
