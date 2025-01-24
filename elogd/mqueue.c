/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "mqueue.h"
#include "pipe.h"
#include "log.h"
#include <utils/fd.h>
#include <utils/time.h>
#include <utils/poll.h>

/*
 * POSIX queue message source.
 *
 * Meant to retrieve messages from a POSIX message queue in a epoll(7)'able
 * manner.
 *
 * See mq_overview(7).
 */
struct elogd_mqueue {
	/* Queue of fetched POSIX queue messages. */
	struct elogd_queue  queue;
	/*
	 * upoll worker used to trigger fetches when new messages are available
	 * from a POSIX queue.
	 */
	struct upoll_worker work;
	/*
	 * high-level elogd object to be nofified when new POSIX queue
	 * messages have been fetched.
	 */
	struct elogd_pipe * pipe;
	/* File descriptor pointing to POSIX queue. */
	mqd_t               fd;
};

#define elogd_mqueue_assert(_mqueue) \
	elogd_assert(_mqueue); \
	elogd_assert(elogd_queue_nr(&(_mqueue)->queue) == \
	             elogd_conf.mqueue_fetch); \
	elogd_assert((_mqueue)->pipe); \
	elogd_assert((_mqueue)->fd >= 0)

#define ELOG_MQUEUE_MIN_LEN \
	(sizeof(struct elog_mqueue_head) + \
	 ELOGD_TAG_MIN_LEN + \
	 1)

static __elogd_nonull(1, 2)
int
elogd_mqueue_read(const struct elogd_mqueue * __restrict mqueue,
                  struct elogd_line * __restrict         line)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.mqueue_on);
	elogd_mqueue_assert(mqueue);
	elogd_assert(line);

	ssize_t ret;

	ret = umq_recv(mqueue->fd, line->data, sizeof(line->data) - 1, NULL);
	if (ret == -EAGAIN)
		return -EAGAIN;

	elogd_assert(ret >= 0);
	if ((size_t)ret < ELOG_MQUEUE_MIN_LEN) {
		elogd_warn("message queue read failed: message too small.");
		return -EINVAL;
	}

	line->vector[ELOGD_LINE_MSG_IOVEC].iov_len = (size_t)ret;
	line->data[ret] = '\0';

	return 0;
}

static __elogd_nonull(1)
int
elogd_mqueue_parse(struct elogd_line * __restrict line)
{
	elogd_assert(line);
	elogd_assert(line->vector[ELOGD_LINE_MSG_IOVEC].iov_len >=
	             ELOG_MQUEUE_MIN_LEN);

	struct elog_mqueue_head * head = (struct elog_mqueue_head *)line->data;
	struct iovec *            vec = &line->vector[ELOGD_LINE_MSG_IOVEC];
	ssize_t                   blen;

	blen = elog_parse_mqueue_msg(head, vec->iov_len);
	if (blen < 0) {
		elogd_warn("message queue parsing failed: unexpected message.");
		return (int)blen;
	}

	/*
	 * Messages are assigned a timestamp within the boot time space.
	 * Inconsistencies in the boot time space is already fixed up by
	 * elog_parse_mqueue_msg() if required.
	 */
	line->tstamp = head->tstamp;
	line->facility = head->prio & LOG_FACMASK;
	line->severity = head->prio & LOG_PRIMASK;
	line->tag_len = head->body;
	line->tag = &head->data[0];
	line->pid = head->pid;

	/* End line with a terminating newline character. */
	head->data[head->body + blen] = '\n';

	vec->iov_base = &head->data[head->body];
	vec->iov_len = (size_t)blen + 1;

	return 0;
}

static __elogd_nonull(1, 2)
int
elogd_mqueue_process(struct elogd_mqueue * __restrict      mqueue,
                     struct stroll_dlist_node * __restrict messages)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.mqueue_on);
	elogd_mqueue_assert(mqueue);
	elogd_assert(messages);

	struct elogd_line * line;
	int                 ret;

	line = elogd_line_create();
	if (!line)
		return -ENOBUFS;

	ret = elogd_mqueue_read(mqueue, line);
	if (ret)
		goto release;

	ret = elogd_mqueue_parse(line);
	if (ret)
		goto release;

#if defined(CONFIG_ELOGD_MQUEUE_REORDER_MERGE)
	stroll_dlist_insert(messages, &line->node);
#elif defined(CONFIG_ELOGD_MQUEUE_REORDER_INSERT)
	stroll_dlist_insert_inorder_back(messages,
	                                 &line->node,
	                                 elogd_queue_line_cmp,
	                                 NULL);
#else
#error Unsupported POSIX message queue reordering strategy !
#endif
	return 0;

release:
	elogd_line_destroy(line);

	return ret;
}

static __elogd_nonull(1, 3)
int
elogd_mqueue_dispatch(struct upoll_worker * work,
                      uint32_t              state __unused,
                      const struct upoll *  poll __unused)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.mqueue_on);
	elogd_assert(work);
	elogd_assert(state);
	elogd_assert(!(state & EPOLLOUT));
	elogd_assert(!(state & EPOLLHUP));
	elogd_assert(!(state & EPOLLRDHUP));
	elogd_assert(!(state & EPOLLPRI));
	elogd_assert(state & (EPOLLIN | EPOLLERR));
	elogd_assert(poll);

	struct elogd_mqueue * mqueue;
	unsigned int          nr;

	mqueue = containerof(work, struct elogd_mqueue, work);
	elogd_mqueue_assert(mqueue);

	nr = elogd_queue_free_count(&mqueue->queue);
	if (nr) {
		struct stroll_dlist_node tmp = STROLL_DLIST_INIT(tmp);
		unsigned int             cnt = 0;

		do {
			int ret;

			ret = elogd_mqueue_process(mqueue, &tmp);
			switch (ret) {
			case 0:
				/*
				 * Account parsed line and proceed to next one.
				 */
				cnt++;
				break;

			case -EINVAL:
				/*
				 * Parsing error: log a message and proceed to
				 * next line.
				 */
				break;

			case -EAGAIN:
			case -ENOBUFS:
				/*
				 * No more data to fetch or no more line buffer
				 * to process remaining input: just return to
				 * give elogd_flush_store() a chance to release
				 * a few line buffers...
				 */
				goto sort;

			default:
				elogd_assert(0);
			}
		} while (--nr);

sort:
		if (cnt) {
#if defined(CONFIG_ELOGD_MQUEUE_REORDER_MERGE)
			stroll_dlist_merge_sort(&tmp, elogd_queue_line_cmp, NULL);
#endif
			elogd_nqueue_presort(&mqueue->queue, &tmp, cnt);
		}
	}

	if (elogd_queue_busy_count(&mqueue->queue))
		elogd_pipe_on_alive(mqueue->pipe, &mqueue->queue);

	return 0;
}

static __elogd_nonull(1, 2, 3)
int
elogd_mqueue_open(struct elogd_mqueue * __restrict mqueue,
                  struct elogd_pipe * __restrict   pipe,
                  const struct upoll * __restrict  poll)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.mqueue_on);
	elogd_assert(mqueue);
	elogd_assert(pipe);
	elogd_assert(poll);

	int            fd;
	int            err;
	const char *   msg;
	struct mq_attr attr;
	struct stat    st;

	elogd_debug("initializing '%s' message queue...",
	            elogd_conf.mqueue_name);

	fd = umq_open(elogd_conf.mqueue_name,
	              O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0) {
		err = fd;
		msg = "open failed";
		goto err;
	}

	err = ufd_fstat(fd, &st);
	if (err) {
		msg = "status retrieval failed";
		goto close;
	}

	if (((st.st_mode & (ALLPERMS & ~(S_IRUSR | S_IWUSR))) != S_IRGRP) ||
	    (st.st_uid != 0)) {
		err = -EPERM;
		msg = "unexpected file attributes";
		goto close;
	}

	umq_getattr(fd, &attr);
	if ((attr.mq_maxmsg < 1) || (attr.mq_msgsize < (long)ELOG_LINE_MAX)) {
		err = -EPERM;
		msg = "invalid message size capacity";
		goto close;
	}

	mqueue->work.dispatch = elogd_mqueue_dispatch;
	err = upoll_register(poll, fd, EPOLLIN, &mqueue->work);
	if (err) {
		msg = "cannot register poll worker";
		goto close;
	}

	elogd_queue_init(&mqueue->queue, elogd_conf.mqueue_fetch);
	mqueue->pipe = pipe;
	mqueue->fd = fd;

	elogd_info("'%s' message queue initialized.",
	           elogd_conf.mqueue_name);

	return 0;

close:
#if defined(CONFIG_ELOGD_DEBUG)
	umq_close(fd);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
err:
	elogd_err("cannot initialize message queue: '%s': %s: %s (%d).",
	          elogd_conf.mqueue_name,
	          msg,
	          strerror(-err),
	          -err);

	return err;
}

static __elogd_nonull(1, 2)
void
elogd_mqueue_close(const struct elogd_mqueue * __restrict mqueue,
                   const struct upoll * __restrict        poll __unused)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.mqueue_on);
	elogd_mqueue_assert(mqueue);
	elogd_assert(poll);

	elogd_debug("closing message queue...");

#if defined(CONFIG_ELOGD_DEBUG)
	upoll_unregister(poll, mqueue->fd);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	elogd_queue_fini(&mqueue->queue);

#if defined(CONFIG_ELOGD_DEBUG)
	umq_close(mqueue->fd);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
}

struct elogd_mqueue *
elogd_mqueue_create(struct elogd_pipe * __restrict  pipe,
                    const struct upoll * __restrict poll)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.mqueue_on);
	elogd_assert(pipe);
	elogd_assert(poll);

	struct elogd_mqueue * mqueue;

	mqueue = malloc(sizeof(*mqueue));
	if (!mqueue) {
		errno = -ENOMEM;
		return NULL;
	}

	if (elogd_mqueue_open(mqueue, pipe, poll))
		goto free;

	return mqueue;

free:
#if defined(CONFIG_ELOGD_DEBUG)
	free(mqueue);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	return NULL;
}

void
elogd_mqueue_destroy(struct elogd_mqueue * __restrict mqueue,
                     const struct upoll * __restrict  poll)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.mqueue_on);
	elogd_mqueue_assert(mqueue);
	elogd_assert(poll);

	elogd_mqueue_close(mqueue, poll);

#if defined(CONFIG_ELOGD_DEBUG)
	free(mqueue);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
}
