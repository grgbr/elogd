/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "mqueue.h"
#include <utils/fd.h>

#define ELOG_MQUEUE_MIN_LEN \
	(sizeof(struct elog_mqueue_head) + \
	 ELOGD_TAG_MIN_LEN + \
	 1)

static __elogd_nonull(1, 2)
int
elogd_mqueue_read(const struct elogd_mqueue * __restrict mqueue,
                  struct elogd_line * __restrict         line)
{
	elogd_assert(mqueue);
	elogd_assert(mqueue->fd >= 0);
	elogd_assert(line);

	ssize_t ret;

	ret = umq_recv(mqueue->fd, line->data, sizeof(line->data) - 1, NULL);
	if (ret == -EAGAIN)
		return -EAGAIN;

	elogd_assert(ret >= 0);
	if ((size_t)ret < ELOG_MQUEUE_MIN_LEN)
		return -EINVAL;

	line->vector[ELOGD_LINE_MSG_IOVEC].iov_len = ret;
	line->data[ret] = '\0';

	return 0;
}

static __elogd_nonull(1) __elogd_nothrow
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
	if (blen < 0)
		return blen;

	/* Messages are assigned a timestamp within the boot time space. */
	line->tstamp = head->tstamp;
	line->facility = head->prio & LOG_FACMASK;
	line->severity = head->prio & LOG_PRIMASK;
	line->tag_len = head->body;
	line->tag = &head->data[0];
	line->pid = head->pid;

	/* End line with a terminating newline character. */
	head->data[head->body + blen] = '\n';

	vec->iov_base = &head->data[head->body];
	vec->iov_len = blen + 1;

	return 0;
}

static __elogd_nonull(1)
int
elogd_mqueue_process(struct elogd_mqueue * __restrict      mqueue,
                     struct stroll_dlist_node * __restrict messages)
{
	elogd_assert(mqueue);
	elogd_assert(mqueue->fd >= 0);

	struct elogd_line * ln;
	int                 ret;

	ln = elogd_line_create();
	if (!ln)
		return -ENOBUFS;

	ret = elogd_mqueue_read(mqueue, ln);
	if (ret)
		goto release;

	ret = elogd_mqueue_parse(ln);
	if (ret)
		goto release;

	stroll_dlist_insert_inorder_back(messages,
	                                 &ln->node,
	                                 elogd_queue_line_cmp,
	                                 NULL);

	return 0;

release:
	elogd_line_destroy(ln);

	return ret;
}

static __elogd_nonull(1, 3)
int
elogd_mqueue_dispatch(struct upoll_worker * work,
                      uint32_t              state __unused,
                      const struct upoll *  poll __unused)
{
	elogd_assert_conf();
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
	elogd_assert(mqueue);
	elogd_assert(mqueue->fd >= 0);

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
#warning log an info message ??
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
		if (cnt)
			elogd_nqueue_presort(&mqueue->queue, &tmp, cnt);
	}

	return 0;
}

int
elogd_mqueue_open(struct elogd_mqueue * __restrict mqueue,
                  const struct upoll * __restrict  poll)
{
	elogd_assert_conf();
	elogd_assert(mqueue);
	elogd_assert(poll);

	int            fd;
	int            err;
	const char *   msg;
	struct mq_attr attr;
	struct stat    st;

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
	mqueue->fd = fd;

	return 0;

close:
	umq_close(fd);
err:
	elogd_err("cannot initialize message queue: '%s': %s: %s (%d).\n",
	          elogd_conf.mqueue_name,
	          msg,
	          strerror(-err),
	          -err);

	return err;
}

void
elogd_mqueue_close(const struct elogd_mqueue * __restrict mqueue,
                   const struct upoll * __restrict        poll)
{
	elogd_assert(mqueue);
	elogd_assert(mqueue->fd >= 0);

	upoll_unregister(poll, mqueue->fd);
	elogd_queue_fini(&mqueue->queue);
	umq_close(mqueue->fd);
}
