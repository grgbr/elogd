/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "svc.h"
#include <utils/time.h>
#include <utils/pwd.h>

static __elogd_nonull(1, 2)
int
elogd_svc_read(const struct elogd_svc * __restrict svc,
               struct elogd_line * __restrict      line)
{
	elogd_assert(svc);
	elogd_assert(line);

	const struct iovec vec = {
		.iov_base = line->data,
		.iov_len  = sizeof(line->data) - 1
	};
	union unsk_creds   anc;
	struct msghdr      msg = {
		.msg_name       = NULL,
		.msg_namelen    = 0,
		.msg_iov        = (struct iovec *)&vec,
		.msg_iovlen     = 1,
		.msg_control    = anc.buff,
		.msg_controllen = sizeof(anc.buff),
		0,
	};
	ssize_t            ret;

	ret = unsk_recv_dgram_msg(svc->unsk.fd, &msg, 0);
	if (ret <= 0) {
		switch (ret) {
		case -EAGAIN: /* No more data to read. */
		case -ENOMEM: /* No more memory. */
			break;

		default:
			/* This should never happen. */
			elogd_assert(0);
		}

		return ret;
	}

	elogd_assert(!(msg.msg_flags & MSG_EOR));
	elogd_assert(!(msg.msg_flags & MSG_OOB));
	elogd_assert(!(msg.msg_flags & MSG_ERRQUEUE));

	/*
	 * TODO:
	 * * warn if message has been truncated (msg.msg_flags & MSG_TRUNC) ?
	 * * also warn if credentials control message has been truncated
	 *   (msg.msg_flags & MSG_CTRUNC) ?
	 */

	line->vector[ELOGD_LINE_MSG_IOVEC].iov_len = ret;
	line->data[ret] = '\0';

	if (!(msg.msg_flags & MSG_CTRUNC)) {
		const struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);

		if (cmsg &&
		    (cmsg->cmsg_level == SOL_SOCKET) &&
		    (cmsg->cmsg_type == SCM_CREDENTIALS) &&
		    (cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))))
			line->pid = ((struct ucred *)CMSG_DATA(cmsg))->pid;
	}

	return 0;
}

static __elogd_nonull(1, 2) __elogd_nothrow
const char *
elogd_svc_parse_prio(struct elogd_line * __restrict line,
                     const char * __restrict        string)
{
	elogd_assert(line);
	elogd_assert(string);

	if (*string != '<')
		return NULL;

	return elogd_parse_prio(&string[1],
	                        '>',
	                        &line->facility,
	                        &line->severity);
}

static __elogd_nonull(1) __elogd_pure __elogd_nothrow
char *
elogd_svc_probe_body_start(const char * __restrict string, size_t len)
{
	elogd_assert(string);
	elogd_assert(len);

	const char * chr = string;

	while (true) {
		chr = (const char *)
		      elogd_probe_string_delim(chr, ':', &string[len] - chr);
		elogd_assert(chr < &string[len]);
		if (!chr || ((&chr[2]) >= &string[len]))
			break;

		if (chr[1] == ' ')
			return (char *)chr;

		chr++;
	}

	return NULL;
}

static __elogd_nonull(1, 2) __elogd_nothrow
char *
elogd_svc_parse_body(struct elogd_line * __restrict line,
                     char * __restrict              string,
                     size_t                         len)
{
	elogd_assert(line);
	elogd_assert(string);

	char *         mark;
	char *         start;
	ssize_t        mlen;
	struct iovec * msg = &line->vector[ELOGD_LINE_MSG_IOVEC];

	if (len < 5)
		/*
		 * Length must be large enough to hold:
		 * one char + ':' + ' ' + one char + '\n'.
		 */
		return NULL;

	/* Locate start of message marker. */
	mark = elogd_svc_probe_body_start(string, len);
	if (!mark)
		return NULL;

	/*
	 * Message starts just after marker and must end with a newline
	 * character or terminating NULL byte.
	 */
	start = &mark[2];
	elogd_assert(start < &string[len]);

	mlen = elog_check_line(start, len - (start - string));
	if (mlen <= 0)
		return NULL;

	/* End line with a terminating newline character. */
	start[mlen++] = '\n';

	msg->iov_base = (void *)start;
	msg->iov_len = mlen;

	/*
	 * Return pointer to first marker character to indicate the caller where
	 * the header part ends.
	 */
	return mark;
}

static __elogd_nonull(1, 2) __elogd_nothrow
int
elogd_svc_parse_tag(struct elogd_line * __restrict line,
                    const char * __restrict        string,
                    size_t                         len)
{
	elogd_assert(line);
	elogd_assert(string);

	const char * ptr;
	
	if (len < 1)
		return -EINVAL;

	ptr = memrchr(string, ' ', len);
	if (ptr) {
		len = &string[len] - ++ptr;
		if (!len)
			return -EINVAL;

		line->tag = ptr;
	}
	else
		line->tag = string;

	ptr = memchr(line->tag, '[', len);
	if (ptr)
		line->tag_len = ptr - line->tag;
	else
		line->tag_len = len;

	if (line->tag_len < ELOGD_TAG_MIN_LEN)
		return -EINVAL;

	return 0;
}

static __elogd_nonull(1) __elogd_nothrow
int
elogd_svc_parse(struct elogd_line * __restrict line)
{
	elogd_assert(line);
	elogd_assert(line->vector[ELOGD_LINE_MSG_IOVEC].iov_len);

	char *               data = line->data;
	const struct iovec * msg = &line->vector[ELOGD_LINE_MSG_IOVEC];
	const char *         end = &line->data[msg->iov_len];
	const char *         mark;

	/* Parse priority tag. */
	data = (char *)elogd_svc_parse_prio(line, data);
	if (!data)
		return -EINVAL;

	mark = elogd_svc_parse_body(line, data, end - data);
	if (!mark)
		return -EINVAL;

	if (elogd_svc_parse_tag(line, data, mark - data))
		return -EINVAL;

	/* Assign message a timestamp within the boot time space. */
	utime_boot_now(&line->tstamp);

	return 0;
}

static __elogd_nonull(1) __elogd_nothrow
int
elogd_svc_process(struct elogd_svc * __restrict svc)
{
	elogd_assert(svc);

	struct elogd_line * ln;
	int                 ret;

	ln = elogd_line_create();
	if (!ln)
		return -ENOBUFS;

	ret = elogd_svc_read(svc, ln);
	if (ret)
		goto release;

	ret = elogd_svc_parse(ln);
	if (ret)
		goto release;

	/* Messages are already ordered within the boot time space. */
	elogd_nqueue(&svc->queue, ln);

	return 0;

release:
	elogd_line_destroy(ln);

	return ret;
}

static __elogd_nonull(1, 3) __elogd_nothrow
int
elogd_svc_dispatch(struct upoll_worker * work,
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

	struct elogd_svc * svc;
	unsigned int       cnt;

	svc = containerof(work, struct elogd_svc, work);
	elogd_assert(svc);

	cnt = elogd_queue_free_count(&svc->queue);
	while (cnt--) {
		int ret;

		ret = elogd_svc_process(svc);
		switch (ret) {
		case 0:
			/* Process next line. */
			break;

		/* Parsing errors. */
		case -EINVAL:
#warning log an info message ??
			/* Process next line. */
			break;

		case -EAGAIN:
		case -ENOBUFS:
			/*
			 * No more data to fetch or no more line buffer to
			 * process remaining input: just return to give
			 * elogd_flush_store() a chance to release a few line
			 * buffers...
			 */
			return 0;

		case -ENOMEM:
			/*
			 * All we can do here is to give up and hope we can
			 * properly shut things down before exiting.
			 */
			return -ENOMEM;

		default:
			elogd_assert(0);
		}
	};

	return 0;
}


int
elogd_svc_open(struct elogd_svc * __restrict   svc,
               const struct upoll * __restrict poll)
{
	elogd_assert(svc);
	elogd_assert(poll);

	int          err;
	const char * msg;
	mode_t       msk;
	gid_t        gid = elogd_gid;

	err = unsk_dgram_svc_open(&svc->unsk, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (err) {
		msg = "open failed";
		goto err;
	}

	msk = umask(ALLPERMS & ~elogd_conf.svc_mode);
	err = unsk_svc_bind(&svc->unsk, elogd_conf.sock_path);
	umask(msk);
	if (err) {
		msg = "bind failed";
		goto close;
	}

	if (elogd_conf.svc_group) {
		err = upwd_get_gid_byname(elogd_conf.svc_group, &gid);
		if (err)
			elogd_warn("'%s': unknown logging socket group, "
			           "using default GID %d.\n",
			           elogd_conf.svc_group,
			           gid);
	}

	err = upath_chown(elogd_conf.sock_path, elogd_uid, gid);
	if (err) {
		msg = "owner / group membership setup failed";
		goto close;
	}

	svc->work.dispatch = elogd_svc_dispatch;
	err = upoll_register(poll, svc->unsk.fd, EPOLLIN, &svc->work);
	if (err) {
		msg = "cannot register poll worker";
		goto close;
	}

	elogd_queue_init(&svc->queue, elogd_conf.svc_fetch);

	return 0;

close:
	unsk_svc_close(&svc->unsk);
err:
	elogd_err("cannot initialize syslog socket: '%s': %s: %s (%d).\n",
	          elogd_conf.sock_path,
	          msg,
	          strerror(-err),
	          -err);

	return err;
}

void
elogd_svc_close(const struct elogd_svc * __restrict svc,
                const struct upoll * __restrict     poll)
{
	elogd_assert(svc);

	upoll_unregister(poll, svc->unsk.fd);
	elogd_queue_fini(&svc->queue);
	unsk_svc_close(&svc->unsk);
}
