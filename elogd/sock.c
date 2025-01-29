/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "sock.h"
#include "pipe.h"
#include "log.h"
#include <utils/time.h>
#include <utils/pwd.h>
#include <utils/unsk.h>
#include <utils/poll.h>

/*
 * Syslog service socket message source.
 *
 * Meant to retrieve messages from an UNIX datagram socket in a epoll(7)'able
 * manner.
 *
 * See unix(7) and syslog(3).
 */
struct elogd_sock {
	/* Queue of fetched syslog service socket messages. */
	struct elogd_queue  queue;
	/*
	 * upoll worker used to trigger fetches when new messages are available
	 * from a syslog service socket.
	 */
	struct upoll_worker work;
	/* Syslog service socket descriptor. */
	struct unsk_svc     unsk;
	/*
	 * high-level elogd object to be nofified when new syslog service socket
	 * messages have been fetched.
	 */
	struct elogd_pipe * pipe;
};

#define elogd_sock_assert(_sock) \
	elogd_assert(_sock); \
	elogd_assert(elogd_queue_nr(&(_sock)->queue) == \
	             elogd_conf.sock_fetch); \
	elogd_assert((_sock)->unsk.fd >= 0); \
	elogd_assert((_sock)->pipe)

static __elogd_nonull(1, 2)
int
elogd_sock_read(const struct elogd_sock * __restrict sock,
                struct elogd_line * __restrict       line)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.sock_on);
	elogd_sock_assert(sock);
	elogd_assert(line);

	const struct iovec vec = {
		.iov_base = line->data,
		.iov_len  = sizeof(line->data) - 1
	};
	union unsk_creds   anc;
STROLL_IGNORE_WARN("-Wcast-qual")
	struct msghdr      msg = {
		.msg_name       = NULL,
		.msg_namelen    = 0,
		.msg_iov        = (struct iovec *)&vec,
		.msg_iovlen     = 1,
		.msg_control    = anc.buff,
		.msg_controllen = sizeof(anc.buff),
		0,
	};
STROLL_RESTORE_WARN
	ssize_t            ret;

	ret = unsk_recv_dgram_msg(sock->unsk.fd, &msg, 0);
	if (ret <= 0) {
		switch (ret) {
		case -EAGAIN: /* No more data to read. */
		case -ENOMEM: /* No more memory. */
			break;

		default:
			/* This should never happen. */
			elogd_assert(0);
		}

		return (int)ret;
	}

	elogd_assert(!(msg.msg_flags & MSG_EOR));
	elogd_assert(!(msg.msg_flags & MSG_OOB));
	elogd_assert(!(msg.msg_flags & MSG_ERRQUEUE));

	line->vector[ELOGD_LINE_MSG_IOVEC].iov_len = (size_t)ret;
	line->data[ret] = '\0';

	if (!(msg.msg_flags & MSG_CTRUNC)) {
		const struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);

		if (cmsg &&
		    (cmsg->cmsg_level == SOL_SOCKET) &&
		    (cmsg->cmsg_type == SCM_CREDENTIALS) &&
		    (cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred)))) {
			struct ucred cred;


			/*
			 * CMSG_DATA(cmsg) don't return a pointer suitably
			 * aligned to struct ucred: use memcpy().
			 */
			memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));
			line->pid = cred.pid;
		}
	}

	if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
		elogd_ratelim_warn("syslog service read failed...",
		                   "syslog service read failed: "
		                   "unxpected truncated message.");

	return 0;
}

static __elogd_nonull(1, 2)
const char *
elogd_sock_parse_prio(struct elogd_line * __restrict line,
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

static __elogd_nonull(1) __elogd_pure
char *
elogd_sock_probe_body_start(const char * __restrict string, size_t len)
{
	elogd_assert(string);
	elogd_assert(len);

	const char * chr = string;

	while (true) {
		chr = (const char *)
		      elogd_probe_string_delim(chr,
		                               ':',
		                               (size_t)(&string[len] - chr));
		elogd_assert(chr < &string[len]);
		if (!chr || ((&chr[2]) >= &string[len]))
			break;

STROLL_IGNORE_WARN("-Wcast-qual")
		if (chr[1] == ' ')
			return (char *)chr;
STROLL_RESTORE_WARN

		chr++;
	}

	return NULL;
}

static __elogd_nonull(1, 2)
char *
elogd_sock_parse_body(struct elogd_line * __restrict line,
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
	mark = elogd_sock_probe_body_start(string, len);
	if (!mark)
		return NULL;

	/*
	 * Message starts just after marker and must end with a newline
	 * character or terminating NULL byte.
	 */
	start = &mark[2];
	elogd_assert(start < &string[len]);

	mlen = elog_check_line(start, len - (size_t)(start - string));
	if (mlen <= 0)
		return NULL;

	/* End line with a terminating newline character. */
	start[mlen++] = '\n';

	msg->iov_base = (void *)start;
	msg->iov_len = (size_t)mlen;

	/*
	 * Return pointer to first marker character to indicate the caller where
	 * the header part ends.
	 */
	return mark;
}

static __elogd_nonull(1, 2)
int
elogd_sock_parse_tag(struct elogd_line * __restrict line,
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
		len = (size_t)(&string[len] - ++ptr);
		if (!len)
			return -EINVAL;

		line->tag = ptr;
	}
	else
		line->tag = string;

	ptr = memchr(line->tag, '[', len);
	if (ptr)
		line->tag_len = (size_t)(ptr - line->tag);
	else
		line->tag_len = len;

	if (line->tag_len < ELOGD_TAG_MIN_LEN)
		return -EINVAL;

	return 0;
}

static __elogd_nonull(1)
int
elogd_sock_parse(struct elogd_line * __restrict line)
{
	elogd_assert(line);
	elogd_assert(line->vector[ELOGD_LINE_MSG_IOVEC].iov_len);

	char *               data = line->data;
	const struct iovec * msg = &line->vector[ELOGD_LINE_MSG_IOVEC];
	const char *         end = &line->data[msg->iov_len];
	const char *         mark;

	/* Parse priority tag. */
STROLL_IGNORE_WARN("-Wcast-qual")
	data = (char *)elogd_sock_parse_prio(line, data);
STROLL_RESTORE_WARN
	if (!data)
		goto err;

	mark = elogd_sock_parse_body(line, data, (size_t)(end - data));
	if (!mark)
		goto err;

	if (elogd_sock_parse_tag(line, data, (size_t)(mark - data)))
		goto err;

	/* Assign message a timestamp within the boot time clock space. */
	utime_boot_now(&line->tstamp);

	return 0;

err:
	elogd_ratelim_warn("syslog service parsing failed...",
	                   "syslog service parsing failed: "
	                   "unexpected message.");

	return -EINVAL;
}

static __elogd_nonull(1)
int
elogd_sock_process(struct elogd_sock * __restrict sock)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.sock_on);
	elogd_sock_assert(sock);

	struct elogd_line * ln;
	int                 ret;

	ln = elogd_line_create();
	if (!ln)
		return -ENOBUFS;

	ret = elogd_sock_read(sock, ln);
	if (ret)
		goto release;

	ret = elogd_sock_parse(ln);
	if (ret)
		goto release;

	/* Messages are already ordered within the boot time space. */
	elogd_nqueue(&sock->queue, ln);

	return 0;

release:
	elogd_line_destroy(ln);

	return ret;
}

static __elogd_nonull(1, 3)
int
elogd_sock_dispatch(struct upoll_worker * work,
                    uint32_t              state __unused,
                    const struct upoll *  poll __unused)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.sock_on);
	elogd_assert(work);
	elogd_assert(state);
	elogd_assert(!(state & EPOLLOUT));
	elogd_assert(!(state & EPOLLHUP));
	elogd_assert(!(state & EPOLLRDHUP));
	elogd_assert(!(state & EPOLLPRI));
	elogd_assert(state & (EPOLLIN | EPOLLERR));
	elogd_assert(poll);

	struct elogd_sock * sock;
	unsigned int        cnt;

	sock = containerof(work, struct elogd_sock, work);
	elogd_sock_assert(sock);

	cnt = elogd_queue_free_count(&sock->queue);
	while (cnt--) {
		int ret;

		ret = elogd_sock_process(sock);
		switch (ret) {
		case 0:
			/* Process next line. */
			break;

		/* Parsing errors. */
		case -EINVAL:
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
			goto publish;

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

publish:
	if (elogd_queue_busy_count(&sock->queue))
		elogd_pipe_on_alive(sock->pipe, &sock->queue);

	return 0;
}

static __elogd_nonull(1, 2, 3)
int
elogd_sock_open(struct elogd_sock * __restrict  sock,
                struct elogd_pipe * __restrict  pipe,
                const struct upoll * __restrict poll)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.sock_on);
	elogd_assert(sock);
	elogd_assert(pipe);
	elogd_assert(poll);

	char *       path;
	gid_t        gid;
	int          err;
	const char * msg;
	mode_t       msk;

	err = (int)elogd_make_path(&path,
	                           elogd_conf.rundir_path,
	                           elogd_conf.rundir_len,
	                           "sock",
	                           sizeof("sock") - 1);
	if (err < 0)
		return err;

	elogd_debug("initializing '%s' syslog service...", path);

	err = upwd_get_gid_byname(elogd_conf.rundir_group, &gid);
	if (err) {
		elogd_err("cannot initialize syslog service: "
		          "'%s': invalid socket group: %s (%d).",
		          elogd_conf.rundir_group,
		          strerror(-err),
		          -err);
		goto free;
	}

	err = unsk_dgram_svc_open(&sock->unsk, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (err) {
		msg = "open failed";
		goto err;
	}

#define ELOGD_SOCK_MODE (S_IRUSR | S_IWGRP)
	msk = umask(ALLPERMS & ~ELOGD_SOCK_MODE);
	err = unsk_svc_bind(&sock->unsk, path);
	umask(msk);
	if (err) {
		msg = "bind failed";
		goto close;
	}

	err = upath_chown(path, elogd_uid, gid);
	if (err) {
		msg = "ownership setup failed";
		goto close;
	}

	sock->work.dispatch = elogd_sock_dispatch;
	err = upoll_register(poll, sock->unsk.fd, EPOLLIN, &sock->work);
	if (err) {
		msg = "cannot register poll worker";
		goto close;
	}

	elogd_queue_init(&sock->queue, elogd_conf.sock_fetch);
	sock->pipe = pipe;

	elogd_info("'%s' syslog service initialized.", path);

	free(path);

	return 0;

close:
#if defined(CONFIG_ELOGD_DEBUG)
	unsk_svc_close(&sock->unsk);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
err:
	elogd_err("cannot initialize syslog service: '%s': %s: %s (%d).",
	          path,
	          msg,
	          strerror(-err),
	          -err);
free:
#if defined(CONFIG_ELOGD_DEBUG)
	free(path);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	return err;
}

static __elogd_nonull(1, 2)
void
elogd_sock_close(const struct elogd_sock * __restrict sock,
                 const struct upoll * __restrict      poll __unused)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.sock_on);
	elogd_sock_assert(sock);
	elogd_assert(poll);

	elogd_debug("closing syslog service...");

#if defined(CONFIG_ELOGD_DEBUG)
	upoll_unregister(poll, sock->unsk.fd);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	elogd_queue_fini(&sock->queue);

#if defined(CONFIG_ELOGD_DEBUG)
	unsk_svc_close(&sock->unsk);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
}

struct elogd_sock *
elogd_sock_create(struct elogd_pipe * __restrict  pipe,
                  const struct upoll * __restrict poll)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.sock_on);
	elogd_assert(pipe);
	elogd_assert(poll);

	struct elogd_sock * sock;

	sock = malloc(sizeof(*sock));
	if (!sock) {
		errno = -ENOMEM;
		return NULL;
	}

	if (elogd_sock_open(sock, pipe, poll))
		goto free;

	return sock;

free:
#if defined(CONFIG_ELOGD_DEBUG)
	free(sock);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	return NULL;
}

void
elogd_sock_destroy(struct elogd_sock * __restrict  sock,
                   const struct upoll * __restrict poll)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.sock_on);
	elogd_sock_assert(sock);
	elogd_assert(poll);

	elogd_sock_close(sock, poll);

#if defined(CONFIG_ELOGD_DEBUG)
	free(sock);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
}
