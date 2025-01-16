/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "svc.h"
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
struct elogd_svc {
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

#define elogd_svc_assert(_svc) \
	elogd_assert(_svc); \
	elogd_assert(elogd_queue_nr(&(_svc)->queue) == elogd_conf.svc_fetch); \
	elogd_assert((_svc)->unsk.fd >= 0); \
	elogd_assert((_svc)->pipe)

static __elogd_nonull(1, 2)
int
elogd_svc_read(const struct elogd_svc * __restrict svc,
               struct elogd_line * __restrict      line)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.sock_path);
	elogd_svc_assert(svc);
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
		elogd_warn("syslog service read failed: "
		           "unxpected truncated message.");

	return 0;
}

static __elogd_nonull(1, 2)
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

static __elogd_nonull(1) __elogd_pure
char *
elogd_svc_probe_body_start(const char * __restrict string, size_t len)
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
elogd_svc_parse(struct elogd_line * __restrict line)
{
	elogd_assert(line);
	elogd_assert(line->vector[ELOGD_LINE_MSG_IOVEC].iov_len);

	char *               data = line->data;
	const struct iovec * msg = &line->vector[ELOGD_LINE_MSG_IOVEC];
	const char *         end = &line->data[msg->iov_len];
	const char *         mark;

	/* Parse priority tag. */
STROLL_IGNORE_WARN("-Wcast-qual")
	data = (char *)elogd_svc_parse_prio(line, data);
STROLL_RESTORE_WARN
	if (!data)
		goto err;

	mark = elogd_svc_parse_body(line, data, (size_t)(end - data));
	if (!mark)
		goto err;

	if (elogd_svc_parse_tag(line, data, (size_t)(mark - data)))
		goto err;

	/* Assign message a timestamp within the boot time clock space. */
	utime_boot_now(&line->tstamp);

	return 0;

err:
	elogd_warn("syslog service parsing failed: unexpected message.");

	return -EINVAL;
}

static __elogd_nonull(1)
int
elogd_svc_process(struct elogd_svc * __restrict svc)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.sock_path);
	elogd_svc_assert(svc);

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

static __elogd_nonull(1, 3)
int
elogd_svc_dispatch(struct upoll_worker * work,
                   uint32_t              state __unused,
                   const struct upoll *  poll __unused)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.sock_path);
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
	elogd_svc_assert(svc);

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
	if (elogd_queue_busy_count(&svc->queue))
		elogd_pipe_on_alive(svc->pipe, &svc->queue);

	return 0;
}

static __elogd_nonull(1, 2, 3)
int
elogd_svc_open(struct elogd_svc * __restrict   svc,
               struct elogd_pipe * __restrict  pipe,
               const struct upoll * __restrict poll)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.sock_path);
	elogd_assert(svc);
	elogd_assert(pipe);
	elogd_assert(poll);

	int          err;
	const char * msg;
	mode_t       msk;
	gid_t        gid = elogd_gid;

	elogd_debug("initializing '%s' syslog service...",
	            elogd_conf.sock_path);

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
			           "using default GID %d.",
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
	svc->pipe = pipe;

	elogd_info("'%s' syslog service initialized.", elogd_conf.sock_path);

	return 0;

close:
#if defined(CONFIG_ELOGD_DEBUG)
	unsk_svc_close(&svc->unsk);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
err:
	elogd_err("cannot initialize syslog service: '%s': %s: %s (%d).",
	          elogd_conf.sock_path,
	          msg,
	          strerror(-err),
	          -err);

	return err;
}

static __elogd_nonull(1, 2)
void
elogd_svc_close(const struct elogd_svc * __restrict svc,
                const struct upoll * __restrict     poll __unused)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.sock_path);
	elogd_svc_assert(svc);
	elogd_assert(poll);

	elogd_debug("closing syslog service...");

#if defined(CONFIG_ELOGD_DEBUG)
	upoll_unregister(poll, svc->unsk.fd);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	elogd_queue_fini(&svc->queue);

#if defined(CONFIG_ELOGD_DEBUG)
	unsk_svc_close(&svc->unsk);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
}

struct elogd_svc *
elogd_svc_create(struct elogd_pipe * __restrict  pipe,
                 const struct upoll * __restrict poll)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.sock_path);
	elogd_assert(pipe);
	elogd_assert(poll);

	struct elogd_svc * svc;

	svc = malloc(sizeof(*svc));
	if (!svc) {
		errno = -ENOMEM;
		return NULL;
	}

	if (elogd_svc_open(svc, pipe, poll))
		goto free;

	return svc;

free:
#if defined(CONFIG_ELOGD_DEBUG)
	free(svc);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	return NULL;
}

void
elogd_svc_destroy(struct elogd_svc * __restrict  svc,
                  const struct upoll * __restrict poll)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.sock_path);
	elogd_svc_assert(svc);
	elogd_assert(poll);

	elogd_svc_close(svc, poll);

#if defined(CONFIG_ELOGD_DEBUG)
	free(svc);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
}
