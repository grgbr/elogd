/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "kern.h"
#include "pipe.h"
#include "log.h"
#include <utils/poll.h>
#include <utils/time.h>
#include <utils/file.h>
#include <ctype.h>
#include <sys/mman.h>

/*
 * Kernel (logging) ring-buffer message source.
 *
 * Meant to retrieve messages from the kernel ring-buffer in a epoll(7)'able
 * manner.
 *
 * See <linux>/doc/Documentation/ABI/testing/dev-kern
 */
struct elogd_kern {
	/* Queue of fetched kernel ring-buffer messages. */
	struct elogd_queue  queue;
	/*
	 * upoll worker used to trigger fetches when new kernel ring-buffer
	 * messages are available.
	 */
	struct upoll_worker work;
	/*
	 * high-level elogd object to be nofified when new kernel ring-buffer
	 * messages have been fetched.
	 */
	struct elogd_pipe * pipe;
	/* File descriptor pointing to "/dev/kern" kernel ring-buffer. */
	int                 dev_fd;
	/*
	 * Pointer to location in elogd status file (see `stat_fd' below) where
	 * last retrieved kernel ring-buffer message's sequence number is
	 * stored.
	 */
	uint64_t *          seqno;
	/*
	 * File descriptor pointing to elogd status file allowing to track
	 * kernel ring-buffer message sequence number (see `seqno' above).
	 *
	 * This 64-bits sequence number allows to reconnect to the buffer and
	 * reconstruct the read position if needed, e.g after an elogd shutdown
	 * or crash.
	 */
	int                 stat_fd;
};

#define elogd_kern_assert(_kern) \
	elogd_assert(_kern); \
	elogd_assert(elogd_queue_nr(&(_kern)->queue) == \
	             elogd_conf.kern_fetch); \
	elogd_assert((_kern)->pipe); \
	elogd_assert((_kern)->dev_fd >= 0); \
	elogd_assert((_kern)->seqno); \
	elogd_assert((_kern)->stat_fd >= 0)

static __elogd_nonull(1, 2)
int
elogd_kern_read(const struct elogd_kern * __restrict kern,
                struct elogd_line * __restrict       line)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.kern_on);
	elogd_kern_assert(kern);
	elogd_assert(line);

	ssize_t ret;

	/*
	 * As stated by <linux>/doc/Documentation/ABI/testing/dev-kern
	 *
	 * Each read() from kern receives one single record of the kernel's
	 * printk buffer.
	 * kern returns EPIPE if record got overwritten in the kernel circular
	 * buffer.
	 * Kernel will have updated the seek position to the next available
	 * record and subsequent read() will return available records again.
	 */
	do {
		ret = ufd_read(kern->dev_fd,
		               line->data,
		               sizeof(line->data) - 1);
	} while (ret == -EPIPE);

	if (ret > 0) {
		line->vector[ELOGD_LINE_MSG_IOVEC].iov_len = (size_t)ret;
		line->data[ret] = '\0';
		return 0;
	}
	else if (!ret || (ret == -EAGAIN))
		return -EAGAIN;

	elogd_warn("kernel ring-buffer read failed: %s (%d).",
	           strerror((int)-ret),
	           (int)-ret);

	return (int)ret;
}

static __elogd_nonull(1, 2)
const char *
elogd_kern_parse_prio(struct elogd_line * __restrict line,
                      const char * __restrict        string)
{
	elogd_assert(line);
	elogd_assert(string);

	return elogd_parse_prio(string, ',', &line->facility, &line->severity);
}

#if __WORDSIZE == 64

static __elogd_nonull(1, 2)
const char *
elogd_kern_parse_seqno(const char * __restrict string,
                       uint64_t * __restrict   seqno)
{
	elogd_assert(string);
	elogd_assert(seqno);

	unsigned long val;
	char *        end;
	size_t        len;

	val = strtoul(string, &end, 10);
	elogd_assert(end >= string);
	len = (size_t)(end - string);
	if (!len || (len > 20) || (*end != ','))
		return NULL;

	*seqno = val;

	/* Skip ',' separator. */
	return &string[len + 1];
}

static __elogd_nonull(1, 2)
const char *
elogd_kern_parse_tstamp(struct elogd_line * __restrict line,
                        const char * __restrict        string)
{
	elogd_assert(line);
	elogd_assert(string);

	unsigned long     val;
	char *            end;
	size_t            len;
	struct timespec * tstamp = &line->tstamp;

	val = strtoul(string, &end, 10);
	elogd_assert(end >= string);
	len = (size_t)(end - string);
	if (!len || (len > 20) || (*end != ','))
		return NULL;

	tstamp->tv_sec = (time_t)(val / 1000000UL);
	tstamp->tv_nsec = (long)((val % 1000000UL) * 1000UL);

	/* Skip ',' separator. */
	return &string[len + 1];
}

#elif __WORDSIZE == 32

static __elogd_nonull(1, 2)
const char *
elogd_kern_parse_seqno(const char * __restrict string,
                       uint64_t * __restrict   seqno)
{
	elogd_assert(string);
	elogd_assert(seqno);

	unsigned long long val;
	char *             end;
	size_t             len;

	val = strtoull(string, &end, 10);
	elogd_assert(end >= string);
	len = (size_t)(end - string);
	if (!len || (len > 20) || (*end != ','))
		return NULL;

	*seqno = val;

	/* Skip ',' separator. */
	return &string[len + 1];
}

static __elogd_nonull(1, 2)
const char *
elogd_kern_parse_tstamp(struct elogd_line * __restrict line,
                        const char * __restrict        string)
{
	elogd_assert(line);
	elogd_assert(string);

	unsigned long long val;
	char *             end;
	size_t             len;
	struct timespec *  tstamp = &line->tstamp;

	val = strtoull(string, &end, 10);
	elogd_assert(end >= string);
	len = (size_t)(end - string);
	if (!len || (len > 20) || (*end != ','))
		return NULL;

	tstamp->tv_sec = (time_t)(val / 1000000ULL);
	tstamp->tv_nsec = (long)((val % 1000000ULL) * 1000ULL);

	/* Skip ',' separator. */
	return &string[len + 1];
}

#else /* __WORDSIZE != 64 && __WORDSIZE != 32 */
#error "Unsupported machine word size !"
#endif /* __WORDSIZE == 64 */

static __elogd_nonull(1)
const char *
elogd_skip_field(const char * __restrict string, int separator, size_t len)
{
	elogd_assert(string);
	elogd_assert(ispunct(separator) ||
	             isblank(separator) ||
	             (separator == '\n'));

	if (len) {
		const char * sep;

		sep = memchr(string, separator, len);
		if (sep <= string)
			return NULL;

		if (++sep <= &string[len])
			return sep;
	}

	return NULL;
}

static __elogd_nonull(1, 2)
int
elogd_kern_parse(struct elogd_line * __restrict line,
                 uint64_t * __restrict          seqno)
{
	elogd_assert(line);
	elogd_assert(line->vector[ELOGD_LINE_MSG_IOVEC].iov_len);
	elogd_assert(seqno);

	const char *   data = line->data;
	struct iovec * msg = &line->vector[ELOGD_LINE_MSG_IOVEC];
	const char *   end = &line->data[msg->iov_len];

	if (isspace(*data))
		/* Skip empty and continuation lines. */
		return -ENODATA;

	/* Parse priority tag. */
	data = elogd_kern_parse_prio(line, data);
	if (!data)
		goto err;

	/* Parse the 64 bits long sequence number. */
	data = elogd_kern_parse_seqno(data, seqno);
	if (!data)
		goto err;

	/* Parse monotonic timestamp. */
	data = elogd_kern_parse_tstamp(line, data);
	if (!data)
		goto err;

	/* Skip remaining fields up to next semi-colon. */
	data = elogd_skip_field(data, ';', (size_t)(end - data));
	if (!data)
		goto err;

	/*
	 * TODO ?: kernel ring-buffer renders special printable characters as
	 * escaped hexadecimal sequences (such as `\x09' for a TAB). Most
	 * notable example of this looks like:
	 *   `rcu: \x09RCU restricting CPUs from NR_CPUS=8192 to nr_cpu_ids=8'
	 *
	 * Given that this happens in extremely rare occations, should we
	 * translate these as real printable characters ?
	 */

	/* Parse and skip empty message body. */
	end = elogd_skip_field(data, '\n', (size_t)(end - data));
	if (!end)
		return -ENODATA;

	line->tag_len = sizeof("kernel") - 1;
	line->tag = "kernel";
	line->pid = 0;

	/*
	 * Save start of message body, include first terminating newline and
	 * skip the rest of message.
	 */
STROLL_IGNORE_WARN("-Wcast-qual")
	msg->iov_base = (void *)data;
STROLL_RESTORE_WARN
	msg->iov_len = (size_t)(end - data);

	return 0;

err:
	elogd_warn("kernel ring-buffer parsing failed: unexpected message.");

	return -EINVAL;
}

static __elogd_nonull(1)
int
elogd_kern_process(struct elogd_kern * __restrict kern)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.kern_on);
	elogd_kern_assert(kern);

	struct elogd_line * line;
	uint64_t            seqno;
	int                 ret;

	line = elogd_line_create();
	if (!line)
		return -ENOBUFS;

	ret = elogd_kern_read(kern, line);
	if (ret)
		goto release;

	ret = elogd_kern_parse(line, &seqno);
	if (ret)
		goto release;

	*kern->seqno = seqno;

	elogd_nqueue(&kern->queue, line);

	return 0;

release:
	elogd_line_destroy(line);

	return ret;
}

static __elogd_nonull(1, 3)
int
elogd_kern_dispatch(struct upoll_worker * work,
                    uint32_t              state __unused,
                    const struct upoll *  poll __unused)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.kern_on);
	elogd_assert(work);
	elogd_assert(state);
	elogd_assert(!(state & EPOLLOUT));
	elogd_assert(!(state & EPOLLRDHUP));
	elogd_assert(!(state & EPOLLPRI));
	elogd_assert(state & (EPOLLIN | EPOLLERR));
	elogd_assert(poll);

	struct elogd_kern * kern;
	unsigned int        cnt;

	kern = containerof(work, struct elogd_kern, work);
	elogd_kern_assert(kern);

	cnt = elogd_queue_free_count(&kern->queue);
	if (cnt) {
		do {
			int ret;

			ret = elogd_kern_process(kern);
			switch (ret) {
			case 0:
				break;

			case -ENOBUFS:
			case -EAGAIN:
				goto publish;

			default:
				break;
			}
		} while (--cnt);
	}

publish:
	if (elogd_queue_busy_count(&kern->queue))
		elogd_pipe_on_alive(kern->pipe, &kern->queue);

	return 0;
}

static __elogd_nonull(1)
int
elogd_kern_skip(struct elogd_kern * __restrict kern)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.kern_on);
	elogd_kern_assert(kern);

	struct elogd_line * line;
	uint64_t            seqno;
	int                 ret;

	line = elogd_line_create();
	if (!line)
		return -ENOBUFS;

	do {
		ret = elogd_kern_read(kern, line);
		elogd_assert(ret != -EINTR);
		if (ret)
			break;

		ret = elogd_kern_parse(line, &seqno);
		if (ret && (ret != -ENODATA))
			break;
	} while (seqno <= *kern->seqno);

	if (ret && (ret != -EAGAIN))
		goto release;

	if (seqno == *kern->seqno) {
		ret = 0;
		goto release;
	}

	*kern->seqno = seqno;

	elogd_nqueue(&kern->queue, line);

	return 0;

release:
	elogd_line_destroy(line);

	return ret;
}

static __elogd_nonull(1)
int
elogd_kern_open_stat(struct elogd_kern * __restrict kern)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.kern_on);
	elogd_assert(kern);

	char *       path;
	int          fd;
	int          err;
	struct stat  st;
	const char * msg;
	uint64_t *   seqno;

	err = (int)elogd_make_path(&path,
	                           elogd_conf.rundir_path,
	                           elogd_conf.rundir_len,
	                           "stat",
	                           sizeof("stat") - 1);
	if (err < 0)
		return err;

	fd = ufile_new(path,
	               O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NOATIME,
	               S_IRUSR | S_IWUSR);
	if (fd < 0) {
		elogd_assert(fd != -EINTR);
		err = fd;
		msg = "open failed";
		goto err;
	}

	err = ufile_fstat(fd, &st);
	if (err) {
		msg = "status retrieval failed";
		goto close;
	}

	if (!S_ISREG(st.st_mode) ||
	    ((st.st_mode & (S_IRUSR | S_IWUSR)) != (S_IRUSR | S_IWUSR)) ||
	    (st.st_uid != elogd_uid) ||
	    (st.st_gid != elogd_gid)) {
		err = -EPERM;
		msg = "unexpected file attributes";
		goto close;
	}

	/*
	 * If file did not exist (and was created just above), ftruncate() will
	 * pad its content with zeros, incurring zero initialization of
	 * kern->seqno.
	 */
	err = ufile_ftruncate(fd, sizeof(*kern->seqno));
	if (err) {
		elogd_assert(err != -EINTR);
		msg = "truncate failed";
		goto close;
	}

	seqno = mmap(NULL,
	             sizeof(*seqno),
	             PROT_READ | PROT_WRITE,
	             MAP_SHARED,
	             fd,
	             0);
	if (seqno == MAP_FAILED) {
		err = -errno;
		elogd_assert(err != -EBADF);
		elogd_assert(err != -EINVAL);
		elogd_assert(err != -EOVERFLOW);

		msg = "mmap failed";
		goto close;
	}

	kern->stat_fd = fd;
	kern->seqno = seqno;

	free(path);

	return 0;

close:
	ufile_close(fd);
err:
	elogd_err("'%s': %s: %s (%d).",
	          path,
	          msg,
	          strerror(-err),
	          -err);
#if defined(CONFIG_ELOGD_DEBUG)
	free(path);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	return err;
}

static __elogd_nonull(1, 2, 3)
int
elogd_kern_open(struct elogd_kern * __restrict  kern,
                struct elogd_pipe * __restrict  pipe,
                const struct upoll * __restrict poll)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.kern_on);
	elogd_assert(kern);
	elogd_assert(pipe);
	elogd_assert(poll);

	int          fd;
	int          err;
	const char * msg;

	elogd_debug("initializing kernel ring-buffer...");

	/*
	 * This will require CAP_SYSLOG or CAP_SYS_ADMIN capability if kernel is
	 * built with CONFIG_SECURITY_DMESG_RESTRICT enabled !!
	 */
	fd = ufd_open(ELOGD_KERN_DPATH,
	              O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW |
	              O_NONBLOCK);
	if (fd < 0) {
		err = fd;
		msg = "'/dev/kern': open failed";
		goto err;
	}

	err = elogd_kern_open_stat(kern);
	if (err) {
		msg = "cannot retrieve message sequence";
		goto close_dev;
	}

	kern->work.dispatch = elogd_kern_dispatch;
	err = upoll_register(poll,
	                     fd,
	                     EPOLLIN,
	                     &kern->work);
	if (err) {
		msg = "cannot register poll worker";
		goto close_stat;
	}

	err = (int)ufd_lseek(fd, 0, SEEK_DATA);
	elogd_assert(!err);

	elogd_queue_init(&kern->queue, elogd_conf.kern_fetch);
	kern->dev_fd = fd;

	kern->pipe = pipe;

	if (*kern->seqno) {
		err = elogd_kern_skip(kern);
		if (err) {
			msg = "cannot skip outdated messages";
			goto close_poll;
		}
	}

	if (elogd_queue_busy_count(&kern->queue))
		elogd_pipe_on_alive(pipe, &kern->queue);

	elogd_info("kernel ring-buffer initialized.");

	return 0;

close_poll:
	upoll_unregister(poll, fd);
close_stat:
	munmap(kern->seqno, sizeof(*kern->seqno));
	ufile_close(kern->stat_fd);
close_dev:
#if defined(CONFIG_ELOGD_DEBUG)
	ufd_close(fd);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
err:
	elogd_err("cannot initialize kernel ring-buffer: %s: %s (%d).",
	          msg,
	          strerror(-err),
	          -err);

	return err;
}

static __elogd_nonull(1, 2)
void
elogd_kern_close(const struct elogd_kern * __restrict kern,
                 const struct upoll * __restrict      poll __unused)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.kern_on);
	elogd_kern_assert(kern);
	elogd_assert(poll);

	elogd_debug("closing kernel ring-buffer...");

#if defined(CONFIG_ELOGD_DEBUG)
	upoll_unregister(poll, kern->dev_fd);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	elogd_queue_fini(&kern->queue);

	munmap(kern->seqno, sizeof(*kern->seqno));
	ufile_close(kern->stat_fd);

#if defined(CONFIG_ELOGD_DEBUG)
	ufd_close(kern->dev_fd);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
}

struct elogd_kern *
elogd_kern_create(struct elogd_pipe * __restrict  pipe,
                  const struct upoll * __restrict poll)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.kern_on);
	elogd_assert(pipe);
	elogd_assert(poll);

	struct elogd_kern * kern;

	kern = malloc(sizeof(*kern));
	if (!kern) {
		errno = -ENOMEM;
		return NULL;
	}

	if (elogd_kern_open(kern, pipe, poll))
		goto free;

	return kern;

free:
#if defined(CONFIG_ELOGD_DEBUG)
	free(kern);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	return NULL;
}

void
elogd_kern_destroy(struct elogd_kern * __restrict  kern,
                   const struct upoll * __restrict poll)
{
	elogd_assert_conf();
	elogd_assert(elogd_conf.kern_on);
	elogd_kern_assert(kern);
	elogd_assert(poll);

	elogd_kern_close(kern, poll);

#if defined(CONFIG_ELOGD_DEBUG)
	free(kern);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
}
