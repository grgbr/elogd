/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "kmsg.h"
#include <utils/time.h>
#include <utils/file.h>
#include <ctype.h>
#include <sys/mman.h>

static __elogd_nonull(1, 2) __elogd_nothrow
const char *
elogd_kmsg_parse_prio(struct elogd_line * __restrict line,
                      const char * __restrict        string)
{
	elogd_assert(line);
	elogd_assert(string);

	return elogd_parse_prio(string, ',', &line->facility, &line->severity);
}

#if __WORDSIZE == 64

static __elogd_nonull(1, 2) __elogd_nothrow
const char *
elogd_kmsg_parse_seqno(const char * __restrict string,
                       uint64_t * __restrict   seqno)
{
	elogd_assert(string);
	elogd_assert(seqno);

	unsigned long val;
	char *        end;
	size_t        len;

	val = strtoul(string, &end, 10);
	len = end - string;
	if (!len || (len > 20) || (*end != ','))
		return NULL;

	*seqno = val;

	/* Skip ',' separator. */
	return &string[len + 1];
}

static __elogd_nonull(1, 2) __elogd_nothrow
const char *
elogd_kmsg_parse_tstamp(struct elogd_line * __restrict line,
                        const char * __restrict        string)
{
	elogd_assert(line);
	elogd_assert(string);

	unsigned long     val;
	char *            end;
	size_t            len;
	struct timespec * tstamp = &line->tstamp;

	val = strtoul(string, &end, 10);
	len = end - string;
	if (!len || (len > 20) || (*end != ','))
		return NULL;

	tstamp->tv_sec = (time_t)(val / 1000000UL);
	tstamp->tv_nsec = (long)((val % 1000000UL) * 1000UL);

	/* Skip ',' separator. */
	return &string[len + 1];
}

#elif __WORDSIZE == 32

static __elogd_nonull(1, 2) __elogd_nothrow
const char *
elogd_kmsg_parse_seqno(const char * __restrict string,
                       uint64_t * __restrict   seqno)
{
	elogd_assert(string);
	elogd_assert(seqno);

	unsigned long long val;
	char *             end;
	size_t             len;

	val = strtoull(string, &end, 10);
	len = end - string;
	if (!len || (len > 20) || (*end != ','))
		return NULL;

	*seqno = val;

	/* Skip ',' separator. */
	return &string[len + 1];
}

static __elogd_nonull(1, 2) __elogd_nothrow
const char *
elogd_kmsg_parse_tstamp(struct elogd_line * __restrict line,
                        const char * __restrict        string)
{
	elogd_assert(line);
	elogd_assert(string);

	unsigned long long val;
	char *             end;
	size_t             len;
	struct timespec *  tstamp = &line->tstamp;

	val = strtoull(string, &end, 10);
	len = end - string;
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

static __elogd_nonull(1) __elogd_nothrow
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

static __elogd_nonull(1, 2) __elogd_nothrow
int
elogd_kmsg_parse(struct elogd_line * __restrict line,
                 uint64_t * __restrict          seqno)
{
	elogd_assert(line);
	elogd_assert(line->vector[ELOGD_LINE_MSG_IOVEC].iov_len);

	const char *    data = line->data;
	struct iovec *  msg = &line->vector[ELOGD_LINE_MSG_IOVEC];
	const char *    end = &line->data[msg->iov_len];
	struct timespec now;

	if (isspace(*data))
		/* Skip empty and continuation lines. */
		return -EINVAL;

	/* Parse priority tag. */
	data = elogd_kmsg_parse_prio(line, data);
	if (!data)
		return -EINVAL;

	/* Parse the 64 bits long sequence number. */
	data = elogd_kmsg_parse_seqno(data, seqno);
	if (!data)
		return -EINVAL;

	/* Parse monotonic timestamp. */
	data = elogd_kmsg_parse_tstamp(line, data);
	if (!data)
		return -EINVAL;

	/* Skip remaining fields up to next semi-colon. */
	data = elogd_skip_field(data, ';', end - data);
	if (!data)
		return -EINVAL;

	/* Parse message body. */
	end = elogd_skip_field(data, '\n', end - data);
	if (!end)
		return -EINVAL;

	/*
	 * Kernel logging messages are assigned timestamp within the boot time
	 * space.
	 */
	utime_boot_now(&now);
	if (utime_tspec_after(&line->tstamp, &now))
		line->tstamp = now;

	line->tag_len = sizeof("kernel") - 1;
	line->tag = "kernel";
	line->pid = 0;

	/*
	 * Save start of message body, include first terminating newline and
	 * skip the rest of message.
	 */
	msg->iov_base = (void *)data;
	msg->iov_len = end - data;

	return 0;
}

static __elogd_nonull(1, 2) __elogd_nothrow
int
elogd_kmsg_read(const struct elogd_kmsg * __restrict kmsg,
                struct elogd_line * __restrict       line)
{
	elogd_assert(kmsg);
	elogd_assert(kmsg->dev_fd >= 0);
	elogd_assert(kmsg->seqno);
	elogd_assert(kmsg->stat_fd >= 0);

	ssize_t ret;

	/*
	 * As stated by <linux>/doc/Documentation/ABI/testing/dev-kmsg
	 *
	 * Each read() from kmsg receives one single record of the kernel's
	 * printk buffer.
	 * kmsg returns EPIPE if record got overwritten in the kernel circular
	 * buffer.
	 * Kernel will have updated the seek position to the next available
	 * record and subsequent read() will return available records again.
	 */
	do {
		ret = ufd_read(kmsg->dev_fd,
		               line->data,
		               sizeof(line->data) - 1);
	} while (ret == -EPIPE);

	if (ret > 0) {
		line->vector[ELOGD_LINE_MSG_IOVEC].iov_len = ret;
		line->data[ret] = '\0';
		return 0;
	}

	return (!ret) ? -EAGAIN : ret;
}

static __elogd_nonull(1) __elogd_nothrow
int
elogd_kmsg_process(struct elogd_kmsg * __restrict kmsg)
{
	elogd_assert(kmsg);
	elogd_assert(kmsg->dev_fd >= 0);
	elogd_assert(kmsg->seqno);
	elogd_assert(kmsg->stat_fd >= 0);

	struct elogd_line * ln;
	uint64_t            seqno;
	int                 ret;

	ln = elogd_line_create();
	if (!ln)
		return -ENOBUFS;

	ret = elogd_kmsg_read(kmsg, ln);
	if (ret)
		goto release;

	ret = elogd_kmsg_parse(ln, &seqno);
	if (ret)
		goto release;

	*kmsg->seqno = seqno;

	/*
	 * No need to reorder lines with respect to timestamp for kernel
	 * messages.
	 */
	elogd_nqueue(&kmsg->queue, ln);

	return 0;

release:
	elogd_line_destroy(ln);

	return ret;
}

static __elogd_nonull(1, 3) __elogd_nothrow
int
elogd_kmsg_dispatch(struct upoll_worker * work,
                    uint32_t              state __unused,
                    const struct upoll *  poll __unused)
{
	elogd_assert_conf();
	elogd_assert(work);
	elogd_assert(state);
	elogd_assert(!(state & EPOLLOUT));
	elogd_assert(!(state & EPOLLRDHUP));
	elogd_assert(!(state & EPOLLPRI));
	elogd_assert(state & (EPOLLIN | EPOLLERR));
	elogd_assert(poll);

	struct elogd_kmsg * kmsg;
	unsigned int        cnt;

	kmsg = containerof(work, struct elogd_kmsg, work);
	elogd_assert(kmsg);
	elogd_assert(kmsg->dev_fd >= 0);
	elogd_assert(kmsg->seqno);
	elogd_assert(kmsg->stat_fd >= 0);

	cnt = elogd_queue_free_count(&kmsg->queue);
	while (cnt--) {
		int ret;

		ret = elogd_kmsg_process(kmsg);
		switch (ret) {
		case 0:
			break;

		case -ENOBUFS:
		case -EAGAIN:
			return 0;

		default:
			elogd_assert(0);
		}
	}

	return 0;
}

static __elogd_nonull(1) __elogd_nothrow
int
elogd_kmsg_skip(struct elogd_kmsg * __restrict kmsg)
{
	elogd_assert(kmsg);
	elogd_assert(kmsg->dev_fd >= 0);
	elogd_assert(kmsg->seqno);
	elogd_assert(kmsg->stat_fd >= 0);

	struct elogd_line * ln;
	uint64_t            seqno;
	int                 ret;

	ln = elogd_line_create();
	if (!ln)
		return -ENOBUFS;

	do {
		ret = elogd_kmsg_read(kmsg, ln);
		elogd_assert(ret != -EINTR);
		if (ret)
			break;

		ret = elogd_kmsg_parse(ln, &seqno);
		if (ret)
			break;
	} while (seqno <= *kmsg->seqno);

	if (ret && (ret != -EAGAIN))
		goto release;

	if (seqno == *kmsg->seqno) {
		ret = 0;
		goto release;
	}

	*kmsg->seqno = seqno;

	/* Messages are already ordered within the boot time space. */
	elogd_nqueue(&kmsg->queue, ln);

	return 0;

release:
	elogd_line_destroy(ln);

	return ret;
}

static __elogd_nonull(1)
int
elogd_kmsg_open_stat(struct elogd_kmsg * __restrict kmsg)
{
	elogd_assert_conf();
	elogd_assert(kmsg);

	int          fd;
	int          err;
	struct stat  st;
	const char * msg;
	uint64_t *   seqno;

	fd = ufile_new(elogd_conf.stat_path,
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
	 * kmsg->seqno.
	 */
	err = ufile_ftruncate(fd, sizeof(*kmsg->seqno));
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

	kmsg->stat_fd = fd;
	kmsg->seqno = seqno;

	return 0;

close:
	ufile_close(fd);
err:
	elogd_err("'%s': %s: %s (%d).\n",
	          elogd_conf.stat_path,
	          msg,
	          strerror(-err),
	          -err);

	return err;
}

int
elogd_kmsg_open(struct elogd_kmsg * __restrict  kmsg,
                const struct upoll * __restrict poll)
{
	elogd_assert(kmsg);
	elogd_assert(poll);

	int          fd;
	int          err;
	const char * msg;

	/*
	 * This will require CAP_SYSLOG or CAP_SYS_ADMIN capability if kernel is
	 * built with CONFIG_SECURITY_DMESG_RESTRICT enabled !!
	 */
	fd = ufd_open("/dev/kmsg",
	              O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW |
	              O_NONBLOCK);
	if (fd < 0) {
		err = fd;
		msg = "'/dev/kmsg': open failed";
		goto err;
	}

	err = elogd_kmsg_open_stat(kmsg);
	if (err) {
		msg = "cannot retrieve message sequence";
		goto close_dev;
	}

	kmsg->work.dispatch = elogd_kmsg_dispatch;
	err = upoll_register(poll,
	                     fd,
	                     EPOLLIN,
	                     &kmsg->work);
	if (err) {
		msg = "cannot register poll worker";
		goto close_stat;
	}

	err = ufd_lseek(fd, 0, SEEK_DATA);
	elogd_assert(!err);

	elogd_queue_init(&kmsg->queue, elogd_conf.kmsg_fetch);
	kmsg->dev_fd = fd;

	if (*kmsg->seqno) {
		err = elogd_kmsg_skip(kmsg);
		if (err) {
			msg = "cannot skip outdated messages";
			goto close_poll;
		}
	}

	return 0;

close_poll:
	upoll_unregister(poll, fd);
close_stat:
	munmap(kmsg->seqno, sizeof(*kmsg->seqno));
	ufile_close(kmsg->stat_fd);
close_dev:
	ufd_close(fd);
err:
	elogd_err("cannot initialize kernel ring-buffer: %s: %s (%d).\n",
	          msg,
	          strerror(-err),
	          -err);

	return err;
}

void
elogd_kmsg_close(const struct elogd_kmsg * __restrict kmsg,
                 const struct upoll * __restrict      poll)
{
	elogd_assert(kmsg);
	elogd_assert(kmsg->dev_fd >= 0);
	elogd_assert(kmsg->seqno);
	elogd_assert(kmsg->stat_fd >= 0);
	elogd_assert(poll);

	upoll_unregister(poll, kmsg->dev_fd);

	elogd_queue_fini(&kmsg->queue);

	munmap(kmsg->seqno, sizeof(*kmsg->seqno));
	ufile_close(kmsg->stat_fd);

	ufd_close(kmsg->dev_fd);
}
