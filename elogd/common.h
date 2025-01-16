/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _ELOGD_COMMON_H
#define _ELOGD_COMMON_H

#if !defined(_GNU_SOURCE)
#error elogd expects the GNU version of basename(3) !
#endif /* !defined(_GNU_SOURCE) */

#include "elogd/config.h"
#include <elog/elog.h>
#if defined(CONFIG_ELOGD_MQUEUE)
#include <utils/mqueue.h>
#endif /* defined(CONFIG_ELOGD_MQUEUE) */
#include <utils/path.h>
#include <utils/pwd.h>
#include <stroll/dlist.h>
#include <linux/taskstats.h>

#if defined(CONFIG_ELOGD_ASSERT)

#include <stroll/assert.h>

#define __elogd_nonull(_arg_index, ...)
#define __elogd_pure
#define __elogd_const
#define __elogd_nothrow
#define elogd_assert(_expr)             stroll_assert("elogd", _expr)

#else  /* !defined(CONFIG_ELOGD_ASSERT) */

#define __elogd_nonull(_arg_index, ...) __nonull(_arg_index, ## __VA_ARGS__)
#define __elogd_pure                    __pure
#define __elogd_const                   __const
#define __elogd_nothrow                 __nothrow
#define elogd_assert(_expr)             do { } while (0)

#endif /* defined(CONFIG_ELOGD_ASSERT) */

extern pid_t elogd_pid;
extern uid_t elogd_uid;
extern gid_t elogd_gid;

/******************************************************************************
 * Global configuration
 ******************************************************************************/

#if CONFIG_ELOGD_SIZE_MIN < 4096
#error Invalid minimum logging file size (must be >= 4096) !
#endif
#define ELOGD_FILE_SIZE_MIN STROLL_CONCAT(CONFIG_ELOGD_SIZE_MIN, U)
#if CONFIG_ELOGD_SIZE_MAX > SSIZE_MAX
#error Invalid maximum logging file size (must be <= SSIZE_MAX) !
#endif
#define ELOGD_FILE_SIZE_MAX STROLL_CONCAT(CONFIG_ELOGD_SIZE_MAX, U)
#define ELOGD_FILE_ROT_MIN  STROLL_CONCAT(CONFIG_ELOGD_ROT_MIN, U)
#define ELOGD_FILE_ROT_MAX  STROLL_CONCAT(CONFIG_ELOGD_ROT_MAX, U)
#define ELOGD_FETCH_MIN     STROLL_CONCAT(CONFIG_ELOGD_FETCH_MIN, U)
#define ELOGD_FETCH_MAX     STROLL_CONCAT(CONFIG_ELOGD_FETCH_MAX, U)
#define ELOGD_DELAY_MIN     STROLL_CONCAT(CONFIG_ELOGD_DELAY_MIN, U)
#define ELOGD_DELAY_MAX     STROLL_CONCAT(CONFIG_ELOGD_DELAY_MAX, U)
#define ELOGD_SVC_MODE      STROLL_CONCAT(0, CONFIG_ELOGD_SVC_MODE)
#define ELOGD_FILE_MODE     STROLL_CONCAT(0, CONFIG_ELOGD_FILE_MODE)
#define ELOGD_DELAY         STROLL_CONCAT(CONFIG_ELOGD_DELAY, U)

struct elogd_config {
	const char *           user;
	const char *           lock_path;
	const char *           stat_path;
	const char *           kmsg_path;
	unsigned int           kmsg_fetch;
#if defined(CONFIG_ELOGD_MQUEUE)
	const char *           mqueue_name;
	unsigned int           mqueue_fetch;
#endif /* defined(CONFIG_ELOGD_MQUEUE) */
	const char *           dir_path;
	const char *           file_base;
	size_t                 file_len;
	const char *           file_group;
	mode_t                 file_mode;
	size_t                 max_size;
	unsigned int           max_rot;
	const char *           sock_path;
	const char *           svc_group;
	mode_t                 svc_mode;
	unsigned int           svc_fetch;
	struct elog_conf       intlog;
	unsigned int           intlog_fetch;
	unsigned int           delay;
	struct elog_stdio_conf stdlog;
};

#if defined(CONFIG_ELOGD_MQUEUE)

#define elogd_assert_mqueue_conf() \
	elogd_assert(!elogd_conf.mqueue_name || \
	             (umq_validate_name(elogd_conf.mqueue_name) > 0)); \
	elogd_assert(elogd_conf.mqueue_fetch > 0)

#else  /* !defined(CONFIG_ELOGD_MQUEUE) */

#define elogd_assert_mqueue_conf()

#endif /* defined(CONFIG_ELOGD_MQUEUE) */

#define elogd_assert_conf() \
	elogd_assert(!elogd_conf.user || \
	             upwd_validate_user_name(elogd_conf.user) > 0); \
	elogd_assert(upath_validate_path_name(elogd_conf.lock_path) > 0); \
	elogd_assert(upath_validate_path_name(elogd_conf.stat_path) > 0); \
	elogd_assert(!elogd_conf.kmsg_path || \
	             (upath_validate_path_name(elogd_conf.kmsg_path) > 0)); \
	elogd_assert(elogd_conf.kmsg_fetch > 0); \
	elogd_assert_mqueue_conf(); \
	elogd_assert(upath_validate_path_name(elogd_conf.dir_path) > 0); \
	elogd_assert(elogd_conf.file_len); \
	elogd_assert((size_t)upath_validate_file_name(elogd_conf.file_base) == \
	             elogd_conf.file_len); \
	elogd_assert(!elogd_conf.file_group || elogd_conf.file_group[0]); \
	elogd_assert(!(elogd_conf.file_mode & ~((mode_t)DEFFILEMODE))); \
	elogd_assert(elogd_conf.max_size >= ELOGD_FILE_SIZE_MIN); \
	elogd_assert(elogd_conf.max_size <= ELOGD_FILE_SIZE_MAX); \
	elogd_assert(elogd_conf.max_rot); \
	elogd_assert(elogd_conf.max_rot <= ELOGD_FILE_ROT_MAX); \
	elogd_assert(!elogd_conf.sock_path || \
	             (upath_validate_path_name(elogd_conf.sock_path) > 0)); \
	elogd_assert(!elogd_conf.svc_group || elogd_conf.svc_group[0]); \
	elogd_assert(!(elogd_conf.svc_mode & ~((mode_t)DEFFILEMODE))); \
	elogd_assert(elogd_conf.svc_fetch > 0); \
	elogd_assert((elogd_conf.intlog.severity == -1) ^ \
	             !(elogd_conf.intlog.severity & ~LOG_PRIMASK)); \
	elogd_assert(elogd_conf.intlog_fetch > 0); \
	elogd_assert(elogd_conf.delay > 0); \
	elogd_assert((elogd_conf.stdlog.super.severity == -1) ^ \
	             !(elogd_conf.stdlog.super.severity & ~LOG_PRIMASK)); \
	elogd_assert(elogd_conf.stdlog.format == \
	             (ELOG_TAG_FMT | ELOG_SEVERITY_FMT))

extern struct elogd_config elogd_conf;

/******************************************************************************
 * Various helper definitions
 ******************************************************************************/

#define ELOGD_PRIO_FIELD_MIN_LEN (3U)
#define ELOGD_PRIO_FIELD_MAX_LEN (5U)
#define ELOGD_TSTAMP_FIELD_LEN   (32U)
#define ELOGD_TAG_MAX_SIZE       ((size_t)TS_COMM_LEN)
#define ELOGD_TAG_MIN_LEN        (1U)
#define ELOGD_TAG_MAX_LEN        (ELOGD_TAG_MAX_SIZE - 1)
#define ELOGD_PID_MAX_LEN        (10U)

extern const char *
elogd_parse_prio(const char * __restrict string,
                 int                     separator,
                 int * __restrict        facility,
                 int * __restrict        severity)
	__elogd_nonull(1, 3, 4) __elogd_nothrow __leaf __warn_result;

extern char *
elogd_probe_string_delim(const char * __restrict string, int delim, size_t len)
	__elogd_nonull(1) __elogd_pure __elogd_nothrow __leaf __warn_result;

/******************************************************************************
 * Logging output line handling.
 ******************************************************************************/

/*
 * Maximum len of a logging output line excluding the terminating newline
 * or NULL byte.
 */
#define ELOGD_LINE_MAX_LEN (1024U)

/*
 * Minimum size of logging output line header (RFC3164 compliant without
 * PID nor hostname fields) including the terminating NULL byte.
 */
#define ELOGD_HEAD_MIN_SIZE \
	(ELOGD_PRIO_FIELD_MIN_LEN + \
	 ELOGD_TSTAMP_FIELD_LEN + \
	 sizeof(' ') + \
	 ELOGD_TAG_MIN_LEN + \
	 sizeof(": "))

/*
 * Maximum size of logging output line header (RFC3164 compliant without
 * hostname field) including the terminating NULL byte.
 */
#define ELOGD_HEAD_MAX_SIZE \
	(ELOGD_PRIO_FIELD_MAX_LEN + \
	 ELOGD_TSTAMP_FIELD_LEN + \
	 sizeof(' ') + \
	 ELOGD_TAG_MAX_LEN + \
	 sizeof('[') + ELOGD_PID_MAX_LEN + sizeof(']') + \
	 sizeof(": "))

enum {
	ELOGD_LINE_HEAD_IOVEC = 0,
	ELOGD_LINE_MSG_IOVEC  = 1,
	ELOGD_LINE_IOVEC_NR
};

struct elogd_line {
	struct stroll_dlist_node node;
	struct timespec          tstamp;
	int                      facility;
	int                      severity;
	size_t                   tag_len;
	const char *             tag;
	pid_t                    pid;
	struct iovec             vector[ELOGD_LINE_IOVEC_NR];
	char                     head[ELOGD_HEAD_MAX_SIZE];
	char                     data[ELOGD_LINE_MAX_LEN + 1];
};

#define elogd_line_assert_msg(_line, _iovec) \
	elogd_assert((_iovec)[ELOGD_LINE_MSG_IOVEC].iov_len); \
	elogd_assert((_iovec)[ELOGD_LINE_MSG_IOVEC].iov_len < \
	             sizeof((_line)->data)); \
	elogd_assert((char *)(_iovec)[ELOGD_LINE_MSG_IOVEC].iov_base >= \
	             (_line)->data); \
	elogd_assert((char *)(_iovec)[ELOGD_LINE_MSG_IOVEC].iov_base < \
	             &(_line)->data[sizeof((_line)->data)])

#define elogd_line_assert_queued(_line) \
	elogd_assert(!((_line)->severity & ~LOG_PRIMASK)); \
	elogd_assert(!((_line)->facility & ~LOG_FACMASK)); \
	elogd_line_assert_msg(_line, (_line)->vector)

static inline __elogd_nonull(1)
              __elogd_pure
              __elogd_nothrow
              __returns_nonull
              __warn_result
struct elogd_line *
elogd_line_from_node(const struct stroll_dlist_node * __restrict node)
{
	elogd_assert(node);

	return stroll_dlist_entry(node, struct elogd_line, node);
}

static inline __elogd_nonull(1) __elogd_pure __elogd_nothrow
size_t
elogd_line_len(const struct elogd_line * __restrict line)
{
	elogd_assert(line);
	elogd_line_assert_msg(line, line->vector);
	elogd_assert(line->vector[ELOGD_LINE_HEAD_IOVEC].iov_base);

	return line->vector[ELOGD_LINE_HEAD_IOVEC].iov_len +
	       line->vector[ELOGD_LINE_MSG_IOVEC].iov_len;
}

static inline __elogd_nonull(1) __elogd_nothrow
void
elogd_line_copy_iovec(
	const struct elogd_line * __restrict line,
	struct iovec                         iovecs[__restrict_arr 2])
{
	elogd_assert(line);
	elogd_line_assert_msg(line, line->vector);
	elogd_assert(line->vector[ELOGD_LINE_HEAD_IOVEC].iov_base);

	iovecs[0] = line->vector[ELOGD_LINE_HEAD_IOVEC];
	iovecs[1] = line->vector[ELOGD_LINE_MSG_IOVEC];
}

extern void
elogd_line_fill_rfc3164(struct elogd_line * __restrict     line,
                        const struct timespec * __restrict real_off)
	 __elogd_nonull(1, 2) __elogd_nothrow __leaf;

extern void
elogd_line_fixup_partial(struct elogd_line * __restrict line, size_t written)
	__elogd_nonull(1) __elogd_nothrow __leaf;

extern struct elogd_line *
elogd_line_create(void)
	__elogd_nothrow __leaf __warn_result;

extern void
elogd_line_destroy(struct elogd_line * __restrict line)
	__elogd_nonull(1) __elogd_nothrow __leaf;

/******************************************************************************
 * Logging output line allocator
 ******************************************************************************/

extern int
elogd_alloc_init(unsigned int nr)
	__elogd_nothrow __leaf __warn_result;

extern void
elogd_alloc_fini(void)
	__elogd_nothrow __leaf;

/******************************************************************************
 * Logging output line queue
 ******************************************************************************/

struct elogd_queue {
	unsigned int             cnt;
	unsigned int             nr;
	struct stroll_dlist_node head;
};

#define elogd_queue_assert(_queue) \
	elogd_assert(_queue); \
	elogd_assert((_queue)->nr); \
	elogd_assert((_queue)->cnt <= (_queue)->nr); \
	elogd_assert(!!(_queue)->cnt ^ stroll_dlist_empty(&(_queue)->head))

#define elogd_queue_foreach_node(_queue, _node) \
	stroll_dlist_foreach_node(&(_queue)->head, _node)

static inline __elogd_nonull(1) __elogd_pure __elogd_nothrow __warn_result
unsigned int
elogd_queue_nr(const struct elogd_queue * __restrict queue)
{
	elogd_queue_assert(queue);

	return queue->nr;
}

static inline __elogd_nonull(1) __elogd_pure __elogd_nothrow __warn_result
unsigned int
elogd_queue_busy_count(const struct elogd_queue * __restrict queue)
{
	elogd_queue_assert(queue);

	return queue->cnt;
}

static inline __elogd_nonull(1) __elogd_pure __elogd_nothrow __warn_result
unsigned int
elogd_queue_free_count(const struct elogd_queue * __restrict queue)
{
	elogd_queue_assert(queue);

	return queue->nr - queue->cnt;
}

static inline __elogd_nonull(1) __elogd_pure __elogd_nothrow __warn_result
bool
elogd_queue_empty(const struct elogd_queue * __restrict queue)
{
	elogd_queue_assert(queue);

	return !queue->cnt;
}

static inline __elogd_nonull(1) __elogd_pure __elogd_nothrow __warn_result
bool
elogd_queue_full(const struct elogd_queue * __restrict queue)
{
	elogd_queue_assert(queue);

	return queue->cnt == queue->nr;
}

static inline __elogd_nonull(1)
              __elogd_pure
              __elogd_nothrow
              __returns_nonull
              __warn_result
struct stroll_dlist_node *
elogd_queue_head(const struct elogd_queue * __restrict queue)
{
	elogd_queue_assert(queue);

STROLL_IGNORE_WARN("-Wcast-qual")
	return (struct stroll_dlist_node *)&queue->head;
STROLL_RESTORE_WARN
}

static inline __elogd_nonull(1)
              __elogd_pure
              __elogd_nothrow
              __returns_nonull
              __warn_result
const struct elogd_line *
elogd_queue_peek(const struct elogd_queue * __restrict queue)
{
	elogd_queue_assert(queue);
	elogd_assert(queue->cnt);

	return elogd_line_from_node(stroll_dlist_next(&queue->head));
}

static inline __elogd_nonull(1, 2) __elogd_nothrow
void
elogd_nqueue(struct elogd_queue * __restrict queue,
             struct elogd_line * __restrict  line)
{
	elogd_queue_assert(queue);
	elogd_assert(queue->cnt < queue->nr);
	elogd_line_assert_queued(line);

	stroll_dlist_nqueue_back(&queue->head, &line->node);
	queue->cnt++;
}

extern int
elogd_queue_line_cmp(const struct stroll_dlist_node * __restrict first,
                     const struct stroll_dlist_node * __restrict second,
                     void *                                      data __unused)
	__elogd_nonull(1, 2) __elogd_pure __elogd_nothrow __leaf __warn_result;

extern void
elogd_queue_move(struct elogd_queue * __restrict destination,
                 struct elogd_queue * __restrict source)
	__elogd_nonull(1, 2) __elogd_nothrow __leaf;

extern void
elogd_nqueue_presort(struct elogd_queue * __restrict       queue,
                     struct stroll_dlist_node * __restrict presort,
                     unsigned int                          count)
	__elogd_nonull(1, 2) __elogd_nothrow;

extern void
elogd_queue_kwmerge(struct elogd_queue * queues[__restrict_arr],
                    unsigned int         count)
	__elogd_nonull(1) __elogd_nothrow __leaf;

extern void
elogd_queue_release_bulk(struct elogd_queue * __restrict       queue,
                         struct stroll_dlist_node * __restrict last,
                         unsigned int                          count)
	__elogd_nonull(1, 2) __elogd_nothrow __leaf;

extern void
elogd_queue_init(struct elogd_queue * __restrict queue, unsigned int nr)
	__elogd_nonull(1) __elogd_nothrow __leaf;

extern void
elogd_queue_fini(const struct elogd_queue * __restrict queue)
	__elogd_nonull(1) __elogd_nothrow __leaf;

#endif /* _ELOGD_COMMON_H */
