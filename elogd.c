#include "elogd/config.h"
#include <elog/elog.h>
#include <stroll/dlist.h>
#include <utils/time.h>
#include <utils/mqueue.h>
#include <utils/unsk.h>
#include <utils/file.h>
#include <utils/dir.h>
#include <utils/signal.h>
#include <enbox/enbox.h>
#include <ctype.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/syslog.h>
#include <sys/statvfs.h>
#include <linux/taskstats.h>

static uid_t elogd_uid;
static gid_t elogd_gid;

/******************************************************************************
 * Configuration handling.
 ******************************************************************************/

#define ELOGD_SVC_MODE \
	STROLL_CONCAT(0, CONFIG_ELOGD_SVC_MODE)

#define ELOGD_FILE_MODE \
	STROLL_CONCAT(0, CONFIG_ELOGD_FILE_MODE)

static struct {
	const char * user;
	const char * lock_path;
	unsigned int kmsg_fetch;
	unsigned int mqueue_fetch;
	unsigned int svc_fetch;
	mode_t       svc_mode;
	const char * svc_group;
	const char * dir_path;
	const char * stat_path;
	const char * sock_path;
	const char * file_base;
	size_t       file_len;
	mode_t       file_mode;
	const char * file_group;
	size_t       max_size;
	unsigned int max_rot;
} elogd_conf = {
	.user         = CONFIG_ELOGD_USER,
	.lock_path    = CONFIG_ELOGD_LOCK_PATH,
	.kmsg_fetch   = CONFIG_ELOGD_KMSG_FETCH,
	.mqueue_fetch = CONFIG_ELOGD_MQUEUE_FETCH,
	.svc_fetch    = CONFIG_ELOGD_SVC_FETCH,
	.svc_mode     = ELOGD_SVC_MODE,
	.svc_group    = CONFIG_ELOGD_SVC_GROUP,
	.dir_path     = CONFIG_ELOGD_DIR_PATH,
	.stat_path    = CONFIG_ELOGD_STAT_PATH,
	.sock_path    = CONFIG_ELOGD_SOCK_PATH,
	.file_base    = CONFIG_ELOGD_FILE_BASE,
	.file_len     = sizeof(CONFIG_ELOGD_FILE_BASE) - 1,
	.file_mode    = ELOGD_FILE_MODE,
	.file_group   = CONFIG_ELOGD_FILE_GROUP,
	.max_size     = CONFIG_ELOGD_MAX_SIZE,
	.max_rot      = CONFIG_ELOGD_MAX_ROT
};

#if defined(CONFIG_ELOGD_ASSERT)

#include <stroll/assert.h>

#define __elogd_nonull(_arg_index, ...)
#define __elogd_pure
#define __elogd_nothrow
#define elogd_assert(_expr)             stroll_assert("elogd", _expr)

#else  /* !defined(CONFIG_ELOGD_ASSERT) */

#define __elogd_nonull(_arg_index, ...) __nonull(_arg_index, ## __VA_ARGS__)
#define __elogd_pure                    __pure
#define __elogd_nothrow                 __nothrow
#define elogd_assert(_expr)             do { } while (0)

#endif /* defined(CONFIG_ELOGD_ASSERT) */

/* Limit maximum file size to 2GB. */
#define ELOGD_FILE_SIZE_MIN (4096U)
#define ELOGD_FILE_SIZE_MAX (2U << 30)

#define elogd_assert_conf() \
	elogd_assert(elogd_conf.kmsg_fetch > 0); \
	elogd_assert(elogd_conf.mqueue_fetch > 0); \
	elogd_assert(elogd_conf.svc_fetch > 0); \
	elogd_assert(!(elogd_conf.svc_mode & ~DEFFILEMODE)); \
	elogd_assert(!elogd_conf.svc_group || elogd_conf.svc_group[0]); \
	elogd_assert(upath_validate_path_name(elogd_conf.dir_path) > 0); \
	elogd_assert(upath_validate_path_name(elogd_conf.stat_path) > 0); \
	elogd_assert(upath_validate_path_name(elogd_conf.sock_path) > 0); \
	elogd_assert(elogd_conf.file_len); \
	elogd_assert((size_t)upath_validate_file_name(elogd_conf.file_base) == \
	             elogd_conf.file_len); \
	elogd_assert(!(elogd_conf.file_mode & ~DEFFILEMODE)); \
	elogd_assert(!elogd_conf.file_group || elogd_conf.file_group[0]); \
	elogd_assert(elogd_conf.max_size >= ELOGD_FILE_SIZE_MIN); \
	elogd_assert(elogd_conf.max_size <= ELOGD_FILE_SIZE_MAX); \
	elogd_assert(elogd_conf.max_rot); \
	elogd_assert(elogd_conf.max_rot <= 100)

#define elogd_assert_tspec(_tspec) \
	elogd_assert(_tspec); \
	elogd_assert((_tspec)->tv_sec >= 0); \
	elogd_assert((_tspec)->tv_sec <= UTIME_TIMET_MAX); \
	elogd_assert((_tspec)->tv_nsec >= 0); \
	elogd_assert((_tspec)->tv_nsec < 1000000000L)

/******************************************************************************
 * Various helpers.
 ******************************************************************************/

#define ELOGD_PRIO_FIELD_MIN_LEN    (3U)
#define ELOGD_PRIO_FIELD_MAX_LEN    (5U)
#define ELOGD_TSTAMP_FIELD_LEN      (32U)
#define ELOGD_TAG_MAX_SIZE          ((size_t)TS_COMM_LEN)
#define ELOGD_TAG_MIN_LEN           (1U)
#define ELOGD_TAG_MAX_LEN           (ELOGD_TAG_MAX_SIZE - 1)
#define ELOGD_PID_MAX_LEN           (10U)

/* Generate string compliant with RFC3164. */
static __elogd_nonull(1) __elogd_nothrow
size_t
elogd_fill_prio_field(char * __restrict head,
                      int               facility,
                      int               severity)
{
	elogd_assert(head);
	elogd_assert(!(severity & ~LOG_PRIMASK));
	elogd_assert(!(facility & ~LOG_FACMASK));

	return (size_t)sprintf(head, "<%d>", LOG_MAKEPRI(facility, severity));
}

/* Generate string compliant with RFC3339. */
static size_t __elogd_nonull(1, 2)
elogd_fill_realtime_field(char * __restrict                  head,
                          const struct timespec * __restrict tstamp)
{
	elogd_assert(head);
	elogd_assert_tspec(tstamp);

	struct tm tmp;

	utime_gmtime_from_tspec(&tmp, tstamp);

	strftime(head, 20, "%FT%T", &tmp);
	sprintf(&head[19], ".%06ld+00:00", tstamp->tv_nsec / 1000U);

	return ELOGD_TSTAMP_FIELD_LEN;
}

static void __elogd_nonull(1)
elogd_real_boot_time(struct timespec * __restrict tspec)
{
	elogd_assert(tspec);

	struct timespec boot;

	/*
	 * Retrieve time elapsed since boot first to make sure fetched
	 * real time >= fetched boot time so that calculation below always gives
	 * a positive result.
	 * Necessary to prevent odd cases from happening where realtime / wall
	 * system clock has not yet been set, i.e., on system where there is no
	 * RTC / networked synchronization or simply when hwclock(8) has not yet
	 * been given a chance to run.
	 * When real time has not been set, its value space origin is Epoch,
	 * encoded as zero. In this case, given that it is not a monotonic
	 * clock, it may happen that retrieved boot time, which itself IS
	 * monotonic, is greater that retreived real time.
	 */

	utime_boot_now(&boot);
	utime_realtime_now(tspec);

	/*
	 * Compute boot time within the realtime space:
	 * tspec = real - boot.
	 */
	utime_tspec_sub(tspec, &boot);
}

static const char * __elogd_nonull(1, 3, 4)
elogd_parse_prio(const char * __restrict string,
                 int                     separator,
                 int * __restrict        facility,
                 int * __restrict        severity)
{
	elogd_assert(string);
	elogd_assert(ispunct(separator) ||
	             isblank(separator) ||
	             (separator == '\n'));
	elogd_assert(facility);
	elogd_assert(severity);

	unsigned long val;
	char *        end;
	size_t        len;

	val = strtoul(string, &end, 10);
	len = end - string;
	if (!len || (len > 3) || (*end != separator))
		return NULL;

	if (val & ~(LOG_FACMASK | LOG_PRIMASK))
		return NULL;

	*facility = val & LOG_FACMASK;
	*severity = val & LOG_PRIMASK;

	/* Skip separator. */
	return &string[len + 1];
}

static __elogd_nonull(1) __elogd_pure __elogd_nothrow
char *
elogd_probe_string_delim(const char * __restrict string, int delim, size_t len)
{
	elogd_assert(string);
	elogd_assert(len);

	const char * chr = string;

	do {
		if (*chr == delim)
			break;

		if (!(isgraph(*chr) || isblank(*chr)))
			return NULL;

		chr++;
	} while (chr < &string[len]);

	return (chr - string) ? (char *)chr : NULL;
}

#define elogd_err(_format, ...) \
	fprintf(stderr, \
	        "%s: error: " _format ".\n", \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

#define elogd_warn(_format, ...) \
	fprintf(stderr, \
	        "%s: warning: " _format ".\n", \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

/******************************************************************************
 * Logging output line handling.
 ******************************************************************************/

/*
 * Maximum len of a logging output line excluding the terminating newline
 * or NULL byte.
 */
#define ELOGD_LINE_MAX_LEN (1024U)

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

#define elog_assert_line_head(_line, _iovec) \
	elogd_assert((_iovec)[ELOGD_LINE_HEAD_IOVEC].iov_len <= \
	             sizeof((_line)->head)); \
	elogd_assert((char *)(_iovec)[ELOGD_LINE_HEAD_IOVEC].iov_base >= \
	             (_line)->head); \
	elogd_assert((char *)(_iovec)[ELOGD_LINE_HEAD_IOVEC].iov_base < \
	             &(_line)->head[sizeof((_line)->head)])

#define elog_assert_line_msg(_line, _iovec) \
	elogd_assert((_iovec)[ELOGD_LINE_MSG_IOVEC].iov_len); \
	elogd_assert((_iovec)[ELOGD_LINE_MSG_IOVEC].iov_len < \
	             sizeof((_line)->data)); \
	elogd_assert((char *)(_iovec)[ELOGD_LINE_MSG_IOVEC].iov_base > \
	             (_line)->data); \
	elogd_assert((char *)(_iovec)[ELOGD_LINE_MSG_IOVEC].iov_base < \
	             &(_line)->data[sizeof((_line)->data)])

#define elog_assert_queued_line(_line) \
	elogd_assert(!((_line)->severity & ~LOG_PRIMASK)); \
	elogd_assert(!((_line)->facility & ~LOG_FACMASK)); \
	elog_assert_line_msg(_line, (_line)->vector)

static void __elogd_nonull(1)
elogd_fixup_partial_line(struct elogd_line * __restrict line, size_t written)
{
	elog_assert_queued_line(line);
	elog_assert_line_head(line, line->vector);
	elogd_assert(written);
	elogd_assert(written < (line->vector[ELOGD_LINE_HEAD_IOVEC].iov_len +
	                        line->vector[ELOGD_LINE_MSG_IOVEC].iov_len));

	struct iovec * vec = line->vector;
	size_t         head = stroll_min(vec[ELOGD_LINE_HEAD_IOVEC].iov_len,
	                                 written);

	vec[ELOGD_LINE_HEAD_IOVEC].iov_base += head;
	vec[ELOGD_LINE_HEAD_IOVEC].iov_len -= head;

	written -= head;
	vec[ELOGD_LINE_MSG_IOVEC].iov_base += written;
	vec[ELOGD_LINE_MSG_IOVEC].iov_len -= written;
}

static size_t __elogd_nonull(1, 2, 3)
elogd_fulfill_line(struct elogd_line * __restrict     line,
                   const struct timespec * __restrict boot,
                   struct iovec                       vector[__restrict_arr 2])
{
	elogd_assert(line);
	elog_assert_line_msg(line, line->vector);
	elogd_assert_tspec(boot);
	elogd_assert(vector);

	struct iovec * vecs = line->vector;

	if (!vecs[ELOGD_LINE_HEAD_IOVEC].iov_base) {
		/* Compute and fill RFC3164 compliant line header. */
		char * head = line->head;
		size_t len;

		utime_tspec_add_clamp(&line->tstamp, boot);

		len = elogd_fill_prio_field(head,
		                            line->facility,
		                            line->severity);

		len += elogd_fill_realtime_field(&head[len], &line->tstamp);

		if (line->tag_len) {
			line->tag_len = stroll_min(line->tag_len,
			                           ELOGD_TAG_MAX_LEN);

			head[len++] = ' ';
			memcpy(&head[len], line->tag, line->tag_len);
			len += line->tag_len;

			if (line->pid > 0) {
				head[len++] = '[';
				len += sprintf(&head[len], "%d", line->pid);
				head[len++] = ']';
			}

			head[len++] = ':';
		}

		head[len++] = ' ';

		vecs[ELOGD_LINE_HEAD_IOVEC].iov_base = head;
		vecs[ELOGD_LINE_HEAD_IOVEC].iov_len = len;
	}

	vector[ELOGD_LINE_HEAD_IOVEC] = vecs[ELOGD_LINE_HEAD_IOVEC];
	vector[ELOGD_LINE_MSG_IOVEC] = vecs[ELOGD_LINE_MSG_IOVEC];

	return vecs[ELOGD_LINE_HEAD_IOVEC].iov_len +
	       vecs[ELOGD_LINE_MSG_IOVEC].iov_len;
}

static void __elogd_nonull(1)
elogd_reset_line(struct elogd_line * __restrict line)
{
	line->vector[ELOGD_LINE_HEAD_IOVEC].iov_base = NULL;
	line->tag_len = 0;
	line->pid = -1;
}

static struct elogd_line *
elogd_alloc_line(void)
{
	return malloc(sizeof(struct elogd_line));
}

static void __elogd_nonull(1)
elogd_free_line(struct elogd_line * line)
{
	free(line);
}

/******************************************************************************
 * Logging output line queue handling.
 ******************************************************************************/

struct elogd_queue {
	struct stroll_dlist_node free;
	unsigned int             busy_cnt;
	struct stroll_dlist_node busy;
	unsigned int             nr;
	struct elogd_line **     lines;
};

static struct elogd_line * __elogd_nonull(1) __elogd_pure
elogd_line_from_node(const struct stroll_dlist_node * __restrict node)
{
	return stroll_dlist_entry(node, struct elogd_line, node);
}

static unsigned int __elogd_nonull(1) __elogd_pure
elogd_queue_nr(const struct elogd_queue * __restrict queue)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(queue->lines);
	elogd_assert(queue->busy_cnt <= queue->nr);
	elogd_assert(!!queue->busy_cnt ^ stroll_dlist_empty(&queue->busy));

	return queue->nr;
}

static unsigned int __elogd_nonull(1) __elogd_pure
elogd_queue_busy_count(const struct elogd_queue * __restrict queue)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(queue->lines);
	elogd_assert(queue->busy_cnt <= queue->nr);
	elogd_assert(!!queue->busy_cnt ^ stroll_dlist_empty(&queue->busy));

	return queue->busy_cnt;
}

/*
 * TODO: drop duplicate messages.
 */
static void __elogd_nonull(1, 2)
elogd_nqueue_line(struct elogd_queue * __restrict queue,
                  struct elogd_line * __restrict  line)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(queue->lines);
	elogd_assert(queue->busy_cnt < queue->nr);
	elogd_assert(!!queue->busy_cnt ^ stroll_dlist_empty(&queue->busy));
	elog_assert_queued_line(line);

	struct stroll_dlist_node * node;
        const struct timespec *    tstamp = &line->tstamp;

	for (node = stroll_dlist_prev(&queue->busy);
	     node != &queue->busy;
	     node = stroll_dlist_prev(node))
		if (utime_tspec_after_eq(tstamp,
		                         &elogd_line_from_node(node)->tstamp))
			break;

	queue->busy_cnt++;
	stroll_dlist_append(node, &line->node);
}

#if 0
static struct elogd_line * __elogd_nonull(1)
elogd_dqueue_line(struct elogd_queue * __restrict queue)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(queue->lines);
	elogd_assert(queue->busy_cnt);
	elogd_assert(queue->busy_cnt <= queue->nr);
	elogd_assert(!stroll_dlist_empty(&queue->busy));

	queue->busy_cnt--;
	return elogd_line_from_node(stroll_dlist_dqueue_front(&queue->busy));
}

static void __elogd_nonull(1, 2, 3)
elogd_bulk_dqueue_lines(struct elogd_queue *                  queue,
                        struct stroll_dlist_node * __restrict lines,
                        struct elogd_line *                   last,
                        unsigned int                          count)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(queue->lines);
	elogd_assert(queue->busy_cnt);
	elogd_assert(queue->busy_cnt <= queue->nr);
	elogd_assert(!stroll_dlist_empty(&queue->busy));
	elogd_assert(lines);
	elog_assert_queued_line(last);
	elogd_assert(count);
	elogd_assert(count <= queue->busy_cnt);

	queue->busy_cnt -= count;
	stroll_dlist_splice_before(lines,
	                           stroll_dlist_next(&queue->busy),
	                           &last->node);
}
#endif

static int __elogd_nonull(1, 2, 3, 5)
elogd_dqueue_iovec_lines(struct elogd_queue *                  queue,
                         struct stroll_dlist_node * __restrict lines,
                         struct iovec * __restrict             vectors,
                         unsigned int                          max_cnt,
                         size_t * __restrict                   size)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(queue->lines);
	elogd_assert(queue->busy_cnt);
	elogd_assert(queue->busy_cnt <= queue->nr);
	elogd_assert(!stroll_dlist_empty(&queue->busy));
	elogd_assert(stroll_dlist_empty(lines));
	elogd_assert(vectors);
	elogd_assert(max_cnt);
	elogd_assert(max_cnt <= queue->busy_cnt);
	elogd_assert((2 * max_cnt) <= IOV_MAX);
	elogd_assert(size);
	elogd_assert(*size);
	elogd_assert(*size <= SSIZE_MAX);

	struct timespec            boot;
	struct stroll_dlist_node * first;
	struct stroll_dlist_node * node;
	struct stroll_dlist_node * last;
	unsigned int               cnt = 0;
	size_t                     bytes = 0;

	/* Get time of boot (in the realtime space). */
	elogd_real_boot_time(&boot);

	first = stroll_dlist_next(&queue->busy);
	node = first;
	while (true) {
		size_t len;

		len = elogd_fulfill_line(elogd_line_from_node(node),
		                         &boot,
		                         &vectors[2 * cnt]);
		if ((bytes + len) > *size)
			break;

		bytes += len;
		last = node;
		if (++cnt == max_cnt)
			break;

		elogd_assert(cnt < max_cnt);
		node = stroll_dlist_next(node);
	}

	if (!cnt)
		return -ENOSPC;

	queue->busy_cnt -= cnt;
	stroll_dlist_splice_before(lines, first, last);

	*size = bytes;

	return cnt;
}

#if 0
static void __elogd_nonull(1, 2)
elogd_requeue_line(struct elogd_queue * __restrict queue,
                   struct elogd_line * __restrict  line)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(queue->lines);
	elogd_assert(queue->busy_cnt < queue->nr);
	elogd_assert(!!queue->busy_cnt ^ stroll_dlist_empty(&queue->busy));
	elog_assert_queued_line(line);
	elog_assert_line_head(line, line->vector);

	queue->busy_cnt++;
	stroll_dlist_nqueue_front(&queue->busy, &line->node);
}
#endif

static void __elogd_nonull(1, 2)
elogd_bulk_requeue_lines(struct elogd_queue * __restrict queue,
                         struct stroll_dlist_node *      lines,
                         unsigned int                    count)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(queue->lines);
	elogd_assert(!!queue->busy_cnt ^ stroll_dlist_empty(&queue->busy));
	elogd_assert(count);
	elogd_assert((queue->busy_cnt + count) <= queue->nr);
	elogd_assert(!stroll_dlist_empty(lines));

	queue->busy_cnt += count;
	stroll_dlist_embed_after(&queue->busy,
	                         stroll_dlist_next(lines),
	                         stroll_dlist_prev(lines));
}

static void __elogd_nonull(1, 2, 3)
elogd_requeue_iovec_lines(struct elogd_queue * __restrict queue,
                          struct stroll_dlist_node *      lines,
                          const struct iovec * __restrict vectors,
                          unsigned int                    count,
                          size_t                          written)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(queue->lines);
	elogd_assert(!!queue->busy_cnt ^ stroll_dlist_empty(&queue->busy));
	elogd_assert(!stroll_dlist_empty(lines));
	elogd_assert(vectors);
	elogd_assert(count);
	elogd_assert((2 * count) <= IOV_MAX);
	elogd_assert((queue->busy_cnt + count) <= queue->nr);
	elogd_assert(written < SSIZE_MAX);

	struct stroll_dlist_node * first;
	struct stroll_dlist_node * node;
	struct stroll_dlist_node * last;
	unsigned int               cnt = 0;
	size_t                     size = 0;

	first = stroll_dlist_next(lines);
	node = first;
	while (true) {
		const struct iovec * vecs = &vectors[2 * cnt];
		size_t               bytes;

		bytes = vecs[ELOGD_LINE_HEAD_IOVEC].iov_len +
		        vecs[ELOGD_LINE_MSG_IOVEC].iov_len;
		if ((size + bytes) > written)
			break;

		size += bytes;
		last = node;
		node = stroll_dlist_next(lines);
		cnt++;
	}

	elogd_assert(cnt < count);
	elogd_assert(!cnt || ((node != lines) && (node != first)));

	/*
	 * Adjust content of first uncompleted line / iovec to reflect the
	 * number of written bytes.
	 */
	elogd_fixup_partial_line(elogd_line_from_node(node), written - size);

	if (cnt)
		/* Release completed lines. */
		stroll_dlist_embed_after(&queue->free, first, last);

	/* Requeue uncompleted lines. */
	queue->busy_cnt += count - cnt;
	stroll_dlist_embed_after(&queue->busy, node, stroll_dlist_prev(lines));
}

static struct elogd_line * __elogd_nonull(1)
elogd_acquire_line(struct elogd_queue * __restrict queue)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(queue->lines);
	elogd_assert(queue->busy_cnt <= queue->nr);
	elogd_assert(!!queue->busy_cnt ^ stroll_dlist_empty(&queue->busy));

	if (!stroll_dlist_empty(&queue->free)) {
		struct elogd_line * ln;

		ln = elogd_line_from_node(stroll_dlist_dqueue_front(&queue->free));
		elogd_reset_line(ln);

		return ln;
	}

	return NULL;
}

static void __elogd_nonull(1, 2)
elogd_release_line(struct elogd_queue * __restrict queue,
                   struct elogd_line * __restrict  line)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(queue->lines);
	elogd_assert(queue->busy_cnt < queue->nr);
	elogd_assert(!!queue->busy_cnt ^ stroll_dlist_empty(&queue->busy));
	elogd_assert(line);

	stroll_dlist_nqueue_front(&queue->free, &line->node);
}

static void __elogd_nonull(1, 2)
elogd_bulk_release_lines(struct elogd_queue * __restrict queue,
                         struct stroll_dlist_node *      lines)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(queue->lines);
	elogd_assert(queue->busy_cnt < queue->nr);
	elogd_assert(!stroll_dlist_empty(lines));

	stroll_dlist_embed_after(&queue->free,
	                         stroll_dlist_next(lines),
	                         stroll_dlist_prev(lines));
}

static int __elogd_nonull(1)
elogd_init_queue(struct elogd_queue * __restrict queue, unsigned int nr)
{
	elogd_assert(queue);

	struct elogd_line ** lines;
	unsigned int         l;

	lines = malloc(nr * sizeof(*lines));
	if (!lines)
		return -ENOMEM;

	stroll_dlist_init(&queue->free);

	for (l = 0; l < nr; l++) {
		lines[l] = elogd_alloc_line();
		if (!lines[l])
			goto destroy;

		stroll_dlist_nqueue_front(&queue->free, &lines[l]->node);
	}

	queue->busy_cnt = 0;
	stroll_dlist_init(&queue->busy);
	queue->nr = nr;
	queue->lines = lines;

	return 0;

destroy:
	while (l--)
		elogd_free_line(queue->lines[l]);

	free(lines);

	return -ENOMEM;
}

static void __elogd_nonull(1)
elogd_fini_queue(struct elogd_queue * __restrict queue)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(queue->lines);
	elogd_assert(queue->busy_cnt <= queue->nr);
	elogd_assert(!!queue->busy_cnt ^ stroll_dlist_empty(&queue->busy));

	unsigned int l;

	for (l = 0; l < queue->nr; l++)
		elogd_free_line(queue->lines[l]);

	free(queue->lines);
}

/******************************************************************************
 * Signal handling.
 ******************************************************************************/

struct elogd_sigchan {
	struct upoll_worker work;
	int                 fd;
};

static int __elogd_nonull(1, 3)
elogd_dispatch_sigchan(struct upoll_worker * work,
                       uint32_t              state __unused,
                       const struct upoll *  poll __unused)
{
	elogd_assert(work);
	elogd_assert(state);
	elogd_assert(!(state & EPOLLOUT));
	elogd_assert(!(state & EPOLLRDHUP));
	elogd_assert(!(state & EPOLLPRI));
	elogd_assert(!(state & EPOLLHUP));
	elogd_assert(!(state & EPOLLERR));
	elogd_assert(state & EPOLLIN);
	elogd_assert(poll);

	const struct elogd_sigchan * chan;
	struct signalfd_siginfo      info;
	int                          ret;

	chan = containerof(work, struct elogd_sigchan, work);
	elogd_assert(chan->fd >= 0);

	ret = usig_read_fd(chan->fd, &info, 1);
	elogd_assert(ret);
	if (ret < 0)
		return (ret == -EAGAIN) ? 0 : ret;

	switch (info.ssi_signo) {
	case SIGHUP:
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		/* Tell caller we were requested to terminate. */
		return -ESHUTDOWN;

	case SIGUSR1:
	case SIGUSR2:
		/* Silently ignore these... */
		return 0;

	default:
		elogd_assert(0);
	}

	return ret;
}

static int __elogd_nonull(1, 2)
elogd_open_sigchan(struct elogd_sigchan * __restrict chan,
                   const struct upoll * __restrict   poll)
{
	elogd_assert(chan);
	elogd_assert(poll);

	sigset_t msk = *usig_empty_msk;
	int      err;

	usig_addset(&msk, SIGHUP);
	usig_addset(&msk, SIGINT);
	usig_addset(&msk, SIGQUIT);
	usig_addset(&msk, SIGTERM);
	usig_addset(&msk, SIGUSR1);
	usig_addset(&msk, SIGUSR2);

	chan->fd = usig_open_fd(&msk, SFD_NONBLOCK | SFD_CLOEXEC);
	if (chan->fd < 0)
		return chan->fd;

	chan->work.dispatch = elogd_dispatch_sigchan;
	err = upoll_register(poll, chan->fd, EPOLLIN, &chan->work);
	if (err)
		goto close;

	usig_procmask(SIG_SETMASK, usig_full_msk, NULL);

	return 0;

close:
	usig_close_fd(chan->fd);

	return err;
}

static void __elogd_nonull(1, 2)
elogd_close_sigchan(const struct elogd_sigchan * __restrict chan,
                    const struct upoll * __restrict         poll)
{
	elogd_assert(chan);
	elogd_assert(chan->fd >= 0);
	elogd_assert(poll);

	upoll_unregister(poll, chan->fd);
	usig_close_fd(chan->fd);
}

/******************************************************************************
 * Logging output file store handling.
 ******************************************************************************/

struct elogd_store {
	int    fd;
	size_t size;
	int    dir;
	char * base;
};

static int __elogd_nonull(1)
elogd_open_store_file(struct elogd_store * __restrict store)
{
	elogd_assert_conf();
	elogd_assert(store);
	elogd_assert(store->dir >= 0);
	elogd_assert(upath_validate_path_name(store->base) >
	             (ssize_t)(elogd_conf.file_len + 1));
	elogd_assert(store->base[elogd_conf.file_len] == '.');
	elogd_assert(store->base[(2 * elogd_conf.file_len) + 1 + 2 + 1] == '.');

	struct stat st;
	int         err;
	gid_t       gid = elogd_gid;

	store->fd = ufile_new_at(store->dir,
	                         store->base,
	                         O_WRONLY | O_APPEND | O_CLOEXEC | O_NOATIME |
	                         O_NOFOLLOW,
	                         elogd_conf.file_mode);

	if (store->fd < 0)
		return store->fd;

	err = ufile_fstat(store->fd, &st);
	if (err)
		goto close;
	if (!S_ISREG(st.st_mode)) {
		err = -EPERM;
		goto close;
	}

	if (elogd_conf.svc_group) {
		err = upwd_get_gid_byname(elogd_conf.file_group, &gid);
		if (err)
			elogd_warn("'%s': invalid logging file group, "
			           "using default GID %d",
			           elogd_conf.file_group,
			           gid);
	}
	err = ufile_fchown(store->fd, elogd_uid, gid);
	if (err)
		goto close;

	err = ufile_fchmod(store->fd, elogd_conf.file_mode);
	if (err)
		goto close;

	store->size = st.st_size;

	return 0;

close:
	ufile_close(store->fd);

	store->fd = -1;

	return err;
}

static void __elogd_nonull(1)
elogd_rotate_store(struct elogd_store * __restrict store)
{
	elogd_assert_conf();
	elogd_assert(store);
	elogd_assert(store->fd >= 0);
	elogd_assert(store->dir >= 0);
	elogd_assert(upath_validate_path_name(store->base) >
	             (ssize_t)(elogd_conf.file_len + 1));
	elogd_assert(store->base[elogd_conf.file_len] == '.');
	elogd_assert(store->base[(2 * elogd_conf.file_len) + 1 + 2 + 1] == '.');
	elogd_assert(elogd_conf.max_rot > 1);

	unsigned int rot = elogd_conf.max_rot - 1;
	char *       orig = store->base;
	size_t       len = elogd_conf.file_len + 1;
	char *       nevv = &store->base[len + 2 + 1];
	int          err;

	err = ufile_sync(store->fd);
	if (err)
		elogd_warn("'%s/%s': cannot sync logging file: %s (%d)",
		           elogd_conf.dir_path,
		           orig,
		           strerror(-err),
		           -err);

	do {
		sprintf(&orig[len], "%u", rot - 1);
		sprintf(&nevv[len], "%u", rot);

		/* Ignore errors since file might be missing. */
		err = ufile_rename_at(store->dir, orig, store->dir, nevv, 0);
		if (err)
			elogd_warn("'%s/%s': "
			           "cannot rotate logging file: %s (%d)",
			           elogd_conf.dir_path,
			           orig,
			           strerror(-err),
			           -err);
	} while (--rot);

	/* Reset primary logging output file name. */
	orig[len] = '0';
	orig[len + 1] = '\0';

	/* Just in case we failed to move primary logging output file. */
	err = ufile_unlink_at(store->dir, orig);
	if (err && (err != -ENOENT))
		elogd_warn("'%s/%s': cannot unlink logging file: %s (%d)",
		           elogd_conf.dir_path,
		           orig,
		           strerror(-err),
		           -err);

	/* Now close primary logging output file. */
	err = ufile_close(store->fd);
	if (err)
		elogd_warn("'%s/%s': "
		           "failed to close logging file: %s (%d)",
		           elogd_conf.dir_path,
		           orig,
		           strerror(-err),
		           -err);

	/* Open / create a new primary logging output file. */
	err = elogd_open_store_file(store);
	if (err)
		elogd_warn("'%s/%s': cannot open logging file: %s (%d)",
		           elogd_conf.dir_path,
		           orig,
		           strerror(-err),
		           -err);

	/*
	 * Finally flush parent directory to make changes visible to external
	 * processes.
	 */
	err = udir_sync(store->dir);
	if (err)
		elogd_warn("'%s': cannot sync logging directory: %s (%d)",
		           elogd_conf.dir_path,
		           strerror(-err),
		           -err);
}

static int __elogd_nonull(1, 2)
elogd_flush_store_queue(struct elogd_store * __restrict store,
                        struct elogd_queue * __restrict queue,
                        unsigned int                    max_cnt,
                        size_t                          size)
{
	elogd_assert_conf();
	elogd_assert(store);
	elogd_assert(store->fd >= 0);
	elogd_assert(store->dir >= 0);
	elogd_assert(upath_validate_path_name(store->base) >
	             (ssize_t)(elogd_conf.file_len + 1));
	elogd_assert(store->base[elogd_conf.file_len] == '.');
	elogd_assert(queue);
	elogd_assert(max_cnt);
	elogd_assert(elogd_queue_busy_count(queue) == max_cnt);
	elogd_assert(size);
	elogd_assert(size <= SSIZE_MAX);

	struct stroll_dlist_node lines = STROLL_DLIST_INIT(lines);
	struct iovec             vectors[2 * max_cnt];
	int                      cnt;
	ssize_t                  ret;

	cnt = elogd_dqueue_iovec_lines(queue, &lines, vectors, max_cnt, &size);
	elogd_assert(cnt);
	if (cnt < 0)
		return cnt;

	ret = ufile_writev(store->fd, vectors, 2 * cnt);
	if (ret >= 0) {
		elogd_assert((size_t)ret <= size);

		if ((size_t)ret == size)
			/* All lines were fully written out. */
			elogd_bulk_release_lines(queue, &lines);
		else
			/* Lines were partially written. */
			elogd_requeue_iovec_lines(queue,
			                          &lines,
			                          vectors,
			                          cnt,
			                          ret);

		return ret;
	}

	elogd_assert(ret != -EAGAIN);
	elogd_assert(ret != -EINTR);
	elogd_assert(ret != -EINVAL);

	elogd_bulk_requeue_lines(queue, &lines, cnt);

	return ret;
}

static void __elogd_nonull(1, 2)
elogd_flush_store(struct elogd_store * __restrict store,
                  struct elogd_queue * __restrict queue)
{
	elogd_assert_conf();
	elogd_assert(store);
	elogd_assert(store->dir >= 0);
	elogd_assert(upath_validate_path_name(store->base) >
	             (ssize_t)(elogd_conf.file_len + 1));
	elogd_assert(store->base[elogd_conf.file_len] == '.');

	unsigned int cnt;
	size_t       max_sz;
	int          ret;

	if (store->fd < 0) {
		ret = elogd_open_store_file(store);
		if (ret) {
			elogd_warn("'%s/%s': cannot open logging file: %s (%d)",
			           elogd_conf.dir_path,
			           store->base,
			           strerror(-ret),
			           -ret);

			return;
		}
	}

	cnt = stroll_min(elogd_queue_busy_count(queue), elogd_queue_nr(queue));
	if (!cnt)
		return;

	if (elogd_conf.max_rot > 1) {
		max_sz = elogd_conf.max_size - stroll_min(store->size,
		                                          elogd_conf.max_size);
		if (max_sz <= (ELOGD_HEAD_MIN_SIZE - 1 + sizeof('\n')))
			goto rotate;
	}
	else
		max_sz = SSIZE_MAX;

	ret = elogd_flush_store_queue(store, queue, cnt, max_sz);
	elogd_assert(ret);
	if (ret > 0) {
		store->size += ret;
		return;
	}

	if (ret == -ENOSPC)
		goto rotate;

	elogd_warn("'%s/%s': cannot flush logging file: %s (%d)",
	           elogd_conf.dir_path,
	           store->base,
	           strerror(-ret),
	           -ret);

	return;

rotate:
	elogd_rotate_store(store);
}

static int __elogd_nonull(1)
elogd_open_store(struct elogd_store * __restrict store)
{
	elogd_assert_conf();
	elogd_assert(store);

	struct statvfs stat;
	int            err;

	store->dir = udir_open(elogd_conf.dir_path,
	                       O_CLOEXEC | O_NOATIME | O_NOFOLLOW);
	if (store->dir < 0) {
		elogd_err("'%s': cannot open logging directory: %s (%d)",
		          elogd_conf.dir_path,
		          strerror(-store->dir),
		          -store->dir);
		return store->dir;
	}

	if (fstatvfs(store->dir, &stat) < 0) {
		err = -errno;

		elogd_assert(err != -EBADF);
		elogd_assert(err != -EFAULT);
		elogd_assert(err != -EINTR);

		elogd_err("'%s': "
		          "cannot fetch logging filesystem status: %s (%d)",
		          elogd_conf.dir_path,
		          strerror(-err),
		          -err);
		goto close_dir;
	}

	/*
	 * Allocate 2 slots of file basename length + '.' + 2 digits + '\0'
	 * bytes long.
	 * The second slot is pre-allocated as a temporary area used to compute
	 * logging output file basenames for rotation purpose.
	 * See elogd_rotate_store().
	 */
	store->base = malloc(2 * (elogd_conf.file_len + 1 + 2 + 1));
	if (!store->base) {
		err = -errno;
		goto close_dir;
	}

	memcpy(store->base, elogd_conf.file_base, elogd_conf.file_len);
	store->base[elogd_conf.file_len] = '.';
	store->base[elogd_conf.file_len + 1] = '0';
	store->base[elogd_conf.file_len + 2] = '\0';

	memcpy(&store->base[elogd_conf.file_len + 1 + 2 + 1],
	       elogd_conf.file_base,
	       elogd_conf.file_len);
	store->base[elogd_conf.file_len + 1 + 2 + 1 +
	            elogd_conf.file_len] = '.';

	err = elogd_open_store_file(store);
	if (err)
		elogd_warn("'%s/%s': cannot open logging file: %s (%d)",
		           elogd_conf.dir_path,
		           store->base,
		           strerror(-err),
		           -err);

	elogd_conf.max_size = stroll_min(elogd_conf.max_size / stat.f_frsize,
	                                 stat.f_blocks / elogd_conf.max_rot);
	elogd_conf.max_size = stroll_min(elogd_conf.max_size,
	                                 ELOGD_FILE_SIZE_MAX /
	                                 (size_t)stat.f_frsize);
	elogd_conf.max_size *= stat.f_frsize;

	return 0;

close_dir:
	udir_close(store->dir);

	return err;
}

static void __elogd_nonull(1)
elogd_close_store(struct elogd_store * __restrict store)
{
	elogd_assert_conf();
	elogd_assert(store);
	elogd_assert(store->dir >= 0);
	elogd_assert(upath_validate_path_name(store->base) >
	             (ssize_t)(elogd_conf.file_len + 1));
	elogd_assert(store->base[elogd_conf.file_len] == '.');

	int err;

	if (store->fd >= 0) {
		err = ufile_sync(store->fd);
		if (err)
			elogd_warn("'%s/%s': cannot sync logging file: %s (%d)",
			           elogd_conf.dir_path,
			           store->base,
			           strerror(-err),
			           -err);

		err = ufile_close(store->fd);
		if (err)
			elogd_warn("'%s/%s': "
			           "cannot close logging file: %s (%d)",
			           elogd_conf.dir_path,
			           store->base,
			           strerror(-err),
			           -err);
	}

	free(store->base);

	err = udir_sync(store->dir);
	if (err)
		elogd_warn("'%s': cannot sync logging directory: %s (%d)",
		           elogd_conf.dir_path,
		           strerror(-err),
		           -err);

	err = udir_close(store->dir);
	if (err)
		elogd_warn("'%s': cannot close logging directory: %s (%d)",
		           elogd_conf.dir_path,
		           strerror(-err),
		           -err);
}

/******************************************************************************
 * Kernel ring-buffer handling.
 ******************************************************************************/

struct elogd_kmsg {
	struct upoll_worker  work;
	int                  dev_fd;
	uint64_t *           seqno;
	struct elogd_queue * queue;
	int                  stat_fd;
};

static const char * __elogd_nonull(1, 2)
elogd_parse_kmsg_prio(struct elogd_line * __restrict line,
                      const char * __restrict        string)
{
	elogd_assert(line);
	elogd_assert(string);

	return elogd_parse_prio(string, ',', &line->facility, &line->severity);
}

#if __WORDSIZE == 64

static const char * __elogd_nonull(1, 2)
elogd_parse_kmsg_seqno(const char * __restrict string,
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

static const char * __elogd_nonull(1, 2)
elogd_parse_kmsg_tstamp(struct elogd_line * __restrict line,
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

	tstamp->tv_sec = val / 1000000UL;
	tstamp->tv_nsec = (val % 1000000UL) * 1000UL;

	/* Skip ',' separator. */
	return &string[len + 1];
}

#elif __WORDSIZE == 32

static const char * __elogd_nonull(1, 2)
elogd_parse_kmsg_seqno(const char * __restrict string,
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

static const char * __elogd_nonull(1, 2)
elogd_parse_kmsg_tstamp(struct elogd_line * __restrict line,
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

	tstamp->tv_sec = val / 1000000ULL;
	tstamp->tv_nsec = (val % 1000000ULL) * 1000ULL;

	/* Skip ',' separator. */
	return &string[len + 1];
}

#else /* __WORDSIZE != 64 && __WORDSIZE != 32 */
#error "Unsupported machine word size !"
#endif /* __WORDSIZE == 64 */

static const char * __elogd_nonull(1)
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

static int __elogd_nonull(1, 2)
elogd_parse_kmsg(struct elogd_line * __restrict line,
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
	data = elogd_parse_kmsg_prio(line, data);
	if (!data)
		return -EINVAL;

	/* Parse the 64 bits long sequence number. */
	data = elogd_parse_kmsg_seqno(data, seqno);
	if (!data)
		return -EINVAL;

	/* Parse monotonic timestamp. */
	data = elogd_parse_kmsg_tstamp(line, data);
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

static int __elogd_nonull(1, 2)
elogd_read_kmsg(const struct elogd_kmsg * __restrict kmsg,
                struct elogd_line * __restrict       line)
{
	elogd_assert(kmsg);
	elogd_assert(kmsg->dev_fd >= 0);
	elogd_assert(kmsg->seqno);
	elogd_assert(kmsg->queue);
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

static int __elogd_nonull(1)
elogd_process_kmsg(const struct elogd_kmsg * __restrict kmsg)
{
	elogd_assert(kmsg);
	elogd_assert(kmsg->dev_fd >= 0);
	elogd_assert(kmsg->seqno);
	elogd_assert(kmsg->queue);
	elogd_assert(kmsg->stat_fd >= 0);

	struct elogd_line * ln;
	uint64_t            seqno;
	int                 ret;

	ln = elogd_acquire_line(kmsg->queue);
	if (!ln)
		return -ENOBUFS;

	ret = elogd_read_kmsg(kmsg, ln);
	if (ret)
		goto release;

	ret = elogd_parse_kmsg(ln, &seqno);
	if (ret)
		goto release;

	*kmsg->seqno = seqno;

	elogd_nqueue_line(kmsg->queue, ln);

	return 0;

release:
	elogd_release_line(kmsg->queue, ln);

	return ret;
}

static int __elogd_nonull(1, 3)
elogd_dispatch_kmsg(struct upoll_worker * work,
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

	const struct elogd_kmsg * kmsg;
	unsigned int              cnt = elogd_conf.kmsg_fetch;

	kmsg = containerof(work, struct elogd_kmsg, work);
	elogd_assert(kmsg);
	elogd_assert(kmsg->dev_fd >= 0);
	elogd_assert(kmsg->seqno);
	elogd_assert(kmsg->queue);
	elogd_assert(kmsg->stat_fd >= 0);

	do {
		int ret;

		ret = elogd_process_kmsg(kmsg);
		switch (ret) {
		case 0:
			break;

		case -ENOBUFS:
		case -EAGAIN:
			return 0;

		default:
			elogd_assert(0);
		}
	} while (--cnt);

	return 0;
}

static int __elogd_nonull(1)
elogd_skip_init_kmsg(const struct elogd_kmsg * __restrict kmsg)
{
	elogd_assert(kmsg);
	elogd_assert(kmsg->dev_fd >= 0);
	elogd_assert(kmsg->seqno);
	elogd_assert(kmsg->queue);
	elogd_assert(kmsg->stat_fd >= 0);

	struct elogd_line * ln;
	uint64_t            seqno;
	int                 ret;

	ln = elogd_acquire_line(kmsg->queue);
	if (!ln)
		return -ENOBUFS;

	do {
		ret = elogd_read_kmsg(kmsg, ln);
		elogd_assert(ret != -EINTR);
		if (ret)
			break;

		ret = elogd_parse_kmsg(ln, &seqno);
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

	elogd_nqueue_line(kmsg->queue, ln);

	return 0;

release:
	elogd_release_line(kmsg->queue, ln);

	return ret;
}

static int __elogd_nonull(1)
elogd_open_kmsg_stat(struct elogd_kmsg * __restrict kmsg)
{
	elogd_assert_conf();
	elogd_assert(kmsg);

	int         fd;
	struct stat st;
	int         err;
	uint64_t *  seqno;

	fd = ufile_new(elogd_conf.stat_path,
	               O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NOATIME,
	               S_IRUSR | S_IWUSR);
	if (fd < 0) {
		elogd_assert(fd != -EINTR);
		return fd;
	}

	err = ufile_fstat(fd, &st);
	if (err)
		goto close;

	if (!S_ISREG(st.st_mode) ||
	    ((st.st_mode & (S_IRUSR | S_IWUSR)) != (S_IRUSR | S_IWUSR)) ||
	    (st.st_uid != elogd_uid) || (st.st_gid != elogd_gid)) {
		err = -EPERM;
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

		goto close;
	}

	kmsg->stat_fd = fd;
	kmsg->seqno = seqno;

	return 0;

close:
	ufile_close(fd);

	return err;
}

static int __elogd_nonull(1, 2, 3)
elogd_open_kmsg(struct elogd_kmsg * __restrict  kmsg,
                struct elogd_queue * __restrict queue,
                const struct upoll * __restrict poll)
{
	elogd_assert(kmsg);
	elogd_assert(queue);
	elogd_assert(poll);

	int fd;
	int err;

	/*
	 * This will require CAP_SYSLOG or CAP_SYS_ADMIN capability if kernel is
	 * built with CONFIG_SECURITY_DMESG_RESTRICT enabled !!
	 */
	fd = ufd_open("/dev/kmsg",
	              O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW |
	              O_NONBLOCK);
	if (fd < 0)
		return fd;

	err = elogd_open_kmsg_stat(kmsg);
	if (err)
		goto close_dev;

	kmsg->work.dispatch = elogd_dispatch_kmsg;
	err = upoll_register(poll,
	                     fd,
	                     EPOLLIN,
	                     &kmsg->work);
	if (err)
		goto close_stat;

	err = ufd_lseek(fd, 0, SEEK_DATA);
	elogd_assert(!err);

	kmsg->dev_fd = fd;
	kmsg->queue = queue;

	if (*kmsg->seqno) {
		err = elogd_skip_init_kmsg(kmsg);
		if (err)
			goto close_poll;
	}

	return 0;

close_poll:
	upoll_unregister(poll, fd);
close_stat:
	munmap(kmsg->seqno, sizeof(*kmsg->seqno));
	ufile_close(kmsg->stat_fd);
close_dev:
	ufd_close(fd);

	return err;
}

static void __elogd_nonull(1, 2)
elogd_close_kmsg(const struct elogd_kmsg * __restrict kmsg,
                 const struct upoll * __restrict      poll)
{
	elogd_assert(kmsg);
	elogd_assert(kmsg->dev_fd >= 0);
	elogd_assert(kmsg->seqno);
	elogd_assert(kmsg->queue);
	elogd_assert(kmsg->stat_fd >= 0);
	elogd_assert(poll);

	upoll_unregister(poll, kmsg->dev_fd);

	munmap(kmsg->seqno, sizeof(*kmsg->seqno));
	ufile_close(kmsg->stat_fd);

	ufd_close(kmsg->dev_fd);
}

/******************************************************************************
 * syslog(3) socket handling.
 ******************************************************************************/

struct elogd_svc {
	struct upoll_worker  work;
	struct unsk_svc      unsk;
	struct elogd_queue * queue;
};

static int __elogd_nonull(1, 2)
elogd_read_svc(const struct elogd_svc * __restrict svc,
               struct elogd_line * __restrict      line)
{
	elogd_assert(svc);
	elogd_assert(svc->queue);
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

static const char * __elogd_nonull(1, 2)
elogd_parse_svc_prio(struct elogd_line * __restrict line,
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

static char * __elogd_nonull(1) __elogd_pure
elogd_probe_svc_body_start(const char * __restrict string, size_t len)
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

static char * __elogd_nonull(1, 2)
elogd_parse_svc_body(struct elogd_line * __restrict line,
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
	mark = elogd_probe_svc_body_start(string, len);
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

static int
elogd_parse_svc_tag(struct elogd_line * __restrict line,
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

static int __elogd_nonull(1)
elogd_parse_svc(struct elogd_line * __restrict line)
{
	elogd_assert(line);
	elogd_assert(line->vector[ELOGD_LINE_MSG_IOVEC].iov_len);

	char *               data = line->data;
	const struct iovec * msg = &line->vector[ELOGD_LINE_MSG_IOVEC];
	const char *         end = &line->data[msg->iov_len];
	const char *         mark;

	/* Parse priority tag. */
	data = (char *)elogd_parse_svc_prio(line, data);
	if (!data)
		return -EINVAL;

	mark = elogd_parse_svc_body(line, data, end - data);
	if (!mark)
		return -EINVAL;

	if (elogd_parse_svc_tag(line, data, mark - data))
		return -EINVAL;

	/* Assign message a timestamp within the boot time space. */
	utime_boot_now(&line->tstamp);

	return 0;
}

static int __elogd_nonull(1)
elogd_process_svc(const struct elogd_svc * __restrict svc)
{
	elogd_assert(svc);
	elogd_assert(svc->queue);

	struct elogd_line * ln;
	int                 ret;

	ln = elogd_acquire_line(svc->queue);
	if (!ln)
		return -ENOBUFS;

	ret = elogd_read_svc(svc, ln);
	if (ret)
		goto release;

	ret = elogd_parse_svc(ln);
	if (ret)
		goto release;

	elogd_nqueue_line(svc->queue, ln);

	return 0;

release:
	elogd_release_line(svc->queue, ln);

	return ret;
}

static int  __elogd_nonull(1, 3)
elogd_dispatch_svc(struct upoll_worker * work,
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

	const struct elogd_svc * svc;
	unsigned int       cnt = elogd_conf.svc_fetch;

	svc = containerof(work, struct elogd_svc, work);
	elogd_assert(svc);
	elogd_assert(svc->queue);

	do {
		int ret;

		ret = elogd_process_svc(svc);
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
	} while (--cnt);

	return 0;
}

static int __elogd_nonull(1, 2, 3)
elogd_open_svc(struct elogd_svc * __restrict   svc,
               struct elogd_queue * __restrict queue,
               const struct upoll * __restrict poll)
{
	elogd_assert(svc);
	elogd_assert(queue);
	elogd_assert(poll);

	int    err;
	mode_t msk;
	gid_t  gid = elogd_gid;

	err = unsk_dgram_svc_open(&svc->unsk, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (err)
		return err;

	msk = umask(ALLPERMS & ~elogd_conf.svc_mode);
	err = unsk_svc_bind(&svc->unsk, elogd_conf.sock_path);
	umask(msk);
	if (err)
		goto close;

	if (elogd_conf.svc_group) {
		err = upwd_get_gid_byname(elogd_conf.svc_group, &gid);
		if (err)
			elogd_warn("'%s': invalid logging socket group, "
			           "using default GID %d",
			           elogd_conf.svc_group,
			           gid);
	}

	err = upath_chown(elogd_conf.sock_path, elogd_uid, gid);
	if (err)
		goto close;

	svc->work.dispatch = elogd_dispatch_svc;
	err = upoll_register(poll, svc->unsk.fd, EPOLLIN, &svc->work);
	if (err)
		goto close;

	svc->queue = queue;

	return 0;

close:
	unsk_svc_close(&svc->unsk);

	return err;
}

static void __elogd_nonull(1, 2)
elogd_close_svc(const struct elogd_svc * __restrict svc,
                const struct upoll * __restrict     poll)
{
	elogd_assert(svc);
	elogd_assert(svc->queue);

	upoll_unregister(poll, svc->unsk.fd);
	unsk_svc_close(&svc->unsk);
}

/******************************************************************************
 * Message queue handling.
 ******************************************************************************/

#define ELOG_MQUEUE_MIN_LEN \
	(sizeof(struct elog_mqueue_head) + \
	 ELOGD_TAG_MIN_LEN + \
	 1)

struct elogd_mqueue {
	struct upoll_worker  work;
	mqd_t                fd;
	struct elogd_queue * lines;
};

static int __elogd_nonull(1, 2)
elogd_read_mqueue(const struct elogd_mqueue * __restrict mqueue,
                  struct elogd_line * __restrict         line)
{
	elogd_assert(mqueue);
	elogd_assert(mqueue->fd >= 0);
	elogd_assert(mqueue->lines);
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

static int __elogd_nonull(1)
elogd_parse_mqueue(struct elogd_line * __restrict line)
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

static int __elogd_nonull(1)
elogd_process_mqueue(struct elogd_mqueue * __restrict mqueue)
{
	elogd_assert(mqueue);
	elogd_assert(mqueue->fd >= 0);
	elogd_assert(mqueue->lines);

	struct elogd_line * ln;
	int                 ret;

	ln = elogd_acquire_line(mqueue->lines);
	if (!ln)
		return -ENOBUFS;

	ret = elogd_read_mqueue(mqueue, ln);
	if (ret)
		goto release;

	ret = elogd_parse_mqueue(ln);
	if (ret)
		goto release;

	elogd_nqueue_line(mqueue->lines, ln);

	return 0;

release:
	elogd_release_line(mqueue->lines, ln);

	return ret;
}

static int  __elogd_nonull(1, 3)
elogd_dispatch_mqueue(struct upoll_worker * work,
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

	struct elogd_mqueue * mqueue = containerof(work,
	                                           struct elogd_mqueue,
	                                           work);
	unsigned int          cnt = elogd_conf.mqueue_fetch;

	elogd_assert(mqueue);
	elogd_assert(mqueue->fd >= 0);
	elogd_assert(cnt > 0);
	elogd_assert(mqueue->lines);

	do {
		int ret;

		ret = elogd_process_mqueue(mqueue);
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

		default:
			elogd_assert(0);
		}
	} while (--cnt);

	return 0;
}

static int __elogd_nonull(1, 2, 3)
elogd_open_mqueue(struct elogd_mqueue * __restrict mqueue,
                  struct elogd_queue * __restrict  lines,
                  const struct upoll * __restrict  poll)
{
	elogd_assert(mqueue);
	elogd_assert(lines);
	elogd_assert(poll);

	int            fd;
	int            err;
	struct mq_attr attr;
	struct stat    st;

	fd = umq_open("/init", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0)
		return fd;

	err = ufd_fstat(fd, &st);
	if (err)
		goto close;

	if (((st.st_mode & (ALLPERMS & ~(S_IRUSR | S_IWUSR))) != S_IRGRP) ||
	    (st.st_uid != 0)) {
		err = -EPERM;
		goto close;
	}

	umq_getattr(fd, &attr);
	if ((attr.mq_maxmsg < 1) || (attr.mq_msgsize < (long)ELOG_LINE_MAX)) {
		err = -EPERM;
		goto close;
	}

	mqueue->work.dispatch = elogd_dispatch_mqueue;
	err = upoll_register(poll, fd, EPOLLIN, &mqueue->work);
	if (err)
		goto close;

	mqueue->fd = fd;
	mqueue->lines = lines;

	return 0;

close:
	umq_close(fd);

	return err;
}

static void __elogd_nonull(1, 2)
elogd_close_mqueue(const struct elogd_mqueue * __restrict mqueue,
                   const struct upoll * __restrict        poll)
{
	elogd_assert(mqueue);
	elogd_assert(mqueue->fd >= 0);
	elogd_assert(mqueue->lines);

	upoll_unregister(poll, mqueue->fd);
	umq_close(mqueue->fd);
}

/******************************************************************************
 * Main...
 ******************************************************************************/

static struct elog_stdio elogd_stdlog;

static struct elog_stdio_conf elogd_stdlog_conf = {
	.super.severity = CONFIG_ELOGD_STDLOG_SEVERITY,
	.format         = CONFIG_ELOGD_STDLOG_FORMAT
};

static int
elogd_lock(void)
{
	int fd;

	fd = ufile_new(elogd_conf.lock_path,
	               O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW,
	               S_IRUSR);
	if (fd < 0)
		return fd;

	if (flock(fd, LOCK_EX | LOCK_NB)) {
		ufile_close(fd);
		return -errno;
	}

	return fd;
}

static void
elogd_unlock(int fd)
{
	elogd_assert(fd >= 0);

	ufile_close(fd);
}

static void
elogd_drop_caps(void)
{
	int err;

	err = enbox_lock_caps();
	if (err)
		goto err;

	err = enbox_clear_bounding_caps();
	if (err)
		goto err;

	return;

err:
	elogd_err("cannot drop capabilities: %s (%d)", strerror(-err), -err);

	exit(EXIT_FAILURE);
}

int
main(void)
{
	int                  lck;
	struct elogd_queue   queue;
	struct upoll         poll;
	struct elogd_sigchan sigs;
	struct elogd_store   store;
	struct elogd_kmsg    kmsg;
	struct elogd_svc     svc;
	struct elogd_mqueue  mqueue;
	int                  err;
	const char *         msg;
	int                  stat = EXIT_FAILURE;

	umask(07077);

	elog_init_stdio(&elogd_stdlog, &elogd_stdlog_conf);
	enbox_setup((struct elog *)&elogd_stdlog);
	elogd_drop_caps();
	enbox_change_ids(elogd_conf.user, ENBOX_RAISE_SUPP_GROUPS);

	lck = elogd_lock();
	if (lck < 0) {
		err = lck;
		msg = "cannot acquire lock file";
		goto out;
	}

	elogd_uid = getuid();
	elogd_gid = getgid();

	err = elogd_init_queue(&queue,
	                       elogd_conf.kmsg_fetch +
	                       elogd_conf.mqueue_fetch +
	                       elogd_conf.svc_fetch);
	if (err) {
		msg = "cannot initialize queueing";
		goto unlock;
	}

	err = upoll_open(&poll, 4);
	if (err) {
		msg = "cannot initialize polling";
		goto fini_queue;
	}

	err = elogd_open_sigchan(&sigs, &poll);
	if (err) {
		msg = "cannot initialize signaling";
		goto close_poll;
	}

	err = elogd_open_store(&store);
	if (err) {
		msg = "cannot initialize logging store";
		goto close_sigs;
	}

#warning Fix /dev/kmsg perms
	err = elogd_open_kmsg(&kmsg, &queue, &poll);
	if (err) {
		msg = "cannot initialize kernel ring-buffer";
		goto close_store;
	}

	err = elogd_open_svc(&svc, &queue, &poll);
	if (err) {
		msg = "cannot initialize syslog socket";
		goto close_kmsg;
	}

	err = elogd_open_mqueue(&mqueue, &queue, &poll);
	if (err) {
		msg = "cannot initialize init message queue";
		goto close_svc;
	}

	do {
		err = upoll_process(&poll, -1);
		if (err == -EINTR) {
			/* ignore signals interrupts (i.e. ptrace(2) related) */
			err = 0;
			continue;
		}
		elogd_assert(!err || (err == -ESHUTDOWN));

		elogd_flush_store(&store, &queue);
	} while (!err);

	if (err == -ESHUTDOWN)
		stat = EXIT_SUCCESS;

	elogd_close_mqueue(&mqueue, &poll);

close_svc:
	elogd_close_svc(&svc, &poll);
close_kmsg:
	elogd_close_kmsg(&kmsg, &poll);
close_store:
	elogd_close_store(&store);
close_sigs:
	elogd_close_sigchan(&sigs, &poll);
close_poll:
	upoll_close(&poll);
fini_queue:
	elogd_fini_queue(&queue);
unlock:
	elogd_unlock(lck);
out:
	if (stat != EXIT_SUCCESS) {
		elogd_assert(err < 0);
		elogd_err("%s: %s (%d)", msg, strerror(-err), -err);
	}

	return stat;
}
