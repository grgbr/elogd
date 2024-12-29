#if !defined(_GNU_SOURCE)
#error elogd expects the GNU version of basename(3) !
#endif /* !defined(_GNU_SOURCE) */

#include "elogd/config.h"

#include <libgen.h>
/* Make sure we use the GNU version of basename(3). */
#if defined(basename)
#undef basename
#endif /* defined(basename) */
#include <string.h>

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
#include <getopt.h>
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

/* Limit maximum file size to 2GB. */
#define ELOGD_FILE_SIZE_MIN STROLL_CONCAT(CONFIG_ELOGD_SIZE_MIN, U)
#define ELOGD_FILE_SIZE_MAX STROLL_CONCAT(CONFIG_ELOGD_SIZE_MAX, U)
#define ELOGD_FILE_ROT_MIN  STROLL_CONCAT(CONFIG_ELOGD_ROT_MIN, U)
#define ELOGD_FILE_ROT_MAX  STROLL_CONCAT(CONFIG_ELOGD_ROT_MAX, U)
#define ELOGD_FETCH_MIN     STROLL_CONCAT(CONFIG_ELOGD_FETCH_MIN, U)
#define ELOGD_FETCH_MAX     STROLL_CONCAT(CONFIG_ELOGD_FETCH_MAX, U)

#define ELOGD_SVC_MODE \
	STROLL_CONCAT(0, CONFIG_ELOGD_SVC_MODE)

#define ELOGD_FILE_MODE \
	STROLL_CONCAT(0, CONFIG_ELOGD_FILE_MODE)

static struct {
	const char * user;
	const char * lock_path;
	const char * stat_path;
	unsigned int kmsg_fetch;
	const char * mqueue_name;
	unsigned int mqueue_fetch;
	const char * dir_path;
	const char * file_base;
	size_t       file_len;
	const char * file_group;
	mode_t       file_mode;
	size_t       max_size;
	unsigned int max_rot;
	const char * sock_path;
	const char * svc_group;
	mode_t       svc_mode;
	unsigned int svc_fetch;
	bool         free_paths;
} elogd_conf = {
	.user         = compile_choose(sizeof(CONFIG_ELOGD_USER) == 1,
	                               NULL,
	                               CONFIG_ELOGD_USER),
	.lock_path    = CONFIG_ELOGD_LOCK_PATH,
	.stat_path    = CONFIG_ELOGD_STAT_PATH,
	.kmsg_fetch   = CONFIG_ELOGD_KMSG_FETCH,
	.mqueue_name  = CONFIG_ELOGD_MQUEUE_NAME,
	.mqueue_fetch = CONFIG_ELOGD_MQUEUE_FETCH,
	.dir_path     = CONFIG_ELOGD_DIR_PATH,
	.file_base    = CONFIG_ELOGD_FILE_BASE,
	.file_len     = sizeof(CONFIG_ELOGD_FILE_BASE) - 1,
	.file_group   = compile_choose(sizeof(CONFIG_ELOGD_FILE_GROUP) == 1,
	                               NULL,
	                               CONFIG_ELOGD_FILE_GROUP),
	.file_mode    = ELOGD_FILE_MODE,
	.max_size     = CONFIG_ELOGD_SIZE,
	.max_rot      = CONFIG_ELOGD_ROT_NR,
	.sock_path    = CONFIG_ELOGD_SOCK_PATH,
	.svc_group    = compile_choose(sizeof(CONFIG_ELOGD_SVC_GROUP) == 1,
	                               NULL,
	                               CONFIG_ELOGD_SVC_GROUP),
	.svc_mode     = ELOGD_SVC_MODE,
	.svc_fetch    = CONFIG_ELOGD_SVC_FETCH,
	.free_paths   = false
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

#define elogd_assert_conf() \
	elogd_assert(!elogd_conf.user || elogd_conf.user[0]); \
	elogd_assert(upath_validate_path_name(elogd_conf.lock_path) > 0); \
	elogd_assert(upath_validate_path_name(elogd_conf.stat_path) > 0); \
	elogd_assert(elogd_conf.kmsg_fetch > 0); \
	elogd_assert(umq_validate_name(elogd_conf.mqueue_name) > 0); \
	elogd_assert(elogd_conf.mqueue_fetch > 0); \
	elogd_assert(upath_validate_path_name(elogd_conf.dir_path) > 0); \
	elogd_assert(elogd_conf.file_len); \
	elogd_assert((size_t)upath_validate_file_name(elogd_conf.file_base) == \
	             elogd_conf.file_len); \
	elogd_assert(!elogd_conf.file_group || elogd_conf.file_group[0]); \
	elogd_assert(!(elogd_conf.file_mode & ~DEFFILEMODE)); \
	elogd_assert(elogd_conf.max_size >= ELOGD_FILE_SIZE_MIN); \
	elogd_assert(elogd_conf.max_size <= ELOGD_FILE_SIZE_MAX); \
	elogd_assert(elogd_conf.max_rot); \
	elogd_assert(elogd_conf.max_rot <= ELOGD_FILE_ROT_MAX); \
	elogd_assert(upath_validate_path_name(elogd_conf.sock_path) > 0); \
	elogd_assert(!elogd_conf.svc_group || elogd_conf.svc_group[0]); \
	elogd_assert(!(elogd_conf.svc_mode & ~DEFFILEMODE)); \
	elogd_assert(elogd_conf.svc_fetch > 0)

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
	sprintf(&head[19], ".%06ld+00:00", tstamp->tv_nsec / 1000L);

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
	        "%s: error: " _format, \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

#define elogd_warn(_format, ...) \
	fprintf(stderr, \
	        "%s: warning: " _format, \
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

	sigset_t     msk = *usig_empty_msk;
	int          err;
	const char * msg;

	usig_addset(&msk, SIGHUP);
	usig_addset(&msk, SIGINT);
	usig_addset(&msk, SIGQUIT);
	usig_addset(&msk, SIGTERM);
	usig_addset(&msk, SIGUSR1);
	usig_addset(&msk, SIGUSR2);

	chan->fd = usig_open_fd(&msk, SFD_NONBLOCK | SFD_CLOEXEC);
	if (chan->fd < 0) {
		err = chan->fd;
		msg = "open failed";
		goto err;
	}

	chan->work.dispatch = elogd_dispatch_sigchan;
	err = upoll_register(poll, chan->fd, EPOLLIN, &chan->work);
	if (err) {
		msg = "cannot register poll worker";
		goto close;
	}

	usig_procmask(SIG_SETMASK, usig_full_msk, NULL);

	return 0;

close:
	usig_close_fd(chan->fd);
err:
	elogd_err("cannot initialize signaling: %s: %s (%d).\n",
	          msg,
	          strerror(-err),
	          -err);

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

static inline
size_t
elogd_store_file_name_max(void)
{
	/* Logging file basename length + '.' + digits + '\0' */
	return elogd_conf.file_len +
	       sizeof('.') +
	       sizeof(STROLL_STRING(CONFIG_ELOGD_ROT_MAX)) - 1 +
	       sizeof('\0');
}

static __elogd_nonull(1)
int
elogd_open_store_file(struct elogd_store * __restrict store)
{
	elogd_assert_conf();
	elogd_assert(store);
	elogd_assert(store->dir >= 0);
	elogd_assert(upath_validate_path_name(store->base) >
	             (ssize_t)(elogd_conf.file_len + 1));
	elogd_assert(store->base[elogd_conf.file_len] == '.');
	elogd_assert(store->base[elogd_store_file_name_max() +
	                         elogd_conf.file_len] == '.');

	struct stat  st;
	int          err;
	const char * msg;
	gid_t        gid = elogd_gid;

	store->fd = ufile_new_at(store->dir,
	                         store->base,
	                         O_WRONLY | O_APPEND | O_CLOEXEC | O_NOATIME |
	                         O_NOFOLLOW,
	                         elogd_conf.file_mode);

	if (store->fd < 0) {
		err = store->fd;
		msg = "open failed";
		goto err;
	}

	err = ufile_fstat(store->fd, &st);
	if (err) {
		msg = "status retrieval failed";
		goto close;
	}
	if (!S_ISREG(st.st_mode)) {
		err = -EPERM;
		msg = "invalid file type";
		goto close;
	}

	if (elogd_conf.file_group) {
		err = upwd_get_gid_byname(elogd_conf.file_group, &gid);
		if (err)
			elogd_warn("'%s': unknown logging file group, "
			           "using default GID %d.\n",
			           elogd_conf.file_group,
			           gid);
	}
	err = ufile_fchown(store->fd, elogd_uid, gid);
	if (err) {
		msg = "owner / group membership setup failed";
		goto close;
	}

	err = ufile_fchmod(store->fd, elogd_conf.file_mode);
	if (err) {
		msg = "file mode bits setup failed";
		goto close;
	}

	store->size = st.st_size;

	return 0;

close:
	ufile_close(store->fd);
	store->fd = -1;
err:
	elogd_warn("'%s/%s': cannot instantiate logging file: %s: %s (%d).\n",
	           elogd_conf.dir_path,
	           store->base,
	           msg,
	           strerror(-err),
	           -err);

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
	elogd_assert(store->base[elogd_store_file_name_max() +
	                         elogd_conf.file_len] == '.');
	elogd_assert(elogd_conf.max_rot > 1);

	unsigned int rot = elogd_conf.max_rot - 1;
	char *       orig = store->base;
	size_t       len = elogd_conf.file_len + 1;
	char *       nevv = &store->base[elogd_store_file_name_max()];
	int          err;

	err = ufile_sync(store->fd);
	if (err)
		elogd_warn("'%s/%s': cannot sync logging file: %s (%d).\n",
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
			           "cannot rotate logging file: %s (%d).\n",
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
		elogd_warn("'%s/%s': cannot unlink logging file: %s (%d).\n",
		           elogd_conf.dir_path,
		           orig,
		           strerror(-err),
		           -err);

	/* Now close primary logging output file. */
	err = ufile_close(store->fd);
	if (err)
		elogd_warn("'%s/%s': "
		           "failed to close logging file: %s (%d).\n",
		           elogd_conf.dir_path,
		           orig,
		           strerror(-err),
		           -err);

	/* Open / create a new primary logging output file. */
	elogd_open_store_file(store);

	/*
	 * Finally flush parent directory to make changes visible to external
	 * processes.
	 */
	err = udir_sync(store->dir);
	if (err)
		elogd_warn("'%s': cannot sync logging directory: %s (%d).\n",
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
		if (elogd_open_store_file(store))
			return;
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

	elogd_warn("'%s/%s': cannot flush logging file: %s (%d).\n",
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
	const char *   msg;

	store->dir = udir_open(elogd_conf.dir_path,
	                       O_CLOEXEC | O_NOATIME | O_NOFOLLOW);
	if (store->dir < 0) {
		err = store->dir;
		msg = "open failed";
		goto err;
	}

	if (fstatvfs(store->dir, &stat) < 0) {
		err = -errno;
		elogd_assert(err != -EBADF);
		elogd_assert(err != -EFAULT);
		elogd_assert(err != -EINTR);

		msg = "logging filesystem status retrieval failed";
		goto close_dir;
	}

	/*
	 * Allocate 2 slots of file basename length + '.' + 2 digits + '\0'
	 * bytes long.
	 * The second slot is pre-allocated as a temporary area used to compute
	 * logging output file basenames for rotation purpose.
	 * See elogd_rotate_store().
	 */
	store->base = malloc(2 * elogd_store_file_name_max());
	if (!store->base) {
		err = -errno;
		goto close_dir;
	}

	memcpy(store->base, elogd_conf.file_base, elogd_conf.file_len);
	store->base[elogd_conf.file_len] = '.';
	store->base[elogd_conf.file_len + 1] = '0';
	store->base[elogd_conf.file_len + 2] = '\0';

	memcpy(&store->base[elogd_store_file_name_max()],
	       elogd_conf.file_base,
	       elogd_conf.file_len);
	store->base[elogd_store_file_name_max() + elogd_conf.file_len] = '.';

	elogd_open_store_file(store);

	elogd_conf.max_size = stroll_min(elogd_conf.max_size / stat.f_frsize,
	                                 stat.f_blocks / elogd_conf.max_rot);
	elogd_conf.max_size = stroll_min(elogd_conf.max_size,
	                                 ELOGD_FILE_SIZE_MAX /
	                                 (size_t)stat.f_frsize);
	elogd_conf.max_size *= stat.f_frsize;

	return 0;

close_dir:
	udir_close(store->dir);
err:
	elogd_err("cannot initialize logging store: '%s': %s: %s (%d).\n",
	          elogd_conf.dir_path,
	          msg,
	          strerror(-err),
	          -err);

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
			elogd_warn("'%s/%s': "
			           "cannot sync logging file: %s (%d).\n",
			           elogd_conf.dir_path,
			           store->base,
			           strerror(-err),
			           -err);

		err = ufile_close(store->fd);
		if (err)
			elogd_warn("'%s/%s': "
			           "cannot close logging file: %s (%d).\n",
			           elogd_conf.dir_path,
			           store->base,
			           strerror(-err),
			           -err);
	}

	free(store->base);

	err = udir_sync(store->dir);
	if (err)
		elogd_warn("'%s': cannot sync logging directory: %s (%d).\n",
		           elogd_conf.dir_path,
		           strerror(-err),
		           -err);

	err = udir_close(store->dir);
	if (err)
		elogd_warn("'%s': cannot close logging directory: %s (%d).\n",
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

	tstamp->tv_sec = (time_t)(val / 1000000UL);
	tstamp->tv_nsec = (long)((val % 1000000UL) * 1000UL);

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

	tstamp->tv_sec = (time_t)(val / 1000000ULL);
	tstamp->tv_nsec = (long)((val % 1000000ULL) * 1000ULL);

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

static int __elogd_nonull(1, 2, 3)
elogd_open_kmsg(struct elogd_kmsg * __restrict  kmsg,
                struct elogd_queue * __restrict queue,
                const struct upoll * __restrict poll)
{
	elogd_assert(kmsg);
	elogd_assert(queue);
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

	err = elogd_open_kmsg_stat(kmsg);
	if (err) {
		msg = "cannot retrieve message sequence";
		goto close_dev;
	}

	kmsg->work.dispatch = elogd_dispatch_kmsg;
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

	kmsg->dev_fd = fd;
	kmsg->queue = queue;

	if (*kmsg->seqno) {
		err = elogd_skip_init_kmsg(kmsg);
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

	svc->work.dispatch = elogd_dispatch_svc;
	err = upoll_register(poll, svc->unsk.fd, EPOLLIN, &svc->work);
	if (err) {
		msg = "cannot register poll worker";
		goto close;
	}

	svc->queue = queue;

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
	elogd_assert_conf();
	elogd_assert(mqueue);
	elogd_assert(lines);
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

	mqueue->work.dispatch = elogd_dispatch_mqueue;
	err = upoll_register(poll, fd, EPOLLIN, &mqueue->work);
	if (err) {
		msg = "cannot register poll worker";
		goto close;
	}

	mqueue->fd = fd;
	mqueue->lines = lines;

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
	int          fd;
	int          err;
	const char * msg;

	fd = ufile_new(elogd_conf.lock_path,
	               O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW,
	               S_IRUSR);
	if (fd < 0) {
		err = fd;
		msg = "open failed";
		goto err;
	}

	if (flock(fd, LOCK_EX | LOCK_NB)) {
		err = -errno;
		msg = "lock failed";
		goto close;
	}

	return fd;

close:
	ufile_close(fd);
err:
	elogd_err("cannot acquire lock file: '%s': %s: %s (%d).\n",
	          elogd_conf.lock_path,
	          msg,
	          strerror(-err),
	          -err);

	return err;
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
	int          err;
	const char * msg;

	err = enbox_lock_caps();
	if (err) {
		msg = "lock failed";
		goto err;
	}

	err = enbox_clear_bounding_caps();
	if (err) {
		msg = "bounding caps clear failed";
		goto err;
	}

	return;

err:
	elogd_err("cannot drop capabilities: %s: %s (%d).\n",
	          msg,
	          strerror(-err),
	          -err);

	exit(EXIT_FAILURE);
}

#define USAGE \
"Usage: %1$s [OPTIONS]\n" \
"eLogd early system logging daemon.\n" \
"\n" \
"With OPTIONS:\n" \
"    -u|--user USER        -- run as USER system user\n" \
"                             (defaults to %2$s)\n" \
"    -l|--lock-path PATH   -- use PATH as pathname to lock file\n" \
"                             (defaults to `" CONFIG_ELOGD_LOCK_PATH "')\n" \
"    -o|--log-path PATH    -- use PATH as pathname to output logging files\n" \
"                             (defaults to `" CONFIG_ELOGD_DIR_PATH "/" CONFIG_ELOGD_FILE_BASE "')\n" \
"    -e|--log-group GROUP  -- set output logging files group membership to GROUP\n" \
"                             (defaults to %3$s)\n" \
"    -m|--log-mode MODE    -- set output logging files file mode bits to MODE\n" \
"                             (defaults to 0" STROLL_STRING(CONFIG_ELOGD_FILE_MODE) ")\n" \
"    -z|--log-size SIZE    -- restrict output logging files size to SIZE bytes\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_SIZE_MIN) " <= SIZE <= " STROLL_STRING(CONFIG_ELOGD_SIZE_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_SIZE) " bytes)\n" \
"    -r|--log-rotate COUNT -- rotate up to COUNT output logging files with\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_ROT_MIN) " <= COUNT <= " STROLL_STRING(CONFIG_ELOGD_ROT_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_ROT_NR) ")\n" \
"    -s|--stat-path PATH   -- use PATH as pathname to private status file\n" \
"                             (defaults to `" CONFIG_ELOGD_STAT_PATH "')\n" \
"    -k|--kern-fetch COUNT -- set maximum number of messages to fetch from\n" \
"                             kernel ring-buffer to COUNT in a row with\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_FETCH_MIN) " <= COUNT <= " STROLL_STRING(CONFIG_ELOGD_FETCH_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_KMSG_FETCH) ")\n" \
"    -n|--mq-name NAME     -- use NAME as shared message queue name\n" \
"                             (defaults to `" CONFIG_ELOGD_MQUEUE_NAME "')\n" \
"    -q|--mq-fetch COUNT   -- set maximum number of messages to fetch from\n" \
"                             shared message queue to COUNT in a row with\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_FETCH_MIN) " <= COUNT <= " STROLL_STRING(CONFIG_ELOGD_FETCH_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_MQUEUE_FETCH) ")\n" \
"    -p|--sock-path PATH   -- use PATH as pathname to syslog socket file\n" \
"                             (defaults to `" CONFIG_ELOGD_SOCK_PATH "')\n" \
"    -b|--sock-group GROUP -- set syslog socket file group membership to GROUP\n" \
"                             (defaults to %4$s)\n" \
"    -c|--sock-mode MODE   -- set syslog socket file mode bits to MODE\n" \
"                             (defaults to 0" STROLL_STRING(CONFIG_ELOGD_SVC_MODE) ")\n" \
"    -f|--sock-fetch COUNT -- set maximum number of messages to fetch from\n" \
"                             syslog socket to COUNT in a row with\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_FETCH_MIN) " <= COUNT <= " STROLL_STRING(CONFIG_ELOGD_FETCH_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_SVC_FETCH) ")\n" \
"    -h|--help             -- this help message\n"

static void
show_usage(void)
{
	fprintf(stderr,
	        USAGE,
	        program_invocation_short_name,
	        compile_choose(sizeof(CONFIG_ELOGD_USER) == 1,
	                       "current user",
	                       "`" CONFIG_ELOGD_USER "'"),
	        compile_choose(sizeof(CONFIG_ELOGD_FILE_GROUP) == 1,
	                       "current group",
	                       "`" CONFIG_ELOGD_FILE_GROUP "'"),
	        compile_choose(sizeof(CONFIG_ELOGD_SVC_GROUP) == 1,
	                       "current group",
	                       "`" CONFIG_ELOGD_SVC_GROUP "'"));
}

static __elogd_nonull(1)
int
elogd_parse_user_name(const char * __restrict name)
{
	elogd_assert(name);

	if (name) {
		ssize_t ret;

		ret = upwd_validate_user_name(name);
		if (ret < 0) {
			elogd_err("invalid daemon user name: %s (%d).\n",
			          strerror((int)-ret),
			          (int)-ret);
			return EXIT_FAILURE;
		}

		elogd_conf.user = optarg;
	}
	else
		elogd_conf.user = NULL;

	return EXIT_SUCCESS;
}

static __elogd_nonull(1, 2, 3)
int
elogd_parse_path(const char * __restrict  arg,
                 const char * __restrict  kind,
                 const char ** __restrict path)
{
	elogd_assert(arg);
	elogd_assert(kind);
	elogd_assert(path);

	ssize_t ret;

	ret = upath_validate_path_name(arg);
	if (ret < 0) {
		elogd_err("invalid %s pathname: %s (%d).\n",
		          kind,
		          strerror((int)-ret),
		          (int)-ret);
		return EXIT_FAILURE;
	}

	*path = arg;

	return EXIT_SUCCESS;
}

static __elogd_nonull(1, 2, 3)
int
elogd_parse_fetch_count(const char * __restrict   arg,
                        const char * __restrict   kind,
                        unsigned int * __restrict count)
{
	elogd_assert(arg);
	elogd_assert(kind);
	elogd_assert(count);

	int err;

	err = ustr_parse_uint_range(arg,
	                            count,
	                            ELOGD_FETCH_MIN,
	                            ELOGD_FETCH_MAX);
	if (err) {
		elogd_err("invalid %s fetch count: %s (%d).\n",
		          kind,
		          strerror(-err),
		          -err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static __elogd_nonull(1)
int
elogd_parse_mqueue_name(const char * __restrict  arg)
{
	elogd_assert(arg);

	ssize_t ret;

	ret = umq_validate_name(arg);
	if (ret < 0) {
		elogd_err("invalid message queue name: %s (%d).\n",
		          strerror((int)-ret),
		          (int)-ret);
		return EXIT_FAILURE;
	}

	elogd_conf.mqueue_name = arg;

	return EXIT_SUCCESS;
}

static
void
elogd_free_logfile_paths(void)
{
	if (elogd_conf.free_paths) {
		free((char *)elogd_conf.dir_path);
		free((char *)elogd_conf.file_base);
	}
}

static __elogd_nonull(1)
int
elogd_parse_log_path(const char * __restrict path)
{
	elogd_assert(path);

	ssize_t ret;
	char *  tmp;
	char *  dir;
	char *  base;

	ret = upath_validate_path_name(path);
	if (ret < 0) {
		elogd_err("invalid output logging pathname: %s (%d).\n",
		          strerror((int)-ret),
		          (int)-ret);
		return EXIT_FAILURE;
	}

	/* dirname() may modify its argument content... */
	tmp = strdup(path);
	if (!tmp)
		return EXIT_FAILURE;

	/*
	 * dirname() may return pointer to statically allocated memory which
	 * may be overwritten by subsequent calls: make a copy of it.
	 */
	dir = dirname(tmp);
	elogd_assert(dir);
	elogd_assert(dir[0]);
	dir = strdup(dir);
	if (!dir)
		goto free_tmp;

	/*
	 * GNU version of basename() may return pointer to statically allocated
	 * memory which may be overwritten by subsequent calls: make a copy of
	 * it.
	 * In addition, it returns the empty string when given argument has a
	 * trailing slash '/'.
	 */
	base = basename(path);
	ret = strlen(base);
	if (!ret) {
		elogd_err("invalid output logging pathname: empty basename.\n");
		goto free_dir;
	}
	elogd_assert(!((base[0] == '.') && (base[1] == '\0')));

	base = strdup(base);
	if (!base)
		goto free_dir;

	elogd_conf.dir_path = dir;
	elogd_conf.file_base = base;
	elogd_conf.file_len = (size_t)ret;
	elogd_conf.free_paths = true;

	free(tmp);

	return EXIT_SUCCESS;

free_dir:
	free(dir);

free_tmp:
	free(tmp);

	return EXIT_FAILURE;
}

static __elogd_nonull(2, 3)
int
elogd_parse_group_name(const char * __restrict  arg,
                       const char * __restrict  kind,
                       const char ** __restrict name)
{
	elogd_assert(kind);
	elogd_assert(name);

	if (arg) {
		ssize_t ret;

		ret = upwd_validate_group_name(arg);
		if (ret < 0) {
			elogd_err("invalid %s group name: %s (%d).\n",
			          kind,
			          strerror((int)-ret),
			          (int)-ret);
			return EXIT_FAILURE;
		}

		*name = arg;
	}
	else
		*name = NULL;

	return EXIT_SUCCESS;
}

static __elogd_nonull(1)
int
elogd_parse_log_size(const char * __restrict size)
{
	elogd_assert(size);

	unsigned int sz;
	int          err;

	err = ustr_parse_uint_range(size,
	                            &sz,
	                            ELOGD_FILE_SIZE_MIN,
	                            ELOGD_FILE_SIZE_MAX);
	if (err) {
		elogd_err("invalid output logging file size: %s (%d).\n",
		          strerror(-err),
		          -err);
		return EXIT_FAILURE;
	}

	elogd_conf.max_size = (size_t)sz;

	return EXIT_SUCCESS;
}

static __elogd_nonull(1)
int
elogd_parse_log_rot(const char * __restrict count)
{
	elogd_assert(count);

	int err;

	err = ustr_parse_uint_range(count,
	                            &elogd_conf.max_rot,
	                            ELOGD_FILE_ROT_MIN,
	                            ELOGD_FILE_ROT_MAX);
	if (err) {
		elogd_err("invalid output logging file rotation count: "
		          "%s (%d).\n",
		          strerror(-err),
		          -err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static __elogd_nonull(1, 2, 3)
int
elogd_parse_mode(const char * __restrict arg,
                 const char * __restrict kind,
                 mode_t * __restrict     mode)
{
	elogd_assert(arg);
	elogd_assert(kind);
	elogd_assert(mode);

	mode_t bits;
	int    err;

	err = upath_parse_mode(arg, &bits);
	if (err) {
		elogd_err("invalid %s mode bits: %s (%d).\n",
		          kind,
		          strerror(-err),
		          -err);
		return EXIT_FAILURE;
	}

	*mode = bits & DEFFILEMODE;

	return EXIT_SUCCESS;
}

int
main(int argc, char * const argv[])
{
	int                  err;
	int                  lck;
	struct elogd_queue   queue;
	struct upoll         poll;
	struct elogd_sigchan sigs;
	struct elogd_store   store;
	struct elogd_kmsg    kmsg;
	struct elogd_svc     svc;
	struct elogd_mqueue  mqueue;
	int                  stat = EXIT_FAILURE;

	while (true) {
		static const struct option opts[] = {
			{ "user",       optional_argument, NULL, 'u' },
			{ "lock-path",  required_argument, NULL, 'l' },
			{ "stat-path",  required_argument, NULL, 's' },
			{ "kern-fetch", required_argument, NULL, 'k' },
			{ "mq-name",    required_argument, NULL, 'n' },
			{ "mq-fetch",   required_argument, NULL, 'q' },
			{ "log-path",   required_argument, NULL, 'o' },
			{ "log-group",  optional_argument, NULL, 'e' },
			{ "log-mode",   required_argument, NULL, 'm' },
			{ "log-size",   required_argument, NULL, 'z' },
			{ "log-rotate", required_argument, NULL, 'r' },
			{ "sock-path",  required_argument, NULL, 'p' },
			{ "sock-group", optional_argument, NULL, 'b' },
			{ "sock-mode",  required_argument, NULL, 'c' },
			{ "sock-fetch", required_argument, NULL, 'f' },
			{ "help",       no_argument,       NULL, 'h' },
			{ NULL,         0,                 NULL, 0 }
		};

		err = getopt_long(argc,
		                  argv,
		                  ":u::l:s:k:n:q:o:e::m:z:r:p:b::c:f:h",
		                  opts,
		                  NULL);
		if (err < 0)
			break;

		switch (err) {
		case 'u':
			if (elogd_parse_user_name(optarg))
				return EXIT_FAILURE;
			break;

		case 'l':
			if (elogd_parse_path(optarg,
			                     "lock file",
			                     &elogd_conf.lock_path))
				return EXIT_FAILURE;
			break;

		case 's':
			if (elogd_parse_path(optarg,
			                     "private status file",
			                     &elogd_conf.stat_path))
				return EXIT_FAILURE;
			break;

		case 'k':
			if (elogd_parse_fetch_count(optarg,
			                            "kernel ring-buffer",
			                            &elogd_conf.kmsg_fetch))
				return EXIT_FAILURE;
			break;

		case 'n':
			if (elogd_parse_mqueue_name(optarg))
				return EXIT_FAILURE;
			break;

		case 'q':
			if (elogd_parse_fetch_count(optarg,
			                            "message queue",
			                            &elogd_conf.mqueue_fetch))
				return EXIT_FAILURE;
			break;

		case 'o':
			if (elogd_parse_log_path(optarg))
				return EXIT_FAILURE;
			break;

		case 'e':
			if (elogd_parse_group_name(optarg,
			                           "output logging file",
			                           &elogd_conf.file_group))
				return EXIT_FAILURE;
			break;

		case 'm':
			if (elogd_parse_mode(optarg,
			                     "output logging file",
			                     &elogd_conf.file_mode))
				return EXIT_FAILURE;
			break;

		case 'z':
			if (elogd_parse_log_size(optarg))
				return EXIT_FAILURE;
			break;

		case 'r':
			if (elogd_parse_log_rot(optarg))
				return EXIT_FAILURE;
			break;

		case 'p':
			if (elogd_parse_path(optarg,
			                     "syslog socket file",
			                     &elogd_conf.sock_path))
				return EXIT_FAILURE;
			break;

		case 'b':
			if (elogd_parse_group_name(optarg,
			                           "syslog socket file",
			                           &elogd_conf.svc_group))
				return EXIT_FAILURE;
			break;

		case 'c':
			if (elogd_parse_mode(optarg,
			                     "syslog socket file",
			                     &elogd_conf.svc_mode))
				return EXIT_FAILURE;
			break;

		case 'f':
			if (elogd_parse_fetch_count(optarg,
			                            "syslog socket",
			                            &elogd_conf.svc_fetch))
				return EXIT_FAILURE;
			break;

		case 'h':
			show_usage();
			return EXIT_SUCCESS;

		case ':':
			elogd_err("option '%s' requires an argument.\n\n",
			          argv[optind - 1]);
			goto usage;

		case '?':
			elogd_err("unrecognized option '%s'.\n\n",
			          argv[optind - 1]);
			goto usage;

		default:
			elogd_err("unexpected option parsing error.\n\n");
			goto usage;
		}
	}

	if (argc - optind) {
		elogd_err("invalid number of arguments.\n\n");
		goto usage;
	}

	umask(07077);

	elog_init_stdio(&elogd_stdlog, &elogd_stdlog_conf);
	enbox_setup((struct elog *)&elogd_stdlog);
	elogd_drop_caps();
	if (elogd_conf.user)
		enbox_change_ids(elogd_conf.user, ENBOX_RAISE_SUPP_GROUPS);

	lck = elogd_lock();
	if (lck < 0) {
		err = lck;
		goto out;
	}

	elogd_uid = getuid();
	elogd_gid = getgid();

	err = elogd_init_queue(&queue,
	                       elogd_conf.kmsg_fetch +
	                       elogd_conf.mqueue_fetch +
	                       elogd_conf.svc_fetch);
	if (err)
		goto unlock;

	err = upoll_open(&poll, 4);
	if (err) {
		elogd_err("cannot initialize polling: %s (%d).\n",
		          strerror(-err),
		          -err);
		goto fini_queue;
	}

	err = elogd_open_sigchan(&sigs, &poll);
	if (err)
		goto close_poll;

	err = elogd_open_store(&store);
	if (err)
		goto close_sigs;

#warning Fix /dev/kmsg perms
	err = elogd_open_kmsg(&kmsg, &queue, &poll);
	if (err)
		goto close_store;

	err = elogd_open_svc(&svc, &queue, &poll);
	if (err)
		goto close_kmsg;

	err = elogd_open_mqueue(&mqueue, &queue, &poll);
	if (err)
		goto close_svc;

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
	elogd_free_logfile_paths();
	return stat;

usage:
	elogd_free_logfile_paths();
	show_usage();
	return EXIT_FAILURE;
}
