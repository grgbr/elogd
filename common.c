/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include <utils/time.h>
#include <ctype.h>

#define elogd_assert_tspec(_tspec) \
	elogd_assert(_tspec); \
	elogd_assert((_tspec)->tv_sec >= 0); \
	elogd_assert((_tspec)->tv_sec <= UTIME_TIMET_MAX); \
	elogd_assert((_tspec)->tv_nsec >= 0); \
	elogd_assert((_tspec)->tv_nsec < 1000000000L)

struct elog_stdio   elogd_stdlog;

struct elogd_config elogd_conf = {
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
	.svc_fetch    = CONFIG_ELOGD_SVC_FETCH

};

/******************************************************************************
 * Various helpers.
 ******************************************************************************/

static __elogd_nonull(1) __elogd_nothrow
size_t
elogd_fill_rfc3164_prio(char * __restrict head,
                        int               facility,
                        int               severity)
{
	elogd_assert(head);
	elogd_assert(!(severity & ~LOG_PRIMASK));
	elogd_assert(!(facility & ~LOG_FACMASK));

	return (size_t)sprintf(head, "<%d>", LOG_MAKEPRI(facility, severity));
}

static __elogd_nonull(1, 2) __elogd_nothrow
size_t
elogd_fill_rfc3339_time(char * __restrict                  string,
                        const struct timespec * __restrict tstamp)
{
	elogd_assert(string);
	elogd_assert_tspec(tstamp);

	struct tm tmp;

	utime_gmtime_from_tspec(&tmp, tstamp);

	strftime(string, 20, "%FT%T", &tmp);
	sprintf(&string[19], ".%06ld+00:00", tstamp->tv_nsec / 1000L);

	return ELOGD_TSTAMP_FIELD_LEN;
}

const char *
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

/******************************************************************************
 * Logging output line handling.
 ******************************************************************************/

static __elogd_nonull(1) __elogd_nothrow
void
elogd_line_reset(struct elogd_line * __restrict line)
{
	line->vector[ELOGD_LINE_HEAD_IOVEC].iov_base = NULL;
	line->tag_len = 0;
	line->pid = -1;
}

size_t
elogd_line_fill_rfc3164(
	struct elogd_line * __restrict     line,
	const struct timespec * __restrict boot,
	struct iovec                       vector[__restrict_arr 2])
{
	elogd_assert(line);
	elogd_line_assert_msg(line, line->vector);
	elogd_assert_tspec(boot);
	elogd_assert(vector);

	struct iovec * vecs = line->vector;

	if (!vecs[ELOGD_LINE_HEAD_IOVEC].iov_base) {
		/* Compute and fill RFC3164 compliant line header. */
		struct timespec tstamp = line->tstamp;
		char *          head = line->head;
		size_t          len;

		utime_tspec_add_clamp(&tstamp, boot);

		len = elogd_fill_rfc3164_prio(head,
		                              line->facility,
		                              line->severity);
		len += elogd_fill_rfc3339_time(&head[len], &tstamp);

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

void
elogd_line_fixup_partial(struct elogd_line * __restrict line, size_t written)
{
	elogd_line_assert_queued(line);
	elogd_line_assert_head(line, line->vector);
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

/******************************************************************************
 * Logging output line allocator
 ******************************************************************************/

struct elogd_alloc {
	/* TODO: move to slist ? */
	struct stroll_dlist_node free;
	struct elogd_line *      lines;
	unsigned int             nr;
};

static struct elogd_alloc elogd_the_alloc;

static __elogd_nothrow
struct elogd_line *
elogd_alloc_one(void)
{
	elogd_assert(elogd_the_alloc.lines);
	elogd_assert(elogd_the_alloc.nr);

	if (!stroll_dlist_empty(&elogd_the_alloc.free))
		return elogd_line_from_node(
			stroll_dlist_dqueue_front(&elogd_the_alloc.free));
	else
		return NULL;
}

struct elogd_line *
elogd_line_create(void)
{
	struct elogd_line * line;

	line = elogd_alloc_one();
	if (line) {
		elogd_line_reset(line);
		return line;
	}

	return NULL;
}

static __elogd_nonull(1) __elogd_nothrow
void
elogd_alloc_free(struct elogd_line * __restrict line)
{
	elogd_assert(elogd_the_alloc.lines);
	elogd_assert(elogd_the_alloc.nr);
	elogd_assert(line);
	elogd_assert(line >= elogd_the_alloc.lines);
	elogd_assert(line < &elogd_the_alloc.lines[elogd_the_alloc.nr]);

	stroll_dlist_nqueue_front(&elogd_the_alloc.free, &line->node);
}

void
elogd_line_destroy(struct elogd_line * __restrict line)
{
	elogd_alloc_free(line);
}

static __elogd_nonull(1) __elogd_nothrow
void
elogd_alloc_free_bulk(struct stroll_dlist_node * __restrict lines)
{
	elogd_assert(elogd_the_alloc.lines);
	elogd_assert(elogd_the_alloc.nr);
	elogd_assert(lines);
	elogd_assert(!stroll_dlist_empty(lines));

	stroll_dlist_embed_after(&elogd_the_alloc.free,
	                         stroll_dlist_next(lines),
	                         stroll_dlist_prev(lines));
}

void
elogd_line_destroy_bulk(struct stroll_dlist_node * lines)
{
	elogd_alloc_free_bulk(lines);
}

int
elogd_alloc_init(unsigned int nr)
{
	elogd_assert(nr);

	unsigned int        l;
	struct elogd_line * lines;

	lines = malloc(nr * sizeof(lines[0]));
	if (lines)
		return -ENOMEM;

	stroll_dlist_init(&elogd_the_alloc.free);
	for (l = 0; l < nr; l++)
		stroll_dlist_insert(&elogd_the_alloc.free, &lines[l].node);
	elogd_the_alloc.lines = lines;
	elogd_the_alloc.nr = nr;

	return 0;
}

void
elogd_alloc_fini(void)
{
	elogd_assert(elogd_the_alloc.lines);
	elogd_assert(elogd_the_alloc.nr);

	free(elogd_the_alloc.lines);
}

/******************************************************************************
 * Logging output Line queue
 ******************************************************************************/

int
elogd_queue_line_cmp(const struct stroll_dlist_node * __restrict first,
                     const struct stroll_dlist_node * __restrict second,
                     void *                                      data __unused)
{
	return utime_tspec_cmp(&elogd_line_from_node(first)->tstamp,
	                       &elogd_line_from_node(second)->tstamp);
}

#if defined(CONFIG_ELOGD_ASSERT)

static __elogd_nonull(1) __elogd_pure __elogd_nothrow
bool
elogd_check_sorted_lines(const struct stroll_dlist_node * __restrict lines,
                         unsigned int                                count)
{
	elogd_assert(lines);
	
	if (count) {
		if (!stroll_dlist_empty(lines)) {
			const struct stroll_dlist_node * prev;
			const struct stroll_dlist_node * curr;
			unsigned int                     cnt = 1;

			prev = stroll_dlist_next(lines);
			curr = prev;
			elogd_line_assert_queued(elogd_line_from_node(curr));
			stroll_dlist_continue_node(lines, curr) {
				cnt++;
				elogd_line_assert_queued(
					elogd_line_from_node(curr));
				if (elogd_queue_line_cmp(prev, curr, NULL) > 0)
					return false;
			}

			return cnt == count;
		}
		else
			return false;
	}
	else
		return stroll_dlist_empty(lines);
}

#else  /* !defined(CONFIG_ELOGD_ASSERT) */

static inline __elogd_nonull(1) __elogd_const __elogd_nothrow
bool
elogd_check_sorted_lines(
	const struct stroll_dlist_node * __restrict lines __unused,
	unsigned int                                count __unused)
{
	return true;
}

#endif /* defined(CONFIG_ELOGD_ASSERT) */

void
elogd_nqueue_presort(struct elogd_queue * __restrict       queue,
                     struct stroll_dlist_node * __restrict presort,
                     unsigned int                          count)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(!!queue->cnt ^ stroll_dlist_empty(&queue->head));
	elogd_assert(count);
	elogd_assert((queue->cnt + count) <= queue->nr);
	elogd_assert(elogd_check_sorted_lines(presort, count));

	if (queue->cnt)
		stroll_dlist_merge_presort(&queue->head,
		                           presort,
		                           elogd_queue_line_cmp,
		                           NULL);
	else
		stroll_dlist_embed_after(&queue->head,
		                         stroll_dlist_next(presort),
		                         stroll_dlist_prev(presort));
	queue->cnt += count;
}

void
elogd_dqueue_bulk(struct elogd_queue * __restrict       queue,
                  struct stroll_dlist_node * __restrict last,
                  struct stroll_dlist_node * __restrict lines,
                  unsigned int                          count)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(!!queue->cnt ^ stroll_dlist_empty(&queue->head));
	elogd_assert(queue->cnt <= queue->nr);
	elogd_assert(count);
	elogd_assert(queue->cnt >= count);
	elogd_assert(lines);

	stroll_dlist_init(lines);
	stroll_dlist_splice_after(lines, stroll_dlist_next(&queue->head), last);
	queue->cnt -= count;
}

void
elogd_requeue_bulk(struct elogd_queue * __restrict       queue,
                   struct stroll_dlist_node * __restrict lines,
                   unsigned int                          count)
{
	elogd_assert(queue);
	elogd_assert(queue->nr);
	elogd_assert(!!queue->cnt ^ stroll_dlist_empty(&queue->head));
	elogd_assert(lines);
	elogd_assert(count);
	elogd_assert((queue->cnt + count) <= queue->nr);
	elogd_assert(elogd_check_sorted_lines(lines, count));

	stroll_dlist_embed_after(&queue->head,
	                         stroll_dlist_next(lines),
	                         stroll_dlist_prev(lines));
	queue->cnt += count;
}


void
elogd_queue_init(struct elogd_queue * __restrict queue, unsigned int nr)
{
	elogd_assert(queue);
	elogd_assert(nr);

	queue->cnt = 0;
	queue->nr = nr;
	stroll_dlist_init(&queue->head);
}
