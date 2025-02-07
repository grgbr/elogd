/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "log.h"
#include <utils/time.h>
#include <ctype.h>

#define elogd_assert_tspec(_tspec) \
	elogd_assert(_tspec); \
	elogd_assert((_tspec)->tv_sec >= 0); \
	elogd_assert((_tspec)->tv_sec <= UTIME_TIMET_MAX); \
	elogd_assert((_tspec)->tv_nsec >= 0); \
	elogd_assert((_tspec)->tv_nsec < 1000000000L)

/******************************************************************************
 * Global configuration
 ******************************************************************************/


struct elogd_config elogd_conf = {
#define ELOGD_DELAY        STROLL_CONCAT(CONFIG_ELOGD_DELAY, U)
	.delay        = ELOGD_DELAY,

#define ELOGD_STORE_ROT    STROLL_CONCAT(CONFIG_ELOGD_STORE_ROT, U)
	.store_rot    = ELOGD_STORE_ROT,
#define ELOGD_STORE_SIZE   STROLL_CONCAT(CONFIG_ELOGD_STORE_SIZE, U)
	.store_size   = ELOGD_STORE_SIZE,
	.store_dpath  = ELOGD_EVAL_STRING(CONFIG_ELOGD_STORE_DPATH),
	.store_fbase  = ELOGD_EVAL_STRING(CONFIG_ELOGD_STORE_FBASE),
	.store_flen   = sizeof(CONFIG_ELOGD_STORE_FBASE) - 1,
	.store_group  = ELOGD_EVAL_STRING(CONFIG_ELOGD_STORE_GROUP),

	.user         = ELOGD_EVAL_STRING(CONFIG_ELOGD_USER),
	.lock_path    = ELOGD_EVAL_STRING(CONFIG_ELOGD_LOCK_PATH),

#define ELOGD_INTLOG_FETCH STROLL_CONCAT(CONFIG_ELOGD_INTLOG_FETCH, U)
	.intlog_fetch = CONFIG_ELOGD_INTLOG_FETCH,

	.rundir_path    = ELOGD_EVAL_STRING(CONFIG_ELOGD_RUNSTATEDIR_PATH),
	.rundir_len     = sizeof(CONFIG_ELOGD_RUNSTATEDIR_PATH) - 1,
	.rundir_group = ELOGD_EVAL_STRING(CONFIG_ELOGD_RUNSTATEDIR_GROUP),

	.sock_on      = true,
#define ELOGD_SOCK_FETCH   STROLL_CONCAT(CONFIG_ELOGD_SOCK_FETCH, U)
	.sock_fetch   = ELOGD_SOCK_FETCH,

#if defined(CONFIG_ELOGD_KERN)
	.kern_on      = true,
#define ELOGD_KERN_FETCH   STROLL_CONCAT(CONFIG_ELOGD_KERN_FETCH, U)
	.kern_fetch   = ELOGD_KERN_FETCH,
#endif /* defined(CONFIG_ELOGD_KERN) */

	/* POSIX message queue log settings. */
#if defined(CONFIG_ELOGD_MQUEUE)
	.mqueue_on    = true,
	.mqueue_name  = ELOGD_EVAL_STRING(CONFIG_ELOGD_MQUEUE_NAME),
#define ELOGD_MQUEUE_FETCH STROLL_CONCAT(CONFIG_ELOGD_MQUEUE_FETCH, U)
	.mqueue_fetch = ELOGD_MQUEUE_FETCH
#endif /* defined(CONFIG_ELOGD_MQUEUE) */
};

/******************************************************************************
 * Various helpers.
 ******************************************************************************/

static __elogd_nonull(1)
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

static __elogd_nonull(1, 2)
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
	elogd_assert(end >= string);
	len = (size_t)(end - string);
	if (!len || (len > 3) || (*end != separator))
		return NULL;

	if (val & ~((unsigned long)(LOG_FACMASK | LOG_PRIMASK)))
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

STROLL_IGNORE_WARN("-Wcast-qual")
	return (chr - string) ? (char *)chr : NULL;
STROLL_RESTORE_WARN
}

/******************************************************************************
 * Logging output line handling.
 ******************************************************************************/

#define elogd_line_assert_head(_line, _iovec) \
	elogd_assert((_iovec)[ELOGD_LINE_HEAD_IOVEC].iov_len <= \
	             sizeof((_line)->head)); \
	elogd_assert((char *)(_iovec)[ELOGD_LINE_HEAD_IOVEC].iov_base >= \
	             (_line)->head); \
	elogd_assert((char *)(_iovec)[ELOGD_LINE_HEAD_IOVEC].iov_base < \
	             &(_line)->head[sizeof((_line)->head)])

static __elogd_nonull(1)
void
elogd_line_reset(struct elogd_line * __restrict line)
{
	line->vector[ELOGD_LINE_HEAD_IOVEC].iov_base = NULL;
	line->tag_len = 0;
	line->pid = -1;
}

void
elogd_line_fill_rfc3164(struct elogd_line * __restrict     line,
                        const struct timespec * __restrict real_off)
{
	elogd_assert(line);
	elogd_assert(real_off);
	elogd_line_assert_msg(line, line->vector);

	struct iovec * vecs = line->vector;

	if (!vecs[ELOGD_LINE_HEAD_IOVEC].iov_base) {
		/* Compute and fill RFC3164 compliant line header. */
		char *          head = line->head;
		size_t          len;
		struct timespec tstamp = line->tstamp;

		len = elogd_fill_rfc3164_prio(head,
		                              line->facility,
		                              line->severity);
		utime_tspec_add_clamp(&tstamp, real_off);
		len += elogd_fill_rfc3339_time(&head[len], &tstamp);

		if (line->tag_len) {
			line->tag_len = stroll_min(line->tag_len,
			                           ELOGD_TAG_MAX_LEN);

			head[len++] = ' ';
			memcpy(&head[len], line->tag, line->tag_len);
			len += line->tag_len;

			if (line->pid > 0) {
				head[len++] = '[';
				len += (size_t)sprintf(&head[len],
				                       "%d",
				                       line->pid);
				head[len++] = ']';
			}

			head[len++] = ':';
		}

		head[len++] = ' ';

		vecs[ELOGD_LINE_HEAD_IOVEC].iov_base = head;
		vecs[ELOGD_LINE_HEAD_IOVEC].iov_len = len;
	}
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
	struct stroll_dlist_node free;
	struct elogd_line *      lines;
	unsigned int             nr;
};

#define elogd_alloc_assert() \
	elogd_assert(elogd_the_alloc.lines); \
	elogd_assert(elogd_the_alloc.nr)

static struct elogd_alloc elogd_the_alloc;

static __elogd_nonull(1, 2)
void
elogd_line_destroy_bulk(struct stroll_dlist_node * first,
                        struct stroll_dlist_node * last)
{
	elogd_alloc_assert();
	elogd_assert(first);
	elogd_assert(first != &elogd_the_alloc.free);
	elogd_assert(last);
	elogd_assert(last != &elogd_the_alloc.free);

	stroll_dlist_embed_after(&elogd_the_alloc.free,
	                         first,
	                         last);
}

struct elogd_line *
elogd_line_create(void)
{
	elogd_alloc_assert();

	if (!stroll_dlist_empty(&elogd_the_alloc.free)) {
		struct elogd_line * line;

		line = elogd_line_from_node(
			stroll_dlist_dqueue_front(&elogd_the_alloc.free));
		elogd_line_reset(line);

		return line;
	}

	return NULL;
}

void
elogd_line_destroy(struct elogd_line * __restrict line)
{
	elogd_alloc_assert();
	elogd_assert(line);
	elogd_assert(line >= elogd_the_alloc.lines);
	elogd_assert(line < &elogd_the_alloc.lines[elogd_the_alloc.nr]);

	stroll_dlist_nqueue_front(&elogd_the_alloc.free, &line->node);
}

int
elogd_alloc_init(unsigned int nr)
{
	elogd_assert(nr);

	unsigned int        l;
	struct elogd_line * lines;

	lines = malloc(nr * sizeof(lines[0]));
	if (!lines)
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
	elogd_alloc_assert();

#if defined(CONFIG_ELOGD_DEBUG)
	free(elogd_the_alloc.lines);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
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

static __elogd_nonull(1) __elogd_pure
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

static inline __elogd_nonull(1) __elogd_const
bool
elogd_check_sorted_lines(
	const struct stroll_dlist_node * __restrict lines __unused,
	unsigned int                                count __unused)
{
	return true;
}

#endif /* defined(CONFIG_ELOGD_ASSERT) */

void
elogd_queue_move(struct elogd_queue * __restrict destination,
                 struct elogd_queue * __restrict source)
{
	elogd_queue_assert(destination);
	elogd_assert(!destination->cnt);
	elogd_queue_assert(source);
	elogd_assert(source->cnt);
	elogd_assert(destination->nr >= source->nr);

	destination->cnt = source->cnt;
	stroll_dlist_embed_after(&destination->head,
	                         stroll_dlist_next(&source->head),
	                         stroll_dlist_prev(&source->head));

	source->cnt = 0;
	stroll_dlist_init(&source->head);
}

void
elogd_nqueue_presort(struct elogd_queue * __restrict       queue,
                     struct stroll_dlist_node * __restrict presort,
                     unsigned int                          count)
{
	elogd_queue_assert(queue);
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
elogd_queue_kwmerge(struct elogd_queue * queues[__restrict_arr],
                    unsigned int         count)
{
	elogd_assert(queues);
	elogd_assert(count > 1);

	unsigned int               q;
	unsigned int               cnt;
	struct stroll_dlist_node * heads[count];

	for (q = 0, cnt = 0; q < count; q++) {
		elogd_queue_assert(queues[q]);
		elogd_assert(queues[q]->cnt);

		cnt += queues[q]->cnt;
		heads[q] = &queues[q]->head;
	}

	stroll_dlist_kwmerge_presort(heads, count, elogd_queue_line_cmp, NULL);

	queues[0]->cnt = cnt;
	for (q = 1; q < count; q++) {
		queues[q]->cnt = 0;
		stroll_dlist_init(&queues[q]->head);
	}
}

void
elogd_queue_release_bulk(struct elogd_queue * __restrict       queue,
                         struct stroll_dlist_node * __restrict last,
                         unsigned int                          count)
{
	elogd_queue_assert(queue);
	elogd_assert(last);
	elogd_assert(last != &queue->head);
	elogd_assert(count);
	elogd_assert(count <= queue->cnt);

	struct stroll_dlist_node * first = stroll_dlist_next(&queue->head);

	stroll_dlist_withdraw(first, last);
	queue->cnt -= count;

	elogd_line_destroy_bulk(first, last);
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

void
elogd_queue_fini(const struct elogd_queue * __restrict queue __unused)
{
	elogd_queue_assert(queue);

#if defined(CONFIG_ELOGD_DEBUG)
	if (queue->cnt)
		elogd_line_destroy_bulk(stroll_dlist_next(&queue->head),
		                        stroll_dlist_prev(&queue->head));
#endif /* defined(CONFIG_ELOGD_DEBUG) */
}
