/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include <utils/timer.h>
#include <ctype.h>

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

static __elogd_nonull(1) __elogd_nothrow
void
elogd_alloc_free(struct elogd_line * __restrict  line)
{
	elogd_assert(elogd_the_alloc.lines);
	elogd_assert(elogd_the_alloc.nr);
	elogd_assert(line);
	elogd_assert(line >= elogd_the_alloc.lines);
	elogd_assert(line < &elogd_the_alloc.lines[elogd_the_alloc.nr]);

	stroll_dlist_nqueue_front(&elogd_the_alloc.free, &line->node);
}

static __elogd_nonull(1) __elogd_nothrow
void
elogd_alloc_bulk(struct stroll_dlist_node * __restrict lines)
{
	elogd_assert(elogd_the_alloc.lines);
	elogd_assert(elogd_the_alloc.nr);
	elogd_assert(lines);
	elogd_assert(!stroll_dlist_empty(lines));

	stroll_dlist_embed_after(&elogd_the_alloc.free,
	                         stroll_dlist_next(lines),
	                         stroll_dlist_prev(lines));
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

void
elogd_line_destroy(struct elogd_line * __restrict line)
{
	elogd_alloc_free(line);
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
			const struct elogd_line * prev;
			const struct elogd_line * curr;
			unsigned int              cnt = 1;

			prev = stroll_dlist_entry(stroll_dlist_next(lines),
			                          struct elogd_line,
			                          node);
			curr = prev;
			stroll_dlist_continue_entry(lines, curr, node) {
				cnt++;
				elogd_line_assert_queued(ln);
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
elogd_queue_init(struct elogd_queue * __restrict queue, unsigned int nr)
{
	elogd_assert(queue);
	elogd_assert(nr);

	queue->cnt = 0;
	queue->nr = nr;
	stroll_dlist_init(&queue->head);
}
