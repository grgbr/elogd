#include "common.h"

#include <libgen.h>
/* Make sure we use the GNU version of basename(3). */
#if defined(basename)
#undef basename
#endif /* defined(basename) */
#include <string.h>

#include "kmsg.h"

#include <stroll/dlist.h>
#include <utils/time.h>
#include <utils/mqueue.h>
#include <utils/file.h>
#include <utils/dir.h>
#include <utils/signal.h>
#include <enbox/enbox.h>
#include <getopt.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/syslog.h>
#include <sys/statvfs.h>

#define elogd_early_err(_format, ...) \
	fprintf(stderr, \
	        "%s: {   err} " _format, \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

#define elogd_assert_tspec(_tspec) \
	elogd_assert(_tspec); \
	elogd_assert((_tspec)->tv_sec >= 0); \
	elogd_assert((_tspec)->tv_sec <= UTIME_TIMET_MAX); \
	elogd_assert((_tspec)->tv_nsec >= 0); \
	elogd_assert((_tspec)->tv_nsec < 1000000000L)

uid_t elogd_uid;
gid_t elogd_gid;

/******************************************************************************
 * Various helpers.
 ******************************************************************************/

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

/******************************************************************************
 * Logging output line handling.
 ******************************************************************************/

static void __elogd_nonull(1)
elogd_fixup_partial_line(struct elogd_line * __restrict line, size_t written)
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

static size_t __elogd_nonull(1, 2, 3)
elogd_fulfill_line(struct elogd_line * __restrict     line,
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

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/

/******************************************************************************
 * Message line source
 ******************************************************************************/

typedef struct elogd_queue *
        (elogd_collect_fn)(struct elogd_source * __restrict source);

struct elogd_source {
	struct elogd_queue queue;
	elogd_collect_fn * collect;
};

static __elogd_nonull(1) __elogd_pure __elogd_nothrow
struct elogd_queue *
elogd_source_queue(struct elogd_source * __restrict source)
{
	elogd_assert(source);
	elogd_assert(source->collect);

	return &source->queue;
}

static __elogd_nonull(1) __elogd_pure __elogd_nothrow
unsigned int
elogd_source_free_count(const struct elogd_source * __restrict source)
{
	elogd_assert(source);
	elogd_assert(source->collect);

	return elogd_queue_nr(&source->queue) -
	       elogd_queue_count(&source->queue);
}

static __elogd_nonull(1, 2) __elogd_nothrow
unsigned int
elogd_source_nqueue(struct elogd_source * __restrict source,
                    struct elogd_line * __restrict   line)
{
	elogd_assert(source);
	elogd_assert(source->collect);
	elogd_assert(line);

	elogd_nqueue(&source->queue, line);
}

static __elogd_nonull(1, 2)
unsigned int
elogd_source_nqueue_presort(struct elogd_source * __restrict      source,
                            struct stroll_dlist_node * __restrict presort)
{
	elogd_assert(source);
	elogd_assert(source->collect);
	elogd_assert(presort);

	elogd_nqueue_presort(&source->queue, presort);
}

static __elogd_nonull(1)
struct elogd_queue *
elogd_source_collect(struct elogd_source * __restrict source)
{
	elogd_assert(source);
	elogd_assert(source->collect);

	if (!elogd_queue_count(&source->queue))
		return NULL;

	return source->collect(source);
}

static __elogd_nonull(1, 3) __elogd_nothrow
void
elogd_source_init(struct elogd_source * __restrict source,
                  unsigned int                     nr,
                  elogd_collect_fn *               collect)
{
	elogd_assert(source);
	elogd_assert(nr);
	elogd_assert(collect);

	elogd_queue_init(&source->queue, nr);
	source->collect = collect;
}

static __elogd_nonull(1, 3) __elogd_nothrow
void
elogd_source_fini(const struct elogd_source * __restrict source)
{
	elogd_assert(source);
	elogd_assert(source->collect);

	elogd_queue_fini(&source->queue);
}

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/******************************************************************************/


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
	elogd_line_assert_queued(line);

	stroll_dlist_insert_inorder_back(&queue->busy,
	                                 &line->node,
	                                 elogd_compare_lines,
	                                 NULL);
	queue->busy_cnt++;
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
	elogd_line_assert_queued(last);
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
	elogd_line_assert_queued(line);
	elogd_line_assert_head(line, line->vector);

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
 * Main...
 ******************************************************************************/

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

static
int
elogd_parse_user_name(const char * __restrict name)
{
	if (name) {
		ssize_t ret;

		ret = upwd_validate_user_name(name);
		if (ret < 0) {
			elogd_early_err("invalid daemon user name: %s (%d).\n",
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
		elogd_early_err("invalid %s pathname: %s (%d).\n",
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
		elogd_early_err("invalid %s fetch count: %s (%d).\n",
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
		elogd_early_err("invalid message queue name: %s (%d).\n",
		                strerror((int)-ret),
		                (int)-ret);
		return EXIT_FAILURE;
	}

	elogd_conf.mqueue_name = arg;

	return EXIT_SUCCESS;
}

static bool elogd_free_paths = false;

static
void
elogd_free_logfile_paths(void)
{
	if (elogd_free_paths) {
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
		elogd_early_err("invalid output logging pathname: %s (%d).\n",
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
		elogd_early_err("invalid output logging pathname: "
		                "empty basename.\n");
		goto free_dir;
	}
	elogd_assert(!((base[0] == '.') && (base[1] == '\0')));

	base = strdup(base);
	if (!base)
		goto free_dir;

	elogd_conf.dir_path = dir;
	elogd_conf.file_base = base;
	elogd_conf.file_len = (size_t)ret;
	elogd_free_paths = true;

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
			elogd_early_err("invalid %s group name: %s (%d).\n",
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
		elogd_early_err("invalid output logging file size: %s (%d).\n",
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
		elogd_early_err("invalid output logging file rotation count: "
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
		elogd_early_err("invalid %s mode bits: %s (%d).\n",
		                kind,
		                strerror(-err),
		                -err);
		return EXIT_FAILURE;
	}

	*mode = bits & DEFFILEMODE;

	return EXIT_SUCCESS;
}

static __elogd_nonull(1, 2)
int
elogd_parse_stdlog(const char * __restrict        arg,
                   struct elog_parse * __restrict context)
{
	elogd_assert(arg);
	elogd_assert(context);

	if (elog_parse_stdio_severity(context, &elogd_conf.stdlog, arg)) {
		elogd_early_err("%s.\n", context->error);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static __elogd_nonull(1)
int
elogd_parse_realize_log(struct elog_parse * __restrict context)
{
	elogd_assert(context);

	int err;

	err = elog_realize_parse(context,
	                         (struct elog_conf *)&elogd_conf.stdlog);
	if (err) {
		elogd_early_err("%s.\n", context->error);
		return EXIT_FAILURE;
	}

	elog_fini_parse(context);

	return EXIT_SUCCESS;
}

static __elogd_nonull(1)
void
elogd_parse_init_log(struct elog_parse * __restrict context)
{
	elogd_assert(context);

	static const struct elog_stdio_conf dflt = {
		.super.severity = CONFIG_ELOGD_STDLOG_SEVERITY,
		.format         = ELOG_TAG_FMT | ELOG_SEVERITY_FMT
	};

	elog_init_stdio_parse(context, &elogd_conf.stdlog, &dflt);
}

static __elogd_nonull(1)
void
elogd_parse_fini_log(const struct elog_parse * __restrict context)
{
	elogd_assert(context);

	elog_fini_parse(context);
}

static
void
elogd_enable_log(void)
{
	elog_init_stdio(&elogd_stdlog, &elogd_conf.stdlog);
}

static
void
elogd_secure(void)
{
	int err;

	umask(07077);
	enbox_setup((struct elog *)&elogd_stdlog);

	err = enbox_lock_caps();
	if (err)
		goto err;

	err = enbox_clear_bounding_caps();
	if (err)
		goto err;

	if (elogd_conf.user) {
		err = enbox_change_ids(elogd_conf.user,
		                       ENBOX_RAISE_SUPP_GROUPS);
		if (err)
			goto err;
	}

	return;

err:
	elogd_err("cannot enable secure operations: %s (%d).\n",
	          strerror(-err),
	          -err);

	exit(EXIT_FAILURE);
}

static int elogd_lock_fd = -1;

static
int
elogd_lock(void)
{
	int          err;
	const char * msg;

	elogd_lock_fd = ufile_new(elogd_conf.lock_path,
	                          O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW,
	                          S_IRUSR);
	if (elogd_lock_fd < 0) {
		err = elogd_lock_fd;
		msg = "open failed";
		goto err;
	}

	if (flock(elogd_lock_fd, LOCK_EX | LOCK_NB)) {
		err = -errno;
		msg = "lock failed";
		goto close;
	}

	return 0;

close:
	ufile_close(elogd_lock_fd);
err:
	elogd_err("cannot acquire lock file: '%s': %s: %s (%d).\n",
	          elogd_conf.lock_path,
	          msg,
	          strerror(-err),
	          -err);

	return err;
}

static
void
elogd_unlock(void)
{
	elogd_assert(elogd_lock_fd >= 0);

	ufile_close(elogd_lock_fd);
}

int
main(int argc, char * const argv[])
{
	struct elog_parse      ctx;
	int                    err;
	struct upoll           poll;
	struct elogd_sigchan   sigs;
	struct elogd_store     store;
	struct elogd_kmsg      kmsg;
	struct elogd_svc       svc;
	struct elogd_mqueue    mqueue;
	int                    stat = EXIT_FAILURE;

	elogd_parse_init_log(&ctx);

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
			{ "stdlog",     required_argument, NULL, 'v' },
			{ "help",       no_argument,       NULL, 'h' },
			{ NULL,         0,                 NULL, 0 }
		};

		err = getopt_long(argc,
		                  argv,
		                  ":u::l:s:k:n:q:o:e::m:z:r:p:b::c:f:v:h",
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

		case 'v':
			if (elogd_parse_stdlog(optarg, &ctx))
				return EXIT_FAILURE;
			break;

		case 'h':
			show_usage();
			return EXIT_SUCCESS;

		case ':':
			elogd_early_err("option '%s' requires an argument.\n\n",
			                argv[optind - 1]);
			goto usage;

		case '?':
			elogd_early_err("unrecognized option '%s'.\n\n",
			                argv[optind - 1]);
			goto usage;

		default:
			elogd_early_err("unexpected option parsing error.\n\n");
			goto usage;
		}
	}

	if (argc - optind) {
		elogd_early_err("invalid number of arguments.\n\n");
		goto usage;
	}

	if (elogd_parse_realize_log(&ctx))
		goto out;
	elogd_enable_log();

	elogd_secure();

	err = elogd_lock();
	if (err)
		goto out;

	elogd_uid = getuid();
	elogd_gid = getgid();

	err = elogd_alloc_init(elogd_conf.kmsg_fetch +
	                       elogd_conf.mqueue_fetch +
	                       elogd_conf.svc_fetch);
	if (err)
		goto unlock;

	err = upoll_open(&poll, 4);
	if (err) {
		elogd_err("cannot initialize polling: %s (%d).\n",
		          strerror(-err),
		          -err);
		goto fini_alloc;
	}

	err = elogd_open_sigchan(&sigs, &poll);
	if (err)
		goto close_poll;

	err = elogd_open_store(&store);
	if (err)
		goto close_sigs;

#warning Fix /dev/kmsg perms
	err = elogd_kmsg_open(&kmsg, &poll);
	if (err)
		goto close_store;

	err = elogd_svc_open(&svc, &poll);
	if (err)
		goto close_kmsg;

	err = elogd_mqueue_open(&mqueue, &poll);
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

	elogd_mqueue_close(&mqueue, &poll);

close_svc:
	elogd_svc_close(&svc, &poll);
close_kmsg:
	elogd_kmsg_close(&kmsg, &poll);
close_store:
	elogd_close_store(&store);
close_sigs:
	elogd_close_sigchan(&sigs, &poll);
close_poll:
	upoll_close(&poll);
fini_alloc:
	elogd_alloc_fini();
unlock:
	elogd_unlock();
out:
	elogd_free_logfile_paths();
	return stat;

usage:
	elogd_free_logfile_paths();
	elogd_parse_fini_log(&ctx);
	show_usage();
	return EXIT_FAILURE;
}
