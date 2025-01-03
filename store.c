/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "store.h"
#include <utils/time.h>
#include <utils/file.h>
#include <utils/dir.h>
#include <utils/pwd.h>
#include <sys/statvfs.h>

static __elogd_nonull(1) __elogd_nothrow
void
elogd_real_boot_time(struct timespec * __restrict tspec)
{
	elogd_assert(tspec);

	struct timespec boot;
	int             ret __unused;

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
	 * Note that real clock time is always >= boot time since system boot
	 * time always starts at 0.
	 */
	ret = utime_tspec_sub(tspec, &boot);
	elogd_assert(ret >= 0);
}

static __elogd_nonull(1, 2, 3, 5) __elogd_nothrow
int
elogd_dqueue_iovec_lines(struct elogd_queue *                  queue,
                         struct stroll_dlist_node * __restrict lines,
                         struct iovec * __restrict             vectors,
                         unsigned int                          max_cnt,
                         size_t * __restrict                   size)
{
	elogd_assert(queue);
	elogd_assert(elogd_queue_busy_count(queue));
	elogd_assert(lines);
	elogd_assert(vectors);
	elogd_assert(max_cnt);
	elogd_assert(max_cnt <= elogd_queue_busy_count(queue));
	elogd_assert((2 * max_cnt) <= IOV_MAX);
	elogd_assert(size);
	elogd_assert(*size);
	elogd_assert(*size <= SSIZE_MAX);

	struct timespec            boot;
	struct stroll_dlist_node * node;
	struct stroll_dlist_node * last;
	unsigned int               cnt = 0;
	size_t                     bytes = 0;

	/* Get time of boot in the real clock time space. */
	elogd_real_boot_time(&boot);

	elogd_queue_foreach_node(queue, node) {
		size_t len;

		len = elogd_line_fill_rfc3164(elogd_line_from_node(node),
		                              &boot,
		                              &vectors[2 * cnt]);
		if ((bytes + len) > *size)
			break;

		bytes += len;
		last = node;
		if (++cnt == max_cnt)
			break;

		elogd_assert(cnt < max_cnt);
	}

	if (!cnt)
		return -ENOSPC;

	elogd_dqueue_bulk(queue, last, lines, cnt);

	*size = bytes;

	return cnt;
}

static __elogd_nonull(1, 2, 3) __elogd_nothrow
void
elogd_requeue_iovec_lines(struct elogd_queue * __restrict queue,
                          struct stroll_dlist_node *      lines,
                          const struct iovec * __restrict vectors,
                          unsigned int                    count,
                          size_t                          written)
{
	elogd_assert(queue);
	elogd_assert(!stroll_dlist_empty(lines));
	elogd_assert(vectors);
	elogd_assert(count);
	elogd_assert((2 * count) <= IOV_MAX);
	elogd_assert((elogd_queue_busy_count(queue) + count) <=
	             elogd_queue_nr(queue));
	elogd_assert(written < SSIZE_MAX);

	struct stroll_dlist_node * node;
	struct stroll_dlist_node * last;
	unsigned int               cnt = 0;
	size_t                     size = 0;

	stroll_dlist_foreach_node(lines, node) {
		const struct iovec * vecs = &vectors[2 * cnt];
		size_t               bytes;

		bytes = vecs[ELOGD_LINE_HEAD_IOVEC].iov_len +
		        vecs[ELOGD_LINE_MSG_IOVEC].iov_len;
		if ((size + bytes) > written)
			break;

		size += bytes;
		last = node;
		cnt++;
	}

	elogd_assert(cnt < count);
	elogd_assert(!cnt ||
	             ((node != lines) && (node != stroll_dlist_next(lines))));

	/*
	 * Adjust content of first uncompleted line / iovec to reflect the
	 * number of written bytes.
	 */
	elogd_line_fixup_partial(elogd_line_from_node(node), written - size);

	if (cnt) {
		/* Release completed lines. */
		struct stroll_dlist_node tmp = STROLL_DLIST_INIT(tmp);

		stroll_dlist_splice_after(&tmp,
		                          stroll_dlist_next(lines),
		                          last);
		elogd_line_destroy_bulk(&tmp);
	}

	/* Requeue uncompleted lines. */
	elogd_requeue_bulk(queue, lines, count - cnt);
}

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
elogd_store_open_file(struct elogd_store * __restrict store)
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

static __elogd_nonull(1)
void
elogd_store_rotate(struct elogd_store * __restrict store)
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
	elogd_store_open_file(store);

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

static __elogd_nonull(1, 2)
int
elogd_store_flush_queue(struct elogd_store * __restrict store,
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

	struct stroll_dlist_node lines;
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
			elogd_line_destroy_bulk(&lines);
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

	elogd_requeue_bulk(queue, &lines, cnt);

	return ret;
}

void
elogd_store_flush(struct elogd_store * __restrict store,
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
		if (elogd_store_open_file(store))
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

	ret = elogd_store_flush_queue(store, queue, cnt, max_sz);
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
	elogd_store_rotate(store);
}

int
elogd_store_open(struct elogd_store * __restrict store)
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
	 * See elogd_store_rotate().
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

	elogd_store_open_file(store);

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

void
elogd_store_close(struct elogd_store * __restrict store)
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
