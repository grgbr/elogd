/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "store.h"
#include "log.h"
#include <utils/time.h>
#include <utils/file.h>
#include <utils/dir.h>
#include <sys/statvfs.h>

#define elogd_store_assert(_store) \
	elogd_assert(_store); \
	elogd_assert((_store)->dir >= 0); \
	elogd_assert(upath_validate_path_name((_store)->base) > \
	             (ssize_t)(elogd_conf.store_flen + 1)); \
	elogd_assert((_store)->base[elogd_conf.store_flen] == '.'); \
	elogd_assert((_store)->base[elogd_store_file_name_max() + \
	                            elogd_conf.store_flen] == '.')

static inline
size_t
elogd_store_file_name_max(void)
{
	/* Logging file basename length + '.' + digits + '\0' */
	return elogd_conf.store_flen +
	       sizeof('.') +
	       sizeof(STROLL_STRING(CONFIG_ELOGD_ROT_MAX)) - 1 +
	       sizeof('\0');
}

static __elogd_nonull(1)
int
elogd_store_open_file(struct elogd_store * __restrict store)
{
	elogd_assert_conf();
	elogd_store_assert(store);

	struct stat  st;
	int          err;
	const char * msg;
	gid_t        gid = elogd_gid;

	store->fd = ufile_new_at(store->dir,
	                         store->base,
	                         O_WRONLY | O_APPEND | O_CLOEXEC | O_NOATIME |
	                         O_NOFOLLOW,
	                         elogd_conf.store_mode);

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
	if ((size_t)st.st_size > elogd_conf.store_size) {
		msg = "file size too large";
		goto close;
	}

	if (elogd_conf.store_group) {
		err = upwd_get_gid_byname(elogd_conf.store_group, &gid);
		if (err)
			elogd_warn("'%s': unknown logging file group, "
			           "using default GID %d.",
			           elogd_conf.store_group,
			           gid);
	}
	err = ufile_fchown(store->fd, elogd_uid, gid);
	if (err) {
		msg = "owner / group membership setup failed";
		goto close;
	}

	err = ufile_fchmod(store->fd, elogd_conf.store_mode);
	if (err) {
		msg = "file mode bits setup failed";
		goto close;
	}

	store->size = (size_t)st.st_size;

	return 0;

close:
	ufile_close(store->fd);
	store->fd = -1;
err:
	elogd_warn("'%s/%s': cannot instantiate logging file: %s: %s (%d).",
	           elogd_conf.store_dpath,
	           store->base,
	           msg,
	           strerror(-err),
	           -err);

	return err;
}

static __elogd_nonull(1)
int
elogd_store_rotate(struct elogd_store * __restrict store)
{
	elogd_assert_conf();
	elogd_assert(store->fd >= 0);
	elogd_store_assert(store);
	elogd_assert(elogd_conf.store_rot > 1);

	unsigned int rot = elogd_conf.store_rot - 1;
	char *       orig = store->base;
	size_t       len = elogd_conf.store_flen + 1;
	char *       nevv = &store->base[elogd_store_file_name_max()];
	int          err;
	int          ret;

	err = ufile_sync(store->fd);
	if (err)
		elogd_warn("'%s/%s': cannot sync logging file: %s (%d).",
		           elogd_conf.store_dpath,
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
			           "cannot rotate logging file: %s (%d).",
			           elogd_conf.store_dpath,
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
		elogd_warn("'%s/%s': cannot unlink logging file: %s (%d).",
		           elogd_conf.store_dpath,
		           orig,
		           strerror(-err),
		           -err);

	/* Now close primary logging output file. */
	err = ufile_close(store->fd);
	if (err)
		elogd_warn("'%s/%s': "
		           "failed to close logging file: %s (%d).",
		           elogd_conf.store_dpath,
		           orig,
		           strerror(-err),
		           -err);

	/* Open / create a new primary logging output file. */
	ret = elogd_store_open_file(store);

	/*
	 * Finally flush parent directory to make changes visible to external
	 * processes.
	 */
	err = udir_sync(store->dir);
	if (err)
		elogd_warn("'%s': cannot sync logging directory: %s (%d).",
		           elogd_conf.store_dpath,
		           strerror(-err),
		           -err);

	return ret;
}

static __elogd_nonull(1, 2)
void
elogd_store_complete_partial_writev(struct elogd_queue * __restrict queue,
                                    const struct iovec * __restrict iovecs,
                                    size_t                          written)
{
	elogd_assert(queue);
	elogd_assert(iovecs);
	elogd_assert(written < SSIZE_MAX);

	struct stroll_dlist_node * last;
	size_t                     size = 0;
	unsigned int               cnt = 0;

	last = elogd_queue_head(queue);
	while (true) {
		size_t bytes = iovecs[ELOGD_LINE_HEAD_IOVEC].iov_len +
		               iovecs[ELOGD_LINE_MSG_IOVEC].iov_len;

		if ((size + bytes) > written)
			break;

		last = stroll_dlist_next(last);
		size += bytes;
		cnt++;
		iovecs = &iovecs[ELOGD_LINE_IOVEC_NR];
	}

	elogd_assert(stroll_dlist_next(last) != elogd_queue_head(queue));
	elogd_assert(size < written);

	/*
	 * Adjust content of first uncompleted line / iovec to reflect the
	 * number of written bytes.
	 */
	elogd_line_fixup_partial(elogd_line_from_node(stroll_dlist_next(last)),
	                         written - size);

	if (cnt)
		/* Release completed lines. */
		elogd_queue_release_bulk(queue, last, cnt);
}

static __elogd_nonull(1, 2)
int
elogd_store_write_queue(struct elogd_store * __restrict store,
                        struct elogd_queue * __restrict queue,
                        unsigned int                    count,
                        size_t                          size)
{
	elogd_assert_conf();
	elogd_assert(store->fd >= 0);
	elogd_store_assert(store);
	elogd_assert(queue);
	elogd_assert(count);
	elogd_assert(count <= ((unsigned int)IOV_MAX / 2));
	elogd_assert(queue);
	elogd_assert(count <= elogd_queue_busy_count(queue));
	elogd_assert(size);
	elogd_assert(size <= SSIZE_MAX);

	struct stroll_dlist_node * node;
	struct stroll_dlist_node * last = last; /* avoid spurious GCC warning */
	struct iovec               iovecs[count << 1];
	unsigned int               cnt = 0;
	size_t                     bytes = 0;
	ssize_t                    ret;

	elogd_queue_foreach_node(queue, node) {
		struct elogd_line * line = elogd_line_from_node(node);
		size_t              len;

		elogd_assert(line->vector[ELOGD_LINE_HEAD_IOVEC].iov_base);
		len = elogd_line_len(line);
		if ((bytes + len) > size)
			break;

		elogd_line_copy_iovec(line, &iovecs[cnt << 1]);

		bytes += len;
		last = node;
		if (++cnt == count)
			break;

		elogd_assert(cnt < count);
	}

	if (!cnt || !bytes)
		return -EMSGSIZE;

	ret = ufile_writev(store->fd, iovecs, cnt << 1);
	elogd_assert(ret != -EINTR);
	elogd_assert(ret != -EAGAIN);
	if (ret >= 0) {
		elogd_assert((size_t)ret <= bytes);

		store->size += (size_t)ret;

		if ((size_t)ret == bytes) {
			/* All lines were fully written out. */
			elogd_queue_release_bulk(queue, last, cnt);
		}
		else if (ret != 0)
			/* Lines were partially written. */
			elogd_store_complete_partial_writev(queue,
			                                    iovecs,
			                                    (size_t)ret);
		return 0;
	}

	return (int)ret;
}

static __elogd_nonull(1) __elogd_pure
size_t
elogd_store_free_size(const struct elogd_store * __restrict store)
{
	elogd_assert_conf();
	elogd_store_assert(store);

	if (elogd_conf.store_rot > 1) {
		size_t sz = elogd_conf.store_size -
		            stroll_min(store->size, elogd_conf.store_size);
		return (sz > (ELOGD_HEAD_MIN_SIZE - 1 + sizeof('\n'))) ?
		       sz :
		       0;
	}
	else
		return (size_t)SSIZE_MAX;
}

int
elogd_store_write(struct elogd_store * __restrict store,
                  struct elogd_queue * __restrict queue,
                  unsigned int                    count)
{
	elogd_assert_conf();
	elogd_store_assert(store);
	elogd_assert(queue);
	elogd_assert(count);
	elogd_assert(count <= elogd_queue_busy_count(queue));

	size_t maxsz;
	int    ret;

	if (store->fd < 0) {
		ret = elogd_store_open_file(store);
		if (ret)
			return ret;
	}

	count = stroll_min(count, (unsigned int)IOV_MAX / 2);
	maxsz = elogd_store_free_size(store);
	if (maxsz > 0)
		ret = elogd_store_write_queue(store, queue, count, maxsz);
	else
		ret = -EMSGSIZE;

	if (ret == -EMSGSIZE) {
		ret = elogd_store_rotate(store);
		if (ret)
			return ret;
		maxsz = elogd_store_free_size(store);

		ret = elogd_store_write_queue(store, queue, count, maxsz);
	}

	if (ret)
		elogd_warn("'%s/%s': write to logging store failed: %s (%d).",
		           elogd_conf.store_dpath,
		           store->base,
		           strerror(-ret),
		           -ret);

	return ret;
}

int
elogd_store_open(struct elogd_store * __restrict store)
{
	elogd_assert_conf();
	elogd_assert(store);

	struct statvfs stat;
	int            err;
	const char *   msg;

	elogd_debug("initializing '%s' message store...",
	            elogd_conf.store_dpath);

	store->dir = udir_open(elogd_conf.store_dpath,
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

	memcpy(store->base, elogd_conf.store_fbase, elogd_conf.store_flen);
	store->base[elogd_conf.store_flen] = '.';
	store->base[elogd_conf.store_flen + 1] = '0';
	store->base[elogd_conf.store_flen + 2] = '\0';

	memcpy(&store->base[elogd_store_file_name_max()],
	       elogd_conf.store_fbase,
	       elogd_conf.store_flen);
	store->base[elogd_store_file_name_max() + elogd_conf.store_flen] = '.';

	elogd_store_open_file(store);

	elogd_conf.store_size = stroll_min(elogd_conf.store_size /
	                                   stat.f_frsize,
	                                   stat.f_blocks /
	                                   elogd_conf.store_rot);
	elogd_conf.store_size = stroll_min(elogd_conf.store_size,
	                                   ELOGD_STORE_SIZE_MAX /
	                                   (size_t)stat.f_frsize);
	elogd_conf.store_size *= stat.f_frsize;

	elogd_info("'%s' logging store initialized.",
	           elogd_conf.store_dpath);

	return 0;

close_dir:
	udir_close(store->dir);
err:
	elogd_err("cannot initialize logging store: '%s': %s: %s (%d).",
	          elogd_conf.store_dpath,
	          msg,
	          strerror(-err),
	          -err);

	return err;
}

void
elogd_store_close(struct elogd_store * __restrict store)
{
	elogd_assert_conf();
	elogd_store_assert(store);

	int err;

	if (store->fd >= 0) {
		err = ufile_sync(store->fd);
		if (err)
			elogd_warn("'%s/%s': "
			           "cannot sync logging file: %s (%d).",
			           elogd_conf.store_dpath,
			           store->base,
			           strerror(-err),
			           -err);

		err = ufile_close(store->fd);
		if (err)
			elogd_warn("'%s/%s': cannot close logging file: "
			           "%s (%d).",
			           elogd_conf.store_dpath,
			           store->base,
			           strerror(-err),
			           -err);
	}

#if defined(CONFIG_ELOGD_DEBUG)
	free(store->base);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	err = udir_sync(store->dir);
	if (err)
		elogd_warn("'%s': cannot sync logging directory: %s (%d).",
		           elogd_conf.store_dpath,
		           strerror(-err),
		           -err);

	err = udir_close(store->dir);
	if (err)
		elogd_warn("'%s': cannot close logging directory: %s (%d).",
		           elogd_conf.store_dpath,
		           strerror(-err),
		           -err);
}
