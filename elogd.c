/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "kmsg.h"
#include "svc.h"
#include "mqueue.h"

#include <libgen.h>
/* Make sure we use the GNU version of basename(3). */
#if defined(basename)
#undef basename
#endif /* defined(basename) */
#include <string.h>

#include <stroll/dlist.h>
#include <utils/time.h>
#include <utils/mqueue.h>
#include <utils/file.h>
#include <utils/signal.h>
#include <enbox/enbox.h>
#include <getopt.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/syslog.h>

uid_t elogd_uid;
gid_t elogd_gid;

#define elogd_early_err(_format, ...) \
	fprintf(stderr, \
	        "%s: {   err} " _format, \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

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

	err = elogd_sigchan_open(&sigs, &poll);
	if (err)
		goto close_poll;

	err = elogd_store_open(&store);
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

		elogd_store_flush(&store, &queue);
	} while (!err);

	if (err == -ESHUTDOWN)
		stat = EXIT_SUCCESS;

	elogd_mqueue_close(&mqueue, &poll);

close_svc:
	elogd_svc_close(&svc, &poll);
close_kmsg:
	elogd_kmsg_close(&kmsg, &poll);
close_store:
	elogd_store_close(&store);
close_sigs:
	elogd_sigchan_close(&sigs, &poll);
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


FINISH ME !!

static __stroll_nonull(1, 2) __stroll_nothrow
int
elogd_merge_queues(struct elogd_queue * __restrict sink,
                   struct elogd_queue *            sources[__restrict_arr];
                   unsigned int                    count)
{
	struct elogd_queue * srcs[count + 1];
	unsigned int         s;
	unsigned int         cnt = 0;

	for (s = 0; s < count; s++) {
		if (elogd_queue_empty(sources[q]))
	}

	if (elogd_queue_empty(sink))

	stroll_dlist_kwmerge_presort(srcs, cnt, elogd_queue_line_cmp, NULL);


}
