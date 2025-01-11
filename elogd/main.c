/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "pipe.h"
#include "sigchan.h"

#include <libgen.h>
/* Make sure we use the GNU version of basename(3). */
#if defined(basename)
#undef basename
#endif /* defined(basename) */
#include <string.h>

#include <utils/file.h>
#include <enbox/enbox.h>
#include <sys/file.h>
#include <getopt.h>
#include <sysexits.h>

uid_t elogd_uid;
gid_t elogd_gid;

#define elogd_early_err(_format, ...) \
	fprintf(stderr, \
	        "%s: {   err} " _format, \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

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
STROLL_IGNORE_WARN("-Wcast-qual")
		free((char *)elogd_conf.dir_path);
		free((char *)elogd_conf.file_base);
STROLL_RESTORE_WARN
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
	ret = (ssize_t)strlen(base);
	elogd_assert(ret >= 0);
	elogd_assert(ret <= NAME_MAX);
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

static __elogd_nonull(1, 2)
int
elogd_parse_delay(const char * __restrict   arg,
                  unsigned int * __restrict delay)
{
	elogd_assert(arg);
	elogd_assert(delay);

	int err;

	err = ustr_parse_uint_range(arg,
	                            delay,
	                            ELOGD_DELAY_MIN,
	                            ELOGD_DELAY_MAX);
	if (err) {
		elogd_early_err("invalid delay: %s (%d).\n",
		                strerror(-err),
		                -err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
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
"    -d|--delay SECONDS    -- set time to wait before saving a message into the\n" \
"                             message store to SECONDS seconds\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_DELAY_MIN) " <= SECONDS <= " STROLL_STRING(CONFIG_ELOGD_DELAY_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_DELAY) ")\n" \
"    -v|--stdlog LEVEL     -- set standard output log level\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_STDLOG_SEVERITY) ")\n" \
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
elogd_parse_cmdln(int argc, char * const argv[])
{
	struct elog_parse                   ctx;
	int                                 ret = EXIT_FAILURE;
	static const struct elog_stdio_conf dflt = {
		.super.severity = CONFIG_ELOGD_STDLOG_SEVERITY,
		.format         = ELOG_TAG_FMT | ELOG_SEVERITY_FMT
	};

	elog_init_stdio_parse(&ctx, &elogd_conf.stdlog, &dflt);

	while (true) {
		int                        opt;
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

		opt = getopt_long(argc,
		                  argv,
		                  ":u::l:s:k:n:q:o:e::m:z:r:p:b::c:f:d:v:h",
		                  opts,
		                  NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'u':
			if (elogd_parse_user_name(optarg))
				goto out;
			break;

		case 'l':
			if (elogd_parse_path(optarg,
			                     "lock file",
			                     &elogd_conf.lock_path))
				goto out;
			break;

		case 's':
			if (elogd_parse_path(optarg,
			                     "private status file",
			                     &elogd_conf.stat_path))
				goto out;
			break;

		case 'k':
			if (elogd_parse_fetch_count(optarg,
			                            "kernel ring-buffer",
			                            &elogd_conf.kmsg_fetch))
				goto out;
			break;

		case 'n':
			if (elogd_parse_mqueue_name(optarg))
				goto out;
			break;

		case 'q':
			if (elogd_parse_fetch_count(optarg,
			                            "message queue",
			                            &elogd_conf.mqueue_fetch))
				goto out;
			break;

		case 'o':
			if (elogd_parse_log_path(optarg))
				goto out;
			break;

		case 'e':
			if (elogd_parse_group_name(optarg,
			                           "output logging file",
			                           &elogd_conf.file_group))
				goto out;
			break;

		case 'm':
			if (elogd_parse_mode(optarg,
			                     "output logging file",
			                     &elogd_conf.file_mode))
				goto out;
			break;

		case 'z':
			if (elogd_parse_log_size(optarg))
				goto out;
			break;

		case 'r':
			if (elogd_parse_log_rot(optarg))
				goto out;
			break;

		case 'p':
			if (elogd_parse_path(optarg,
			                     "syslog socket file",
			                     &elogd_conf.sock_path))
				goto out;
			break;

		case 'b':
			if (elogd_parse_group_name(optarg,
			                           "syslog socket file",
			                           &elogd_conf.svc_group))
				goto out;
			break;

		case 'c':
			if (elogd_parse_mode(optarg,
			                     "syslog socket file",
			                     &elogd_conf.svc_mode))
				goto out;
			break;

		case 'f':
			if (elogd_parse_fetch_count(optarg,
			                            "syslog socket",
			                            &elogd_conf.svc_fetch))
				goto out;
			break;

		case 'd':
			if (elogd_parse_delay(optarg, &elogd_conf.delay))
				goto out;
			break;

		case 'v':
			if (elogd_parse_stdlog(optarg, &ctx))
				goto out;
			break;

		case 'h':
			ret = EX_USAGE;
			goto usage;

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

	if (elog_realize_parse(&ctx, (struct elog_conf *)&elogd_conf.stdlog)) {
		elogd_early_err("%s.\n", ctx.error);
		goto out;
	}

	elog_fini_parse(&ctx);

	return EXIT_SUCCESS;

usage:
	show_usage();
out:
	elogd_free_logfile_paths();
	elog_fini_parse(&ctx);

	return ret;
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

static __elogd_nonull(1) __utils_nothrow
int
elogd_setup_loop(struct upoll * __restrict poll, unsigned int nr)
{
	elogd_assert(poll);
	elogd_assert(nr);

	int err;

	err = upoll_open(poll, nr);
	if (err) {
		elogd_err("cannot initialize polling: %s (%d).\n",
		          strerror(-err),
		          -err);
		return err;
	}

	return 0;
}

static __elogd_nonull(1, 2) __elogd_nothrow
int
elogd_start(struct elogd_pipe * __restrict pipe, struct upoll * __restrict poll)
{
	elogd_debug("starting...");

	while (true) {
		switch (upoll_process(poll, 0)) {
		case 0:
		case -ETIME:
			if (elogd_pipe_process_starting(pipe))
				return 0;
			break;

		case -ESHUTDOWN:
			return -ESHUTDOWN;

		case -EINTR:
			/*
			 * Ignore signals interrupts (i.e. ptrace(2) related)
			 */
			break;

		default:
			elogd_assert(0);
		}
	}

	unreachable();
}

static __elogd_nonull(1, 2) __elogd_nothrow
void
elogd_run(struct elogd_pipe * __restrict pipe, struct upoll * __restrict poll)
{
	elogd_info("ready.");

	while (true) {
		int tmout;

		tmout = elogd_pipe_process_timeout(pipe);

		switch (upoll_process(poll, tmout)) {
		case 0:
		case -ETIME:
			elogd_pipe_process_running(pipe);
			break;

		case -ESHUTDOWN:
			return;

		case -EINTR:
			/*
			 * Ignore signals interrupts (i.e. ptrace(2) related)
			 */
			break;

		default:
			elogd_assert(0);
		}
	}

	unreachable();
}

static __elogd_nonull(1) __elogd_nothrow
int
elogd_stop(struct elogd_pipe * __restrict pipe)
{
	int ret;

	elogd_debug("stopping...");

	ret = elogd_pipe_stop(pipe);

	if (ret)
		elogd_err("stopping failed: %s (%d).\n",
		          strerror(-ret),
		          -ret);
	else
		elogd_info("stopped.");

	return ret;
}

int
main(int argc, char * const argv[])
{
	int                  ret;
	struct upoll         poll;
	struct elogd_sigchan sigs;
	struct elogd_pipe    pipe;

	ret = elogd_parse_cmdln(argc, argv);
	if (ret)
		return (ret == EX_USAGE) ? EXIT_SUCCESS : ret;
	ret = EXIT_FAILURE;

	elogd_enable_log();
	elogd_secure();
	if (elogd_lock())
		goto out;
	elogd_uid = getuid();
	elogd_gid = getgid();

	if (elogd_setup_loop(&poll, ELOGD_PIPE_POLL_NR + 1))
		goto unlock;
	if (elogd_sigchan_open(&sigs, &poll))
		goto close_poll;
	if (elogd_pipe_open(&pipe, &poll))
		goto close_sigs;

	ret = EXIT_SUCCESS;
	if (elogd_start(&pipe, &poll))
		goto stop;

	elogd_run(&pipe, &poll);

stop:
	elogd_stop(&pipe);
	elogd_pipe_close(&pipe, &poll);
close_sigs:
	elogd_sigchan_close(&sigs, &poll);
close_poll:
	upoll_close(&poll);
unlock:
	elogd_unlock();
out:
	elogd_free_logfile_paths();

	return ret;
}
