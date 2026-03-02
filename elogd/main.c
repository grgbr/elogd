/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "log.h"
#include "pipe.h"
#include "sigchan.h"

#include <libgen.h>
/* Make sure we use the GNU version of basename(3). */
#if defined(basename)
#undef basename
#endif /* defined(basename) */
#include <string.h>

#include <enbox/enbox.h>
#include <stroll/bmap.h>
#include <utils/file.h>
#include <getopt.h>
#include <sysexits.h>

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
		elogd_early_log("invalid %s fetch count: %s (%d).",
		                kind,
		                strerror(-err),
		                -err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static bool elogd_free_paths = false;

#if defined(CONFIG_ELOGD_DEBUG)

static
void
elogd_free_logfile_paths(void)
{
	if (elogd_free_paths) {
STROLL_IGNORE_WARN("-Wcast-qual")
		free((char *)elogd_conf.store_dpath);
		free((char *)elogd_conf.store_fbase);
STROLL_RESTORE_WARN
	}
}

#else /* !defined(CONFIG_ELOGD_DEBUG) */

static inline void elogd_free_logfile_paths(void) { }

#endif /* defined(CONFIG_ELOGD_DEBUG) */

static __elogd_nonull(1)
int
elogd_parse_store_path(const char * __restrict path)
{
	elogd_assert(path);

	ssize_t ret;
	char *  tmp;
	char *  dir;
	char *  base;

	ret = upath_validate_path_name(path);
	if (ret < 0) {
		elogd_early_log("invalid log store pathname: %s (%d).",
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
		elogd_early_log("invalid log store pathname: empty basename.");
		goto free_dir;
	}
	elogd_assert(!((base[0] == '.') && (base[1] == '\0')));

	base = strdup(base);
	if (!base)
		goto free_dir;

	elogd_conf.store_dpath = dir;
	elogd_conf.store_fbase = base;
	elogd_conf.store_flen = (size_t)ret;
	elogd_free_paths = true;

	free(tmp);

	return EXIT_SUCCESS;

free_dir:
#if defined(CONFIG_ELOGD_DEBUG)
	free(dir);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

free_tmp:
#if defined(CONFIG_ELOGD_DEBUG)
	free(tmp);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	return EXIT_FAILURE;
}

static __elogd_nonull(1)
int
elogd_parse_store_size(const char * __restrict size)
{
	elogd_assert(size);

	unsigned int sz;
	int          err;

	err = ustr_parse_uint_range(size,
	                            &sz,
	                            ELOGD_STORE_SIZE_MIN,
	                            ELOGD_STORE_SIZE_MAX);
	if (err) {
		elogd_early_log("invalid log store file size: %s (%d).",
		                strerror(-err),
		                -err);
		return EXIT_FAILURE;
	}

	elogd_conf.store_size = (size_t)sz;

	return EXIT_SUCCESS;
}

static __elogd_nonull(1)
int
elogd_parse_store_rot(const char * __restrict count)
{
	elogd_assert(count);

	int err;

	err = ustr_parse_uint_range(count,
	                            &elogd_conf.store_rot,
	                            ELOGD_STORE_ROT_MIN,
	                            ELOGD_STORE_ROT_MAX);
	if (err) {
		elogd_early_log("invalid log store file rotation count: "
		                "%s (%d).",
		                strerror(-err),
		                -err);
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
		elogd_early_log("invalid delay: %s (%d).",
		                strerror(-err),
		                -err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

#if defined(CONFIG_ELOGD_KERN)

static inline
bool
elogd_kern_on(void)
{
	return elogd_conf.kern_on;
}

#else   /* !defined(CONFIG_ELOGD_KERN) */

static inline
bool
elogd_kern_on(void)
{
	return false;
}

#endif  /* defined(CONFIG_ELOGD_KERN) */

#if defined(CONFIG_ELOGD_MQUEUE)

static inline
bool
elogd_mqueue_on(void)
{
	return elogd_conf.mqueue_on;
}

#else   /* !defined(CONFIG_ELOGD_KERN) */

static inline
bool
elogd_mqueue_on(void)
{
	return false;
}

#endif  /* defined(CONFIG_ELOGD_MQUEUE) */

#if defined(CONFIG_ELOGD_KERN)

#define USAGE_KERN \
"    --no-kern             -- disable kernel log source\n" \
"    --kern-fetch=COUNT    -- set maximum number of messages to fetch from\n" \
"                             kernel log to COUNT in a row with\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_FETCH_MIN) " <= COUNT <= " STROLL_STRING(CONFIG_ELOGD_FETCH_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_KERN_FETCH) ")\n"

#else  /* !defined(CONFIG_ELOGD_KERN) */

#define USAGE_KERN

#endif /* defined(CONFIG_ELOGD_KERN) */

#if defined(CONFIG_ELOGD_MQUEUE)

#define USAGE_MQUEUE \
"    --no-mq               -- disable message queue log source\n" \
"    --mq-name=NAME        -- use NAME as message queue name\n" \
"                             (defaults to `" CONFIG_ELOGD_MQUEUE_NAME "')\n" \
"    --mq-fetch=COUNT      -- set maximum number of messages to fetch from\n" \
"                             message queue log to COUNT in a row with\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_FETCH_MIN) " <= COUNT <= " STROLL_STRING(CONFIG_ELOGD_FETCH_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_MQUEUE_FETCH) ")\n"

#else  /* !defined(CONFIG_ELOGD_MQUEUE) */

#define USAGE_MQUEUE

#endif /* defined(CONFIG_ELOGD_MQUEUE) */

#define USAGE \
"Usage: %1$s [OPTIONS]\n" \
"eLogd early system logging daemon.\n" \
"\n" \
"With OPTIONS:\n" \
"    --user=USER           -- run as USER user\n" \
"                             (defaults to `" CONFIG_ELOGD_USER "')\n" \
"    --lock-path=PATH      -- use PATH as pathname to lock file\n" \
"                             (defaults to `" CONFIG_ELOGD_LOCK_PATH "')\n" \
"    --delay=SECONDS       -- set time to wait before saving a message into the\n" \
"                             message store to SECONDS seconds\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_DELAY_MIN) " <= SECONDS <= " STROLL_STRING(CONFIG_ELOGD_DELAY_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_DELAY) ")\n" \
"    --store-path=PATH     -- use PATH as pathname to log store files\n" \
"                             (defaults to `" CONFIG_ELOGD_STORE_DPATH "/" CONFIG_ELOGD_STORE_FBASE "')\n" \
"    --store-group=GROUP   -- set log store files group membership to GROUP\n" \
"                             (defaults to `" CONFIG_ELOGD_STORE_GROUP "')\n" \
"    --store-rot=COUNT     -- rotate up to COUNT log store files with\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_ROT_MIN) " <= COUNT <= " STROLL_STRING(CONFIG_ELOGD_ROT_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_ROT_NR) ")\n" \
"    --store-size=SIZE     -- restrict log store files size to SIZE bytes\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_SIZE_MIN) " <= SIZE <= " STROLL_STRING(CONFIG_ELOGD_SIZE_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_SIZE) " bytes)\n" \
"    --rundir-path=PATH    -- use PATH as pathname to directory where volatile\n" \
"                             internal state data are stored\n" \
"                             (defaults to `" CONFIG_ELOGD_RUNSTATEDIR_PATH "')\n" \
"    --rundir-group=GROUP  -- set volatile internal state data directory group\n" \
"                             membership to GROUP\n" \
"                             (defaults to `" CONFIG_ELOGD_RUNSTATEDIR_GROUP "')\n" \
"    --no-sock             -- disable syslog socket log source\n" \
"    --sock-fetch=COUNT    -- set maximum number of messages to fetch from\n" \
"                             syslog socket to COUNT in a row with\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_FETCH_MIN) " <= COUNT <= " STROLL_STRING(CONFIG_ELOGD_FETCH_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_SOCK_FETCH) ")\n" \
USAGE_KERN \
USAGE_MQUEUE \
"    --int-log=SEVERITY    -- set internal log verbosity level to SEVERITY\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_INTLOG_SEVERITY) ")\n" \
"    --int-fetch=COUNT     -- set maximum number of messages to fetch from\n" \
"                             kernel log to COUNT in a row with\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_FETCH_MIN) " <= COUNT <= " STROLL_STRING(CONFIG_ELOGD_FETCH_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_KERN_FETCH) ")\n" \
"    --verbose=SEVERITY    -- set console log verbosity level to SEVERITY\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_STDLOG_SEVERITY) ")\n" \
"    -h|--help             -- this help message\n" \
"\n" \
ELOGD_USAGE_LEVEL

static void
elogd_show_usage(void)
{
	fprintf(stderr, USAGE "\n", program_invocation_short_name);
}

enum {
	USER_OPT         = 1U << 0,
	LOCK_PATH_OPT    = 1U << 1,
	DELAY_OPT        = 1U << 2,
	STORE_PATH_OPT   = 1U << 3,
	STORE_GROUP_OPT  = 1U << 4,
	STORE_ROT_OPT    = 1U << 5,
	STORE_SIZE_OPT   = 1U << 6,
	RUNDIR_PATH_OPT  = 1U << 7,
	RUNDIR_GROUP_OPT = 1U << 8,
	NO_SOCK_OPT      = 1U << 9,
	SOCK_FETCH_OPT   = 1U << 10,
#if defined(CONFIG_ELOGD_KERN)
	NO_KERN_OPT      = 1U << 11,
	KERN_FETCH_OPT   = 1U << 12,
#endif /* defined(CONFIG_ELOGD_KERN) */
#if defined(CONFIG_ELOGD_MQUEUE)
	NO_MQUEUE_OPT    = 1U << 13,
	MQUEUE_NAME_OPT  = 1U << 14,
	MQUEUE_FETCH_OPT = 1U << 15,
#endif /* defined(CONFIG_ELOGD_MQUEUE) */
	INT_LOG_OPT      = 1U << 16,
	INT_FETCH_OPT    = 1U << 17,
	VERBOSE_OPT      = 1U << 18,
	HELP_OPT         = 'h',
	MISSING_OPT      = ':',
	UNKNOWN_OPT      = '?'
};

static  __elogd_nonull(2)
int
elogd_parse_cmdln(int argc, char * const argv[])
{
	elogd_assert(argc);
	elogd_assert(argv);

	struct elog_parse stdlog_parse;
	struct elog_parse intlog_parse;
	unsigned int      optmsk = STROLL_BMAP_INIT_CLEAR;
	int               ret = EXIT_FAILURE;

	elogd_log_init_parse(&stdlog_parse, &intlog_parse);

	while (true) {
		int                        opt;
		static const struct option opts[] = {
			{ "user",         required_argument, NULL, USER_OPT },
			{ "lock-path",    required_argument, NULL, LOCK_PATH_OPT },
			{ "delay",        required_argument, NULL, DELAY_OPT },
			{ "store-path",   required_argument, NULL, STORE_PATH_OPT },
			{ "store-group",  required_argument, NULL, STORE_GROUP_OPT },
			{ "store-rot",    required_argument, NULL, STORE_ROT_OPT },
			{ "store-size",   required_argument, NULL, STORE_SIZE_OPT },
			{ "rundir-path",  required_argument, NULL, RUNDIR_PATH_OPT },
			{ "rundir-group", required_argument, NULL, RUNDIR_GROUP_OPT },
			{ "no-sock",      no_argument,       NULL, NO_SOCK_OPT },
			{ "sock-fetch",   required_argument, NULL, SOCK_FETCH_OPT },
#if defined(CONFIG_ELOGD_KERN)
			{ "no-kern",      no_argument,       NULL, NO_KERN_OPT },
			{ "kern-fetch",   required_argument, NULL, KERN_FETCH_OPT },
#endif /* defined(CONFIG_ELOGD_KERN) */
#if defined(CONFIG_ELOGD_MQUEUE)
			{ "no-mq",        no_argument,       NULL, NO_MQUEUE_OPT },
			{ "mq-name",      required_argument, NULL, MQUEUE_NAME_OPT },
			{ "mq-fetch",     required_argument, NULL, MQUEUE_FETCH_OPT },
#endif /* defined(CONFIG_ELOGD_MQUEUE) */ 
			{ "int-log",      required_argument, NULL, INT_LOG_OPT },
			{ "int-fetch",    required_argument, NULL, INT_FETCH_OPT },
			{ "verbose",      required_argument, NULL, VERBOSE_OPT },
			{ "help",         no_argument,       NULL, HELP_OPT },
			{ NULL,           0,                 NULL, -1 }
		};

		opt = getopt_long(argc, argv, ":h", opts, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case USER_OPT:
			if (elogd_parse_user_name(optarg, &elogd_conf.user))
				goto out;
			break;

		case LOCK_PATH_OPT:
			if (elogd_parse_lock_path(optarg,
			                          &elogd_conf.lock_path))
				goto out;
			break;

		case DELAY_OPT:
			if (elogd_parse_delay(optarg, &elogd_conf.delay))
				goto out;
			break;

		case STORE_PATH_OPT:
			if (elogd_parse_store_path(optarg))
				goto out;
			break;

		case STORE_GROUP_OPT:
			if (elogd_parse_group_name(optarg,
			                           "log store file",
			                           &elogd_conf.store_group))
				goto out;
			break;

		case STORE_ROT_OPT:
			if (elogd_parse_store_rot(optarg))
				goto out;
			break;

		case STORE_SIZE_OPT:
			if (elogd_parse_store_size(optarg))
				goto out;
			break;

		case RUNDIR_PATH_OPT:
			if (elogd_parse_rundir_path(optarg,
			                            &elogd_conf.rundir_path,
			                            &elogd_conf.rundir_len))
				goto out;
			break;

		case RUNDIR_GROUP_OPT:
			if (elogd_parse_group_name(optarg,
			                           "rundir directory",
			                           &elogd_conf.rundir_group))
				goto out;
			break;

		case NO_SOCK_OPT:
			elogd_conf.sock_on = false;
			break;

		case SOCK_FETCH_OPT:
			if (elogd_parse_fetch_count(optarg,
			                            "syslog socket",
			                            &elogd_conf.sock_fetch))
				goto out;
			break;

#if defined(CONFIG_ELOGD_KERN)
		case NO_KERN_OPT:
			elogd_conf.kern_on = false;
			break;

		case KERN_FETCH_OPT:
			if (elogd_parse_fetch_count(optarg,
			                            "kernel log",
			                            &elogd_conf.kern_fetch))
				goto out;
			break;
#endif /* defined(CONFIG_ELOGD_KERN) */

#if defined(CONFIG_ELOGD_MQUEUE)
		case NO_MQUEUE_OPT:
			elogd_conf.mqueue_on = false;
			break;

		case MQUEUE_NAME_OPT:
			if (elogd_parse_mqueue_name(optarg,
			                            &elogd_conf.mqueue_name))
				goto out;
			break;

		case MQUEUE_FETCH_OPT:
			if (elogd_parse_fetch_count(optarg,
			                            "message queue",
			                            &elogd_conf.mqueue_fetch))
				goto out;
			break;
#endif /* defined(CONFIG_ELOGD_MQUEUE) */

		case INT_LOG_OPT:
			if (elogd_log_parse_intern(optarg, &intlog_parse))
				goto out;
			break;

		case INT_FETCH_OPT:
			if (elogd_parse_fetch_count(optarg,
			                            "internal log",
			                            &elogd_conf.intlog_fetch))
				goto out;
			break;

		case VERBOSE_OPT:
			if (elogd_parse_stdlog(optarg,
			                       &stdlog_parse,
			                       &elogd_conf.stdlog))
				goto out;
			break;

		case HELP_OPT:
			ret = EX_USAGE;
			goto usage;

		case MISSING_OPT:
			elogd_early_log("option '%s' requires an argument.\n",
			                argv[optind - 1]);
			goto usage;

		case UNKNOWN_OPT:
			elogd_early_log("unrecognized option '%s'.\n",
			                argv[optind - 1]);
			goto usage;

		default:
			elogd_early_log("unexpected option parsing error.\n");
			goto usage;
		}

		stroll_bmap_set_mask(&optmsk, (unsigned int)opt);
	}

	if (argc - optind) {
		elogd_early_log("invalid number of arguments.\n");
		goto usage;
	}

	if (!elogd_conf.sock_on && !elogd_kern_on() && !elogd_mqueue_on()) {
		elogd_early_log("invalid configuration: "
		                "all log sources disabled.");
		goto out;
	}

	elogd_log_fini_parse(&stdlog_parse, &intlog_parse);

	if (stroll_bmap_test_mask(optmsk, NO_SOCK_OPT) &&
	    stroll_bmap_test_mask(optmsk, SOCK_FETCH_OPT))
		elogd_early_log(
			"syslog socket log disabled, "
			"ignoring --sock-fetch option...");

#if defined(CONFIG_ELOGD_KERN)
	if (stroll_bmap_test_mask(optmsk, NO_KERN_OPT) &&
	    stroll_bmap_test_mask(optmsk, KERN_FETCH_OPT))
		elogd_early_log(
			"kernel log disabled, "
			"ignoring --kern-fetch option...");
#endif /* defined(CONFIG_ELOGD_KERN) */

#if defined(CONFIG_ELOGD_MQUEUE)
	if (stroll_bmap_test_mask(optmsk, NO_MQUEUE_OPT) &&
	    stroll_bmap_test_mask(optmsk, MQUEUE_FETCH_OPT | MQUEUE_NAME_OPT))
		elogd_early_log(
			"message queue log disabled, "
			"ignoring --mq-name / --mq-fetch options...");
#endif /* defined(CONFIG_ELOGD_MQUEUE) */

	return EXIT_SUCCESS;

usage:
	elogd_show_usage();
out:
	elogd_free_logfile_paths();
#if defined(CONFIG_ELOGD_DEBUG)
	elogd_log_fini_parse(&stdlog_parse, &intlog_parse);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	return ret;
}

static
unsigned int
elogd_fetch_nr(void)
{
	unsigned int nr = 0;

	if (elogd_conf.sock_on)
		nr += elogd_conf.sock_fetch;

#if defined(CONFIG_ELOGD_KERN)
	if (elogd_conf.kern_on)
		nr += elogd_conf.kern_fetch;
#endif /* defined(CONFIG_ELOGD_KERN) */

#if defined(CONFIG_ELOGD_MQUEUE)
	if (elogd_conf.mqueue_on)
		nr += elogd_conf.mqueue_fetch;
#endif /* defined(CONFIG_ELOGD_MQUEUE) */

	if (elogd_conf.intlog.severity >= 0)
		nr += elogd_conf.intlog_fetch;

	return nr;
}

static
void
elogd_secure(void)
{
	elogd_assert_conf();

	const struct passwd * pwd;
	int                   err;
	const char *          msg;
	uint64_t              caps = elogd_kern_on() ? ENBOX_CAP(CAP_SYSLOG)
	                                                : 0;

	umask(07077);
	enbox_setup((struct elog *)elogd_logger);

	pwd = upwd_get_user_byname(elogd_conf.user);
	if (!pwd) {
		err = -errno;
		elogd_assert(err < 0);
		elogd_assert(err != -ENODATA);
		elogd_assert(err != -ENAMETOOLONG);

		msg = "unexpected user";
		goto err;
	}

	if (!pwd->pw_uid || (pwd->pw_uid == enbox_uid)) {
		enbox_ensure_safe(caps);
		return;
	}

	err = enbox_change_ids(pwd, ENBOX_RAISE_SUPP_GROUPS, caps);
	if (err) {
		msg = "cannot change IDs";
		goto err;
	}

	return;

err:
	elogd_err("cannot enable secure operations: %s: %s (%d).",
	          msg,
	          strerror(-err),
	          -err);

	exit(EXIT_FAILURE);
}

static
int
elogd_acquire_lock(void)
{
	if (elogd_lock(elogd_conf.lock_path))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

static __elogd_nonull(1)
int
elogd_init_loop(struct upoll * __restrict poll, unsigned int nr)
{
	elogd_assert(poll);
	elogd_assert(nr);

	int err;

	err = upoll_open(poll, nr);
	if (err) {
		elogd_err("cannot initialize polling: %s (%d).",
		          strerror(-err),
		          -err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static __elogd_nonull(1)
void
elogd_stop(struct elogd_pipe * __restrict pipe)
{
	elogd_assert(pipe);

	int ret;

	elogd_notice("stop requested.");

	ret = elogd_pipe_stop(pipe);

	if (ret)
		elogd_err("stopping failed: %s (%d).",
		          strerror(-ret),
		          -ret);
	else
		elogd_info("stopped.");
}

static __elogd_nonull(1, 2)
int
elogd_start(struct elogd_pipe * __restrict pipe, struct upoll * __restrict poll)
{
	elogd_assert(pipe);
	elogd_assert(poll);

	elogd_debug("starting...");

	while (true) {
		switch (upoll_process(poll, 0)) {
		case 0:
		case -ETIME:
			if (elogd_pipe_process_starting(pipe))
				return 0;
			break;

		case -ESHUTDOWN:
			elogd_stop(pipe);
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

static __elogd_nonull(1, 2)
void
elogd_run(struct elogd_pipe * __restrict pipe, struct upoll * __restrict poll)
{
	elogd_assert(pipe);
	elogd_assert(poll);

	elogd_notice("ready.");

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

int
main(int argc, char * const argv[])
{
	elogd_assert(argc);
	elogd_assert(argv);

	int                  ret;
	struct upoll         poll;
	struct elogd_sigchan sigs;
	struct elogd_pipe    pipe;
	unsigned int         nr;

	elogd_pid = getpid();

	ret = elogd_parse_cmdln(argc, argv);
	if (ret)
		return (ret == EX_USAGE) ? EXIT_SUCCESS : ret;
	ret = EXIT_FAILURE;

	nr = 2 * elogd_fetch_nr();
	if (elogd_alloc_init(nr))
		goto out;

	if (elogd_log_enable())
		goto fini_alloc;
	elogd_secure();
	if (elogd_acquire_lock())
		goto fini_log;

	if (elogd_init_loop(&poll, ELOGD_PIPE_POLL_NR + 1))
		goto unlock;
	if (elogd_sigchan_open(&sigs, &poll))
		goto close_poll;
	if (elogd_pipe_open(&pipe, nr, &poll))
		goto close_sigs;

	ret = EXIT_SUCCESS;
	if (elogd_start(&pipe, &poll))
		goto close_pipe;

	elogd_run(&pipe, &poll);

	elogd_stop(&pipe);

close_pipe:
	elogd_pipe_close(&pipe, &poll);
close_sigs:
	elogd_sigchan_close(&sigs, &poll);
close_poll:
#if defined(CONFIG_ELOGD_DEBUG)
	upoll_close(&poll);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
unlock:
	elogd_unlock();
fini_log:
	elogd_log_fini();
fini_alloc:
	elogd_alloc_fini();
out:
	elogd_free_logfile_paths();

	return ret;
}
