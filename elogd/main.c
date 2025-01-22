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
#include <utils/file.h>
#include <sys/file.h>
#include <getopt.h>
#include <sysexits.h>

uid_t elogd_uid;
gid_t elogd_gid;

static __elogd_nonull(2, 3)
int
elogd_parse_opt_path(const char * __restrict  arg,
                     const char * __restrict  kind,
                     const char ** __restrict path)
{
	elogd_assert(kind);
	elogd_assert(path);

	if (arg) {
		if (elogd_parse_path(arg, kind, path) < 0)
			return EXIT_FAILURE;
	}
	else
		*path = NULL;

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
		elogd_early_log("invalid %s fetch count: %s (%d).",
		                kind,
		                strerror(-err),
		                -err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

#if defined(CONFIG_ELOGD_MQUEUE)

static
int
elogd_parse_mqueue_name(const char * __restrict arg)
{
	if (arg) {
		ssize_t ret;

		ret = umq_validate_name(arg);
		if (ret < 0) {
			elogd_early_log("invalid message queue name: %s (%d).",
			                strerror((int)-ret),
			                (int)-ret);
			return EXIT_FAILURE;
		}

		elogd_conf.mqueue_name = arg;
	}
	else
		elogd_conf.mqueue_name = NULL;

	return EXIT_SUCCESS;
}

#endif /* defined(CONFIG_ELOGD_MQUEUE) */

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
		elogd_early_log("invalid output logging pathname: %s (%d).",
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
		elogd_early_log("invalid output logging pathname: "
		                "empty basename.");
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

static __elogd_nonull(2, 3)
int
elogd_parse_opt_group_name(const char * __restrict  arg,
                           const char * __restrict  kind,
                           const char ** __restrict name)
{
	elogd_assert(kind);
	elogd_assert(name);

	if (arg) {
		if (elogd_parse_group_name(arg, kind, name))
			return EXIT_FAILURE;
	}
	else
		*name = NULL;

	return EXIT_SUCCESS;
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
		elogd_early_log("invalid output logging file size: %s (%d).",
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
		elogd_early_log("invalid output logging file rotation count: "
		                "%s (%d).",
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
		elogd_early_log("invalid %s mode bits: %s (%d).",
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

#if defined(CONFIG_ELOGD_MQUEUE)

#define USAGE_MQUEUE \
"    --mq-name[=NAME]      -- when NAME is specified, use NAME as shared message\n" \
"                             queue name, disable POSIX queue source otherwise\n" \
"                             (defaults to `" CONFIG_ELOGD_MQUEUE_NAME "')\n" \
"    --mq-fetch=COUNT      -- set maximum number of messages to fetch from\n" \
"                             shared message queue to COUNT in a row with\n" \
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
"    --user[=USER]         -- when USER is specified, run as USER user, do not\n" \
"                             change UID otherwise\n" \
"                             (defaults to %2$s)\n" \
"    --lock-path=PATH      -- use PATH as pathname to lock file\n" \
"                             (defaults to `" ELOGD_LOCK_PATH "')\n" \
"    --std-log[=LEVEL]     -- when LEVEL is specified, set console / stdio log\n" \
"                             severity to LEVEL, disable stdio logging otherwise\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_STDLOG_SEVERITY) ")\n" \
"    --int-log[=LEVEL]     -- when LEVEL is specified, set internal log severity\n" \
"                             to LEVEL, disable internal logging otherwise\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_INTLOG_SEVERITY) ")\n" \
"    --int-fetch=COUNT     -- set maximum number of messages to fetch from\n" \
"                             kernel ring-buffer to COUNT in a row with\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_FETCH_MIN) " <= COUNT <= " STROLL_STRING(CONFIG_ELOGD_FETCH_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_KERN_FETCH) ")\n" \
"    --delay=SECONDS       -- set time to wait before saving a message into the\n" \
"                             message store to SECONDS seconds\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_DELAY_MIN) " <= SECONDS <= " STROLL_STRING(CONFIG_ELOGD_DELAY_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_DELAY) ")\n" \
"    --store-path=PATH     -- use PATH as pathname to output logging files\n" \
"                             (defaults to `" CONFIG_ELOGD_STORE_DPATH "/" CONFIG_ELOGD_STORE_FBASE "')\n" \
"    --store-group[=GROUP] -- when GROUP is specified, set output logging files\n" \
"                             group membership to GROUP, leave it as-is otherwise\n" \
"                             (defaults to %3$s)\n" \
"    --store-mode=MODE     -- set output logging files file mode bits to MODE\n" \
"                             (defaults to 0" STROLL_STRING(CONFIG_ELOGD_STORE_MODE) ")\n" \
"    --store-rot=COUNT     -- rotate up to COUNT output logging files with\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_ROT_MIN) " <= COUNT <= " STROLL_STRING(CONFIG_ELOGD_ROT_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_ROT_NR) ")\n" \
"    --store-size=SIZE     -- restrict output logging files size to SIZE bytes\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_SIZE_MIN) " <= SIZE <= " STROLL_STRING(CONFIG_ELOGD_SIZE_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_SIZE) " bytes)\n" \
"    --sock-path[=PATH]    -- when PATH is specified, use PATH as pathname to\n" \
"                             syslog socket file, disable syslog service socket\n" \
"                             otherwise\n" \
"                             (defaults to `" ELOGD_SOCK_PATH "')\n" \
"    --sock-group[=GROUP]  -- when GROUP is specified, set syslog socket file\n" \
"                             group membership to GROUP, leave it as-is otherwise\n" \
"                             (defaults to %4$s)\n" \
"    --sock-mode=MODE      -- set syslog socket file mode bits to MODE\n" \
"                             (defaults to 0" STROLL_STRING(CONFIG_ELOGD_SOCK_MODE) ")\n" \
"    --sock-fetch=COUNT    -- set maximum number of messages to fetch from\n" \
"                             syslog socket to COUNT in a row with\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_FETCH_MIN) " <= COUNT <= " STROLL_STRING(CONFIG_ELOGD_FETCH_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_SOCK_FETCH) ")\n" \
"    --kern-dpath[=PATH]   -- when PATH is specified, use PATH as pathname to\n" \
"                             kernel ring-buffer device file, disable kernel log\n" \
"                             messages retrieval otherwise\n" \
"                             (defaults to `" ELOGD_KERN_DPATH "')\n" \
"    --kern-spath=PATH     -- use PATH as pathname to private status file\n" \
"                             (defaults to `" CONFIG_ELOGD_KERN_SPATH "')\n" \
"    --kern-fetch=COUNT    -- set maximum number of messages to fetch from\n" \
"                             kernel ring-buffer to COUNT in a row with\n" \
"                             " STROLL_STRING(CONFIG_ELOGD_FETCH_MIN) " <= COUNT <= " STROLL_STRING(CONFIG_ELOGD_FETCH_MAX)"\n" \
"                             (defaults to " STROLL_STRING(CONFIG_ELOGD_KERN_FETCH) ")\n" \
USAGE_MQUEUE \
"    -h|--help             -- this help message\n" \
"\n" \
"Where:\n" \
"    LEVEL := dflt|emerg|alert|crit|err|warn|notice|info" USAGE_DEBUG_LEVEL "\n"

static void
show_usage(void)
{
	fprintf(stderr,
	        USAGE,
	        program_invocation_short_name,
	        compile_choose(sizeof(CONFIG_ELOGD_USER) == 1,
	                       "current user",
	                       "`" CONFIG_ELOGD_USER "'"),
	        compile_choose(sizeof(CONFIG_ELOGD_STORE_GROUP) == 1,
	                       "current group",
	                       "`" CONFIG_ELOGD_STORE_GROUP "'"),
	        compile_choose(sizeof(CONFIG_ELOGD_SOCK_GROUP) == 1,
	                       "current group",
	                       "`" CONFIG_ELOGD_SOCK_GROUP "'"));
}

static  __elogd_nonull(2)
int
elogd_parse_cmdln(int argc, char * const argv[])
{
	elogd_assert(argc);
	elogd_assert(argv);

	struct elog_parse stdlog_parse;
	struct elog_parse intlog_parse;
	int               ret = EXIT_FAILURE;

	elogd_log_init_parse(&stdlog_parse, &intlog_parse);

	while (true) {
		int                        opt;
		static const struct option opts[] = {
#define ELOGD_USER_OPT         (0)
			{ "user",        required_argument, NULL, ELOGD_USER_OPT },
#define ELOGD_LOCK_PATH_OPT    (1)
			{ "lock-path",   required_argument, NULL, ELOGD_LOCK_PATH_OPT },
#define ELOGD_STD_LOG_OPT      (2)
			{ "std-log",     optional_argument, NULL, ELOGD_STD_LOG_OPT },
#define ELOGD_INT_LOG_OPT      (3)
			{ "int-log",     optional_argument, NULL, ELOGD_INT_LOG_OPT },
#define ELOGD_INT_FETCH_OPT    (4)
			{ "int-fetch",   required_argument, NULL, ELOGD_INT_FETCH_OPT },
#define ELOGD_DELAY_OPT        (5)
			{ "delay",       required_argument, NULL, ELOGD_DELAY_OPT },
#define ELOGD_STORE_PATH_OPT   (6)
			{ "store-path",  required_argument, NULL, ELOGD_STORE_PATH_OPT },
#define ELOGD_STORE_GROUP_OPT  (7)
			{ "store-group", optional_argument, NULL, ELOGD_STORE_GROUP_OPT },
#define ELOGD_STORE_MODE_OPT   (8)
			{ "store-mode",  required_argument, NULL, ELOGD_STORE_MODE_OPT },
#define ELOGD_STORE_ROT_OPT    (9)
			{ "store-rot",   required_argument, NULL, ELOGD_STORE_ROT_OPT },
#define ELOGD_STORE_SIZE_OPT   (10)
			{ "store-size",  required_argument, NULL, ELOGD_STORE_SIZE_OPT },
#define ELOGD_SOCK_PATH_OPT    (11)
			{ "sock-path",   optional_argument, NULL, ELOGD_SOCK_PATH_OPT },
#define ELOGD_SOCK_GROUP_OPT   (12)
			{ "sock-group",  optional_argument, NULL, ELOGD_SOCK_GROUP_OPT },
#define ELOGD_SOCK_MODE_OPT    (13)
			{ "sock-mode",   required_argument, NULL, ELOGD_SOCK_MODE_OPT },
#define ELOGD_SOCK_FETCH_OPT   (14)
			{ "sock-fetch",  required_argument, NULL, ELOGD_SOCK_FETCH_OPT },
#define ELOGD_KERN_DPATH_OPT   (15)
			{ "kern-dpath",  optional_argument, NULL, ELOGD_KERN_DPATH_OPT },
#define ELOGD_KERN_SPATH_OPT   (16)
			{ "kern-spath",  required_argument, NULL, ELOGD_KERN_SPATH_OPT },
#define ELOGD_KERN_FETCH_OPT   (17)
			{ "kern-fetch",  required_argument, NULL, ELOGD_KERN_FETCH_OPT },
#if defined(CONFIG_ELOGD_MQUEUE)
#define ELOGD_MQUEUE_NAME_OPT  (18)
			{ "mq-name",     optional_argument, NULL, ELOGD_MQUEUE_NAME_OPT },
#define ELOGD_MQUEUE_FETCH_OPT (19)
			{ "mq-fetch",    required_argument, NULL, ELOGD_MQUEUE_FETCH_OPT },
#endif /* defined(CONFIG_ELOGD_MQUEUE) */
#define ELOGD_HELP_OPT         ('h')
			{ "help",        no_argument,       NULL, ELOGD_HELP_OPT },

			{ NULL,          0,                 NULL, -1 }
		};

		opt = getopt_long(argc, argv, ":h", opts, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case ELOGD_USER_OPT:
			if (elogd_parse_user_name(optarg, &elogd_conf.user))
				goto out;
			break;

		case ELOGD_LOCK_PATH_OPT:
			if (elogd_parse_path(optarg,
			                     "lock file",
			                     &elogd_conf.lock_path) < 0)
				goto out;
			break;

		case ELOGD_STD_LOG_OPT:
			if (elogd_log_parse_std(&stdlog_parse, optarg))
				goto out;
			break;

		case ELOGD_INT_LOG_OPT:
			if (elogd_log_parse_intern(&intlog_parse, optarg))
				goto out;
			break;

		case ELOGD_INT_FETCH_OPT:
			if (elogd_parse_fetch_count(optarg,
			                            "internal log",
			                            &elogd_conf.sock_fetch))
				goto out;
			break;

		case ELOGD_DELAY_OPT:
			if (elogd_parse_delay(optarg, &elogd_conf.delay))
				goto out;
			break;

		case ELOGD_STORE_PATH_OPT:
			if (elogd_parse_store_path(optarg))
				goto out;
			break;

		case ELOGD_STORE_GROUP_OPT:
			if (elogd_parse_opt_group_name(optarg,
			                               "output logging file",
			                               &elogd_conf.store_group))
				goto out;
			break;

		case ELOGD_STORE_MODE_OPT:
			if (elogd_parse_mode(optarg,
			                     "output logging file",
			                     &elogd_conf.store_mode))
				goto out;
			break;

		case ELOGD_STORE_ROT_OPT:
			if (elogd_parse_store_rot(optarg))
				goto out;
			break;

		case ELOGD_STORE_SIZE_OPT:
			if (elogd_parse_store_size(optarg))
				goto out;
			break;

		case ELOGD_SOCK_PATH_OPT:
			if (elogd_parse_opt_path(optarg,
			                         "syslog socket file",
			                         &elogd_conf.sock_path))
				goto out;
			break;

		case ELOGD_SOCK_GROUP_OPT:
			if (elogd_parse_opt_group_name(optarg,
			                               "syslog socket file",
			                               &elogd_conf.sock_group))
				goto out;
			break;

		case ELOGD_SOCK_MODE_OPT:
			if (elogd_parse_mode(optarg,
			                     "syslog socket file",
			                     &elogd_conf.sock_mode))
				goto out;
			break;

		case ELOGD_SOCK_FETCH_OPT:
			if (elogd_parse_fetch_count(optarg,
			                            "syslog socket",
			                            &elogd_conf.sock_fetch))
				goto out;
			break;

		case ELOGD_KERN_DPATH_OPT:
			if (elogd_parse_opt_path(
				optarg,
				"kernel ring-buffer device file",
				&elogd_conf.kern_dpath))
				goto out;
			break;

		case ELOGD_KERN_SPATH_OPT:
			if (elogd_parse_path(optarg,
			                     "private status file",
			                     &elogd_conf.kern_spath) < 0)
				goto out;
			break;

		case ELOGD_KERN_FETCH_OPT:
			if (elogd_parse_fetch_count(optarg,
			                            "kernel ring-buffer",
			                            &elogd_conf.kern_fetch))
				goto out;
			break;

#if defined(CONFIG_ELOGD_MQUEUE)
		case ELOGD_MQUEUE_NAME_OPT:
			if (elogd_parse_mqueue_name(optarg))
				goto out;
			break;

		case ELOGD_MQUEUE_FETCH_OPT:
			if (elogd_parse_fetch_count(optarg,
			                            "message queue",
			                            &elogd_conf.mqueue_fetch))
				goto out;
			break;
#endif /* defined(CONFIG_ELOGD_MQUEUE) */

		case ELOGD_HELP_OPT:
			ret = EX_USAGE;
			goto usage;

		case ':':
			elogd_early_log("option '%s' requires an argument.\n",
			                argv[optind - 1]);
			goto usage;

		case '?':
			elogd_early_log("unrecognized option '%s'.\n",
			                argv[optind - 1]);
			goto usage;

		default:
			elogd_early_log("unexpected option parsing error.\n");
			goto usage;
		}
	}

	if (argc - optind) {
		elogd_early_log("invalid number of arguments.\n");
		goto usage;
	}

	if (!elogd_conf.kern_dpath &&
#if defined(CONFIG_ELOGD_MQUEUE)
	    !elogd_conf.mqueue_name &&
#endif /* defined(CONFIG_ELOGD_MQUEUE) */
	    !elogd_conf.sock_path) {
		elogd_early_log("invalid configuration: "
		                "all message sources disabled.");
		goto out;
	}

	elogd_log_fini_parse(&stdlog_parse, &intlog_parse);

	return EXIT_SUCCESS;

usage:
	show_usage();
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

	if (elogd_conf.kern_dpath)
		nr += elogd_conf.kern_fetch;

#if defined(CONFIG_ELOGD_MQUEUE)
	if (elogd_conf.mqueue_name)
		nr += elogd_conf.mqueue_fetch;
#endif /* defined(CONFIG_ELOGD_MQUEUE) */

	if (elogd_conf.sock_path)
		nr += elogd_conf.sock_fetch;

	if (elogd_conf.intlog.severity >= 0)
		nr += elogd_conf.intlog_fetch;

	return nr;
}

static
void
elogd_secure(void)
{
	elogd_assert_conf();
	
	int err;

	umask(07077);
	enbox_setup((struct elog *)&elogd_logger);

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

	elogd_uid = getuid();
	elogd_gid = getgid();

	return;

err:
	elogd_err("cannot enable secure operations: %s (%d).",
	          strerror(-err),
	          -err);

	exit(EXIT_FAILURE);
}

static int elogd_lock_fd = -1;

static
int
elogd_lock(void)
{
	elogd_assert_conf();

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
#if defined(CONFIG_ELOGD_DEBUG)
	ufile_close(elogd_lock_fd);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
err:
	elogd_err("cannot acquire lock file: '%s': %s: %s (%d).",
	          elogd_conf.lock_path,
	          msg,
	          strerror(-err),
	          -err);

	return err;
}

#if defined(CONFIG_ELOGD_DEBUG)

static
void
elogd_unlock(void)
{
	elogd_assert(elogd_lock_fd >= 0);

	ufile_close(elogd_lock_fd);
}

#else  /* !defined(CONFIG_ELOGD_DEBUG) */

static
void
elogd_unlock(void)
{
	elogd_assert(elogd_lock_fd >= 0);
}

#endif /* defined(CONFIG_ELOGD_DEBUG) */

static __elogd_nonull(1)
int
elogd_setup_loop(struct upoll * __restrict poll, unsigned int nr)
{
	elogd_assert(poll);
	elogd_assert(nr);

	int err;

	err = upoll_open(poll, nr);
	if (err) {
		elogd_err("cannot initialize polling: %s (%d).",
		          strerror(-err),
		          -err);
		return err;
	}

	return 0;
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
	if (elogd_lock())
		goto fini_log;

	if (elogd_setup_loop(&poll, ELOGD_PIPE_POLL_NR + 1))
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
