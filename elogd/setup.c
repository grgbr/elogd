/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "builtin.h"
#include <stroll/bmap.h>
#include <utils/file.h>
#include <enbox/enbox.h>
#include <getopt.h>
#include <sysexits.h>

struct elogd_setup_conf {
	bool                   kern_on;
#if defined(CONFIG_ELOGD_KERN)
	const char *           kern_group;
#endif /* defined(CONFIG_ELOGD_KERN) */
	const char *           user;
	const char *           rundir_path;
	size_t                 rundir_len;
	const char *           rundir_group;
	bool                   devlog_on;
	bool                   store_on;
	const char *           store_path;
	const char *           store_group;
	struct elog_stdio_conf stdlog;
};

#if defined(CONFIG_ELOGD_KERN)

#define elogd_setup_assert_kern(_conf) \
	elogd_assert(upwd_validate_group_name((_conf)->kern_group) > 0)

#else  /* !defined(CONFIG_ELOGD_KERN) */

#define elogd_setup_assert_kern(_conf)

#endif /* defined(CONFIG_ELOGD_KERN) */

#define elogd_setup_assert_conf(_conf) \
	elogd_setup_assert_kern(_conf); \
	elogd_assert(upwd_validate_user_name((_conf)->user) > 0); \
	elogd_assert((_conf)->rundir_len); \
	elogd_assert((size_t) \
	             upath_validate_path_name((_conf)->rundir_path) == \
	             (_conf)->rundir_len); \
	elogd_assert(upwd_validate_group_name((_conf)->rundir_group) > 0); \
	elogd_assert(upath_validate_path_name((_conf)->store_path) > 0); \
	elogd_assert(upwd_validate_group_name((_conf)->store_group) > 0); \
	elogd_assert(((_conf)->stdlog.super.severity == -1) ^ \
	             !((_conf)->stdlog.super.severity & ~LOG_PRIMASK)); \
	elogd_assert((_conf)->stdlog.format == ELOG_TAG_FMT)

static struct elogd_setup_conf elogd_setup_the_conf = {
	.kern_on        = true,
#if defined(CONFIG_ELOGD_KERN)
	.kern_group     = CONFIG_ELOGD_KERN_GROUP,
#endif /* defined(CONFIG_ELOGD_KERN) */
	.user           = ELOGD_USER,
	.rundir_path    = ELOGD_RUNSTATEDIR_PATH,
	.rundir_len     = sizeof(ELOGD_RUNSTATEDIR_PATH) - 1,
	.rundir_group   = ELOGD_RUNSTATEDIR_GROUP,
	.devlog_on      = true,
	.store_on       = true,
	.store_path     = CONFIG_ELOGD_STORE_DPATH,
	.store_group    = ELOGD_STORE_GROUP
};

static __elogd_nonull(1, 2)
int
elogd_setup_sysctl_write(const char * __restrict path,
                         const char * __restrict string,
                         size_t                  len)
{
	elogd_assert(upath_validate_path_name(path) > 0);
	elogd_assert(string);
	elogd_assert(strlen(string) == len);

	int     fd;
	ssize_t ret;

#define ELOGD_SETUP_SYSCTL_WRITE_FLAGS \
	(O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOATIME | O_NOFOLLOW)
	fd = ufile_open(path, ELOGD_SETUP_SYSCTL_WRITE_FLAGS);
	if (fd < 0)
		return fd;

	do {
		ret = ufile_write(fd, string, len);
		if (ret < 0)
			goto close;
		len -= (size_t)ret;
	} while (len);

	ret = 0;

close:
	ufile_close(fd);

	return (int)ret;
}

/*
 * Deny access from dmesg(8) to unprivileged users.
 *
 * See `dmesg_restrict' within
 * <linux>/Documentation/admin-guide/sysctl/kernel.rst
 */
static
int
elogd_setup_kern_dmesg(void)
{
	return elogd_setup_sysctl_write("/proc/sys/kernel/dmesg_restrict",
	                                "1\n",
	                                2);
}

#if defined(CONFIG_ELOGD_KERN)

/*
 * Enable kernel log access from userspace.
 *
 * See `printk_devkmsg' within
 * <linux>/Documentation/admin-guide/sysctl/kernel.rst
 */
static
int
elogd_setup_kern_kmsg(void)
{
	return elogd_setup_sysctl_write("/proc/sys/kernel/printk_devkmsg",
	                                "on\n",
	                                3);
}

#else  /* !defined(CONFIG_ELOGD_KERN) */

/*
 * Disable kernel log access from userspace.
 *
 * See `printk_devkmsg' within
 * <linux>/Documentation/admin-guide/sysctl/kernel.rst
 */
static
int
elogd_setup_kern_kmsg(void)
{
	return elogd_setup_sysctl_write("/proc/sys/kernel/printk_devkmsg",
	                                "off\n",
	                                4);
}

#endif /* defined(CONFIG_ELOGD_KERN) */

static
int
elogd_setup_kern_log(void)
{
	elogd_setup_assert_conf(&elogd_setup_the_conf);

	int  err;

	err = elogd_setup_kern_kmsg();
	if (err) {
		elogd_err("kernel log: "
		          "failed to enable access from userspace: %s (%d).",
		          strerror(-err),
		          -err);
		return EXIT_FAILURE;
	}

	err = elogd_setup_kern_dmesg();
	if (err) {
		elogd_err("kernel log: "
		          "failed to disable unprivileged access: %s (%d).",
		          strerror(-err),
		          -err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

#if defined(CONFIG_ELOGD_KERN)

/*
 * Setup kernel log ring-buffer (usualy `/dev/kmsg').
 *
 * Create the corresponding device node file if needed and set proper permission
 * ownership and mode bits.
 *
 * See <linux>/Documentation/admin-guide/sysctl/kernel.rst
 *     <linux>/Documentation/admin-guide/devices.txt
 *     <linux>/Documentation/ABI/testing/dev-kmsg
 */
static
int
elogd_setup_kern_dev(void)
{
	elogd_setup_assert_conf(&elogd_setup_the_conf);

	gid_t  gid;
	int    err;

	err = upwd_get_gid_byname(elogd_setup_the_conf.kern_group, &gid);
	if (err) {
		elogd_err("'" ELOGD_KERN_DPATH " kernel log device: "
		          "unknown '%s' group name.",
		          elogd_setup_the_conf.kern_group);
		return EXIT_FAILURE;
	}

	err = enbox_make_chrdev(ELOGD_KERN_DPATH,
	                        0,                 /* root */
	                        gid,               /* klog */
	                        S_IRUSR | S_IRGRP, /* 0440 */
	                        ELOGD_KERN_MAJOR,
	                        ELOGD_KERN_MINOR);
	if (err) {
		elogd_err("'" ELOGD_KERN_DPATH "' kernel log device: "
		          "failed to setup device node: "
		          "%s (%d).",
		          strerror(-err),
		          -err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

#else  /* !defined(CONFIG_ELOGD_KERN) */

static
int
elogd_setup_kern_dev(void)
{
	elogd_setup_assert_conf(&elogd_setup_the_conf);

	int err;

	err = enbox_make_chrdev(ELOGD_KERN_DPATH,
	                        0,                 /* root */
	                        0,                 /* root */
	                        S_IRUSR,           /* 0400 */
	                        ELOGD_KERN_MAJOR,
	                        ELOGD_KERN_MINOR);
	if (err) {
		elogd_err("'" ELOGD_KERN_DPATH "' kernel log device: "
		          "failed to setup device node: "
		          "%s (%d).",
		          strerror(-err),
		          -err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

#endif /* defined(CONFIG_ELOGD_KERN) */

static __elogd_nonull(1, 2, 3, 5)
int
elogd_setup_dir(const char * __restrict path,
                const char * __restrict user,
                const char * __restrict group,
                mode_t                  mode,
                const char * __restrict name)
{
	elogd_assert(upath_validate_path_name(path) > 0);
	elogd_assert(upwd_validate_user_name(user) > 0);
	elogd_assert(upwd_validate_group_name(group) > 0);
	elogd_assert(!(mode & ~((mode_t)ACCESSPERMS)));
	elogd_assert(name[0]);

	uid_t uid;
	gid_t gid;
	int   err;

	err = upwd_get_uid_byname(user, &uid);
	if (err) {
		elogd_err("'%s' %s directory: unknown '%s' user name.",
		          path,
		          name,
		          user);
		return EXIT_FAILURE;
	}

	err = upwd_get_gid_byname(group, &gid);
	if (err) {
		elogd_err("'%s' %s directory: unknown '%s' group name.",
		          path,
		          name,
		          group);
		return EXIT_FAILURE;
	}

	err = enbox_make_dir(path, uid, gid, mode);
	if (err) {
		elogd_err("'%s' %s directory: failed to setup: %s (%d).",
		          path,
		          name,
		          strerror(-err),
		          -err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/*
 * Setup eLogd runstatedir directory.
 *
 * This directory holds non-persistant (across reboots) / volatile daemon state
 * data files. These are by default:
 * - `stat', the kernel log ring-buffer state tracking file ;
 * - `sock', the UNIX named socket file allowing members of the
 *   CONFIG_ELOGD_RUNSTATEDIR_GROUP group to post log messages ala syslog(3).
 */
static
int
elogd_setup_rundir(void)
{
	elogd_setup_assert_conf(&elogd_setup_the_conf);

	return elogd_setup_dir(elogd_setup_the_conf.rundir_path,
	                       elogd_setup_the_conf.user,         /* elogd */
	                       elogd_setup_the_conf.rundir_group, /* logpost */
	                       S_IRWXU | S_IXGRP,                 /* 0710 */
	                       "run state");
}

static
int
elogd_setup_devlog(void)
{
	elogd_setup_assert_conf(&elogd_setup_the_conf);

	char * target;
	int    err;

	err = (int)elogd_make_path(&target,
	                           elogd_setup_the_conf.rundir_path,
	                           elogd_setup_the_conf.rundir_len,
	                           "sock",
	                           sizeof("sock") - 1);
	if (err < 0)
		goto err;

	err = enbox_make_slink("/dev/log", target, 0, 0);
	if (err)
		goto free;

	free(target);

	return EXIT_SUCCESS;

free:
#if defined(CONFIG_ELOGD_DEBUG)
	free(target);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
err:
	elogd_err("`/dev/log' symlink: failed to setup: %s (%d).",
	          strerror(-err),
	          -err);

	return EXIT_FAILURE;
}

static
int
elogd_setup_storedir(void)
{
	elogd_setup_assert_conf(&elogd_setup_the_conf);

	return elogd_setup_dir(elogd_setup_the_conf.store_path,
	                       elogd_setup_the_conf.user,        /* elogd */
	                       elogd_setup_the_conf.store_group, /* elogd */
	                       S_IRWXU | S_IRGRP | S_IXGRP,      /* 0750 */
	                       "store");
}

#if defined(CONFIG_ELOGD_KERN)

#define ELOGD_SETUP_KERN_USAGE \
"    --kern-group=GROUP   -- set kernel log device node file group membership\n" \
"                            to GROUP\n" \
"                            (defaults to `" CONFIG_ELOGD_KERN_GROUP "')\n"

#else  /* !defined(CONFIG_ELOGD_KERN) */

#define ELOGD_SETUP_KERN_USAGE

#endif /* defined(CONFIG_ELOGD_KERN) */

#define USAGE \
"Usage: %1$s [OPTIONS]\n" \
"Setup eLogd daemon runtime environment.\n" \
"\n" \
"With OPTIONS:\n" \
"    --user=USER          -- setup filesystem for running eLogd daemon as USER\n" \
"                            user\n" \
"                            (defaults to `" CONFIG_ELOGD_USER "')\n" \
"    --no-kern            -- do not setup kernel log\n" \
"    --rundir-path=PATH   -- use PATH as pathname to directory where volatile\n" \
"                            internal state data are stored\n" \
"                            (defaults to `" ELOGD_RUNSTATEDIR_DPATH "')\n" \
"    --rundir-group=GROUP -- set volatile internal state data directory group\n" \
"                            membership to GROUP\n" \
"                            (defaults to `" CONFIG_ELOGD_RUNSTATEDIR_GROUP "')\n" \
"    --no-devlog          -- do not setup the `/dev/log' symlink\n" \
"    --no-store           -- do not setup log store directory\n" \
"    --store-path=PATH    -- use PATH as pathname to log store directory\n" \
"                            (defaults to `" CONFIG_ELOGD_STORE_DPATH "')\n" \
"    --store-group=GROUP  -- set log store directory group membership to GROUP\n" \
"                            (defaults to `" CONFIG_ELOGD_STORE_GROUP "')\n" \
"    --verbose=SEVERITY   -- set console log verbosity level to SEVERITY\n" \
"                            (defaults to " STROLL_STRING(CONFIG_ELOGD_STDLOG_SEVERITY) ")\n" \
"    -h|--help            -- this help message\n" \
"\n" \
ELOGD_USAGE_LEVEL

static void
elogd_setup_show_usage(void)
{
	fprintf(stderr, USAGE "\n", program_invocation_short_name);
}

enum {
	USER_OPT           = 1U << 0,
	NO_KERN_OPT        = 1U << 1,
#if defined(CONFIG_ELOGD_KERN)
	KERN_GROUP_OPT     = 1U << 2,
#endif /* defined(CONFIG_ELOGD_KERN) */
	RUNDIR_PATH_OPT    = 1U << 3,
	RUNDIR_GROUP_OPT   = 1U << 4,
	NO_DEVLOG_OPT      = 1U << 5,
	NO_STORE_OPT       = 1U << 6,
	STORE_PATH_OPT     = 1U << 7,
	STORE_GROUP_OPT    = 1U << 8,
	VERBOSE_OPT        = 1U << 9,
	HELP_OPT           = 'h',
	MISSING_OPT        = ':',
	UNKNOWN_OPT        = '?'
};

static  __elogd_nonull(2)
int
elogd_setup_parse_cmdln(int argc, char * const argv[])
{
	elogd_assert(argc);
	elogd_assert(argv);

	struct elog_parse parse;
	unsigned int      optmsk = STROLL_BMAP_INIT_CLEAR;
	int               ret = EXIT_FAILURE;

	elogd_parse_init(&parse, &elogd_setup_the_conf.stdlog);

	while (true) {
		int                        opt;
		static const struct option opts[] = {
			{ "no-kern",        no_argument,       NULL, NO_KERN_OPT},
#if defined(CONFIG_ELOGD_KERN)
			{ "kern-group",     required_argument, NULL, KERN_GROUP_OPT },
#endif /* defined(CONFIG_ELOGD_KERN) */
			{ "user",           required_argument, NULL, USER_OPT },
			{ "rundir-path",    required_argument, NULL, RUNDIR_PATH_OPT },
			{ "rundir-group",   required_argument, NULL, RUNDIR_GROUP_OPT },
			{ "no-devlog",      no_argument,       NULL, NO_DEVLOG_OPT },
			{ "no-store",       no_argument,       NULL, NO_STORE_OPT },
			{ "store-path",     required_argument, NULL, STORE_PATH_OPT },
			{ "store-group",    required_argument, NULL, STORE_GROUP_OPT },
			{ "verbose",        required_argument, NULL, VERBOSE_OPT },
			{ "help",           no_argument,       NULL, HELP_OPT },
			{ NULL,             0,                 NULL, -1 }
		};

		opt = getopt_long(argc, argv, ":h", opts, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case USER_OPT:
			if (elogd_parse_user_name(optarg,
			                          &elogd_setup_the_conf.user))
				goto out;
			break;

		case NO_KERN_OPT:
			elogd_setup_the_conf.kern_on = false;
			break;

#if defined(CONFIG_ELOGD_KERN)
		case KERN_GROUP_OPT:
			if (elogd_parse_group_name(
				optarg,
				"kernel log device file",
				&elogd_setup_the_conf.kern_group))
				goto out;
			break;
#endif /* defined(CONFIG_ELOGD_KERN) */

		case RUNDIR_PATH_OPT:
			if (elogd_parse_rundir_path(
				optarg,
				&elogd_setup_the_conf.rundir_path,
				&elogd_setup_the_conf.rundir_len))
				goto out;
			break;

		case RUNDIR_GROUP_OPT:
			if (elogd_parse_group_name(
				optarg,
				"rundir directory",
				&elogd_setup_the_conf.rundir_group))
				goto out;
			break;

		case NO_DEVLOG_OPT:
			elogd_setup_the_conf.devlog_on = false;
			break;

		case NO_STORE_OPT:
			elogd_setup_the_conf.store_on = false;
			break;

		case STORE_PATH_OPT:
			if (elogd_parse_path(
				optarg,
				"store directory",
				&elogd_setup_the_conf.store_path) < 0)
				goto out;
			break;

		case STORE_GROUP_OPT:
			if (elogd_parse_group_name(
				optarg,
				"store directory",
				&elogd_setup_the_conf.store_group))
				goto out;
			break;

		case VERBOSE_OPT:
			if (elogd_parse_stdlog(optarg,
			                       &parse,
			                       &elogd_setup_the_conf.stdlog))
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

#if defined(CONFIG_ELOGD_KERN)
	if (stroll_bmap_test_mask(optmsk, NO_KERN_OPT) &&
	    stroll_bmap_test_mask(optmsk, KERN_GROUP_OPT))
		elogd_early_log(
			"kernel log setup disabled, "
			"ignoring --kern-from-user / --kern-group options...");
#endif /* defined(CONFIG_ELOGD_KERN) */

	if (stroll_bmap_test_mask(optmsk, NO_STORE_OPT) &&
	    stroll_bmap_test_mask(optmsk, STORE_PATH_OPT | STORE_GROUP_OPT))
		elogd_early_log(
			"log store directory setup disabled, "
			"ignoring --store-path / --store-group options...");

	elogd_parse_fini(&parse);

	if (elogd_setup_the_conf.stdlog.super.severity >= 0) {
		struct elog * stdlog;

		stdlog = (struct elog *)
		         elog_create_stdio(&elogd_setup_the_conf.stdlog);
		if (!stdlog)
			return EXIT_FAILURE;

		elog_setup(ELOG_DFLT_TAG, elogd_pid);
		elogd_logger = stdlog;
	}

	return EXIT_SUCCESS;

usage:
	elogd_setup_show_usage();
out:
	elogd_parse_fini(&parse);

	return ret;
}

static char * elogd_setup_lock_path;

static
int
elogd_setup_lock(void)
{
	elogd_setup_assert_conf(&elogd_setup_the_conf);

	if (elogd_make_lock_path(&elogd_setup_lock_path,
	                         elogd_setup_the_conf.rundir_path,
	                         elogd_setup_the_conf.rundir_len))
		return EXIT_FAILURE;

	if (elogd_lock(elogd_setup_lock_path))
		goto free;

	return EXIT_SUCCESS;

free:
#if defined(CONFIG_ELOGD_DEBUG)
	free(elogd_setup_lock_path);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	return EXIT_FAILURE;
}

static
int
elogd_setup_unlock(void)
{
	elogd_setup_assert_conf(&elogd_setup_the_conf);
	elogd_assert(elogd_setup_lock_path);

	int ret;

	ret = ufile_unlink(elogd_setup_lock_path);
	if (ret)
		elogd_warn("cannot remove lock file: '%s': %s (%d).",
		           elogd_setup_lock_path,
		           strerror(-ret),
		           -ret);

	elogd_unlock();

#if defined(CONFIG_ELOGD_DEBUG)
	free(elogd_setup_lock_path);
#endif /* defined(CONFIG_ELOGD_DEBUG) */

	return ret;
}

int
main(int argc, char * const argv[])
{
	elogd_assert(argc);
	elogd_assert(argv);

	int ret = EXIT_FAILURE;

	if (elogd_setup_parse_cmdln(argc, argv))
		return ret;

	umask(07077);
	enbox_setup((struct elog *)elogd_logger);

	if (elogd_setup_lock())
		goto out;

	if (elogd_setup_the_conf.kern_on) {
		if (elogd_setup_kern_log())
			goto unlock;

		if  (elogd_setup_kern_dev())
			goto unlock;
	}

	if (elogd_setup_rundir())
		goto unlock;

	if (elogd_setup_the_conf.devlog_on)
		if (elogd_setup_devlog())
			goto unlock;

	if (elogd_setup_the_conf.store_on)
		if (elogd_setup_storedir())
			goto unlock;

	if (!elogd_setup_unlock())
		ret = EXIT_SUCCESS;

	elogd_log_fini();

	return ret;

unlock:
	elogd_setup_unlock();
out:
	elogd_log_fini();

	return EXIT_FAILURE;
}
