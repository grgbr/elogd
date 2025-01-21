/*
/proc/sys/kernel/dmesg_restrict -- 
/dev/kmsg mknod user group mode

/run/elogd user group mode
/dev/log symlink

/run/elog user group mode
TODO: create /dev/log link
      implement elogd fallback timeout in case of store write error -ENOSPC....
*/

#include <utils/path.h>
#include <enbox/enbox.h>

/*
 * Disable writing log messages from userspace.
 *
 * See <linux>/Documentation/admin-guide/sysctl/kernel.rst
 */
static
int
elogd_setup_kern_rdonly(void)
{
	int     fd;
	ssize_t ret;

#define ELOGD_KERN_CTRL_PATH \
	"/proc/sys/kernel/printk_devkmsg"
#define ELOGD_KERN_CTRL_FLAGS \
	(O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOATIME | O_NOFOLLOW)
	fd = ufile_open(ELOGD_KERN_CTRL_PATH, ELOGD_KERN_CTRL_FLAGS);
	if (fd < 0)
		return fd;

	ret = ufile_nointr_full_write(fd, "off", sizeof("off") - 1);
	if (ret != (sizeof("off") - 1)) {
		elogd_assert(ret < 0);
		goto close;
	}

	ret = 0;

close:
	ufile_close(fd);

	return ret;
}

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
static __elogd_nonull(1, 2)
int
elogd_setup_kern_dev(const char * __restrict path,
                     const char * __restrict group,
                     bool                    rdonly)
{
	elogd_assert(upath_validate_path_name(path) > 0);
	elogd_assert(upwd_validate_group_name(group) > 0);

	git_t  gid;
	int    err;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

	err = upwd_get_gid_byname(group, &gid);
	if (err) {
		elogd_err("'%s' kernel ring-buffer: "
		          "unknown '%s' group name.",
		          path,
		          group);
		return EXIT_FAILURE;
	}

	if (rdonly) {
		err = elogd_setup_kern_rdonly();
		if (err) {
			elogd_err("'%s' kernel ring-buffer: "
			          "failed to disable logging from userspace: "
			          "%s (%d).",
			          path,
			          strerror(-err),
			          -err);
			return EXIT_FAILURE;
		}

		mode &= ~((mode_t)(S_IWGRP));
	}

	err = enbox_make_chrdev(path,
	                        0,                 /* root */
	                        gid,               /* klog */
	                        mode,              /* 0660 or 0640 */
#define ELOGD_KMSG_MAJOR (1)
	                        ELOGD_KMSG_MAJOR,
#define ELOGD_KMSG_MINOR (11)
	                        ELOGD_KMSG_MINOR)
	if (err) {
		elogd_err("'%s' kernel ring-buffer: "
		          "failed to setup device node: "
		          "%s (%d).",
		          path,
		          strerror(-err),
		          -err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static __elogd_nonull(1, 2, 3, 4)
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
 * - CONFIG_ELOGD_KERN_SPATH, the kernel log ring-buffer state tracking file ;
 * - CONFIG_ELOGD_SOCK_PATH, the UNIX named socket file allowing members of the
 *   CONFIG_ELOGD_SOCK_GROUP group to post log messages ala syslog(3).
 */
static __elogd_nonull(1, 2, 3)
int
elogd_setup_rundir(const char * __restrict path,
                   const char * __restrict user,
                   const char * __restrict group)
{
	elogd_assert(upath_validate_path_name(path) > 0);
	elogd_assert(upwd_validate_user_name(user) > 0);
	elogd_assert(upwd_validate_group_name(group) > 0);

	return elogd_setup_dir(path,
	                       user,              /* elogd */
	                       group,             /* logpost */
	                       S_IRWXU | S_IXGRP, /* 0710 */
	                       "run state");
}


static __elogd_nonull(1, 2, 3)
int
elogd_setup_storedir(const char * __restrict path,
                     const char * __restrict user,
                     const char * __restrict group)
{
	elogd_assert(upath_validate_path_name(path) > 0);
	elogd_assert(upwd_validate_user_name(user) > 0);
	elogd_assert(upwd_validate_group_name(group) > 0);
	elogd_assert(!(mode & ~ELOGD_RUNDIR_VALID_MODE));

	return elogd_setup_dir(path,
	                       user,                        /* elogd */
	                       group,                       /* logview */
	                       S_IRWXU | S_IRGRP | S_IXGRP, /* 0750 */
	                       "store");
}









































struct elogd_setup_conf {
	bool                   kern_from_user;
	bool                   kern_on;
	const char *           kern_group;
	const char *           rundir_path;
	const char *           rundir_group;
	bool                   devlog_on;
	bool                   store_on;
	const char *           store_path;
	const char *           store_group;
	struct elog_stdio_conf stdlog;
};

static struct elogd_setup_conf elogd_setup_the_conf = {
	.kern_from_user = false,
	.kern_on        = true,
	.kern_group     = CONFIG_ELOGD_KERN_GROUP,
	.rundir_path    = CONFIG_ELOGD_RUNDIR_PATH,
	.rundir_group   = CONFIG_ELOGD_SOCK_GROUP,
	.devlog_on      = true,
	.store_on       = true,
	.store_path     = CONFIG_ELOGD_STORE_DPATH,
	.store_group    = CONFIG_ELOGD_STORE_GROUP,
	.stdlog         = elogd_setup_stdio_dflt
};

static
int
elogd_setup_enable_log(void)
{
	if (elogd_setup_the_conf.stdlog.super.severity >= 0) {
		struct elog * stdlog;

		stdlog = elog_create_stdio(&elogd_setup_the_conf.stdlog);
		if (!stdlog)
			return -ENOMEM;

		elogd_log_init(stdlog);
	}

	return 0;
}

static  __elogd_nonull(2)
int
elogd_setup_parse_cmdln(int argc, char * const argv[])
{
	setup_assert(argc);
	setup_assert(argv);

	struct elog_parse parse;
	unsigned int      optmsk = 0;
	int               ret = EXIT_FAILURE;

	elogd_parse_init(&parse, &elogd_setup_the_conf.stdlog);

	while (true) {
		int                        opt;
		static const struct option opts[] = {
#define KERN_FROM_USER_OPT (0)
			{ "kern-from-user", no_argument,       NULL, KERN_FROM_USER_OPT},
#define NO_KERN_OPT        (1)
			{ "no-kern",        no_argument,       NULL, NO_KERN_OPT},
#define KERN_GROUP_OPT     (2)
			{ "kern-group",     required_argument, NULL, KERN_GROUP_OPT },
#define RUNDIR_PATH_OPT    (3)
			{ "rundir-path",    required_argument, NULL, RUNDIR_PATH_OPT },
#define RUNDIR_GROUP_OPT   (4)
			{ "rundir-group",   required_argument, NULL, RUNDIR_GROUP_OPT },
#define NO_DEVLOG_OPT      (5)
			{ "no-devlog",      no_argument,       NULL, NO_DEVLOG_OPT },
#define NO_STORE_OPT       (6)
			{ "no-store",       no_argument,       NULL, NO_STORE_OPT },
#define STORE_PATH_OPT     (7)
			{ "store-path",     required_argument, NULL, STORE_PATH_OPT },
#define STORE_GROUP_OPT    (8)
			{ "store-group",    required_argument, NULL, STORE_GROUP_OPT },
#define VERBOSE_OPT        (9)
			{ "verbose",        required_argument, NULL, VERBOSE_OPT },
#define QUIET_OPT          (10)
			{ "quiet",          no_argument,       NULL, QUIET_OPT },
#define HELP_OPT           ('h')
			{ "help",           no_argument,       NULL, HELP_OPT },

			{ NULL,             0,                 NULL, -1 }
		};

		opt = getopt_long(argc, argv, ":h", opts, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case KERN_FROM_USER_OPT:
			elogd_setup_the_conf.kern_from_user = true;
			break;

		case NO_KERN_OPT:
			elogd_setup_the_conf.kern_on = false;
			break;

		case KERN_GROUP_OPT:
			if (elogd_parse_group_name(
				optarg,
				"kernel log device file",
				&elogd_setup_the_conf.kern_group))
				goto out;
			break;

		case RUNDIR_PATH_OPT:
			if (elogd_parse_path(optarg,
			                     "rundir directory",
			                     &elogd_setup_the_conf.rundir_path))
				goto out;
			break;

		case RUNDIR_GROUP_OPT:
			if (elogd_parse_group_name(
				optarg,
				"rundir directory",
				&elogd_setup_the_conf.rundir_group))
				goto out;

		case NO_DEVLOG_OPT:
			elogd_setup_the_conf.devlog = false;
			break;

		case NO_STORE_OPT:
			elogd_setup_the_conf.store_on = false;
			break;

		case STORE_PATH_OPT:
			if (elogd_parse_path(
				optarg,
				"store directory",
				&elogd_setup_the_conf.store_path))
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
			break

		case QUIET_OPT:
			elogd_parse_quiet(&elogd_setup_the_conf.stdlog);
			break;

		case HELP_OPT:
			ret = EX_USAGE;
			goto usage;

		case ':':
			elogd_early_err("option '%s' requires an argument.\n",
			                argv[optind - 1]);
			goto usage;

		case '?':
			elogd_early_err("unrecognized option '%s'.\n",
			                argv[optind - 1]);
			goto usage;

		default:
			elogd_early_err("unexpected option parsing error.\n");
			goto usage;
		}

		optmsk |= (1U << opt);
	}

	if (argc - optind) {
		elogd_early_err("invalid number of arguments.\n");
		goto usage;
	}

	if (optmsk & (1U << NO_KERN_OPT)) {
		if (optmsk & (1U << KERN_GROUP_OPT))
			elogd_early_warn(
				"kernel log device file setup disabled: "
				"ignoring --kern-group option...");
	}

	if (optmsk & (1U << NO_STORE_OPT)) {
		if (optmsk & ((1U << STORE_PATH_OPT) | (1U << STORE_GROUP_OPT)))
			elogd_early_warn(
				"output logging directory setup disabled: "
				"ignoring --store-path / --store-group options...");
	}

	if (optmsk & (1U << QUIET_OPT)) {
		if (optmsk & (1U << VERBOSE_OPT))
			elogd_early_warn(
				"quiet operation requested: "
				"ignoring --verbose option...");
	}

	elogd_parse_fini(&parse);

	return EXIT_SUCCESS;

usage:
	show_usage();
out:
	elogd_parse_fini(&parse);

	return ret;
}


#define USAGE \
"Usage: %1$s [OPTIONS]\n" \
"Setup eLogd daemon runtime environment.\n" \
"\n" \
"With OPTIONS:\n" \
"    --kern-from-user     -- enable logging to kernel from userspace\n" \
"    --no-kern            -- do not setup kernel log device file\n" \
"    --kern-group=GROUP   -- set kernel log device node file group membership\n" \
"                            to GROUP\n" \
"                            (defaults to `" CONFIG_ELOGD_KERN_GROUP "')\n" \
"    --rundir-path=PATH   -- use PATH as pathname to directory where volatile\n" \
"                            internal state data are stored\n"
"                            (defaults to `" CONFIG_ELOGD_RUNSTATEDIR "')\n" \
"    --rundir-group=GROUP -- set volatile internal state data directory group\n" \
"                            membership to GROUP\n" \
"                            (defaults to `" CONFIG_ELOGD_SOCK_GROUP "')\n" \
"    --no-devlog          -- do not setup the `/dev/log' symlink\n" \
"    --no-store           -- do not setup output logging directory\n" \
"    --store-path=PATH    -- use PATH as pathname to output logging directory\n" \
"                            (defaults to `" CONFIG_ELOGD_STORE_DPATH "')\n" \
"    --store-group=GROUP  -- set output logging directory group membership to\n"
"                            GROUP\n" \
"                            (defaults to `" CONFIG_ELOGD_STORE_GROUP "')\n" \
"    --verbose=SEVERITY   -- set `%1$s' console / stdio logging verbosity level\n" \
"                            to SEVERITY\n" \
"                            (defaults to " STROLL_STRING(CONFIG_ELOGD_STDLOG_SEVERITY) ")\n" \
"    --quiet              -- disable `%1$s' logging to console / stdio entirely\n" \
"    -h|--help            -- this help message\n" \
"\n" \
"Where:\n" \
"    SEVERITY := dflt|emerg|alert|crit|err|warn|notice|info" USAGE_DEBUG_LEVEL "\n"

static void
show_usage(void)
{
	fprintf(stderr, USAGE, program_invocation_short_name);
}

int
main(int argc, char * const argv[])
{
	elogd_assert(argc);
	elogd_assert(argv);

	int ret = EXIT_FAILURE;

	ret = elogd_setup_parse_cmdln(argc, argv);
	if (ret)
		return EXIT_FAILURE;

	if (!elogd_setup_the_conf.quiet)
		elog_init_stdio(&setup_logger, &elogd_setup_the_conf.stdlog);

	if (setup_kern_from_user())
		goto out;

	if (elogd_setup_the_conf.kern_on)
		if  (setup_kern_dev())
			goto out;

	if (setup_rundir())
		goto out;

	if (elogd_setup_the_conf.devlog_on)
		if (setup_devlog())
			goto out;

	if (elogd_setup_the_conf.store_on)
		if (setup_store())
			goto out;

	ret = EXIT_SUCCESS;

out:
	if (!elogd_setup_the_conf.quiet)
		elog_fini((struct elog *)&setup_logger);

	return ret;
}




