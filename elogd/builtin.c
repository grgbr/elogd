#include "builtin.h"

pid_t         elogd_pid;
struct elog * elogd_logger;

void
elogd_log_init(struct elog * __restrict logger)
{
	elogd_assert(logger);
	elogd_assert(elogd_pid > 0);

	elog_setup(ELOG_DFLT_TAG, elogd_pid);

	elogd_logger = logger;
}

void
elogd_log_fini(void)
{
	elogd_assert(elogd_pid > 0);

#if !defined(CONFIG_ELOGD_DEBUG)
	if (elogd_logger)
		elog_fini(elogd_logger);
#endif /* !defined(CONFIG_ELOGD_DEBUG) */
}

int
elogd_parse_stdlog(const char * __restrict             arg,
                   struct elog_parse * __restrict      parse,
                   struct elog_stdio_conf * __restrict config)
{
	elogd_assert(arg);
	elogd_assert(parse);
	elogd_assert(config);

	if (elog_parse_stdio_severity(parse, config, arg)) {
		elogd_early_err("%s.", parse->error);
		return EXIT_FAILURE;
	}

#if !defined(CONFIG_ELOGD_DEBUG)
	if (config->super.severity >= ELOG_DEBUG_SEVERITY) {
		elogd_early_err("unexpected stdio log severity.");
		return EXIT_FAILURE;
	}
#endif /* !defined(CONFIG_ELOGD_DEBUG) */

	return EXIT_SUCCESS;
}

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
		elogd_early_err("invalid %s pathname: %s (%d).",
		                kind,
		                strerror((int)-ret),
		                (int)-ret);
		return EXIT_FAILURE;
	}

	*path = arg;

	return EXIT_SUCCESS;
}

int
elogd_parse_group_name(const char * __restrict  arg,
                       const char * __restrict  kind,
                       const char ** __restrict name)
{
	elogd_assert(arg);
	elogd_assert(kind);
	elogd_assert(name);

	ssize_t ret;

	ret = upwd_validate_group_name(arg);
	if (ret < 0) {
		elogd_early_err("invalid %s group name: %s (%d).",
		                kind,
		                strerror((int)-ret),
		                (int)-ret);
		return EXIT_FAILURE;
	}

	*name = arg;

	return EXIT_SUCCESS;
}

void
elogd_parse_init(struct elog_parse * __restrict      parse,
                 struct elog_stdio_conf * __restrict config)
{
	elogd_assert(parse);
	elogd_assert(config);

	static const struct elog_stdio_conf dflt = {
		.super.severity = CONFIG_ELOGD_STDLOG_SEVERITY,
		.format         = ELOG_TAG_FMT
	};

	elogd_pid = getpid();

	elog_init_stdio_parse(parse, config, &dflt);
}
