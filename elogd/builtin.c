#include "builtin.h"
#include <utils/path.h>
#include <utils/pwd.h>

pid_t         elogd_pid = -1;
struct elog * elogd_logger;

int
elogd_parse_stdlog(const char * __restrict             arg,
                   struct elog_parse * __restrict      parse,
                   struct elog_stdio_conf * __restrict config)
{
	elogd_assert(elogd_pid > 0);
	elogd_assert(arg);
	elogd_assert(parse);
	elogd_assert(config);

	if (elog_parse_stdio_severity(parse, config, arg)) {
		elogd_early_log("%s.", parse->error);
		return EXIT_FAILURE;
	}

#if !defined(CONFIG_ELOGD_DEBUG)
	if (config->super.severity >= ELOG_DEBUG_SEVERITY) {
		elogd_early_log("unexpected stdio log severity.");
		return EXIT_FAILURE;
	}
#endif /* !defined(CONFIG_ELOGD_DEBUG) */

	return EXIT_SUCCESS;
}

ssize_t
elogd_parse_path(const char * __restrict  arg,
                 const char * __restrict  kind,
                 const char ** __restrict path)
{
	elogd_assert(elogd_pid > 0);
	elogd_assert(arg);
	elogd_assert(kind);
	elogd_assert(path);

	ssize_t ret;

	ret = upath_validate_path_name(arg);
	if (ret < 0) {
		elogd_early_log("invalid %s pathname: %s (%d).",
		                kind,
		                strerror((int)-ret),
		                (int)-ret);
	}
	else
		*path = arg;

	return ret;
}

int
elogd_parse_rundir_path(const char * __restrict  arg,
                        const char ** __restrict path,
                        size_t * __restrict      length)
{
	elogd_assert(arg);
	elogd_assert(path);
	elogd_assert(length);

	ssize_t len;

	len = elogd_parse_path(arg, "rundir directory", path);
	if (len < 0)
		return EXIT_FAILURE;

	elogd_assert(len);

	*length = (size_t)len;

	return EXIT_SUCCESS;
}

int
elogd_parse_user_name(const char * __restrict  arg,
                      const char ** __restrict user)
{
	ssize_t ret;

	ret = upwd_validate_user_name(arg);
	elogd_assert(ret);
	if (ret < 0) {
		elogd_early_log("invalid daemon user name: %s (%d).",
		                strerror((int)-ret),
		                (int)-ret);
		return EXIT_FAILURE;
	}

	*user = arg;

	return EXIT_SUCCESS;
}

int
elogd_parse_group_name(const char * __restrict  arg,
                       const char * __restrict  kind,
                       const char ** __restrict name)
{
	elogd_assert(elogd_pid > 0);
	elogd_assert(arg);
	elogd_assert(kind);
	elogd_assert(name);

	ssize_t ret;

	ret = upwd_validate_group_name(arg);
	if (ret < 0) {
		elogd_early_log("invalid %s group name: %s (%d).",
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

ssize_t
elogd_make_path(char ** __restrict      result,
                const char * __restrict dir_path,
                size_t                  dir_len,
                const char * __restrict file_name,
                size_t                  file_len)
{
	elogd_assert(result);
	elogd_assert((char *)result != dir_path);
	elogd_assert((char *)result != file_name);
	elogd_assert(dir_path != file_name);
	elogd_assert(dir_len > 0);
	elogd_assert(upath_validate_path(dir_path, dir_len + 1) > 0);
	elogd_assert(file_len > 0);
	elogd_assert(upath_is_file_name(file_name, file_len));

	size_t len = dir_len + 1 + file_len;
	char * path;

	if ((len + 1) > PATH_MAX) {
		elogd_err("failed to build pathname: %s (%d).",
		          strerror(ENAMETOOLONG),
		          ENAMETOOLONG);
		return -ENAMETOOLONG;
	}

	path = malloc(len + 1);
	if (!path)
		return -ENOMEM;

	memcpy(path, dir_path, dir_len);
	path[dir_len] = '/';
	memcpy(&path[dir_len + 1], file_name, file_len);
	path[len] = '\0';

	*result = path;

	return (ssize_t)len;
}
