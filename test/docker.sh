#!/bin/sh -e

prefix="$HOME/devel/tidor/out/root"

log_err()
{
	local msg="$1"

	echo "$0: $msg" >&2
}

log_info()
{
	local msg="$1"

	echo "$msg" >&2
}

image_ready()
{
	if ! docker image ls elogd | grep --quiet '^elogd'; then
		return 1
	fi

	return 0
}

build_image()
{
	docker build \
	       --file $dockerfile \
	       --tag 'elogd' \
	       $(realpath $prefix)
}

do_run()
{
	if ! image_ready; then
		if ! build_image; then
			return 1
		fi
	fi

	if ! docker run \
	            --rm=true \
	            --volume=/opt/htchain:/opt/htchain:ro \
	            --volume=$(realpath $prefix):$(realpath $prefix):ro \
	            --privileged \
	            "$@"; then
		return 1
	fi
}

init_cmds=\
'touch /dev/mqueue/elogd_test &&'\
'chmod 640 /dev/mqueue/elogd_test'

run()
{
	log_info "Running '$(realpath $prefix)/sbin/elogd $*'..."

	if ! do_run "--tty=false" \
	            "--interactive=false" \
	            "elogd" \
	            "/bin/bash" \
	            "-c" \
	            "$init_cmds && exec $(realpath $prefix)/sbin/elogd $*"; then
		return 1
	fi
}

shell()
{
	log_info "Running '/bin/bash'..."

	if ! do_run "--tty=true" \
	            "--interactive=true" \
	            "elogd" \
	            "/bin/bash" \
	            "-c" \
	            "$init_cmds && exec /bin/bash -i"; then
		return 1
	fi
}

usage()
{
	cat >&2 <<_EOF
Usage: $arg0 [OPTIONS] COMMAND
Run eLogd docker test.

Where OPTIONS:
    -h | --help           this help message

Where COMMAND ::= build|run|shell|help

With:
    build -- build docker image
    run   -- run docker test
    shell -- run a shell with docker image
_EOF
}

arg0="$(basename $0)"
dockerfile="$(dirname $(realpath $0))/Dockerfile"

if [ $# -lt 1 ]; then
	log_err 'invalid number of arguments.\n'
	usage
	exit 1
fi

cmd="$1"
if [ "$cmd" = "-h" ] || [ "$cmd" = "--help" ] || [ "$cmd" = "help" ]; then
	usage
	exit 0
elif [ "$cmd" = "build" ]; then
	if [ $# -ne 1 ]; then
		log_err 'invalid build command number of arguments.\n'
		usage
		exit 1
	fi
	build_image
elif [ "$cmd" = "run" ]; then
	shift 1
	run "$@"
elif [ "$cmd" = "shell" ]; then
	if [ $# -ne 1 ]; then
		log_err 'invalid shell command number of arguments.\n'
		usage
		exit 1
	fi
	shell
else
	log_err "invalid '$cmd' command."
	exit 1
fi
