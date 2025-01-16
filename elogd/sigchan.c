/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of eLogd.
 * Copyright (C) 2022-2025 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "common.h"
#include "log.h"
#include "sigchan.h"
#include <utils/signal.h>

#define elogd_sigchan_assert(_chan) \
	elogd_assert(_chan); \
	elogd_assert((_chan)->fd >= 0)

static __elogd_nonull(1, 3)
int
elogd_sigchan_dispatch(struct upoll_worker * work,
                       uint32_t              state __unused,
                       const struct upoll *  poll __unused)
{
	elogd_assert(work);
	elogd_assert(state);
	elogd_assert(!(state & EPOLLOUT));
	elogd_assert(!(state & EPOLLRDHUP));
	elogd_assert(!(state & EPOLLPRI));
	elogd_assert(!(state & EPOLLHUP));
	elogd_assert(!(state & EPOLLERR));
	elogd_assert(state & EPOLLIN);
	elogd_assert(poll);

	const struct elogd_sigchan * chan;
	struct signalfd_siginfo      info;
	int                          ret;

	chan = containerof(work, struct elogd_sigchan, work);
	elogd_sigchan_assert(chan);

	ret = usig_read_fd(chan->fd, &info, 1);
	elogd_assert(ret);
	if (ret < 0)
		return (ret == -EAGAIN) ? 0 : ret;

	switch (info.ssi_signo) {
	case SIGHUP:
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		/* Tell caller we were requested to terminate. */
		return -ESHUTDOWN;

	case SIGUSR1:
	case SIGUSR2:
		/* Silently ignore these... */
		return 0;

	default:
		elogd_assert(0);
	}

	return ret;
}

int
elogd_sigchan_open(struct elogd_sigchan * __restrict chan,
                   const struct upoll * __restrict   poll)
{
	elogd_assert(chan);
	elogd_assert(poll);

	sigset_t     msk = *usig_empty_msk;
	int          err;
	const char * msg;

	elogd_debug("registering signal handlers...");

	usig_addset(&msk, SIGHUP);
	usig_addset(&msk, SIGINT);
	usig_addset(&msk, SIGQUIT);
	usig_addset(&msk, SIGTERM);
	usig_addset(&msk, SIGUSR1);
	usig_addset(&msk, SIGUSR2);

	chan->fd = usig_open_fd(&msk, SFD_NONBLOCK | SFD_CLOEXEC);
	if (chan->fd < 0) {
		err = chan->fd;
		msg = "open failed";
		goto err;
	}

	chan->work.dispatch = elogd_sigchan_dispatch;
	err = upoll_register(poll, chan->fd, EPOLLIN, &chan->work);
	if (err) {
		msg = "cannot register poll worker";
		goto close;
	}

	usig_procmask(SIG_SETMASK, usig_full_msk, NULL);

	elogd_debug("signal handlers registered.");

	return 0;

close:
#if defined(CONFIG_ELOGD_DEBUG)
	usig_close_fd(chan->fd);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
err:
	elogd_err("cannot initialize signaling: %s: %s (%d).",
	          msg,
	          strerror(-err),
	          -err);

	return err;
}

void
elogd_sigchan_close(const struct elogd_sigchan * __restrict chan __unused,
                    const struct upoll * __restrict         poll __unused)
{
	elogd_sigchan_assert(chan);
	elogd_assert(poll);

	elogd_debug("unregistering signal handlers...");

#if defined(CONFIG_ELOGD_DEBUG)
	upoll_unregister(poll, chan->fd);
	usig_close_fd(chan->fd);
#endif /* defined(CONFIG_ELOGD_DEBUG) */
}
