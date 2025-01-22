################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Stroll.
# Copyright (C) 2017-2023 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

common-cflags       := -Wall \
                       -Wextra \
                       -Wformat=2 \
                       -Wconversion \
                       -Wundef \
                       -Wshadow \
                       -Wcast-qual \
                       -Wcast-align \
                       -Wmissing-declarations \
                       -D_GNU_SOURCE \
                       $(EXTRA_CFLAGS) \
                       -idirafter $(SRCDIR)

common-ldflags      := $(common-cflags) $(EXTRA_LDFLAGS) \
                       -Wl,--as-needed \
                       -Wl,-z,start-stop-visibility=hidden

ifneq ($(filter y,$(CONFIG_ELOGD_ASSERT)),)
common-cflags       := $(filter-out -DNDEBUG,$(common-cflags))
common-ldflags      := $(filter-out -DNDEBUG,$(common-ldflags))
endif # ($(filter y,$(CONFIG_ELOGD_ASSERT)),)

builtins            := builtin.a
builtin.a-objs      := builtin.o
builtin.a-cflags    := $(common-cflags)

bins                := elogd
elogd-objs          := main.o pipe.o store.o sock.o kern.o log.o intern.o \
                       sigchan.o common.o
elogd-objs          += $(call kconf_enabled,ELOGD_MQUEUE,mqueue.o)
elogd-cflags        := $(common-cflags)
elogd-ldflags       := $(common-ldflags) -l:builtin.a
elogd-pkgconf       := libelog libenbox libutils libstroll
elogd-path          := $(SBINDIR)/elogd

bins                += elogd-setup
elogd-setup-objs    := setup.o
elogd-setup-cflags  := $(common-cflags)
elogd-setup-ldflags := $(common-ldflags) -l:builtin.a
elogd-setup-pkgconf := libelog libenbox libutils libstroll
elogd-setup-path    := $(SBINDIR)/elogd-setup

# ex: filetype=make :
