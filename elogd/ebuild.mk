################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of Stroll.
# Copyright (C) 2017-2023 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

common-cflags  := -Wall \
                  -Wextra \
                  -Wformat=2 \
                  -Wconversion \
                  -Wundef \
                  -Wshadow \
                  -Wcast-qual \
                  -Wcast-align \
                  -Wmissing-declarations \
                  -D_GNU_SOURCE \
                  $(EXTRA_CFLAGS)

common-ldflags := $(common-cflags) $(EXTRA_LDFLAGS) \
                  -Wl,-z,start-stop-visibility=hidden

ifneq ($(filter y,$(CONFIG_ELOGD_ASSERT)),)
common-cflags  := $(filter-out -DNDEBUG,$(common-cflags))
common-ldflags := $(filter-out -DNDEBUG,$(common-ldflags))
endif # ($(filter y,$(CONFIG_ELOGD_ASSERT)),)

bins           := elogd
elogd-objs     := main.o pipe.o store.o sock.o kern.o log.o intern.o sigchan.o \
                  common.o
elogd-objs     += $(call kconf_enabled,ELOGD_MQUEUE,mqueue.o)
elogd-cflags   := $(common-cflags) -idirafter $(SRCDIR)
elogd-ldflags  := $(EXTRA_LDFLAGS)
elogd-pkgconf  := libelog libenbox libutils libstroll
elogd-path     := $(SBINDIR)/elogd

# ex: filetype=make :
