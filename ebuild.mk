################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of eLogd.
# Copyright (C) 2022-2024 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

config-in     := Config.in
config-h      := $(PACKAGE)/config.h

common-cflags := -Wall -Wextra -Wformat=2 $(EXTRA_CFLAGS)

bins          := elogd
elogd-objs    := elogd.o
elogd-cflags  := -Wall -Wextra -Wformat=2 $(EXTRA_CFLAGS)
elogd-ldflags := $(EXTRA_LDFLAGS)
elogd-pkgconf := libelog libenbox libutils
elogd-path    := $(SBINDIR)/elogd

################################################################################
# Source code tags generation
################################################################################

tagfiles := $(shell find $(CURDIR) -type f)
