################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of eLogd.
# Copyright (C) 2022-2024 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

config-in := Config.in
config-h  := $(PACKAGE)/config.h

subdirs   := elogd

################################################################################
# Source code tags generation
################################################################################

tagfiles  := $(shell find $(addprefix $(CURDIR)/,$(subdirs)) \
                          $(HEADERDIR) \
                          -type f)
