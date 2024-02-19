override PACKAGE := elogd
override VERSION := 1.0
EXTRA_CFLAGS     := -O2 -DNDEBUG
EXTRA_LDFLAGS    := $(EXTRA_CFLAGS)

export VERSION EXTRA_CFLAGS EXTRA_LDFLAGS

ifeq ($(strip $(EBUILDDIR)),)
ifneq ($(realpath ebuild/main.mk),)
EBUILDDIR := $(realpath ebuild)
else  # ($(realpath ebuild/main.mk),)
EBUILDDIR := $(realpath /usr/share/ebuild)
endif # !($(realpath ebuild/main.mk),)
endif # ($(strip $(EBUILDDIR)),)

ifeq ($(realpath $(EBUILDDIR)/main.mk),)
$(error '$(EBUILDDIR)': no valid eBuild install found !)
endif # ($(realpath $(EBUILDDIR)/main.mk),)

include $(EBUILDDIR)/main.mk
