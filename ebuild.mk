config-in                  := Config.in

common-cflags              := -Wall -Wextra -Wformat=2 $(EXTRA_CFLAGS)

bins                       += elogd
elogd-objs                 := elogd.o
elogd-cflags               := -Wall -Wextra -Wformat=2 $(EXTRA_CFLAGS)
elogd-ldflags              := $(EXTRA_LDFLAGS)
elogd-pkgconf              := libelog libenbox libutils
elogd-path                 := $(SBINDIR)/elogd
