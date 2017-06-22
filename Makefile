#!/bin/bash
#
RM := rm -f
CP := cp
MKDIR := mkdir -p
#
DESTDIR ?=
PREFIX ?= /usr
INSTALL_LOCATION=$(DESTDIR)$(PREFIX)
#
CC ?= gcc
CFLAGS := -O2
CLIBS := -lssl -ljson-c -lz
#
SRC = $(wildcard *.c)
OBJS = $(notdir $(subst .c,.o,$(SRC)))
TARGET ?= konachan
VERSION := 1.0.5


all : $(TARGET)
	@echo "Finished making $(TARGET) \n"

$(TARGET) : CFLAGS += -DNDEBUG
$(TARGET) : $(OBJS)
	$(CC) $(CLFAGS) $^ -o $@ $(CLIBS)

%.o : %.c
	$(CC) $(CFLAGS) -c $^ -o $@


install : $(TARGET)
	@echo "Installing konachan.\n"
	$(MKDIR) $(INSTALL_LOCATION)/bin
	$(CP) $(TARGET) $(INSTALL_LOCATION)/bin
	$(CP) konachan.bc /etc/bash_completion.d/konachan


distribution : $(TARGET)
	$(RM) -r $(TARGET)-$(VERSION)
	$(MKDIR) $(TARGET)-$(VERSION)
	$(CP) *.c Makefile README.md *.1 konachan.bc $(TARGET)-$(VERSION)
	tar cf - $(TARGET)-$(VERSION) | gzip -c > $(TARGET)-$(VERSION).tar.gz
	$(RM) -r $(TARGET)-$(VERSION)

clean :
	$(RM) *.o

.PHONY : all install distribution clean
