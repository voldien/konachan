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
VERSION := 1.0.4


all : $(TARGET)
	@echo "Finished making $(TARGET) \n"

$(TARGET) : $(OBJS)
	$(CC) $(CLFAGS) $^ -o $@ $(CLIBS)

%.o : %.c
	$(CC) $(CFLAGS) -c $^ -o $@


install : $(TARGET)
	@echo "Installing konachan.\n"
	$(MKDIR) $(INSTALL_LOCATION)/bin
	$(CP) $(TARGET) $(INSTALL_LOCATION)/bin


distribution : $(TARGET)
	$(RM) -r konachan-$(VERSION)
	$(MKDIR) konachan-$(VERSION)
	$(CP) *.c Makefile README.md *.1 konachan-$(VERSION)
	tar cf - konachan-$(VERSION) | gzip -c > konachan-$(VERSION).tar.gz
	$(RM) -r konachan-$(VERSION)

clean :
	$(RM) *.o

.PHONY : all install distribution clean
