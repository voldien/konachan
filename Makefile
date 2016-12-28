#!/bin/bash

RM := rm -f
CP := cp
ZIP := gzip
INSTALL := install -s
CC ?= gcc
CFLAGS := -O2
CLIBS := -lssl -ljson-c
SRC = $(wildcard *.c)
OBJS = $(notdir $(subst .c,.o,$(SRC)))
TARGET ?= konachan


vpath %.c .
vpath %.o .
VPATH := .



all : $(TARGET)
	@echo "Making $(TARGET) \n"

$(TARGET) : $(OBJS)
	$(CC) $(CLFAGS) $^ -o $@ $(CLIBS)

%.o : %.c
	$(CC) $(CFLAGS) -c $^ -o $@


install : $(TARGET)
	@echo "Instaling konachan.\n"
	$(INSTALL) $^ /usr/local/bin/
	$(ZIP) -ck konachan.1 > /usr/local/share/man/man1/konachan.1.gz


clean :
	$(RM) *.o
