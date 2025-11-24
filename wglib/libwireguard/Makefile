CC=gcc
CFLAGS= -Wall -g -O -fPIC
RM= rm -f
.PHONY: all clean

all: wireguard.so wireguard.a
clean:
	$(RM) *.o *.so

wireguard.so: wireguard.o
	$(LINK.c) -shared $^ -o $@

wireguard.a: wireguard.o
	$(AR) rcs $@ $^
