CC=gcc
WFLAGS=-Wall
CFLAGS=-O2
INCLUDES=-Iinclude

LIBNAME=libsuci.so

all: $(LIBNAME)

%.o: %.c
	$(CC) $(WFLAGS) -c -o $@ $(INCLUDES) $(CFLAGS) $<

LIBSUCI_OBJ=suci.o

$(LIBNAME): $(LIBSUCI_OBJ)
	$(CC) $(CFLAGS) -shared -o $@ $^
