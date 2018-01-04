TARGET=runCommand

CFLAGS+=-g -Wall

DIRS=$(shell pwd)

SRCS=$(foreach DIR, $(DIRS), $(wildcard $(DIR)/*.c))
OBJS=$(patsubst %.c, %.o, $(SRCS))

CFLAGS+=-DUSE_SIM 
CFLAGS+=-isystem $(MODEL_APP_DIR)/libstatus/include -isystem $(APPSDIR)/libstatus/include
LDFLAGS+= -luci -lsuci

all: ${OBJS}
	$(CC) $(LDFLAGS) $(CFLAGS) -o $(TARGET) $(OBJS) 
	
clean: 
	rm -rf ${TARGET} $(OBJS) *.bak

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

