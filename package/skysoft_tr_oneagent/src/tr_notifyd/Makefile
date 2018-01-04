
#include $(TOPDIR)/Profile.mak

TARGET=tr_notifyd

OBJS+=tr_notifyd.o notifyd_base.o logopt.o function.o 

CFLAGS += -Wall -g

LDFLAGS += -luci -lsuci

all:${OBJS}
	$(CC) $(LDFLAGS) $(CFLAGS) -o $(TARGET) $(OBJS)

%.o : %.c 
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o 
	rm -f tr_notifyd
