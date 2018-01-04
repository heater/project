
TARGET = oneagent_mon
OBJS += oneagent_mon.o 

CFLAGS += -g -Wall 
LDFLAGS += -luci -lsuci

all:${OBJS}
	$(CC) $(LDFLAGS) $(CFLAGS) -o $(TARGET) $(OBJS)

clean:
	rm -rf ${TARGET} $(OBJS) 

%.o:%.c 
	$(CC) $(CFLAGS) -o $@ -c $<
