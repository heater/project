
TARGET = senducitocli 
OBJS += senducitocli.o logopt.o 

CFLAGS += -g -Wall 
LDFLAGS += 

DEFS += -DCLI_USE_UDS

all:${OBJS}
	$(CC) $(LDFLAGS) $(CFLAGS) -o $(TARGET) $(OBJS) $(DEFS)

clean:
	rm -rf ${TARGET} $(OBJS) 

%.o:%.c 
	$(CC) $(CFLAGS) -o $@ -c $< $(DEFS)

