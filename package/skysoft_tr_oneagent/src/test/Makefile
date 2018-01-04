DEFS += -DCLI_USE_UDS

all: udpclient sendtocli notify

udpclient: udpclient.c
	$(CC) -o udpclient udpclient.c
sendtocli: sendtocli.c
	$(CC) -o sendtocli sendtocli.c $(DEFS)
notify: notify.c
	$(CC) -o notify notify.c
	
clean:
	@rm -f udpclient sendtocli notify
