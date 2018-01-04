CFLAGS+=-g -Wall
CFLAGS+=-DUSE_SIM 
CFLAGS+=-isystem $(MODEL_APP_DIR)/libstatus/include -isystem $(APPSDIR)/libstatus/include
LDFLAGS+= -luci -lsuci

DOWNOBJS= downloaddiag.o common.o http.o ftp.o
UPOBJS= uploaddiag.o common.o http.o ftp.o
UDPOBJS= UDPechoClient.o UDPechoServer.o
LIB= common.h http.h ftp.h
DOWNTARGET=downloaddiag
UPTARGET=uploaddiag
UDPTARGET=UDPechoServer

all: ${DOWNTARGET} ${UPTARGET}

${DOWNTARGET}: ${LIB} ${DOWNOBJS}
	${CC} ${CFLAGS} ${DOWNOBJS} ${LDFLAGS} -o ${DOWNTARGET}

${UPTARGET}: ${LIB} ${UPOBJS}
	${CC} ${CFLAGS} ${UPOBJS} ${LDFLAGS} -o ${UPTARGET}

${UDPTARGET}: UDPechoServer.c
	${CC} ${CFLAGS} ${LDFLAGS} UDPechoServer.c -o ${UDPTARGET}

clean:
	rm -rf *.o 
	rm -rf ${DOWNTARGET} ${UPTARGET} ${UDPTARGET}
