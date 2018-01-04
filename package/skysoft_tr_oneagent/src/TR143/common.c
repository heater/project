#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>

#include "common.h"

char *DiagnosticsState[]={
	"None",
	"Requested",
	"Completed",
	"Error_InitConnectionFailed",
	"Error_NoResponse",
	"Error_TransferFailed",
	"Error_PasswordRequestedFailed",
	"Error_LoginFailed",
	"Error_NoTransferMode",
	"Error_NoPASV",
	"Error_IncorrectSize",
	"Error_Timeout",
	"Error_NoCWD",
	"Error_NoSTOR",
	"Error_Internal"	
};

void SendCpeMessage(void)
{
     char CPEMsg[] = "Diagnostics Complete";
     int len;
     int tcpconnfd;
     struct sockaddr_in servaddr;

     memset(&servaddr,0,sizeof(servaddr));
     servaddr.sin_family = AF_INET;
     inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);
     servaddr.sin_port = htons(30006);
     len = sizeof(CPEMsg);
     tcpconnfd = socket( AF_INET, SOCK_DGRAM, 0 );
     if ( tcpconnfd == -1 ) {
               //printf("[%s:%d] socket error !!\n",__FILE__,__LINE__);
               return ;
     }
     if (sendto(tcpconnfd, (void *)CPEMsg, len, 0, (const struct sockaddr *)&servaddr, sizeof(servaddr)) != len) {
          ;//printf("[%s:%d] can not send message to CPE listen fd !!\n",__FILE__,__LINE__);
      } else {
         ;//printf("[%s:%d] has send message to cpe udp listen port !!\n",__FILE__,__LINE__);
     }
     close(tcpconnfd);
}

void save_and_notify(char *filename, S_Diagnostic *diagnostic){
	FILE * fp;
	char buf[4096]={0};
/*	DIAGDBG("DiagnosticsState=%d,ROMTime=%s, BOMTime=%s, EOMTime=%s,TestBytesReceived=%u, TotalBytesReceived=%u, TotalBytesSent=%u,TCPOpenRequestTime=%s, TCPOpenResponseTime=%s",diagnostic->DiagnosticsState, diagnostic->ROMTime, diagnostic->BOMTime, diagnostic->EOMTime,diagnostic->TestBytesReceived, diagnostic->TotalBytesReceived, diagnostic->TotalBytesSent,diagnostic->TCPOpenRequestTime, diagnostic->TCPOpenResponseTime);
	*/
	fp = fopen(filename, "w");
	if(fp){
		snprintf(buf, sizeof(buf), "DiagnosticsState:%s\nROMTime:%s\nBOMTime:%s\nEOMTime:%s\nTestBytesReceived:%u\nTotalBytesReceived:%u\nTotalBytesSent:%u\nTCPOpenRequestTime:%s\nTCPOpenResponseTime:%s\n",DiagnosticsState[diagnostic->DiagnosticsState], diagnostic->ROMTime, diagnostic->BOMTime, diagnostic->EOMTime,diagnostic->TestBytesReceived, diagnostic->TotalBytesReceived, diagnostic->TotalBytesSent,diagnostic->TCPOpenRequestTime, diagnostic->TCPOpenResponseTime);
		fwrite(buf, 1, sizeof(buf), fp);
		fclose(fp);
	}else{
		DIAGDBG("Can't open the TR143_FILE");
	}

	/*if(!strcmp(filename, TR143_DOWNLOAD_FILE)){ //Download
		nvram_setf("CWMP_DownloadDiagnostics.DiagnosticsState", "%s", DiagnosticsState[diagnostic->DiagnosticsState]);
		nvram_setf("CWMP_DownloadDiagnostics.ROMTime", "%s", diagnostic->ROMTime);
		nvram_setf("CWMP_DownloadDiagnostics.BOMTime", "%s", diagnostic->BOMTime);
		nvram_setf("CWMP_DownloadDiagnostics.EOMTime", "%s", diagnostic->EOMTime);
		nvram_setf("CWMP_DownloadDiagnostics.TestBytesReceived", "%u", diagnostic->TestBytesReceived);
		nvram_setf("CWMP_DownloadDiagnostics.TotalBytesReceived", "%u", diagnostic->TotalBytesReceived);
		nvram_setf("CWMP_DownloadDiagnostics.TCPOpenRequestTime", "%s", diagnostic->TCPOpenRequestTime);
		nvram_setf("CWMP_DownloadDiagnostics.TCPOpenResponseTime", "%s", diagnostic->TCPOpenResponseTime);
	}else{
		nvram_setf("CWMP_UploadDiagnostics.DiagnosticsState", "%s", DiagnosticsState[diagnostic->DiagnosticsState]);
		nvram_setf("CWMP_UploadDiagnostics.ROMTime", "%s", diagnostic->ROMTime);
		nvram_setf("CWMP_UploadDiagnostics.BOMTime", "%s", diagnostic->BOMTime);
		nvram_setf("CWMP_UploadDiagnostics.EOMTime", "%s", diagnostic->EOMTime);
		nvram_setf("CWMP_UploadDiagnostics.TotalBytesSent", "%u", diagnostic->TotalBytesSent);
		nvram_setf("CWMP_UploadDiagnostics.TCPOpenRequestTime", "%s", diagnostic->TCPOpenRequestTime);
		nvram_setf("CWMP_UploadDiagnostics.TCPOpenResponseTime", "%s", diagnostic->TCPOpenResponseTime);
	}

	SendCpeMessage();*/
}

int getfilesize(char *arg, unsigned long *size){
	DIAGDBG("THE ARG=%s", arg);
	char *endptr;
	int save_errno = errno;	
	errno = 0;
	if(arg == NULL)
		return -1;

	*size = strtoul(arg, &endptr, 0);
	if(errno != 0 || *endptr != '\0' || endptr==arg){//strtoul only set the errno when the overflow
		printf("the errno=%s(%d)", strerror(errno), errno);
		return -1;
	}
	errno = save_errno;
	return 0;
}

int select_with_timeout(int fd, int flag, int timeout){//flag 0: write, 1: read
	fd_set fdset;
	struct timeval tm;
	int ret;

	FD_ZERO(&fdset);
	FD_SET(fd, &fdset);
	tm.tv_sec = timeout;
	tm.tv_usec = 0;

	if (flag)
		ret = select(fd + 1, &fdset, NULL, NULL, &tm);
	else
		ret = select(fd + 1, NULL, &fdset, NULL, &tm);

	if ( ret <= 0 || !FD_ISSET(fd, &fdset))
	{
		DIAGDBG("select timeout");
		return -1;
	}

	return 0;
}

size_t read_with_timeout(int fd, char *buf, int len){
	if(select_with_timeout(fd, 1, TR143_SESSION_TIMEOUT))
		return -1; //timeout
	return recv(fd, buf, len, 0);
}

int RReadn(int fd, char *ptr, int nbytes, int timeout){
	int nleft, nread=0;
	int res=0;

	nleft = nbytes;

	while (nleft > 0){
		errno=0;
		res = select_with_timeout(fd, 1, timeout);
		if(res < 0){//-1 timeout or have error
			DIAGDBG("Read Packet select timeout || Error");
			return res;
		}
		nread = recv(fd, ptr, nleft, 0);

		if(nread < 0){
			if(errno == EAGAIN)
				return nbytes-nleft;
			else
				DIAGDBG("RRead Error:%s(%d)", strerror(errno), errno);
			return nread; //error
		}else if(nread == 0){
			break;
		}
		nleft -= nread;
		ptr += nread;
	}
	return nbytes - nleft;//return read bytes
}

int Readline(int fd, char *buf, int maxlen, int timeout){
	int n, rc;
	char *ptr = buf;
	char c;
	int flags, bflags;

	/* turn on synchroneous I/O, this call will block. */
	flags = (long) fcntl(fd, F_GETFL);
	bflags = flags & ~O_NONBLOCK;//clear non-block flag, change to block mode
	fcntl(fd, F_SETFL, bflags);

	for(n=1; n < maxlen; n++){
		rc=RReadn(fd, &c, 1, timeout);
		if(rc==1){
			*ptr++=c;
			if(c == '\n')
				break;
		}else if(rc==0){
			if(n==1){
				fcntl(fd, F_SETFL, flags);//recover the flags
				return 0;//no data to read
			}else
				break;//some data was read
		}else{
			DIAGDBG("Readline ERRORNO: %s(%d)", strerror(errno), errno);
			fcntl(fd, F_SETFL, flags);//recover the flags
			return -1;
		}
	}
	*ptr = '\0';
	fcntl(fd, F_SETFL, flags);//recover the flags
	DIAGDBG("Readline:%s",buf);
	return n;//return the length
}

int SSend(int fd, char *buf, int len){
	int bytes_send=0, byte_left=0;
	errno = 0;

	bytes_send = send(fd, buf, len, 0);//return the sendbytes actually

	if(bytes_send <= 0){
		if(errno != EAGAIN){
			printf("Send error:%s(%d)",strerror(errno),errno);
			return bytes_send;
		}
	}
	return bytes_send;
}

int open_conn_socket(struct sockaddr_in *s_info, char *if_name, int dscp, int priority){
	int fd;
	int flags, bflags;
	int errlen=0, errval=0;
	struct ifreq ifr;
	unsigned char tos;

        char ipadddr[16]={0};
	if(!inet_ntop(AF_INET, &s_info->sin_addr, ipadddr, sizeof(ipadddr))){
		printf("The Server Host ip is invalid Error:%s(%d)\n", strerror(errno),errno);
		return -1;
	}else{
		if(!strcmp(ipadddr, "0.0.0.0") || !strcmp(ipadddr, "127.0.0.1")){
			printf("The Server Host ip:%s is invalid\n", ipadddr);
			return -1;
		}
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd<0){
		DIAGDBG("open the socket error");
		return -1;
	}

	if(strlen(if_name)){//spec, if if_name is NULL, will use the default routing interface
		strcpy(ifr.ifr_name, if_name);
		ifr.ifr_addr.sa_family = AF_INET;
		if(ioctl(fd, SIOCGIFADDR, &ifr)<0){
			close(fd);
			DIAGDBG("ioctl get SIOCGIFADDR error");
			return -1;
		}
		if(bind(fd, (struct sockaddr *)&ifr.ifr_addr, sizeof(ifr.ifr_addr))<0){
			if( errno == EADDRINUSE){
				DIAGDBG("the port is opened");
			}
			close(fd);
			DIAGDBG("Bind error");
			return -1;
		}
	}
	flags= (long) fcntl(fd, F_GETFL);
	bflags= flags | O_NONBLOCK; //set as O_NONBLOCK mode
	fcntl(fd, F_SETFL, bflags);
	if( (connect(fd, (struct sockaddr *)s_info, sizeof(struct sockaddr_in)) <0 && errno != EINPROGRESS) || select_with_timeout(fd, 0, TR143_SESSION_TIMEOUT) < 0 ){
		DIAGDBG("connect error, the errno:%s(%d)", strerror(errno), errno);
		close(fd);
		return -1;
	}

	//getsockopt double check the connection is successfully
	errlen = sizeof(int);
	if(getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&errval), &errlen) < 0){
		DIAGDBG("getsockopt() Errno:%s(%d)", strerror(errno), errno);
		close(fd);
		return -1;
	}
	if(errval){
		DIAGDBG("getsockopt SO_ERROR:%s(%d)", strerror(errval), errval);
		close(fd);
		return -1;
	}
	fcntl(fd, F_SETFL, flags);

	//if interface is empty, to check the socket connect to server by which interfac & get the interface name
	if(!strlen(if_name)){
		struct sockaddr_in bindsun;
		int if_index;
		socklen_t sunlen;

		sunlen = sizeof(bindsun);
		getsockname(fd, (struct sockaddr *)&bindsun, &sunlen);

		for (if_index = 1; 1; if_index++)
		{
			ifr.ifr_ifindex = if_index;
			if (ioctl(fd, SIOCGIFNAME, &ifr)) break;
			if (ioctl(fd, SIOCGIFADDR, &ifr)) continue;
			if (bindsun.sin_addr.s_addr == ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr)
			{
				//strncpy(if_name, ifr.ifr_name, sizeof(if_name)-1);
				strcpy(if_name, ifr.ifr_name);
				DIAGDBG("bind interface:%s", ifr.ifr_name);
				break;
			}
		}
	}

	tos=dscp << 2;
	if(setsockopt(fd, SOL_IP, IP_TOS, &tos, sizeof(tos)) < 0){
		printf("setsockopt dscp error:%s(%d)", strerror(errno), errno);
	}

	if(setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) < 0){
		printf("setsockopt ethernetPriority error:%s(%d)", strerror(errno), errno);
	}

	return fd;
}

int parseURL(char *url, S_URL *surl){
	int n;
	char *p = NULL, *sp = NULL;
	DIAGDBG("Parse URL:%s",url);

//	*port = 0;
//	strcpy(uri, "");

	/* proto */
	p = (char *) url;
	if ((p = strchr(url, ':')) == NULL) {
		return -1;
	}
	n = p - url;
	strncpy(surl->protocol, url, n);
	surl->protocol[n] = '\0';

	/* skip "://" */
	if (*p++ != ':') return -1;
	if (*p++ != '/') return -1;
	if (*p++ != '/') return -1;

	sp = strchr(p, '@');
	if (sp != NULL)
	{
		*sp = '\0';
		strcpy(surl->user, p);
		p = sp + 1;
	}
	else
	{
		strcpy(surl->user, "anonymous:anonymous");
	}
	/* host */
	{
		char *hp = surl->host;

		while (*p && *p != ':' && *p != '/') {
			*hp++ = *p++;
		}
		*hp = '\0';
	}
	if (strlen(surl->host) == 0)
		return -1;

	/* end */
	if (*p == '\0') {
		surl->port = 0;
		strcpy(surl->uri, "");
		return 0;
	}

	/* port */
	if (*p == ':') {
		char buf[10];
		char *pp = buf;

		p++;
		while (isdigit(*p)) {
			*pp++ = *p++;
		}
		*pp = '\0';
		if (strlen(buf) == 0)
			return -1;
		surl->port = atoi(buf);
	}

	/* uri */
	if (*p == '/') {
		char *up = surl->uri;
		while ((*up++ = *p++));
	}

	DIAGDBG("the protocol=%s, host=%s, port=%d, uri=%s",surl->protocol,surl->host,surl->port,surl->uri);
	return 0;
};

int get_if_stats(char *if_name, unsigned int *rx, unsigned int *tx){
	FILE *file;
	char buf[512], *p;
	unsigned int discard;
	int ret = -1;
	unsigned int lrx, ltx;
	if(if_name[0] == '\0'){
		DIAGDBG("get_if_stats: if_name IS NULL");
		return -1;
	}
	file = fopen("/proc/net/dev", "r");
	if(!file){
		DIAGDBG("Can't open the file:/proc/net/dev");
		return -1;
	}
	fgets(buf, sizeof(buf), file);
	fgets(buf, sizeof(buf), file);

	while(fgets(buf, sizeof(buf), file)){
		if( !strstr(buf, if_name) || (!(p = strchr(buf, ':'))))
			continue;
		sscanf(p+1, "%u%u%u%u%u%u%u%u%u",&lrx, &discard, &discard, &discard, &discard, &discard, &discard, &discard, &ltx);
		ret = 0;
		break;
	}
	if(rx) *rx = lrx;
	if(tx) *tx = ltx;

	fclose(file);
	return ret;
}

/*void setDateTimeMics(char *timestr, int len){
	time_t now;
	struct tm *tmp;
	struct timeval tv;
	char *format=(char *)malloc(len);
	memset(format, 0, len);

	now = time(NULL);
	tmp = localtime(&now);
	gettimeofday(&tv, NULL);

	strftime(format, len, "%Y-%m-%dT%H:%M:%S.%%06u", tmp);
	snprintf(timestr, len, format, tv.tv_usec);
	free(format);
	return;
}*/

void setDateTimeMics(struct timeval *tv, int len)
{ 
	int ret; 
	struct timespec tp; 

	if ((ret=clock_gettime(CLOCK_REALTIME, &tp))==0) { 
		tv->tv_sec = tp.tv_sec; 
		tv->tv_usec = (tp.tv_nsec + 500) / 1000; //ns->ms 
	} 
	return;
}

void get_str_time(char *name, struct timeval tv)
{
	struct tm *lt;
	char str[100];
	char timestr[64];
	FILE *fp = NULL;
	char buff[128];

	sprintf(buff, "%d.%06d", tv.tv_sec, tv.tv_usec);
	lt = localtime(&(tv.tv_sec));
	strftime(str,100,"%Y-%m-%dT %H:%M:%S",lt);
	sprintf(timestr, "%s.%dZ", str, tv.tv_usec);
	printf("%s: %s\n", name, timestr);	  

	fp = fopen(TR143_UPLOAD_FILE, "a");

	if(fp != NULL)
	{
		fprintf(fp, "%s:%s\n", name, timestr);
		if((strcmp(name, "BOMTime") == 0) || (strcmp(name, "EOMTime") == 0))
		{
			fprintf(fp, "%s_org:%s\n", name, buff);
		}
		fclose(fp);
	}
}


