#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "common.h"

unsigned int httpTestBytesSent = 0;
/*----------------------------------------------------------------------*
 * discard all there is to read on the in buffer
 * This is used since some stupid browsers (e.g. IE) sends more data
 * than specified in the content-lenght header
 * Returns result of last read():
 *     0 - eof
 *     -1 - connection error.
 *      1 - no data, possibly more.
 */
int Skip(int fd){//discard the lost read message
	char c;
	int nread = 0, ret = 0;
	long flags, nbflags;

	flags = (long) fcntl(fd, F_GETFL);
	nbflags = flags | O_NONBLOCK;//set as O_NONBLOCK & read all message
	fcntl(fd, F_SETFL, nbflags);

	do{
		nread = recv(fd, &c, 1, 0);
		if(nread<0){
			ret = errno == EAGAIN? 1: -1;
			break;
		}
	}while(nread > 0);
	fcntl(fd, F_SETFL, flags);

	return ret;
}

//remove the spaces, \r and \n
void StripTail(char *s){
	if(*s!='\0'){
		while(*s)
			s++;
		s--;
		while(*s == '\r' || *s == '\n' || *s ==' ' || *s == '\t'){
			*s = '\0';
			s--;
		}
	}
}

int SendRequest(int fd, char *type, char *uri){
	char buf[BUF_SIZE_MAX];
	int len;
	
	len = snprintf(buf, BUF_SIZE_MAX, "%s %s HTTP/1.1\r\n", type, uri);

	if(len != SSend(fd, buf, len)){
		DIAGDBG("SendRequest lost ");
		return -1;
	}
	DIAGDBG("SendRequest=>%s",buf);
	httpTestBytesSent += len;
	return 0;
}

int SendHeader(int fd, char *header, char *value){
	char buf[BUF_SIZE_MAX];
	int len;

	if(header == NULL || value == NULL){
		DIAGDBG("header || value is NULL ");
		return -1;
	}
	len = snprintf(buf, BUF_SIZE_MAX, "%s: %s\r\n", header, value);
	if(len != SSend(fd, buf, len)){
		DIAGDBG("SendHeader lost ");
		return -1;
	}
	DIAGDBG("SendHeader=>%s",buf);
	httpTestBytesSent += len;
	return 0;
}

int SendRaw(int fd, char *arg, int length){
//	int total_len=0, len=0;

/*	while(total_len < length){
		printf("the total_len=%d\n", total_len);
		if((len = send(fd, arg+total_len, length-total_len, 0)) >=0){
			total_len +=len;
			continue;
		}
	}
*/

	if(length != SSend(fd, arg, length)){
		DIAGDBG("SendRaw lost");
		return -1;
	}
	DIAGDBG("SendRaw=>(%d)%s",length, arg);
	httpTestBytesSent += length;
	return 0;

}

int ParseHttpResponse(int fd, S_HttpHdrs *hdrs){
	char buf[BUF_SIZE_MAX];
	char protocol[BUF_SIZE_MAX];
	char status[BUF_SIZE_MAX];
	char message[BUF_SIZE_MAX];
	int bufsize;

	if((bufsize = Readline(fd, buf, BUF_SIZE_MAX, HTTP_SESSION_TIMEOUT)) <= 0){
		DIAGDBG("Readline error");
		return -1;
	}
	if(sscanf(buf, "%[^ ] %[^ ] %[^ ]", protocol, status, message)!=3){
		DIAGDBG("sscanf error on %s", buf);
		return -1;
	}

	StripTail(protocol);
	StripTail(status);
	StripTail(message);
	free(hdrs->protocol);
	hdrs->protocol=strdup(protocol);
	hdrs->status_code=atoi(status);
	free(hdrs->message);
	hdrs->message=strdup(message);

	DIAGDBG("ParseHttpResponse:(Protocol=%s, status=%d, message=%s", hdrs->protocol, hdrs->status_code, hdrs->message);

	return bufsize;
}

static char HostStr[]="Host:";
static char ConnectionStr[]="Connection:";
static char SetCookieStr[]="Set-Cookie:";
static char SetCookieStr2[]="Set-Cookie2:";
static char ContentLthStr[]="Content-Length:";
static char ContentTypeStr[]="Content-Type:";
static char WWWAuthenticateStr[]="WWW-Authenticate:";
static char AuthorizationStr[]="Authorization:";
static char TransferEncoding[]="Transfer-Encoding:";
static char LocationStr[]="Location:";

void addCookieHdr(CookieHdr **p, char *c){
	CookieHdr *newCookie =	malloc(sizeof(struct CookieHdr));
	char *cp;

	if(newCookie){
		if((cp = strchr(c, '='))){
			newCookie->next= *p;
			newCookie->name=strndup(c, cp-c);
			newCookie->value=strdup(cp+1);
			*p = newCookie;
		}else{
			free(newCookie);
		}
	}
}

int ParseHdrs(int fd, S_HttpHdrs *hdrs){
	char buf[BUF_SIZE_MAX];
	char *cp;
	int n;
	int tolsize=0;
	//Parse the request Headers
	while ((n = Readline(fd, buf, BUF_SIZE_MAX, HTTP_SESSION_TIMEOUT))){
		tolsize += n;
		StripTail(buf);
		
		if(strcmp(buf, "")==0){
			break;
		}else if(!strncasecmp(buf, HostStr, sizeof(HostStr)-1)){
			cp = &buf[sizeof(HostStr)-1];
			cp += strspn(cp, " \t");//remove the space
			free(hdrs->host);
			hdrs->host=strdup(cp);
		}else if(!strncasecmp(buf, ConnectionStr, sizeof(ConnectionStr)-1)){
			cp = &buf[sizeof(ConnectionStr)-1];
			cp += strspn(cp, " \t");
			free(hdrs->Connection);
			hdrs->Connection=strdup(cp);
		}else if(!strncasecmp(buf, ContentLthStr, sizeof(ContentLthStr)-1)){
			cp = &buf[sizeof(ContentLthStr)-1];
			cp += strspn(cp, " \t");
			hdrs->content_length = atoi(cp);
		}else if(!strncasecmp(buf, ContentTypeStr, sizeof(ContentTypeStr)-1)){
			cp = &buf[sizeof(ContentTypeStr)-1];
			cp += strspn(cp, " \t");
			free(hdrs->content_type);
			hdrs->content_type=strdup(cp);
		}else if(!strncasecmp(buf, WWWAuthenticateStr, sizeof(WWWAuthenticateStr)-1)){
			cp = &buf[sizeof(WWWAuthenticateStr)-1];
			cp += strspn(cp, " \t");
			free(hdrs->wwwAuthenticate);
			hdrs->wwwAuthenticate=strdup(cp);
		}else if(!strncasecmp(buf, AuthorizationStr, sizeof(AuthorizationStr)-1)){
			cp = &buf[sizeof(AuthorizationStr)-1];
			cp += strspn(cp, " \t");
			free(hdrs->Authorization);
			hdrs->Authorization=strdup(cp);
		}else if(!strncasecmp(buf, TransferEncoding, sizeof(TransferEncoding)-1)){
			cp = &buf[sizeof(TransferEncoding)-1];
			cp += strspn(cp, " \t");
			free(hdrs->TransferEncoding);
			hdrs->TransferEncoding=strdup(cp);
		}else if(!strncasecmp(buf, LocationStr, sizeof(LocationStr)-1)){
			cp = &buf[sizeof(LocationStr)-1];
			cp += strspn(cp, " \t");
			free(hdrs->locationHdr);
			hdrs->locationHdr=strdup(cp);
		}else if(!strncasecmp(buf, SetCookieStr, sizeof(SetCookieStr)-1) || !strncasecmp(buf, SetCookieStr2, sizeof(SetCookieStr2)-1)){
			char *c;
			cp = &buf[sizeof(SetCookieStr)-1];
			cp += strspn(cp, " \t");
			if( (c = strstr(cp, ";")))
				*c = '\0';
			addCookieHdr( &hdrs->setCookies, cp);
		}
	}
	//DIAGDBG("ParseHdrs Done, the tolsize=%d", tolsize);
	return tolsize;
}

int http_readLengthMsg(int fd, int readlength, int doSkip){//the readlength must >0
	char buf[512];
	int bufcnt=0, readcnt=0;
	int buflength = readlength;
	
	while(bufcnt < readlength){
		if(( readcnt = RReadn(fd, buf, ((buflength > sizeof(buf)) ? sizeof(buf) : buflength), HTTP_SESSION_TIMEOUT) ) > 0 ){
			bufcnt += readcnt;
			buflength -= readcnt;
		}else{
			DIAGDBG("RReadn error or timeout");
			break;
		}
	}

	DIAGDBG("http_readLengthMsg: readlength=%d, actual read=%d", readlength, bufcnt);
	if(readcnt <=0){
		DIAGDBG("http_readLengthMsg ERROR");
		return -1;
	}
	if(doSkip)
		Skip(fd);
	return bufcnt;//return the read size
}

int http_readChunkedMsg(int fd){
	char chunkbuf[512];
	int chunked_sz=0, read_sz=0, total_sz=0;

	while(1){
		do{
			chunkbuf[0] = '\0';
			read_sz = Readline(fd, chunkbuf, sizeof(chunkbuf), HTTP_SESSION_TIMEOUT);
			if(read_sz <= 0){
				DIAGDBG("http_readChunkedMsg: readchunked size error");
				return -1;
			}
		}while(read_sz > 0 && isxdigit(chunkbuf[0]) == 0);//is not hex, mean is not Chunked len
	
		total_sz += read_sz;
		sscanf(chunkbuf, "%x", &chunked_sz);//get the Chunked len

		if(chunked_sz <= 0) break;
		if((read_sz = http_readLengthMsg(fd, chunked_sz, 0)) < 0){
			DIAGDBG("http_readLengthMsg ERROR, chunked_sz=%d, read_sz=%d",chunked_sz, read_sz);
			return -1;
		}
		total_sz += read_sz;
	}
	Skip(fd);
	return total_sz;//return the totalsize
}

//$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$//
int send_http_get(int fd, char *uri, char *server_addr, int port){
	char hostname[270]={0};
	if(port != 80)//spec: need include port on Host(if port is not 80)
		snprintf(hostname, sizeof(hostname), "%s:%d", server_addr, port);
	else
		snprintf(hostname, sizeof(hostname), "%s", server_addr);

	if(SendRequest(fd, "GET", uri))
		return -1;
	if(SendHeader(fd, "Host", hostname)|| SendHeader(fd, "User-Agent", TR143_AGENT_NAME)|| 	SendHeader(fd, "Connection", "keep-alive"))
		return -1;

	SendRaw(fd, "\r\n", 2);
	return 0;
}

int send_http_put(int fd, char *uri, char *server_addr, int port, char *if_name, unsigned int length, unsigned int *txbytes, S_Diagnostic *diagnostic){
	DIAGDBG("Do send_http_put the length=%u", length);
	char hostname[270]={0};
	char buf[512]={0};
	long long sendcnt=0;

	if(port != 80)//spec: need include port on Host(if port is not 80)
		snprintf(hostname, sizeof(hostname), "%s:%d", server_addr, port);
	else
		snprintf(hostname, sizeof(hostname), "%s", server_addr);
	
	sprintf(buf, "%u", length);
	if(SendRequest(fd, "PUT", uri))
		return -1;
	if(SendHeader(fd, "Host", hostname)|| SendHeader(fd, "User-Agent", TR143_AGENT_NAME)|| SendHeader(fd, "Connection", "keep-alive")||\
			SendHeader(fd, "Content-type", "text/xml")|| SendHeader(fd, "Content-Length", buf ))
		return -1;
	SendRaw(fd, "\r\n", 2);
	
	memset(buf, 'a', sizeof(buf));

	//start send DATA
	get_if_stats(if_name, NULL, txbytes);
	setDateTimeMics(&(diagnostic->BOMTime), sizeof(diagnostic->BOMTime));
        DIAGDBG("Set the BOMTIME......%s", diagnostic->BOMTime);

	for(sendcnt = length; sendcnt >= 0; sendcnt-=sizeof(buf)){
		if(SendRaw(fd, buf, (sendcnt > sizeof(buf) ? sizeof(buf):sendcnt))<0){
			return -1;
		}
	}
	return 0;
}

void Free_HttpHdrs(S_HttpHdrs *hdrs){
	CookieHdr *cp, *last;	

	free(hdrs->content_type);
	free(hdrs->protocol);
	free(hdrs->wwwAuthenticate);
	free(hdrs->Authorization);
	free(hdrs->TransferEncoding);
	free(hdrs->Connection);
	free(hdrs->method);
	free(hdrs->path);
	free(hdrs->host);
	cp = hdrs->setCookies;
	while(cp){
		last = cp->next;
		free(cp->name);
		free(cp->value);
		free(cp);
		cp = last;
	}
	free(hdrs->message);
	free(hdrs->locationHdr);
	free(hdrs->filename);
	free(hdrs->arg);
	free(hdrs);
}

int http_GetData(int fd,unsigned int *TestBytesReceived){
	S_HttpHdrs *hdrs;
	int errCode = Completed;
	unsigned int testrxbytes = 0;

	hdrs = malloc(sizeof(struct S_HttpHdrs));
	memset(hdrs, 0, sizeof(struct S_HttpHdrs));

	if( (testrxbytes = ParseHttpResponse(fd, hdrs)) < 0 ){
		DIAGDBG("Parse the HttpResponse Error");
		errCode = Error_TransferFailed;
		goto err1;
	}
	*TestBytesReceived += testrxbytes;
	DIAGDBG("the testrxbytes=%d, the TestBytesReceived=%d", testrxbytes, *TestBytesReceived);
	
	*TestBytesReceived += ParseHdrs(fd, hdrs);
	DIAGDBG("the TestBytesReceived=%d", *TestBytesReceived);

	if(hdrs->status_code !=200){
		DIAGDBG("http response statuscode %d",hdrs->status_code);
		if(hdrs->status_code == 401)
			errCode = Error_LoginFailed;
		else
			errCode = Error_TransferFailed;
		goto err1;
	}

	if(hdrs->TransferEncoding && !strcasecmp(hdrs->TransferEncoding,"chunked")){
		if( (testrxbytes = http_readChunkedMsg(fd)) < 0){
			DIAGDBG("call http_readChunkedMsg error");
			errCode = Error_TransferFailed;
		}else{
			*TestBytesReceived += testrxbytes;
			DIAGDBG("the testrxbytes=%d, the TestBytesReceived=%d", testrxbytes, *TestBytesReceived);
		}
	}else if(hdrs->content_length > 0){
		if( (testrxbytes = http_readLengthMsg(fd, hdrs->content_length, 1)) < 0){
			DIAGDBG("call http_readLengthMsg error, content_length=%d", hdrs->content_length);
			errCode = Error_TransferFailed;
		}else{
			*TestBytesReceived += testrxbytes;
			DIAGDBG("the testrxbytes=%d, the TestBytesReceived=%d", testrxbytes, *TestBytesReceived);
		}
	}
err1:
	Free_HttpHdrs(hdrs);
	return errCode;
}

S_Diagnostic *httpdownload(S_URL surl, char *if_name, int dscp, int priority){
	DIAGDBG("Enter the httpdownload+++, port=%d, interface=%s", surl.port, if_name);
	S_Diagnostic *diagnostic = (S_Diagnostic *)malloc(sizeof(struct S_Diagnostic));
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_in *sinp;
	int rv=0, sfd=0;
	int errCode = Completed;
	unsigned int rxbytes=0;
	char service[6];

	if(surl.port == 0)
		surl.port=80;
	snprintf(service, sizeof(service), "%d", surl.port);

	memset(diagnostic, 0, sizeof(struct S_Diagnostic));
	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if((rv = getaddrinfo(surl.host, service, &hints, &servinfo)) != 0){
		printf("getaddrinfo error:%s\n",gai_strerror(rv));
		diagnostic->DiagnosticsState = Error_InitConnectionFailed;
		return diagnostic;
	}
/*	
	struct sockaddr_in *sinp;
	char *addr;
	char ipadddr[16]={0};
	sinp= (struct sockaddr_in *)p->ai_addr;
	addr= inet_ntop(AF_INET, &sinp->sin_addr, ipadddr, sizeof(ipadddr));
	DIAGDBG("the p->protocol=%d, ip_address=%s, port=%d", p->ai_protocol, ipadddr, ntohs(sinp->sin_port));
*/

	for (p = servinfo; p != NULL; p = p->ai_next){//add for DNS Query response multiple ip
		sinp= (struct sockaddr_in *)p->ai_addr;

		setDateTimeMics(&(diagnostic->TCPOpenRequestTime), sizeof(diagnostic->TCPOpenRequestTime));
		DIAGDBG("Set the TCPOpenRequestTime......%s", diagnostic->TCPOpenRequestTime);
		sfd = open_conn_socket(sinp, if_name, dscp, priority);
		setDateTimeMics(&(diagnostic->TCPOpenResponseTime), sizeof(diagnostic->TCPOpenResponseTime));
		DIAGDBG("Set the TCPOpenResponseTime......%s", diagnostic->TCPOpenResponseTime);

		if(sfd < 0){
			DIAGDBG("open the socket fail");
			continue;
		}else{
			DIAGDBG("open the socket successfully");
			break;
		}
	}

	if(p == NULL){//No address success
		printf("Connected to the Server Fail: No socket successfully\n");
		errCode = Error_InitConnectionFailed;
		goto err1;
	}
	DIAGDBG("......Connected to the Server......\n");

	setDateTimeMics(&(diagnostic->ROMTime), sizeof(diagnostic->ROMTime));
	DIAGDBG("Set the ROMTIME......%s", diagnostic->ROMTime);
	if(send_http_get(sfd, surl.uri, surl.host, surl.port)<0){
		DIAGDBG("Send http get request error");
		errCode = Error_InitConnectionFailed;
		goto err2;
	}
	get_if_stats(if_name, &rxbytes, NULL);

	if(select_with_timeout(sfd, 1, TR143_SESSION_TIMEOUT)){
		DIAGDBG("http get response timeout");
		errCode = Error_NoResponse;
		goto err2;
	}
	setDateTimeMics(&(diagnostic->BOMTime), sizeof(diagnostic->BOMTime));
	DIAGDBG("Set the BOMTIME......%s", diagnostic->BOMTime);

	errCode = http_GetData(sfd, &diagnostic->TestBytesReceived);

	get_if_stats(if_name, &diagnostic->TotalBytesReceived, NULL);
	diagnostic->TotalBytesReceived -= rxbytes;
	
	setDateTimeMics(&(diagnostic->EOMTime), sizeof(diagnostic->EOMTime));
	DIAGDBG("Set the EOMTIME......%s", diagnostic->EOMTime);

err2:
	close(sfd);
err1:
	freeaddrinfo(servinfo);
	diagnostic->DiagnosticsState = errCode;
	return diagnostic;
}

S_Diagnostic *httpupload(S_URL surl, char *if_name, int dscp, int priority, unsigned int filelength){
	DIAGDBG("Enter the httpupload+++, port=%d, interface=%s", surl.port, if_name);
	S_Diagnostic *diagnostic = (S_Diagnostic *)malloc(sizeof(struct S_Diagnostic));
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_in *sinp;
	int rv=0, sfd=0;
	int errCode = Completed;
	S_HttpHdrs *hdrs;
	unsigned int txbytes=0;
	char service[6];

	if(surl.port == 0)
		surl.port=80;
	snprintf(service, sizeof(service), "%d", surl.port);

	memset(diagnostic, 0, sizeof(struct S_Diagnostic));
	memset(&hints, 0, sizeof(struct addrinfo));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if((rv = getaddrinfo(surl.host, service, &hints, &servinfo)) != 0){
		printf("getaddrinfo error:%s\n",gai_strerror(rv));
		diagnostic->DiagnosticsState = Error_InitConnectionFailed;
		return diagnostic;
	}

	for (p = servinfo; p != NULL; p = p->ai_next){//add for DNS Query response multiple ip
		sinp= (struct sockaddr_in *)p->ai_addr;

		setDateTimeMics(&(diagnostic->TCPOpenRequestTime), sizeof(diagnostic->TCPOpenRequestTime));
		DIAGDBG("Set the TCPOpenRequestTime......%s", diagnostic->TCPOpenRequestTime);
		sfd = open_conn_socket(sinp, if_name, dscp, priority);
		setDateTimeMics(&(diagnostic->TCPOpenResponseTime), sizeof(diagnostic->TCPOpenResponseTime));
		DIAGDBG("Set the TCPOpenResponseTime......%s", diagnostic->TCPOpenResponseTime);

		if(sfd < 0){
			DIAGDBG("open the socket fail");
			continue;
		}else{
			DIAGDBG("open the socket successfully");
			break;
		}
	}

	if(p == NULL){//No address success
		printf("Connected to the Server Fail: No socket successfully\n");
		errCode = Error_InitConnectionFailed;
		goto err1;
	}
	DIAGDBG("......Connected to the Server......\n");

	setDateTimeMics(&(diagnostic->ROMTime), sizeof(diagnostic->ROMTime));
	DIAGDBG("Set the ROMTIME......%s", diagnostic->ROMTime);

	if(send_http_put(sfd, surl.uri, surl.host, surl.port, if_name, filelength, &txbytes, diagnostic) < 0){
		DIAGDBG("Send http put request error");
		errCode = Error_InitConnectionFailed;
		goto err2;
	}
	DIAGDBG("......http put send......, txbytes=%u, diagnostic->BOMTime=%s\n", txbytes, diagnostic->BOMTime);

	if(select_with_timeout(sfd, 1, TR143_SESSION_TIMEOUT)){
		DIAGDBG("http put response timeout");
		errCode = Error_NoResponse;
		goto err2;
	}
	
	setDateTimeMics(&(diagnostic->EOMTime), sizeof(diagnostic->EOMTime));
	DIAGDBG("Set the EOMTIME......%s", diagnostic->EOMTime);
	get_if_stats(if_name, NULL, &diagnostic->TotalBytesSent);
	diagnostic->TotalBytesSent -= txbytes;
	

	hdrs = malloc(sizeof(struct S_HttpHdrs));
	memset(hdrs, 0, sizeof(struct S_HttpHdrs));

	if(ParseHttpResponse(sfd, hdrs) < 0){ //ParseHttpResponse return packetsize
		DIAGDBG("Parse the HttpResponse Error");
		errCode = Error_TransferFailed;
		goto err3;
	}	
	ParseHdrs(sfd, hdrs);

	if (hdrs->status_code != 100 &&  // Continue status might be returned by Microsoft-IIS/5.1
		hdrs->status_code != 201 &&   // Created status is returned by Microsoft-IIS/5.1
		hdrs->status_code != 204 &&   // No content status is returned by Apache/2.2.2
		hdrs->status_code != 200 ){
		DIAGDBG("HttpResponse statusCode: %d", hdrs->status_code);
		if(hdrs->status_code == 401)
			errCode = Error_LoginFailed;
		else
			errCode = Error_TransferFailed;
	}else{
		errCode = Completed;
	}

err3:
	Free_HttpHdrs(hdrs);
err2:
	close(sfd);
err1:
	freeaddrinfo(servinfo);
	diagnostic->DiagnosticsState = errCode;
	return diagnostic;

}
