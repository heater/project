#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "common.h"

unsigned int ftpTestBytesSent = 0;
int ftpcmd(int sfd, char *s1, char *s2, char *buf, int bufsize){
	int length=0;
	char string[256]={0};
	char *buf_ptr;
	DIAGDBG("ftpcmd:%s%s(%d)", s1, s2, bufsize);
	
	if(s1){
		if(!s2)
			s2="";
		length = sprintf(string, "%s%s\r\n", s1, s2);
		if(SSend(sfd, string, length)!= length)
			DIAGDBG("ftpcmd send lost");
	}
	ftpTestBytesSent += length;
	
	do{
		if(Readline(sfd, buf, bufsize, TR143_SESSION_TIMEOUT) <=0){
			DIAGDBG("RReadline: no data to read or read error");
			return -1;
		}

	//	DIAGDBG("RReadline:%s", buf);
		buf_ptr = strstr(buf, "\r\n");
		if(buf_ptr)
			*buf_ptr = '\0';
	}while( !isdigit(buf[0]) || buf[3] != ' ');

	return atoi(buf);
}

S_Diagnostic *ftpdownload(S_URL surl, char *if_name, int dscp, int priority){
	DIAGDBG("Enter the ftpdownload+++, interface=%s", if_name);
	S_Diagnostic *diagnostic = (S_Diagnostic *)malloc(sizeof(struct S_Diagnostic));
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_in *sinp;
	int rv=0, sfd=0, dfd=0;
	char *s, *filename, buf[256];
	unsigned long filesize;
	int n, errCode = Completed;
	int port, firstRead = 1;
	unsigned int rxbytes=0;
	char service[6];

	if(surl.port == 0)
		surl.port = 21;
	snprintf(service, sizeof(service), "%d", surl.port);
	filename = (surl.uri[0]== '/') ? &surl.uri[1]:surl.uri;

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
		sfd = open_conn_socket(sinp, if_name, dscp, priority);
		if(sfd < 0){
			DIAGDBG("open the control socket fail");
			continue;
		}else{
			DIAGDBG("open the control socket successfully");
			break;
		}
	}

	if(p == NULL){//No address success
		printf("Connected to the Server Fail: No socket successfully\n");
		errCode = Error_InitConnectionFailed;
		goto err3;
	}
	DIAGDBG("......Connected to the Server......");

	if(ftpcmd(sfd, NULL, NULL, buf, sizeof(buf)) != 220){ //220: System_Ready
		DIAGDBG("Server not ready");
		errCode = Error_InitConnectionFailed;
		goto err2;
	}

	switch(ftpcmd(sfd, "USER ", "anonymous", buf, sizeof(buf))){//spec define: TR143_p26(use the anonymous to login)
		case 230://230: login_successful
			break;
		case 331://331: please_specify_the_password
			if(ftpcmd(sfd, "PASS ", "anonymous", buf, sizeof(buf)) == 230)
				break;
			DIAGDBG("Auth PASS fail");
			errCode = Error_LoginFailed;
			goto err2;
		default:
			DIAGDBG("Auth User fail");
			errCode = Error_PasswordRequestFailed;
			goto err2;
	}

	if(ftpcmd(sfd, "TYPE I", NULL, buf, sizeof(buf)) != 200){ //200: Switching to Binary mode
		DIAGDBG("Transfer Mode error");
		errCode = Error_NoTransferMode;
		goto err2;
	}
	
	if(ftpcmd(sfd, "PASV", NULL, buf, sizeof(buf)) != 227){ //227: Entering Passive Mode
		DIAGDBG("PASV error");
		errCode = Error_NoPASV;
		goto err2;
	}
	
	s = strrchr(buf, ',');
	*s = 0;
	port = atoi(s+1);
	s = strrchr(buf, ',');
	port += atoi(s+1) * 256;
	//set ip & port
	char ipadddr[16]={0};
	sinp= (struct sockaddr_in *)p->ai_addr;
	inet_ntop(AF_INET, &sinp->sin_addr, ipadddr, sizeof(ipadddr));
	sinp->sin_port=htons(port);
	DIAGDBG("the p->protocol=%d, ip_address=%s, port=%d", p->ai_protocol, ipadddr, ntohs(sinp->sin_port));

	setDateTimeMics(&(diagnostic->TCPOpenRequestTime), sizeof(diagnostic->TCPOpenRequestTime));
	DIAGDBG("Set the TCPOpenRequestTime......%s", diagnostic->TCPOpenRequestTime);
	dfd = open_conn_socket(sinp, if_name, dscp, priority);
	setDateTimeMics(&(diagnostic->TCPOpenResponseTime), sizeof(diagnostic->TCPOpenResponseTime));
	DIAGDBG("Set the TCPOpenResponseTime......%s", diagnostic->TCPOpenResponseTime);

	if(dfd <= 0){
		DIAGDBG("open the data socket error");
		errCode = Error_NoResponse;
		goto err2;
	}	
	
	if((ftpcmd(sfd, "SIZE ", filename, buf, sizeof(buf)) != 213) || getfilesize(buf+4, &filesize)){//213 File status
		DIAGDBG("SIZE error");
		errCode = Error_IncorrectSize;
		goto err1;
	}
	
	setDateTimeMics(&(diagnostic->ROMTime), sizeof(diagnostic->ROMTime));
	DIAGDBG("Set the ROMTIME......%s", diagnostic->ROMTime);
	get_if_stats(if_name, &rxbytes, NULL);
	if(ftpcmd(sfd, "RETR ", filename, buf, sizeof(buf)) > 150){
		DIAGDBG("RETR error");
		errCode = Error_Timeout;
		goto err1;
	}
	DIAGDBG("RETR send, the filesize:%lu", filesize);
	
	while(filesize > 0){
		n = read_with_timeout(dfd, buf, (filesize > sizeof(buf))? sizeof(buf):filesize);
		if(n <= 0){
			DIAGDBG("file read error, %d", n);
			errCode = n < 0 ? Error_Timeout:Error_TransferFailed;
			goto err1;
		}
		if(firstRead){
			setDateTimeMics(&(diagnostic->BOMTime), sizeof(diagnostic->BOMTime));
			DIAGDBG("Set the BOMTIME......%s", diagnostic->BOMTime);
			firstRead = 0;
		}
		diagnostic->TestBytesReceived += n;
		filesize -= n;
	}

	get_if_stats(if_name, &diagnostic->TotalBytesReceived, NULL);
	diagnostic->TotalBytesReceived -= rxbytes;
	setDateTimeMics(&(diagnostic->EOMTime), sizeof(diagnostic->EOMTime));
	DIAGDBG("Set the EOMTIME......%s", diagnostic->EOMTime);
	close(dfd);
	
	if(ftpcmd(sfd, NULL, NULL, buf, sizeof(buf)) != 226){
		DIAGDBG("read file send OK fail");
	}

	ftpcmd(sfd, "QUIT", NULL, buf, sizeof(buf));
	goto err2;

err1:
	close(dfd);
err2:
	close(sfd);
err3:
	freeaddrinfo(servinfo);
	diagnostic->DiagnosticsState = errCode;
	return diagnostic;
};

S_Diagnostic *ftpupload(S_URL surl, char *if_name, int dscp, int priority, unsigned int  filelength){
	DIAGDBG("Enter the ftpupload+++, interface=%s, filelength=%u", if_name, filelength);
	S_Diagnostic *diagnostic = (S_Diagnostic *)malloc(sizeof(struct S_Diagnostic));
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_in *sinp;
	int rv=0, sfd=0, dfd=0;
	char *s, *filename, buf[512];
	long long testfilelength = filelength;
	int n, errCode = Completed;
	int port;
	unsigned int txbytes=0;
	char service[6];
	char user[128] = {0};
	char pass[128] = {0};
	char *ptr = NULL;
	
	if(surl.port == 0)
		surl.port = 21;

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
		sfd = open_conn_socket(sinp, if_name, dscp, priority);
		if(sfd < 0){
			DIAGDBG("open the control socket fail");
			continue;
		}else{
			DIAGDBG("open the control socket successfully");
			break;
		}
	}

	if(p == NULL){//No address success
		printf("Connected to the Server Fail: No socket successfully\n");
		errCode = Error_InitConnectionFailed;
		goto err3;
	}

	if(ftpcmd(sfd, NULL, NULL, buf, sizeof(buf)) != 220){ //220: System_Ready
		DIAGDBG("Server not ready");
		errCode = Error_InitConnectionFailed;
		goto err2;
	}

	ptr = strchr(surl.user, ':');
	if(ptr != NULL)
	{
		*ptr = '\0';
		strcpy(user, surl.user);
		strcpy(pass, ptr+1);
	}
	switch(ftpcmd(sfd, "USER ", user, buf, sizeof(buf))){//spec define: TR143_p26(use the anonymous to login)
		case 230://230: login_successful
			break;
		case 331://331: please_specify_the_password
			if(ftpcmd(sfd, "PASS ", pass, buf, sizeof(buf)) == 230)
				break;
			DIAGDBG("Auth PASS fail");
			errCode = Error_LoginFailed;
			goto err2;
		default:
			DIAGDBG("Auth User fail");
			errCode = Error_PasswordRequestFailed;
			goto err2;
	}

	if(ftpcmd(sfd, "TYPE I", NULL, buf, sizeof(buf)) != 200){ //200: Switching to Binary mode
		DIAGDBG("Transfer Mode error");
		errCode = Error_NoTransferMode;
		goto err2;
	}
	
	if(ftpcmd(sfd, "PASV", NULL, buf, sizeof(buf)) != 227){ //227: Entering Passive Mode
		DIAGDBG("PASV error");
		errCode = Error_NoPASV;
		goto err2;
	}
	
	s = strrchr(buf, ',');
	*s = 0;
	port = atoi(s+1);
	s = strrchr(buf, ',');
	port += atoi(s+1) * 256;
	//set ip & port
	char ipadddr[16]={0};
	sinp= (struct sockaddr_in *)p->ai_addr;
	inet_ntop(AF_INET, &sinp->sin_addr, ipadddr, sizeof(ipadddr));
	sinp->sin_port=htons(port);
	DIAGDBG("the p->protocol=%d, ip_address=%s, port=%d", p->ai_protocol, ipadddr, ntohs(sinp->sin_port));

	setDateTimeMics(&(diagnostic->TCPOpenRequestTime), sizeof(diagnostic->TCPOpenRequestTime));
	DIAGDBG("Set the TCPOpenRequestTime......%s", diagnostic->TCPOpenRequestTime);
	dfd = open_conn_socket(sinp, if_name, dscp, priority);
	setDateTimeMics(&(diagnostic->TCPOpenResponseTime), sizeof(diagnostic->TCPOpenResponseTime));
	DIAGDBG("Set the TCPOpenResponseTime......%s", diagnostic->TCPOpenResponseTime);

	if(dfd <= 0){
		DIAGDBG("open the data socket error");
		errCode = Error_NoResponse;
		goto err2;
	}	
	
	filename = strrchr(surl.uri, '/');
	if(filename != NULL){
		*filename = '\0';
		filename++;
		if(surl.uri[0] != '\0' && ftpcmd(sfd, "CWD ", surl.uri, buf, sizeof(buf)) != 250){//250: Requested file action okay, completed
			DIAGDBG("CWD %s, error", surl.uri);
			errCode = Error_NoCWD;
			goto err1;
		}
		DIAGDBG("CWD:%s", surl.uri);
	}else{
		filename = surl.uri;
	}

	setDateTimeMics(&(diagnostic->ROMTime), sizeof(diagnostic->ROMTime));
	DIAGDBG("Set the ROMTIME......%s", diagnostic->ROMTime);

	if(ftpcmd(sfd, "STOR ", filename, buf, sizeof(buf)) > 150){
		DIAGDBG("STOR error");
		errCode = Error_NoSTOR;
		goto err1;
	}
	DIAGDBG("STOR send, the filelength:%u", filelength);

	get_if_stats(if_name, NULL, &txbytes);
	setDateTimeMics(&(diagnostic->BOMTime), sizeof(diagnostic->BOMTime));
	DIAGDBG("Set the BOMTIME......%s", diagnostic->BOMTime);

	memset(buf, 'a', sizeof(buf));

	while(testfilelength > 0){
		n = send(dfd, buf, (testfilelength > sizeof(buf))? sizeof(buf):testfilelength, 0);
		if(n <= 0){
			DIAGDBG("ftp file send error:%d", n);
			errCode = Error_TransferFailed;
			goto err1;
		}
		testfilelength -= n;
		ftpTestBytesSent += n;
	}
	setDateTimeMics(&(diagnostic->EOMTime), sizeof(diagnostic->EOMTime));
	DIAGDBG("Set the EOMTIME......%s", diagnostic->EOMTime);
	get_if_stats(if_name, NULL, &diagnostic->TotalBytesSent);
	diagnostic->TotalBytesSent -= txbytes;
	close(dfd);

	if(ftpcmd(sfd, NULL, NULL, buf, sizeof(buf)) != 226){//TO_CHECK: may have code 226-Error during write to file
								  //			    226 Transfer aborted
		DIAGDBG("file send fail");
		errCode = Error_TransferFailed;
		goto err2;
	}

	ftpcmd(sfd, "QUIT", NULL, buf, sizeof(buf));
	goto err2;

err1:
	close(dfd);
err2:
	close(sfd);
err3:
	freeaddrinfo(servinfo);
	diagnostic->DiagnosticsState = errCode;
	return diagnostic;

}
