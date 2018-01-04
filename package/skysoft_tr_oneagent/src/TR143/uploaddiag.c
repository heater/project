/* TR143 Version 1.0 UploadDiagnostics
 * support only for the single IPv4 connection
 * HTTP Implementation notes:
	-persistent connections MUST be used.
	-Pipelining is not supported.
	-HTTP authentication is not supported.
	-HTTP headers may be 1.0 or 1.1. HTTPS is not supported.
 * FTP
	-binary transfer mode MUST be used
	-login with anonymous
 * Usage uploaddiag [-i interface] [-d dscp] [-p ethpriority] [-u uploadURL] [-l testFileLength]
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "http.h"
#include "ftp.h"
#include "common.h"

extern unsigned int httpTestBytesSent;
extern unsigned int ftpTestBytesSent;

int main (int argc, char *argv[])
{
	int ch;
	char interface[256]={0};
	int dscp=0, ethernetPriority=0;
	unsigned int testFileLength=0;
	char uploadURL[512]={0};
	S_URL surl;
	S_Diagnostic *diagnostic;
	char command[256]={0};

	memset(&surl,0,sizeof(surl));

	while ((ch = getopt(argc, argv, "i:d:p:u:l:")) != -1)
		switch (ch) {
			case 'i':
				strncpy(interface, optarg, sizeof(interface)-1);
				break;
			case 'd':
				dscp = atoi(optarg);
				break;
			case 'p':
				ethernetPriority = atoi(optarg);
				break;
			case 'u':
				strncpy(uploadURL, optarg, sizeof(uploadURL)-1);
				break;
			case 'l'://spec: define type is unsigned int
				testFileLength = strtoul(optarg, NULL, 0);
				break;
			default:
				printf("Usage uploaddiag [-i interface] [-d dscp] [-p ethpriority] [-u uploadURL] [-l testFileLength]\n");
		                return 0;
		}
	DIAGDBG("the interface=%s, dscp=%d, ethernetPriority=%d, uploadURL=%s, testFileLength=%u", interface, dscp, ethernetPriority, uploadURL, testFileLength);
	
	if(parseURL(uploadURL, &surl)<0 || strcmp(surl.uri,"/")==0 || strlen(surl.uri)==0){
		DIAGDBG("parse the uploadURL fail");
		diagnostic = (S_Diagnostic *)malloc(sizeof(struct S_Diagnostic));
		memset(diagnostic, 0, sizeof(struct S_Diagnostic));
		diagnostic->DiagnosticsState = Error_InitConnectionFailed;
		goto err1;
	}
	
	if(strstr(surl.protocol,"http")){
		diagnostic = httpupload(surl, interface, dscp, ethernetPriority, testFileLength);
	}else{
		diagnostic = ftpupload(surl, interface, dscp, ethernetPriority, testFileLength);
	}

err1:
	/*printf("DiagnosticsState=%d, ROMTime=%s, BOMTime=%s, EOMTime=%s, TestBytesReceived=%u, TotalBytesReceived=%u, TotalBytesSent=%u, TCPOpenRequestTime:%s, TCPOpenResponseTime=%s",
	diagnostic->DiagnosticsState, diagnostic->ROMTime, diagnostic->BOMTime, diagnostic->EOMTime,
	       	diagnostic->TestBytesReceived, diagnostic->TotalBytesReceived, diagnostic->TotalBytesSent, 
		diagnostic->TCPOpenRequestTime, diagnostic->TCPOpenResponseTime);*/

	//spec: If the state is anything other than Completed, the values of the results parameters for this test are indeterminate.
	//save_and_notify(TR143_UPLOAD_FILE, diagnostic);

	get_str_time("TCPOpenRequestTime", diagnostic->TCPOpenRequestTime);
	get_str_time("TCPOpenResponseTime", diagnostic->TCPOpenResponseTime);
	get_str_time("ROMTime", diagnostic->ROMTime);
	get_str_time("BOMTime", diagnostic->BOMTime);
	get_str_time("EOMTime", diagnostic->EOMTime);
	

	//sprintf(command, "echo \"HeaderReceived=%d\" >> /tmp/wgetresult", headersize);
	//system(command);
	sprintf(command, "echo \"TotalBytesSent:%d\" >> %s", diagnostic->TotalBytesSent, TR143_UPLOAD_FILE);
	system(command);
	
	if(strstr(surl.protocol,"http"))
	{
		sprintf(command, "echo \"TestBytesSent:%d\" >> %s", httpTestBytesSent, TR143_UPLOAD_FILE);
		system(command);
	}
	else
	{
		sprintf(command, "echo \"TestBytesSent:%d\" >> %s", ftpTestBytesSent, TR143_UPLOAD_FILE);
		system(command);
	}

	free(diagnostic);
	return 0;
}
