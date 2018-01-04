/* TR143 Version 1.0 DownloadDiagnostics
 * support only for the single IPv4 connection
 * HTTP implementation notes:
	-persistent connections MUST be used
	-Pipelining is not supported.
	-The CPE counts the number of bytes received on the Interface for the duration of the test.
	-HTTP authentication is not supported.
	-HTTP headers may be 1.0 or 1.1. HTTPS is not supported.
 * FTP
	-binary transfer mode MUST be used
	-login with anonymous
 * Usage downloaddiag [-i interface] [-d dscp] [-p ethpriority] [-u downloadURL]
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "http.h"
#include "ftp.h"
#include "common.h"

int main (int argc, char *argv[])
{
	int ch;
	char interface[256]={0};
	int dscp=0, ethernetPriority=0;
	char downloadURL[512]={0};
	S_URL surl;
	S_Diagnostic *diagnostic;

	memset(&surl,0,sizeof(surl));

	while ((ch = getopt(argc, argv, "i:d:p:u:")) != -1)
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
				strncpy(downloadURL, optarg, sizeof(downloadURL)-1);
				break;
			default:
				printf("Usage downloaddiag [-i interface] [-d dscp] [-p ethpriority] [-u downloadURL]\n");
				return 0;
		}
	DIAGDBG("the interface=%s, dscp=%d, ethernetPriority=%d, downloadURL=%s", interface, dscp, ethernetPriority, downloadURL);
	if(parseURL(downloadURL,&surl)<0 || strcmp(surl.uri,"/")==0 || strlen(surl.uri)==0){
		DIAGDBG("parse the downloadURL fail");
		diagnostic = (S_Diagnostic *)malloc(sizeof(struct S_Diagnostic));
		memset(diagnostic, 0, sizeof(struct S_Diagnostic));
		diagnostic->DiagnosticsState = Error_InitConnectionFailed;
		goto err1;
	}
	
	if(strstr(surl.protocol,"http")){
		diagnostic = httpdownload(surl, interface, dscp, ethernetPriority);
	}else{
		diagnostic = ftpdownload(surl, interface, dscp, ethernetPriority);
	}

err1:
	printf("DiagnosticsState=%d, ROMTime=%s, BOMTime=%s, EOMTime=%s, TestBytesReceived=%u, TotalBytesReceived=%u, TotalBytesSent=%u, TCPOpenRequestTime:%s, TCPOpenResponseTime=%s",
	diagnostic->DiagnosticsState, diagnostic->ROMTime, diagnostic->BOMTime, diagnostic->EOMTime,
	       	diagnostic->TestBytesReceived, diagnostic->TotalBytesReceived, diagnostic->TotalBytesSent, 
		diagnostic->TCPOpenRequestTime, diagnostic->TCPOpenResponseTime);

	//spec: If the state is anything other than Completed, the values of the results parameters for this test are indeterminate.
	save_and_notify(TR143_DOWNLOAD_FILE, diagnostic);

	free(diagnostic);
	return 0;
}
