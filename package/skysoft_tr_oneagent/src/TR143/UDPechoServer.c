/* TR143 Version 1.0 UDPEchoDiagnostics
 * support UDPEchoPlus
 * Runing when the TR69 configure the "CWMP_UDPEchoConfig.Enable" as 1
 * TO_DO: Gateway have NAT need add port forwarding
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#define BUFSIZE 1024
#define DEF_TIME "0001-01-01T00:00:00Z"

#define PRINTDBG(format, args...)if(debug == 1 ){printf(format, ##args);}

int debug=0;

struct UDPPlus_S{
	unsigned int TestGenSN;
	unsigned int TestRespSN;
	unsigned int TestRespRecvTimeStamp;
	unsigned int TestRespReplyTimeStamp;
	unsigned int TestRespReplyFailureCount;
};

struct UDPServerStat_S{
	unsigned int PacketsReceived;
	unsigned int PacketsResponded;
	unsigned int BytesReceived;
	unsigned int BytesResponded;
	char TimeFirstPacketReceived[64];
	char TimeLastPacketReceived[64];
	unsigned int TestRespSN;
	unsigned int TestRespFC;
};

void getTime(char *timestr, int len){
	time_t now;
	struct tm *tmp;
	struct timeval tv;
        char *format=(char *)malloc(len);
        memset(format, 0, len);

	now=time(NULL);
	tmp = localtime(&now);
	gettimeofday(&tv, NULL);

	strftime(format, len, "%Y-%m-%dT%H:%M:%S.%%06u", tmp);
	snprintf(timestr, len, format, tv.tv_usec);
	free(format);
}

int main(int argc, char **argv) {
	int sockfd;
	int clientlen;
	struct sockaddr_in serveraddr;
	struct sockaddr_in clientaddr;
	//char buf[BUFSIZE]; /* message buf */
	unsigned int buf[BUFSIZE];
	int optval;
	unsigned int len;
	
	int enable=0, UDPPort=0, echoPlusEnabled=0;
	char interface[6]={0};
	char sourceIPAddress[46]={0};
	struct UDPPlus_S *Plusbuf;
	struct UDPServerStat_S *UDPstat;
	
	if(nvram_getf("CWMP_UDPEchoConfig.Enable","%d",&enable)) goto err;
	if(nvram_getf("CWMP_UDPEchoConfig.InterfaceName","%s",interface)) goto err;
	if(nvram_getf("CWMP_UDPEchoConfig.SourceIPAddress","%s",sourceIPAddress)) goto err;
	if(nvram_getf("CWMP_UDPEchoConfig.UDPPort","%d",&UDPPort)) goto err;
	if(nvram_getf("CWMP_UDPEchoConfig.EchoPlusEnabled","%d",&echoPlusEnabled)) goto err;

	if(!enable){
		printf("UDPEchoConfig disable\n");
		return 0;
	}
	
	UDPstat=(struct UDPServerStat_S *)malloc(sizeof(struct UDPServerStat_S));
	memset(UDPstat, 0, sizeof(struct UDPServerStat_S));
	strcpy(UDPstat->TimeFirstPacketReceived, DEF_TIME);
	strcpy(UDPstat->TimeLastPacketReceived, DEF_TIME);

	PRINTDBG("the UDPEchoServer Start......interface=%s, sourceIPAddress=%s, UDPPort=%d, echoPlusEnabled=%d\n", interface, sourceIPAddress, UDPPort, echoPlusEnabled);
	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0){
		printf("ERROR opening socket\n");
		return -1;
	}
	
	optval = 1;
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int))<0){
		printf("setsockopt SO_REUSEADDR error\n");
		return -1;
	}

	if(interface[0]){//bind the interface
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, interface);
		PRINTDBG("setsockopt of SO_BINDTODEVICE\n");
		if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr))<0)
		{
			printf("bind to interface %s fail\n", interface);
			return -1;
		}
	}

	memset((char *) &serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)UDPPort);

	if (bind(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0){//bind the UDP port
		printf("ERROR on binding");
		return -1;
	}

	//reset the stat
	nvram_setf("CWMP_UDPEchoConfig.PacketsReceived","%d",0);
	nvram_setf("CWMP_UDPEchoConfig.PacketsResponded","%d",0);
	nvram_setf("CWMP_UDPEchoConfig.BytesReceived","%d",0);
	nvram_setf("CWMP_UDPEchoConfig.BytesResponded","%d",0);
	nvram_setf("CWMP_UDPEchoConfig.TimeFirstPacketReceived","%s","");
	nvram_setf("CWMP_UDPEchoConfig.TimeLastPacketReceived","%s","");

	//main loop: wait for a datagram, then echo it
	clientlen = sizeof(clientaddr);
	while (1) {
		
		memset(buf, 0, BUFSIZE);
		len = recvfrom(sockfd, buf, BUFSIZE, 0, (struct sockaddr *) &clientaddr, (socklen_t *) &clientlen);
		if (len < 0)
			printf("ERROR in recvfrom\n");

		printf("recv %d bytes:%s from %s:%u \n", len, buf, inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));

		if(sourceIPAddress[0] && strcmp(sourceIPAddress, inet_ntoa(clientaddr.sin_addr))){
			printf("sourceIPAddress is not match, %s != %s\n", sourceIPAddress, inet_ntoa(clientaddr.sin_addr));
			continue;
		}

		if(!strcmp(UDPstat->TimeFirstPacketReceived, DEF_TIME))
			getTime(UDPstat->TimeFirstPacketReceived, sizeof(UDPstat->TimeFirstPacketReceived));
		getTime(UDPstat->TimeLastPacketReceived, sizeof(UDPstat->TimeLastPacketReceived));
		UDPstat->PacketsReceived++;
		UDPstat->BytesReceived += len + 8;

		if(echoPlusEnabled && len >= sizeof(struct UDPPlus_S)){
			Plusbuf = (struct UDPPlus_S*)buf;
			PRINTDBG("======================Receive======================\n");
			PRINTDBG("TestGenSN = %d\r\n", ntohl(Plusbuf->TestGenSN));
			PRINTDBG("TestRespSN = %d\r\n", ntohl(Plusbuf->TestRespSN));
			Plusbuf->TestRespRecvTimeStamp = ntohl(Plusbuf->TestRespRecvTimeStamp);
			PRINTDBG("TestRespRecvTimeStamp = %s", ctime((time_t *)&Plusbuf->TestRespRecvTimeStamp));
			Plusbuf->TestRespReplyTimeStamp = ntohl(Plusbuf->TestRespReplyTimeStamp);
			PRINTDBG("TestTestRespReplyTimeStamp = %s", ctime((time_t *)&Plusbuf->TestRespReplyTimeStamp));
			PRINTDBG("TestRespReplyFailureCount = %d\r\n", ntohl(Plusbuf->TestRespReplyFailureCount));

			Plusbuf->TestRespSN = UDPstat->TestRespSN;
			time((time_t *)&Plusbuf->TestRespRecvTimeStamp);
			time((time_t *)&Plusbuf->TestRespReplyTimeStamp);
			Plusbuf->TestRespReplyFailureCount = UDPstat->TestRespFC;
			
			PRINTDBG("======================Send======================\n");
			PRINTDBG("TestGenSN = %d\r\n", ntohl(Plusbuf->TestGenSN));
			PRINTDBG("TestRespSN = %d\r\n", Plusbuf->TestRespSN);
			PRINTDBG("TestRespRecvTimeStamp = %u, %s", Plusbuf->TestRespRecvTimeStamp, ctime((time_t *)&Plusbuf->TestRespRecvTimeStamp));
			PRINTDBG("TestTestRespReplyTimeStamp = %u, %s", Plusbuf->TestRespReplyTimeStamp, ctime((time_t *)&Plusbuf->TestRespReplyTimeStamp));
			PRINTDBG("TestRespReplyFailureCount = %d\r\n", ntohl(Plusbuf->TestRespReplyFailureCount));
			PRINTDBG("================================================\n");
			//covert to network byte
			Plusbuf->TestRespSN = htonl(Plusbuf->TestRespSN);
			Plusbuf->TestRespRecvTimeStamp = htonl(Plusbuf->TestRespRecvTimeStamp);
			Plusbuf->TestRespReplyTimeStamp = htonl(Plusbuf->TestRespReplyTimeStamp);
			Plusbuf->TestRespReplyFailureCount = htonl(Plusbuf->TestRespReplyFailureCount);	
		}

		if(sendto(sockfd, buf, len, 0, (struct sockaddr *) &clientaddr, clientlen) < 0){
			printf("ERROR in sendto");
			UDPstat->TestRespFC++;
		}else{
			UDPstat->PacketsResponded++;
			UDPstat->BytesResponded += len + 8;
			UDPstat->TestRespSN++;
		}

		//save the stat to nvram
		PRINTDBG("the UDPstat Result ==\n PacketsReceived=%u\n PacketsResponded=%u\n BytesReceived=%u\n BytesResponded=%u\n\
TimeFirstPacketReceived=%s\n TimeLastPacketReceived=%s\n TestRespSN=%u\n TestRespFC=%u\n",\
			UDPstat->PacketsReceived, UDPstat->PacketsResponded, UDPstat->BytesReceived, UDPstat->BytesResponded,\
			UDPstat->TimeFirstPacketReceived, UDPstat->TimeLastPacketReceived, UDPstat->TestRespSN, UDPstat->TestRespFC);
		nvram_setf("CWMP_UDPEchoConfig.PacketsReceived", "%u", UDPstat->PacketsReceived); 
		nvram_setf("CWMP_UDPEchoConfig.PacketsResponded", "%u", UDPstat->PacketsResponded);
		nvram_setf("CWMP_UDPEchoConfig.BytesReceived", "%u", UDPstat->BytesReceived);
		nvram_setf("CWMP_UDPEchoConfig.BytesResponded", "%u", UDPstat->BytesResponded);
		nvram_setf("CWMP_UDPEchoConfig.TimeFirstPacketReceived", "%s", UDPstat->TimeFirstPacketReceived);
		nvram_setf("CWMP_UDPEchoConfig.TimeLastPacketReceived", "%s", UDPstat->TimeLastPacketReceived);
	}
	close(sockfd);

	return 0;
err:
	printf("[%s:%s:%d] Error....\n",__FILE__,__FUNCTION__,__LINE__);
	return -1;
}
