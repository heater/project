/* Writed by ASKEY SH*/

#include <sys/sysinfo.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/timeb.h>
#include <time.h>
#include <sys/time.h>
#ifndef USE_X86
#include <iwinfo.h>
#endif

#include "tr_uciconfig.h"
#include "log.h"
#include "tr_lib.h"
#include "apps.h"
#include "event.h"
#include "system.h"
#include "session.h"

//for SHA1
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include "encrypt.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define MAX_URL_LEN 2048
#define DES3_BYTE 8
#define DES3_PKCS7
static const char hex_chars[] = "0123456789ABCDEF";
//end

char *deviceParameterStart[] = { "<URLBase>", "<major>", "<minor>", "<deviceType>", "<friendlyName>", "<manufacturer>", "<manufacturerURL>", "<modelDescription>", "<modelName>", 
								"<modelNumber>", "<modelURL>", "<serialNumber>", "<UDN>", "<UPC>", "<presentationURL>", NULL }; 
char *deviceParameterEnd[] = { "</URLBase>", "</major>", "</minor>", "</deviceType>", "</friendlyName>", "</manufacturer>", "</manufacturerURL>", "</modelDescription>", "</modelName>", 
								"</modelNumber>", "</modelURL>", "</serialNumber>", "</UDN>", "</UPC>", "</presentationURL>", NULL }; 
char *deviceParameterName[] = { "URLBase", "major", "minor", "deviceType", "friendlyName", "manufacturer", "manufacturerURL", "modelDescription", "modelName", 
								"modelNumber", "modelURL", "serialNumber", "UDN", "UPC", "presentationURL", NULL }; 
char *ServiceParameterStart[] = {"<serviceType>", "<serviceId>", "<SCPDURL>", "<ControlURL>", "<EventSubURL>", NULL};
char *ServiceParameterEnd[] = {"</serviceType>", "</serviceId>", "</SCPDURL>", "</ControlURL>", "</EventSubURL>", NULL};
char *ServiceParameterName[] = {"serviceType", "serviceId", "SCPDURL", "ControlURL", "EventSubURL", NULL};

extern processMaxInstanceNum;
extern session_end;
extern dealayrebootsens;
extern schedulerebootsens;
extern int parameternum;

int runX_CharterRIP = 0;
int restart_network = 0;
int restart_IPv6 = 0;
int restart_Lan_network = 0;
int restart_radvd = 0;
int wifi_restart = 0;
int wifi_radio_restart = 0;
int portmapping_restart = 0;
int dhcp_restart = 0;
int dhcp_num = 0;
int start_upload = 0;
int start_download = 0;
int set_remoteaccess = 0;

a_WifimappingInfo wifi_map[] = {
	{"wireless.wla", "ath0", 10101},
	{"wireless.wla_guest", "ath01", 10102},
	{"wireless.spectrumWiFi5g", "ath02", 10103},
	{"wireless.spectrumWiFi5g_clear", "ath03", 10104},
	{"wireless.wla_hotspot", "ath04", 10105},
	{"wireless.wla_mesh", "mesh0", 10106},
	{"wireless.wla1", "ath05", 10107},
	{"wireless.wla2", "ath06", 10108},
	{"wireless.wlg", "ath1", 10001},
	{"wireless.wlg_guest", "ath11", 10002},
	{"wireless.spectrumWiFi", "ath12", 10003},
	{"wireless.spectrumWiFi_clear", "ath13", 10004},
	{"wireless.wlg_hotspot", "ath14", 10005},
	{"wireless.wlg_mesh", "mesh1", 10006},
	{"wireless.wlg1", "ath15", 10007},
	{"wireless.wlg2", "ath16", 10008},
	{"", "", 0}
};

a_infomparaInfo ip_map[] = {
	{1, "Device.DeviceInfo.SpecVersion", "", 1},
	{1, "Device.DeviceInfo.HardwareVersion", "", 2},
	{1, "Device.DeviceInfo.SoftwareVersion", "", 3},
	{1, "Device.DeviceInfo.ProvisioningCode", "", 4},
	{1, "Device.ManagementServer.ConnectionRequestURL", "", 5},
	{1, "Device.ManagementServer.ParameterKey", "", 6},
	{1, "Device.Ethernet.Interface.1.MACAddress", "", 7},
	{1, "Device.ManagementServer.AliasBasedAddressing", "", 8},
	{0, "", "", 0}
};	

a_WifiradiomappingInfo wifiradio_map[] = {
	{5, 0, 10100},
	{24, 1, 10000},
	{-1, -1, -1},
};

a_LanmappingInfo lan_map[] = {
	{1, "network.lan", "lan", "br-lan", 200},
	{0, "network.lan1", "lan1", "br-lan1", 201},
	{0, "network.lan2", "lan2", "br-lan2", 202},
	{0, "network.lan3", "lan3", "br-lan3", 203},
	{-1, "", "", "", -1},
};


void getLanInterfaceNameWithInstanceNum(char *p, char *buff)
{
	int i;
	for (i = 0; i < IP_LAN_INSTANCE_NUM; i ++){
		if (atoi(p) == lan_map[i].num){
			strcpy(buff, lan_map[i].laninf);
			printf("====Lan Interface [%s]\n", buff);
		}
	}
}

void getLanInterfaceNameWithInstanceNum2(int p, char *buff)
{
	int i;
	for (i = 0; i < IP_LAN_INSTANCE_NUM; i ++){
		if (p == lan_map[i].num){
			strcpy(buff, lan_map[i].laninf);
			printf("====Lan Interface [%s]\n", buff);
		}
	}
}

void getLanUbsInterfaceNameWithInstanceNum(char *p, char *buff)
{
	int i;
	for (i = 0; i < IP_LAN_INSTANCE_NUM; i ++){
		if (atoi(p) == lan_map[i].num){
			strcpy(buff, lan_map[i].ubsinf);
			printf("====Lan UBS Interface [%s]\n", buff);
		}
	}
}

void getLanUbsInterfaceNameWithInstanceNum2(int p, char *buff)
{
	int i;
	for (i = 0; i < IP_LAN_INSTANCE_NUM; i ++){
		if (p == lan_map[i].num){
			strcpy(buff, lan_map[i].ubsinf);
			printf("====Lan UBS Interface [%s]\n", buff);
		}
	}
}

void getLanUciPathWithInstanceNum(char *p, char *buff)
{
	int i;
	for (i = 0; i < IP_LAN_INSTANCE_NUM; i ++){
		if (atoi(p) == lan_map[i].num){
			strcpy(buff, lan_map[i].uci_path);
			printf("====Lan UCI sub path [%s]\n", buff);
		}
	}
}

int getLanIPv6CapableWithInstanceNum(char *p)
{
	int i;
	for (i = 0; i < IP_LAN_INSTANCE_NUM; i ++){
		if (atoi(p) == lan_map[i].num){
			printf("====Lan IP ipv6 Capable [%d]\n", lan_map[i].ipv6);
			return lan_map[i].ipv6;
		}
	}

	return 0;
}

int getLanIPInstanceNum(char *p)
{
	int i;
	for (i = 0; i < IP_LAN_INSTANCE_NUM; i ++){
		if ((atoi(p)-1) == i){
			printf("====Lan IP Instance Number [%d]\n", lan_map[i].num);
			return lan_map[i].num;
		}
	}

	return 0;
}

int getLanIPInstanceNumWithInterfaceName(char *inf)
{
	int i;
	for (i = 0; i < WIFI_MAX_INSTANCE_NUM; i ++){
		if (strcmp(inf, lan_map[i].laninf) == 0)
			return lan_map[i].num;
	}

	return 0;
}

int getinformparaEnbl(char *p, char *buff)
{
	int i;

	for (i = 0; i < INFORMPARA_MAX_INSTANCE_NUM; i ++){
		if (atoi(p) == ip_map[i].num)
		{
			sprintf(buff, "%d", ip_map[i].Enable);
			return 0;
		}
	}
	return 1; 
}

int getinformparaName(char *p, char *buff)
{
	int i;

	for (i = 0; i < INFORMPARA_MAX_INSTANCE_NUM; i ++){
		if (atoi(p) == ip_map[i].num)
		{
			sprintf(buff, "%s", ip_map[i].ParameterName);
			return 0;
		}
	}
	return 1;
}

int getinformparaEvent(char *p, char *buff)
{
	int i;

	for (i = 0; i < INFORMPARA_MAX_INSTANCE_NUM; i ++){
		if (atoi(p) == ip_map[i].num)
		{
			sprintf(buff, "%s", ip_map[i].EventList);
			return 0;
		}
	}
	return 1;
}

void get_time(char *name)
{
	struct timeval tv;
	struct tm *lt;
	char str[100] = {0};
	char timestr[64] = {0};
	FILE *fp = NULL;
	char buff[128] = {0};

	gettimeofday(&tv, NULL);
	lt = localtime(&(tv.tv_sec));
	strftime(str,100,"%Y-%m-%dT%H:%M:%S",lt);
	sprintf(timestr, "%s.%dZ", str, tv.tv_usec);
	printf("%s\n", timestr);	  

	fp = fopen("/tmp/udpechoresult", "a");

	if(fp != NULL)
	{
		sprintf(buff, "%s=%s\n", name, timestr);
		fputs(buff, fp);		
		fclose(fp);
	}
}

int udpecho(char *host, char *port, int num, int timeout, int size, int interval)
{
	struct sockaddr_in si_other;
	int s, slen=sizeof(si_other);
	struct echo_plus_st *eps;
	char buf[1024] = {0};
	int res = 0;
    struct timeval tv;
    fd_set readfds;
    int i=0;
    unsigned int n=0;
	int SuccessCount = 0;
	int FailureCount = 0;
	double AverageResponseTime = 0;
	double MinimumResponseTime = 0;
	double MaximumResponseTime = 0;
	struct timeval tv1;
	char buff1[128] = {0};
	char buff2[128] = {0};
	double responsetime = 0;
	double sum = 0;
	char name[128] = {0};
	char command[128] = {0};

	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1) {
		fprintf(stderr, "Create socket failed: %s\n", strerror(errno));
		return -1;
	}

	memset((char *) &si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(atoi(port));
	if (inet_aton(host, &si_other.sin_addr)==0) {
		fprintf(stderr, "inet_aton() failed: %s\n", strerror(errno));
		return -1;
	}
	system("rm /tmp/udpechoresult");
	for(i=1; i<=num; i++)
	{
		eps = calloc(sizeof(*eps) + size, 1);
		memset(eps, 0, sizeof(*eps) + size);
		eps->test_gen_sn = i;
		sendto(s, eps, sizeof(*eps) + size, 0, (struct sockaddr *)&si_other, slen);
		sprintf(name, "PacketSendTime%d", i);
		get_time(name);
		sprintf(name, "TestGenSN%d", i);
		sprintf(command,"echo \"%s=%d\" >> /tmp/udpechoresult", name, eps->test_gen_sn);		
		system(command);
		printf("%s\n", command);
		gettimeofday(&tv, NULL);
		sprintf(buff1, "%d.%06d", tv.tv_sec, tv.tv_usec);
		free(eps);
		FD_ZERO(&readfds);
		FD_SET(s,&readfds);
		tv.tv_sec = 0;
		tv.tv_usec = timeout * 1000;
		select(s+1,&readfds,NULL,NULL,&tv);
		printf("debug %d\n", i);
		if(FD_ISSET(s,&readfds))
		{
			sprintf(name, "PacketReceiveTime%d", i);
			get_time(name);
			if((res = recvfrom(s, buf, sizeof(buf) - 1, 0, NULL, NULL)) < 0)
			{
				return -1;
			}
			buf[res] = 0;
			eps = (struct echo_plus_st *)buf;
			
			gettimeofday(&tv, NULL);
			sprintf(buff2, "%d.%06d", tv.tv_sec, tv.tv_usec);
			sprintf(name, "PacketSuccess%d", i);
			sprintf(command,"echo \"%s=1\" >> /tmp/udpechoresult", name);
			system(command);
			sprintf(name, "TestRespSN%d", i);
			sprintf(command,"echo \"%s=%d\" >> /tmp/udpechoresult", name, eps->test_resp_sn);
			system(command);
			sprintf(name, "TestRespRcvTimeStamp%d", i);
			sprintf(command,"echo \"%s=%d\" >> /tmp/udpechoresult", name, eps->recv_ts);			
			system(command);
			sprintf(name, "TestRespReplyTimeStamp%d", i);
			sprintf(command,"echo \"%s=%d\" >> /tmp/udpechoresult", name, eps->reply_ts);
			system(command);
			sprintf(name, "TestRespReplyFailureCount%d", i);
			sprintf(command,"echo \"%s=0\" >> /tmp/udpechoresult", name);
			system(command);
			SuccessCount++;
			responsetime = atof(buff2) - atof(buff1);
		}
		else
		{
			sprintf(name, "PacketSuccess%d", i);
			sprintf(command,"echo \"%s=0\" >> /tmp/udpechoresult", name);
			system(command);
			sprintf(name, "TestRespSN%d", i);
			sprintf(command,"echo \"%s=%d\" >> /tmp/udpechoresult", name, eps->test_resp_sn);
			system(command);
			sprintf(name, "TestRespRcvTimeStamp%d", i);
			sprintf(command,"echo \"%s=%d\" >> /tmp/udpechoresult", name, eps->recv_ts);
			system(command);
			sprintf(name, "TestRespReplyTimeStamp%d", i);
			sprintf(command,"echo \"%s=%d\" >> /tmp/udpechoresult", name, eps->reply_ts);
			system(command);
			sprintf(name, "TestRespReplyFailureCount%d", i);
			sprintf(command,"echo \"%s=%d\" >> /tmp/udpechoresult", name, eps->fail_count);
			system(command);
			sprintf(name, "PacketReceiveTime%d", i);
			sprintf(command, "echo \"%s= 0001-01-01T00:00:00Z\" >> /tmp/udpechoresult", name);
			system(command);
			FailureCount++;
		}
		usleep(interval * 1000);
		sum = sum + responsetime;
		if(MaximumResponseTime < responsetime)
		{
			MaximumResponseTime = responsetime;
		}

		if((MinimumResponseTime > responsetime) || (MinimumResponseTime == 0))
		{
			MinimumResponseTime = responsetime;
		}
	}

	AverageResponseTime = sum / num;
	printf("SuccessCount %d\n", SuccessCount);
	printf("FailureCount %d\n", FailureCount);
	printf("MaximumResponseTime %f\n", MaximumResponseTime);
	printf("MinimumResponseTime %f\n", MinimumResponseTime);
	printf("AverageResponseTime %f\n", AverageResponseTime);
	sprintf(command,"echo \"SuccessCount=%d\" >> /tmp/udpechoresult", SuccessCount);
	system(command);
	sprintf(command,"echo \"FailureCount=%d\" >> /tmp/udpechoresult", FailureCount);
	system(command);
	sprintf(command,"echo \"MaximumResponseTime=%f\" >> /tmp/udpechoresult", MaximumResponseTime);
	system(command);
	sprintf(command,"echo \"MinimumResponseTime=%f\" >> /tmp/udpechoresult", MinimumResponseTime);
	system(command);
	sprintf(command,"echo \"AverageResponseTime=%f\" >> /tmp/udpechoresult", AverageResponseTime);
	system(command);
	
	close(s);
	return 0;
}

int upnpdevice()
{
	FILE *fp;
	FILE *fp1;
	int file_size;
	char *tmp = NULL;
    char line[256] = {0};
	char command[128] = {0};
	char location[128] = {0};
	char *m = NULL;
	char *n = NULL;
	int count = 1;
	int count1 = 1;
	char *p = NULL;
	char *q = NULL;
	char *s = NULL;
	int i = 0;
	int num = 1;	
	char value[256]= {0};
	int DeviceInstanceNumberOfEntries = 0;
	int RootDeviceNumberOfEntries = 0;

	system("rm /tmp/upnpdevice");
	fp = fopen("/tmp/NOTIFY" , "r");
	if(fp != NULL)
	{
        while ( fgets(line, sizeof(line), fp) ) 
		{
			if(strcasestr(line, "LOCATION") != NULL)
			{
				m = strcasestr(line, "http");
				n = strstr(line, "xml");
				if((m == NULL) || (n == NULL))
				{
					continue;
				}
				memset(location, 0, sizeof(location));
				strncpy(location, m, n+3-m);
				printf("m: %s\n", m);
				if(m != NULL)
				{
					system("rm /tmp/rootDesc.xml");
					sprintf(command, "curl --connect-timeout 5 %s -o /tmp/rootDesc.xml", location);
					printf("command: %s\n", command);
					system(command);
					fp1 = fopen("/tmp/rootDesc.xml" , "r");
					if(fp1 != NULL)
					{
						fseek( fp1 , 0 , SEEK_END );
						
						file_size = ftell( fp1 );
						fseek( fp1 , 0 , SEEK_SET);
						
						tmp =  (char *)malloc( (file_size + 1) * sizeof( char ) );
						if(tmp == NULL)
						{
							continue;
						}
						fread( tmp , file_size , sizeof(char) , fp1);
						tmp[file_size] = '\0';
						//printf("%s" , tmp );
						fclose(fp1);
						RootDeviceNumberOfEntries++;
					}
					else
					{
						continue;
					}
										
					if((fp1 = fopen("/tmp/upnpdevice", "a"))!= NULL)
					{
						i = 0;
						while(deviceParameterStart[i] != NULL)
						{
							p = tmp;
							num = count1;
							while((q = strcasestr(p, deviceParameterStart[i])) != NULL)
							{
								memset(value, 0, sizeof(value));
								if((s = strcasestr(q, deviceParameterEnd[i])) != NULL)
								{
									strncpy(value, q+strlen(deviceParameterStart[i]), s-(q+strlen(deviceParameterStart[i])));
									p = s + strlen(deviceParameterEnd[i]);
									fprintf(fp1, "%s%d=%s\n", deviceParameterName[i], num, value);
									if(i == 3)
									{
										fprintf(fp1, "ParentDevice%d=%d\n", num, RootDeviceNumberOfEntries);
									}
								}
								num++;
							}
							if(i == 3)
							{
								DeviceInstanceNumberOfEntries = num - 1;
								count = num;
							}
							i++;
						}
						fclose(fp1);
					}	
					free(tmp);					
				}
			}
			count1 = count;
    	}
		fclose(fp);
	}
	
	if((fp1 = fopen("/tmp/upnpdevice", "a"))!= NULL)
	{
		fprintf(fp1, "DeviceInstanceNumberOfEntries=%d\n", DeviceInstanceNumberOfEntries);
		fprintf(fp1, "RootDeviceNumberOfEntries=%d\n", RootDeviceNumberOfEntries);
		fprintf(fp1, "DeviceNumberOfEntries=%d\n", DeviceInstanceNumberOfEntries-RootDeviceNumberOfEntries);	
		fclose(fp1);
	}
	else
	{
		return 1;
	}
}

int upnpservice()
{
	FILE *fp;
	FILE *fp1;
	int file_size;
	char *tmp = NULL;
	char line[256] = {0};
	char command[128] = {0};
	char location[128] = {0};
	char *m = NULL;
	char *n = NULL;
	int count = 1;
	int count1 = 1;
	char *p = NULL;
	char *q = NULL;
	char *s = NULL;
	int i = 0;
	int num = 1;	
	char value[256]= {0};
	int ServiceInstanceNumberOfEntries = 0;
	int RootDeviceNumberOfEntries = 0;

	system("rm /tmp/upnpservice");
	fp = fopen("/tmp/NOTIFY" , "r");
	if(fp != NULL)
	{
		while ( fgets(line, sizeof(line), fp) ) 
		{
			if(strcasestr(line, "LOCATION") != NULL)
			{
				m = strcasestr(line, "http");
				n = strstr(line, "xml");
				if((m == NULL) || (n == NULL))
				{
					continue;
				}
				memset(location, 0, sizeof(location));
				strncpy(location, m, n+3-m);
				printf("m: %s\n", m);
				if(m != NULL)
				{
					system("rm /tmp/rootDesc.xml");
					sprintf(command, "curl --connect-timeout 5 %s -o /tmp/rootDesc.xml", location);
					printf("command: %s\n", command);
					system(command);
					fp1 = fopen("/tmp/rootDesc.xml" , "r");
					if(fp1 != NULL)
					{
						fseek( fp1 , 0 , SEEK_END );
						
						file_size = ftell( fp1 );
						fseek( fp1 , 0 , SEEK_SET);
						
						tmp =  (char *)malloc( (file_size + 1) * sizeof( char ) );
						if(tmp == NULL)
						{
							continue;
						}
						fread( tmp , file_size , sizeof(char) , fp1);
						tmp[file_size] = '\0';
						//printf("%s" , tmp );
						fclose(fp1);
						RootDeviceNumberOfEntries++;
					}
					else
					{
						continue;
					}
					
					if((fp1 = fopen("/tmp/upnpservice", "a"))!= NULL)
					{
						i = 0;
						while(ServiceParameterStart[i] != NULL)
						{
							p = tmp;
							num = count1;
							while((q = strcasestr(p, ServiceParameterStart[i])) != NULL)
							{
								memset(value, 0, sizeof(value));
								if((s = strcasestr(q, ServiceParameterEnd[i])) != NULL)
								{
									strncpy(value, q+strlen(ServiceParameterStart[i]), s-(q+strlen(ServiceParameterStart[i])));
									p = s + strlen(ServiceParameterEnd[i]);
									fprintf(fp1, "%s%d=%s\n", ServiceParameterName[i], num, value);
									if(i == 3)
									{
										fprintf(fp1, "ParentDevice%d=%d\n", num, RootDeviceNumberOfEntries);
									}
								}
								num++;
							}
							if(i == 0)
							{
								ServiceInstanceNumberOfEntries = num - 1;
								count = num;
							}
							i++;
						}
						fclose(fp1);
					}	
					free(tmp);					
				}
			}
			count1 = count;
		}
		fclose(fp);
	}
	printf("####################### ServiceInstanceNumberOfEntries = %d\n", ServiceInstanceNumberOfEntries);	
	if((fp1 = fopen("/tmp/upnpservice", "a"))!= NULL)
	{
		fprintf(fp1, "ServiceInstanceNumberOfEntries=%d\n", ServiceInstanceNumberOfEntries);
		fprintf(fp1, "ServiceNumberOfEntries=%d\n", ServiceInstanceNumberOfEntries);
		fclose(fp1);
	}
	else
	{
		return 1;
	}
	return 0;
}

/*To get  node index
sample: path=Device.WiFi.NeighboringWiFiDiagnostic.Result.4.BSSID
	     option=.Result.
*/		
char *parseTemplate(char *path, char *option)
{
    char *p = NULL;
    char *q = NULL;

    if((p = strstr(path, option)) != NULL){
        p = p + strlen(option);
        if((q = strstr(p, ".")) != NULL)
            *q = '\0';
        else
            return NULL;
    }
    else
        return NULL;

    return p;
}

void toSaveMapFile(char *mapfile, char *instance, char * value)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i = 0;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);

	lib_read_mapfile(mapfile,mapInfos,MAXMAPITEMS); //read mapfile first
	for(i=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].instance  == atoi(instance))
		{
			strcpy(mapInfos[i].value, value);
			break;
		}
	}
	
	lib_save_mapfile(mapfile,mapInfos,MAXMAPITEMS);
}

void getMfcInfo(char * name, char *value)
{
    char line[256] = {0};
    char *tmpName = NULL;
    char *tmpValue = NULL;
    char *tmpValue1 = NULL;
    FILE *fp = NULL;

    if ((fp = fopen("/tmp/mf_info.txt", "r")) != NULL) {
        while ( fgets(line, sizeof(line), fp) ) {
            tmpName=strtok(line," ");
            if (strcmp(tmpName, name) == 0){
            	tmpValue1=strtok(NULL,"[");
            	tmpValue=strtok(NULL,"]");
	            strcpy(value, tmpValue);
				break;
            }
        }
        fclose(fp);
    }
    else
       strcpy(value, "");
}

void getMfcInfo2(char * name, char *value)
{
    char line[256] = {0};
    char *tmpName = NULL;
    char *tmpValue = NULL;
    FILE *fp = NULL;

    if ((fp = fopen("/etc/system_version.info", "r")) != NULL) {
        while ( fgets(line, sizeof(line), fp) ) {
            tmpName=strtok(line,"=");
            if (strcmp(tmpName, name) == 0){
            	tmpValue=strtok(NULL,"\"");
	            strcpy(value, tmpValue);
				break;
            }
        }
        fclose(fp);
    }
    else
       strcpy(value, "");
}

void getProcessStatus(char *pid, char *value, char *string)
{
	FILE *fp = NULL;
	char line[2048] = {0};
	char col[18][64];
	char stat_filename[64] = {0};
	char *ptr = NULL, *prt1 = NULL;
	if (strcmp(string, "Command") == 0 || strcmp(string, "Priority") == 0 || strcmp(string, "CPUTime") == 0){
		sprintf(stat_filename, "/proc/%s/stat", pid);
		if ((fp = fopen(stat_filename, "r")) != NULL) {
			fgets(line, sizeof(line), fp);
			sscanf(line, "%s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s ",
        		col[0], col[1], col[2], col[3], col[4], col[5], col[6],
        		col[7], col[8], col[9], col[10], col[11], col[12], col[13],
        		col[14], col[15], col[16], col[17]);
			//command
			if (strcmp(string, "Command") == 0){
				ptr=strtok(col[1]+1,")");
				if (ptr != NULL)
					strcpy(value, ptr);
				else
					strcpy(value, col[1]);
			}
    		//priority
    		if (strcmp(string, "Priority") == 0)
				strcpy(value, col[17]);
			//cputime
			if (strcmp(string, "CPUTime") == 0){
				unsigned int HZ = sysconf(_SC_CLK_TCK);
				sprintf(value, "%u", 1000/HZ * (strtoul(col[13], NULL, 0) + strtoul(col[14], NULL, 0)));
			}
			fclose(fp);
		}
	}

	if (strcmp(string, "State") == 0 || strcmp(string, "Size") == 0){
		sprintf(stat_filename, "cat /proc/%s/status", pid);
		if ((fp = popen(stat_filename, "r")) != NULL) {
			memset(line, 0, sizeof(line));
			while (fgets(line, sizeof(line), fp)) {
				//State
				if (strcmp(string, "State") == 0){
					if ((ptr = strstr(line, "State:")) != NULL) {
						if ((prt1 = strchr(ptr + sizeof("State:"), '\n')) != NULL)
							*prt1 = '\0';
						strcpy(value, ptr + sizeof("State:"));
					}
				}
				//Size
				if (strcmp(string, "Size") == 0){
					if (strstr(line, "VmSize:") != NULL) {
						char size[2][64];
						sscanf(line, "%s %s ", size[0], size[1]);
						strcpy(value, size[1]);
					}
				}
				memset(line, 0, sizeof(line));
			}
			pclose(fp);
		}
	}
}

void getDevStatus(char *inf, char *key, char *value)
{
	FILE *fp = NULL;
	char line[512] = {0};
	char col[2][256];
	char cmd[64] = {0};
	char *ptr = NULL;
	int found = 0;
	
	sprintf(cmd, "/sbin/devstatus %s | sed 's/\"//g'", inf);
	if ((fp = popen(cmd, "r")) != NULL) {
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, key) != NULL) {
				sscanf(line, "%s %s", col[0], col[1]);
				if ((ptr = strstr(col[1], ",")) != NULL)
					*ptr= '\0';
				strcpy(value, col[1]);
				found = 1;
				break;
			}
			memset(line, 0, sizeof(line));
		}
		pclose(fp);
	}
	
	if (found == 0) 
		strcpy(value, "0");
}

int get_DHCPv4_Server_Pool_Client_num(int index)
{
    FILE *fp = NULL;
    char line[128] = {0};
    int i = 0;
	char ipsubnet[32] = {0};
	char clientip[32] = {0};
	char path[64] = {0};
	char *ptr = NULL;

	//to get ip subnet
	if (index == 1)
		strcpy(path, "dhcp.lan.start");
	else
		sprintf(path, "dhcp.lan%d.start", index-1);
	do_uci_get(path, ipsubnet);
	if (strcmp(ipsubnet, "") != 0){
		if ((ptr = strrchr(ipsubnet, '.')) != NULL)
			*ptr = '\0';
		printf("==########=====ipsubnet1=%s\n", ipsubnet);
	}

	if ((fp = fopen("/tmp/dhcp.leases","r")) != NULL) {
    	while (fgets(line, sizeof(line), fp)){
			memset(clientip, 0, sizeof(clientip));
			sscanf(line,"%*s %*s %s %*s",clientip);
			if (strcmp(clientip, "") != 0){
				if ((ptr = strrchr(clientip, '.')) != NULL)
					*ptr = '\0';
				printf("==########=====clientip=%s\n", clientip);
				if (strcmp(ipsubnet, clientip) == 0)
					i++;
			}
    	}
    	fclose(fp);
	}

    return i;
}

/* key is the mac address */
void get_DHCPv4_Server_Pool_Client_info(char *key, char *value, char *string)
{
	FILE *fp = NULL;
    char line[128] = {0};
	char clientinfo[4][128];
	
	if((fp=fopen("/tmp/dhcp.leases","r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp)){
			memset(clientinfo, 0, sizeof(clientinfo));
			sscanf(line,"%s %s %s %s %*s",clientinfo[0], clientinfo[1], clientinfo[2], clientinfo[3]);
			if (strcasecmp(key, clientinfo[1]) == 0){
				if (strcmp(string, "LeaseTime") == 0){
					strcpy(value, clientinfo[0]);
					break;
				}
				if (strcmp(string, "MacAddress") == 0){
					strcpy(value, clientinfo[1]);
					break;
				}
				if (strcmp(string, "IpAddress") == 0){
					strcpy(value, clientinfo[2]);
					break;
				}
				if (strcmp(string, "HostName") == 0){
					strcpy(value, clientinfo[3]);
					break;
				}
			}
    	}
    	fclose(fp);
	}
}

void get_DHCPv4_Server_Pool_Client_entry_path(char *key, char *inf, char *value)
{
	FILE *fp = NULL;
    char line[128] = {0};
	char index[32] = {0};
	char filename[64] = {0};
	int num = 0;
	int i = 0;

	for (i = 1; i <= IP_LAN_INSTANCE_NUM; i ++){
		sprintf(filename, "/oneagent/conf/DHCPv4ServerPool%dClientMap.mapping", i);
		if((fp=fopen(filename,"r")) != NULL){
			while(fgets(line,sizeof(line)-1,fp)){
				if (strstr (line, key) != NULL){
					sscanf(line,"%s %*s", index);
					if (strstr(inf, "br-lan") != NULL){
						num = strlen("br-lan");
						if (inf[num] != '\0')
							sprintf(value, "Device.DHCPv4.Server.Pool.%d.Client.%s", atoi(inf+num)+1, index);
						else
							sprintf(value, "Device.DHCPv4.Server.Pool.1.Client.%s", index);
					}
					else
						sprintf(value, "Device.DHCPv4.Server.Pool.1.Client.%s", index);
					break;
				}
	    	}
	    	fclose(fp);
		}
	}
}

void get_Layer3Interface_path(char *inf, char *value)
{
	sprintf(value, "Device.IP.Interface.%d", getLanIPInstanceNumWithInterfaceName(inf));
}

/* key is the mac address */
void get_Hosts_Host_info(char *key, char *value, char *string)
{
	FILE *fp = NULL;
    char line[128] = {0};
	char clientinfo[6][128];
	
	if((fp=fopen("/proc/net/arp","r")) != NULL){
		fgets(line,sizeof(line)-1,fp);
		while(fgets(line,sizeof(line)-1,fp)){
			memset(clientinfo, 0, sizeof(clientinfo));
			sscanf(line,"%s %s %s %s %s %s",clientinfo[0], clientinfo[1], clientinfo[2], clientinfo[3],clientinfo[4], clientinfo[5]);
			if (strcasecmp(key, clientinfo[3]) == 0){
				if (strcmp(string, "ip") == 0){
					strcpy(value, clientinfo[0]);
					break;
				}
				if (strcmp(string, "mac") == 0){
					strcpy(value, clientinfo[3]);
					break;
				}
				if (strcmp(string, "l3dev") == 0){
					strcpy(value, clientinfo[5]);
					break;
				}
			}
    	}
    	fclose(fp);
	}
}

void get_DHCPv4_Server_Pool_1_StaticAddress_info(char *key, char *value, char *string)
{
	FILE *fp = NULL;
    char line[128] = {0};
	char staticipinfo[2][32];
	char * ptr = NULL;
	
	if((fp=fopen("/etc/ethers","r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp)){
			memset(staticipinfo, 0, sizeof(staticipinfo));
			sscanf(line,"%s %s",staticipinfo[0], staticipinfo[1]);
			if((ptr = strstr(staticipinfo[1],"\n")) != NULL)
					*ptr = '\0';
				if(strcmp(staticipinfo[1], "") == 0)
					continue;
			if (strcmp(key, staticipinfo[1]) == 0){
				if (strcmp(string, "mac") == 0){
					strcpy(value, staticipinfo[0]);
					break;
				}
				if (strcmp(string, "ip") == 0){
					strcpy(value, staticipinfo[1]);
					break;
				}
			}
    	}
    	fclose(fp);
	}
}

void set_DHCPv4_Server_Pool_1_StaticAddress_info(char *key, char *value, char *string)
{
	FILE *fp = NULL;
    char line[128] = {0};
	char staticipinfo[2][32];
	char * ptr = NULL;
    int i = 0, j = 0;
	a_Dhcpv4StaticIpInfo ipinfo[MAXMAPITEMS];

	memset(ipinfo, 0, sizeof(a_Dhcpv4StaticIpInfo)*MAXMAPITEMS);
	
	if((fp=fopen("/etc/ethers","r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp)){
			i++;
			memset(staticipinfo, 0, sizeof(staticipinfo));
			sscanf(line,"%s %s",staticipinfo[0], staticipinfo[1]);
			if((ptr = strstr(staticipinfo[1],"\n")) != NULL)
					*ptr = '\0';
				if(strcmp(staticipinfo[1], "") == 0){
					i --;
					continue;
				}
			if (strcmp(key, staticipinfo[1]) == 0){
				if (strcmp(string, "mac") == 0)
					strcpy(staticipinfo[0], value);
				if (strcmp(string, "ip") == 0)
					strcpy(staticipinfo[1], value);
				if (strcmp(string, "del") == 0){
					i --;
					continue;
				}
			}
			strcpy(ipinfo[i-1].mac, staticipinfo[0]);
			strcpy(ipinfo[i-1].ip, staticipinfo[1]);
    	}
    	fclose(fp);
	}

	if (i == 0)
		system("echo > /etc/ethers");
	else{
		for (j = 0; j < i; j ++){
			memset(line, 0, sizeof(line));
			if (j == 0)
				sprintf(line, "echo %s %s > /etc/ethers", ipinfo[j].mac, ipinfo[j].ip);
			else
				sprintf(line, "echo %s %s >> /etc/ethers", ipinfo[j].mac, ipinfo[j].ip);

			system(line);
		}
	}
}

/* get ReservedAddresses list */
void get_DHCPv4_Server_Pool_1_ReservedAddresses_list(char *value)
{
	FILE *fp = NULL;
    char line[128] = {0};
	char reservedIp[32] = {0};
	char * ptr = NULL;
    int i = 0;
	
	if((fp=fopen("/etc/ethers","r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp) && i < 32){ //ACS defined: the largest item is 32 
			i++;
			memset(reservedIp, 0, sizeof(reservedIp));
			sscanf(line,"%*s %s", reservedIp);
			if((ptr = strstr(reservedIp,"\n")) != NULL)
					*ptr = '\0';
			if(strcmp(reservedIp, "") == 0)
				continue;
			if (value[0] == '\0')
				strcpy(value, reservedIp);
			else
				sprintf(value, "%s,%s", value, reservedIp);

    	}
    	fclose(fp);
	}
	else
		strcpy(value, "");

	return i;
}

void getInterfaceInfo(char *inf, a_infinfo *wandeviceinfo)
{
	FILE *fd = NULL;
	char line[128] = {0};
	char *ptr = NULL;
	char cmd[128] = {0};

	sprintf(cmd, "ubus call network.interface.%s status | sed 's/\"//g'", inf);
	if ((fd = popen(cmd, "r")) != NULL){
		while(fgets(line,sizeof(line)-1,fd)){
			if (strstr(line, "up: true") != NULL){
				wandeviceinfo->status = 1;
				continue;
			}
			if(strstr(line, "uptime:") != NULL){
				sscanf(line, "%*s %s", wandeviceinfo->uptime);
				if((ptr = strstr(wandeviceinfo->uptime,",")) != NULL)
					*ptr = '\0';
				continue;
			}
			if(strstr(line, "l3_device:") != NULL){
				sscanf(line, "%*s %s", wandeviceinfo->l3_device);
				if((ptr = strstr(wandeviceinfo->l3_device,",")) != NULL)
					*ptr = '\0';
				continue;
			}
			if (strstr(line, "proto:") != NULL){
				sscanf(line, "%*s %s", wandeviceinfo->proto);
				if((ptr = strstr(wandeviceinfo->proto,",")) != NULL)
					*ptr = '\0';
				continue;
			}
			if (strstr(line, "device:") != NULL){
                sscanf(line, "%*s %s", wandeviceinfo->device);
                if((ptr = strstr(wandeviceinfo->device,",")) != NULL)
                    *ptr = '\0';
				continue;
            }
			if (strstr(line, "ipv4-address:") != NULL){
                while(fgets(line,sizeof(line)-1,fd)){
					if (strstr(line, "],") == NULL){
	                    if (strstr(line, "address:") != NULL){
	                        sscanf(line, "%*s %s", wandeviceinfo->ipv4_address);
	                        if((ptr = strstr(wandeviceinfo->ipv4_address,",")) != NULL)
	                            *ptr = '\0';
	                        //break;
	                    }
						if (strstr(line, "mask:") != NULL){
	                        sscanf(line, "%*s %s", wandeviceinfo->mask);
	                        if((ptr = strstr(wandeviceinfo->mask,",")) != NULL)
	                            *ptr = '\0';
	                        break;
	                    }
					}
					else
						break;
                }
                continue;
            }
			if (strstr(line, "ipv6-address:") != NULL){
                while(fgets(line,sizeof(line)-1,fd)){
					if (strstr(line, "],") == NULL){
	                    if (strstr(line, "address:") != NULL){
	                        sscanf(line, "%*s %s", wandeviceinfo->ipv6_address);
	                        if((ptr = strstr(wandeviceinfo->ipv6_address,",")) != NULL)
	                            *ptr = '\0';
	                        //break;
	                    }
						if (strstr(line, "mask:") != NULL){
	                        sscanf(line, "%*s %s", wandeviceinfo->ipv6_mask);
	                        if((ptr = strstr(wandeviceinfo->ipv6_mask,",")) != NULL)
	                            *ptr = '\0';
	                        break;
	                    }
					}
					else
						break;
                }
                continue;
            }
			if (strstr(line, "ipv6-prefix:") != NULL){
                while(fgets(line,sizeof(line)-1,fd)){
					if (strstr(line, "],") == NULL){
	                    if (strstr(line, "address:") != NULL){
	                        sscanf(line, "%*s %s", wandeviceinfo->ipv6_prefix_address);
	                        if((ptr = strstr(wandeviceinfo->ipv6_prefix_address,",")) != NULL)
	                            *ptr = '\0';
	                        //break;
	                    }
						if (strstr(line, "mask:") != NULL){
	                        sscanf(line, "%*s %s", wandeviceinfo->ipv6_prefix_mask);
	                        if((ptr = strstr(wandeviceinfo->ipv6_prefix_mask,",")) != NULL)
	                            *ptr = '\0';
	                        break;
	                    }
					}
					else
						break;
                }
                continue;
            }
			if (strstr(line, "route:") != NULL){
				while(fgets(line,sizeof(line)-1,fd)){
					if (strstr(line, "],") == NULL){
						if (strstr(line, "nexthop:") != NULL && strstr(line, "0.0.0.0") == NULL){ //ingor 0.0.0.0 ip address
	                		sscanf(line, "%*s %s", wandeviceinfo->nexthop);
	                		if((ptr = strstr(wandeviceinfo->nexthop,",")) != NULL)
	                    		*ptr = '\0';
							break;
						}
					}
					else
						break;
				}
				continue;
            }
			if (strstr(line, "dns-server:") != NULL){
                while(fgets(line,sizeof(line)-1,fd)){
                    if (strstr(line, "],") == NULL){
						char dnsip[512] = {0};
						ptr = strrchr(line, '\t');
						if (ptr)
							strcpy(dnsip, ptr+1);
						else
							strcpy(dnsip, line);
						if((ptr = strstr(dnsip,"\n")) != NULL)
							*ptr = '\0';
                        if((ptr = strstr(dnsip,",")) != NULL)
                            *ptr = '\0';
						if(strcmp(dnsip, "") != 0){
							if (wandeviceinfo->dns[0] == '\0'){
								strcpy(wandeviceinfo->dns, dnsip);
							}
							else{
								sprintf(wandeviceinfo->dns,"%s,%s", wandeviceinfo->dns, dnsip);
							}
						}
                    }
					else
						break;
                }
                continue;
            }
			if (strstr(line, "inactive: {") != NULL){ //we don't check the info behind the 'inactive'
                break;
            }
		}

		pclose(fd);
		
		tr_log(LOG_DEBUG,"=====up=%d",wandeviceinfo->status);
		tr_log(LOG_DEBUG,"=====uptime=%s",wandeviceinfo->uptime);
		tr_log(LOG_DEBUG,"=====l3_device=%s",wandeviceinfo->l3_device);
		tr_log(LOG_DEBUG,"=====proto=%s",wandeviceinfo->proto);
		tr_log(LOG_DEBUG,"=====device=%s",wandeviceinfo->device);
		tr_log(LOG_DEBUG,"=====ipv4_address=%s",wandeviceinfo->ipv4_address);
		tr_log(LOG_DEBUG,"=====mask=%s",wandeviceinfo->mask);
		tr_log(LOG_DEBUG,"=====ipv6_address=%s",wandeviceinfo->ipv6_address);
		tr_log(LOG_DEBUG,"=====ipv6_mask=%s",wandeviceinfo->ipv6_mask);
		tr_log(LOG_DEBUG,"=====ipv6_prefix_address=%s",wandeviceinfo->ipv6_prefix_address);
		tr_log(LOG_DEBUG,"=====ipv6_prefix_mask=%s",wandeviceinfo->ipv6_prefix_mask);
		tr_log(LOG_DEBUG,"=====nexthop=%s",wandeviceinfo->nexthop);
		tr_log(LOG_DEBUG,"=====dns=%s",wandeviceinfo->dns);
	}
}

void getLanLowerLayerInterface(char *inf, char *inf2)
{
	FILE *fd = NULL;
	char line[128] = {0};
	char *ptr = NULL;
	char *ptr2 = NULL;
	char cmd[64] = {0};

	inf[0] = '\0';

	sprintf(cmd, "brctl show %s", inf2);
	if ((fd = popen(cmd, "r")) != NULL){
		while(fgets(line,sizeof(line)-1,fd)){
			if ((ptr = strstr(line,"eth")) != NULL || (ptr = strstr(line,"ath")) != NULL || (ptr = strstr(line,"mesh")) != NULL){
				if((ptr2= strstr(ptr, "\n")) != NULL)
					*ptr2 = '\0';
				if (inf[0] == '\0')
					strcpy(inf, ptr);
				else
					sprintf(inf, "%s,%s", inf, ptr);
			}
		}
		pclose(fd);
	}
}

int checkEthWanUpDown()
{
	int ret = 0;
	char wanup[32] = {0};
	
	ret = do_uci_get("network.wan.disabled", wanup);
	if(ret)
	{
		ret = 1; //no this uci node with defalut settings
	}
	else{
		if (atoi(wanup) == 0)
			ret = 1;
		else
			ret = 0;
	}

	return ret;
}

int checkDhcpServerOnOff(char *index)
{
	int ret = 0;
	char dhcponoff[32] = {0};
	char ucipath[32] = {0};
	char inf[32] = {0};
	char mac[32] = {0};
	int en1 = 0, en2 = 0;

	if ((atoi(index)-1) == 0)
		strcpy(inf, "br-lan" );//br-lan
	else
		sprintf(inf, "br-lan%d", atoi(index)-1);//br-lan1 , br-lan2 .br-lan3
	getInfaceMac(inf, mac);
	tr_log(LOG_DEBUG,"checkDhcpServerOnOff MAC=[%s]",mac);
	if (strcmp(mac, "") != 0)
		en1 = 1;
	else
		en1 = 0;

	if (atoi(index) == 1)
		strcpy(ucipath, "dhcp.lan.ignore");
	else
		sprintf(ucipath, "dhcp.lan%d.ignore", atoi(index)-1);
	
	ret = do_uci_get(ucipath, dhcponoff);
	if(ret)
	{
		en2 = 1;
	}
	else{
		if (strcmp(dhcponoff, "0") == 0) //0 means enable
			en2 = 1;
		else
			en2 = 0;
	}

	if (en1 == 1 && en2 == 1)
		ret = 1;
	else
		ret = 0;

	return ret;
}

int getWanMode(char *mode)
{
	int ret = 0;
	char wanmode1[32] = {0};
	char wanmode2[32] = {0};
	ret = do_uci_get("network.wan0.proto", wanmode1);
	/*if(ret) //MUST remove
	{
		return -1;
	}*/
	ret = do_uci_get("network.wan.proto", wanmode2);
	if(ret)
	{
		return -1;
	}

	if ((strcmp(wanmode1, "pptp") == 0 || strcmp(wanmode1, "l2tp") == 0) && strcmp(wanmode2, "dhcp") == 0)
		strcpy(mode, wanmode1);
	else
		strcpy(mode, wanmode2);

	return ret;
}

void getWanHigherLayerInterface (char *inf)
{
	a_infinfo wanStatus;
	char wantype[32] = {0};
	char wanmode[32] = {0};

	if (getWanMode(wanmode) != 0){
		tr_log(LOG_DEBUG,"Get Wan Mode failed");
		return;
	}
	if (strcmp(wanmode, "pptp") == 0 || strcmp(wanmode, "l2tp") == 0)
		strcpy(wantype, "wan0");
	else
		strcpy(wantype, "wan");
	memset(&wanStatus, 0, sizeof(wanStatus));
	getInterfaceInfo(wantype, &wanStatus);
	if (wanStatus.status == 1) //always getting up interface
		strcpy(inf, wanStatus.l3_device);
}

void getDnsServerInfo(a_dnsinfo *dnsinfo)
{
	a_infinfo wanStatus;
	char *p = NULL;
	int ret = 0;
	char autodns[32] = {0};
	memset(&wanStatus, 0, sizeof(wanStatus));

	ret = do_uci_get("network.wan.peerdns", autodns);
	if(ret) //menas autodns is enabled
	{
		strcpy(autodns, "1");
	}
	getInterfaceInfo("wan0", &wanStatus);
	if(wanStatus.status == 1){ //for pptp and l2tp
		strcpy(dnsinfo->device, wanStatus.l3_device);
		if(atoi(autodns) == 1)
			strcpy(dnsinfo->type, "IPCP");
		else
			strcpy(dnsinfo->type, "Static");
		if ((p = strstr(wanStatus.dns, ",")) != NULL){
			strcpy(dnsinfo->dns2, p+1);
			*p = '\0';
			strcpy(dnsinfo->dns1, wanStatus.dns);
			dnsinfo->statusdns1 = 1;
			dnsinfo->statusdns2 = 1;
		}
		else //only one dns address
		{
			if (strcmp(wanStatus.dns, "") != 0){
				strcpy(dnsinfo->dns1, wanStatus.dns);
				dnsinfo->statusdns1 = 1;
				dnsinfo->statusdns2 = 0;
			}
			else{
				dnsinfo->statusdns1 = 0;
				dnsinfo->statusdns2 = 0;
			}
		}
	}
	else{
		memset(&wanStatus, 0, sizeof(wanStatus));
		getInterfaceInfo("wan", &wanStatus);
		if(wanStatus.status == 1){
			strcpy(dnsinfo->device, wanStatus.l3_device);
			if(strcmp(wanStatus.proto, "dhcp") == 0){
				if(atoi(autodns) == 1)
					strcpy(dnsinfo->type, "DHCP");
				else
					strcpy(dnsinfo->type, "Static");
			}else if(strcmp(wanStatus.proto, "pppoe") == 0){
				if(atoi(autodns) == 1)
					strcpy(dnsinfo->type, "IPCP");
				else
					strcpy(dnsinfo->type, "Static");
			}else
				strcpy(dnsinfo->type, "Static");
			
			if ((p = strstr(wanStatus.dns, ",")) != NULL){
				strcpy(dnsinfo->dns2, p+1);
				*p = '\0';
				strcpy(dnsinfo->dns1, wanStatus.dns);
				dnsinfo->statusdns1 = 1;
				dnsinfo->statusdns2 = 1;
			}
			else //only one dns address
			{
				if (strcmp(wanStatus.dns, "") != 0){
					strcpy(dnsinfo->dns1, wanStatus.dns);
					dnsinfo->statusdns1 = 1;
					dnsinfo->statusdns2 = 0;
				}
				else{
					dnsinfo->statusdns1 = 0;
					dnsinfo->statusdns2 = 0;
				}
			}
		}
	}
}

void getNetmask(char *inf, char *mask)
{
	FILE *fd = NULL;
	char line[128] = {0};
	char cmd[128] = {0};
	char *ptr = NULL;
	char *ptr2 = NULL;

	sprintf(cmd, "ifconfig %s | grep Mask", inf);
	if ((fd = popen(cmd, "r")) != NULL){
		if(fgets(line,sizeof(line)-1,fd)){
			if ((ptr = strstr(line,"Mask:")) != NULL){
				if((ptr2= strstr(ptr, "\n")) != NULL)
					*ptr2 = '\0';
				strcpy(mask, ptr+strlen("Mask:"));
			}
		}
		pclose(fd);
	}
}

void getNetMtu(char *inf, char *mtu)
{
	FILE *fd = NULL;
	char line[128] = {0};
	char cmd[128] = {0};
	char *ptr = NULL;
	char *ptr2 = NULL;

	sprintf(cmd, "ifconfig %s | grep MTU", inf);
	if ((fd = popen(cmd, "r")) != NULL){
		if(fgets(line,sizeof(line)-1,fd)){
			if ((ptr = strstr(line,"MTU:")) != NULL){
				if((ptr2= strstr(ptr, " ")) != NULL)
					*ptr2 = '\0';
				if((ptr2= strstr(ptr, "\n")) != NULL)
					*ptr2 = '\0';
				strcpy(mtu, ptr+strlen("MTU:"));
			}
		}
		pclose(fd);
	}
}

void getInfaceMac(char *inf, char *mac)
{
	FILE *fd = NULL, *fd2 = NULL;
	char line[128] = {0};
	char cmd[128] = {0};
	char *ptr = NULL;
	char *ptr2 = NULL;

	sprintf(cmd, "ifconfig | grep %s", inf);
	if ((fd = popen(cmd, "r")) != NULL){
		if(fgets(line,sizeof(line)-1,fd)){
			memset(cmd, 0, sizeof(cmd));
			memset(line, 0, sizeof(line));
			sprintf(cmd, "ifconfig %s | grep HWaddr", inf); //double check
			if ((fd2 = popen(cmd, "r")) != NULL){
				if(fgets(line,sizeof(line)-1,fd2)){
					if ((ptr = strstr(line,"HWaddr")) != NULL){
						if((ptr2= strstr(ptr, "\n")) != NULL)
							*ptr2 = '\0';
						if((ptr2= strstr(ptr, " ")) != NULL)
							*ptr2 = '\0';
						strcpy(mac, ptr+strlen("HWaddr "));
					}
				}
				pclose(fd2);
			}
		}
		pclose(fd);
	}
}

void getInfaceWanMac(char *mac)
{
	FILE *fd = NULL;
	char line[128] = {0};
	char *ptr = NULL;

	if ((fd = popen("mf_tool READ_WAN_MAC", "r")) != NULL){
		if(fgets(line,sizeof(line)-1,fd)){
			if ((ptr = strstr(line,"\n")) != NULL){
				*ptr = '\0';
			}
			if ((ptr = strstr(line," ")) != NULL){
				*ptr = '\0';
			}
			strcpy(mac, line);
		}
		pclose(fd);
	}
}

void getInfaceName(char *inf, char *mac)
{
	FILE *fd = NULL;
	char line[128] = {0};
	char cmd[128] = {0};
	char *ptr = NULL;
	tr_log(LOG_DEBUG,"get mac [%s]",mac);

	sprintf(cmd, "ifconfig | grep HWaddr");
	if ((fd = popen(cmd, "r")) != NULL)
	{
		while(fgets(line, sizeof(line), fd))
		{
			if (strstr(line, mac) != NULL)
			{
				sscanf(line,"%s %*s %*s %*s %*s", inf);
				if(strncmp(inf, "br-lan", strlen("br-lan")) != 0)
					break;
			}
		}
		pclose(fd);
	}
}

/* get device up time */
void getDeviceUpTime(char * finename, char * time)
{
	FILE *fp = NULL;
	char buff[128] = {0};
	char *p = NULL;
	char *q = NULL;

    fp = fopen(finename, "r");
    if(fp != NULL)
    {
		fgets(buff, sizeof(buff), fp);
		fclose(fp);

		q = buff;
		while((p = strstr(q, " ")) != NULL)
        {
            *p = '\0';
        }

        if ((p = strstr(q, ".")) != NULL)
            *p = '\0';

        strcpy(time, buff);
    }
	else
		strcpy(time, "0");
}

void getFirewallLastChaneTime(char *time)
{
	FILE *fd = NULL;
	char line[128] = {0};
	char *ptr = NULL;

	if ((fd = popen("cat /tmp/fiewallLastChange", "r")) != NULL){
		if(fgets(line,sizeof(line)-1,fd)){
			if ((ptr = strstr(line,"\n")) != NULL){
				*ptr = '\0';
				strcpy(time, line);
			}
		}
		pclose(fd);
	}
	else
		strcpy(time, "");
}

void getFirewallChainNumberOfEntries(char *value)
{
	FILE *fd = NULL;
	char line[128] = {0};
	char *ptr = NULL;
	int entry = 0;

	if ((fd = popen("iptables -L", "r")) != NULL){
		while(fgets(line,sizeof(line)-1,fd)){
			if (strstr(line,"Chain") != NULL){
				entry ++;
				memset(line, 0, sizeof(line));
			}
		}
		pclose(fd);
	}
	if ((fd = popen("iptables -L -t nat", "r")) != NULL){
		while(fgets(line,sizeof(line)-1,fd)){
			if (strstr(line,"Chain") != NULL){
				entry ++;
				memset(line, 0, sizeof(line));
			}
		}
		pclose(fd);
	}
	if ((fd = popen("ip6tables -L", "r")) != NULL){
		while(fgets(line,sizeof(line)-1,fd)){
			if (strstr(line,"Chain") != NULL){
				entry ++;
				memset(line, 0, sizeof(line));
			}
		}
		pclose(fd);
	}
	sprintf(value, "%d", entry);
}

void getInterfaceLastChangeTime(char * time)
{
	char initTime[128] = {0};
	char newTime[128] = {0};
	long int time1;
	long int time2;
	char *ptr;

	getDeviceUpTime("/proc/uptime", newTime);
	getDeviceUpTime("/tmp/infLastChange", initTime);

	time1 = strtol(newTime, &ptr, 10);
	time2 = strtol(initTime, &ptr, 10);

	sprintf(time, "%ld", time1 - time2);
}

/* get cpu usage */
void getCpuUsage(char * value)
{
	char line[512] = {0};
	char buf[32] = {0};
	FILE *topfile= NULL;
	int count = 0;
	char *p = NULL;
	int usage = 0;
	
	if((topfile = popen("top -n 1", "r")) != NULL){
		while ( fgets(line, sizeof(line), topfile) ){
			if (count++ == 1){
				sscanf(line, "%*s %*s %*s %*s %*s %*s %*s %s %*s", buf);
				if ((p = strstr(buf, "%")) != NULL) //get idle value
					*p = '\0';
				usage = 100 - atoi(buf); //usaged
				sprintf(value, "%d", usage);
				break;
			}
		}
		pclose(topfile);
	}
}

/* Getting all precess number */
int get_all_process_num()
{
    FILE *fp = NULL;
    char line[128] = {0};
    int i = 0;

	if ((fp = popen("ls /proc/ | grep ^[0-9]*$ | sort -n", "r")) != NULL) {
    	while (fgets(line, sizeof(line), fp)){
        	i++;
    	}
    	pclose(fp);
	}

	if (i > processMaxInstanceNum)
		i = processMaxInstanceNum;

    return i;
}

/* get wlan associated device info */
void get_Wlan_AssociatedDeviceInfo(a_wlanAssociatedDev *dev)
{
	char *p = NULL;
	char buff[1024] = {0};
	FILE *fp = NULL;
	char mac[32] = {0};
	char inf[32] = {0};
	char pathname[128] = {0};
	int i = 0, j = 0, index = 0;
	int found = 0;

	for (i = 0; i < sizeof(dev->mac); i ++)
		dev->mac[i] = tolower(dev->mac[i]);

	for (i = WIFI5G_START_INSTANCE_NUM; i <= WIFI5G_END_INSTANCE_NUM; i ++){
		memset(buff, 0, sizeof(buff));
		memset(inf, 0, sizeof(inf));
		getWiFiInterfaceNameWithInstanceNum2(i, inf);
		sprintf(buff, "wlanconfig %s list sta", inf);

		sprintf(pathname, "Device.WiFi.AccessPoint.%d.AssociatedDevice.", getWiFiInstanceNumWithInterfaceName(inf));

		if ((fp = popen(buff, "r")) != NULL){
			index = 0;
			while(fgets(buff, sizeof(buff), fp)){
				memset(mac, 0, sizeof(mac));
				sscanf(buff, "%s %*s", mac);
				if((p = strstr(mac, "\n")) != NULL)
					*p = '\0';
				for (j = 0; j < sizeof(mac); j ++)
					mac[j] = tolower(mac[j]);
				if (strcasecmp(dev->mac, mac) == 0){
					index ++;
					strcpy(dev->inf, inf);
					sprintf(dev->pathname, "%s%d", pathname, index);
					found ++;
					break;
				}
			}
			pclose(fp);
		}
	}

	if (found != 0)
		return;

	for (i = WIFI24G_START_INSTANCE_NUM; i <= WIFI24G_END_INSTANCE_NUM; i ++){
		memset(buff, 0, sizeof(buff));
		memset(inf, 0, sizeof(inf));
		getWiFiInterfaceNameWithInstanceNum2(i, inf);
		sprintf(buff, "wlanconfig %s list sta", inf);

		sprintf(pathname, "Device.WiFi.AccessPoint.%d.AssociatedDevice.", getWiFiInstanceNumWithInterfaceName(inf));

		if ((fp = popen(buff, "r")) != NULL){
			index = 0;
			while(fgets(buff, sizeof(buff), fp)){
				memset(mac, 0, sizeof(mac));
				sscanf(buff, "%s %*s", mac);
				if((p = strstr(mac, "\n")) != NULL)
					*p = '\0';
				for (j = 0; j < sizeof(mac); j ++)
					mac[j] = tolower(mac[j]);
				if (strcasecmp(dev->mac, mac) == 0){
					index ++;
					strcpy(dev->inf, inf);
					sprintf(dev->pathname, "%s%d", pathname, index);
					break;
				}
			}
			pclose(fp);
		}
	}
}

void getNextHopGwMac(char *mac)
{
	a_infinfo wandeviceinfo;

	memset(&wandeviceinfo, 0, sizeof(wandeviceinfo));
	getInterfaceInfo("wan", &wandeviceinfo); //only check dhcp or static wan
	if (wandeviceinfo.status == 1 && strcmp(wandeviceinfo.proto, "pppoe") != 0 ){
		FILE *fp = NULL;
		char line[128] = {0};
		char ip[32] = {0};
		char gwmac[32] = {0};
		if((fp=fopen("/proc/net/arp","r")) != NULL){
			fgets(line,sizeof(line)-1,fp); //get one line
			while(fgets(line,sizeof(line)-1,fp)){
				sscanf(line,"%s %*s %*s %s %*s", ip, gwmac);
				if (strcmp(ip, wandeviceinfo.nexthop) == 0){
					strcpy(mac, gwmac);
					break;
				}
			}
			fclose(fp);
		}
	}
}

void get_USBHostsDeviceInfo(char *busnum, char *value, char *key)
{
	FILE *fp = NULL;
	char usbpath[128] = {0};
    char line[128] = {0};
	char * ptr = NULL;

	if (atoi(busnum) == 1)
		strcpy(usbpath, "/sys/bus/platform/devices/xhci-hcd.0/usb1/1-1");
	else if (atoi(busnum) == 3)
		strcpy(usbpath, "/sys/bus/platform/devices/xhci-hcd.1/usb3/3-1");
	else
		return ;
	
	sprintf(usbpath,"%s/%s", usbpath, key);
	if((fp=fopen(usbpath, "r")) != NULL){
		fgets(line,sizeof(line)-1,fp);
		if ((ptr = strstr(line, "\n")) != NULL)
			*ptr = '\0';
		strcpy(value, line);
		fclose(fp);
	}
}

void get_USBHostsDeviceInfo2(char *busnum, char *value, char *key)
{
	FILE *fp = NULL;
	char usbpath[128] = {0};
    char line[128] = {0};
	char * ptr = NULL;

	if (atoi(busnum) == 1)
		strcpy(usbpath, "/sys/bus/platform/devices/xhci-hcd.0/usb1");
	else if (atoi(busnum) == 3)
		strcpy(usbpath, "/sys/bus/platform/devices/xhci-hcd.1/usb3");
	else
		return ;
	
	sprintf(usbpath,"%s/%s", usbpath, key);
	if((fp=fopen(usbpath, "r")) != NULL){
		fgets(line,sizeof(line)-1,fp);
		if ((ptr = strstr(line, "\n")) != NULL)
			*ptr = '\0';
		strcpy(value, line);
		fclose(fp);
	}
}

/* key is the Destination ip and interface */
void get_ipv6_routing_info(char *key, char *value, char *string)
{
	FILE *fp = NULL;
    char line[512] = {0};
	char routinginfo[7][128];
	char newkey[128] = {0};
	
	if((fp=popen("route -A inet6 -n","r")) != NULL){
		fgets(line,sizeof(line)-1,fp); //ingor first line
		fgets(line,sizeof(line)-1,fp); //ingor second line
		while(fgets(line,sizeof(line)-1,fp)){
			memset(routinginfo, 0, sizeof(routinginfo));
			memset(newkey, 0, sizeof(newkey));
			sscanf(line,"%s %s %s %s %s %s %s",routinginfo[0], routinginfo[1], routinginfo[2], routinginfo[3], routinginfo[4], routinginfo[5], routinginfo[6]);
			sprintf(newkey, "%s|%s", routinginfo[0], routinginfo[6]);
			if (strcmp(key, newkey) == 0){
				if (strcmp(string, "Status") == 0){
					strcpy(value, "Enabled");
					break;
				}
				if (strcmp(string, "DestIPPrefix") == 0){
					strcpy(value, routinginfo[0]);
					break;
				}
				if (strcmp(string, "NextHop") == 0){
					strcpy(value, routinginfo[1]);
					break;
				}
				if (strcmp(string, "ForwardingMetric") == 0){
					strcpy(value, routinginfo[3]);
					break;
				}
				if (strcmp(string, "Interface") == 0){
					strcpy(value, routinginfo[6]);
					break;
				}
			}
			else{
				if (strcmp(string, "Status") == 0){
					strcpy(value, "Disabled");
					break;
				}
			}
    	}
    	pclose(fp);
	}
}

void getNeighRetransTimer(char *inf, char *value)
{
	FILE *fp = NULL;
    char line[128] = {0};
	char * ptr = NULL;
	char *path[128] = {0};
	
	sprintf(path,"/proc/sys/net/ipv6/neigh/%s/retrans_time_ms", inf);
	if((fp=fopen(path, "r")) != NULL){
		fgets(line,sizeof(line)-1,fp);
		if ((ptr = strstr(line, "\n")) != NULL)
			*ptr = '\0';
		strcpy(value, line);
		fclose(fp);
	}
}

void getRtrSolicitationInterval(char *inf, char *value)
{
	FILE *fp = NULL;
    char line[128] = {0};
	char * ptr = NULL;
	char *path[128] = {0};
	char *endptr;
	
	sprintf(path,"/proc/sys/net/ipv6/conf/%s/router_solicitation_interval", inf);
	if((fp=fopen(path, "r")) != NULL){
		fgets(line,sizeof(line)-1,fp);
		if ((ptr = strstr(line, "\n")) != NULL)
			*ptr = '\0';
		sprintf(value, "%ld", strtol(line, &endptr, 10) * 1000); //milliseconds
		//strcpy(value, line);
		fclose(fp);
	}
}

void getMaxRtrSolicitations(char *inf, char *value)
{
	FILE *fp = NULL;
    char line[128] = {0};
	char * ptr = NULL;
	char *path[128] = {0};
	
	sprintf(path,"/proc/sys/net/ipv6/conf/%s/router_solicitations", inf);
	if((fp=fopen(path, "r")) != NULL){
		fgets(line,sizeof(line)-1,fp);
		if ((ptr = strstr(line, "\n")) != NULL)
			*ptr = '\0';
		strcpy(value, line);
		fclose(fp);
	}
}

void getRouterAdvertisementOptionValue(char *value, char *type)
{
	FILE *fp = NULL;
    char line[256] = {0};
	char * ptr = NULL;

	if (atoi(type) == 1){
		getMfcInfo("LANPortMAC", value);
	}
	else{
		if((fp=fopen("/var/etc/radvd.conf","r")) != NULL){
			while(fgets(line,sizeof(line)-1,fp)){
				if ((ptr = strstr(line, "prefix")) != NULL && atoi(type) == 3){
					sscanf(line,"%*s %s",value);
					if ((ptr = strstr(value, "\n")) != NULL)
						*ptr = '\0';
				}
				if ((ptr = strstr(line, "RDNSS")) != NULL && atoi(type) == 25){
					if ((ptr = strstr(ptr, " ")) != NULL){
						strcpy(value, ptr+1);
						if ((ptr = strstr(value, "\n")) != NULL)
							*ptr = '\0';
					}
				}
	    	}
	    	fclose(fp);
		}
	}
}

void get_Device_DHCPv6_Server_Pool_1_Client_address_by_mac(char *mac, char *value)
{	
	FILE *fp = NULL, *fp2 = NULL;
    char line[128] = {0};
	char cmd[128] = {0};
	char ipaddr[128] = {0};
	int found = 0;

	sprintf(cmd, "ip -f inet6 neigh show | grep %s", mac);
	if((fp=popen(cmd,"r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp)){
			sscanf(line,"%s %*s",ipaddr);
			memset(cmd, 0, sizeof(cmd));
			sprintf(cmd, "cat /var/lib/dibbler/server-cache.xml | grep %s", ipaddr);
			if((fp2=popen(cmd,"r")) != NULL){
				memset(line, 0, sizeof(line));
				fgets(line,sizeof(line)-1,fp);
				if (strcmp(line, "") != 0){
					strcpy(value, ipaddr);
					found = 1;
				}
				pclose(fp2);
			}
			if (found == 1)
				break;
		}
    	pclose(fp);
	}
	else
		strcpy(value, "");
}

void check_Device_DHCP_Server_Pool_Client_address_active(char *family, char *ip, char *value)
{	
	FILE *fp = NULL, *fp2 = NULL;
    char line[128] = {0};
	char cmd[128] = {0};
	char ipaddr[128] = {0};
	int found = 0;

	sprintf(cmd, "ip -f %s neigh show | grep %s", family, ip);
	if((fp=popen(cmd,"r")) != NULL){
		if(fgets(line,sizeof(line)-1,fp)){
			strcpy(value, "1");
		}
		else
			strcpy(value, "0");
    	pclose(fp);
	}
	else
		strcpy(value, "0");
}

void getDhcpv6IANAPreferredLifetime(char *value)
{
	FILE *fp = NULL;
    char line[128] = {0};
	char *ptr = NULL, *ptr2 = NULL;
	
	if((fp=popen("cat /var/lib/dibbler/server-CfgMgr.xml | grep 'pref min=' | sed 's/\"//g'","r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp)){
			if ((ptr = strstr(line, "=")) != NULL){
				if ((ptr2 = strstr(ptr, " ")) != NULL){
					*ptr2 = '\0';
					strcpy(value, ptr+1);
					printf("================debug========value=%s, ptr+1=%s\n", value, ptr+1);
				}
			}
		}
    	pclose(fp);
	}
}

void getDhcpv6IANAValidLifetime(char *value)
{
	FILE *fp = NULL;
    char line[128] = {0};
	char *ptr = NULL, *ptr2 = NULL;
	
	if((fp=popen("cat /var/lib/dibbler/server-CfgMgr.xml | grep 'valid min=' | sed 's/\"//g'","r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp)){
			if ((ptr = strstr(line, "=")) != NULL){
				if ((ptr2 = strstr(ptr, " ")) != NULL){
					*ptr2 = '\0';
					strcpy(value, ptr+1);
					printf("================debug========value=%s, ptr+1=%s\n", value, ptr+1);
				}
			}
		}
    	pclose(fp);
	}
}

void getCoreChipTemperatureStatus(int sector, a_TemperatureSensorInfo *temperatureSensorInfo)
{
	FILE *fp = NULL;
    char line[128] = {0};
	char *ptr = NULL;
	int enable = 0;
	char path[128] = {0};

	sprintf(path, "/sys/devices/virtual/thermal/thermal_zone%d/mode", sector);
	if((fp=fopen(path,"r")) != NULL){
		fgets(line,sizeof(line)-1,fp);
		if (strstr(line, "enabled") != NULL){
			enable = 1;
			strcpy(temperatureSensorInfo->Enable, "1");
			strcpy(temperatureSensorInfo->Status, "Enabled");
		}
		else{
			enable = 0;
			strcpy(temperatureSensorInfo->Enable, "0");
			strcpy(temperatureSensorInfo->Status, "Disabled");
		}
		fclose(fp);
	}

	strcpy(temperatureSensorInfo->Reset, "0"); //always 0
	sprintf(temperatureSensorInfo->Name, "Core CPU Sensor%d", sector);

	memset(path, 0, sizeof(path));
	sprintf(path, "/oneagent/conf/thermal_zone%dresttime", sector);
	if(enable == 0)
		strcpy(temperatureSensorInfo->ResetTime, "0001-01-01T00:00:00Z");
	else{
		if((fp=fopen(path,"r")) != NULL){
			memset(line, 0, sizeof(line));
			fgets(line,sizeof(line)-1,fp);
			if ((ptr = strstr(line, "\n")) != NULL)
				*ptr = '\0';
			strcpy(temperatureSensorInfo->ResetTime, line);
			fclose(fp);
		}
		else
			strcpy(temperatureSensorInfo->ResetTime, "0001-01-01T00:00:00Z");
	}

	memset(path, 0, sizeof(path));
	sprintf(path, "/sys/devices/virtual/thermal/thermal_zone%d/temp", sector);
	if (enable == 1){
		if((fp=fopen(path,"r")) != NULL){
			memset(line, 0, sizeof(line));
			fgets(line,sizeof(line)-1,fp);
			if ((ptr = strstr(line, "\n")) != NULL)
				*ptr = '\0';
			strcpy(temperatureSensorInfo->Value, line);
			fclose(fp);
			if((fp=popen("date","r")) != NULL){
				memset(line, 0, sizeof(line));
				fgets(line,sizeof(line)-1,fp);
				if ((ptr = strstr(line, "\n")) != NULL)
					*ptr = '\0';
				strcpy(temperatureSensorInfo->LastUpdate, line);
				pclose(fp);
			}
		}
	}
	else{
		strcpy(temperatureSensorInfo->Value, "-274"); //means not ready
		strcpy(temperatureSensorInfo->LastUpdate, "0001-01-01T00:00:00Z");
	}

	memset(path, 0, sizeof(path));
	sprintf(path, "/sys/devices/virtual/thermal/thermal_zone%d/trip_point_3_temp", sector);
	if (enable == 1){
		if((fp=fopen(path,"r")) != NULL){
			memset(line, 0, sizeof(line));
			fgets(line,sizeof(line)-1,fp);
			if ((ptr = strstr(line, "\n")) != NULL)
				*ptr = '\0';
			strcpy(temperatureSensorInfo->LowAlarmValue, line);
			fclose(fp);
		}
	}
	else{
		strcpy(temperatureSensorInfo->LowAlarmValue, "-274"); //means not ready
	}

	memset(path, 0, sizeof(path));
	sprintf(path, "/sys/devices/virtual/thermal/thermal_zone%d/trip_point_0_temp", sector);
	if (enable == 1){
		if((fp=fopen(path,"r")) != NULL){
			memset(line, 0, sizeof(line));
			fgets(line,sizeof(line)-1,fp);
			if ((ptr = strstr(line, "\n")) != NULL)
				*ptr = '\0';
			strcpy(temperatureSensorInfo->HighAlarmValue, line);
			fclose(fp);
		}
	}
	else{
		strcpy(temperatureSensorInfo->HighAlarmValue, "-274"); //means not ready
	}

	strcpy(temperatureSensorInfo->MinValue, "-274");
	strcpy(temperatureSensorInfo->MinTime, "0001-01-01T00:00:00Z");
	strcpy(temperatureSensorInfo->MaxValue, "-274");
	strcpy(temperatureSensorInfo->MaxTime, "0001-01-01T00:00:00Z");
	strcpy(temperatureSensorInfo->PollingInterval, "0"); //always 0
}

void getWifiChipTemperatureStatus(int sector, a_TemperatureSensorInfo *temperatureSensorInfo)
{
	FILE *fp = NULL;
    char line[128] = {0};
	char *ptr = NULL, *ptr2 = NULL;
	int enable = 0;
	char path[128] = {0};

	sprintf(path, "thermaltool -i wifi%d -get | grep 'enable: 1'", sector);
	if((fp=popen(path,"r")) != NULL){
		fgets(line,sizeof(line)-1,fp);
		if (strcmp(line, "") != 0){
			enable = 1;
			strcpy(temperatureSensorInfo->Enable, "1");
			strcpy(temperatureSensorInfo->Status, "Enabled");
		}
		else{
			enable = 0;
			strcpy(temperatureSensorInfo->Enable, "0");
			strcpy(temperatureSensorInfo->Status, "Disabled");
		}
		pclose(fp);
	}

	strcpy(temperatureSensorInfo->Reset, "0"); //always 0
	if (sector == 0)
		strcpy(temperatureSensorInfo->Name, "Wifi5G Chip Sensor");
	else
		strcpy(temperatureSensorInfo->Name, "Wifi2.4G Chip Sensor");

	memset(path, 0, sizeof(path));
	sprintf(path, "/oneagent/conf/wifi%dresttime", sector);
	if(enable == 0)
		strcpy(temperatureSensorInfo->ResetTime, "0001-01-01T00:00:00Z");
	else{
		if((fp=fopen(path,"r")) != NULL){
			memset(line, 0, sizeof(line));
			fgets(line,sizeof(line)-1,fp);
			if ((ptr = strstr(line, "\n")) != NULL)
				*ptr = '\0';
			strcpy(temperatureSensorInfo->ResetTime, line);
			fclose(fp);
		}
		else
			strcpy(temperatureSensorInfo->ResetTime, "0001-01-01T00:00:00Z");
	}

	memset(path, 0, sizeof(path));
	sprintf(path, "thermaltool -i wifi%d -get | grep 'sensor temperature'", sector);
	if (enable == 1){
		if((fp=popen(path,"r")) != NULL){
			memset(line, 0, sizeof(line));
			fgets(line,sizeof(line)-1,fp);
			if ((ptr = strstr(line, ",")) != NULL)
				*ptr = '\0';
			sscanf(line,"%*s %*s %s", temperatureSensorInfo->Value);
			pclose(fp);
			if((fp=popen("date","r")) != NULL){
				memset(line, 0, sizeof(line));
				fgets(line,sizeof(line)-1,fp);
				if ((ptr = strstr(line, "\n")) != NULL)
					*ptr = '\0';
				strcpy(temperatureSensorInfo->LastUpdate, line);
				pclose(fp);
			}
		}
	}
	else{
		strcpy(temperatureSensorInfo->Value, "-274"); //means not ready
		strcpy(temperatureSensorInfo->LastUpdate, "0001-01-01T00:00:00Z");
	}

	memset(path, 0, sizeof(path));
	sprintf(path, "thermaltool -i wifi%d -get | grep 'level: 0'", sector);
	if (enable == 1){
		if((fp=popen(path,"r")) != NULL){
			memset(line, 0, sizeof(line));
			fgets(line,sizeof(line)-1,fp);
			if ((ptr = strstr(line, "low thresold")) != NULL){
				if ((ptr2 = strstr(ptr, ",")) != NULL){
					*ptr2 = '\0';
					sscanf(ptr,"%*s %*s %s", temperatureSensorInfo->LowAlarmValue);
				}
			}
			pclose(fp);
		}
	}
	else{
		strcpy(temperatureSensorInfo->LowAlarmValue, "-274"); //means not ready
	}

	memset(path, 0, sizeof(path));
	sprintf(path, "thermaltool -i wifi%d -get | grep 'level: 0'", sector);
	if (enable == 1){
		if((fp=popen(path,"r")) != NULL){
			memset(line, 0, sizeof(line));
			fgets(line,sizeof(line)-1,fp);
			if ((ptr = strstr(line, "high thresold")) != NULL){
				if ((ptr2 = strstr(ptr, ",")) != NULL){
					*ptr2 = '\0';
					sscanf(ptr,"%*s %*s %s", temperatureSensorInfo->HighAlarmValue);
				}
			}
			pclose(fp);
		}
	}
	else{
		strcpy(temperatureSensorInfo->HighAlarmValue, "-274"); //means not ready
	}

	strcpy(temperatureSensorInfo->MinValue, "-274");
	strcpy(temperatureSensorInfo->MinTime, "0001-01-01T00:00:00Z");
	strcpy(temperatureSensorInfo->MaxValue, "-274");
	strcpy(temperatureSensorInfo->MaxTime, "0001-01-01T00:00:00Z");
	strcpy(temperatureSensorInfo->PollingInterval, "0"); //always 0
}

int get_Device_DHCPv4_Server_Option_value(char *key, char *value)
{
	int ret = 0;
	char ip[3][32];
	char *ptr = NULL;

	if (atoi(key) == 3){ //getting routing ip
		ret = do_uci_get("dhcp.lan.dhcp_option", value);
		if(ret)
		{
			return -1;
		}
		memset(ip, 0, sizeof(ip));
		sscanf(value, "%s %*s", ip[0]);
		if((ptr = strstr(ip[0], ",")) != NULL)
			strcpy(value, ptr+1);
	}
	else if (atoi(key) == 6){ //Domain Name Server
		ret = do_uci_get("dhcp.lan.dhcp_option", value);
		if(ret)
		{
			return -1;
		}
		memset(ip, 0, sizeof(ip));
		sscanf(value, "%s %s %s", ip[0], ip[1], ip[2]);
		if((ptr = strstr(ip[1], ",")) != NULL)
			strcpy(ip[1], ptr+1);
		if((ptr = strstr(ip[2], ",")) != NULL){
			strcpy(ip[2], ptr+1);
			sprintf(value, "%s,%s", ip[1], ip[2]);
		}
		else
			sprintf(value, "%s", ip[1]);
	}
	else if (atoi(key) == 15){ //Domane Name
		ret = do_uci_get("dhcp.@dnsmasq[0].domain", value);
		if(ret)
		{
			return -1;
		}
	}
	else if (atoi(key) == 51){ //Lease Time
		ret = do_uci_get("dhcp.lan.leasetime", value);
		if(ret)
		{
			return -1;
		}
		if ((ptr = strstr(value, "s")) != NULL){
			*ptr = '\0';
		}
		else if ((ptr = strstr(value, "h")) != NULL) {
			*ptr = '\0';
			sprintf(value, "%d", atoi(value)*60*60); //changed hours to seconds
		}
	}
	else
		return -1;
}

long int getLocalTimeWithSeconds()
{
	time_t timep;
	struct tm *p;

	time(&timep);
	printf("time() : %ld \n", timep);
	p = localtime(&timep);
	timep = mktime(p);
	printf("time()->localtime()->mktime():%ld\n", timep);

	return (long int)timep;
}

void changedSecondsToDateTime(long int seconds, char *datetype)
{
	struct timeval tv;
	struct tm *lt;
	char str[100] = {0};

	tv.tv_sec = seconds;
	lt = localtime(&(tv.tv_sec));
	strftime(str,100,"%Y-%m-%dT%H:%M:%SZ",lt);
	strcpy(datetype, str);
	printf("===========datetype value=%s\n", datetype);
}

int changedDateTimeToSeconds(char *datetype)
{
	struct tm lt;
	long int seconds = 0;

	//strptime(datetype, "%Y-%m-%dT%H:%M:%SZ", &lt);
	strptime(datetype, "%Y-%m-%dT%H:%M:%S", &lt);
	seconds = mktime(&lt);
	printf("==========seconds=%ld\n", seconds);
	return seconds;
}


void getNSLookupDiagnosticsResultValue(int number, char *key, char *value)
{
	FILE *fp = NULL;
	char line[128] = {0};
	char cmd[128] = {0};
	char *ptr = NULL;
	int found = 0;

	if (strcmp(key, "Status") == 0 || strcmp(key, "AnswerType") == 0){
		sprintf(cmd, "cat /tmp/NSLookupDiagnostics.Result%d | grep Name:", number);
		if((fp=popen(cmd,"r")) != NULL){
			if (fgets(line,sizeof(line)-1,fp)){
				if (strcmp(key, "Status") == 0)
					strcpy(value, "Success");
				else
					strcpy(value, "Authoritative");
			}
			else{
				if (strcmp(key, "Status") == 0)
					strcpy(value, "Error_DNSServerNotAvailable");
				else
					strcpy(value, "None");
			}
			pclose(fp);
		}
	}

	if (strcmp(key, "ResponseTime") == 0){
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "cat /tmp/NSLookupDiagnostics.Result%d | grep ResponseTime", number);
		if((fp=popen(cmd,"r")) != NULL){
			if (fgets(line,sizeof(line)-1,fp)){
				sscanf(line, "%*s %s", value);
				if ((ptr = strstr(value, "\n")) != NULL)
					*ptr = '\0';
				if (atoi(value) == 0)
					strcpy(value, "1000"); //1s
			}
			else
				strcpy(value, "0");
			pclose(fp);
		}
	}

	if (strcmp(key, "HostNameReturned") == 0){
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "cat /tmp/NSLookupDiagnostics.Result%d | grep Name:", number);
		if((fp=popen(cmd,"r")) != NULL){
			if (fgets(line,sizeof(line)-1,fp)){
				sscanf(line, "%*s %s", value);
				if ((ptr = strstr(value, "\n")) != NULL)
					*ptr = '\0';
			}
			else
				strcpy(value, "");
			pclose(fp);
		}
	}

	if (strcmp(key, "DNSServerIP") == 0){
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "cat /tmp/NSLookupDiagnostics.Result%d", number);
		if((fp=popen(cmd,"r")) != NULL){
			while (fgets(line,sizeof(line)-1,fp)){
				if (strstr(line, "Name:") != NULL)
					break;
				else{
					if (strstr(line, "Address") != NULL){
						sscanf(line, "%*s %*s %s", value);
						if ((ptr = strstr(value, "\n")) != NULL)
							*ptr = '\0';
					}
				}
			}
			pclose(fp);
		}
	}

	if (strcmp(key, "IPAddresses") == 0){
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "cat /tmp/NSLookupDiagnostics.Result%d", number);
		if((fp=popen(cmd,"r")) != NULL){
			found = 0;
			char ip[32] = {0};
			while (fgets(line,sizeof(line)-1,fp)){
				if (strstr(line, "Name:") == NULL && found == 0)
					continue;
				else
					found = 1;
				
				if (strstr(line, "Address") != NULL){
					sscanf(line, "%*s %*s %s", ip);
					if ((ptr = strstr(ip, "\n")) != NULL)
						*ptr = '\0';
					if (strcmp(value, "") == 0)
						strcpy(value, ip);
					else
						sprintf(value, "%s,%s", value, ip);
				}
			}
			if (found == 0)
				strcpy(value, "");
			pclose(fp);
		}
	}
}

int getSSIDuciConfig(char *p, char *buff, char *option)
{
	int i;
	for (i = 0; i < WIFI_MAX_INSTANCE_NUM; i ++){
		if (atoi(p) == wifi_map[i].num)
			sprintf(buff, "%s.%s", wifi_map[i].uci_path, option);
	}
}

int getSSIDuciConfig2(char *p, char *buff, char *option)
{
	if(atoi(p) == 1)
	{
		sprintf(buff, "wireless.wla.%s", option);
	}
	else if(atoi(p) == 2)
	{
		sprintf(buff, "wireless.wlg.%s", option);
	}
}

int getWiFiRadioUciNum(char *p)
{
	int i;
	for (i = 0; i < 2; i ++){
		if (atoi(p) == wifiradio_map[i].instance)
			return wifiradio_map[i].num;
	}

	return 0;
}

int getWiFiRadioType(char *p)
{
	int i;
	for (i = 0; i < 2; i ++){
		if (atoi(p) == wifiradio_map[i].instance)
			return wifiradio_map[i].type;
	}

	return 0;
}

int getWiFiLowerLayersPath(int *p, char *buff)
{
	if (WIFI5G_START_INSTANCE_NUM <= atoi(p) <= WIFI5G_END_INSTANCE_NUM)
		strcpy(buff, WIFI_RADIO_5G_PATH);
	else if (WIFI24G_START_INSTANCE_NUM <= atoi(p) <= WIFI24G_END_INSTANCE_NUM)
		strcpy(buff, WIFI_RADIO_24G_PATH);
	else
		return -1;

	return 0;
}

void getWiFiInterfaceNameWithInstanceNum(char *p, char *buff)
{
	int i;
	for (i = 0; i < WIFI_MAX_INSTANCE_NUM; i ++){
		if (atoi(p) == wifi_map[i].num)
			strcpy(buff, wifi_map[i].wlaninf);
	}
}

void getWiFiInterfaceNameWithInstanceNum2(int num, char *buff)
{
	int i;
	for (i = 0; i < WIFI_MAX_INSTANCE_NUM; i ++){
		if (num == wifi_map[i].num)
			strcpy(buff, wifi_map[i].wlaninf);
	}
}

int getWiFiInstanceNumWithInterfaceName(char *inf)
{
	int i;
	for (i = 0; i < WIFI_MAX_INSTANCE_NUM; i ++){
		if (strcmp(inf, wifi_map[i].wlaninf) == 0)
			return wifi_map[i].num;
	}

	return 0;
}

#define MAX_PF_ELEM 256

int rewrite_portmaping_entry(char *option, char *value, char *ExternalPort)
{
	int i = 0;
	int ret = -1;
	char linebuf[128] = {0};
	char tmparray[64] = {0};
	char valbuf[64] = {0};
	char valbuf1[64] = {0};
	char port_protocol[256] = {0};
	char portrage[64] = {0};
	char ExternalPortEndRange[64] = {0};
	char *p = NULL;

	tr_log(LOG_DEBUG,"set option [%s]",option);
	tr_log(LOG_DEBUG,"set value [%s]",value);
	tr_log(LOG_DEBUG,"set ExternalPort [%s]",ExternalPort);

	for(i=0; i<MAX_PF_ELEM; i++)
	{
		sprintf(tmparray, "firewall_nat.pf%d", i);
		tr_log(LOG_DEBUG,"tmparray [%s]",tmparray);
		sprintf(linebuf, "%s.port_range", tmparray);
		ret = do_uci_get(linebuf, valbuf);
		if (ret != 0)
		{
			continue;
		}
		p = strchr(valbuf, ':');
		if(p != NULL)
		{
			*p = '\0';
		}

		sprintf(linebuf, "%s.protocol", tmparray);
		tr_log(LOG_DEBUG,"linebuf [%s]",linebuf);
		ret = do_uci_get(linebuf, valbuf1);

		sprintf(port_protocol, "%s_%s", valbuf, valbuf1);
		
		if(strcmp(port_protocol, ExternalPort) == 0)
		{
			if(strcmp(option, "ServiceName") == 0)
			{
				sprintf(linebuf, "%s.srv_name", tmparray);
				do_uci_set(linebuf, value);
			}
			else if(strcmp(option, "ExternalPort") == 0)
			{
				sprintf(linebuf, "%s.port_range", tmparray);
				ret = do_uci_get(linebuf, valbuf);

				p = strchr(valbuf, ':');
				if(p != NULL)
				{
					strcpy(ExternalPortEndRange, p+1);
				}
				memset(portrage, 0, sizeof(portrage));
				if ((ExternalPortEndRange[0] != '\0') && (atoi(ExternalPortEndRange) != atoi(value)))
				{
					sprintf(portrage, "%s:%s", value, ExternalPortEndRange);
					do_uci_set(linebuf, portrage);
				}
				else
				{
					do_uci_set(linebuf, value);
				}
			}
			else if(strcmp(option, "PortRange") == 0)
			{
				memset(portrage, 0, sizeof(portrage));
				sprintf(linebuf, "%s.port_range", tmparray);
				ret = do_uci_get(linebuf, portrage);
				if((atoi(value) != 0) && ((strchr(portrage, ':') == NULL)))
				{
					if(atoi(portrage) == atoi(value))
					{
						return 0;
					}

					if(atoi(portrage) > atoi(value))
					{
						return -1;
					}
					
					strcat(portrage, ":");
					strcat(portrage, value);
					do_uci_set(linebuf, portrage);
				}
				else if((atoi(value) != 0) && ((p = strchr(portrage, ':')) != NULL))
				{
					*p = '\0';
					if(atoi(portrage) == atoi(value))
					{
						do_uci_set(linebuf, portrage);
						return 0;
					}

					if(atoi(portrage) > atoi(value))
					{
						return -1;
					}

					strcat(portrage, ":");
					strcat(portrage, value);
					do_uci_set(linebuf, portrage);
				}
			}	
			else if(strcmp(option, "LocalIp") == 0)
			{
				sprintf(linebuf, "%s.local_ip", tmparray);
				do_uci_set(linebuf, value);
			}
			else if(strcmp(option, "ExternalIP") == 0)
			{
				sprintf(linebuf, "%s.external_ip", tmparray);
				do_uci_set(linebuf, value);
			}
			else if(strcmp(option, "LocalPort") == 0)
			{
				sprintf(linebuf, "%s.local_port", tmparray);
				do_uci_set(linebuf, value);
			}
			else if(strcmp(option, "Protocol") == 0)
			{
				sprintf(linebuf, "%s.protocol", tmparray);
				if(strcasecmp(value, "tcp") == 0)
				{
					do_uci_set(linebuf, "0");
				}
				else if(strcasecmp(value, "udp") == 0)
				{
					do_uci_set(linebuf, "1");
				}
				else if(strcasecmp(value, "both") == 0)
				{
					do_uci_set(linebuf, "2");
				}
			}
			else if(strcmp(option, "Enable") == 0)
			{
				sprintf(linebuf, "%s.is_enable", tmparray);
				do_uci_set(linebuf, value);
			}
			break;
		}
	}
	
	/*fp = fopen("/etc/portforwarding_save.txt", "r");
	if(fp != NULL)
	{
		fgets(buff1, sizeof(buff1), fp);
		s = buff1;

		p = strstr(buff1, "IsEnable");
		if(p != NULL)
		{
			q = strchr(p, ',');
			if(q != NULL)
			{
				strncpy(isenable, p-1, q- (p-1));	
			}
		}
		
		while((p = strstr(s, "ServiceName")) != NULL)
		{
			if (i > MAXPORTMPENTRY)
				break;
			if((q = strchr(p, '}')) != NULL)
			{
				strncpy(entry[i], p-2, (q+1) - (p-2));
				tr_log(LOG_DEBUG,"set entry[%d] [%s]", i, entry[i]);
				i++;
				s = q + 1;
			}
		}
		fclose(fp);
	}

	for(j=0; j<i; j++)
	{
		if((p = strstr(entry[j], "PortRange")) != NULL)
		{
			q = strchr(p, ':');
			s = strchr(p, ',');
			if(q != NULL && s != NULL)
			{
				memset(portrage, 0, sizeof(portrage));
				strncpy(portrage, q+2, (s-1)-(q+2));
				printf("portrage: %s\n", portrage);
			}
		}

		if ((p = strstr(portrage, ":")) != NULL)
			*p = '\0';

		if(strcmp(portrage, ExternalPort) == 0)
		{
			buff = entry[j];
			break;
		}
	}

	if (buff == NULL)
		return -1;

	tr_log(LOG_DEBUG,"set buff [%s]",buff);
	if((p = strstr(buff, "ServiceName")) != NULL)
	{
		q = strchr(p, ':');
		s = strchr(p, ',');
		if(q != NULL && s != NULL)
		{
			strncpy(servicename, q+2, (s-1)-(q+2));
		}
	}

	if((p = strstr(buff, "PortRange")) != NULL)
	{
		q = strchr(p, ':');
		s = strchr(p, ',');
		if(q != NULL && s != NULL)
		{
			memset(portrage, 0, sizeof(portrage));
			strncpy(portrage, q+2, (s-1)-(q+2));
			if ((p = strstr(portrage, ":")) != NULL)
				strcpy(ExternalPortEndRange, p+1);
		}
	}

	if((p = strstr(buff, "LocalIp")) != NULL)
	{
		q = strchr(p, ':');
		s = strchr(p, ',');
		if(q != NULL && s != NULL)
		{
			strncpy(localip, q+2, (s-1)-(q+2));
		}
	}

	if((p = strstr(buff, "LocalPort")) != NULL)
	{
		q = strchr(p, ':');
		s = strchr(p, ',');
		if(q != NULL && s != NULL)
		{
			strncpy(localport, q+2, (s-1)-(q+2));
		}
	}
	
	if((p = strstr(buff, "Protocol")) != NULL)
	{
		q = strchr(p, ':');
		s = strchr(p, '}');
		if(q != NULL && s != NULL)
		{
			strncpy(protocol, q+2, (s-1)-(q+2));
		}
	}

	tr_log(LOG_DEBUG,"set option [%s]",option);
	tr_log(LOG_DEBUG,"set value [%s]",value);

	if(strcmp(option, "ServiceName") == 0)
	{
		strcpy(servicename, value);
	}
	else if(strcmp(option, "ExternalPort") == 0)
	{
		memset(portrage, 0, sizeof(portrage));
		if (ExternalPortEndRange[0] != '\0')
			sprintf(portrage, "%s:%s", value, ExternalPortEndRange);
		else
			strcpy(portrage, value);
	}
	else if(strcmp(option, "PortRange") == 0)
	{
		if((atoi(value) != 0) && ((strchr(portrage, ':') == NULL)))
		{
			strcat(portrage, ":");
			strcat(portrage, value);
		}
		else if((atoi(value) != 0) && ((p = strchr(portrage, ':')) != NULL))
		{
			*p = '\0';
			strcat(portrage, ":");
			strcat(portrage, value);
		}
	}	
	else if(strcmp(option, "LocalIp") == 0)
	{
		strcpy(localip, value);
	}
	else if(strcmp(option, "LocalPort") == 0)
	{
		strcpy(localport, value);
	}
	else if(strcmp(option, "Protocol") == 0)
	{
		if(strcasecmp(value, "tcp") == 0)
		{
			strcpy(protocol, "0");
		}
		else if(strcasecmp(value, "udp") == 0)
		{
			strcpy(protocol, "1");
		}
		else if(strcasecmp(value, "both") == 0)
		{
			strcpy(protocol, "2");
		}
	}

	sprintf(portmapingentry, "{\"ServiceName\":\"%s\",\"PortRange\":\"%s\",\"LocalIp\":\"%s\",\"LocalPort\":\"%s\",\"Protocol\":\"%s\"}", 
		servicename, portrage, localip, localport, protocol);

	strcpy(buff, portmapingentry);
	
	sprintf(buff1, "{%s,\"PortForwardList\":[", isenable);

	for(j=0; j<i; j++)
	{
		strcat(buff1, entry[j]);
		strcat(buff1, ",");
	}

	p = strrchr(buff1, ',');
	if(p != NULL)
	{
		*p = '\0';
	}
	strcat(buff1, "]}");

	fp = fopen("/etc/portforwarding_save.txt", "w");
	if(fp != NULL)
	{
		fputs(buff1, fp);
		fclose(fp);
	}*/
	return 0;
}

int setwanhttpsacs(char *mischttpsport, char *lanip, char* lanport)
{
	int ret = 0,find = 0;	
	char cmdbuf[256] = {0};
	char tmpbuf[256] = {0};

	find = do_uci_get("firewall.wanhttpsacs",tmpbuf);
	if(find != 0){
		ret = do_uci_add("firewall","redirect",tmpbuf);
		if(ret != 0){return ret;}
		sprintf(cmdbuf, "firewall.%s", tmpbuf);
		ret = do_uci_rename(cmdbuf, "wanhttpsacs");
		if(ret != 0){return ret;}
	}

	do_uci_set("firewall.wanhttpsacs.enabled","1");

	ret = do_uci_set(FW_WAN_HTTPS_ACS_SRC,"wan");
	if(ret != 0){return ret;}
	ret = do_uci_set(FW_WAN_HTTPS_ACS_SRC_DPORT,mischttpsport);
	if(ret != 0){return ret;}
	ret = do_uci_set(FW_WAN_HTTPS_ACS_PROTO,"tcp");
	if(ret != 0){return ret;}
	ret = do_uci_set(FW_WAN_HTTPS_ACS_DEST,"lan");
	if(ret != 0){return ret;}
	ret = do_uci_set(FW_WAN_HTTPS_ACS_DEST_PORT,lanport);
	if(ret != 0){return ret;}

	return ret;
}

int setwanhttpacs(char *mischttpsport, char *lanip, char* lanport)
{
	int ret = 0,find = 0;	
	char cmdbuf[256] = {0};
	char tmpbuf[256] = {0};

	find = do_uci_get("firewall.wanhttpacs",tmpbuf);
	if(find != 0){
		ret = do_uci_add("firewall","redirect",tmpbuf);
		if(ret != 0){return ret;}
		sprintf(cmdbuf, "firewall.%s", tmpbuf);
		ret = do_uci_rename(cmdbuf, "wanhttpacs");
		if(ret != 0){return ret;}
	}

	do_uci_set("firewall.wanhttpacs.enabled","1");

	ret = do_uci_set(FW_WAN_HTTP_ACS_SRC,"wan");
	if(ret != 0){return ret;}
	ret = do_uci_set(FW_WAN_HTTP_ACS_SRC_DPORT,mischttpsport);
	if(ret != 0){return ret;}
	ret = do_uci_set(FW_WAN_HTTP_ACS_PROTO,"tcp");
	if(ret != 0){return ret;}
	ret = do_uci_set(FW_WAN_HTTP_ACS_DEST,"lan");
	if(ret != 0){return ret;}
	ret = do_uci_set(FW_WAN_HTTP_ACS_DEST_PORT,lanport);
	if(ret != 0){return ret;}

	return ret;
}

int disablewanacs()
{
	int i=0,find;
	char namebuf[128]={0};
	char tmpbuf[128]={0};

	find = do_uci_get("firewall.wanhttpacs",tmpbuf);
	if(!find)
		do_uci_set("firewall.wanhttpacs.enabled","0");
	find = do_uci_get("firewall.wanhttpsacs",tmpbuf);
	if(!find)
		do_uci_set("firewall.wanhttpsacs.enabled","0");

	do_uci_delete("firewall.wanhttpacs_limit",NULL);
	do_uci_delete("firewall.wanhttpsacs_limit",NULL);
	
	for(i=0;i<CLIENT_LIMIT_MAX;i++){
		sprintf(namebuf,"firewall.wanhttpacs_%d",i);
		find = do_uci_get(namebuf,tmpbuf);
		if(!find)
			do_uci_delete(namebuf,NULL);
		else
			break;
	}
	
	for(i=0;i<CLIENT_LIMIT_MAX;i++){
		sprintf(namebuf,"firewall.wanhttpsacs_%d",i);
		find = do_uci_get(namebuf,tmpbuf);
		if(!find)
			do_uci_delete(namebuf,NULL);
		else
			break;
	}
	return 1;
}

int getlanip(char* val)
{
	FILE* fp;   
	char buf[150] = {0};
	char *retval=NULL;
	char command[150] = {0};   
	sprintf(command, "ifconfig br-lan | awk '{print $2}' | grep ^addr: | awk -F ':' '{print $2\";\"}'");   

	if((fp = popen(command,"r")) == NULL){
		tr_log(LOG_ERROR,"getlanip error");
		return -1;
	}  

	if((fgets(buf,150,fp))!= NULL)
	{
		retval = strtok(buf,";");
	}
	pclose(fp);
	sprintf(val,"%s",retval);
	return 0;
}

// mode: 0 http; 1 https; 2 both;
int getRemoteAccessMode()
{
	char value[32] = {0};
	int find = 0;
	int mode = 0;
	
	memset(value, 0x00, sizeof(value));
	find = do_uci_get(ADMIN_SYS_MISC_HTTP_MODE, value);
	if(!find){
		mode = atoi(value);
	}
	else{
		mode = 0;
	}

	return mode;
}

int doRemoteAccess(int enable)
{
	char value[128] = {0};
	char tmpbuf[128] = {0};
	char cmdbuf[512] = {0};
	char mischttpport[128] = {0};
	char mischttpsport[128] = {0};
	char lanip[128];
	int ret = 0;
	int httpmode = 0;
	char *lanport = NULL;
	
	if(enable == 1)
	{
		ret = do_uci_set(ADMIN_SYS_MISC_HTTP,"1");
		ret = do_uci_get(ADMIN_SYS_AUTH_MODE_HTTP, value);
		int httpsen = do_uci_get(ADMIN_SYS_AUTH_MODE_HTTPS,value);
		
		if(!ret && !httpsen)
		{
			lanport = strrchr(value,':');
			lanport++;
			httpmode = 2;
		}
		else if (!ret && httpsen)
		{
			httpmode = 0;
		}
		else if(ret && !httpsen)
		{
			lanport = strrchr(value,':');
			lanport++;
			httpmode = 1;
		}

		ret = do_uci_get(ADMIN_SYS_MISC_HTTP_PORT,mischttpport);
		ret = do_uci_get(ADMIN_SYS_MISC_HTTPS_PORT,mischttpsport);

		char lanip[128] = {0};
		ret = getlanip(lanip);
		if(ret != 0)
		{
			return -1;
		}

		switch(httpmode)
		{
			case 0://http
				sprintf(cmdbuf,"echo \
					\"iptables -I input_rule -j ACCEPT -p tcp -d %s --dport 80\" \
					> %s",lanip,WAN_ACCESS_WEB);
				system(cmdbuf);
				setwanhttpacs(mischttpport,lanip,"80");
				do_uci_delete("firewall.wanhttpsacs",NULL);
				break;
			case 1://https
				sprintf(cmdbuf,"echo \
					\"iptables -I input_rule -j ACCEPT -p tcp -d %s --dport %s\" \
					> %s",lanip,lanport,WAN_ACCESS_WEB);
				system(cmdbuf);
				setwanhttpsacs(mischttpsport,lanip,lanport);
				do_uci_delete("firewall.wanhttpacs",NULL);
				break;
			case 2://both
				sprintf(cmdbuf,"echo \
					\"iptables -I input_rule -j ACCEPT -p tcp -d %s --dport 80\" \
					> %s",lanip,WAN_ACCESS_WEB);
				system(cmdbuf);
				setwanhttpacs(mischttpport,lanip,"80");
				sprintf(cmdbuf,"echo \
					\"iptables -I input_rule -j ACCEPT -p tcp -d %s --dport %s\" \
					>> %s",lanip,lanport,WAN_ACCESS_WEB);
				system(cmdbuf);
				setwanhttpsacs(mischttpsport,lanip,lanport);
				break;
		}


		int find = do_uci_get(ADMIN_SYS_WAN_ACCESS,tmpbuf);
		if(find != 0)
		{
			memset(tmpbuf,0,sizeof(tmpbuf));
			ret = do_uci_add("firewall","include",tmpbuf);
			sprintf(cmdbuf, "firewall.%s", tmpbuf);
			ret = do_uci_rename(cmdbuf, "wanaccess");
			if(ret != 0)
			{
				return -1;
			}
			ret = do_uci_set("firewall.wanaccess.path",WAN_ACCESS_WEB);
			ret = do_uci_set("firewall.wanaccess.type","script");
			ret = do_uci_set("firewall.wanaccess.family","any");
			ret = do_uci_set("firewall.wanaccess.reload","1");
		}
	}
	else
	{
		ret = do_uci_set(ADMIN_SYS_MISC_HTTP,"0");
		sprintf(cmdbuf,"echo > %s",WAN_ACCESS_WEB);
		ret = system(cmdbuf);
		disablewanacs();
		ret = do_uci_set(LOGIN_ALLOW_SPECIFIED_IP,"0");
		if(ret != 0)
		{
			return -1;
		}
	}
	if (ret == 0) 
	{	
		do_uci_commit("uhttpd");
		do_uci_commit("firewall");		
		system("/etc/init.d/firewall restart"); //firewall restart
		system("/etc/init.d/uhttpd restart	&");	//httpd reload(must be reload)
	}
	return ret;
}

static int limithttpacs(char clientlist[][64],int clientlimit,int clientnum,char* mischttpport)
{
	char cmdbuf[1024]={0};
	char tmpbuf[128]={0};
	char lanip[128]={0};
	FILE *fp=NULL;
	int i=0;
	int ret = getlanip(lanip);
	if(ret != 0){
		return 0;
	}
	
	if(clientlimit && clientnum>0){
		do_uci_set("firewall.wanhttpacs.enabled","0");
		ret = do_uci_get("firewall.wanhttpacs_limit",tmpbuf);
		if(ret != 0){
			ret = do_uci_add("firewall","include",tmpbuf);
			if(ret != 0){return ret;}
			sprintf(cmdbuf, "firewall.%s", tmpbuf);
			ret = do_uci_rename(cmdbuf, "wanhttpacs_limit");			
			if(ret != 0){return ret;}
			ret = do_uci_set("firewall.wanhttpacs_limit.path",WAN_HTTP_ACCESS_WEB);
			if(ret != 0){return ret;}
			ret = do_uci_set("firewall.wanhttpacs_limit.type","script");
			if(ret != 0){return ret;}
			ret = do_uci_set("firewall.wanhttpacs_limit.family","any");
			if(ret != 0){return ret;}
			ret = do_uci_set("firewall.wanhttpacs_limit.reload","1");
			if(ret != 0){return ret;}
		}

		fp=fopen(WAN_HTTP_ACCESS_WEB,"w");
		for(i=0;i<clientnum;i++){
			fprintf(fp,"iptables -t nat -I zone_wan_prerouting -j DNAT -p tcp --dport %s -m iprange --src-range %s --to-destination %s:%s\n",mischttpport,clientlist[i],lanip,"80");
		}
		fclose(fp);
	}else{
		do_uci_delete("firewall.wanhttpacs_limit",NULL);
		setwanhttpacs(mischttpport,lanip,"80");
	}

	return 1;
}

static int limithttpsacs(char clientlist[][64],int clientlimit,int clientnum,char* lanport,char* mischttpsport)
{
	char cmdbuf[1024]={0};
	char tmpbuf[128]={0};
	char lanip[128]={0};
	FILE *fp=NULL;
	int i=0;
	int ret = getlanip(lanip);
	if(ret != 0){
		return 0;
	}
	
	if(clientlimit && clientnum>0){
		do_uci_set("firewall.wanhttpsacs.enabled","0");
		ret = do_uci_get("firewall.wanhttpsacs_limit",tmpbuf);
		if(ret != 0){
			ret = do_uci_add("firewall","include",tmpbuf);
			if(ret != 0){return ret;}
			sprintf(cmdbuf, "firewall.%s", tmpbuf);
			ret = do_uci_rename(cmdbuf, "wanhttpsacs_limit");			
			if(ret != 0){return ret;}
			ret = do_uci_set("firewall.wanhttpsacs_limit.path",WAN_HTTPS_ACCESS_WEB);
			if(ret != 0){return ret;}
			ret = do_uci_set("firewall.wanhttpsacs_limit.type","script");
			if(ret != 0){return ret;}
			ret = do_uci_set("firewall.wanhttpsacs_limit.family","any");
			if(ret != 0){return ret;}
			ret = do_uci_set("firewall.wanhttpsacs_limit.reload","1");
			if(ret != 0){return ret;}
		}
		
		fp=fopen(WAN_HTTPS_ACCESS_WEB,"w");
		for(i=0;i<clientnum;i++){
			fprintf(fp,"iptables -t nat -I zone_wan_prerouting -j DNAT -p tcp --dport %s -m iprange --src-range %s --to-destination %s:%s\n",mischttpsport,clientlist[i],lanip,lanport);
		}
		fclose(fp);
		fp = NULL;
	}else{
		do_uci_delete("firewall.wanhttpsacs_limit",NULL);
		setwanhttpsacs(mischttpsport,lanip,lanport);
	}

	return 1;
}

static void parse_iprange_list(char *ipranges, char *delimiter, char clientlist[][64], int *clientnum )
{
	int j;
	char *str = NULL;
	char *token = NULL;
	char *saveptr = NULL;

	*clientnum = 0;
	for (j = 1, str = ipranges; ; j++, str = NULL) {
		token = strtok_r(str, delimiter, &saveptr);
		if (token == NULL)
			break;
		strcpy(clientlist[*clientnum], token);
		*clientnum = j;
	}
}

int setRemoteAccess(int enable)
{
	char value[128] = {0};
	char tmpbuf[128] = {0};
	char cmdbuf[512] = {0};
	char mischttpport[128] = {0};
	char mischttpsport[128] = {0};
	char lanip[128];
	int ret = 0;
	int http = 0;
	int https = 0;
	int httpmode = 0;
	char *lanport = NULL;
	char allowip[32] = {0};
	char ipranges[128] = {0};
	char clientlist[CLIENT_LIMIT_MAX][64]={{0}};
	int clientlimit = 0;
	int clientnum = 0;
	
	if(parameternum == 0)
	{
	if(enable == 1)
	{
		ret = do_uci_set(ADMIN_SYS_MISC_HTTP,"1");
		if(ret)
			return -1;

		http = do_uci_get(ADMIN_SYS_AUTH_MODE_HTTP, value);
		https = do_uci_get(ADMIN_SYS_AUTH_MODE_HTTPS,value);		
		/*if (!http && https)
		{
			httpmode = 0;
		}
		else if(http && !https)
		{
			lanport = strrchr(value,':');
			lanport++;
			httpmode = 1;
		}
		else if(!http && !https)
		{
			lanport = strrchr(value,':');
			lanport++;
			httpmode = 2;
		}*/

		if (getRemoteAccessMode() == 0){
			httpmode = 0;
		}
		else
		{
			httpmode = 1;
			lanport = value;
		}

		char lanip[128] = {0};
		ret = getlanip(lanip);
		if(ret != 0)
		{
			return -2;
		}

		if(do_uci_get(ADMIN_SYS_MISC_HTTP_PORT,mischttpport))
			strcpy(mischttpport, "8081");
		
		if(do_uci_get(ADMIN_SYS_MISC_HTTPS_PORT,mischttpsport))
			strcpy(mischttpsport, "8444");

		if(do_uci_get(LOGIN_ALLOW_SPECIFIED_IP,allowip))
			strcpy(allowip, "0");
		clientlimit = atoi(allowip);

		if(do_uci_get(LOGIN_ALLOWED_IP, ipranges)){
			strcpy(ipranges, "");
		}
		
		parse_iprange_list(ipranges, " ", clientlist, &clientnum);
		switch(httpmode)
		{
			case 0://http
				disablewanacs();
				/*sprintf(cmdbuf,"echo \
					\"iptables -I input_rule -j ACCEPT -p tcp -d %s --dport 80\" \
					> %s",lanip,WAN_ACCESS_WEB);
				system(cmdbuf);*/
				limithttpacs(clientlist,clientlimit,clientnum,mischttpport);
				do_uci_set("firewall.wanhttpsacs.enabled","0");
				break;
			case 1://https
				disablewanacs();
				/*sprintf(cmdbuf,"echo \
					\"iptables -I input_rule -j ACCEPT -p tcp -d %s --dport %s\" \
					> %s",lanip,lanport,WAN_ACCESS_WEB);
				system(cmdbuf);*/
				limithttpsacs(clientlist,clientlimit,clientnum,lanport,mischttpsport);
				do_uci_set("firewall.wanhttpacs.enabled","0");
				break;
			/*case 2://both
				sprintf(cmdbuf,"echo \
					\"iptables -I input_rule -j ACCEPT -p tcp -d %s --dport 80\" \
					> %s",lanip,WAN_ACCESS_WEB);
				system(cmdbuf);
				limithttpacs(clientlist,clientlimit,clientnum,mischttpport);
				sprintf(cmdbuf,"echo \
					\"iptables -I input_rule -j ACCEPT -p tcp -d %s --dport %s\" \
					>> %s",lanip,lanport,WAN_ACCESS_WEB);
				system(cmdbuf);
				limithttpsacs(clientlist,clientlimit,clientnum,lanport,mischttpsport);
				break;*/
		}


		int find = do_uci_get(ADMIN_SYS_WAN_ACCESS,tmpbuf);
		if(find != 0)
		{
			memset(tmpbuf,0,sizeof(tmpbuf));
			ret = do_uci_add("firewall","include",tmpbuf);
			sprintf(cmdbuf, "firewall.%s", tmpbuf);
			ret = do_uci_rename(cmdbuf, "wanaccess");
			if(ret != 0)
			{
				return -1;
			}
			ret = do_uci_set("firewall.wanaccess.path",WAN_ACCESS_WEB);
			ret = do_uci_set("firewall.wanaccess.type","script");
			ret = do_uci_set("firewall.wanaccess.family","any");
			ret = do_uci_set("firewall.wanaccess.reload","1");
		}
	}
	else
	{
		ret = do_uci_set(ADMIN_SYS_MISC_HTTP,"0");
		/*sprintf(cmdbuf,"echo > %s",WAN_ACCESS_WEB);
		ret = system(cmdbuf);*/
		disablewanacs();
		ret = do_uci_set(LOGIN_ALLOW_SPECIFIED_IP,"0");
		if(ret != 0)
		{
			return -1;
		}
	}
	if (ret == 0) 
	{	
		do_uci_commit("lighttpd");
		do_uci_commit("firewall");		
		system("/etc/init.d/firewall restart"); //firewall restart
		system("/etc/init.d/lighttpd restart	&");	//httpd reload(must be reload)
	}
	}
	return ret;
}

void setRemoteAccess2()
{
	if(parameternum == 0)
		set_remoteaccess = 1;
}

void set_RemoteAccess()
{
	pthread_detach( pthread_self() );
	tr_log( LOG_WARNING, "set_RemoteAccess" );
	system("sh /lib/firewall/wanacs.sh &");
	return;
}

int get_ssdk_mib_statistics(int index, char *name)
{
	char command[256] = {0};
	char buff[256] = {0};
	char temp[256] = {0};
	FILE *fp = NULL;
	char *p = NULL;
	char *q = NULL;
	char *s = NULL;
	int count = 0;
	char *endptr;
	
	sprintf(command, "ssdk_sh mib statistics get %d", index);
	fp = popen(command, "r");
	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp))
		{
			if((p = strstr(buff, name)) != NULL)
			{
				tr_log(LOG_DEBUG,"p [%s]",p );
				q = strstr(p, "<");
				s = strstr(p, ">");
				*s = '\0';
				strcpy(temp, q+1);
				tr_log(LOG_DEBUG,"temp[%s]",temp);
				count = strtol(temp, &endptr, 16);
				tr_log(LOG_DEBUG,"count[%d]",count);
				break;
			}
		}
		pclose(fp);
	}
	return count;
}

void getSSIStats(char *p, char *key, char *value)
{
	char buff[128] = {0};
	char tmp[128] = {0};
	char inf[32] = {0};
	FILE *fp = NULL;
	char *q = NULL;
	
	getWiFiInterfaceNameWithInstanceNum(p, inf);
	sprintf(tmp, "apstats -v -i %s | grep '%s'", inf, key);
	
	tr_log(LOG_DEBUG,"################################################tmp[%s]",tmp);

	fp = popen(tmp, "r");
	if(fp != NULL)
	{
		if(fgets(buff, sizeof(buff), fp) != NULL)
		{
			if((q = strstr(buff, "=")) != NULL)
					strcpy(value, q+2);
			if((q = strstr(value, "\n")) != NULL)
				*q = '\0';
		}
		else
			strcpy(value, "0");
		pclose(fp);
	}
	else
		strcpy(value, "0");
}

int _get_endporint_5g_enable()
{
	int ret = 0;
	char ath_en[32] = {0};
	char wifimode[32] = {0};
	ret = do_uci_get("wireless.wla.ath_enable", ath_en);
	if(ret)
	{
		return -1;
	}
	ret = do_uci_get("wireless.wla.mode", wifimode);
	if(ret)
	{
		return -1;
	}
	if (strcmp(wifimode, "sta") == 0 && atoi(ath_en) == 1)
		ret = 1;
	else
		ret = 0;

	return ret;
}

int _get_endporint_24g_enable()
{
	int ret = 0;
	char ath_en[32] = {0};
	char wifimode[32] = {0};
	ret = do_uci_get("wireless.wlg.ath_enable", ath_en);
	if(ret)
	{
		return -1;
	}
	ret = do_uci_get("wireless.wlg.mode", wifimode);
	if(ret)
	{
		return -1;
	}
	if (strcmp(wifimode, "sta") == 0 && atoi(ath_en) == 1)
		ret = 1;
	else
		ret = 0;

	return ret;
}

int _get_endporint_5g_profile_status(char *value)
{
	int ret = 0;
	char ath_en[32] = {0};
	char wifimode[32] = {0};
	FILE *fp = NULL;
	char line[128] = {0};
	ret = do_uci_get("wireless.wla.ath_enable", ath_en);
	if(ret)
	{
		return -1;
	}
	if (atoi(ath_en) == 0){
		strcpy(value, "Disabled");
		ret = 0;
		goto end;
	}
	
	ret = do_uci_get("wireless.wla.mode", wifimode);
	if(ret)
	{
		return -1;
	}
	if (strcmp(wifimode, "sta") != 0){
		strcpy(value, "Disabled");
		ret = 0;
		goto end;
	}

	if (fp = popen("iwconfig ath0 | grep 'Not-Associated'", "r")){
		if (fgets(line, sizeof(line), fp))
			strcpy(value, "Available");
		else
			strcpy(value, "Active");
		pclose(fp);
	}
	
	end:
	tr_log(LOG_DEBUG,"get value [%s]",value);
	return ret;
}

int _get_endporint_24g_profile_status(char *value)
{
	int ret = 0;
	char ath_en[32] = {0};
	char wifimode[32] = {0};
	FILE *fp = NULL;
	char line[128] = {0};
	ret = do_uci_get("wireless.wlg.ath_enable", ath_en);
	if(ret)
	{
		return -1;
	}
	if (atoi(ath_en) == 0){
		strcpy(value, "Disabled");
		ret = 0;
		goto end;
	}
	
	ret = do_uci_get("wireless.wlg.mode", wifimode);
	if(ret)
	{
		return -1;
	}
	if (strcmp(wifimode, "sta") != 0){
		strcpy(value, "Disabled");
		ret = 0;
		goto end;
	}

	if (fp = popen("iwconfig ath1 | grep 'Not-Associated'", "r")){
		if (fgets(line, sizeof(line), fp))
			strcpy(value, "Available");
		else
			strcpy(value, "Active");
		pclose(fp);
	}
	
	end:
	tr_log(LOG_DEBUG,"get value [%s]",value);
	return ret;
}

int getRouterIPv4Number()
{
	FILE *fp = NULL;
	char buff[256] = {0};
	int i = 0;
	
	fp = fopen("/oneagent/conf/RouterIPv4Map.mapping", "r");

	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp))
		{
			i++;
		}
		fclose(fp);
	}
	return i;
}

void getRouterIPv4Option(char *key, char *value, char *option)
{
	char buff[256] = {0};
	char destIP[256] = {0};
	char gateway[256] = {0};
	char mask[256] = {0};
	char metric[256] = {0};
	char iface[256] = {0};	
	FILE *fp = NULL;

	system("route -n >/tmp/routeipv4");	

	fp = fopen("/tmp/routeipv4", "r");
	if(fp != NULL)
	{
		fgets(buff, sizeof(buff), fp);
		fgets(buff, sizeof(buff), fp);
		while(fgets(buff, sizeof(buff), fp))
		{
			sscanf(buff, "%s %s %s %*s %s %*s %*s %s", destIP, gateway, mask, metric, iface);
			if(strcmp(destIP, key) == 0)
				break;
		}
		fclose(fp);
	}
	
	if(strcmp(option, "Destination") == 0)
	{
		strcpy(value, destIP);
	}
	else if(strcmp(option, "Gateway") == 0)
	{
		strcpy(value, gateway);
	}
	else if(strcmp(option, "Genmask") == 0)
	{
		strcpy(value, mask);
	}
	else if(strcmp(option, "Metric") == 0)
	{
		strcpy(value, metric);
	}
	else if(strcmp(option, "Iface") == 0)
	{
		strcpy(value, iface);
	}
}

int isStaticRoute(char *key)
{
	char tmpbuf[256] = {0};
	char destIP[256] = {0};
	char name[128] = {0};
	int j = 0;

	do_uci_get("staticrt.staticrt.listnum", tmpbuf);
	for(j=0; j<atoi(tmpbuf); j++)
	{
		sprintf(name,"staticrt.routelist_%d.hostip",j);
		do_uci_get(name,destIP);

		if(strcmp(destIP, key) == 0)
		{
			return j+1;
		}
	}
	return 0;
}

int run_portmaping_entry()
{
	char *buff = NULL;
	char buff1[8192] = {0};
	char portmapingentry[1024] = {0};
	char servicename[128] = {0};
	char port_range[128] = {0};
	char local_ip[128] = {0};
	char local_port[128] = {0};
	char proto_type[128] = {0};
	FILE *fp = NULL;
	char *p = NULL;
	char *q = NULL;
	char *s = NULL;
	char entry[32][1024] = {0};
	int i = 0;
	int j = 0;
	char isenable[32] = {0};
	char ip_rule[128][256] = {{0}};
	char cmdline[512] = {0};
	int ret = 0;
	
	fp = fopen("/etc/portforwarding_save.txt", "r");
	if(fp != NULL)
	{
		fgets(buff1, sizeof(buff1), fp);
		s = buff1;

		p = strstr(buff1, "IsEnable");
		if(p != NULL)
		{
			q = strchr(p, ':');
			s = strchr(p, ',');
			tr_log(LOG_NOTICE,"+++++++++++++++q:[%s]\n", q );
			tr_log(LOG_NOTICE,"+++++++++++++++s:[%s]\n", s );
			if(q != NULL && s != NULL)
			{
				strncpy(isenable, q+1, s-(q+1));	
				tr_log(LOG_NOTICE,"+++++++++++++++isenable:[%s]\n", isenable);
			}
		}
		
		while((p = strstr(s, "ServiceName")) != NULL)
		{
			if((q = strchr(p, '}')) != NULL)
			{
				strncpy(entry[i], p-2, (q+1) - (p-2));
				tr_log(LOG_DEBUG,"set entry[%d] [%s]", i, entry[i]);
				i++;
				s = q + 1;
			}
		}
		fclose(fp);
	}
	tr_log(LOG_NOTICE,"+++++++++++++++isenable:[%d]\n", atoi(isenable) );

	if(atoi(isenable) == 1)
	{
		for(j=0; j<i; j++)
		{
			buff = entry[j];
			if((p = strstr(buff, "PortRange")) != NULL)
			{
				q = strchr(p, ':');
				s = strchr(p, ',');
				if(q != NULL && s != NULL)
				{
					strncpy(port_range, q+2, (s-1)-(q+2));
				}
			}
			
			if((p = strstr(buff, "LocalIp")) != NULL)
			{
				q = strchr(p, ':');
				s = strchr(p, ',');
				if(q != NULL && s != NULL)
				{
					strncpy(local_ip, q+2, (s-1)-(q+2));
				}
			}
			
			if((p = strstr(buff, "LocalPort")) != NULL)
			{
				q = strchr(p, ':');
				s = strchr(p, ',');
				if(q != NULL && s != NULL)
				{
					strncpy(local_port, q+2, (s-1)-(q+2));
				}
			}
			
			if((p = strstr(buff, "Protocol")) != NULL)
			{
				q = strchr(p, ':');
				s = strchr(p, '}');
				if(q != NULL && s != NULL)
				{
					strncpy(proto_type, q+2, (s-1)-(q+2));
				}
			}
		
			switch (atoi(proto_type)) {
				case 0:
					sprintf(ip_rule[j], "iptables -t filter -I zone_wan_forward -d %s/32 -p %s -m %s --dport %s -j ACCEPT", \
						local_ip, "tcp", "tcp", local_port);
					sprintf(ip_rule[j + 1], "iptables -t nat -I prerouting_wan_rule -p %s -m %s --dport %s -j DNAT --to-destination %s:%s ", \
						"tcp", "tcp", port_range, local_ip, local_port);
					j = j + 2;
					break;
				case 1: 
					sprintf(ip_rule[j], "iptables -t filter -I zone_wan_forward -d %s/32 -p %s -m %s --dport %s -j ACCEPT", \
						local_ip, "udp", "udp", local_port);
					sprintf(ip_rule[j + 1], "iptables -t nat -I prerouting_wan_rule -p %s -m %s --dport %s -j DNAT --to-destination %s:%s ", \
						"udp", "udp", port_range, local_ip, local_port);
					j = j + 2;
					break;
				case 2: 
					sprintf(ip_rule[j], "iptables -t filter -I zone_wan_forward -d %s/32 -p %s -m %s --dport %s -j ACCEPT", \
						local_ip, "tcp", "tcp", local_port);
					sprintf(ip_rule[j + 1], "iptables -t nat -I prerouting_wan_rule -p %s -m %s --dport %s -j DNAT --to-destination %s:%s ", \
						"tcp", "tcp", port_range, local_ip, local_port);
					sprintf(ip_rule[j + 2], "iptables -t filter -I zone_wan_forward -d %s/32 -p %s -m %s --dport %s -j ACCEPT", \
						local_ip, "udp", "udp", local_port);
					sprintf(ip_rule[j + 3], "iptables -t nat -I prerouting_wan_rule -p %s -m %s --dport %s -j DNAT --to-destination %s:%s ", \
						"udp", "udp", port_range, local_ip, local_port);
					j = j + 4;
					break;
				case 3: 
					sprintf(ip_rule[j], "iptables -I zone_wan_forward -p %s -j DNAT --to-destination %s ", \
						port_range, local_ip);
					j++;
					break;
				default:
					ret = -1;
					break;
			}
		}
		
		sprintf(cmdline, "echo -e \" \" > %s", "/etc/firewall_port_forwarding.user");
		system(cmdline);
		
		for (i = 0; ip_rule[i][0] != 0; i++)
		{
			if (i >= 127) {
				break;
			}
			sprintf(cmdline, "echo -e \"%s\" >> %s", ip_rule[i], "/etc/firewall_port_forwarding.user");
			tr_log(LOG_NOTICE,"+++++++++++++++cmdline: %s\n", cmdline);
			ret = system(cmdline);
			if (ret != 0) 
			{
				return -1;
			}
		}
	}
	else
	{
		do_uci_set("firewall.wan_pf._enabled", "0");
		do_uci_delete("firewall.wan_pf.path", NULL);
		ret = do_uci_set("firewall.wan_pf.enabled", "0");
	}
	ret = do_uci_commit("firewall");
	if(ret)
	{
		return (-1);
	}
	system("/etc/init.d/firewall restart");
	return ret;
}

int getPortmappingEntry(char *option, char *value, char *key)
{
	int i = 0;
	int ret = -1;
	char linebuf[128] = {0};
	char tmparray[64] = {0};
	char valbuf[64] = {0};
	char valbuf1[64] = {0};
	char port_protocol[256] = {0};
	char *ptr = NULL;

	tr_log(LOG_DEBUG,"get value [%s]",key);

	for(i=0; i<MAX_PF_ELEM; i++)
	{
		sprintf(tmparray, "firewall_nat.pf%d", i);
		sprintf(linebuf, "%s.port_range", tmparray);
		tr_log(LOG_DEBUG,"tmparray [%s]",tmparray);
		ret = do_uci_get(linebuf, valbuf);
		if (ret != 0)
		{
			continue;
		}
		ptr = strchr(valbuf, ':');
		if(ptr != NULL)
		{
			*ptr = '\0';
		}

		sprintf(linebuf, "%s.protocol", tmparray);
		tr_log(LOG_DEBUG,"linebuf [%s]",linebuf);
		ret = do_uci_get(linebuf, valbuf1);

		sprintf(port_protocol, "%s_%s", valbuf, valbuf1);
		tr_log(LOG_DEBUG,"port_protocol [%s]",port_protocol);
		
		if(strcmp(port_protocol, key) == 0)
		{
			if(strcmp(option, "ServiceName") == 0)
			{
				sprintf(linebuf, "%s.srv_name", tmparray);
				do_uci_get(linebuf, value);
			}
			else if(strcmp(option, "ExternalPort") == 0)
			{
				sprintf(linebuf, "%s.port_range", tmparray);
				do_uci_get(linebuf, value);
			}
			else if(strcmp(option, "PortRange") == 0)
			{
				sprintf(linebuf, "%s.port_range", tmparray);
				do_uci_get(linebuf, value);
			}	
			else if(strcmp(option, "LocalIp") == 0)
			{
				sprintf(linebuf, "%s.local_ip", tmparray);
				do_uci_get(linebuf, value);
			}
			else if(strcmp(option, "ExternalIP") == 0)
			{
				sprintf(linebuf, "%s.public_ip", tmparray);
				do_uci_get(linebuf, value);
			}
			else if(strcmp(option, "LocalPort") == 0)
			{
				sprintf(linebuf, "%s.local_port", tmparray);
				do_uci_get(linebuf, value);
			}
			else if(strcmp(option, "Protocol") == 0)
			{
				sprintf(linebuf, "%s.protocol", tmparray);
				do_uci_get(linebuf, value);
			}
			else if(strcmp(option, "Enable") == 0)
			{
				sprintf(linebuf, "%s.is_enable", tmparray);
				do_uci_get(linebuf, value);
			}
			break;
		}
	}

	/*char buff[8192] = {0};
	FILE *fp = NULL;
	char *p = NULL;
	char *q = NULL;
	char *s = NULL;
	char entry[MAXPORTMPENTRY][1024] = {0};
	int i = 0;
	int j = 0;
	char tmp[128] = {0};
	
	fp = fopen("/etc/portforwarding_save.txt", "r");
	if(fp != NULL)
	{
		fgets(buff, sizeof(buff), fp);
		s = buff;
		printf("s: %s\n", s);
		while((p = strstr(s, "ServiceName")) != NULL)
		{
			if (i > MAXPORTMPENTRY)
				break;
			if((q = strchr(p, '}')) != NULL)
			{
				strncpy(entry[i], p-2, (q+1) - (p-2));
				i++;
				s = q + 1;
			}
		}
		fclose(fp);
	}

	for(j=0; j<i; j++)
	{
		if((p = strstr(entry[j], "PortRange")) != NULL)
		{
			q = strchr(p, ':');
			s = strchr(p, ',');
			if(q != NULL && s != NULL)
			{
				memset(tmp, 0, sizeof(tmp));
				strncpy(tmp, q+2, (s-1)-(q+2));
				tr_log(LOG_DEBUG,"#########################tmp[%s]",tmp);
			}
			if ((p = strstr(tmp, ":")) != NULL)
				*p = '\0';
			if(strcmp(tmp, key) == 0)
			{
				strcpy(value, entry[j]);
				return 1;
			}
		}
	}*/
	return 0;
}

void restartTR069CWMP()
{
	//system("killall -SIGUSR1 oneagent_mon"); // do not reboot instantly, it may result in tr.xml losing object.
	need_reboot_agent(); // reboot when session destroy.
	tr_log(LOG_DEBUG,"reboot when session destroy.");
}

void doDelayReboot()
{
	int i = 0;
	pthread_detach( pthread_self() );
	while (i < dealayrebootsens){
		sleep(1);
		i ++;
		//tr_log( LOG_DEBUG, "Do Dealy reboot, %d, dealayrebootsens=%d.................", i, dealayrebootsens);
	}
	while (session_end != 1){ //MUST wait for sessin end
		sleep(1);
		tr_log( LOG_DEBUG, "Waiting sesstion to end.................");
	}
	tr_log( LOG_DEBUG, "End Dealy reboot secs.................");
	do_uci_set(DM_DelayReboot, "-1");
	do_uci_commit(MS);
	system("reboot");
	pthread_exit( 0 );
}

void doScheduleReboot()
{
	long int i = 0;
	pthread_detach( pthread_self() );
	while (i < schedulerebootsens){
		sleep(1);
		i ++;
		//tr_log( LOG_DEBUG, "Do Schedule reboot, %ld, schedulerebootsens=%ld.................", i, schedulerebootsens);
	}
	while (session_end != 1){ //MUST wait for sessin end
		sleep(1);
		tr_log( LOG_DEBUG, "Waiting sesstion to end................");
	}
	tr_log( LOG_DEBUG, "End Schedule reboot secs.................");
	system("reboot");
	pthread_exit( 0 );
}

void getMAPTInfo(char *value, char *key)
{
	FILE *fp = NULL;
	char cmd[128] = {0};
	char line[512] = {0};
	char *ptr1 = NULL, *ptr2 = NULL;

	sprintf(cmd, "cat /tmp/map-wan6_4.rules | grep '%s'", key);

	if ((fp=popen(cmd,"r")) != NULL){
		if (fgets(line,sizeof(line)-1,fp)){
			if ((ptr1 = strstr(line, "=")) != NULL){
				strcpy(value, ptr1 + 1);
				if ((ptr2 = strstr(value, "\n")) != NULL)
					*ptr2 = '\0';
			}
			else
				strcpy(value, "");
		}
		else
			strcpy(value, "");

		pclose(fp);
	}
	else
		strcpy(value, "");
}

int getDHCPv6ClientLinkStatus()
{
	int ret = 0;
	char dhcpc[32] = {0};
	a_infinfo wanStatus;

	do_uci_get("ipv6.@global[0].connection_type", dhcpc);
	if (atoi(dhcpc) == 1){
		memset(&wanStatus, 0, sizeof(wanStatus));
		getInterfaceInfo("wan6", &wanStatus);
		if (strcmp(wanStatus.ipv6_address, "") != 0)
			ret = 1;
	}

	return ret;
}

int getDHCPv6ServerPoolStatus()
{
	int ret = 0;
	char ipv6_connection_type[32] = {0};
	ret = do_uci_get("ipv6.@global[0].connection_type", ipv6_connection_type);
	if(ret)
	{
		strcpy(ipv6_connection_type, "0");
	}
	if (atoi(ipv6_connection_type) != 0){ //means static ipv6 mode
		return 1;
	}

	return 0;
}

int getIPv6Enable()
{
	int ret = 0;
	char value[32] = {0};
	
	ret = do_uci_get("ipv6.@global[0].connection_type", value);
	if(ret)
		ret = 0;
	if (atoi(value) == 0)
		ret = 0;
	else
		ret = 1;
	return ret;
}

int isInRange(int d, int min, int max)
{
    return ( d > max || d < min )? 0: 1;
}

int isValidIP(char *buf)
{
    int ip[4] = {0};
	int i = 0;
	int count = 0;

	for(i=0; i<strlen(buf); i++)
	{
		if((buf[i] >= '0' && buf[i] <= '9') || (buf[i] == '.'))
		{
			if(buf[i] == '.')
			{
				count++;
			}

			if(count > 3)
			{
				return 0;
			}
			continue;
		}
		return 0;
	}

    sscanf(buf,"%d.%d.%d.%d",&(ip[0]),&(ip[1]),&(ip[2]),&(ip[3]));
    //tr_log(LOG_DEBUG,"buf=%s, IP=%d.%d.%d.%d\n", buf, ip[0], ip[1], ip[2], ip[3]);

    if (isInRange(ip[0], 1, 223) == 0) return 0;
    if (ip[0]== 127) return 0;
    if (isInRange(ip[1], 0, 255) == 0) return 0;
    if (isInRange(ip[2], 0, 255) == 0) return 0;
    if (isInRange(ip[3], 1, 255) == 0) return 0;

    return 1;
}

//for routing dest ip
int isValidIP2(char *buf)
{
    int ip[4] = {0};
	int i = 0;
	int count = 0;

	for(i=0; i<strlen(buf); i++)
	{
		if((buf[i] >= '0' && buf[i] <= '9') || (buf[i] == '.'))
		{
			if(buf[i] == '.')
			{
				count++;
			}

			if(count > 3)
			{
				return 0;
			}
			continue;
		}
		return 0;
	}

    sscanf(buf,"%d.%d.%d.%d",&(ip[0]),&(ip[1]),&(ip[2]),&(ip[3]));
    //printf("[%s] buf=%s, IP=%d.%d.%d.%d\n",__FUNCTION__, buf, ip[0], ip[1], ip[2], ip[3]);

    if (isInRange(ip[0], 1, 223) == 0) return 0;
    if (ip[0]== 127) return 0;
    if (isInRange(ip[1], 0, 255) == 0) return 0;
    if (isInRange(ip[2], 0, 255) == 0) return 0;
    if (isInRange(ip[3], 0, 255) == 0) return 0;

    return 1;
}

int isValidNetmask(char *buf)
{
    int i=0, j=0, ip[4] = {0};
    unsigned long mask = 0;
	int count = 0;

	for(i=0; i<strlen(buf); i++)
	{
		if((buf[i] >= '0' && buf[i] <= '9') || (buf[i] == '.'))
		{
			if(buf[i] == '.')
			{
				count++;
			}

			if(count > 3)
			{
				return 0;
			}
			continue;
		}
		return 0;
	}

	if (sscanf(buf,"%d.%d.%d.%d",&(ip[0]),&(ip[1]),&(ip[2]),&(ip[3]))!=4)
  		return 0;
    //printf("buf=%s, Mask=%d.%d.%d.%d\n", buf, ip[0], ip[1], ip[2], ip[3]);

    for (i=0; i<4; i++) {
        if (isInRange(ip[i], 0, 255) == 0) return 0;
        mask <<= 8;
        mask |= (ip[i] & 0xFF);
    }
    for (i=0; i<32; i++) {
        if (j==0) {
            if ((mask & 0x01) == 1) j=1;
        }
        else {
            if ((mask & 0x01) == 0) return 0;
        }
        mask >>= 1;
    }
    return 1;
}

int isValidMac(char *buf)
{
    int mac[6] = {0};
    char macbuf[20] = {0};

    sscanf(buf,"%x:%x:%x:%x:%x:%x",&(mac[0]),&(mac[1]),&(mac[2]),&(mac[3]),&(mac[4]),&(mac[5]));
    //printf("buf=%s, Mac=%x:%x:%x:%x:%x:%x\n", buf, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    sprintf(macbuf, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return (strcasecmp(macbuf, buf)==0)? 1: 0;
}

int get_Device_DHCPv6_Clinet_SendOption_num(char *key)
{
	int ret = 0;
	int i = 0;
	int j = 0;
	int found = 0;
	char Tag[32] = {0};
	char OptionNumberOfEntries[256] = {0};
	char value[64] = {0};
	char name[256] = {0};

	memset(OptionNumberOfEntries,0,sizeof(OptionNumberOfEntries));

	ret = do_uci_get(DDCt_SentOptionNumberOfEntries_3549, OptionNumberOfEntries);
	if(ret)
	{
		return i;
	}
	tr_log( LOG_NOTICE, "OptionNumberOfEntries: %d", atoi(OptionNumberOfEntries));

	tr_log( LOG_NOTICE, "key: %s", key);
	while(i < atoi(OptionNumberOfEntries))
	{
		memset(Tag,0,sizeof(Tag));
		memset(value,0,sizeof(value));
		j++;
		sprintf(name, "trconf.Device_DHCPv6_Clinet_template_SendOption_%d", j); 	
		do_uci_get(name,value);
		
		if(strcmp(value, "acs") == 0)
		{
			sprintf(name, "trconf.Device_DHCPv6_Clinet_template_SendOption_%d.Tag", j);		
			do_uci_get(name, Tag);
			tr_log( LOG_NOTICE, "name: %s", name);
			tr_log( LOG_NOTICE, "Tag: %s", Tag);

			if(strcmp(Tag, key) == 0)
			{
				found = 1;
				break;
			}
			i++;
		}
	}

	if(found == 1)
	{
		return j;
	}
	else
	{
		return 0;
	}
}

int get_Device_DHCPv4_Server_Option_num(char *key)
{
	int ret = 0;
	int i = 0;
	int j = 0;
	int found = 0;
	char Tag[32] = {0};
	char OptionNumberOfEntries[256] = {0};
	char value[64] = {0};
	char name[256] = {0};

	memset(OptionNumberOfEntries,0,sizeof(OptionNumberOfEntries));

	ret = do_uci_get(DDSPt_OptionNumberOfEntries, OptionNumberOfEntries);
	if(ret)
	{
		return i;
	}
	tr_log( LOG_NOTICE, "OptionNumberOfEntries: %d", atoi(OptionNumberOfEntries));

	tr_log( LOG_NOTICE, "key: %s", key);
	while(i < atoi(OptionNumberOfEntries))
	{
		memset(Tag,0,sizeof(Tag));
		memset(value,0,sizeof(value));
		j++;
		sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d", j); 	
		do_uci_get(name,value);
		
		if(strcmp(value, "acs") == 0)
		{
			sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Tag", j);		
			do_uci_get(name, Tag);
			tr_log( LOG_NOTICE, "name: %s", name);
			tr_log( LOG_NOTICE, "Tag: %s", Tag);

			if(strcmp(Tag, key) == 0)
			{
				found = 1;
				break;
			}
			i++;
		}
	}

	if(found == 1)
	{
		return j;
	}
	else
	{
		return 0;
	}
}

int get_NeighboringWiFi_info(char *BSSID, char *name, char *value)
{
	FILE *fp = NULL;
	char buff[256] = {0};
	char tmp[256] = {0};
	char ESSID[256] = {0};
	char Mode[256] = {0};
	char Frequency[256] = {0};
	char Quality[256] = {0};
	char Encryptionkey[256] = {0};
	char BitRates[256] = {0};
	char IE[256] = {0};
	char GroupCipher[256] = {0};
	char phy_mode[256] = {0};
	char *p = NULL;
	char *q = NULL;
	int found = 0;
	int wpa = 0;
	int wpa2 = 0;
	
	fp = fopen("/tmp/ath0_scan_result", "r");

	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp))
		{
			if(strstr(buff, "Cell") != NULL && strstr(buff, "- Address:") != NULL && strstr(buff, BSSID) != NULL)
			{
				if(strcmp(name, "Radio") == 0)
				{
					strcpy(value, WIFI_RADIO_5G_PATH);
					found = 1;
				}

				if(strcmp(name, "OperatingFrequencyBand") == 0)
				{
					strcpy(value, "5GHz");
					found = 1;
				}

				if(strcmp(name, "SupportedStandards") == 0)
				{
					strcpy(value, "a,n,ac");
					found = 1;
				}
				break;
			}
		}

		while((fgets(buff, sizeof(buff), fp)) && (strstr(buff, "Cell") == NULL) && strstr(buff, "- Address:") == NULL)
		{
			if(strcmp(name, "SSID") == 0 && strstr(buff, "ESSID:") != NULL)
			{
				if((p = strchr(buff, '"')) != NULL)
				{
					strcpy(value, (p+1));
					if((q = strrchr(value, '"')) != NULL)
					{
						*q = '\0';
					}
					found = 1;
					break;
				}
			}
			
			if(strcmp(name, "Mode") == 0 && strstr(buff, "Mode:") != NULL)
			{
				if(strstr(buff, "Master") != NULL)
				{
					strcpy(value, "AdHoc");
				}
				else
				{
					strcpy(value, "Infrastructure");
				}
				found = 1;
				break;
			}

			if(strcmp(name, "Channel") == 0 && strstr(buff, "Frequency:") != NULL)
			{
				if((p = strstr(buff, "Channel")) != NULL)
				{
					strcpy(value, (p+strlen("Channel ")));
					if((q = strchr(value, ')')) != NULL)
					{
						*q = '\0';
					}
					found = 1;
					break;
				}
			}

			if(strcmp(name, "SignalStrength") == 0 && strstr(buff, "Quality=") != NULL)
			{
				if(((p = strstr(buff, "Signal level=")) != NULL) && ((q = strstr(buff, " dBm")) != NULL))
				{
					strncpy(value, (p+strlen("Signal level=")), q-(p+strlen("Signal level=")));
					found = 1;
					break;
				}
			}

			if(strstr(buff, "Encryption key:") != NULL)
			{
				strcpy(Encryptionkey, buff);
			}
			
			if(strstr(buff, "IE:") != NULL && strstr(buff, "WPA2") != NULL)
			{
				wpa2 = 1;
			}

			if(strstr(buff, "IE:") != NULL && strstr(buff, "WPA ") != NULL)
			{
				wpa = 1;
			}
			
			if(strcmp(name, "EncryptionMode") == 0 && strstr(buff, "Group Cipher :") != NULL)
			{
				if((p = strstr(buff, "Group Cipher :")) != NULL)
				{
					strcpy(value, p+strlen("Group Cipher : "));
					found = 1;
					break;
				}
			}

			if(strcmp(name, "OperatingStandards") == 0 && strstr(buff, "phy_mode=") != NULL)
			{
				if(strstr(buff, "IEEE80211_MODE_11AC") != NULL)
				{
					strcpy(value, "ac");
					found = 1;
					break;
				}
				else if(strstr(buff, "IEEE80211_MODE_11NA") != NULL)
				{
					strcpy(value, "na");
					found = 1;
					break;
				}
				else if(strstr(buff, "IEEE80211_MODE_11N") != NULL)
				{
					strcpy(value, "n");
					found = 1;
					break;
				}
				else if(strstr(buff, "IEEE80211_MODE_11A") != NULL)
				{
					strcpy(value, "a");
					found = 1;
					break;
				}
			}

			if(strcmp(name, "OperatingChannelBandwidth") == 0 && strstr(buff, "phy_mode=") != NULL)
			{
				if(strstr(buff, "HT20") != NULL)
				{
					strcpy(value, "20MHz");
				}
				else if(strstr(buff, "HT40") != NULL)
				{
					strcpy(value, "40MHz");
				}
				else
				{
					strcpy(value, "20MHz");
				}
				found = 1;
				break;
			}
		
			if(strcmp(name, "BeaconPeriod") == 0 && strstr(buff, "bcn_int=") != NULL)
			{
				p = strchr(buff, '=');
				if(p != NULL)
				{
					strcpy(value, p+1);
				}
			}

			if(strcmp(name, "Noise") == 0 && strstr(buff, "Noise level=") != NULL)
			{
				if(((p = strstr(buff, "Noise level=")) != NULL) && ((q = strstr(p, " dBm")) != NULL))
				{
					strncpy(value, (p+strlen("Noise level=")), q-(p+strlen("Noise level=")));
					found = 1;
					break;
				}
			}

			if((strcmp(name, "BasicDataTransferRates") == 0 || strcmp(name, "SupportedDataTransferRates") == 0) && strstr(buff, "Bit Rates:") != NULL)
			{
				strcpy(value, buff);
				while(fgets(tmp, sizeof(tmp), fp))
				{
					if(strstr(tmp, "Mb/s") != NULL)
					{
						strcat(value, tmp);
					}
					else
					{
						break;
					}
				}
				found = 1;
				break;
			}
		}
		fclose(fp);

		if(strcmp(name, "SecurityModeEnabled") == 0)
		{
			if(strstr(Encryptionkey, "off") != NULL)
			{
				strcpy(value, "None");				
			}
			else
			{
				if(wpa == 1 && wpa2 == 1)
				{
					strcpy(value, "WPA-WPA2");				
				}
				else if(wpa == 1 && wpa2 == 0)
				{
					strcpy(value, "WPA");				
				}
				else if(wpa == 0 && wpa2 == 1)
				{
					strcpy(value, "WPA2");				
				}
				else
				{
					strcpy(value, "WEP");				
				}
			}
		}
		
		if(found == 1)
		{
			return 0;
		}
	}

	fp = fopen("/tmp/ath1_scan_result", "r");
	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp))
		{
			if(strstr(buff, "Cell") != NULL && strstr(buff, "- Address:") != NULL && strstr(buff, BSSID) != NULL)
			{
				if(strcmp(name, "Radio") == 0)
				{
					strcpy(value, WIFI_RADIO_24G_PATH);
					found = 1;
				}

				if(strcmp(name, "OperatingFrequencyBand") == 0)
				{
					strcpy(value, "2.4GHz");
					found = 1;
				}

				if(strcmp(name, "SupportedStandards") == 0)
				{
					strcpy(value, "b,g,n");
					found = 1;
				}
				break;
			}
		}

		while((fgets(buff, sizeof(buff), fp)) && (strstr(buff, "Cell") == NULL) && strstr(buff, "- Address:") == NULL)
		{
			if(strcmp(name, "SSID") == 0 && strstr(buff, "ESSID:") != NULL)
			{
				if((p = strchr(buff, '"')) != NULL && (q = strrchr(buff, '"')) != NULL)
				{
					strncpy(value, (p+1), q-(p+1));
					found = 1;
					break;
				}
			}
			
			if(strcmp(name, "Mode") == 0 && strstr(buff, "Mode:") != NULL)
			{
				if(strstr(buff, "Master") != NULL)
				{
					strcpy(value, "AdHoc");
				}
				else
				{
					strcpy(value, "Infrastructure");
				}
				found = 1;
				break;
			}

			if(strcmp(name, "Channel") == 0 && strstr(buff, "Frequency:") != NULL)
			{
				if(((p = strstr(buff, "Channel")) != NULL) && ((q = strrchr(buff, ')')) != NULL))
				{
					strncpy(value, (p+strlen("Channel ")), q-(p+strlen("Channel ")));
					found = 1;
					break;
				}
			}

			if(strcmp(name, "SignalStrength") == 0 && strstr(buff, "Quality=") != NULL)
			{
				if(((p = strstr(buff, "Signal level=")) != NULL) && ((q = strstr(buff, " dBm")) != NULL))
				{
					strncpy(value, (p+strlen("Signal level=")), q-(p+strlen("Signal level=")));
					found = 1;
					break;
				}
			}

			if(strstr(buff, "Encryption key:") != NULL)
			{
				strcpy(Encryptionkey, buff);
			}
			
			if(strstr(buff, "IE:") != NULL && strstr(buff, "WPA2") != NULL)
			{
				wpa2 = 1;
			}

			if(strstr(buff, "IE:") != NULL && strstr(buff, "WPA ") != NULL)
			{
				wpa = 1;
			}
			
			if(strcmp(name, "EncryptionMode") == 0 && strstr(buff, "Group Cipher :") != NULL)
			{
				if((p = strstr(buff, "Group Cipher :")) != NULL)
				{
					strcpy(value, p+strlen("Group Cipher : "));
					found = 1;
					break;
				}
			}

			if(strcmp(name, "OperatingStandards") == 0 && strstr(buff, "phy_mode=") != NULL)
			{
				printf("buff: \n", buff);
				if(strstr(buff, "IEEE80211_MODE_11G") != NULL)
				{
					strcpy(value, "g");
					found = 1;
					break;
				}
				else if(strstr(buff, "IEEE80211_MODE_11B") != NULL)
				{
					strcpy(value, "b");
					found = 1;
					break;
				}
				else if(strstr(buff, "IEEE80211_MODE_11NG") != NULL)
				{
					strcpy(value, "n,g");
					found = 1;
					break;
				}
				else if(strstr(buff, "IEEE80211_MODE_11N") != NULL)
				{
					strcpy(value, "n");
					found = 1;
					break;
				}
			}

			if(strcmp(name, "OperatingChannelBandwidth") == 0 && strstr(buff, "phy_mode=") != NULL)
			{
				if(strstr(buff, "HT20") != NULL)
				{
					strcpy(value, "20MHz");
				}
				else if(strstr(buff, "HT40") != NULL)
				{
					strcpy(value, "40MHz");
				}
				else if(strstr(buff, "HT80") != NULL)
				{
					strcpy(value, "40MHz");
				}
				else
				{
					strcpy(value, "20MHz");
				}
				found = 1;
				break;
			}
		
			if(strcmp(name, "BeaconPeriod") == 0 && strstr(buff, "bcn_int=") != NULL)
			{
				p = strchr(buff, '=');
				if(p != NULL)
				{
					strcpy(value, p+1);
				}
			}

			if(strcmp(name, "Noise") == 0 && strstr(buff, "Noise level=") != NULL)
			{
				if(((p = strstr(buff, "Noise level=")) != NULL) && ((q = strstr(p, " dBm")) != NULL))
				{
					strncpy(value, (p+strlen("Noise level=")), q-(p+strlen("Noise level=")));
					found = 1;
					break;
				}
			}

			if((strcmp(name, "BasicDataTransferRates") == 0 || strcmp(name, "SupportedDataTransferRates") == 0) && strstr(buff, "Bit Rates:") != NULL)
			{
				strcpy(value, buff);
				while(fgets(tmp, sizeof(tmp), fp))
				{
					if(strstr(tmp, "Mb/s") != NULL)
					{
						strcat(value, tmp);
					}
					else
					{
						break;
					}
				}
				found = 1;
				break;
			}
		}
		fclose(fp);

		if(strcmp(name, "SecurityModeEnabled") == 0)
		{
			if(strstr(Encryptionkey, "off") != NULL)
			{
				strcpy(value, "None");				
			}
			else
			{
				if(wpa == 1 && wpa2 == 1)
				{
					strcpy(value, "WPA-WPA2");				
				}
				else if(wpa == 1 && wpa2 == 0)
				{
					strcpy(value, "WPA");				
				}
				else if(wpa == 0 && wpa2 == 1)
				{
					strcpy(value, "WPA2");				
				}
				else
				{
					strcpy(value, "WEP");				
				}
			}
		}
		
		if(found == 1)
		{
			return 0;
		}
	}
}

int set_dhcpv6_clinet_sentoption()
{
	int ret = 0;
	int i = 0;
	int j = 0;
	char Tag[32] = {0};
	char Enable[32] = {0};
	char OptionNumberOfEntries[256] = {0};
	char Value[256] = {0};
	char name[256] = {0};
	char node[32] = {0};

	do_uci_delete("ipv6.@native[0].clientid", NULL);
	do_uci_delete("ipv6.@native[0].requestedoptions", NULL);
	do_uci_delete("ipv6.@native[0].userclass", NULL);
	do_uci_delete("ipv6.@native[0].vendorclass", NULL);
	do_uci_delete("ipv6.@native[0].reqprefix", NULL);

	memset(OptionNumberOfEntries,0,sizeof(OptionNumberOfEntries));
	ret = do_uci_get(DDCt_SentOptionNumberOfEntries_3549, OptionNumberOfEntries);

	while(i < atoi(OptionNumberOfEntries))
	{
		memset(Tag,0,sizeof(Tag));
		memset(Enable,0,sizeof(Enable));
		memset(Value,0,sizeof(Value));
		memset(node,0,sizeof(node));
		j++;
		sprintf(name, "trconf.Device_DHCPv6_Clinet_template_SendOption_%d", j);	
		do_uci_get(name,node);
		
		if(strcmp(node, "acs") == 0)
		{
			i++;
			sprintf(name, "trconf.Device_DHCPv6_Clinet_template_SendOption_%d.Tag", j);		
			do_uci_get(name, Tag);
			sprintf(name, "trconf.Device_DHCPv6_Clinet_template_SendOption_%d.Enable", j);		
			do_uci_get(name, Enable);
			sprintf(name, "trconf.Device_DHCPv6_Clinet_template_SendOption_%d.Value", j);		
			do_uci_get(name, Value);

			if(atoi(Enable) == 1)
			{
				if(atoi(Tag) == 1)
				{
					do_uci_set("ipv6.@native[0].clientid", Value);
					continue;
				}
				if(atoi(Tag) == 6)
				{
					do_uci_set("ipv6.@native[0].requestedoptions", Value);
					continue;
				}
				if(atoi(Tag) == 15)
				{
					do_uci_set("ipv6.@native[0].userclass", Value);
					continue;
				}
				if(atoi(Tag) == 16)
				{
					do_uci_set("ipv6.@native[0].vendorclass", Value);
					continue;
				}
				if(atoi(Tag) == 26)
				{
					do_uci_set("ipv6.@native[0].reqprefix", Value);
					continue;
				}
			}
		}
	}
    do_uci_commit("ipv6");
}

int set_dhcp_option()
{
	int ret = 0;
	int i = 0;
	int j = 0;
	char Tag[32] = {0};
	char Enable[32] = {0};
	char OptionNumberOfEntries[256] = {0};
	char Value[256] = {0};
	char name[256] = {0};
	char node[32] = {0};
	char DnsServer[32] = {0};
	char DefGateway[32] = {0};
	char WinsServer[32] = {0};
	char linebuffer[512] = { 0 };
	char dhcp_option[128] = {0};
	char *p = NULL;
	char *buf = NULL;

	memset(DnsServer, 0x00, sizeof(DnsServer));
	memset(DefGateway, 0x00, sizeof(DefGateway));
	memset(WinsServer, 0x00, sizeof(WinsServer));
	memset(linebuffer, 0x00, sizeof(linebuffer));
	/*do_uci_get("dhcp.lan.dhcp_option", linebuffer);
	if (linebuffer[0] != 0) 
	{
		buf = linebuffer;
		while ((p = strtok(buf, " ")) != NULL) 
		{
			tr_log( LOG_NOTICE, "p: %s", p);
			if ((p[0] == '3') && (p[1] == ',')) 
			{
				strcpy(DefGateway, p + 2);
			}

			if ((p[0] == '6') && (p[1] == ',')) {
				strcpy(DnsServer, p + 2);
			}
			if ((p[0] == '4') && (p[1] == '4') && (p[2] == ',')) {
				strcpy(WinsServer, p + 3);
			}
			buf = NULL;
		}
	}*/
	do_uci_delete("dhcp.lan.dhcp_option", NULL);

	memset(OptionNumberOfEntries,0,sizeof(OptionNumberOfEntries));
	ret = do_uci_get(DDSPt_OptionNumberOfEntries, OptionNumberOfEntries);

	while(i < atoi(OptionNumberOfEntries))
	{
		memset(Tag,0,sizeof(Tag));
		memset(Enable,0,sizeof(Enable));
		memset(Value,0,sizeof(Value));
		memset(node,0,sizeof(node));
		memset(dhcp_option,0,sizeof(dhcp_option));
		j++;
		sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d", j);	
		do_uci_get(name,node);
		
		if(strcmp(node, "acs") == 0)
		{
			i++;
			sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Tag", j);		
			do_uci_get(name, Tag);
			sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Enable", j);		
			do_uci_get(name, Enable);
			sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Value", j);		
			do_uci_get(name, Value);

			if(atoi(Enable) == 1)
			{
				if(atoi(Tag) == 3)
				{
					strcpy(DefGateway, Value);
					continue;
				}
				if(atoi(Tag) == 6)
				{
					strcpy(DnsServer, Value);
					continue;
				}
				if(atoi(Tag) == 44)
				{
					strcpy(WinsServer, Value);
					continue;
				}
				sprintf(dhcp_option, "%s,%s", Tag, Value);
				tr_log( LOG_NOTICE, "dhcp_option: %s", dhcp_option);
				do_uci_add_list("dhcp.lan.dhcp_option", dhcp_option);
			}
		}
	}
	if (DefGateway[0] != 0) 
	{
		memset(dhcp_option,0,sizeof(dhcp_option));
		sprintf(dhcp_option, "3,%s", DefGateway);
		do_uci_add_list("dhcp.lan.dhcp_option", dhcp_option);
	}
	if (DnsServer[0] != 0) 
	{
		memset(dhcp_option,0,sizeof(dhcp_option));
		sprintf(dhcp_option, "6,%s", DnsServer);
		do_uci_add_list("dhcp.lan.dhcp_option", dhcp_option);
	}
	if (WinsServer[0] != 0) 
	{
		memset(dhcp_option,0,sizeof(dhcp_option));
		sprintf(dhcp_option, "44,%s", WinsServer);
		do_uci_add_list("dhcp.lan.dhcp_option", dhcp_option);
	}
    do_uci_commit("dhcp");
}

void getManagementServerManageableDeviceInfo(char *filename, char *key, char *value)
{
	FILE *fd = NULL;
	char line[128] = {0};
	char *p = NULL;

	if ((fd=fopen(filename,"r")) != NULL){
		while(fgets(line,sizeof(line)-1,fd)){
			if (((strstr(line, "oui=") != NULL) && (strcmp(key, "ManufacturerOUI") == 0))
				|| ((strstr(line, "serial=") != NULL) && (strcmp(key, "SerialNumber") == 0))
				|| ((strstr(line, "class=") != NULL) && (strcmp(key, "ProductClass") == 0))){
				if ((p = strstr(line, "=")) != NULL){
					strcpy(value, p+1);
				}	
			}
		}
		fclose(fd);
	}
}

int updatentpserverlist(int num, char *value)
{
	int ret = 0;
	char ntpserverlist[4096] = {0};
	char ntpserver1[256] = {0};
	char ntpserver2[256] = {0};
	char ntpserver3[256] = {0};
	char ntpserver4[256] = {0};
	char ntpserver5[256] = {0};

	ret = do_uci_get("system.ntp.server", ntpserverlist);
	sscanf(ntpserverlist, "%s %s %s %s %s", ntpserver1, ntpserver2, ntpserver3, ntpserver4, ntpserver5);

	switch(num)
	{
		case 1:
			strcpy(ntpserver1, value);
			break;
		case 2:
			strcpy(ntpserver2, value);
			break;
		case 3:
			strcpy(ntpserver3, value);
			break;
		case 4:
			strcpy(ntpserver4, value);
			break;
		case 5:
			strcpy(ntpserver5, value);
			break;
	}
	sprintf(ntpserverlist, "%s %s %s %s %s", ntpserver1, ntpserver2, ntpserver3, ntpserver4, ntpserver5);\
	do_uci_set("system.ntp.server", ntpserverlist);
	ret = do_uci_set("system.ntp.server", ntpserverlist);
	if(ret)
	{
		return (-1);
	}
	else
	{
		ret = do_uci_commit("system");
		if(ret)
		{
			return (-1);
		}
		system("/etc/init.d/sysntpd restart");
		system("date -k"); 
	}
	return ret;
}

void sentEventforDiagnostic()
{
	add_single_event( S_EVENT_DIAGNOSTICS_COMPLETE );
	complete_add_event( 0 );
}

int get_DynamicDNS_Server(char *value){

    int ret = -1;
    char tmparray[256] = {0};
    int i = 0;

    ret = do_uci_get(DDC1_Server, tmparray);

    for (i = 0; i < DDNSSERVERNUM; i++) {
    	if(!strcmp(ddns_list[i], tmparray)) {
    		break;
    	}
    }
    switch(i) {
        case 0:
            sprintf(value,ddns_server[0]);
            break;
        case 1:
	     sprintf(value,ddns_server[1]);
            break;
        case 2:
            sprintf(value,ddns_server[2]);
            break;
        case 3:
            sprintf(value,ddns_server[3]);
            break;
        default:
            break;
    }
    
    return ret;
}

int set_DynamicDNS_Server(char *value){

    int ret = -1;
    char wildcard[2] = {0};
    int i = 0;
    //ret = do_uci_get(NET_DDNS_WILDCARD,wildcard);
    //int num = -1;
    char linebuffer[128] = {0};
	
    for(i = 0; i < DDNSSERVERNUM; i++){
        if(strcmp(value,ddns_server[i])==0){
            /*By now ,we just support two server.*/
            break;			
        }
    }
    
    if((i >= 0) && (i <= 3)) {
        ret = do_uci_set(DDC1_Server, ddns_list[i]);
    }else{
        ret = do_uci_set(DDC1_Server, ddns_list[0]); 
    }
   
    return ret;
}

#define ALLOW_UDP_ECHO_NAME      "Allow-UDPECHO"

void set_udpecho()
{
	char tmpbuf[256]={0};
	char cmdbuf[256]={0};
	char enabled[128] = {0};
	char dest_port[128] = {0};
	int ret = 0,find = 0;

	if(parameternum == 0)
	{
		do_uci_get(DIDU_Enable, enabled);
		do_uci_get(DIDU_UDPPort, dest_port);

		find = do_uci_get("firewall.Allow_UDPECHO",tmpbuf);
		if(find != 0)
		{
			ret = do_uci_add("firewall","rule",tmpbuf);
			if(ret != 0)
			{
				return ret;
			}
			sprintf(cmdbuf, "firewall.%s", tmpbuf);
			ret = do_uci_rename(cmdbuf, "Allow_UDPECHO");
			if(ret != 0)
			{
				return ret;
			}
		}

		do_uci_set("firewall.Allow_UDPECHO.src", "wan");
		do_uci_set("firewall.Allow_UDPECHO.proto", "udp");
		do_uci_set("firewall.Allow_UDPECHO.family", "ipv4");
		do_uci_set("firewall.Allow_UDPECHO.target", "ACCEPT");
		do_uci_set("firewall.Allow_UDPECHO.enabled", enabled);
		do_uci_set("firewall.Allow_UDPECHO.dest_port", dest_port);
		do_uci_commit("firewall");

		system("/etc/init.d/firewall restart");
	}
}

void getDHCPServerLeaseTime(char *value)
{
	int ret = 0;

	ret = do_uci_get("dhcp.lan.leasetime", value);
	if(ret)
	{
		strcpy(value, "604800"); //default value
	}
	else
	{
		char *ptr = NULL;
		if ((ptr = strstr(value, "s")) != NULL){
			*ptr = '\0';
		}
		else if ((ptr = strstr(value, "h")) != NULL) {
			*ptr = '\0';
			sprintf(value, "%d", atoi(value)*60*60); //changed hours to seconds
		}
	}
}

int parse_captive_portal_url(char *url, char *ssl, char *hostname, char *path)
{
	char url_cp[1024] = {0};
	char *p = NULL;
	char *hs = NULL, *he = NULL;
	char *ps = NULL, *pe = NULL;
	int hlen = 0, plen = 0;

	if(!strcpy(url_cp, url))
		return -1;

	if (strstr(url, "https://"))
		strcpy(ssl, "yes");
	else
		strcpy(ssl, "");

	p = strstr(url_cp, "://");
	if (!p)
		return -1;

	hs = p + strlen("://");
	if (!hs)
		return -1;
	
	he = strstr(hs, "/");
	if (!he)
	{
		strcpy(hostname, hs);
		strcpy(path,"/");
	}
	else
	{
		hlen = he - hs;
		strncpy(hostname, hs, hlen);
		hostname[hlen] = '\0';

		ps = he;
		pe = strrchr(ps, '/');	
		if (!pe)
		{
			strcpy(path,"/");
		}
		else
		{
			plen = pe - ps + 1;
			strncpy(path, ps, plen);
			path[plen] = '\0';
		}	
	}
	return 0;
}

/* all installed apps */
int getDeploymentUnitNumberOfEntries()
{
	FILE *fp = NULL;
    char line[512] = {0};
    int i = 0;
	
	if((fp=popen("opkg list-installed","r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp)){
			i ++;
    	}
    	pclose(fp);
	}

	return i;
}

/* all libs and script files */
int getExecutionUnitNumberOfEntries()
{
	FILE *fp = NULL;
    char line[512] = {0};
    int i = 0;
	
	if((fp=popen("ls -l /lib/ | grep .so","r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp)){
			i ++;
    	}
    	pclose(fp);
	}

	if((fp=popen("find / -name *.sh","r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp)){
			i ++;
    	}
    	pclose(fp);
	}

	return i;
}

void getDiskSpace(char *value, char *key)
{
	FILE *fp = NULL;
    char line[512] = {0};
    int i = 0;
	
	if((fp=popen("df | grep overlayfs","r")) != NULL){
		fgets(line,sizeof(line)-1,fp);
    	pclose(fp);
		if (strcmp(key, "AllocatedDiskSpace") == 0)
			sscanf(line, "%*s %s %*s", value);
		else if (strcmp(key, "AvailableDiskSpace") == 0)
			sscanf(line, "%*s %*s %*s %s %*s", value);
		else
			strcpy(value, "-1");
	}
	else
		strcpy(value, "-1");
}

void getMemoryInfo(char *value, char *key)
{
	FILE *fp = NULL;
    char line[512] = {0};
	char cmd[64] = {0};
    int i = 0;

	sprintf(cmd, "cat /proc/meminfo | grep %s", key);
	if((fp=popen(cmd,"r")) != NULL){
		fgets(line,sizeof(line)-1,fp);
    	pclose(fp);
		sscanf(line, "%*s %s %*s", value);
	}
	else
		strcpy(value, "-1");
}

void getEthInterfaceName(char *in, char *inf)
{
	int ret = 0;
	char str[64] = {0};

	sprintf(str, "network.%s.ifname", in);
	ret = do_uci_get(str, inf);
	if(ret) //no this uci node with defalut settings
	{
		if (strcmp(in, "wan") == 0)
			strcpy(inf, "eth0");
		else
			strcpy(inf, "eth1");
	}
}

void startDownload()
{
	char url[256] = {0};
	char command[256] = {0};
	char value[32] = {0};
	int ret = 0;

	ret = do_uci_get(DIDD_DiagnosticsState, value);

	if(strcasecmp(value, "requested") == 0 && parameternum == 0)
	{
		start_download = 1;
	}
	else
	{
		return (-1);
	}
}

void TrDownload()
{
	pthread_detach( pthread_self() );
	char url[256] = {0};
	char command[256] = {0};
	char value[32] = {0};
	int ret = 0;

	ret = do_uci_get(DIDD_DownloadURL, url);
	if(ret)
	{
		return -1;
	}
	system("rm /tmp/wgetresult");
	sprintf(command, "wget %s -O /dev/null", url);
	system(command);

	ret = do_uci_set(DIDD_DiagnosticsState, "Complete");
	if(ret)
	{
		return;
	}
	else
	{
		sentEventforDiagnostic();
		ret = do_uci_commit(MS);
		if(ret)
		{
			return;
		}
	}
	return;
}

void startUpload()
{
	char value[32] = {0};
	int ret = 0;

	ret = do_uci_get(DIDU_DiagnosticsState, value);
	
	tr_log(LOG_DEBUG,"value [%s]",value);
	tr_log(LOG_DEBUG,"parameternum [%d]",parameternum);
	if(strcasecmp(value, "requested") == 0 && parameternum == 0)
	{
		start_upload = 1;	
	}
	else
	{
		return (-1);
	}
}

void TrUpload()
{
	pthread_detach( pthread_self() );
	char url[256] = {0};
	char filelength[256] = {0};
	char command[256] = {0};
	char value[32] = {0};
	char mac[32] = {0};
	char mac1[32] = {0};
	char tmpurl[257] = {0};
	char tmpname[257] = {0};
	char buff[128] = {0};
	char buff2[128] = {0};
	char interface[128] = {0};
	char dscp[128] = {0};
	char EthernetPriority[128] = {0};
	char waninf[32] = {0};
	char *ptr = NULL;
	int ret = 0;
	int i = 0;
	
	getInfaceWanMac(mac); //Using WAN MAC address
	tr_log(LOG_DEBUG,"WAN Iinterface MAC [%s]",mac);
	if (mac[0] != '\0'){
		int i = 0, j = 0;
		for (i = 0; i < 17; i ++){
			if (mac[i] != ':'){
				mac1[j] = toupper(mac[i]);
				j ++;
			}
		}
		mac1[j] = '\0';
	}
	ret = do_uci_get(DIDU_UploadURL, url);
	if(ret)
	{
		return -1;
	}
	ret = do_uci_get(DIDU_TestFileLength, filelength);
	if(ret)
	{
		return -1;
	}
	else
	{
		if(url[strlen(url)-1] != '/')
		{
			ptr = strrchr(url, '/');
			if(ptr != NULL)
			{
				if(*(ptr-1) == '/')
				{
					sprintf(tmpurl, "%s/%s_upload.txt", url, mac1);
					sprintf(tmpname, "%s_upload.txt", mac1);
				}
				else
				{
					*ptr = '\0';
					sprintf(tmpurl, "%s/%s_%s", url, mac1, ptr+1);
					sprintf(tmpname, "%s_%s", mac1, ptr+1);
				}
			}
		}
		else
		{
			sprintf(tmpurl, "%s%s_upload.txt", url, mac1);
			sprintf(tmpname, "%s_upload.txt", mac1);
		}
		
		/*sprintf(command, "dd if=/dev/zero of=/tmp/%s bs=%s count=1", tmpname, filelength);
		tr_log(LOG_DEBUG,"command [%s]",command);
		system(command);*/
	}

	memset(buff, 0, sizeof(buff));
	memset(interface, 0, sizeof(interface));
	ret = do_uci_get(DIDU_Interface, buff); 	
	if(buff[0] != '\0')
	{
		for (i = 0; i <= IP_LAN_INSTANCE_NUM; i ++){
			sprintf(buff2, "Device.IP.Interface.%d", lan_map[i].num);
			if (strcmp(buff, buff2) == 0){
				sprintf(interface, "-i %s", lan_map[i].laninf);
				break;
			}
		}
		if(strcmp(buff, IP_WAN_INTERFACE_PATH) == 0)
		{
			getWanHigherLayerInterface(waninf);
			sprintf(interface, "-i %s", waninf);
		}
	}

	if(buff[0] == '\0')
	{
		getWanHigherLayerInterface(waninf);
		sprintf(interface, "-i %s", waninf);
	}

	memset(buff, 0, sizeof(buff));
	ret = do_uci_get(DIDU_DSCP, buff); 	
	if(buff[0] != '\0')
	{
		sprintf(dscp, "-d %s", buff);
	}
	tr_log(LOG_DEBUG,"dscp [%s]",dscp);

	memset(buff, 0, sizeof(buff));
	ret = do_uci_get(DIDU_EthernetPriority, buff); 	
	if(buff[0] != '\0')
	{
		sprintf(EthernetPriority, "-p %s", buff);
	}
	tr_log(LOG_DEBUG,"EthernetPriority [%s]",EthernetPriority);
	
	system("rm /tmp/TR143UP_DIAG.txt");
	
	tr_log(LOG_DEBUG,"tmpname [%s]",tmpname);
	tr_log(LOG_DEBUG,"tmpurl [%s]",tmpurl);
	
	sprintf(command, " /oneagent/uploaddiag %s %s %s -u %s -l %s", dscp, EthernetPriority, interface, tmpurl, filelength);
	tr_log(LOG_DEBUG,"command [%s]",command);
	system(command);


	ret = do_uci_set(DIDU_DiagnosticsState, "Complete");
	if(ret)
	{
		return;
	}
	else
	{
		sentEventforDiagnostic();
		ret = do_uci_commit(MS);
		if(ret)
		{
			return;
		}
	}

	return;
}

void startUDPEcho()
{
	char Host[256] = {0};
	char Port[256] = {0};
	char NumberOfRepetitions[256] = {0};
	char Timeout[256] = {0};
	char DataBlockSize[256] = {0};
	char InterTransmissionTime[256] = {0};
	char value[32] = {0};
	int ret = 0;

	ret = do_uci_get(DIDU_DiagnosticsState_2488, value);
	tr_log(LOG_DEBUG,"startUDPEcho value [%s]",value);
	tr_log(LOG_DEBUG,"startUDPEcho parameternum [%d]",parameternum);
	
	if(strcasecmp(value, "requested") == 0 && parameternum == 0)
	{
		ret = do_uci_get(DIDU_Host, Host);
		if(ret)
		{
			return -1;
		}
		ret = do_uci_get(DIDU_Port, Port);
		if(ret)
		{
			return -1;
		}
		ret = do_uci_get(DIDU_NumberOfRepetitions, NumberOfRepetitions);
		if(ret)
		{
			return -1;
		}
		ret = do_uci_get(DIDU_Timeout, Timeout);
		if(ret)
		{
			return -1;
		}
		ret = do_uci_get(DIDU_DataBlockSize, DataBlockSize);
		if(ret)
		{
			return -1;
		}
		ret = do_uci_get(DIDU_InterTransmissionTime, InterTransmissionTime);
		if(InterTransmissionTime[0] = '\0')
		{
			strcpy(InterTransmissionTime, "100");
		}
		if(ret)
		{
			return -1;
		}
		udpecho(Host, Port, atoi(NumberOfRepetitions), atoi(Timeout), atoi(DataBlockSize), atoi(InterTransmissionTime));
	}
	else
	{
		return (-1);
	}

	ret = do_uci_set(DIDU_DiagnosticsState_2488, "Complete");
	if(ret)
	{
		return (-1);
	}
	else
	{
		sentEventforDiagnostic();
		ret = do_uci_commit(MS);
		if(ret)
		{
			return (-1);
		}
	}
}

void startIPPing()
{
	char command[128] = {0};
	char command1[128] = {0};
	char command2[128] = {0};
	char buff[128] = {0};
	char buff2[128] = {0};
	char interface[128] = {0};
	char host[128] = {0};
	char number[128] = {0};
	char timeout[128] = {0};
	char size[128] = {0};
	char protocol[128] = {0};
	char dscp[128] = {0};
	char output[128] = {0};
	char dest[128] = {0};
	int dscpflag = 0;
	char waninf[32] = {0};
	char value[32] = {0};
	int ret = 0;
	int i = 0;

	ret = do_uci_get(DIDI_DiagnosticsState, value);
	
	if(strcasecmp(value, "requested") == 0 && parameternum == 0)
	{
		ret = do_uci_get(DIDI_Host, buff);
		if(buff[0] == '\0')
		{
			ret = do_uci_set(DIDI_DiagnosticsState, "Error_CannotResolveHostName");
			if(ret)
			{
				return (-1);
			}
			else
			{
				ret = do_uci_commit(MS);
				if(ret)
				{
					return (-1);
				}
			}
			return ret;
		}
		else
		{
			strcpy(host, buff);
			sprintf(dest, "-d %s", buff);
		}
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDI_Interface, buff);		
		if(buff[0] != '\0')
		{
			for (i = 0; i <= IP_LAN_INSTANCE_NUM; i ++){
				sprintf(buff2, "Device.IP.Interface.%d", lan_map[i].num);
				if (strcmp(buff, buff2) == 0){
					sprintf(interface, "-I %s", lan_map[i].laninf);
					sprintf(output, "-o %s", lan_map[i].laninf);
					break;
				}
			}
			if(strcmp(buff, IP_WAN_INTERFACE_PATH) == 0)
			{
				getWanHigherLayerInterface(waninf);
				sprintf(interface, "-I %s", waninf);
				sprintf(output, "-o %s", waninf);
			}
		}
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDI_NumberOfRepetitions, buff);
		if(buff[0] != '\0')
		{
			sprintf(number, "-c %s", buff);
		}
		else
		{
			strcpy(number, "-c 5");
		}
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDI_Timeout, buff);
		if(buff[0] != '\0')
		{
			if(atoi(buff) < 1000)
			{
				strcpy(timeout, "-W 1");
			}
			else
			{
				sprintf(timeout, "-W %d", atoi(buff)/1000);
			}
		}
		else
		{
			strcpy(timeout, "-W 5");
		}
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDI_DataBlockSize, buff);
		if(buff[0] != '\0')
		{
			sprintf(size, "-s %s", buff);
		}

		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDI_DSCP, buff);
		if(buff[0] != '\0')
		{
			sprintf(dscp, "-j DSCP --set-dscp %s", buff);
			sprintf(command1, "iptables -t mangle -A OUTPUT -p icmp %s %s %s", dest, output, dscp);
			tr_log(LOG_DEBUG,"command1[%s]",command1);
			sprintf(command2, "iptables -t mangle -D OUTPUT -p icmp %s %s %s", dest, output, dscp);
			tr_log(LOG_DEBUG,"command2[%s]",command2);
			dscpflag = 1;
		}
		
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDI_ProtocolVersion, buff);
		if(strcasecmp(buff, "IPv6") == 0)
		{
			strcpy(protocol, "-6");
		}
		else
		{
			strcpy(protocol, "-4");
		}
		
		system("rm /tmp/pingresult");
		sprintf(command, "ping %s %s %s %s %s %s >> /tmp/pingresult", protocol, number, size, interface, timeout, host);		
		tr_log(LOG_DEBUG,"command[%s]",command);
		if(dscpflag == 1)
			system(command1);
		system(command);
		if(dscpflag == 1)
			system(command2);
	}
	else
	{
		return (-1);
	}
	
	ret = do_uci_set(DIDI_DiagnosticsState, "Complete");
	if(ret)
	{
		return (-1);
	}
	else
	{
		sentEventforDiagnostic();
		ret = do_uci_commit(MS);
		if(ret)
		{
			return (-1);
		}
	}
}

void startTraceRoute()
{
	char buff[128] = {0};
	char buff2[128] = {0};
	char interface[128] = {0};
	char host[128] = {0};
	char numberoftries[128] = {0};
	char timeout[128] = {0};
	char size[128] = {0};
	char dscp[128] = {0};
	char maxhop[128] = {0};
	char command[128] = {0};
	char waninf[32] = {0};
	char value[32] = {0};
	int ret = 0;
	int i = 0;

	ret = do_uci_get(DIDT_DiagnosticsState, value);
	
	if(strcasecmp(value, "requested") == 0 && parameternum == 0)
	{
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDT_Interface, buff);
		if(buff[0] != '\0')
		{
			for (i = 0; i <= IP_LAN_INSTANCE_NUM; i ++){
				sprintf(buff2, "Device.IP.Interface.%d", lan_map[i].num);
				if (strcmp(buff, buff2) == 0){
					sprintf(interface, "-i %s", lan_map[i].laninf);
					break;
				}
			}
			if(strcmp(buff, IP_WAN_INTERFACE_PATH) == 0)
			{
				getWanHigherLayerInterface(waninf);
				sprintf(interface, "-i %s", waninf);
			}
		}
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDT_Host, buff);
		if(buff[0] == '\0')
		{
			ret = do_uci_set(DIDT_DiagnosticsState, "Error_CannotResolveHostName");
			if(ret)
			{
				return (-1);
			}
			else
			{
				ret = do_uci_commit(MS);
				if(ret)
				{
					return (-1);
				}
			}
			return ret;
		}
		else
		{
			strcpy(host, buff);
		}
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDT_NumberOfTries, buff);
		if(buff[0] != '\0')
		{
			sprintf(numberoftries, "-q %s", buff);
		}
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDT_Timeout, buff);
		if(buff[0] != '\0')
		{
			if(atoi(buff) < 1000)
			{
				strcpy(timeout, "-w 1");
			}
			else
			{
				sprintf(timeout, "-w %d", atoi(buff)/1000);
			}
		}
		else
		{
			strcpy(timeout, "-w 5");
		}
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDT_DataBlockSize, buff);
		if(buff[0] != '\0')
		{
			strcpy(size, buff);
		}
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDT_DSCP, buff);
		if(buff[0] != '\0')
		{
			sprintf(dscp, "-t %d", atoi(buff) << 2);
		}
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDT_MaxHopCount, buff);
		if(buff[0] != '\0')
		{
			sprintf(maxhop, "-m %s", buff);
		}
		system("rm /tmp/tracerouteresult"); 	
		sprintf(command, "traceroute -I %s %s %s %s %s %s %s >> /tmp/tracerouteresult", interface, numberoftries, timeout, dscp, maxhop, host, size);
		tr_log(LOG_DEBUG,"command[%s]",command);
		system(command);
	}
	else
	{
		return (-1);
	}
	
	ret = do_uci_set(DIDT_DiagnosticsState, "Complete");
	if(ret)
	{
		return (-1);
	}
	else
	{
		sentEventforDiagnostic();
		ret = do_uci_commit(MS);
		if(ret)
		{
			return (-1);
		}
	}
}

void startServerSelection()
{
	char command[128] = {0};
	char command1[128] = {0};
	char command2[128] = {0};
	char buff[256] = {0};
	char buff2[256] = {0};
	char interface[128] = {0};
	char host[256] = {0};
	char host1[64] = {0};
	char number[128] = {0};
	char timeout[128] = {0};
	char dscp[128] = {0};
	char output[128] = {0};
	char dest[128] = {0};
	int dscpflag = 0;
	char waninf[32] = {0};
	char *p = NULL;
	char *q = NULL;
	char value[32] = {0};
	int ret = 0;
	int i = 0;

	ret = do_uci_get(DIDS_DiagnosticsState, value);
	
	if(strcasecmp(value, "requested") == 0 && parameternum == 0)
	{
		ret = do_uci_get(DIDS_HostList, buff);
		if(buff[0] == '\0')
		{
			ret = do_uci_set(DIDS_DiagnosticsState, "Error_CannotResolveHostName");
			if(ret)
			{
				return (-1);
			}
			else
			{
				ret = do_uci_commit(MS);
				if(ret)
				{
					return (-1);
				}
			}
			return ret;
		}
		else
		{
			strcpy(host, buff);
			sprintf(dest, "-d %s", buff);
		}
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDS_Interface, buff);		
		if(buff[0] != '\0')
		{
			for (i = 0; i <= IP_LAN_INSTANCE_NUM; i ++){
				sprintf(buff2, "Device.IP.Interface.%d", lan_map[i].num);
				if (strcmp(buff, buff2) == 0){
					sprintf(interface, "-I %s", lan_map[i].laninf);
					sprintf(output, "-o %s", lan_map[i].laninf);
					break;
				}
			}
			if(strcmp(buff, IP_WAN_INTERFACE_PATH) == 0)
			{
				getWanHigherLayerInterface(waninf);
				sprintf(interface, "-I %s", waninf);
				sprintf(output, "-o %s", waninf);
			}
		}
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDS_NumberOfRepetitions, buff);
		if(buff[0] != '\0')
		{
			sprintf(number, "-c %s", buff);
		}
		else
		{
			strcpy(number, "-c 5");
		}
		memset(buff, 0, sizeof(buff));
		ret = do_uci_get(DIDS_Timeout, buff);
		if(buff[0] != '\0')
		{
			if(atoi(buff) < 1000)
			{
				strcpy(timeout, "-W 1");
			}
			else
			{
				sprintf(timeout, "-W %d", atoi(buff)/1000);
			}
		}
		else
		{
			strcpy(timeout, "-w 5");
		}
		system("rm /tmp/pingresult");
		p = host;
		while((q = strchr(p, ',')) != NULL)
		{
			*q = '\0';
			strcpy(host1, p);
			sprintf(command, "ping %s %s %s %s >> /tmp/pingresult", number, interface, timeout, host1);		
			tr_log(LOG_DEBUG,"command[%s]",command);
			system(command);
			p = q + 1;
		}
		strcpy(host1, p);
		sprintf(command, "ping %s %s %s %s >> /tmp/pingresult", number, interface, timeout, host1);		
		tr_log(LOG_DEBUG,"command[%s]",command);
		system(command);
	}
	else
	{
		return (-1);
	}
	
	ret = do_uci_set(DIDS_DiagnosticsState, "Complete");
	if(ret)
	{
		return (-1);
	}
	else
	{
		sentEventforDiagnostic();
		ret = do_uci_commit(MS);
		if(ret)
		{
			return (-1);
		}
	}
}

void doSSHFuncs(int in)
{
	int ret = 0,find = 0;
	char cmdbuf[256] = {0};
	char tmpbuf[256] = {0};

	if(parameternum == 0)
	{
		find = do_uci_get("firewall.wansshacs",tmpbuf);
		if(find != 0)
		{
			ret = do_uci_add("firewall","rule",tmpbuf);
			if(ret != 0)
			{
				return ret;
			}
			sprintf(cmdbuf, "firewall.%s", tmpbuf);
			ret = do_uci_rename(cmdbuf, "wansshacs");
			if(ret != 0)
			{
				return ret;
			}
		}

		ret = do_uci_set(FW_WAN_SSH_ACS_SRC,"wan");
		if(ret != 0)
		{
			return ret;
		}
		ret = do_uci_set(FW_WAN_SSH_ACS_PROTO,"tcp");
		if(ret != 0)
		{
			return ret;
		}
		ret = do_uci_set(FW_WAN_SSH_ACS_TARGET,"ACCEPT");
		if(ret != 0)
		{
			return ret;
		}

		ret = do_uci_get(ADMIN_SYS_SSH_PORT,tmpbuf);
		if(ret != 0)
		{
			return ret;
		}
		ret = do_uci_set(FW_WAN_SSH_ACS_DEST_PORT,tmpbuf);
		if(ret != 0)
		{
			return ret;
		}

		ret = do_uci_get(ADMIN_SYS_SSH_ENABLE,tmpbuf);
		if(ret != 0)
		{
			return ret;
		}
		ret = do_uci_set(FW_WAN_SSH_ACS_ENABLE,tmpbuf);
		if(ret != 0)
		{
			return ret;
		}

		do_uci_commit("firewall");
		/*if (in == 0){ //For WAN
			system("/sbin/sshacs passwd");
			system("/etc/init.d/firewall restart");
		}*/
		
		system("/sbin/sshacs passwd");
		system("/etc/init.d/firewall restart");
		system("/etc/init.d/dropbear restart");
	}
}

char valueToHexCh(const int value)
{
	char result = '\0';

	if(value >= 0 && value <= 9){
		result = (char)(value + 48);
	}
	else if(value >= 10 && value <= 15){
		result = (char)(value - 10 + 65);
	}
	else{
		;
	}

	return result;
}

int hexCharToValue(const char ch){
	int result = 0;
	if(ch >= '0' && ch <= '9'){
		result = (int)(ch - '0');
	}
	else if(ch >= 'a' && ch <= 'z'){
		result = (int)(ch - 'a') + 10;
	}
	else if(ch >= 'A' && ch <= 'Z'){
		result = (int)(ch - 'A') + 10;
	}
	else{
		result = -1;
	}
	return result;
}

int hexToStr(char *hex, char *ch)
{
	int high,low;
	int tmp = 0;

	if(hex == NULL || ch == NULL){
		return -1;
	}

	if(strlen(hex) %2 == 1){
		return -2;
	}

	while(*hex){
		high = hexCharToValue(*hex);
		if(high < 0){
			*ch = '\0';
		return -3;
		}
		hex++;
		low = hexCharToValue(*hex);
		if(low < 0){
			*ch = '\0';
			return -3;
		}
		tmp = (high << 4) + low;
		*ch++ = (char)tmp;
		hex++;
	}
	*ch = '\0';
	return 0;
}


int strToHex(char *ch, char *hex)
{
	int high,low;
	int tmp = 0;

	if(ch == NULL || hex == NULL){
		return -1;
	}

	if(strlen(ch) == 0){
		return -2;
	}

	while(*ch){
		tmp = (int)*ch;
		high = tmp >> 4;
		low = tmp & 15;
		*hex++ = valueToHexCh(high);
		*hex++ = valueToHexCh(low);
		ch++;
	}
	*hex = '\0';
	return 0;
}

void convert_hex(unsigned char *md, unsigned char *mdstr)
{
	int i;
	int j = 0;
	unsigned int c;

	for(i=0;i<20;i++){
		c=(md[i]>>4)&0x0f;
		mdstr[j++]=hex_chars[c];
		mdstr[j++]=hex_chars[md[i]&0x0f];
	}
	mdstr[40]='\0';
}

unsigned char *sha1_encode(unsigned char *src, unsigned char *value)
{
	SHA_CTX shactx;
	//char data[]="hello?groad.net";
	char md[SHA_DIGEST_LENGTH];
	char mdstr[40];

	//printf("Carlos debug: src = %s\n", src);
	SHA1_Init(&shactx);
	SHA1_Update(&shactx,src,strlen(src));
	SHA1_Final(md,&shactx);
	//printf("Carlos debug: md = %s\n", md);
	convert_hex(md,mdstr);
	printf ("Result of SHA1 : %s\n",mdstr);
	strcpy(value, mdstr);
	return 0;
}

void doRipFuncs()
{
	if(parameternum == 0)
	{
		runX_CharterRIP = 1;
	}
}

void runRipFuncs()
{
	//do_uci_commit("ripd");
	//do_uci_commit("firewall");
	system("/lib/network/prepare_rip_block.sh reload trcfg");
	system("ubus call network reload");
	system("/etc/init.d/quagga restart");
	system("sleep 3 && /etc/init.d/firewall restart &");
}

int doBandSteeringFuncs()
{
	int ret = 0;
	if(parameternum == 0)
	{
		ret = system(LBD_RESTART);
	}

	return ret;
}

void write_vendor_file(int index)
{
	FILE *fp = NULL;
	FILE *fp1 = NULL;
	FILE *fp2 = NULL;
	char filename[256] = {0};
	char filename2[256] = {0};

	sprintf(filename,"/oneagent/conf/ca%d.pem",index);
	tr_log(LOG_DEBUG,"filename[%s]",filename);
	fp = fopen(filename,"rb");
	if(fp == NULL)
	{
		sprintf(filename2,"/tmp/vendor/cert%d",index);
		tr_log(LOG_DEBUG,"filename2[%s]",filename2);
		fp2 = fopen(filename2, "r");
		if(fp2 != NULL)
		{
			int Certlen = 0;
			char cert[4096] = {0};
			char value[4096] = {0};
			char filename1[256] = {0};
			char head[30] = "-----BEGIN CERTIFICATE-----";
			char end[30] = "-----END CERTIFICATE-----";
			char line[10] = "\r\n";
			Certlen = fread(value,1,4096,fp2);
			fclose(fp2);

			sprintf(cert,"%s%s%s%s%s",head,line,value,line,end);
			sprintf(filename1,"/oneagent/conf/ca%d",index);
			tr_log(LOG_DEBUG,"filename1[%s]",filename1);
			fp1 = fopen(filename1,"w+");
			if(fp1 != NULL){
				char cmd[256] = {0};
				fwrite(cert, 1, strlen(cert), fp1);
				fclose(fp1);
				sprintf(cmd, "openssl x509 -outform PEM -in %s -out %s",filename1,filename);
				system(cmd);
			}
		}
	}
	else
		fclose(fp);
}

int pem_to_x509(int index, X509 **ptr_caCert)
{
	FILE *fp = NULL;
	char filename[256] = {0};

	tr_log(LOG_DEBUG,"index[%d]",index);
	sprintf(filename,"/oneagent/conf/ca%d.pem",index);
	tr_log(LOG_DEBUG,"filename[%s]",filename);
	fp = fopen(filename,"rb");
	if(fp == NULL)
	{
		tr_log(LOG_DEBUG,"can't open ca file");
		return -1;
	}
	else {
		tr_log(LOG_DEBUG,"get CA===1");
		*ptr_caCert = PEM_read_X509(fp, NULL, NULL, NULL);
		tr_log(LOG_DEBUG,"get CA===2");
		if(*ptr_caCert == NULL){
			tr_log(LOG_DEBUG,"PEM_read_X509 error");
			return -1;
		}
		tr_log(LOG_DEBUG,"get CA===3");
		fclose(fp);
	}

	return 0;
}

time_t ASN1_UTCTIME_get(const ASN1_UTCTIME *s)
{
    struct tm tm;
    int offset;

    memset(&tm, '\0', sizeof(tm));

	#define g2(p) (((p)[0]-'0')*10+(p)[1]-'0')
    tm.tm_year = g2(s->data);
    if (tm.tm_year < 50)
        tm.tm_year += 100;
    tm.tm_mon = g2(s->data + 2) - 1;
    tm.tm_mday = g2(s->data + 4);
    tm.tm_hour = g2(s->data + 6);
    tm.tm_min = g2(s->data + 8);
    tm.tm_sec = g2(s->data + 10);
    if (s->data[12] == 'Z')
        offset = 0;
    else {
        offset = g2(s->data + 13) * 60 + g2(s->data + 15);
        if (s->data[12] == '-')
            offset = -offset;
    }
    return mktime(&tm) - offset * 60;
}

void ASN1_UTCTIME_get1(const ASN1_UTCTIME *s, char *datetype)
{
    struct tm tm;
    int offset;
	char timestr[64] = {0};

    memset(&tm, '\0', sizeof(tm));

	#define g2(p) (((p)[0]-'0')*10+(p)[1]-'0')
    tm.tm_year = g2(s->data);
    if (tm.tm_year < 50)
        tm.tm_year += 100;
    tm.tm_mon = g2(s->data + 2) - 1;
    tm.tm_mday = g2(s->data + 4);
    tm.tm_hour = g2(s->data + 6);
    tm.tm_min = g2(s->data + 8);
    tm.tm_sec = g2(s->data + 10);
    if (s->data[12] == 'Z')
        offset = 0;
    else {
        offset = g2(s->data + 13) * 60 + g2(s->data + 15);
        if (s->data[12] == '-')
            offset = -offset;
    }

	strftime(timestr,100,"%Y-%m-%dT%H:%M:%SZ",&tm);
	strcpy(datetype, timestr);
}

void doDetectFuncs()
{
	if(parameternum == 0){
		system("echo 1 > /tmp/vendor/acs_restart_detection");
		system("/etc/init.d/detection stop");
		system("/etc/init.d/detection start");
	}
}

void addUciTopNode(char *topnode, char *name)
{
	char tmpbuf[256] = {0};
	char cmdbuf[512] = {0};

	do_uci_add(topnode, topnode, tmpbuf);
	sprintf(cmdbuf, "%s.%s", topnode, tmpbuf);
	do_uci_rename(cmdbuf, name);
}

void doIPInterfaceReset()
{
	if(parameternum == 0){
		system("/usr/sbin/reset_to_lan_default_settings.sh");
	}
}

int writeToNonvolatileCertFile(int index, char *value)
{

	FILE *fp = NULL;
	char filename[64] = {0};

	sprintf(filename,"/tmp/vendor/cert%d",index);
	fp = fopen(filename, "w+");
	if(fp != NULL)
	{
		fwrite(value,strlen(value),1,fp);
		fclose(fp);
	}
	else
		return -1;

	return 0;
}

int readFromNonvolatileFlashFile(char *name, char *value)
{
	FILE *fp = NULL;
	char tmp[128] = {0};
	char line[128] = {0};
	char *na = NULL;
	char *val = NULL;
	char *tp = NULL;
	int len = 0;

	fp = fopen("/tmp/vendor/persist", "r+");
	if(fp != NULL)
	{
		while(fgets(tmp,sizeof(tmp),fp)){
			strcpy(line,tmp);
			na = strtok(tmp,"=");	
			if(strcmp(na,name) == 0) {
				tp = strstr(line,"=");
				val = &tp[1];
				len = strlen(val);
				val[len-1]= '\0';
				strcpy(value,val);
			}else
				continue;
		}

		fclose(fp);
	}
	else 
		return -1;

	return 0;
}

int writeToNonvolatileFlashFile(char *name, char *value)
{
	FILE *fp = NULL;
	char tmp[128] = {0};
	char line[128] = {0};
	char *na = NULL;
	char *val = NULL;
	char *tp = NULL;
	int flag = 0;
	int len = 0;
	a_Fileinfo info[6];
	int i = 0;
	int count = 0;
	char buf[128] = {0};

	fp = fopen("/tmp/vendor/persist", "r");
	if(fp != NULL)
	{
		tr_log(LOG_DEBUG,"open file");
		while(fgets(tmp,sizeof(tmp),fp)){
			strcpy(line,tmp);
			na = strtok(tmp,"=");
			strcpy(info[i].name,na);
			tp = strstr(line,"=");
			val = &tp[1];
			len = strlen(val);
			val[len-1]= '\0';
			strcpy(info[i].value,val);
			tr_log(LOG_DEBUG,"info[i].value:%s strlen(info[i].value):%d,strlenvalue:%d\n",info[i].value,strlen(info[i].value),strlen(value));
			i++;
		}
		fclose(fp);
	}
	count = i;
	tr_log(LOG_DEBUG,"count[%d]",count);
	for(i=0;i<count;i++)
	{
		if(strcmp(name,info[i].name) == 0)
		{
			tr_log(LOG_DEBUG,"name same value:%s,info[i].value:%s\n",value,info[i].value);
			if(strcmp(value,info[i].value) == 0)
			{
				tr_log(LOG_DEBUG,"caojie debug value same\n");
				break;
			}
			else
			{
				memset(info[i].value,0,sizeof(info[i].value));
				strcpy(info[i].value,value);
				tr_log(LOG_DEBUG,"info[i].value:%s\n",info[i].value);
				flag = 1;
				break;
			}
		}
		else
			continue;
	}
	tr_log(LOG_DEBUG,"i[%d],count[%d]",i,count);

	if(i==count)
	{
		strcpy(info[count].name,name);
		strcpy(info[count].value,value);
		count++;
		flag = 1;
	}
	tr_log(LOG_DEBUG,"i[%d],count[%d]",i,count);
	if(flag == 1)
	{
		fp = fopen("/tmp/vendor/persist", "w+");
		if(fp != NULL)
		{
			for(i=0;i<count;i++)
			{
				sprintf(buf, "%s=%s\n", info[i].name,info[i].value);
				tr_log(LOG_DEBUG,"buf[%s]\n",buf);
				fputs(buf, fp);
			}
			fclose(fp);

		}
		else 
			return -1;
	}
	return 0;
}

int validate_args_boolean( char *value)
{
	if( (strcmp(value, "false" ) == 0) || ( strcmp(value, "true" ) == 0) || ( strcmp(value, "0" ) == 0) || ( strcmp(value, "1" ) == 0) )
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

int getQosQueueEntry(char *Alias)
{
	int i;
	char linebuf[128] = {0};
	char tmparray[64] = {0};
	char valbuf[64] = {0};
	char QueueNumberOfEntries[256] = {0};

	do_uci_get("qos.number.QueueNumberOfEntries", QueueNumberOfEntries);
	printf("QueueNumberOfEntries :%d\n", atoi(QueueNumberOfEntries));

	for(i=1; i<=atoi(QueueNumberOfEntries); i++)
	{
		sprintf(tmparray, "qos.queue%d", i);
		sprintf(linebuf, "%s.Alias", tmparray);
		do_uci_get(linebuf, valbuf);
		tr_log(LOG_DEBUG,"linebuf [%s]",linebuf);
		tr_log(LOG_DEBUG,"valbuf [%s]",valbuf);

		if(strcmp(valbuf, Alias) == 0)
		{
			return i;
		}
	}
	return -1;
}

int getQosClassificationEntry(char *Alias)
{
	char linebuf[128] = {0};
	char tmparray[64] = {0};
	char valbuf[64] = {0};
	int i = 0;
	int found = 0;
	char MaxClassificationEntries[256] = {0};

	do_uci_get("qos.number.MaxClassificationEntries", MaxClassificationEntries);
	while(i < atoi(MaxClassificationEntries))
	{
		i++;
		sprintf(tmparray, "qos.cf%d", i);
		sprintf(linebuf, "%s.Alias", tmparray);
		do_uci_get(linebuf, valbuf);
		tr_log(LOG_DEBUG,"linebuf [%s]",linebuf);
		tr_log(LOG_DEBUG,"valbuf [%s]",valbuf);
		tr_log(LOG_DEBUG,"Alias [%s]",Alias);

		if(strcmp(valbuf, Alias) == 0)
		{
			found = 1;
			break;
		}
	}

	if(found == 1)
	{
		return i;
	}
	else
	{
		return -1;
	}
}

void doQoSQueue()
{
	if(parameternum == 0)
	{
		system("sh /lib/queue.sh");
		system("sh /tmp/queue.ctrl");
	}
}

void doQoSClassification()
{
	if(parameternum == 0)
	{
		system("sh /lib/classification.sh");
		system("sleep 3");
		system("sh /tmp/classification.ctrl");
	}
}

int checkPortUsing(int port)
{
    FILE *fp = NULL;
    char line[1024] = {0};
    char localinfo[128] = {0};
	char *ptr = NULL;
	int used= 0;
	
	if ((fp=popen("netstat -t -u -n","r")) != NULL)
	{
		fgets(line,sizeof(line),fp);
		fgets(line,sizeof(line),fp);
		while (fgets(line,sizeof(line),fp))
		{
			sscanf(line, "%*s %*s %*s %s %*s %*s", localinfo);
			if((ptr = strrchr(localinfo, ':')) != NULL)
			{
				if(atoi(ptr+1) == port)
				{
					used = 1;
					break;
				}
			}
		}
		pclose(fp);
	}
	return used;
}

int checkInterface(char *value)
{
	char name[256] = {0};
	int num = 0;
	int i = 0, found = 0;

	for (i = 0; i <= IP_LAN_INSTANCE_NUM; i ++){
		sprintf(name, "Device.IP.Interface.%d", lan_map[i].num);
		if (strcasecmp(value, name) == 0){
			found = 1;
			break;
		}
	}

	if (strcasecmp(value, IP_WAN_INTERFACE_PATH) == 0)
	{
		found = 1;
	}

	return found;
}

void doWifiReload(int num)
{
	tr_log(LOG_DEBUG,"num [%d]",num);
	wifi_restart = 1;
}

void runWifiReload()
{
	pthread_detach( pthread_self() );
	tr_log(LOG_DEBUG,"parameternum [%d]",parameternum);
	if(parameternum == 0)
	{
		system("/sbin/wifi reload_legacy wifi0");
		system("/sbin/wifi reload_legacy wifi1");
	}
	//pthread_exit( 0 );
	return;
}

void doSbinWifi()
{
	wifi_radio_restart = 1;
}

void runSbinWifi()
{
	pthread_detach( pthread_self() );
	tr_log(LOG_DEBUG,"parameternum [%d]",parameternum);
	if(parameternum == 0)
	{
		system("/sbin/wifi");
	}
	//pthread_exit( 0 );
	return;
}

void doGRE(int enable)
{
	tr_log(LOG_DEBUG,"parameternum [%d]",parameternum);
	if(parameternum == 0)
	{
		if(enable == 1)
			system("/oneagent/runCommand gre start");
		else
			system("/oneagent/runCommand gre stop");
			
	}
}

void doQoSShaper()
{
	tr_log(LOG_DEBUG,"parameternum [%d]",parameternum);
	if(parameternum == 0)
	{
		system("/lib/shaper.sh");
	}
}

void doPortmapping()
{
	portmapping_restart = 1;
}

void runPortmapping()
{
	pthread_detach( pthread_self() );
	tr_log(LOG_DEBUG,"parameternum [%d]",parameternum);
	if(parameternum == 0)
	{
		system("/lib/firewall/firewall_nat.sh");
	}
	//pthread_exit( 0 );
	return;
}

void doDhcprestart(int num)
{
	char cmd[256] = {0};
	tr_log(LOG_DEBUG,"num [%d]",num);
	
	if(parameternum == 0)
	{
		dhcp_restart = 1;
		dhcp_num = num;
	}
}

void Dhcprestart(int num)
{
	char cmd[256] = {0};
	tr_log(LOG_DEBUG,"num [%d]",num);
	
	system("/etc/init.d/dnsmasq stop");
	if(num == 1)
	{
		strcpy(cmd, "ifup lan");
	}
	else
	{
		sprintf(cmd, "ifup lan%d", num-1);
	}
	
	tr_log(LOG_DEBUG,"cmd [%s]",cmd);
	system(cmd);
}

void doRestartNetwork()
{
	restart_network = 1;
}

void RestartNetwork()
{
	system("/etc/init.d/network restart");
	system("sleep 3 && /etc/init.d/firewall restart");
}

void doRestartLanNetwork()
{
	restart_Lan_network = 1;
}

void RestartLanNetwork()
{
	system("/etc/init.d/dnsmasq stop");
	system("/etc/init.d/network restart");
}

void doIPv6Restart()
{
	restart_IPv6 = 1;
}

void IPv6Restart()
{
	system("/etc/init.d/radvd enable");
	system("/etc/init.d/dibbler-server enable");
	do_uci_set("network.wan.restart", "1");
	system("/etc/init.d/network restart");
	system("sleep 3 && /etc/init.d/firewall restart");
}

void doRadvdRestart()
{
	restart_radvd = 1;
}

void RadvdRestart()
{
	system("/etc/init.d/radvd restart");
}

void dowifidog()
{
	if(parameternum == 0)
	{
		system("/etc/init.d/wifidog restart &");
	}
}

void executeCMD(char *cmd,char *rusult)
{
        FILE *fd = NULL;
        char line[128] = {0};
        char *ptr = NULL;
	if ((fd = popen(cmd, "r")) != NULL){
       // if ((fd = popen("cat /var/is_send_notify", "r")) != NULL){
                if(fgets(line,sizeof(line)-1,fd)){
                        if ((ptr = strstr(line,"\n")) != NULL){
                                *ptr = '\0';
                        }
                        if ((ptr = strstr(line," ")) != NULL){
                                *ptr = '\0';
                        }
                        strcpy(rusult, line);
                }
                pclose(fd);
        }
}