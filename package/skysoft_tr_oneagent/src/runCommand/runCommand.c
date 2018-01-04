#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uci.h>
#include <suci.h>

#define IP_WAN_INTERFACE_PATH "Device.IP.Interface.5"

//extern int uci_caller = UCI_CALLER_TR;

typedef struct a_waninfo{
    int status;
	char uptime[128];
    char l3_device[32];
    char proto[32];
    char device[32];
    char ipv4_address[32];
	char mask[32];
	char ipv6_address[128];
	char ipv6_mask[32];
	char ipv6_prefix_address[128];
	char ipv6_prefix_mask[64];
    char nexthop[128];
    char dns[512];
}a_infinfo;

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
						if (strstr(line, "nexthop:") != NULL){
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
	}
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
	
int getvalue_mapfile_byinstance(char* filename,char *value, int inst)
{
    int i = 0;
	int instance;
	char szinstance[16];
	char szvalue[256];
	
	FILE *fp = fopen(filename,"r");
	if (fp)
	{
		while(!feof(fp))
		{
			fscanf(fp,"%s %*s %s",szinstance,szvalue);
			instance	= atoi(szinstance);
			if (instance == inst)
			{
				printf("value = %s \n", szvalue);
				strcpy(value,szvalue);
				fclose(fp);
				return 0;
			}
			i++;
		}
		fclose(fp);
	}
	return -1;
}

void runqos(char *cmd)
{
	char ShaperNumberOfEntries[32] = {0};
	char QueueNumberOfEntries[32] = {0};
	char ClassificationNumberOfEntries[32] = {0};
	char ShapingRate[32] = {0};
	char ShapingBurstSize[32] = {0};
	char InterfaceName[256] = {0};
	char TrafficClasses[256] = {0};
	char Interface[256] = {0};
	char Weight[256] = {0};
	char Precedence[256] = {0};
	char SchedulerAlgorithm[256] = {0};
	char name[256] = {0};
	char command[256] = {0};
	int i = 0;
	int j = 0;
	int classid = 1;
	int classid1 = 1;
	int wrrflag1 = 0;	
	int wrrflag2 = 0;	
	int wfqflag1 = 0;	
	int wfqflag2 = 0;	
	int setdefault = 0;
	int setdefault1 = 0;
	char value[64] = {0};
	char waninf[32] = {0};

	getEthInterfaceName("wan", waninf);
	
	memset(ShaperNumberOfEntries, 0, sizeof(ShaperNumberOfEntries));
	do_uci_get("trconf.Device_QoS.ShaperNumberOfEntries", ShaperNumberOfEntries);
	printf("ShaperNumberOfEntries: %s\n", ShaperNumberOfEntries);

	while(i < atoi(ShaperNumberOfEntries))
	{
		j++;
		sprintf(name, "trconf.Device_QoS_Shaper_%d", j); 	
		do_uci_get(name,value);

		if(strcmp(value, "acs") == 0)
		{
			sprintf(name, "trconf.Device_QoS_Shaper_%d.Interface", j);	
			do_uci_get(name, Interface);
			sprintf(name, "trconf.Device_QoS_Shaper_%d.ShapingRate", j);	
			do_uci_get(name, ShapingRate);
			sprintf(name, "trconf.Device_QoS_Shaper_%d.ShapingBurstSize", j);	
			do_uci_get(name, ShapingBurstSize);

			if(strcmp(Interface, "Device.IP.Interface.1") == 0)
			{
				strcpy(InterfaceName, "br-lan");
			}
			else
			{
				strcpy(InterfaceName, waninf);
			}

			if(strcmp(cmd, "start") == 0)
			{
				sprintf(command, "tc qdisc add dev %s root handle 1: nsstbl rate %s burst %d", InterfaceName, ShapingRate, atoi(ShapingBurstSize)*8);
				system(command);
				printf("command: %s\n", command);
			}
			else
			{
				sprintf(command, "tc qdisc del dev %s root handle 1: nsstbl rate %s burst %d", InterfaceName, ShapingRate, atoi(ShapingBurstSize)*8);
				system(command);
				printf("command: %s\n", command);
			}
			memset(Interface, 0, sizeof(Interface));
			memset(ShapingRate, 0, sizeof(ShapingRate));
			memset(ShapingBurstSize, 0, sizeof(ShapingBurstSize));
			memset(command, 0, sizeof(command));
			i++;
		}
	}

	memset(QueueNumberOfEntries, 0, sizeof(QueueNumberOfEntries));
	do_uci_get("trconf.Device_QoS.QueueNumberOfEntries", QueueNumberOfEntries);
	printf("QueueNumberOfEntries: %s\n", QueueNumberOfEntries);

	i = 0;
	j = 0;
	while(i < atoi(QueueNumberOfEntries))
	{
		j++;
		sprintf(name, "trconf.Device_QoS_Queue_%d", j);		
		memset(value, 0, sizeof(value));
		do_uci_get(name,value);
		if(strcmp(value, "acs") == 0)
		{
			i++;
			sprintf(name, "trconf.Device_QoS_Queue_%d.TrafficClasses", j);	
			do_uci_get(name, TrafficClasses);
			sprintf(name, "trconf.Device_QoS_Queue_%d.Interface", j);	
			do_uci_get(name, Interface);
			sprintf(name, "trconf.Device_QoS_Queue_%d.Weight", j);	
			do_uci_get(name, Weight);
			sprintf(name, "trconf.Device_QoS_Queue_%d.Precedence", j);	
			do_uci_get(name, Precedence);
			sprintf(name, "trconf.Device_QoS_Queue_%d.SchedulerAlgorithm", j);	
			do_uci_get(name, SchedulerAlgorithm);

			if(strcmp(Interface, "Device.IP.Interface.1") == 0)
			{
				strcpy(InterfaceName, "br-lan");
			}
			else
			{
				strcpy(InterfaceName, waninf);
			}

			if(strcasecmp(SchedulerAlgorithm, "SP") == 0)
			{
				sprintf(command, "tc qdisc add dev %s parent 1:1 handle 10: nssprio bands 3", InterfaceName);
				system(command);
				printf("command: %s\n", command);
				sprintf(command, "tc qdisc add dev %s parent 10:1 handle 101: nsspfifo", InterfaceName);
				system(command);
				printf("command: %s\n", command);
				sprintf(command, "tc qdisc add dev %s parent 10:2 handle 102: nsspfifo", InterfaceName);
				system(command);
				printf("command: %s\n", command);
				sprintf(command, "tc qdisc add dev %s parent 10:3 handle 103: nsspfifo set_default", InterfaceName);
				system(command);
				printf("command: %s\n", command);
			}
			else if(strcasecmp(SchedulerAlgorithm, "WRR") == 0)
			{
				if(strcmp(InterfaceName, "br-lan") == 0)
				{
					if(wrrflag1 == 0)
					{
						sprintf(command, "tc qdisc add dev %s parent 1:1 handle 2: nsswrr", InterfaceName);
						system(command);
						printf("command: %s\n", command);
						wrrflag1 = 1;
					}
					sprintf(command, "tc class add dev %s parent 2: classid 2:%d nsswrr quantum %s", InterfaceName, classid, Weight);
					system(command);
					printf("command: %s\n", command);
					if(setdefault == 0)
					{
						sprintf(command, "tc qdisc add dev %s parent 2:%d handle %d00: nsspfifo set_default", InterfaceName, classid, classid);
						system(command);
						printf("command: %s\n", command);
						setdefault = 1;
					}
					else
					{
						sprintf(command, "tc qdisc add dev %s parent 2:%d handle %d00: nsspfifo", InterfaceName, classid, classid);
						system(command);
						printf("command: %s\n", command);
					}
					classid++;
				}
				else
				{
					if(wrrflag2 == 0)
					{
						sprintf(command, "tc qdisc add dev %s parent 1:1 handle 2: nsswrr", InterfaceName);
						system(command);
						printf("command: %s\n", command);
						wrrflag2 = 1;
					}
					sprintf(command, "tc class add dev %s parent 2: classid 2:%d nsswrr quantum %s", InterfaceName, classid1, Weight);
					system(command);
					printf("command: %s\n", command);
					if(setdefault1 == 0)
					{
						sprintf(command, "tc qdisc add dev %s parent 2:%d handle %d00: nsspfifo set_default", InterfaceName, classid1, classid1);
						system(command);
						printf("command: %s\n", command);
						setdefault1 = 1;
					}
					else
					{
						sprintf(command, "tc qdisc add dev %s parent 2:%d handle %d00: nsspfifo", InterfaceName, classid1, classid1);
						system(command);
						printf("command: %s\n", command);
					}
					classid1++;
				}		
			}
			else if(strcasecmp(SchedulerAlgorithm, "WFQ") == 0)
			{
				if(strcmp(InterfaceName, "br-lan") == 0)
				{
					if(wfqflag1 == 0)
					{
						sprintf(command, "tc qdisc add dev %s parent 1:1 handle 2: nsswfq", InterfaceName);
						system(command);
						printf("command: %s\n", command);
						wfqflag1 = 1;
					}
					sprintf(command, "tc class add dev %s parent 2: classid 2:%d nsswfq quantum %s", InterfaceName, classid, Weight);
					system(command);
					printf("command: %s\n", command);
					if(setdefault == 0)
					{
						sprintf(command, "tc qdisc add dev %s parent 2:%d handle %d00: nsspfifo set_default", InterfaceName, classid, classid);
						system(command);
						printf("command: %s\n", command);
						setdefault = 1;
					}
					else
					{
						sprintf(command, "tc qdisc add dev %s parent 2:%d handle %d00: nsspfifo", InterfaceName, classid, classid);
						system(command);
						printf("command: %s\n", command);
					}
					classid++;
				}
				else
				{
					if(wfqflag2 == 0)
					{
						sprintf(command, "tc qdisc add dev %s parent 1:1 handle 2: nsswfq", InterfaceName);
						system(command);
						printf("command: %s\n", command);
						wfqflag2 = 1;
					}
					sprintf(command, "tc class add dev %s parent 2: classid 2:%d nsswfq quantum %s", InterfaceName, classid1, Weight);
					system(command);
					printf("command: %s\n", command);
					if(setdefault1 == 0)
					{
						sprintf(command, "tc qdisc add dev %s parent 2:%d handle %d00: nsspfifo set_default", InterfaceName, classid1, classid1);
						system(command);
						printf("command: %s\n", command);
						setdefault1 = 1;
					}
					else
					{
						sprintf(command, "tc qdisc add dev %s parent 2:%d handle %d00: nsspfifo", InterfaceName, classid1, classid1);
						system(command);
						printf("command: %s\n", command);
					}
					classid1++;
				}		
			}
		}
	}

	char Enable[32] = {0};
	char Order[32] = {0};
	char AllInterfaces[32] = {0};
	char DestIP[32] = {0};
	char DestMask[32] = {0};
	char DestIPExclude[32] = {0};
	char SourceIP[32] = {0};
	char SourceMask[32] = {0};
	char SourceIPExclude[32] = {0};
	char DestPort[32] = {0};
	char DestPortRangeMax[32] = {0};
	char DestPortExclude[32] = {0};
	char SourcePort[32] = {0};
	char SourcePortRangeMax[32] = {0};
	char SourcePortExclude[32] = {0};
	char SourceMACAddress[32] = {0};
	char SourceMACMask[32] = {0};
	char SourceMACExclude[32] = {0};
	char DestMACAddress[32] = {0};
	char DestMACMask[32] = {0};
	char DestMACExclude[32] = {0};
	char TCPACK[32] = {0};
	char TCPACKExclude[32] = {0};
	char DSCPMark[32] = {0};
	char TrafficClass[32] = {0};
	char Protocol[32] = {0};
	char ProtocolExclude[32] = {0};
	char Ethertype[32] = {0};
	char EthertypeExclude[32] = {0};
	char SSAP[32] = {0};
	char SSAPExclude[32] = {0};
	char DSCPCheck[32] = {0};
	char DSCPExclude[32] = {0};
	char EthernetPriorityCheck[32] = {0};
	char EthernetPriorityExclude[32] = {0};
	char VLANIDCheck[32] = {0};
	char VLANIDExclude[32] = {0};
	char IPLengthMin[32] = {0};
	char IPLengthMax[32] = {0};
	char IPLengthExclude[32] = {0};
	char App[32] = {0};
	char iptablescommand[1024] = {0};
	char ebtablescommand[1024] = {0};

	memset(ClassificationNumberOfEntries, 0, sizeof(ClassificationNumberOfEntries));
	do_uci_get("trconf.Device_QoS.ClassificationNumberOfEntries", ClassificationNumberOfEntries);
	printf("ClassificationNumberOfEntries: %s\n", ClassificationNumberOfEntries);

	i = 0;
	j = 0;
	while(i < atoi(ClassificationNumberOfEntries))
	{
		j++;
		sprintf(name, "trconf.Device_QoS_Classification_%d", j);
		memset(value, 0, sizeof(value));
		do_uci_get(name,value);
		if(strcmp(value, "acs") == 0)
		{
			i++;
			memset(Enable, 0, sizeof(Enable));
			sprintf(name, "trconf.Device_QoS_Classification_%d.Enable", j);	
			do_uci_get(name, Enable);

			if(atoi(Enable) == 0)
			{
				continue;
			}
			
			memset(Order, 0, sizeof(Order));
			memset(Interface, 0, sizeof(Interface));
			memset(AllInterfaces, 0, sizeof(AllInterfaces));
			memset(DestIP, 0, sizeof(DestIP));
			memset(DestMask, 0, sizeof(DestMask));
			memset(DestIPExclude, 0, sizeof(DestIPExclude));
			memset(SourceIP, 0, sizeof(SourceIP));
			memset(SourceMask, 0, sizeof(SourceMask));
			memset(SourceIPExclude, 0, sizeof(SourceIPExclude));
			memset(DestPort, 0, sizeof(DestPort));
			memset(DestPortRangeMax, 0, sizeof(DestPortRangeMax));
			memset(DestPortExclude, 0, sizeof(DestPortExclude));
			memset(SourcePort, 0, sizeof(SourcePort));
			memset(SourcePortRangeMax, 0, sizeof(SourcePortRangeMax));
			memset(SourcePortExclude, 0, sizeof(SourcePortExclude));
			memset(SourceMACAddress, 0, sizeof(SourceMACAddress));
			memset(SourceMACMask, 0, sizeof(SourceMACMask));
			memset(SourceMACExclude, 0, sizeof(SourceMACExclude));
			memset(DestMACAddress, 0, sizeof(DestMACAddress));
			memset(DestMACMask, 0, sizeof(DestMACMask));
			memset(DestMACExclude, 0, sizeof(DestMACExclude));
			memset(TCPACK, 0, sizeof(TCPACK));
			memset(TCPACKExclude, 0, sizeof(TCPACKExclude));
			memset(DSCPMark, 0, sizeof(DSCPMark));
			memset(Protocol, 0, sizeof(Protocol));
			memset(ProtocolExclude, 0, sizeof(ProtocolExclude));
			memset(TrafficClass, 0, sizeof(TrafficClass));
			memset(Ethertype, 0, sizeof(Ethertype));
			memset(EthertypeExclude, 0, sizeof(EthertypeExclude));
			memset(SSAP, 0, sizeof(SSAP));
			memset(SSAPExclude, 0, sizeof(SSAPExclude));
			memset(DSCPCheck, 0, sizeof(DSCPCheck));
			memset(DSCPExclude, 0, sizeof(DSCPExclude));
			memset(EthernetPriorityCheck, 0, sizeof(EthernetPriorityCheck));
			memset(EthernetPriorityExclude, 0, sizeof(EthernetPriorityExclude));
			memset(VLANIDCheck, 0, sizeof(VLANIDCheck));
			memset(VLANIDExclude, 0, sizeof(VLANIDExclude));
			memset(App, 0, sizeof(App));
			memset(IPLengthMin, 0, sizeof(IPLengthMin));
			memset(IPLengthMax, 0, sizeof(IPLengthMax));
			memset(IPLengthExclude, 0, sizeof(IPLengthExclude));
			
			sprintf(name, "trconf.Device_QoS_Classification_%d.Order", j);	
			do_uci_get(name, Order);
			sprintf(name, "trconf.Device_QoS_Classification_%d.Interface", j);	
			do_uci_get(name, Interface);
			sprintf(name, "trconf.Device_QoS_Classification_%d.AllInterfaces", j);	
			do_uci_get(name, AllInterfaces);
			sprintf(name, "trconf.Device_QoS_Classification_%d.DestIP", j);	
			do_uci_get(name, DestIP);
			sprintf(name, "trconf.Device_QoS_Classification_%d.DestMask", j);	
			do_uci_get(name, DestMask);
			sprintf(name, "trconf.Device_QoS_Classification_%d.DestIPExclude", j);	
			do_uci_get(name, DestIPExclude);
			sprintf(name, "trconf.Device_QoS_Classification_%d.SourceIP", j);	
			do_uci_get(name, SourceIP);
			sprintf(name, "trconf.Device_QoS_Classification_%d.SourceMask", j);	
			do_uci_get(name, SourceMask);
			sprintf(name, "trconf.Device_QoS_Classification_%d.SourceIPExclude", j);	
			do_uci_get(name, SourceIPExclude);
			sprintf(name, "trconf.Device_QoS_Classification_%d.DestPort", j);	
			do_uci_get(name, DestPort);
			sprintf(name, "trconf.Device_QoS_Classification_%d.DestPortRangeMax", j);	
			do_uci_get(name, DestPortRangeMax);
			sprintf(name, "trconf.Device_QoS_Classification_%d.DestPortExclude", j);	
			do_uci_get(name, DestPortExclude);
			sprintf(name, "trconf.Device_QoS_Classification_%d.SourcePort", j);	
			do_uci_get(name, SourcePort);
			sprintf(name, "trconf.Device_QoS_Classification_%d.SourcePortRangeMax", j);	
			do_uci_get(name, SourcePortRangeMax);
			sprintf(name, "trconf.Device_QoS_Classification_%d.SourcePortExclude", j);	
			do_uci_get(name, SourcePortExclude);
			sprintf(name, "trconf.Device_QoS_Classification_%d.SourceMACAddress", j);	
			do_uci_get(name, SourceMACAddress);
			sprintf(name, "trconf.Device_QoS_Classification_%d.SourceMACMask", j);	
			do_uci_get(name, SourceMACMask);
			sprintf(name, "trconf.Device_QoS_Classification_%d.SourceMACExclude", j);	
			do_uci_get(name, SourceMACExclude);
			sprintf(name, "trconf.Device_QoS_Classification_%d.TCPACK", j);	
			do_uci_get(name, TCPACK);
			sprintf(name, "trconf.Device_QoS_Classification_%d.TCPACKExclude", j);	
			do_uci_get(name, TCPACKExclude);
			sprintf(name, "trconf.Device_QoS_Classification_%d.TrafficClass", j);	
			do_uci_get(name, TrafficClass);
			sprintf(name, "trconf.Device_QoS_Classification_%d.DSCPMark", j);	
			do_uci_get(name, DSCPMark);
			sprintf(name, "trconf.Device_QoS_Classification_%d.Protocol", j);	
			do_uci_get(name, Protocol);
			sprintf(name, "trconf.Device_QoS_Classification_%d.ProtocolExclude", j);	
			do_uci_get(name, ProtocolExclude);
			sprintf(name, "trconf.Device_QoS_Classification_%d.DestMACAddress", j);	
			do_uci_get(name, DestMACAddress);
			sprintf(name, "trconf.Device_QoS_Classification_%d.DestMACMask", j);	
			do_uci_get(name, DestMACMask);
			sprintf(name, "trconf.Device_QoS_Classification_%d.DestMACExclude", j);	
			do_uci_get(name, DestMACExclude);
			sprintf(name, "trconf.Device_QoS_Classification_%d.Ethertype", j);	
			do_uci_get(name, Ethertype);
			sprintf(name, "trconf.Device_QoS_Classification_%d.EthertypeExclude", j);	
			do_uci_get(name, EthertypeExclude);
			sprintf(name, "trconf.Device_QoS_Classification_%d.SSAP", j);	
			do_uci_get(name, SSAP);
			sprintf(name, "trconf.Device_QoS_Classification_%d.SSAPExclude", j);	
			do_uci_get(name, SSAPExclude);
			sprintf(name, "trconf.Device_QoS_Classification_%d.DSCPCheck", j);	
			do_uci_get(name, DSCPCheck);
			sprintf(name, "trconf.Device_QoS_Classification_%d.DSCPExclude", j);	
			do_uci_get(name, DSCPExclude);
			sprintf(name, "trconf.Device_QoS_Classification_%d.EthernetPriorityCheck", j);	
			do_uci_get(name, EthernetPriorityCheck);
			sprintf(name, "trconf.Device_QoS_Classification_%d.EthernetPriorityExclude", j);	
			do_uci_get(name, EthernetPriorityExclude);
			sprintf(name, "trconf.Device_QoS_Classification_%d.VLANIDCheck", j);	
			do_uci_get(name, VLANIDCheck);
			sprintf(name, "trconf.Device_QoS_Classification_%d.VLANIDExclude", j);	
			do_uci_get(name, VLANIDExclude);
			sprintf(name, "trconf.Device_QoS_Classification_%d.App", j);	
			do_uci_get(name, App);
			sprintf(name, "trconf.Device_QoS_Classification_%d.IPLengthMin", j);	
			do_uci_get(name, IPLengthMin);
			sprintf(name, "trconf.Device_QoS_Classification_%d.IPLengthMax", j);	
			do_uci_get(name, IPLengthMax);
			sprintf(name, "trconf.Device_QoS_Classification_%d.IPLengthExclude", j);	
			do_uci_get(name, IPLengthExclude);

			char markmatch[64] = {0};
			if(Order[0] != '\0')
			{
				sprintf(markmatch, "-m mark --mark %s", Order);
			}

			char intefacematch[64] = {0};
			memset(intefacematch, 0, sizeof(intefacematch));
			if(atoi(AllInterfaces) != 1)
			{
				if(strcmp(Interface, "Device.IP.Interface.1") == 0)
				{
					strcpy(intefacematch, "-i br-lan");
				}
				else if(strcmp(Interface, IP_WAN_INTERFACE_PATH) == 0)
				{
					strcpy(intefacematch, "-i eth0");
				}
			}
			
			char destipmatch[64] = {0};
			if(atoi(DestIPExclude) == 1)
			{
				if((DestIP[0] != '\0') && (DestMask[0] == '\0'))
					sprintf(destipmatch, "! -d %s", DestIP);
				if((DestIP[0] != '\0') && (DestMask[0] != '\0'))
					sprintf(destipmatch, "! -d %s/%s", DestIP, DestMask);
			}
			else
			{
				if((DestIP[0] != '\0') && (DestMask[0] == '\0'))
					sprintf(destipmatch, "-d %s", DestIP);
				if((DestIP[0] != '\0') && (DestMask[0] != '\0'))
					sprintf(destipmatch, "-d %s/%s", DestIP, DestMask);
			}
				
			char srcipmatch[64] = {0};
			if(atoi(SourceIPExclude) == 1)
			{
				if((SourceIP[0] != '\0') && (SourceMask[0] == '\0'))
					sprintf(srcipmatch, "! -s %s", SourceIP);
				if((SourceIP[0] != '\0') && (SourceMask[0] != '\0'))
					sprintf(srcipmatch, "! -s %s/%s", SourceIP, SourceMask);
			}
			else
			{
				if((SourceIP[0] != '\0') && (SourceMask[0] == '\0'))
					sprintf(srcipmatch, "-s %s", SourceIP);
				if((SourceIP[0] != '\0') && (SourceMask[0] != '\0'))
					sprintf(srcipmatch, "-s %s/%s", SourceIP, SourceMask);
			}

			char Protocolmatch[64] = {0};
			if(atoi(ProtocolExclude) == 1)
			{
				if((Protocol[0] != '\0') && (atoi(Protocol) != -1))
					sprintf(Protocolmatch, "! -p %s", Protocol);
			}
			else
			{
				if((Protocol[0] != '\0') && (atoi(Protocol) != -1))
					sprintf(Protocolmatch, "-p %s", Protocol);
			}

			char destportmatch[64] = {0};
			if(atoi(DestPortExclude) == 1)
			{
				if((DestPort[0] != '\0') && (DestPortRangeMax[0] == '\0'))
					sprintf(destportmatch, "! --dport %s", DestPort);
				if((DestPort[0] != '\0') && (DestPortRangeMax[0] != '\0'))
					sprintf(destportmatch, "! --dport %s:%s", DestPort, DestPortRangeMax);
				if(DestPort[0] != '\0')
					strcpy(Protocolmatch, "-p tcp");
			}
			else
			{
				if((DestPort[0] != '\0') && (DestPortRangeMax[0] == '\0'))
					sprintf(destportmatch, "--dport %s", DestPort);
				if((DestPort[0] != '\0') && (DestPortRangeMax[0] != '\0'))
					sprintf(destportmatch, "--dport %s:%s", DestPort, DestPortRangeMax);
				if(DestPort[0] != '\0')
					strcpy(Protocolmatch, "-p tcp");
			}
			
			char srcportmatch[64] = {0};
			if(atoi(SourcePortExclude) == 1)
			{
				if((SourcePort[0] != '\0') && (SourcePortRangeMax[0] == '\0'))
					sprintf(srcportmatch, "! --sport %s", SourcePort);
				if((SourcePort[0] != '\0') && (SourcePortRangeMax[0] != '\0'))
					sprintf(srcportmatch, "! --sport %s:%s", SourcePort, SourcePortRangeMax);
				if(SourcePort[0] != '\0')
					strcpy(Protocolmatch, "-p tcp");
			}
			else
			{
				if((SourcePort[0] != '\0') && (SourcePortRangeMax[0] == '\0'))
					sprintf(srcportmatch, "--sport %s", SourcePort);
				if((SourcePort[0] != '\0') && (SourcePortRangeMax[0] != '\0'))
					sprintf(srcportmatch, "--sport %s:%s", SourcePort, SourcePortRangeMax);
				if(SourcePort[0] != '\0')
					strcpy(Protocolmatch, "-p tcp");
			}
			
			char srcmacmatch[64] = {0};
			memset(srcmacmatch, 0, sizeof(srcmacmatch));
			if(atoi(SourceMACExclude) == 1)
			{
				if((SourceMACAddress[0] != '\0') && (SourceMACMask[0] == '\0'))
					sprintf(srcmacmatch, "-s ! %s", SourceMACAddress);
				if((SourceMACAddress[0] != '\0') && (SourceMACMask[0] != '\0'))
					sprintf(srcmacmatch, "-s ! %s/%s", SourceMACAddress, SourceMACMask);
			}
			else
			{
				if((SourceMACAddress[0] != '\0') && (SourceMACMask[0] == '\0'))
					sprintf(srcmacmatch, "-s %s", SourceMACAddress);
				if((SourceMACAddress[0] != '\0') && (SourceMACMask[0] != '\0'))
					sprintf(srcmacmatch, "-s %s/%s", SourceMACAddress, SourceMACMask);
			}

			char destmacmatch[64] = {0};
			memset(destmacmatch, 0, sizeof(destmacmatch));
			if(atoi(DestMACExclude) == 1)
			{
				if((DestMACAddress[0] != '\0') && (DestMACMask[0] == '\0'))
					sprintf(destmacmatch, "-d ! %s", DestMACAddress);
				if((DestMACAddress[0] != '\0') && (DestMACMask[0] != '\0'))
					sprintf(destmacmatch, "-d ! %s/%s", DestMACAddress, DestMACMask);
			}
			else
			{
				if((DestMACAddress[0] != '\0') && (DestMACMask[0] == '\0'))
					sprintf(destmacmatch, "-d %s", DestMACAddress);
				if((DestMACAddress[0] != '\0') && (DestMACMask[0] != '\0'))
					sprintf(destmacmatch, "-d %s/%s", DestMACAddress, DestMACMask);
			}

			char ethertypematch[64] = {0};
			memset(ethertypematch, 0, sizeof(ethertypematch));
			if(atoi(EthertypeExclude) == 1)
			{
				if((Ethertype[0] != '\0') && (atoi(Ethertype) != -1))
					sprintf(ethertypematch, "-p ! %s", Ethertype);
			}
			else
			{
				if((Ethertype[0] != '\0') && (atoi(Ethertype) != -1))
					sprintf(ethertypematch, "-p %s", Ethertype);
			}

			char sapmatch[64] = {0};
			memset(sapmatch, 0, sizeof(sapmatch));
			if(atoi(SSAPExclude) == 1)
			{
				if((SSAP[0] != '\0') && (atoi(SSAP) != -1))
				{
					strcpy(ethertypematch, "-p LENGTH");
					sprintf(sapmatch, "--802_3-sap ! %s", SSAP);
				}
			}
			else
			{
				if((SSAP[0] != '\0') && (atoi(SSAP) != -1))
				{
					strcpy(ethertypematch, "-p LENGTH");
					sprintf(sapmatch, "--802_3-sap %s", SSAP);
				}
			}
					
			char tcpackmatch[64] = {0};
			if(atoi(TCPACKExclude) == 1)
			{
				if(atoi(TCPACK) == 1)
				{
					sprintf(tcpackmatch, "! --tcp-flags ALL ACK");
					strcpy(Protocolmatch, "-p tcp");
				}
			}
			else
			{
				if(atoi(TCPACK) == 1)
				{
					sprintf(tcpackmatch, "--tcp-flags ALL ACK");
					strcpy(Protocolmatch, "-p tcp");
				}
			}

			char dscpmatch[64] = {0};
			if(atoi(DSCPExclude) == 1)
			{
				if((DSCPCheck[0] != '\0') && (atoi(DSCPCheck) != -1))
					sprintf(dscpmatch, "-m dscp ! --dscp %s", DSCPCheck);
			}
			else
			{
				if((DSCPCheck[0] != '\0') && (atoi(DSCPCheck) != -1))
					sprintf(dscpmatch, "-m dscp --dscp %s", DSCPCheck);
			}

			char etherpriomatch[64] = {0};
			memset(etherpriomatch, 0, sizeof(etherpriomatch));
			if(atoi(EthernetPriorityExclude) == 1)
			{
				if((EthernetPriorityCheck[0] != '\0') && (atoi(EthernetPriorityCheck) != -1))
				{
					strcpy(ethertypematch, "-p 0x8100");
					sprintf(etherpriomatch, "-vlan-prio ! %s", EthernetPriorityCheck);
					memset(sapmatch, 0, sizeof(sapmatch));
				}
			}
			else
			{
				if((EthernetPriorityCheck[0] != '\0') && (atoi(EthernetPriorityCheck) != -1))
				{
					strcpy(ethertypematch, "-p 0x8100");
					sprintf(etherpriomatch, "-vlan-prio %s", EthernetPriorityCheck);
					memset(sapmatch, 0, sizeof(sapmatch));
				}
			}

			char vlanidmatch[64] = {0};
			memset(vlanidmatch, 0, sizeof(vlanidmatch));
			if(atoi(VLANIDExclude) == 1)
			{
				if((VLANIDCheck[0] != '\0') && (atoi(VLANIDCheck) != -1))
				{
					strcpy(ethertypematch, "-p 0x8100");
					sprintf(vlanidmatch, "--vlan-id ! %s", VLANIDCheck);
					memset(sapmatch, 0, sizeof(sapmatch));
				}
			}
			else
			{
				if((VLANIDCheck[0] != '\0') && (atoi(VLANIDCheck) != -1))
				{
					strcpy(ethertypematch, "-p 0x8100");
					sprintf(vlanidmatch, "--vlan-id %s", VLANIDCheck);
					memset(sapmatch, 0, sizeof(sapmatch));
				}
			}

			char iplengthmatch[64] = {0};
			if(atoi(IPLengthExclude) == 1)
			{
				if((IPLengthMin[0] != '\0') && (IPLengthMax[0] == '\0'))
					sprintf(iplengthmatch, "-m length ! --length  %s", IPLengthMin);
				if((IPLengthMin[0] != '\0') && (IPLengthMax[0] != '\0'))
					sprintf(iplengthmatch, "-m length ! --length  %s:%s", IPLengthMin, IPLengthMax);
			}
			else
			{
				if((IPLengthMin[0] != '\0') && (IPLengthMax[0] == '\0'))
					sprintf(iplengthmatch, "-m length --length %s", IPLengthMin);
				if((IPLengthMin[0] != '\0') && (IPLengthMax[0] != '\0'))
					sprintf(iplengthmatch, "-m length --length %s:%s", IPLengthMin, IPLengthMax);
			}
			
			if(atoi(TrafficClass) < 0)
			{
				char *index = strrchr(App, '.');
				char Alias[256] = {0};
				char name[256] = {0};
				char ProtocolIdentifier[256] = {0};
				char DefaultTrafficClass[256] = {0};
				char DefaultDSCPMark[256] = {0};
				char *p = NULL;
				
				if (index != NULL)
				{
					getvalue_mapfile_byinstance("/oneagent/conf/QoSAppMap.mapping", Alias, atoi(index+1));
					p = strchr(Alias, '_');
					if(p != NULL)
					{
						sprintf(name, "trconf.Device_QoS_App_%d.ProtocolIdentifier", atoi(p+1));		
						printf("name[%s]\n", name);
						do_uci_get(name, ProtocolIdentifier);
						printf("value[%s]\n", ProtocolIdentifier);
						if(strcasestr(ProtocolIdentifier, "sip") != NULL)
						{
							strcpy(destportmatch, "--dport 6060");
							strcpy(Protocolmatch, "-p tcp");
						}
						else if(strcasestr(ProtocolIdentifier, "h.323") != NULL)
						{
							strcpy(destportmatch, "--dport 1720");
							strcpy(Protocolmatch, "-p tcp");
						}
						else if(strcasestr(ProtocolIdentifier, "h.248") != NULL)
						{
							strcpy(destportmatch, "--dport 2944");
							strcpy(Protocolmatch, "-p tcp");
						}
						else if(strcasestr(ProtocolIdentifier, "mgcp") != NULL)
						{
							strcpy(destportmatch, "--dport 2727");
							strcpy(Protocolmatch, "-p tcp");
						}
						sprintf(name, "trconf.Device_QoS_App_%d.DefaultTrafficClass", atoi(p+1));		
						do_uci_get(name, DefaultTrafficClass);
						printf("name[%s]\n", name);
						printf("value[%s]\n", DefaultTrafficClass);
						sprintf(name, "trconf.Device_QoS_App_%d.DefaultDSCPMark", atoi(p+1));		
						do_uci_get(name, DefaultDSCPMark);
						printf("name[%s]\n", name);
						printf("value[%s]\n", DefaultDSCPMark);
						strcpy(TrafficClass, DefaultTrafficClass);
						strcpy(DSCPMark, DefaultDSCPMark);
					}
				}
			}

			if(strcmp(cmd, "start") == 0)
			{
				if((srcmacmatch[0] != '\0') || (destmacmatch[0] != '\0') || (ethertypematch[0] != '\0') || (sapmatch[0] != '\0') || (vlanidmatch[0] != '\0') || (etherpriomatch[0] != '\0'))
				{
					sprintf(ebtablescommand, "ebtables -A FORWARD %s %s %s %s %s %s -j mark --mark-set %s", ethertypematch, 
						srcmacmatch, destmacmatch, sapmatch, vlanidmatch, etherpriomatch, Order);	
					printf("ebtablescommand: %s\n", ebtablescommand);
					system(ebtablescommand);
					sprintf(iptablescommand, "iptables -t mangle -A FORWARD %s %s %s %s %s %s %s %s %s %s -j CLASSIFY --set-class %s:0", intefacematch, destipmatch, srcipmatch, Protocolmatch,
							destportmatch, srcportmatch, tcpackmatch, dscpmatch, markmatch, iplengthmatch, TrafficClass);
					printf("iptablescommand: %s\n", iptablescommand);
					system(iptablescommand);
					sprintf(iptablescommand, "iptables -t mangle -A FORWARD %s %s %s %s %s %s %s %s %s %s -j DSCP --set-dscp %s", intefacematch, destipmatch, srcipmatch, Protocolmatch,
							destportmatch, srcportmatch, tcpackmatch, dscpmatch, markmatch, iplengthmatch, DSCPMark);
					printf("iptablescommand: %s\n", iptablescommand);
					system(iptablescommand);
				}
				else
				{
					sprintf(iptablescommand, "iptables -t mangle -A FORWARD %s %s %s %s %s %s %s %s %s -j CLASSIFY --set-class %s:0", intefacematch, destipmatch, srcipmatch, Protocolmatch,
							destportmatch, srcportmatch, tcpackmatch, dscpmatch, iplengthmatch, TrafficClass);
					printf("iptablescommand: %s\n", iptablescommand);
					system(iptablescommand);
					sprintf(iptablescommand, "iptables -t mangle -A FORWARD %s %s %s %s %s %s %s %s %s -j DSCP --set-dscp %s", intefacematch, destipmatch, srcipmatch, Protocolmatch,
							destportmatch, srcportmatch, tcpackmatch, dscpmatch, iplengthmatch, DSCPMark);
					printf("iptablescommand: %s\n", iptablescommand);
					system(iptablescommand);
				}
			}
			else
			{
				if((srcmacmatch[0] != '\0') || (destmacmatch[0] != '\0') || (ethertypematch[0] != '\0') || (sapmatch[0] != '\0') || (vlanidmatch[0] != '\0') || (etherpriomatch[0] != '\0'))
				{
					sprintf(ebtablescommand, "ebtables -D FORWARD %s %s %s %s %s %s -j mark --mark-set %s", ethertypematch, 
						srcmacmatch, destmacmatch, sapmatch, vlanidmatch, etherpriomatch, Order);	
					printf("ebtablescommand: %s\n", ebtablescommand);
					system(ebtablescommand);
					sprintf(iptablescommand, "iptables -t mangle -D FORWARD %s %s %s %s %s %s %s %s %s %s -j CLASSIFY --set-class %s:0", intefacematch, destipmatch, srcipmatch, Protocolmatch,
							destportmatch, srcportmatch, tcpackmatch, dscpmatch, markmatch, iplengthmatch, TrafficClass);
					printf("iptablescommand: %s\n", iptablescommand);
					system(iptablescommand);
					sprintf(iptablescommand, "iptables -t mangle -D FORWARD %s %s %s %s %s %s %s %s %s %s -j DSCP --set-dscp %s", intefacematch, destipmatch, srcipmatch, Protocolmatch,
							destportmatch, srcportmatch, tcpackmatch, dscpmatch, markmatch, iplengthmatch, DSCPMark);
					printf("iptablescommand: %s\n", iptablescommand);
					system(iptablescommand);
				}
				else
				{
					sprintf(iptablescommand, "iptables -t mangle -D FORWARD %s %s %s %s %s %s %s %s %s -j CLASSIFY --set-class %s:0", intefacematch, destipmatch, srcipmatch, Protocolmatch,
							destportmatch, srcportmatch, tcpackmatch, dscpmatch, iplengthmatch, TrafficClass);
					printf("iptablescommand: %s\n", iptablescommand);
					system(iptablescommand);
					sprintf(iptablescommand, "iptables -t mangle -D FORWARD %s %s %s %s %s %s %s %s %s -j DSCP --set-dscp %s", intefacematch, destipmatch, srcipmatch, Protocolmatch,
							destportmatch, srcportmatch, tcpackmatch, dscpmatch, iplengthmatch, DSCPMark);
					printf("iptablescommand: %s\n", iptablescommand);
					system(iptablescommand);
				}
			}
		}
	}
}

void rungre(char *cmd)
{
	int ret = 0;
	int i = 0;
	int j = 0;
	char RemoteEndpoints[256] = {0};
	char DefaultDSCPMark[256] = {0};
	char UseChecksum[256] = {0};
	char Checksum[256] = {0};
	char KeyIdentifierGenerationPolicy[256] = {0};
	char KeyIdentifier[256] = {0};
	char Key[256] = {0};
	char UseSequenceNumber[256] = {0};
	char SequenceNumber[256] = {0};
	char value[64] = {0};
	char name[256] = {0};
	char *p = NULL;
	char *q = NULL;
	char command[512] = {0};
	char wanproto[32] = {0};
	char waninterface[32] = {0};
	char wanip[32] = {0};
	char remoteip[32] = {0};
	a_infinfo wanStatus;
	long int time = 0;
	char tmp[32] = {0};
	char waninf[32] = {0};

	getEthInterfaceName("wan", waninf);
	do_uci_get("network.wan.proto", wanproto);
	if(strcmp(wanproto, "pppoe") == 0)
	{
		strcpy(waninterface, "pppoe-wan");
	}
	else
	{
		strcpy(waninterface, waninf);
	}

	memset(&wanStatus, 0, sizeof(wanStatus));
	getInterfaceInfo("wan", &wanStatus);
	strcpy(wanip, wanStatus.ipv4_address);

	do_uci_get("trconf.Device_GRE_Tunnel_template.RemoteEndpoints", RemoteEndpoints);
	memset(DefaultDSCPMark,0,sizeof(DefaultDSCPMark));
	do_uci_get("trconf.Device_GRE_Tunnel_template.DefaultDSCPMark", DefaultDSCPMark);

	if(RemoteEndpoints[0] != '\0' && RemoteEndpoints[0] != ' ')
	{
		q = RemoteEndpoints;
		while((p = strchr(q, ',')) != NULL)
		{
			sprintf(value,"grenet%d", i);
			i++;

			
			memset(UseChecksum,0,sizeof(UseChecksum));
			memset(Checksum,0,sizeof(Checksum));
			sprintf(name,"trconf.Device_GRE_Tunnel_Interface_%d.UseChecksum", i);
			do_uci_get(name, UseChecksum);
			if(atoi(UseChecksum) == 1)
			{
				strcpy(Checksum, "csum");
			}
			memset(KeyIdentifierGenerationPolicy,0,sizeof(KeyIdentifierGenerationPolicy));
			memset(KeyIdentifier,0,sizeof(KeyIdentifier));
			memset(Key,0,sizeof(Key));
			sprintf(name,"trconf.Device_GRE_Tunnel_Interface_%d.KeyIdentifierGenerationPolicy", i);
			do_uci_get(name, KeyIdentifierGenerationPolicy);
			sprintf(name,"trconf.Device_GRE_Tunnel_Interface_%d.KeyIdentifier", i);
			do_uci_get(name, KeyIdentifier);
			if(strcasecmp(KeyIdentifierGenerationPolicy, "Provisioned") == 0)
			{
				sprintf(Key, "key %s", KeyIdentifier);
			}
			memset(UseSequenceNumber,0,sizeof(UseSequenceNumber));
			memset(SequenceNumber,0,sizeof(SequenceNumber));
			sprintf(name,"trconf.Device_GRE_Tunnel_Interface_%d.UseSequenceNumber", i);
			do_uci_get(name, UseSequenceNumber);
			if(atoi(UseSequenceNumber) == 1)
			{
				strcpy(SequenceNumber, "seq");
			}

			*p = '\0';
			strcpy(remoteip, q);
			if(strcmp(cmd, "start") == 0)
			{
				sprintf(command, "ip tunnel add %s mode gre remote %s local %s %s %s %s ttl 255 dev %s", value, remoteip, wanip, SequenceNumber, Key, Checksum, waninterface);
				printf("command: %s\n", command);
				system(command);
				sprintf(command, "ifconfig %s mtu 1476 up", value);
				system(command);
				printf("command: %s\n", command);
			}
			else
			{
				sprintf(command, "ip tunnel del %s mode gre remote %s local %s %s %s %s ttl 255 dev %s", value, remoteip, wanip, SequenceNumber, Key, Checksum, waninterface);
				printf("command: %s\n", command);
				system(command);
			}
			time = getLocalTimeWithSeconds();
			sprintf(tmp, "%ld", time);
			sprintf(name,"trconf.Device_GRE_Tunnel_Interface_%d.uptime", i);
			do_uci_set(name, tmp);
			system(command);
			q = p + 1;			
		}
		sprintf(value,"grenet%d", i);
		i++;
		strcpy(remoteip, q);
		if(strcmp(cmd, "start") == 0)
		{
			sprintf(command, "ip tunnel add %s mode gre remote %s local %s %s %s %s ttl 255 dev %s", value, remoteip, wanip, SequenceNumber, Key, Checksum, waninterface);
			printf("command: %s\n", command);
			system(command);
			sprintf(command, "ifconfig %s mtu 1476 up", value);
			printf("command: %s\n", command);
			system(command);
		}
		else
		{
			sprintf(command, "ip tunnel del %s mode gre remote %s local %s %s %s %s ttl 255 dev %s", value, remoteip, wanip, SequenceNumber, Key, Checksum, waninterface);
			printf("command: %s\n", command);
			system(command);
		}
		time = getLocalTimeWithSeconds();
		sprintf(tmp, "%ld", time);
		sprintf(name,"trconf.Device_GRE_Tunnel_Interface_%d.uptime", i);
		do_uci_set(name, tmp);
		system(command);
	}
}
int main(int argc, char *argv[])
{
	int ret=0;
	if(argc == 3)
	{
		if(!strcmp(argv[1],"qos"))
		{
			runqos(argv[2]);
		}
		else if(!strcmp(argv[1],"gre"))
		{
			rungre(argv[2]);
		}
		else
		{
			ret = -1;
		}
	}
	else
	{
			ret = -1;
	}
	return ret;
}
