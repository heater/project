/* Writed by ASKEY SH*/

#ifndef __HEADER_APPS_H__
#define __HEADER_APPS_H__

#define UPNP_VERSION_STRING "UPnP/1.1"
#define UPNP_VERSION	"20150721"
#define USE_IFACEWATCHER 1
#define USE_NETFILTER 1
#define SUPPORT_REMOTEHOST
#define MINIUPNPD_VERSION "1.8"

#define OS_NAME		"OpenWRT"
#define OS_VERSION	"OpenWRT/OpenWrt/Attitude_Adjustment__r40331_"
#define OS_URL		"http://www.openwrt.org/"

#define MINIUPNPD_SERVER_STRING	OS_VERSION " " UPNP_VERSION_STRING " MiniUPnPd/" MINIUPNPD_VERSION

/* Macro constant definitions. */
#define DYNDNS_UPT_URL "http://[USERNAME]:[PASSWORD]@members.dyndns.org/nic/update?hostname=[DOMAIN]&myip=[IP]"
#define DYNDNS_UPT_URL_WILDCARD "http://[USERNAME]:[PASSWORD]@members.dyndns.org/nic/update?wildcard=ON&hostname=[DOMAIN]&myip=[IP]"

#define CUSTOM_DYNDNS_UPT_URL "http://[USERNAME]:[PASSWORD]@members.dyndns.org/nic/update?system=custom&hostname=[DOMAIN]&myip=[IP]"
#define CUSTOM_DYNDNS_UPT_URL_WILDCARD "http://[USERNAME]:[PASSWORD]@members.dyndns.org/nic/update?wildcard=ON&system=custom&hostname=[DOMAIN]&myip=[IP]"

#define STATIC_DYNDNS_UPT_URL "http://[USERNAME]:[PASSWORD]@members.dyndns.org/nic/update?system=statdns&hostname=[DOMAIN]&myip=[IP]"
#define STATIC_DYNDNS_UPT_URL_WILDCARD "http://[USERNAME]:[PASSWORD]@members.dyndns.org/nic/update?wildcard=ON&system=statdns&hostname=[DOMAIN]&myip=[IP]"

#define ZONEEDIT_UPT_URL "http://[USERNAME]:[PASSWORD]@dynamic.zoneedit.com/auth/dynamic.html?host=[DOMAIN]&dnsto=[IP]"
#define ZONEEDIT_UPT_URL_WILDCARD "http://[USERNAME]:[PASSWORD]@dynamic.zoneedit.com/auth/dynamic.html?wildcard=ON&host=[DOMAIN]&dnsto=[IP]"

#define DNSOMATIC_UPT_URL "http://[USERNAME]:[PASSWORD]@updates.dnsomatic.com/nic/update?hostname=[DOMAIN]&myip=[IP]"
#define DNSOMATIC_UPT_URL_WILDCARD "http://[USERNAME]:[PASSWORD]@updates.dnsomatic.com/nic/update?wildcard=ON&hostname=[DOMAIN]&myip=[IP]" 

#define NO_IP_UPT_URL "http://[USERNAME]:[PASSWORD]@dynupdate.no-ip.com/nic/update?hostname=[DOMAIN]&myip=[IP]"
#define NO_IP_UPT_URL_WILDCARD "http://[USERNAME]:[PASSWORD]@dynupdate.no-ip.com/nic/update?wildcard=ON&hostname=[DOMAIN]&myip=[IP]" 

#define TUNNELBROKER_UPT_URL "http://[USERNAME]:[PASSWORD]@dyn.dns.he.net/nic/update?hostname=[DOMAIN]&myip=[IP]"

#define WINCO_DDNS_UPT_URL "http://[DOMAIN]:[PASSWORD]@members.ddns.com.br/nic/update?hostname=[DOMAIN]&myip=[IP]"
#define WINCO_DDNS_UPT_URL_WILDCARD "http://[DOMAIN]:[PASSWORD]@members.ddns.com.br/nic/update?wildcard=ON&hostname=[DOMAIN]&myip=[IP]"

#define DDNS_STATUS_DAT_FILE "/var/run/ddns/myddns_ipv4.dat"
#define DDNS_STATUS_ERR_FILE "/var/run/ddns/myddns_ipv4.err"
#define DDNS_STATUS_UPT_FILE "/var/run/ddns/myddns_ipv4.update"
/* Type definitions. */

/*tunnelbroker.net -> dns.he.net*/
static char *ddns_list[4] = {"noip2", "dyndns", "qdns", "dtdns"};

/*By now we just support two kind of the ddns server dyndns.com and no-ip.com*/
#define DDNSSERVERNUM 4
static char *ddns_server[DDNSSERVERNUM]={"WWW.NO-IP.COM", "WWW.DYNDNS.COM", "WWW.3322.ORG", "WWW.DTDNS.COM"};

#define NET_FW_PORTFWD_NUM 			"firewall_nat.port_fwd.element_count"

#define IP_LAN_INSTANCE_NUM 4
#define IP_LAN_START_INSTANCE_NUM 200
#define IP_LAN_END_INSTANCE_NUM 203
#define IP_WAN_INSTANCE_NUM 1
#define IP_WAN_INSTANCE_INDEX 300
#define IP_WAN_INTERFACE_PATH "Device.IP.Interface.300"
#define ETHERNET_LAN_INSTANCE_INDEX 5
#define ETHERNET_LAN_INTERFACE_PATH "Device.Ethernet.Interface.5"
#define ETHERNET_LAN_LINK_PATH "Device.Ethernet.Link.5"
#define ETHERNET_WAN_INSTANCE_INDEX 1
#define ETHERNET_WAN_INTERFACE_PATH "Device.Ethernet.Interface.1"
#define ETHERNET_WAN_LINK_PATH "Device.Ethernet.Link.1"

#define MAX_QOS_ELEMS 16 
#define DHCPV4_SERVER_POOL_INSTANCE_NUM 4

struct echo_plus_st
{
	uint32_t test_gen_sn;
	uint32_t test_resp_sn;
	uint32_t recv_ts;
	uint32_t reply_ts;
	uint32_t fail_count;
	char data[0];
};

typedef struct a_interfaceinfo{
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

typedef struct a_dnsserverinfo{
    int statusdns1;
	int statusdns2;
    char type[32];
    char device[32];
    char dns1[128];
	char dns2[128];
}a_dnsinfo;

typedef struct a_wlan_associated_dev{
    char mac[32];
	char inf[32];
    char pathname[128];
}a_wlanAssociatedDev;

typedef struct a_dhcpv4_staticip_info{
    char mac[32];
	char ip[32];
}a_Dhcpv4StaticIpInfo;

typedef struct a_temperaturesensor_info{
    char Enable[32];
	char Status[32];
	char Reset[32];
	char ResetTime[64];
	char Name[32];
	char Value[32];
	char LastUpdate[64];
	char MinValue[32];
	char MinTime[64];
	char MaxValue[32];
	char MaxTime[64];
	char LowAlarmValue[32];
	char LowAlarmTime[64];
	char HighAlarmValue[32];
	char PollingInterval[32];
	char HighAlarmTime[64];
}a_TemperatureSensorInfo;

typedef struct a_wifimapping_info{
	char *uci_path;
	char *wlaninf;
	int num;
}a_WifimappingInfo;

typedef struct a_wifiradiomapping_info{
	int type;
	int num;
	int instance;
}a_WifiradiomappingInfo;

typedef struct a_informpara_info{
	int Enable;
	char *ParameterName;
	char *EventList;
	int num;
}a_infomparaInfo;

typedef struct a_fileinfo{
    char name[128];
    char value[256];
}a_Fileinfo;

typedef struct a_lanmapping_info{
	int ipv6;
	char *uci_path;
	char *ubsinf;
	char *laninf;
	int num;
}a_LanmappingInfo;

#define WIFI5G_RADIO_INSTANCE_NUM 10100
#define WIFI5G_START_INSTANCE_NUM 10101
#define WIFI5G_END_INSTANCE_NUM 10108
#define WIFI24G_RADIO_INSTANCE_NUM 10000
#define WIFI24G_START_INSTANCE_NUM 10001
#define WIFI24G_END_INSTANCE_NUM 10008
#define WIFI_MAX_INSTANCE_NUM 16
#define INFORMPARA_MAX_INSTANCE_NUM 8
#define WIFI_RADIO_24G_PATH "Device.WiFi.Radio.10000"
#define WIFI_RADIO_5G_PATH "Device.WiFi.Radio.10100"

extern void getLanInterfaceNameWithInstanceNum(char *p, char *buff);
extern void getLanInterfaceNameWithInstanceNum2(int p, char *buff);
extern void getLanUbsInterfaceNameWithInstanceNum(char *p, char *buff);
extern void getLanUbsInterfaceNameWithInstanceNum2(int p, char *buff);
extern void getLanUciPathWithInstanceNum(char *p, char *buff);
extern int getLanIPv6CapableWithInstanceNum(char *p);
extern int getLanIPInstanceNum(char *p);
extern int getLanIPInstanceNumWithInterfaceName(char *inf);
extern int getinformparaEnbl(char *p, char *buff);
extern int getinformparaName(char *p, char *buff);
extern int getinformparaEvent(char *p, char *buff);
extern void get_time(char *name);
extern int udpecho(char *host, char *port, int num, int timeout, int size, int interval);
extern int upnpdevice();
extern int upnpservice();
extern char *parseTemplate(char *path, char *option);
extern void toSaveMapFile(char *mapfile, char *instance, char * value);
extern void getMfcInfo(char * name, char *value);
extern void getMfcInfo2(char * name, char *value);
extern void getProcessStatus(char *pid, char *value, char *string);
extern void getDevStatus(char *inf, char *key, char *value);
extern int get_DHCPv4_Server_Pool_Client_num(int index);
extern void get_DHCPv4_Server_Pool_Client_info(char *key, char *value, char *string);
extern void get_DHCPv4_Server_Pool_Client_entry_path(char *key, char *inf, char *value);
extern void get_Layer3Interface_path(char *inf, char *value);
extern void get_Hosts_Host_info(char *key, char *value, char *string);
extern void get_DHCPv4_Server_Pool_1_StaticAddress_info(char *key, char *value, char *string);
extern void set_DHCPv4_Server_Pool_1_StaticAddress_info(char *key, char *value, char *string);
extern void get_DHCPv4_Server_Pool_1_ReservedAddresses_list(char *value);
extern void getInterfaceInfo(char *inf, a_infinfo *wandeviceinfo);
extern void getLanLowerLayerInterface(char *inf, char *inf2);
extern int checkEthWanUpDown();
extern int checkDhcpServerOnOff(char *index);
extern int getWanMode(char *mode);
extern void getWanHigherLayerInterface (char *inf);
extern void getDnsServerInfo(a_dnsinfo *dnsinfo);
extern void getNetmask(char *inf, char *mask);
extern void getNetMtu(char *inf, char *mtu);
extern void getInfaceMac(char *inf, char *mac);
extern void getInfaceWanMac(char *mac);
extern void getInfaceName(char *inf, char *mac);
extern void getDeviceUpTime(char * finename, char * time);
extern void getFirewallLastChaneTime(char *time);
extern void getFirewallChainNumberOfEntries(char *value);
extern void getInterfaceLastChangeTime(char * time);
extern void getCpuUsage(char * value);
extern int get_all_process_num();
extern void get_Wlan_AssociatedDeviceInfo(a_wlanAssociatedDev *dev);
extern void getNextHopGwMac(char *mac);
extern void get_USBHostsDeviceInfo(char *busnum, char *value, char *key);
extern void get_USBHostsDeviceInfo2(char *busnum, char *value, char *key);
extern void get_ipv6_routing_info(char *key, char *value, char *string);
extern void getNeighRetransTimer(char *inf, char *value);
extern void getRtrSolicitationInterval(char *inf, char *value);
extern void getMaxRtrSolicitations(char *inf, char *value);
extern void getRouterAdvertisementOptionValue(char *value, char *type);
extern void get_Device_DHCPv6_Server_Pool_1_Client_address_by_mac(char *mac, char *value);
extern void check_Device_DHCP_Server_Pool_Client_address_active(char *family, char *ip, char *value);
extern void getDhcpv6IANAPreferredLifetime(char *value);
extern void getDhcpv6IANAValidLifetime(char *value);
extern void getCoreChipTemperatureStatus(int sector, a_TemperatureSensorInfo *temperatureSensorInfo);
extern void getWifiChipTemperatureStatus(int sector, a_TemperatureSensorInfo *temperatureSensorInfo);
extern int get_Device_DHCPv4_Server_Option_value(char *key, char *value);
extern long int getLocalTimeWithSeconds();
extern void getNSLookupDiagnosticsResultValue(int number, char *key, char *value);
extern int getSSIDuciConfig(char *p, char *buff, char *option);
extern int getSSIDuciConfig2(char *p, char *buff, char *option);
extern int getWiFiRadioUciNum(char *p);
extern int getWiFiRadioType(char *p);
extern int getWiFiLowerLayersPath(int *p, char *buff);
extern void getWiFiInterfaceNameWithInstanceNum(char *p, char *buff);
extern void getWiFiInterfaceNameWithInstanceNum2(int num, char *buff);
extern int getWiFiInstanceNumWithInterfaceName(char *inf);
extern int rewrite_portmaping_entry(char *option, char *value, char *ExternalPort);
extern int setwanhttpsacs(char *mischttpsport, char *lanip, char* lanport);
extern int setwanhttpacs(char *mischttpsport, char *lanip, char* lanport);
extern int disablewanacs();
extern int getlanip(char* val);
extern int doRemoteAccess(int enable);
extern int setRemoteAccess(int enable);
extern void setRemoteAccess2();
extern void set_RemoteAccess();
extern int get_ssdk_mib_statistics(int index, char *name);
extern void getSSIStats(char *p, char *key, char *value);
extern int _get_endporint_5g_enable();
extern int _get_endporint_24g_enable();
extern int _get_endporint_5g_profile_status(char *value);
extern int _get_endporint_24g_profile_status(char *value);
extern int getRouterIPv4Number();
extern void getRouterIPv4Option(char *key, char *value, char *option);
extern int isStaticRoute(char *key);
extern int run_portmaping_entry();
extern int getPortmappingEntry(char *option, char *value, char *key);
extern void restartTR069CWMP();
extern void getMAPTInfo(char *value, char *key);
extern int getDHCPv6ClientLinkStatus();
extern int getDHCPv6ServerPoolStatus();
extern int getIPv6Enable();
extern int isValidIP(char *buf);
extern int isValidIP2(char *buf);
extern int isValidNetmask(char *buf);
extern int isValidMac(char *buf);
extern int get_Device_DHCPv4_Server_Option_num();
extern int get_NeighboringWiFi_info();
extern int set_dhcp_option_force();
extern void getManagementServerManageableDeviceInfo(char *filename, char *key, char *value);
extern void changedSecondsToDateTime(long int seconds, char *datetype);
extern int changedDateTimeToSeconds(char *datetype);
extern int get_DynamicDNS_Server(char *value);
extern int set_DynamicDNS_Server(char *value);
extern void set_udpecho();
extern void doDelayReboot();
extern void doScheduleReboot();
extern void getDHCPServerLeaseTime(char *value);
extern int parse_captive_portal_url(char *url, char *ssl, char *hostname, char *path);
extern int getDeploymentUnitNumberOfEntries();
extern int getExecutionUnitNumberOfEntries();
extern void getDiskSpace(char * value, char * key);
extern void getMemoryInfo(char *value, char *key);
extern void getEthInterfaceName(char *in, char *inf);
extern void startDownload();
extern void TrDownload();
extern void startUpload();
extern void TrUpload();
extern void startUDPEcho();
extern void startIPPing();
extern void startTraceRoute();
extern void startServerSelection();
extern void doSSHFuncs(int in);
extern int hexToStr(char *hex, char *ch);
extern int strToHex(char *ch, char *hex);
extern unsigned char *sha1_encode(unsigned char *src, unsigned char *value);
extern void doRipFuncs();
extern void runRipFuncs();
extern int doBandSteeringFuncs();
extern int pem_to_x509(int index, X509 **caCert);
extern void write_vendor_file(int index);
extern time_t ASN1_UTCTIME_get(const ASN1_UTCTIME *s);
extern void ASN1_UTCTIME_get1(const ASN1_UTCTIME *s, char *datetype);
extern void doDetectFuncs();
extern void addUciTopNode(char *topnode, char *name);
extern void doIPInterfaceReset();
extern int writeToNonvolatileCertFile(int index, char *value);
extern int readFromNonvolatileFlashFile(char *name, char *value);
extern int writeToNonvolatileFlashFile(char *name, char *value);
extern int validate_args_boolean( char *value);
extern int getQosQueueEntry(char *Alias);
extern int getQosClassificationEntry(char *Order);
extern void doQoSClassification();
extern void doQoSQueue();
extern void doIPv6Restart();
extern void IPv6Restart();
extern void doRestartNetwork();
extern void RestartNetwork();
extern void doRestartLanNetwork();
extern void RestartLanNetwork();
extern void doRadvdRestart();
extern void RadvdRestart();
int checkPortUsing(int port);
extern void executeCMD(char *cmd, char *result);
extern int checkPortUsing(int port);
extern void runWifiReload();
extern void runSbinWifi();
extern void runPortmapping();
extern void doDhcprestart();
extern void Dhcprestart();
#endif

