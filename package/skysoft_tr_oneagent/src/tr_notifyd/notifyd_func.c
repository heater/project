

#include "tr_notifyd.h"

typedef struct obj_if_tab_t {
	char *object;
	char *interface;
} obj_if_tab;

obj_if_tab obj_if_map_tab[] = {
	{"Device.WiFi.AccessPoint.10101.", "ath0"},
	{"Device.WiFi.AccessPoint.10102.", "ath01"},
	{"Device.WiFi.AccessPoint.10103.", "ath02"},
	{"Device.WiFi.AccessPoint.10104.", "ath03"},
	{"Device.WiFi.AccessPoint.10105.", "ath04"},
	{"Device.WiFi.AccessPoint.10106.", "mesh0"},
	{"Device.WiFi.AccessPoint.10107.", "ath05"},
	{"Device.WiFi.AccessPoint.10108.", "ath06"},
	{"Device.WiFi.AccessPoint.10001.", "ath1"},
	{"Device.WiFi.AccessPoint.10002.", "ath11"},
	{"Device.WiFi.AccessPoint.10003.", "ath12"},
	{"Device.WiFi.AccessPoint.10004.", "ath13"},
	{"Device.WiFi.AccessPoint.10005.", "ath14"},
	{"Device.WiFi.AccessPoint.10006.", "mesh1"},
	{"Device.WiFi.AccessPoint.10007.", "ath15"},
	{"Device.WiFi.AccessPoint.10008.", "ath16"},
	{NULL, NULL}
};

// Device.ManagementServer.ManageableDeviceNumberOfEntries
int host_numa = 0;
int host_numb = 0;
int *p_host_num = NULL;
char hostsa[MAX_HOST_NUM][MAX_ARP_OPTION_LEN]={{0}};
char hostsb[MAX_HOST_NUM][MAX_ARP_OPTION_LEN]={{0}};
char (*p_host)[MAX_ARP_OPTION_LEN] = NULL;
int sta_numa = 0;
int sta_numb = 0;
int *p_sta_num = NULL;
char stasa[MAX_STA_NUM][MAX_STA_OPTION_LEN]={{0}};
char stasb[MAX_STA_NUM][MAX_STA_OPTION_LEN]={{0}};
char (*p_sta)[MAX_STA_OPTION_LEN] = NULL;
int device_numa = 0;
int device_numb = 0;
int *p_device_num = NULL;
char devicesa[MAX_DEVICE_NUM][MAX_DEVICE_OPTION_LEN]={{0}};
char devicesb[MAX_DEVICE_NUM][MAX_DEVICE_OPTION_LEN]={{0}};
char (*p_device)[MAX_DEVICE_OPTION_LEN] = NULL;
int port_numa = 0;
int port_numb = 0;
int *p_port_num = NULL;
char portsa[MAX_PORT_NUM][MAX_PORT_OPTION_LEN]={{0}};
char portsb[MAX_PORT_NUM][MAX_PORT_OPTION_LEN]={{0}};
char (*p_port)[MAX_PORT_OPTION_LEN] = NULL;
// Device.Routing.Router.{i}.IPv4ForwardingNumberOfEntries
// Device.NAT.PortMappingNumberOfEntries
// Device.DHCPv4.Client.{i}.DHCPStatus
char dhcp_status[32];
char dhcp_status_old[32];
int rsvip_numa = 0;
int rsvip_numb = 0;
int *p_rsvip_num = NULL;
char rsvipsa[MAX_RSVIP_NUM][MAX_RSVIP_OPTION_LEN]={{0}};
char rsvipsb[MAX_RSVIP_NUM][MAX_RSVIP_OPTION_LEN]={{0}};
char (*p_rsvip)[MAX_RSVIP_OPTION_LEN] = NULL;



// Device.WiFi.Radio.{i}.Channel

int read_host_list(char (*p_host)[MAX_ARP_OPTION_LEN], int *host_num)
{
	int ret = -1;
	char linebuffer[512] = {0};
	char ifname[10] = {0};
	int i = 0;
	FILE *fp = NULL;
	char arp_tbl[6][64] = {{0}};
	enum arp_tbl_options {
		IPADDR = 0,
		HWTYPE = 1,
		FLAGS = 2,
		HWADDR = 3,
		MASK = 4,
		DEVICE = 5
	};
	
#ifdef X86_DEBUG
	strcpy(ifname, "eth0");
#else
	strcpy(ifname, "br-lan");
#endif

	fp = fopen("/proc/net/arp", "r");
	if (fp == NULL) {
		printf("popen arp table failed!\n");
		return ret;
	} else {
		i = 0;
		while (fgets(linebuffer, 512, fp)){
			memset(arp_tbl[0], 0x00, sizeof(arp_tbl));
			sscanf(linebuffer, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", 
				arp_tbl[IPADDR], arp_tbl[HWTYPE], arp_tbl[FLAGS], 
				arp_tbl[HWADDR], arp_tbl[MASK], arp_tbl[DEVICE]);
			//printf("arp_tbl[IPADDR]=%s, arp_tbl[HWADDR]=%s, ifname=%s, arp_tbl[DEVICE]=%s", 
			//	arp_tbl[IPADDR], arp_tbl[HWADDR], ifname, arp_tbl[DEVICE]);
			if(strstr(arp_tbl[DEVICE], ifname)){
				strcpy(p_host[i], arp_tbl[HWADDR]);
				//printf("p_host[%d]=%s\n", i, p_host[i]);
				i++;
				*host_num = i;
			}
		}
		fclose(fp);
	}
	return ret;
}

/*check if the clients number is changed*/
void check_host_event()
{
#if 0
	if(p_host != hostsa)
		p_host = hostsa;
	else
		p_host = hostsb;
	
	if(p_host_num != &host_numa)
		p_host_num = &host_numa;
	else
		p_host_num = &host_numb;
	
	read_host_list(p_host, p_host_num);
	printf("host_numa=%d, host_numb=%d\n", host_numa, host_numb);
	if(host_numa != host_numb){
		send_tr_notify_static("Device.Hosts.HostNumberOfEntries");
	}
	else{
		// compare hostsa and hostsb to check if add one and delete another
		printf("host_numa == host_numb, no host add or delete!\n");
	}

#endif
	char cmdline[256] = {0};
	sprintf(cmdline,"%s","killall -10 netscan");		
	system(cmdline);
	
}

int read_wireless_client_list(char *athn, char (*p_sta)[MAX_STA_OPTION_LEN], int *sta_num)
{
	int ret = -1;
	char linebuffer[1024] = {0};
//	char ifname[10] = {0};
	int i = 0;
	FILE *fp = NULL;
	char sta_tbl[19][64] = {{0}};
	//char cmdline[128] = {0};
	enum sta_tbl_options {
		ADDR = 0,
		AID = 1,
		CHAN = 2,
		TXRATE = 3,
		RXRATE = 4,
		RSSI = 5,
		IDLE = 6,
		TXSEQ = 7,
		RXSEQ = 8,
		CAPS = 9,
		ACAPS = 10,
		ERP = 11,
		STATE = 12,
		MAXRATE = 13,
		HTCAPS = 14,
		ASSOCTIME = 15,
		IEs = 16,
		MODE = 17,
		PSMODE = 18
	};

#ifdef X86_DEBUG
	fp = popen("cat /home/bobzhang/os/kata/work/tr_notify_daemon/tr_notify_list/wlanconfig_ath1_list_sta.txt | grep \":\"", "r");
#else
	sprintf(cmdline, "wlanconfig %s list sta | grep \":\"", athn);
	fp = popen(cmdline, "r");
#endif
	if (fp == NULL) {
		printf("popen sta table failed!\n");
		return ret;
	} else {
		i = 0;
		while (fgets(linebuffer, 1024, fp)){
			memset(sta_tbl[0], 0x00, sizeof(sta_tbl));
			sscanf(linebuffer, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", 
				sta_tbl[ADDR], sta_tbl[AID], sta_tbl[CHAN], sta_tbl[TXRATE], sta_tbl[RXRATE], 
				sta_tbl[RSSI], sta_tbl[IDLE], sta_tbl[TXSEQ], sta_tbl[RXSEQ], sta_tbl[CAPS],
				sta_tbl[ACAPS], sta_tbl[ERP], sta_tbl[STATE], sta_tbl[MAXRATE], sta_tbl[HTCAPS],
				sta_tbl[ASSOCTIME], sta_tbl[IEs], sta_tbl[MODE], sta_tbl[PSMODE]);
			printf("sta_tbl[ADDR]=%s, sta_tbl[RSSI]=%s\n", sta_tbl[ADDR], sta_tbl[RSSI]);
			if(strcmp(sta_tbl[ADDR], "")){
				strcpy(p_sta[i], sta_tbl[ADDR]);
				printf("p_sta[%d]=%s\n", i, p_sta[i]);
				i++;
				*sta_num = i;
			}
		}
		pclose(fp);
	}
	return ret;
}

void check_wireless_client_event()
{
	if(p_sta != stasa)
		p_sta = stasa;
	else
		p_sta = stasb;
	
	if(p_sta_num != &sta_numa)
		p_sta_num = &sta_numa;
	else
		p_sta_num = &sta_numb;
	
	read_wireless_client_list("ath1", p_sta, p_sta_num);
	printf("sta_numa=%d, sta_numb=%d\n", sta_numa, sta_numb);
	if(sta_numa != sta_numb){
		send_tr_notify_dynamic("Device.WiFi.AccessPoint.i.AssociatedDeviceNumberOfEntries", "ath1");
	}
	else{
		// compare stasa and stasb to check if one join and another leave
		printf("sta_numa == sta_numb, no station join or leave!\n");
	}
}

int read_active_port_list(char (*p_port)[MAX_PORT_OPTION_LEN], int *port_num)
{
	int ret = 0;
	char linebuffer[1024] = {0};
//	char ifname[10] = {0};
	int i = 0;
	FILE *fp = NULL;
	char port_tbl[19][64] = {{0}};
	enum port_tbl_options {
		PROTO = 0,
		RECVQ = 1,
		SENDQ = 2,
		LOCALADDR = 3,
		FOREIGNADDR = 4,
		STATE = 5
	};

#ifdef X86_DEBUG
	fp = popen("cat /home/bobzhang/os/kata/work/tr_notify_daemon/tr_notify_list/netstat_ntl.txt", "r");
#else
	fp = popen("netstat -n -t -l | grep \":\"", "r");
#endif
	if (fp == NULL) {
		printf("popen read active port table failed!\n");
		ret = -1;
		return ret;
	} else {
		i = 0;
		while (fgets(linebuffer, 1024, fp)){
			memset(port_tbl[0], 0x00, sizeof(port_tbl));
			sscanf(linebuffer, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", 
				port_tbl[PROTO], port_tbl[RECVQ], port_tbl[SENDQ], 
				port_tbl[LOCALADDR], port_tbl[FOREIGNADDR], port_tbl[STATE]);
			printf("port_tbl[LOCALADDR]=%s, port_tbl[FOREIGNADDR]=%s\n", port_tbl[LOCALADDR], port_tbl[FOREIGNADDR]);
			if(strcmp(port_tbl[LOCALADDR], "")){
				strcpy(p_port[i], port_tbl[LOCALADDR]);
				printf("p_port[%d]=%s\n", i, p_port[i]);
				i++;
				*port_num = i;
			}
		}
		pclose(fp);
		return ret;
	}
}

void check_active_port_event()
{
	if(p_port != portsa)
		p_port = portsa;
	else
		p_port = portsb;
	
	if(p_port_num != &port_numa)
		p_port_num = &port_numa;
	else
		p_port_num = &port_numb;
	
	read_active_port_list(p_port, p_port_num);
	printf("port_numa=%d, port_numb=%d\n", port_numa, port_numb);
	if(port_numa != port_numb){
		send_tr_notify_static("Device.IP.ActivePortNumberOfEntries");
	}
	else{
		// compare portsa and portsb to check if add one and delete another
		printf("port_numa == port_numb, no active port add or delete!\n");
	}
}

void read_manageable_device_list(char (*p_device)[MAX_RSVIP_OPTION_LEN], int *device_num)
{
//	int ret = -1;
	char linebuffer[512] = {0};
//	char ifname[10] = {0};
	int i = 0;
	FILE *fp = NULL;
	char device_tbl[2][64] = {{0}};
	enum device_tbl_options {
		TIME = 0,
		MACADDR = 1,
		IPADDR = 2,
		HOSTNAME = 3,
		LAST = 4
	};

#ifdef X86_DEBUG
	fp = fopen("/home/bobzhang/os/kata/work/tr_notify_daemon/tr_notify_list/tmp_dhcp.leases.txt", "r");
#else
	fp = fopen("/tmp/dhcp.lease", "r");
#endif
	if (fp == NULL) {
		printf("fopen for read manageable device list failed!\n");
	} else {
		i = 0;
		while (fgets(linebuffer, 512, fp)){
			memset(device_tbl[0], 0x00, sizeof(device_tbl));
			sscanf(linebuffer, "%[^ ] %[^ ] %[^ ] %[^ ] %[^ ]", 
				device_tbl[TIME], device_tbl[MACADDR], device_tbl[IPADDR], 
				device_tbl[HOSTNAME], device_tbl[LAST]);
			if(strcmp(device_tbl[IPADDR], "")){
				printf("device_tbl[MACADDR],=%s, device_tbl[IPADDR]=%s\n", device_tbl[MACADDR], device_tbl[IPADDR] );
				strcpy(p_device[i], device_tbl[MACADDR]);
				printf("p_device[%d]=%s\n", i, p_device[i]);
				i++;
				*device_num = i;
			}
		}
		fclose(fp);
	}
}

void check_manageable_device_event()
{
	if(p_device != devicesa)
		p_device = devicesa;
	else
		p_device = devicesb;
	
	if(p_device_num != &device_numa)
		p_device_num = &device_numa;
	else
		p_device_num = &device_numb;
	
	read_manageable_device_list(p_device, p_device_num);
	printf("device_numa=%d, device_numb=%d\n", device_numa, device_numb);
	if(device_numa != device_numb){
		send_tr_notify_static("Device.ManagementServer.ManageableDeviceNumberOfEntries");
	}
	else{
		// compare devicesa and devicesb to check if add one and delete another
		printf("device_numa == device_numb, no device add or delete!\n");
	}
}

int  read_dhcp_client_status()
{
//	char buffer[32] = "";
	FILE *fp = NULL;
	int ret = -1;
#ifdef X86_DEBUG
	fp = popen("cat /home/bobzhang/os/kata/work/tr_notify_daemon/tr_notify_list/wan_up_dhcp.json", "r");
#else
	fp = popen("ubus call network.interface.wan status", "r");
#endif
	// need to judge proto and ipaddress
	if(fp==NULL){
		printf("popen the network wan status failed!\n");
		return ret;
	}
	/*there should do the right thing*/

	
	pclose(fp);
	return ret;
	
	
}

void check_dhcp_client_status_event()
{
	read_dhcp_client_status();
}

void read_reserved_ip_list(char (*p_rsvip)[MAX_RSVIP_OPTION_LEN], int *rsvip_num)
{
//	int ret = -1;
	char linebuffer[512] = {0};
//	char ifname[10] = {0};
	int i = 0;
	FILE *fp = NULL;
	char rsvip_tbl[2][64] = {{0}};
	enum rsvip_tbl_options {
		MACADDR = 0,
		IPADDR = 1
	};

#ifdef X86_DEBUG
	fp = fopen("/home/bobzhang/os/kata/work/tr_notify_daemon/tr_notify_list/etc_ethers.txt", "r");
#else
	fp = fopen("/etc/ethers", "r");
#endif
	if (fp == NULL) {
		printf("fopen for read reserved ip list failed!\n");
	} else {
		i = 0;
		while (fgets(linebuffer, 512, fp)){
			memset(rsvip_tbl[0], 0x00, sizeof(rsvip_tbl));
			sscanf(linebuffer, "%[^ ] %[^ ]", rsvip_tbl[MACADDR], rsvip_tbl[IPADDR]);
			if(strcmp(rsvip_tbl[IPADDR], "")){
				printf("rsvip_tbl[MACADDR],=%s, rsvip_tbl[IPADDR]=%s\n", rsvip_tbl[MACADDR], rsvip_tbl[IPADDR] );
				strcpy(p_rsvip[i], rsvip_tbl[MACADDR]);
				printf("p_rsvip[%d]=%s\n", i, p_rsvip[i]);
				i++;
				*rsvip_num = i;
			}
		}
		fclose(fp);
	}
}

void check_reserved_ip_event()
{
	if(p_rsvip != rsvipsa)
		p_rsvip = rsvipsa;
	else
		p_rsvip = rsvipsb;
	
	if(p_rsvip_num != &rsvip_numa)
		p_rsvip_num = &rsvip_numa;
	else
		p_rsvip_num = &rsvip_numb;
	
	read_reserved_ip_list(p_rsvip, p_rsvip_num);
	printf("rsvip_numa=%d, rsvip_numb=%d\n", rsvip_numa, rsvip_numb);
	if(rsvip_numa != rsvip_numb){
		send_tr_notify_static("Device.DHCPv4.Server.Pool.1.StaticAddressNumberOfEntries");
	}
	else{
		// compare rsvipsa and rsvipsb to check if add one and delete another
		printf("rsvip_numa == rsvip_numb, no rsvip add or delete!\n");
	}
}


