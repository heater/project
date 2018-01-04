
#ifndef __TR_NOTIFYD_H__
#define __TR_NOTIFYD_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>

#include "log.h"

/** tr_notifyd opt log pointer */
t_log_p cgi_log;

/* Macro API definitions. */

#define tr_crit(fmt,...) \
		do { \
			debug_log_print(cgi_log, eLOG_LEVEL_CRITICAL, __FUNCTION__, \
				__FILE__, __LINE__, (fmt), ##__VA_ARGS__); \
		} while(0)

#define tr_err(fmt,...) \
	do { \
		debug_log_print(cgi_log, eLOG_LEVEL_ERROR, __FUNCTION__, \
			__FILE__, __LINE__, (fmt), ##__VA_ARGS__); \
	} while(0)

#define tr_info(fmt,...) \
	do { \
		debug_log_print(cgi_log, eLOG_LEVEL_INFOR, __FUNCTION__, \
			__FILE__, __LINE__, (fmt), ##__VA_ARGS__); \
	} while(0)

#define tr_dbg(fmt,...) \
	do { \
		debug_log_print(cgi_log, eLOG_LEVEL_DEBUG, __FUNCTION__, \
			__FILE__, __LINE__, (fmt), ##__VA_ARGS__); \
	} while(0)

#define tr_trace_enter() \
	do { \
		debug_log_print(cgi_log, eLOG_LEVEL_TRACE, __FUNCTION__, \
			__FILE__, __LINE__, "[ENTER]\n"); \
	} while(0)

#define tr_trace_exit() \
	do { \
		debug_log_print(cgi_log, eLOG_LEVEL_TRACE, __FUNCTION__, \
			__FILE__, __LINE__, "[EXIT]\n"); \
	} while(0)

#define tr_trace_line() \
	do { \
		debug_log_print(cgi_log, eLOG_LEVEL_TRACE, __FUNCTION__, \
			__FILE__, __LINE__, "[CHECK]\n"); \
	} while(0)

#define tr_log_init() \
	debug_log_init(&cgi_log, TR_NOTIFY_LOG_FILE, 0, CGI_LOG_LEVEL)

#define DEBUG_LEVEL 0
#define X86_DEBUG 0
#define TR_NOTIFYD_LOG_FILE "/tmp/tr_notifyd.log"
#define TR069_NOTIFY_MAX_LEN 2048
// Device.Hosts.Host.{i}.
#define MAX_HOST_NUM 512
#define MAX_ARP_OPTION_LEN 64
// Device.WiFi.AccessPoint.{i}.AssociatedDevice.{i}.
#define MAX_STA_NUM 64
#define MAX_STA_OPTION_LEN 32
#define MAX_DEVICE_NUM 128
#define MAX_DEVICE_OPTION_LEN 64
// Device.IP.ActivePortNumberOfEntries
#define MAX_PORT_NUM 512
#define MAX_PORT_OPTION_LEN 64
// Device.DHCPv4.Server.Pool.{i}.StaticAddressNumberOfEntries
#define MAX_RSVIP_NUM 128
#define MAX_RSVIP_OPTION_LEN 64


/*uci config path*/

#define CAPTIVE_ENABLE 	"wifidog.settings.wifidog_enable"
#define CAPTIVE_URL		"wifidog.settings.gateway_host"
#define CAPTIVE_STATUS    	"wifidog.settings.wifidog_status"




/*the base functions*/
void log_notify(const char *format, ...);
void send_tr_notify_static(char *path);
void send_tr_notify_dynamic(char *path, char *key);
int sendtocli(char *argv, char *argv2);
void setup_timer(int interval);
void cancel_timer();


/*The notification function that belong the sub-modules of the router,such as 
network status,clients status andso on.*/

void check_host_event();
int read_host_list(char (*p_host)[MAX_ARP_OPTION_LEN], int *host_num);
int read_wireless_client_list(char *athn, char (*p_sta)[MAX_STA_OPTION_LEN], 
	int *sta_num);
void check_wireless_client_event();
int read_active_port_list(char (*p_port)[MAX_PORT_OPTION_LEN], int *port_num);
void check_active_port_event();
void read_manageable_device_list(char (*p_device)[MAX_RSVIP_OPTION_LEN], 
	int *device_num);
void check_manageable_device_event();
int  read_dhcp_client_status();
void check_dhcp_client_status_event();
void read_reserved_ip_list(char (*p_rsvip)[MAX_RSVIP_OPTION_LEN], int *rsvip_num);
void check_reserved_ip_event();
int check_captive_portal_status();

#endif
