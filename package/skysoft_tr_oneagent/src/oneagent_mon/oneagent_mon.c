#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <uci.h>
#include <suci.h>

#define MS "trconf"
#define TRCONF MS"."
#define DM_EnableCWMP			TRCONF "Device_ManagementServer.EnableCWMP"

#define RESET_ONEAGENT_FLAG_INITIAL 0
#define RESET_ONEAGENT_FLAG_PRERESET 1
#define RESET_ONEAGENT_FLAG_RESET 2

int mon_log_enable = 0;
int mon_log_to_file = 0;
int reset_oneagent_flag = RESET_ONEAGENT_FLAG_INITIAL;

#define LOG_FILE "/var/oneagent_mon_log.txt"

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

void log_mon(const char *format, ...)
{
	FILE *logfd = NULL;
	va_list args;

	if (mon_log_enable){
		if (mon_log_to_file){
			logfd = fopen(LOG_FILE, "a+");
			if(logfd){
				va_start (args, format);
				//fprintf(logfd, "%s: ", getTimestamp());
				vfprintf (logfd, format, args);
				fprintf(logfd, "%c", '\n');
				va_end (args);
				fflush(logfd);
				fclose(logfd);
			}
		}
		else{
			va_start (args, format);
			//fprintf(stdout, "%s: ", getTimestamp());
			vfprintf (stdout, format, args);
			fprintf(stdout, "%c", '\n');
			va_end (args);
			fflush(stdout);
		}
	}
}

void restart_oneagent()
{
	//log_mon("----- implement oneagent restart function here -----");
	system("/etc/init.d/tr-069 restart &");
}

void sigusr1_handler()
{
	log_mon("----- recv SIGUSR1, restart oneagent now -----");
	reset_oneagent_flag == RESET_ONEAGENT_FLAG_INITIAL;
	restart_oneagent();
}

void sigusr2_handler()
{
	log_mon("----- recv SIGUSR2, no action defined, do nothing -----");
}

void sigalrm_handler()
{
	log_mon("----- recv SIGALRM, no action defined, do nothing -----");
}

void sigterm_handler()
{
	log_mon("----- recv SIGTERM, exit now -----");
	_exit(EXIT_SUCCESS);
}

void init_signal_handler()
{
	signal(SIGUSR1, sigusr1_handler);
	signal(SIGUSR2, sigusr2_handler);
	signal(SIGALRM, sigalrm_handler);
	signal(SIGTERM, sigterm_handler);
}

void display_usage(char *s)
{
	fprintf(stderr, "\n");
	fprintf(stderr, "Usage: %s [-lf]\n", s);
	fprintf(stderr, "      -l, enable debug, print log to stdout by default\n");
	fprintf(stderr, "      -f, used with option l, print log to file, /var/oneagent_mon_log.txt\n");
	fprintf(stderr, "Signals:\n");
	fprintf(stderr, "      USR1	Restart oneagent\n");
	fprintf(stderr, "      USR2	To be defined\n");
	fprintf(stderr, "\n");
	fflush(stderr);
	exit(EXIT_FAILURE);
}

void parse_args(int argc, char **argv)
{
	int opt = -1;

	while((opt = getopt(argc, argv, "lfh")) != -1){
		switch (opt) {
			case 'l':
				mon_log_enable = 1;
				break;
			case 'f':
				mon_log_to_file = 1;
				break;
			case 'h':
				display_usage(argv[0]);
				break;
			default :
				display_usage(argv[0]);
				break;
		}
	}	
	log_mon("mon_log_enable=%d, mon_log_to_file=%d", mon_log_enable, mon_log_to_file);
}

static void getInterfaceInfo(char *inf, a_infinfo *wandeviceinfo)
{
	FILE *fd = NULL;
	char line[128] = {0};
	char *ptr = NULL;
	char cmd[128] = {0};

	sprintf(cmd, "ubus call network.interface.%s status | sed 's/\"//g'", inf);
	if ((fd = popen(cmd, "r")) != NULL){
		while(fgets(line, sizeof(line) - 1, fd)){
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
		
		log_mon("=====up=%d", wandeviceinfo->status);
		log_mon("=====uptime=%s", wandeviceinfo->uptime);
		log_mon("=====l3_device=%s", wandeviceinfo->l3_device);
		log_mon("=====proto=%s", wandeviceinfo->proto);
		log_mon("=====device=%s", wandeviceinfo->device);
		log_mon("=====ipv4_address=%s", wandeviceinfo->ipv4_address);
		log_mon("=====mask=%s", wandeviceinfo->mask);
		log_mon("=====ipv6_address=%s", wandeviceinfo->ipv6_address);
		log_mon("=====ipv6_mask=%s", wandeviceinfo->ipv6_mask);
		log_mon("=====ipv6_prefix_address=%s", wandeviceinfo->ipv6_prefix_address);
		log_mon("=====ipv6_prefix_mask=%s", wandeviceinfo->ipv6_prefix_mask);
		log_mon("=====nexthop=%s", wandeviceinfo->nexthop);
		log_mon("=====dns=%s", wandeviceinfo->dns);
	}
}

int get_oneagent_running_state(void)
{
	int runsta = 0;
	FILE *fp = NULL;
	char pronum[128] = {0};
	int rc = 0;

	fp = popen("ps | grep /oneagent/conf | grep /oneagent/oneagent | wc -l", "r");
	if (fp == NULL) {
		runsta = 0;
		return runsta;
	} else {
		memset(pronum, 0x00, sizeof(pronum));
		fgets(pronum, sizeof(pronum) - 1, fp);
		if (atoi(pronum) >= 1) {
			runsta = 1; // oneagent is running
			log_mon("oneagent is running,pronum=%s", pronum);
		} else {
			runsta = 0; // oneagent is not running
			log_mon("oneagent is not running,pronum=%s", pronum);
		}
	}
	pclose(fp);
	
	log_mon("End return runsta=%d", runsta);
	return runsta;
}

int main(int argc, char *argv[])
{
	char tr_enable[2] = {0};
	int is_running = 1;
	a_infinfo iface, iface6;

	parse_args(argc, argv);
	daemon(0, mon_log_enable);
	init_signal_handler();

	while(1)
	{
		is_running = get_oneagent_running_state();
		if (is_running == 0) {
			memset(tr_enable, 0x00, sizeof(tr_enable));
			do_uci_get(DM_EnableCWMP, tr_enable);
			if (tr_enable[0] == '1') {
				memset(&iface, 0x00, sizeof(iface));
				memset(&iface6, 0x00, sizeof(iface6));
				getInterfaceInfo("wan", &iface);
				getInterfaceInfo("wan6", &iface6);
				if ((iface.status == 0)&&(iface.ipv4_address[0] == '\0') && 
					(iface6.status == 0)&&(iface6.ipv6_address[0] == '\0'))
				{
					reset_oneagent_flag = RESET_ONEAGENT_FLAG_INITIAL;
				} else {
					reset_oneagent_flag = reset_oneagent_flag + 1;
					if (reset_oneagent_flag == RESET_ONEAGENT_FLAG_RESET)
					{
						memset(tr_enable, 0x00, sizeof(tr_enable));
						do_uci_get(DM_EnableCWMP, tr_enable);
						if (tr_enable[0] == '1') {
							is_running = get_oneagent_running_state();
							if (!is_running) {
								log_mon("----- oneagent restart -----");
								restart_oneagent();	
							}
						}
						reset_oneagent_flag = RESET_ONEAGENT_FLAG_INITIAL;
					}
				}
			} else {
				reset_oneagent_flag = RESET_ONEAGENT_FLAG_INITIAL;
			}
		}else {
			reset_oneagent_flag = RESET_ONEAGENT_FLAG_INITIAL;
		}

		sleep(30);
		//pause();
	}

	return 0;
}

