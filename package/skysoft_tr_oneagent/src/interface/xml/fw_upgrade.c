#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include "fw_upgrade.h"
#include "tr.h"

int process_fw_upgrade( const char *path )
{
	FILE *fw_fp, *fwc_fp;
	char fw_path[128];
	char cmd[256];
	char firm_check[128] = {0};
	int fwc_time = 0;
	int ret = 0;

	memset(fw_path, 0, sizeof(fw_path));
	tr_full_name(path, fw_path, sizeof(fw_path));
	printf("Firmware Path:%s\n", fw_path);
	if (access(fw_path, F_OK) == 0) {
		system("rm -rf /tmp/firmware_check"); //ASKEY add, must remove firest
		memset(cmd, 0, sizeof(cmd));
		sprintf(cmd, "/sbin/sysupgrade %s", fw_path); //ASKEY mod, using sysupgrade to do upgrading
		printf("Firmware upgrade cmd:%s\n", cmd);
		fw_fp = popen(cmd, "r"); /* dummy command for check upgrade*/
		while(1) {
			fwc_time++;
			fwc_fp = fopen("/tmp/firmware_check", "r");
			if(fwc_fp == NULL) {
				sleep(1);
				continue;
			}
			fgets(firm_check,128,fwc_fp);
			printf("firm_check [%s]\n", firm_check);
			fclose(fwc_fp);
			if(!strncmp(firm_check,"##Firmware check success##", strlen("##Firmware check success##"))) {
				printf("firm_check return success\n");
				fprintf(stdout, "{\"Success\":true, \"FailReason\":\"\"}");
				fflush(stdout);
				ret = 0;
				break;
			}
			if(!strncmp(firm_check,"##Firmware check same version##", strlen("##Firmware check same version##"))) {
				printf("firm_check return same version\n");
				fprintf(stdout, "{\"Success\":false, \"FailReason\":\"err_0004\"}");
				fflush(stdout);
				ret = -1;
				break;
				}
			if(!strncmp(firm_check,"##Firmware check err##", strlen("##Firmware check err##"))) {
				printf("firm_check return err\n");
				fprintf(stdout, "{\"Success\":false, \"FailReason\":\"err_0005\"}");
				fflush(stdout);
				ret = -1;
				break;
				}			
			if(fwc_time > 30) {
				fprintf(stdout, "{\"Success\":false, \"FailReason\":\"err_0002\"}");
				ret = -1;
				break;
			}
			sleep(1);
		}
		system("rm -rf /tmp/firmware_check");
		if (ret == -1) //MUST, AKSEY SH
			pclose(fw_fp);
	} else {
		ret = -1;
		fprintf(stdout, "{\"Success\":true, \"FailReason\":\"\"}");
		fflush(stdout);
	}

	return ret;
}

int process_config( const char *path )
{
    FILE *conf_fp, *confc_fp;
	char conf_path[128];
	char cmd[256];
	char conf_check[128] = {0};
	int confc_time = 0;
	int ret = 0;

	memset(conf_path, 0, sizeof(conf_path));
	tr_full_name(path, conf_path, sizeof(conf_path));
	printf("config file Path:%s\n", conf_path);
    if (access(conf_path, F_OK) == 0) 
	{
	   memset(cmd, 0, sizeof(cmd));
	   sprintf(cmd, "/sbin/sysupgrade -r %s", conf_path);
	   conf_fp = popen(cmd, "r"); /* dummy command for check conf*/
       while(1) 
	   {
         confc_time++;
         confc_fp = fopen("/tmp/config_check", "r");
         if(confc_fp == NULL) 
		 {
			sleep(1);
			continue;
		 }
	     fgets(conf_check,128,confc_fp);
		 fclose(confc_fp);
		 if(!strncmp(conf_check,"##config check success##", strlen("##config check success##"))) 
		 {			
			fprintf(stdout, "{\"Success\":true, \"FailReason\":\"\"}");
			fflush(stdout);
			ret = 0;
			break;
		 }
		 if(!strncmp(conf_check,"##config check fail##", strlen("##config check fail##"))) {
				printf("firm_check return fail\n");
				fprintf(stdout, "{\"Success\":false, \"FailReason\":\"err_0007\"}");
				fflush(stdout);
				return ret;
		 }
		 if(confc_time > 30) 
		 {
			fprintf(stdout, "{\"Success\":false, \"FailReason\":\"err_0002\"}");
			ret = -1;
		    break;
		 }
		 sleep(1);
	  }
      pclose(conf_fp);
	  fflush(stdout);
	  //system("(sleep 1 && reboot -s puma9) &");
	  need_reboot_device();
   }
   else 
   {
      ret = -1;
	  fprintf(stdout, "{\"Success\":false, \"FailReason\":\"err_0001\"}");
	  fflush(stdout);
    }
    return ret;
}


