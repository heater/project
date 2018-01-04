/**
	Copyright(C) 2014 Skysoft Info&Tech Co.,Ltd. All right reserved.
	@file logopt.c
	@brief Log debug source file.
	@author Mike Liu (mike.liu@cdskysoft.com)
	@version 1.0
	@date 2014-12-19(Create) 2014-12-19(Update)
	@todo Something in plan.
	@details detail description of this file.
**/ 

/* Include files. */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "log.h"

/* Macro constant definitions. */

#define CON_COLOR_GREEN         	"\033[1;32m"
#define CON_COLOR_RED           		"\033[1;31m"
#define CON_COLOR_PURPLE        	"\033[1;35m"
#define CON_COLOR_YELLOW        	"\033[1;33m"
#define CON_COLOR_CYAN          	"\033[1;36m"
#define CON_COLOR_END				"\033[m"


#define LOGIN_USER					"system.sauth.login_user"

/* Type definitions. */

typedef struct debug_log {
	FILE *fp;
	unsigned char use_stdout;
	unsigned int level;
	unsigned long attr;
	unsigned long msg_buf_len;
	char *msg_buf;
	char *log_filename;
} t_log;

/* Local function declarations. */

/* Macro API definitions. */

/* Global variable declarations. */

int debug_log_init(t_log_p * log_p, const char *log_file, unsigned long attr, int init_level)
{

	t_log_p log;
	char tmparray[128] = {0};
	char command[128] = {0};

	FILE *pf = NULL;
	int ret = 0;
	
	log = malloc(sizeof(t_log));
	if (log == NULL) {
		return (-1);
	}
	
	
	if (log_file != NULL) {
		log->fp = fopen(log_file, "a+");
		if (log->fp == NULL) {
			fprintf(stderr, "Open[%s] failed, USE Stdout as debug output.\n", log_file);
			log->log_filename = NULL;
			log->use_stdout = 1;
			log->fp = stdout;
		} else {
			log->log_filename = strdup(log_file);
			log->use_stdout = 0;
		}
	} else {
		fprintf(stderr, "USE Stdout as debug output.\n");
		log->use_stdout = 1;
		log->log_filename = NULL;
		log->fp = stdout;
	}

	log->msg_buf_len = LOG_DEBUG_DEFAULT_BUF_LEN;
	log->msg_buf = malloc(log->msg_buf_len);
	if (log->msg_buf == NULL) {
		if (log->log_filename) {
			free(log->log_filename);
		}
		if (!log->use_stdout) {
		fclose(log->fp);
		}
		free(log);
		return (-2);
	}

	log->level = init_level;
	log->attr = attr;

	*log_p = log;

	return (0);
}

static inline void _get_time(char *buff, int buff_len)
{
	struct timeval tv = { 0 };
	struct tm *time_v = NULL, time_value = { 0 };

	gettimeofday(&tv, NULL);
	/* time_v = localtime(&tv.tv_sec); */
	time_v = localtime_r(&tv.tv_sec, &time_value);
	if (NULL != time_v) {
		snprintf(buff, buff_len, "%d-%02d-%02d %02d:%02d:%02d ",
			 time_v->tm_year + 1900, time_v->tm_mon + 1,
			 time_v->tm_mday, time_v->tm_hour, time_v->tm_min, time_v->tm_sec);
	}
}

int debug_log_print(t_log_p log, int level, const char *func,
		    const char *file, unsigned long line, const char *fmt, ...)
{
	va_list args;
	int rc = 0;
	int buf_len;
	char *new_buf;
	char time[64];
	long fsize;

	if ((level <= LOG_DEBUG_DEFAULT_LEVEL) || (level <= log->level)) {
		_get_time(time, sizeof(time));
		if (!log->use_stdout) {
			fsize = ftell(log->fp);
			if (fsize > LOG_DEBUG_FILE_SIZE) {
				int fd;
				fclose(log->fp);
				fd = open(log->log_filename, O_CREAT | O_WRONLY | O_TRUNC | O_APPEND, 0666);
				if (fd >= 0) {
					close(fd);
				}
				log->fp = fopen(log->log_filename, "w+");
				if (log->fp == NULL) {
					log->fp = stdout;
					log->use_stdout = 1;
				}
				fprintf(log->fp, "%s" CON_COLOR_RED "[!!!!!!]" CON_COLOR_END
					CON_COLOR_RED " FILE truncate!(size: %ld)" CON_COLOR_END "\n", time, fsize);
			}
		}

		va_start(args, fmt);
		do {
			buf_len = log->msg_buf_len;
			rc = vsnprintf(log->msg_buf, log->msg_buf_len, fmt, args);
			if (rc >= buf_len) {
				//printf("Need relloc buf to %lu\n", log->msg_buf_len);
				new_buf = malloc(buf_len * 2);
				if (new_buf == NULL) {
					break;
				} else {
					free(log->msg_buf);
					log->msg_buf = new_buf;
					log->msg_buf_len = buf_len * 2;
				}
			}
		} while (rc >= buf_len);
		va_end(args);

#define LINE_FILE_FUNC_FMT   "[%4lu@%-15s][%-25s]"

		switch (level) {
		case eLOG_LEVEL_TRACE:
			rc = fprintf(log->fp, "%s" CON_COLOR_GREEN "[TRACE]" CON_COLOR_END
				     CON_COLOR_CYAN LINE_FILE_FUNC_FMT CON_COLOR_END CON_COLOR_GREEN
				     " %s" CON_COLOR_END, time, line, file, func, log->msg_buf);
			break;
		case eLOG_LEVEL_DEBUG:
			rc = fprintf(log->fp, "%s" CON_COLOR_GREEN "[DEBUG]" CON_COLOR_END
				     CON_COLOR_CYAN LINE_FILE_FUNC_FMT CON_COLOR_END CON_COLOR_GREEN
				     " %s" CON_COLOR_END, time, line, file, func, log->msg_buf);
			break;
		case eLOG_LEVEL_INFOR:
			rc = fprintf(log->fp, "%s" CON_COLOR_YELLOW "[INFO ]" CON_COLOR_END
				     CON_COLOR_CYAN LINE_FILE_FUNC_FMT CON_COLOR_END CON_COLOR_YELLOW
				     " %s" CON_COLOR_END, time, line, file, func, log->msg_buf);
			break;
		case eLOG_LEVEL_WARNING:
			rc = fprintf(log->fp, "%s" CON_COLOR_PURPLE "[WARN ]" CON_COLOR_END
				     CON_COLOR_CYAN LINE_FILE_FUNC_FMT CON_COLOR_END CON_COLOR_PURPLE
				     " %s" CON_COLOR_END, time, line, file, func, log->msg_buf);
			break;
		case eLOG_LEVEL_ERROR:
			rc = fprintf(log->fp, "%s" CON_COLOR_RED "[ERROR]" CON_COLOR_END
				     CON_COLOR_CYAN LINE_FILE_FUNC_FMT CON_COLOR_END CON_COLOR_RED
				     " %s" CON_COLOR_END, time, line, file, func, log->msg_buf);
			break;
		case eLOG_LEVEL_CRITICAL:
			rc = fprintf(log->fp, "%s" CON_COLOR_RED "[!!!!!]" CON_COLOR_END
				     CON_COLOR_CYAN LINE_FILE_FUNC_FMT CON_COLOR_END CON_COLOR_RED
				     " %s" CON_COLOR_END, time, line, file, func, log->msg_buf);
			break;
		default:
			rc = fprintf(log->fp, "%s[DEBUG]" LINE_FILE_FUNC_FMT "%s",
				     time, line, file, func, log->msg_buf);
			break;
		}
#undef LINE_FILE_FUNC_FMT
		fflush(log->fp);
	}

	return (rc);
}

void debug_log_clean(t_log_p * log_p)
{
	t_log_p log = *log_p;

	if (log != NULL) {
		log->msg_buf_len = 0;

		if (log->msg_buf != NULL) {
			free(log->msg_buf);
			log->msg_buf = NULL;
		}

		if ((!log->use_stdout) && (log->fp != NULL)) {
			fclose(log->fp);
			log->fp = NULL;
		}

		if (log->log_filename != NULL) {
			free(log->log_filename);
			log->log_filename = NULL;
		}
		free(log);
	}
	*log_p = NULL;
}
