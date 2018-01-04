/*
**  Copyright (c) 2014 Michael Liu(michael.liu.point@gmail.com).
**
**  Project: Gateway Unified Management Platform
**  File:    common.h
**  Author:  Michael
**  Date:    03/20/2014
**
**  Purpose:
**    common defines.
*/

#ifndef __GUM_COMMON_H__
#define __GUM_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

/* Include files. */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include <sys/un.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>

#include <sys/mman.h>

#include <signal.h>
#include <arpa/inet.h>

#include <time.h>

#include "logopt.h"


/* Macro constant definitions. */
#define LOG_FILE	"/tmp/senducitocli.log"
#define LOG_LEVEL	eLOG_LEVEL_DEBUG

/* Macro API definitions. */
#define log_crit(fmt,...) \
		do { \
			debug_log_print(log_file, eLOG_LEVEL_CRITICAL, __FUNCTION__, \
				__FILE__, __LINE__, (fmt), ##__VA_ARGS__); \
		} while(0)

#define log_err(fmt,...) \
	do { \
		debug_log_print(log_file, eLOG_LEVEL_ERROR, __FUNCTION__, \
			__FILE__, __LINE__, (fmt), ##__VA_ARGS__); \
	} while(0)

#define log_info(fmt,...) \
	do { \
		debug_log_print(log_file, eLOG_LEVEL_INFOR, __FUNCTION__, \
			__FILE__, __LINE__, (fmt), ##__VA_ARGS__); \
	} while(0)

#define log_dbg(fmt,...) \
	do { \
		debug_log_print(log_file, eLOG_LEVEL_DEBUG, __FUNCTION__, \
			__FILE__, __LINE__, (fmt), ##__VA_ARGS__); \
	} while(0)

#define log_trace_enter() \
	do { \
		debug_log_print(log_file, eLOG_LEVEL_TRACE, __FUNCTION__, \
			__FILE__, __LINE__, "[ENTER]\n"); \
	} while(0)

#define log_trace_exit() \
	do { \
		debug_log_print(log_file, eLOG_LEVEL_TRACE, __FUNCTION__, \
			__FILE__, __LINE__, "[EXIT ]\n"); \
	} while(0)

#define log_trace_line() \
	do { \
		debug_log_print(log_file, eLOG_LEVEL_TRACE, __FUNCTION__, \
			__FILE__, __LINE__, "[CHECK]\n"); \
	} while(0)

#if 1
#define log_init() \
	debug_log_init(&log_file, LOG_FILE, 0, LOG_LEVEL)
#else
#define log_file_init() \
	debug_log_init(&log_file, NULL, 0, eLOG_LEVEL_TRACE)
#endif

#define log_clean() \
	debug_log_clean(&log_file)

/* Global variable declarations. */

	extern t_log_p log_file;

#ifdef __cplusplus
}				/* extern "C" */
#endif				/* __cplusplus */
#endif				/* __GUM_COMMON_H__ */

