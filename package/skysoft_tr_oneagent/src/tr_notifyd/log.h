/**
	Copyright(C) 2014 Skysoft Info&Tech Co.,Ltd. All right reserved.
	@file code_spec_test.h
	@brief Log debug header file.
	@author Mike Liu (mike.liu@cdskysoft.com)
	@version 1.0
	@date 2014-12-19(Create) 2014-12-19(Update)
	@todo Something in plan.
	@details detail description of this file.
**/ 

#ifndef __LOG_FOR_DEBUG_H__
#define __LOG_FOR_DEBUG_H__

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

/* Include files. */

/* Macro constant definitions. */
#define TR_NOTIFY_LOG_FILE				"/var/log/tr_notifyd.log"

/** default cgi log debug level */
#define CGI_LOG_LEVEL					eLOG_LEVEL_TRACE

#define LOG_DEBUG_DEFAULT_LEVEL		eLOG_LEVEL_ERROR
#define LOG_DEBUG_DEFAULT_BUF_LEN		128
#define LOG_DEBUG_FILE_SIZE				(512 * 1024)

/* Type definitions. */

	enum {
		eLOG_LEVEL_CRITICAL = 0,
		eLOG_LEVEL_ERROR = 1,
		eLOG_LEVEL_WARNING = 2,
		eLOG_LEVEL_INFOR = 3,
		eLOG_LEVEL_DEBUG = 4,
		eLOG_LEVEL_TRACE = 5,
	} e_log_level;

	typedef struct debug_log *t_log_p;

/* External function declarations. */

extern int debug_log_init(t_log_p * log_p, const char *log_file, unsigned long attr, int init_level);
extern int debug_log_print(t_log_p log, int level, const char *func,
			   const char *file, unsigned long line, const char *fmt, ...);
extern void debug_log_clean(t_log_p * log_p);

/* Macro API definitions. */

/* Global variable declarations. */

#ifdef __cplusplus
}				/* extern "C" */
#endif				/* __cplusplus */
#endif				/* __LOG_FOR_DEBUG_H__ */
