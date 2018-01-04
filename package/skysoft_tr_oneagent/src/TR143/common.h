#ifndef COMMON_H
#define COMMON_H
#include <netdb.h>

//#define DIAG_DBG
#ifdef DIAG_DBG
	#define DIAGDBG(format, args...){printf(format, ##args);printf("\n");}
#else
	#define DIAGDBG(format, args...){}
#endif	

#define TR143_SESSION_TIMEOUT 10
#define HTTP_SESSION_TIMEOUT 30
#define TR143_AGENT_NAME "TR143_DIAGNOSTIC"
#define TR143_DOWNLOAD_FILE "/tmp/TR143DOWN_DIAG.txt"
#define TR143_UPLOAD_FILE "/tmp/TR143UP_DIAG.txt"

#define BUF_SIZE_MAX 4096

typedef struct S_Diagnostic{
	int DiagnosticsState;
	//char ROMTime[64];
	//char BOMTime[64];
	//char EOMTime[64];
	unsigned int TestBytesReceived;
	unsigned int TotalBytesReceived;
	unsigned int TestBytesSent;
	unsigned int TotalBytesSent;
	//char TCPOpenRequestTime[64];
	//char TCPOpenResponseTime[64];
	struct timeval ROMTime, BOMTime, EOMTime;
	struct timeval TCPOpenRequestTime, TCPOpenResponseTime;
} S_Diagnostic;

typedef enum{
	Completed=2,
	Error_InitConnectionFailed,
	Error_NoResponse,
	Error_TransferFailed,
	Error_PasswordRequestFailed, 
	Error_LoginFailed,
	Error_NoTransferMode,
	Error_NoPASV,
	Error_IncorrectSize,
	Error_Timeout,
	Error_NoCWD,
	Error_NoSTOR,
	Error_Internal
} Tr143DiagState;

extern char *DiagnosticsState[];

typedef struct S_URL{
	char protocol[8];
	char host[256];
	int port;
	char uri[256];
	char user[256];
} S_URL;

typedef struct CookieHdr {
	struct CookieHdr *next;
	char    *name;
	char    *value;
} CookieHdr;

typedef struct S_HttpHdrs{
	/* common */
	char *content_type;
	char *protocol;
	char *wwwAuthenticate;
	char *Authorization;
	char *TransferEncoding;
	char *Connection;
	/* request */
	char *method;
	char *path;
	char *host;
	int  port; 
	int  content_length;

	/* result */
	int  status_code;
	CookieHdr *setCookies;
	char *message;
	char *locationHdr;            /* from 3xx status response */
	/* request derived */
	// tIpAddr addr;  /* IP-address of communicating entity */
//#	tZone zone;    /* zone in which communicating entity is */
	char *filename;
	char *arg;

}S_HttpHdrs;

void save_and_notify(char *filename, S_Diagnostic *diagnostic);
int getfilesize(char *arg, unsigned long *size);
int select_with_timeout(int fd, int flag, int timeout);
size_t read_with_timeout(int fd, char *buf, int len);
int RReadn(int fd, char *ptr, int nbytes, int timeout);
int Readline(int fd, char *buf, int maxlen, int timeout);
int SSend(int fd, char *buf, int len);
int open_conn_socket(struct sockaddr_in *s_info, char *if_name, int dscp, int priority);
int parseURL(char *url, S_URL *surl);
int get_if_stats(char *if_name, unsigned int *rx, unsigned int *tx);
void setDateTimeMics(struct timeval *tv, int len);
void get_str_time(char *name, struct timeval tv);
#endif
