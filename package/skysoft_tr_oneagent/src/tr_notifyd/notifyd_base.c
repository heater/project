
#include "tr_notifyd.h"



void log_notify(const char *format, ...)
{
	FILE *logfd = NULL;
	va_list args;

	logfd = fopen(TR_NOTIFYD_LOG_FILE, "a");
	if(logfd)
	{
		fprintf(logfd, format, args);
		//fprintf(logfd, "%s", "\n");
		fflush(logfd);
		fclose(logfd);
	}
}

void send_tr_notify_static(char *path)
{
	printf("send notify static now\n");
	char notify_cmd[TR069_NOTIFY_MAX_LEN] = "";
	sprintf(notify_cmd, "/oneagent/senducitocli http://127.0.0.1:1234/value/change/group/ \"%s;\"", path);
	system(notify_cmd);
	log_notify(notify_cmd);
}

void send_tr_notify_dynamic(char *path, char *key)
{
	printf("send notify dynamic now\n");
	char notify_cmd[TR069_NOTIFY_MAX_LEN] = "";
	sprintf(notify_cmd, "/oneagent/senducitocli http://127.0.0.1:1234/value/change/group/ \"%s;\" \"%s&;\"", path, key);
	system(notify_cmd);
	log_notify(notify_cmd);
}

int sendtocli(char *argv, char *argv2)
{
	int ipv6_flag = 0;
#if 0
	if (argc != 3) {
		log_notify("Usage: %s url content", argv[0]);
		return -1;
	} else if (fork() == 0) {	//Child process
#endif
		int fd;
		char *host, *path, *port;
		int iport = 80;
		char argv1[64];
		strcpy(argv1, argv);
		log_notify("sendtocli start %s", argv1);
		if (strncasecmp(argv1, "http://", 7) == 0)
			host = argv1 + 7;
		else
			host = argv1;
		path = strchr(host, '/');
		if (path) {
			*path = '\0';
			path++;
		} else {
			path = "";
		}
		if (strchr(host, '[') != NULL) {
			ipv6_flag = 1;
		}

		if (ipv6_flag == 1) {
			port = strstr(host, "]:");
			if (port) {
				*port = '\0';
				iport = atoi(port + 2);
				host++;
			}
		} else {
			port = strchr(host, ':');
			if (port) {
				*port = '\0';
				iport = atoi(port + 1);
			}

		}

#if 0
		struct sockaddr_in server;
		struct hostent *hp;
		fd = socket(AF_INET, SOCK_STREAM, 0);
		memset(&server, 0, sizeof(server));
		server.sin_family = AF_INET;
		server.sin_port = htons(iport);
		hp = gethostbyname(host);
		if (!hp) {
			printf("Resolve peer(%s) address failed: %s\n", host, strerror(errno));
			return -1;
		}
		memcpy(&(server.sin_addr), hp->h_addr, sizeof(server.sin_addr));
		if (connect(fd, (struct sockaddr *)&server, sizeof(server)) != 0) {
			printf("Connect to peer failed: %s\n", strerror(errno));
			close(fd);
			return -1;
		}
#else
		struct addrinfo hints, *res;
		int rc;
		char cport[10];
		if (ipv6_flag) {
			strncpy(cport, port + 2, sizeof(cport));
		} else {
			strncpy(cport, port + 1, sizeof(cport));
		}
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		log_notify("host: %s, cport: %s", host, cport);
		if ((rc = getaddrinfo(host, cport, &hints, &res)) != 0) {
			log_notify("Get server address information failed: %s!", gai_strerror(rc));
			return -1;
		}
		do {
			fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if (connect(fd, res->ai_addr, res->ai_addrlen) == 0) {
				break;
			} else {
				log_notify("Connect to server(%s) failed: %s", host, strerror(errno));
				close(fd);
				return -1;
			}
		} while ((res = res->ai_next) != NULL);

#endif

		//connect ok
		{
			int len;
			int res = 0;
			char buffer[5120];
			char *from;

			len = strlen(argv2);
			len = snprintf(buffer, sizeof(buffer), 
				"POST /%s HTTP/1.1\r\n"
				"Host: %s%s%s:%d\r\n"	//for ipv6_addr
				"Content-Type: application/x-www-form-urlencoded\r\n"
				"Content-Length: %d\r\n"
				"\r\n"
				"%s", path, (ipv6_flag) ? "[" : "", host, (ipv6_flag) ? "]" : "", iport, len, argv2);

			from = buffer;
			do {
				len -= res;
				from += res;
				res = send(fd, from, len, 0);
			} while (res > 0);

			if (res == 0) {
				log_notify("send OK");
				close(fd);
			}
		}
#if 0
	}
#endif
	return 0;
}
void setup_timer(int interval)
{	
	struct itimerval value;

	value.it_value.tv_sec = interval;
	value.it_value.tv_usec = 0;
	value.it_interval = value.it_value;
	setitimer(ITIMER_REAL, &value, NULL);
}

void cancel_timer()
{
	struct itimerval value;
	
	value.it_value.tv_sec = 0;
	value.it_value.tv_usec = 0;
	value.it_interval.tv_sec = 0;
	value.it_interval.tv_usec = 0;
	setitimer(ITIMER_REAL, &value, NULL);	
}


