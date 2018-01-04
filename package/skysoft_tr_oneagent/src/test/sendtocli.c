#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#ifdef  CLI_USE_UDS
#include <sys/un.h>
#endif

#ifdef  CLI_USE_UDS
static char sock_name[108] = "/var/oneagent_cli.sock";
#endif

int main(int argc, char *argv[])
{
	int ipv6_flag = 0;
	if(argc != 3) {
		printf("Usage: %s url content\n", argv[0]);
		return -1;
	} else if(fork() == 0) { //Child process
		int fd;
		char *host, *path, *port;
		int iport = 80;

		if(strncasecmp(argv[1], "http://", 7) == 0)
			host = argv[1] + 7;
		else
			host = argv[1];
		path = strchr(host, '/');
		if(path) {
			*path = '\0';
			path++;
		} else {
			path = "";
		}
		
		if(strchr(host, '[') != NULL) {
			ipv6_flag = 1;	
		}	

		if(ipv6_flag == 1) {
			port = strstr(host, "]:");
			if(port) {
				*port = '\0';
				iport = atoi(port + 2);
				host++;
			}
		} else {
			port = strchr(host, ':');
			if(port) {
				*port = '\0';
				iport = atoi(port + 1);
			}

		}

#ifdef CLI_USE_UDS
		struct sockaddr_un server;
	
		fd = socket(AF_UNIX, SOCK_STREAM, 0);
		memset(&server, 0, sizeof(server));
		server.sun_family = AF_UNIX;
		strncpy(server.sun_path, sock_name, (sizeof(server.sun_path) - 1));
		if (connect(fd, (struct sockaddr *)&server, strlen(server.sun_path) + sizeof(server.sun_family)) != 0) {
			close(fd);
			return -1;
		}	
#else
		struct addrinfo hints, *res;
		int rc;
		char cport[10];
		if(ipv6_flag){
			strncpy(cport, port+2, sizeof(cport));
		} else {
			strncpy(cport, port+1, sizeof(cport));
		}
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		printf("host: %s, cport: %s\n", host, cport);
		if((rc = getaddrinfo(host, cport, &hints, &res)) != 0) {
                	printf("Get server address information failed: %s!\n", gai_strerror(rc));
                	return -1;
		}
		do {
			fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if(connect(fd, res->ai_addr, res->ai_addrlen) == 0){
		    		break;
			} else {
		    		printf("Connect to server(%s) failed: %s\n", host, strerror(errno));
		  //  		close(fd);
		    		return -1;
			}
	    	} while((res = res->ai_next) != NULL);

#endif
		
		//connect ok
		{
			int len;
			int res = 0;
			char buffer[5120];
			char *from;

			len = strlen(argv[2]);

			len = snprintf(buffer, sizeof(buffer),
				"POST /%s HTTP/1.1\r\n"
				"Host: %s%s%s:%d\r\n" //for ipv6_addr
				"Content-Type: application/x-www-form-urlencoded\r\n"
				"Content-Length: %d\r\n"
				"\r\n"
				"%s", path, (ipv6_flag)?"[":"", host, (ipv6_flag)?"]":"", iport, len, argv[2]);

			from = buffer;
			do {
				len -= res;
				from += res;
				res = send(fd, from, len, 0);
			} while(res > 0);

			if(res == 0) {
				printf("send OK\n");
				close(fd);
			}
		}
	}
	return 0;
}
