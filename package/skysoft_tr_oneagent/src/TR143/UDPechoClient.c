/* echo-client-udp.c */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>

struct UDPPlus_S{
	unsigned int TestGenSN;
	unsigned int TestRespSN;
	unsigned int TestRespRecvTimeStamp;
	unsigned int TestRespReplyTimeStamp;
	unsigned int TestRespReplyFailureCount;
};

int get_stdin( char *buf, int maxlen ) {
	int i=0;
	int n;

	while ( (n=read(STDIN_FILENO,buf+i,maxlen-i)) > 0 ) {
		i+=n;
		if (i==maxlen) break;
	}
	if (n!=0) {
		printf("Error reading stdin");
		return -1;
	}
	/* return the number of bytes read including the last read */
	return i;
}


/* client program:
 *    The following must passed in on the command line:
 *    hostname of the server (argv[1])
 *    port number of the server (argv[2])
 *    */

#define MAXBUF 10*1024

int main( int argc, char **argv ) {
	int sk, rc;
	struct sockaddr_in server, client;
	struct hostent *hp;
	char buf[MAXBUF];
	int buf_len;
	int n_sent;
	int n_read;
	int enableplus=0;
	int times=0;

	/* Make sure we have the right number of command line args */
	if (argc!=5) {
		printf("Usage: %s <server name> <port number> <EnablePlus> <times>\n",argv[0]);
		return 0;
	}
	enableplus=atoi(argv[3]);
	times=atoi(argv[4]);

	if ((sk = socket( PF_INET, SOCK_DGRAM, 0 )) < 0)
	{
		printf("Problem creating socket\n");
		return -1;
	}

	server.sin_family = AF_INET;
	if ((hp = gethostbyname(argv[1]))==0) {
		printf("Invalid or unknown host\n");
		return -1;
	}

	/* copy the IP address into the sockaddr
	 * It is already in network byte order
	 * */
	memcpy( &server.sin_addr.s_addr, hp->h_addr, hp->h_length);
	/* establish the server port number - we must use network byte order! */
	server.sin_port = htons(atoi(argv[2]));

	/* bind any port */
	client.sin_family = AF_INET;
	client.sin_addr.s_addr = htonl (INADDR_ANY);
	client.sin_port = htons (7547);

	rc = bind (sk, (struct sockaddr *) &client, sizeof (client));
	if (rc < 0)
	{
		printf ("%s: cannot bind port\n", argv[0]);
		return -1;
	}

	if(enableplus){
		struct UDPPlus_S plusbuf;
		struct UDPPlus_S *pbuf;
		//add for UDP Plus
		memset(&plusbuf, 0, sizeof(struct UDPPlus_S));
		int i=0;
		for(i=0; i<times; i++){
			plusbuf.TestGenSN = ntohl(plusbuf.TestGenSN) + 1;//covert the unsigned int from network byte to host byte
			plusbuf.TestGenSN = htonl(plusbuf.TestGenSN);//covert the unsigned int from host byte to network byte

			buf_len = sizeof(struct UDPPlus_S);
			n_sent = sendto(sk, &plusbuf, buf_len, 0, (struct sockaddr*) &server, sizeof(server));

			if (n_sent<0) {
				printf("Problem sending data");
				return -1;
			}

			if (n_sent!=buf_len) {
				printf("Sendto sent %d bytes\n",n_sent);
			}

			/* Wait for a reply (from anyone) */
			n_read = recvfrom(sk, buf, MAXBUF, 0, NULL, NULL);
			if (n_read<0) {
				printf("Problem in recvfrom");
				return -1;
			}

			printf("Got back %d bytes\n",n_read);
			pbuf = (struct UDPPlus_S *)buf;

			//printf("TestGenSN = %d\r\n", ntohl(pbuf->TestGenSN));
			//printf("TestRespSN = %d\r\n", ntohl(pbuf->TestRespSN));
			//pbuf->TestRespRecvTimeStamp = ntohl(pbuf->TestRespRecvTimeStamp);
			//printf("TestRespRecvTimeStamp = %u, %s", pbuf->TestRespRecvTimeStamp, ctime(&pbuf->TestRespRecvTimeStamp));
			//pbuf->TestRespReplyTimeStamp = ntohl(pbuf->TestRespReplyTimeStamp);
			//printf("TestTestRespReplyTimeStamp = %u, %s", pbuf->TestRespReplyTimeStamp, ctime(&pbuf->TestRespReplyTimeStamp));

		}
	}else{
		int i=0;
		for(i=0; i<times; i++){
			/* read everything possible */
			//buf_len = get_stdin(buf,MAXBUF);
			//printf("Got %d bytes from stdin - sending...\n",buf_len);
			strcpy(buf, "Send the UDPEcho From Client");
			buf_len=strlen(buf);
			/* send it to the echo server */
			n_sent = sendto(sk,buf,buf_len,0,(struct sockaddr*) &server,sizeof(server));

			if (n_sent<0) {
				printf("Problem sending data");
				return -1;
			}

			if (n_sent!=buf_len) {
				printf("Sendto sent %d bytes\n",n_sent);
			}

			/* Wait for a reply (from anyone) */
			n_read = recvfrom(sk,buf,MAXBUF,0,NULL,NULL);
			if (n_read<0) {
				printf("Problem in recvfrom");
				return -1;
			}

			printf("Got back %d bytes\n",n_read);
			/* send what we got back to stdout */
			if (write(STDOUT_FILENO,buf,n_read) < 0) {
				printf("Problem writing to stdout");
				return -1;
			}
		}
	}
	return 0;
}
