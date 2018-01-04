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
#include <stdarg.h>
#include <sys/stat.h>
#ifdef  CLI_USE_UDS
#include <sys/un.h>
#endif

#include "log.h"

#define MAPFILENAME "/oneagent/conf/pathmapping"
#define MAPKEYFILENAME "/oneagent/conf/keyfilemapping"
//#define LOGFILENAME "/oneagent/conf/senducitocli.log" // may failed to open for write when called by a daemon.
#define LOGFILENAME "/tmp/senducitocli.log"
#define CONFPATH "/oneagent/conf/"
#ifdef  CLI_USE_UDS
static char sock_name[108] = "/var/oneagent_cli.sock";
#endif

#define UCIMAXLEN 1024
#define NAMELEN 256
#define GROUPNUM 256
#define MAPNUM 512
#define MAXCMDLINELEN 2048

t_log_p log_file;

struct mappingInfo_s {
	char tr69path[NAMELEN];
	char uciname[NAMELEN];
};
typedef struct mappingInfo_s mapInfo_t;

struct mappingkey_s {
	char keyfile[NAMELEN];
	char objectuciname[NAMELEN];
};
typedef struct mappingkey_s mapkey_t;

struct keyfiles_s {
	char keyfile[NAMELEN];
	char key[NAMELEN];
};
typedef struct keyfiles_s objkeyfile_t;

int getsubstr_num(char *src, char *substr)
{
	int substrnum = 0;

	char *p = src;
	char *ret;

	while (ret = strstr(p, substr)) {
		p = ret + 1;
		substrnum++;
	}
	return substrnum;

}

char *str_replace_once(const char *src, const char *oldstr, const char *newstr)
{
	if (NULL == src || NULL == oldstr || NULL == newstr) {
		return NULL;
	}
	//从源串中拷贝一份到目的串
	char *dest = strdup(src);
	//如果串相等，则直接返回
	if (strcmp(oldstr, newstr) == 0) {
		return dest;
	}
	//子串位置指针
	char *needle;
	//临时内存区
	char *tmp, *dest_tmp = dest;

	//如果找到子串, 并且子串位置在前len个子串范围内, 则进行替换, 否则直接返回
	if (needle = strstr(dest, oldstr)) {

		//分配新的空间: +1 是为了添加串尾的'\0'结束符
		tmp = (char *)malloc(strlen(dest) + strlen(newstr) - strlen(oldstr) + 1);

		//把src内的前needle-dest个内存空间的数据，拷贝到arr
		strncpy(tmp, dest, needle - dest);

		//标识串结束
		tmp[needle - dest] = '\0';

		//连接arr和newstr, 即把newstr附在arr尾部, 从而组成新串(或说字符数组)arr
		strcat(tmp, newstr);

		//把src中 从oldstr子串位置后的部分和arr连接在一起，组成新串arr
		strcat(tmp, needle + strlen(oldstr));

		//把用malloc分配的内存，复制给指针retv
		dest = strdup(tmp);

		free(dest_tmp);
		//释放malloc分配的内存空间
		free(tmp);
		dest_tmp = dest;
	}
	return dest;
}

int main(int argc, char *argv[])
{
	char tmp[UCIMAXLEN];
	char uciname[UCIMAXLEN];
	char keyvalue[NAMELEN];
	int ucigroup[GROUPNUM];
	int keygroup[GROUPNUM];
	char uripath[UCIMAXLEN];
	int i;
	char cmdline[MAXCMDLINELEN] = "";

	log_init();
	for (i = 0; i < argc; i++) {
		strcat(cmdline, argv[i]);
		strcat(cmdline, " ");
	}
	log_dbg("cmdline = %s\n", cmdline);

	if ((argc != 4) && (argc != 3)) {
		log_dbg("Usage: %s uri uciname key\n", argv[0]);
		log_clean();
		return -1;
	}

	if (fork() == 0) {	//Child process
	
		strcpy(uciname, argv[2]);
		if (argc == 4) {
			strcpy(keyvalue, argv[3]);
		}

		int i = 0, j = 0, p = 0;
		int ucicount = 0;

		//log_dbg("uciname = %s argc %d  %c \n", uciname, argc, uciname[0]);
		while (uciname[i] != '\0') /*while(i < (strlen(uciname))) */
		{
			//log_dbg("%d , %c\n", i, uciname[i]);
			if (uciname[i] == ';') {
				ucigroup[j] = p;
				uciname[i] = '\0';
				p = i + 1;
				j++;
				ucicount++;
			}
			i++;
		}

		if(ucicount == 0)
		{
			//do what sendtocli was originally meant to do before this uci crap was introduced
			sendtocli(argv[1], argv[2]);
			printf("%s  ===  %s \n\r",argv[1],argv[2]);
			return 0;
		}

		int keycount = 0;
		if (argc == 4) {
			i = 0;
			j = 0;
			p = 0;

			while (keyvalue[i] != '\0') {
				if (keyvalue[i] == ';') {
					keygroup[j] = p;
					keyvalue[i] = '\0';
					p = i + 1;
					j++;
					keycount++;
				}
				i++;
			}
		}

		mapInfo_t pathmap[MAPNUM];
		int mappingnum = 0;
		initPathMap(pathmap, &mappingnum);

		mapkey_t keymap[MAPNUM];
		int mapkeynum = 0;
		initKeyMap(keymap, &mapkeynum);

		memset(uripath, 0, UCIMAXLEN);
		strcpy(uripath, "name=");

		int objecti = 0;
		//log_dbg("ucicount = %d", ucicount);
		for (i = 0; i < ucicount; i++) {
			char got = 0;

			//log_dbg("uciname :%s\n", &uciname[0]);
			//log_dbg("i : %d ucigroup %d\n", i, ucigroup[i]);
			for (j = 0; j < mappingnum; j++) {
				//log_dbg("dbg--->j :%d pathmap uciname %s\n",j,pathmap[j].uciname); 
				//log_dbg("dbg--->j :%d uciname %s\n",j,&(uciname[ucigroup[i]])); 
				if (strcasecmp(&(uciname[ucigroup[i]]), pathmap[j].uciname) == 0) {
					log_dbg("found match path, j :%d pathmap uciname %s\n",j,pathmap[j].uciname); 
					strcpy(&(uripath[strlen(uripath)]), pathmap[j].tr69path);
					strcpy(&(uripath[strlen(uripath)]), ";");
					got = 1;
					//break;
					if (strlen(uripath) > strlen("name=")) {
						sendtocli(argv[1], uripath);
						memset(uripath, 0, UCIMAXLEN);
						strcpy(uripath, "name=");
					}
				}
			}

			char isobject = 0;
			char objectnum = mapkeynum;
			log_dbg("got = %d \n", got);
			if (!got) {
				int insnum = getsubstr_num(&(uciname[ucigroup[i]]), ".i.");

				log_dbg("insnum = %d objectnum = %d \n", insnum, objectnum);
				int find = 0;
				char szkeyfile[NAMELEN];
				memset(szkeyfile, 0, sizeof(szkeyfile));
				if (insnum > 0) {
					int m, n = 0;
					for (m = 0; m < insnum; m++) {
						find = 0;
						for (j = n; j < objectnum; j++) {
							log_dbg("uciname = %s objectuciname = %s \n", &(uciname[ucigroup[i]]), keymap[j].objectuciname);
							if (strncasecmp(&(uciname[ucigroup[i]]), keymap[j].objectuciname, strlen(keymap[j].objectuciname)) == 0) {
								strcpy(&(szkeyfile[strlen(szkeyfile)]), keymap[j].keyfile);
								strcpy(&(szkeyfile[strlen(szkeyfile)]), "&");
								find = 1;
								n = j + 1;
								break;
							}
						}

						if (!find) {
							isobject = 0;
							objecti++;
							break;
						}
					}
				}

				if (find) {
					isobject = 1;
					objecti++;
				}

				log_dbg("isobject = %d objecti = %d \n", isobject, objecti);
				if (isobject) {
					char szobjectpath[NAMELEN];
					memset(szobjectpath, 0, NAMELEN);
					getObjectPath(&(uciname[ucigroup[i]]), &(keyvalue[keygroup[objecti - 1]]), szkeyfile, insnum, szobjectpath);
					if (strlen(szobjectpath) > 0) {
						strcpy(&(uripath[strlen(uripath)]), szobjectpath);
						strcpy(&(uripath[strlen(uripath)]), ";");
					}
				}
				/* strcpy(&(uripath[strlen(uripath)]),"\""); */
				log_dbg("uripath = %s\n", uripath);
				/* sendtocli("http://127.0.0.1:1234/value/change/group/", uripath); */
				if (strlen(uripath) > strlen("name=")) {
					sendtocli(argv[1], uripath);
				}
			}
		}
	}
	log_clean();
	return 0;
}

int getinstance_mapfile_bykey(char *filename, char *value)
{
	int i;
	int instance = 0;
	char szinstance[16];
	char szvalue[NAMELEN];
	char abfilename[NAMELEN];
	struct stat st;

	if(filename)
		sprintf(abfilename, "%s%s", CONFPATH, filename);
	log_dbg("abfilename = %s\n", abfilename);
	stat(abfilename,&st);
	if (S_ISDIR(st.st_mode))
		return -1;
	FILE *fp = fopen(abfilename, "r");
	i = 0;
	if (fp) {
		/* need add get mapping info from mapping file */
		while (!feof(fp)) {
			fscanf(fp, "%s %*s %s", szinstance, szvalue);
			log_dbg("szinstance = %s szvalue = %s  value = %s \n", szinstance, szvalue, value);
			if (strcasecmp(szvalue, value) == 0) {
				instance = atoi(szinstance);
				/*log_dbg("instance = %d", instance); */
				return instance;
			}
		}
		fclose(fp);
	} else {
		log_dbg("failed to open file - %s !\n", abfilename);
	}

	return -1;

}

int getObjectPath(char *uciname, char *key, char *keyfile, int insnum, char *objectpath)
{
	objkeyfile_t objkeyfile[16];

	int keynum = getsubstr_num(key, "&");

	log_dbg("key = %s keyfile %s keynum = %d,insnum = %d \n", key, keyfile, keynum, insnum);
	if (keynum != insnum) {
		log_dbg("key value is not match with instance num\n");
		return 0;
	}

	char *p = key;
	char *q = keyfile;
	char *retp;
	char *retq;
	int i = 0;
	while ((retp = strstr(p, "&")) && (retq = strstr(q, "&"))) {
		strncpy(objkeyfile[i].key, p, retp - p);
		strncpy(objkeyfile[i].keyfile, q, retq - q);
		p = retp + 1;
		q = retq + 1;
		i++;
	}

	char tmpuci[NAMELEN];
	int find;
	strcpy(tmpuci, uciname);
	for (i = 0; i < insnum; i++) {
		int instance;
		log_dbg("keyfile = %s key = %s\n", objkeyfile[i].keyfile, objkeyfile[i].key);
		instance = getinstance_mapfile_bykey(objkeyfile[i].keyfile, objkeyfile[i].key);

		log_dbg("instance = %d\n", instance);
		find = 0;
		if (instance > 0) {
			char *des = NULL;
			char tmpins[6];

			find = 1;
			sprintf(tmpins, ".%d.", instance);
			des = str_replace_once(tmpuci, ".i.", tmpins);
			if (des) {
				strcpy(tmpuci, des);
				free(des);
			}
		} else {
			break;
		}
	}

	if (find) {
		strcpy(objectpath, tmpuci);
	}
	log_dbg("objectpath = %s\n", objectpath);
	return 0;
}

int initKeyMap(mapkey_t * map, int *num)
{
	char szkeyfile[NAMELEN];
	char szobjectname[NAMELEN];

	FILE *fp = fopen(MAPKEYFILENAME, "r");
	int i = 0;
	if (fp) {
		while (!feof(fp)) {
			memset(szkeyfile, 0, NAMELEN);
			memset(szobjectname, 0, NAMELEN);
			fscanf(fp, "%s %*s %s", szkeyfile, szobjectname);
			/*log_dbg("keymapfile keyfile %s : objectname %s\n", szkeyfile,szobjectname); */
			strcpy(map[i].keyfile, szkeyfile);
			strcpy(map[i].objectuciname, szobjectname);
			i++;
		}
		fclose(fp);
		*num = i;
		/*log_dbg("i = %d\n",i); */
		return 0;
	} else {
		log_dbg("failed to open file - %s !\n", MAPKEYFILENAME);
		return -1;
	}
}

int initPathMap(mapInfo_t * map, int *num)
{
	char sztr69path[NAMELEN];
	char szuciname[NAMELEN];

	FILE *fp = fopen(MAPFILENAME, "r");
	int i = 0;
	if (fp) {
		while (!feof(fp)) {
			memset(szuciname, 0, NAMELEN);
			memset(sztr69path, 0, NAMELEN);
			fscanf(fp, "%s %*s %s", szuciname, sztr69path);
			/*log_dbg("mapfile tr69 %s : uciname %s\n", sztr69path,szuciname); */
			strcpy(map[i].uciname, szuciname);
			strcpy(map[i].tr69path, sztr69path);
			i++;
		}
		fclose(fp);
		*num = i;
		/*log_dbg("i = %d\n",i); */
		return 0;
	} else {
		log_dbg("failed to open file - %s !\n", MAPFILENAME);
		return -1;
	}
}

/*int main(int argc, char *argv[]) */
int sendtocli(char *argv, char *argv2)
{
	int ipv6_flag = 0;
	int fd;
	char *host, *path, *port;
	int iport = 80;
	char argv1[64];
	strcpy(argv1, argv);
	log_dbg("sendtocli start %s\n", argv1);
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
		
#ifdef CLI_USE_UDS
	struct sockaddr_un server;
	
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&server, 0, sizeof(server));
	server.sun_family = AF_UNIX;
	strncpy(server.sun_path, sock_name, (sizeof(server.sun_path) - 1));
	if (connect(fd, (struct sockaddr *)&server, strlen(server.sun_path) + sizeof(server.sun_family)) != 0) {
		log_dbg("Connect to peer failed: %s\n", strerror(errno));
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
	log_dbg("host: %s, cport: %s\n", host, cport);
	if ((rc = getaddrinfo(host, cport, &hints, &res)) != 0) {
		log_dbg("Get server address information failed: %s!\n", gai_strerror(rc));
		return -1;
	}
	do {
		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (connect(fd, res->ai_addr, res->ai_addrlen) == 0) {
			break;
		} else {
			log_dbg("Connect to server(%s) failed: %s\n", host, strerror(errno));
			close(fd);
			return -1;
		}
	} while ((res = res->ai_next) != NULL);

#endif // #ifdef CLI_USE_UDS

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
			log_dbg("send OK\n");
			close(fd);
		}
	}

	return 0;
}
