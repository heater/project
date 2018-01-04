/*!
 * *************************************************************
 *
 * Copyright(c) 2011, Works Systems, Inc. All rights reserved.
 *
 * This software is supplied under the terms of a license agreement
 * with Works Systems, Inc, and may not be copied nor disclosed except
 * in accordance with the terms of that agreement.
 *
 * *************************************************************
 */

/*!
 * \file connection.c
 * \brief HTTP session connection abstraction implementation
 */
#include <string.h>
#include <stdlib.h>


#include "tr_strings.h"
#include "network.h"
#include "connection.h"
#include "log.h"
#include "ssl.h"
#include "war_string.h"
#include "war_socket.h"
#include "war_errorcode.h"

#include "tr_uciconfig.h"
#include "tr_lib.h" //ASKEY SH add

extern short tcplistenport;
//ASKEY SH add/s
char currentIP[128] = {0};		/* Unix domain is largest */
int try_ipv6 = -1;
int ipv6_exist= 0;
int ipv4_exist= 0;
//ASKEY SH add/e

int tr_conn( struct connection *conn, const char *u )
{
    char url[1025];
#ifdef __ENABLE_SSL__
    char *proto = "http";
#endif
    char *host = NULL;
    char *c;
    conn->secure = 0;
    conn->fd = -1;
#ifdef __ENABLE_SSL__
    conn->ctx = NULL;
    conn->ssl = NULL;
#endif
    u = skip_blanks( u );
    war_snprintf( url, sizeof( url ), "%s", u );
    c = strstr( url, "://" );

    if( c ) {
        *c = '\0';
        host = c + 3;
#ifdef __ENABLE_SSL__

        if( war_strcasecmp( url, "https" ) == 0 ) {
            proto = "https";
        } else
#endif
            if( war_strcasecmp( url, "http" ) ) {
                tr_log( LOG_WARNING, "Unsupported protocol: %s", url );
                return -1;
            }
    } else {
        host = url;
    }

    c = strchr( host, '/' );

    if( c ) {
        war_snprintf( conn->path, sizeof( conn->path ), "%s", c );
        *c = '\0';
    } else {
        war_snprintf( conn->path, sizeof( conn->path ), "/" );
    }

    /* URL type:
     * Domain name:port/
     * Domain name/
     * [ipv6_addr(:)]:port/
     * [ipv6_addr(:)]/
     * ipv4_addr:port/
     * ipv4_addr/
     */

    if( *host == '[' ) { /* [ipv6_addr] */
        char *c1 = NULL;
        host++;
        c = strchr( host, ']' );

        if( c == NULL ) {
            tr_log( LOG_ERROR, "[] not match" );
            return -1;
        }

        *c = '\0';
        war_snprintf( conn->host, sizeof( conn->host ), "%s", host );
        c++;

        if( ( c1 = strchr( c, ':' ) ) != NULL ) {
            war_snprintf( conn->port, sizeof( conn->port ), "%s", c1 + 1 );
#ifdef __ENABLE_SSL__
        } else if( war_strcasecmp( proto, "https" ) == 0 ) {
            war_snprintf( conn->port, sizeof( conn->port ), "443" );   /* The default port for HTTPS */
#endif
        } else {
            war_snprintf( conn->port, sizeof( conn->port ), "80" );
        }
    } else {
        /* Domain name and ipv4_addr */
        c = strchr( host, ':' );

        if( c ) {
            war_snprintf( conn->port, sizeof( conn->port ), "%s", c + 1 );
            *c = '\0';
#ifdef __ENABLE_SSL__
        } else if( war_strcasecmp( proto, "https" ) == 0 ) {
            war_snprintf( conn->port, sizeof( conn->port ), "443" );   /* The default port for HTTPS */
#endif
        } else {
            war_snprintf( conn->port, sizeof( conn->port ), "80" );
        }

        war_snprintf( conn->host, sizeof( conn->host ), "%s", host );
    }

#if defined(__DEVICE_IPV4__)
    {
        struct sockaddr_in addr;
        struct hostent *hp;
        memset( &addr, 0, sizeof( addr ) );
        addr.sin_port = htons( tr_atos( conn->port ) );
        addr.sin_family = AF_INET;

        if( ( addr.sin_addr.s_addr = inet_addr( host ) ) == INADDR_NONE ) {
            hp = war_gethostbyname( host );

            if( hp ) {
                memcpy( & ( addr.sin_addr ), hp->h_addr, sizeof( addr.sin_addr ) );
            } else {
                tr_log( LOG_WARNING, "Resolve server address(%s) failed!", host );
                return -1;
            }
        }

        conn->fd = war_socket( AF_INET, SOCK_STREAM, 0 );

        if( conn->fd < 0 ) {
            tr_log( LOG_ERROR, "Create socket failed: %s", war_strerror( war_geterror() ) );
            return -1;
        } else if( tr_connect( conn->fd, ( struct sockaddr * ) &addr, sizeof( addr ) ) < 0 ) {
            tr_log( LOG_ERROR, "Connect to server(%s) failed: %s", host, war_strerror( war_geterror() ) );
            war_sockclose( conn->fd );
            conn->fd = -1;
            return -1;
        }
    }
#else
    {
        int rc;
        struct addrinfo hints, *res, *ressave;
        memset( &hints, 0, sizeof( hints ) );
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
#ifdef CODE_DEBUG
        tr_log( LOG_DEBUG, "conn->host: %s, conn->port: %s", conn->host, conn->port );
#endif

        if( ( rc = getaddrinfo( conn->host, conn->port, &hints, &res ) ) != 0 ) {
            tr_log( LOG_WARNING, "Get server(%s) address information failed: %s!", host, gai_strerror( rc ) );
            return -1;
        }

        ressave = res;

	//ASKEY SH add/s
		ipv6_exist = 0;
		ipv4_exist = 0;
		do {
			if(res->ai_family == AF_INET6)
			{
				ipv6_exist = 1;
				if(try_ipv6 == -1)
				{
					try_ipv6 = 1;
				}
			}
			else if(res->ai_family == AF_INET)
			{
				ipv4_exist = 1;
			}
		} while( ( res = res->ai_next ) != NULL );

		char enable[16] = {0};

		if(do_uci_get("ipv6.@global[0].connection_type", enable))
		{
			strcpy(enable, "0");
		}
	
		if(ipv4_exist == 1 && ipv6_exist == 1 && try_ipv6 == 0 && get_retry_ipv6_count() == 0)
		{
			try_ipv6 = 1;
		}
		
		if (atoi(enable) == 0)
		{
			ipv6_exist = 0;
			try_ipv6 = 0;
		}

		tr_log( LOG_DEBUG, "******************* ipv4_exist: %d", ipv4_exist);
		tr_log( LOG_DEBUG, "******************* ipv6_exist: %d", ipv6_exist);
		tr_log( LOG_DEBUG, "******************* enable: %s", enable);
		tr_log( LOG_DEBUG, "******************* try_ipv6: %d", try_ipv6);
		tr_log( LOG_DEBUG, "******************* retry_count: %d", get_retry_count());
		tr_log( LOG_DEBUG, "******************* retry_ipv6_count: %d", get_retry_ipv6_count());

		res = ressave;
	//ASKEY SH add/e
		
        do {
            conn->fd = war_socket( res->ai_family, res->ai_socktype, res->ai_protocol );
	//ASKEY SH add/s
			if(try_ipv6 == 1)
			{
				if(res->ai_family == AF_INET)
				{
					continue;
				}
			}
			else if(try_ipv6 == 0)
			{
				if(res->ai_family == AF_INET6)
				{
					continue;
				}
			}

			if(res->ai_family == AF_INET)
			{
				struct sockaddr_in	*sin = (struct sockaddr_in *) res->ai_addr;
				if (inet_ntop(AF_INET, &sin->sin_addr, currentIP, sizeof(currentIP)) == NULL)
				{
					continue;
				}				
			}
			else if(res->ai_family == AF_INET6)
			{
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) res->ai_addr;
				if (inet_ntop(AF_INET6, &sin6->sin6_addr, currentIP, sizeof(currentIP)) == NULL)
				{
					continue;
				}
			}
			tr_log( LOG_DEBUG, "******************* currentIP: %s", currentIP);
	//ASKEY SH add/e
			
            if( conn->fd < 0 ) {
                tr_log( LOG_ERROR, "Create socket failed: %s", war_sockstrerror( war_getsockerror() ) );
            } else if( tr_connect( conn->fd, res->ai_addr, res->ai_addrlen ) == 0 ) {
                /* askey wangzheng 2015-07-29 s: add tcp connection request url */
                struct sockaddr_in addrMy;
                socklen_t len = sizeof(addrMy);
			#ifdef __DEVICE_IPV6__ //ASKEY SH mod start
				struct sockaddr_in6 addr6My;
                socklen_t len6 = sizeof(addr6My);

				int ret = 0;
				char addr6[INET6_ADDRSTRLEN] = {0};

				//if(strstr(conn->host, ":") != NULL)
				if(strstr(currentIP, ":") != NULL)
				{
					ret = getsockname(conn->fd, &addr6My, &len6);
				}
				else
				{
					ret= war_getsockname(conn->fd,(struct sockaddr*)&addrMy, &len);
				}
			#else
				int ret= war_getsockname(conn->fd,(struct sockaddr*)&addrMy, &len);
			#endif ////ASKEY SH mod end

				if (ret == 0)
				{
				    char tcpconnurl[64] = {0};
					//ASKEY SH mod/s
					char httpcre[3] = {0};
                                        do_uci_get(DM_HTTPConnectionRequestEnable,httpcre);
                                        tr_log( LOG_DEBUG, "httpcre: %s", httpcre);
                                        if(strcmp(httpcre,"0")==0)
                                        {
				    		sprintf(tcpconnurl," ");
						tr_log( LOG_DEBUG, "set lib crs_url");
						node_t node1,node2;
						
						lib_start_session();
    						lib_resolve_node(CRS_ENABLE , &node2 );
    						lib_set_value( node2, "0");
   						lib_end_session();
					}
					else
					{
					#ifdef __DEVICE_IPV6__ //ASKEY SH mod start
						//if(strstr(conn->host, ":") != NULL)
						if(strstr(currentIP, ":") != NULL)
						{
							inet_ntop(AF_INET6, &(addr6My.sin6_addr),addr6,INET6_ADDRSTRLEN);
							sprintf(tcpconnurl,"http://[%s]:%d",addr6,tcplistenport);
						}
						else
						{
				    		sprintf(tcpconnurl,"http://%s:%d",inet_ntoa(addrMy.sin_addr),tcplistenport);
						}
					#else
						sprintf(tcpconnurl,"http://%s:%d",inet_ntoa(addrMy.sin_addr),tcplistenport);
					#endif //ASKEY SH mod end
					}
					//ASKEY SH mod/e
					tr_log( LOG_NOTICE, "Set tcpconnect URL: %s", tcpconnurl);
					char oldurl[64] = {0};
					do_uci_get(DM_ConnectionRequestURL,oldurl);
					tr_log( LOG_NOTICE, "tcpconnect oldurl: %s", oldurl);
					if (strcasecmp(oldurl, tcpconnurl) != 0)
					{
					   system("echo \"***********************\" > /dev/console");
					   system("echo \"set new ConnectionRequestURL!!! \" > /dev/console");
					   system("echo \"***********************\" > /dev/console");
					   do_uci_set(DM_ConnectionRequestURL, tcpconnurl);
				       do_uci_commit("trconf");
					   value_change( CRS_URL, tcpconnurl ); //ASKEY SH add
					}
				}	
				/* askey wangzheng 2015-07-29 e: add tcp connection request url */
                break;
            } else {
                tr_log( LOG_ERROR, "Connect to server(%s) failed: %s", conn->host, war_sockstrerror( war_getsockerror() ) );
                war_sockclose( conn->fd );
                conn->fd = -1;
            }
        } while( ( res = res->ai_next ) != NULL );

        freeaddrinfo( ressave );
    }
#endif
#ifdef __ENABLE_SSL__

    if( conn->fd >= 0 ) {
        block_socket( conn->fd );
    }

    if( conn->fd >= 0 && war_strcasecmp( proto, "https" ) == 0 ) {
        conn->secure = 1;

        if( setup_ssl_connection( conn ) != 0 ) {
            war_sockclose( conn->fd );
            conn->fd = -1;
        }
    }

#endif

    if( conn->fd >= 0 ) {
        nonblock_socket( conn->fd );
    }

    return conn->fd;
}


void tr_disconn( struct connection *conn )
{
#ifdef __ENABLE_SSL__
    destroy_ssl_connection( conn );
#endif

    if( conn->fd >= 0 ) {
        war_sockclose( conn->fd );
        conn->fd = -1;
    }
}


int tr_conn_recv( struct connection *conn, void *buf, int len )
{
#ifdef __ENABLE_SSL__

    if( conn->ssl ) {
#if 0
        int ret;
        bzero( buf, len );
        ret = SSL_read( conn->ssl, buf, len );
        tr_log( LOG_DEBUG, "recv ssl: \n%s(end)", ( char * ) buf );
        return ret;
#else
        return SSL_read( conn->ssl, buf, len );
#endif
    } else
#endif
    {
#if 0
        int ret;
        bzero( buf, len );
        ret = recv( conn->fd, buf, len, 0 );
        tr_log( LOG_DEBUG, "recv: \n%s(end)", ( char * ) buf );
        return ret;
#else
        return recv( conn->fd, buf, len, 0 );
#endif
    }
}

int tr_conn_send( struct connection *conn, const void *buf, int len )
{
//ASKEEY Remove debug
#if 0 //def CODE_DEBUG
    tr_log( LOG_DEBUG, "Send to peer: \n%s", ( char * ) buf );
#endif
#ifdef __ENABLE_SSL__

    if( conn->ssl ) {
        return SSL_write( conn->ssl, buf, len );
    } else
#endif
        return send( conn->fd, buf, len, 0 );
}
