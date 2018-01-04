#include "log.h"
#include "hex.h"
#include "tr.h"
#include "tr_strings.h"
#include "inform.h"
#include "event.h"
#include "session.h"
#include "xmpp.h"
#include "cli.h"
#include "ev_sched.h"
#include "network.h"
#include "tr_lib.h"
#include "war_string.h"
#include "war_socket.h"
#include "war_time.h"
#include "war_errorcode.h"
#include "spv.h"
#include "tr_uciconfig.h"

static void notify_connection_enable_changed( const char *path, const char *new )
{
        printf("\n notify_connection_enable_changed ");
}


void master_destroy( struct sched *sc )
{
    if( sc ) {
        sc->need_destroy = 1;

        if( sc->fd >= 0 ) {
            war_sockclose( sc->fd );
            sc->fd = -1;
        }

        if( sc->pdata ) { /* Destroy slave */
            struct sched *slave;
            slave = ( struct sched * )( sc->pdata );
            slave->pdata = NULL;
            slave->need_destroy = 1;

            if( slave->fd >= 0 ) {
                war_sockclose( slave->fd );
                slave->fd = -1;
            }

            sc->pdata = NULL;
        }

        if( sc == xmpp_master ) {
            xmpp_master = NULL;
        }
    }
}


void x_build_CR_header(char* xMsg )
{
        x_msg_hdr *hdr= ( x_msg_hdr * ) xMsg;

        hdr->type = CR_RESP;
        hdr->len=0;
    return;
}

void x_add_option(X_OPTION_TYPE opType , char *xMsg, const char* value )
{
        x_msg_hdr *hdr= (x_msg_hdr *) xMsg;
        x_msg_option *optPtr;
        optPtr =( x_msg_option *) ( xMsg + hdr->len + X_MSG_HDR_SZ);

        //set the hdr len taking the new option into account
        hdr->len += strlen(value) + 1 + X_OPTION_HDR_SZ;

        //populate the new option
        optPtr->type = opType;
        optPtr->len = strlen(value)+1;
        strcpy(optPtr->value, value );
        optPtr->value[optPtr->len]='\0';
        return ;
}


int create_cr_res_msg(char *xMsg ,char *errstr, char *username, char *password, char *id, const char* to)
{
        x_msg_option *opt;
        int len;

        x_build_CR_header(xMsg );
        x_add_option(X_USERNAME, xMsg, username );
        x_add_option(X_PASSWORD, xMsg, password );
        x_add_option(X_CRID, xMsg,id );
        x_add_option(X_FROM, xMsg,to );
        x_add_option(X_STATUS, xMsg,errstr );
    tr_log(LOG_DEBUG,"\n len : %d",((x_msg_hdr *) xMsg)->len );
        return( ((x_msg_hdr *) xMsg)->len + X_MSG_HDR_SZ) ;
}

void x_get_CR_header(char* xMsg,x_msg_hdr **hdr  )
{
        *hdr= ( x_msg_hdr * ) xMsg;

        return;
}

char * x_get_option(X_OPTION_TYPE opType , char *xMsg )
{
        x_msg_hdr *hdr= (x_msg_hdr *) xMsg;
        x_msg_option *optPtr;
        int i=0;

        optPtr =( x_msg_option *) hdr->value;

        for(i=hdr->len; i>0 ;optPtr=( x_msg_option *)(((char*)optPtr)+optPtr->len + X_OPTION_HDR_SZ) )
        {
                if(optPtr->type == opType )
                {
                        printf("\n match : %s",  (char*)optPtr->value);
                        return (char*)optPtr->value;
                }

                i -= optPtr->len + X_OPTION_HDR_SZ;
        }
        return NULL;
}



int x_change_value_connection(const char *cmd, char *value, char*inform,int instance)
{
        int ret;
        char prevVal[X_BUFSIZE]={0};
        ret = do_uci_get(cmd, prevVal);

        if(ret == 0)
        {
                if(strcmp(value,prevVal ) == 0)
                        return 0;
        }
        printf("Setting [%s][%s]",cmd,value );
        ret = do_uci_set(cmd, value);

        if(ret)
        {
                printf("Error XMPP:Setting the status");
                //kill itself
                return -1;
        }

        ret = do_uci_commit(X_CONNECTION);
        if(ret)
        {
                //kill itself
                return -1;
        }

        // inform tr-069 of status change
        sprintf(cmd,"%s http://127.0.0.1:1234/value/change/ \"name=Device.XMPP.Connection.%d.%s&value=%s\"", SEND_UCI_TO_CLI ,instance,inform ,value );
        system(cmd);
        return 0;
}




int x_get_allowed_jabberids(char array[][256] )
{
        int ret=0,i=0;
        char value[X_JID_SZ*32]={0},*pjid=NULL;

        tr_log(LOG_DEBUG, "Enter x_get_allowed_jabberids");

        ret = do_uci_get(DM_ConnReqAllowedJabberIDs, value);
        if(ret)
        {
                return;
        }

        //string is empty, all JIDs are allowed
        if(strcmp(value,"")==0 )
                return 0;

        pjid=strtok( value, ",");

        if(pjid != NULL )
                memcpy(array[i],pjid, strlen(pjid)+1 );
        else
                return -1;

        tr_log(LOG_DEBUG, "jabberid : %s",array[i] );

        i++;
        while(1)
        {
                pjid = strtok( NULL, ",");
                if(pjid != NULL )
                        memcpy(array[i],pjid, strlen(pjid)+1 );
                else
                        break;

                tr_log(LOG_DEBUG, "jabberid : %s",array[i] );

                i++;
        }
        return i;
}

int isBareJid( char *jarray)
{
        if(strstr( jarray, "/")==NULL)
                return 1;
        else
                return 0;
}


int x_get_cr_username_pwd( char *uname, char *pwd)
{
        int ret=0;

        ret = do_uci_get(DM_ConnectionRequestUsername , uname);
        if(ret)
        {
                return -1;
        }

        ret = do_uci_get(DM_ConnectionRequestPassword , pwd);
        if(ret)
        {
                return -1;
        }

        return 0;
}



void xmpp_detecting_readable( struct sched *sc )
{
    char xbuf[X_BUFSIZE];
    int res,n,xbuflen;
    socklen_t clientlen=sizeof( struct sockaddr_in); /* byte size of client's address */
    struct sockaddr_in clientaddr; /* client addr */
    x_msg_hdr *hdr=NULL;

    n = recvfrom(sc->fd, xbuf, X_BUFSIZE, 0,
                 (struct sockaddr *) &clientaddr, &clientlen);
    if (n < 0)
    {
        tr_log(LOG_ERROR, "ERROR in recvfrom");
        return;
    }

   tr_log( LOG_DEBUG, "bytes(%d) recv from XMPP server on fd %d",n,sc->fd );

    x_get_CR_header(xbuf, &hdr);

        //only handle CR response
    if(hdr->type == CR_REQ )
    {
        int i,instance;
        char *status, *uname, *pwd, *id, *from, toJid[X_JID_SZ], *fromUsername, *fromDomain, *fromResource;

        id= x_get_option(X_CRID , xbuf );
        from= x_get_option(X_FROM , xbuf );
        memcpy(toJid, from, X_JID_SZ );

        uname = x_get_option(X_USERNAME , xbuf );
        pwd = x_get_option(X_PASSWORD , xbuf );
        if(uname && pwd )
        {
                char jabberIdList[32][X_JID_SZ]={0},*jarray=NULL ;
                int i=0, allowed=0,fromLen=strlen(from), count;
                tr_log(LOG_DEBUG, "\n from %s,%d ",from,fromLen );

                fromUsername=strtok( from, "@");

                fromDomain=strtok( NULL, "/");

                if(fromDomain)
                        fromResource = fromDomain + strlen(fromDomain) + 1;


                tr_log(LOG_DEBUG, "from uname : %s, domain : %s, resource : %s",fromUsername,fromDomain,fromResource );

                //match from allowed jabberid list
                count = x_get_allowed_jabberids(jabberIdList );
                tr_log(LOG_DEBUG, "\n count : %d jid %s",count, jabberIdList[0] );
                tr_log(LOG_DEBUG, "\n jid %s",jabberIdList[1] );

                if(count == 0 || count == -1)
                        allowed=1;
                else
                {
                        while(count > 0)
                        {
                                int len,isBare;
                                jarray=jabberIdList[i];
                                if( jarray==NULL)
                                        break;

                                isBare=isBareJid( jarray);
                                len=strlen( jarray);

                                if(!isBare  )
                                {
                                        tr_log(LOG_DEBUG, "\nJID is full [%s] [%s]", jarray,toJid);

                                        if(strcmp( jarray,toJid )==0)
                                        {
                                                tr_log(LOG_DEBUG, "\n is allowed [%s] [%s]", jarray,toJid );

                                                allowed=1;
                                                break;
                                        }
                                }
                                else
                                {
                                        char *username=NULL, *domain=NULL;

                                        tr_log(LOG_DEBUG, "\n JID is bare" );
                                        //get username and domain
                                        username=strtok( jarray, "@");
                                        if(username)
                                        {
                                                domain = jarray+strlen(username)+1;
                                                tr_log(LOG_DEBUG, "\n uname : %s, domain %s",username, domain );

                                                if(strcmp(username,fromUsername ) ==0 &&  strcmp(domain, fromDomain ) ==0)
                                                {
                                                        tr_log(LOG_DEBUG, "\n is allowed" );

                                                        //allowed
                                                        allowed=1;
                                                }
                                        }
                                }

                                i++;
                                count--;
                        }
                }

                if(allowed == 1)
                {
                        char validuname[X_CR_UNAME_SZ], validpwd[X_CR_PWD_SZ];

                        tr_log(LOG_DEBUG, "\n Matching CR Username and PWD" );

                        //now match the username password
                        if(x_get_cr_username_pwd( validuname, validpwd) !=0)
                                return;

                        tr_log(LOG_DEBUG, "\n uname [%s] - [%s]",validuname,uname );
                        tr_log(LOG_DEBUG, "\n pwd [%s] - [%s]",validpwd,pwd );

                        if(strcmp(uname,validuname )==0 && strcmp(pwd,validpwd)==0 )
            {
                                xbuflen = create_cr_res_msg(xbuf,"success", uname , pwd , id, toJid );
                            add_single_event( S_EVENT_CONNECTION_REQUEST );
                            create_session();
            }
                        else
                                xbuflen = create_cr_res_msg(xbuf,"not-authorized", uname , pwd , id, toJid );

                }
                else
                {
                        xbuflen = create_cr_res_msg(xbuf,"service-unavailable", uname , pwd , id, toJid );
                }
        }
        else
        {

        }

        if(xbuflen > 0 )
        {
                n = sendto( sc->fd, xbuf, xbuflen, 0, (struct sockaddr *) &clientaddr, clientlen);

                if (n < 0)
                    tr_log(LOG_ERROR, "ERROR in sendto(%d) on fd %d error : %d",xbuflen ,sc->fd,errno);
                else
                {
                        tr_log( LOG_DEBUG, "bytes(%d) sent to XMPP server",n );

                }
        }
    }
    else if( hdr->type == JID_NOTIF )
    {
        int i, instance;
        char *jid,*status,cmd[256];

        jid= x_get_option(X_JID , xbuf );
        status= x_get_option(X_STATUS , xbuf );
        instance= atoi(x_get_option(X_INSTANCE , xbuf ));
        tr_log( LOG_DEBUG, "Recv JID : %s, Status: %s",jid,status );
        //set the jabber ID
        sprintf(cmd,"%s%d.JabberID",XMPP_CON, instance );
        x_change_value_connection(cmd , jid, "JabberID",instance);
    }
    else
    {

    }
    //process the packet

    /* 
     * sendto: echo the input back to the client 
     */

}

void xmpp_detecting_timeout( struct sched *sc )
{
        tr_log( LOG_ERROR, "XMPP detecting timeout .. ");
        sc->timeout = current_time() + 60;
}



int launch_xmpp_listener()
{
        tr_log( LOG_ERROR, "Launching XMPP listener" );
        udp_listen_for_cr("0.0.0.0", 0);

        register_vct(CRS_USERNAME , notify_connection_enable_changed );

}


int x_init_xmpp(  node_t node, char *reversePort)
{
        int count,i;
        node_t *children = NULL;

        count = lib_get_children( node, &children );

        if( count > 0 ) {
                for( i = 0; i < count; i++ )
                {
                        tr_log( LOG_DEBUG, "Node name : %s", children[i]->name );
                        //restart the xmpp agents
                        x_xmpp_agent_restart( children[i]->name);
                }
        }
}


int     udp_listen_for_cr(char *ipStr, int port)
{
        struct sched *sc = NULL;
        int udp;
        struct sockaddr_in addr;
        int     len = sizeof(struct sockaddr),ret=0 ;
        char port_str[64], value[32];
        char *path = "Device.XMPP.Connection.";
        node_t node;


        tr_log( LOG_ERROR, "listening on %s, %d",ipStr,port );
        udp = tr_listen( ipStr, port, SOCK_DGRAM, 1 );
        getsockname( udp,(struct sockaddr *) &addr, &len );

        tr_log( LOG_ERROR, "XMPP : socket : %d, ip:%s, port%d", udp , inet_ntoa(addr.sin_addr),htons( addr.sin_port) );

    
    //make sure xmpp config file exists
        sprintf(port_str,"%d",htons( addr.sin_port) );
        //setting the port
        ret = do_uci_set( "xmpp.comm.port", port_str);
        if(ret)
        {
                tr_log(LOG_ERROR,"Error setting XMPP reverse port");
                exit(1);
        }


        ret = lib_resolve_node(path, &node);
        if( ret != 0 )
                exit(1);


        x_init_xmpp( node,port_str );

        sc = calloc( 1, sizeof( *sc ) );
        sc->fd = udp;

        if( sc ) {
            sc->type = SCHED_WAITING_READABLE;
            sc->timeout =  current_time()+60;
            sc->on_readable = xmpp_detecting_readable;
            sc->on_timeout = xmpp_detecting_timeout;
            sc->on_destroy = master_destroy;
#ifdef CODE_DEBUG
            sc->name = "XMPP client";
#endif
            add_sched( sc );
        }

        return 0;
}
