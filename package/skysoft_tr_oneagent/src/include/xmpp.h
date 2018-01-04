#ifndef _XMPP_H
#define _XMPP_H

#define SEND_UCI_TO_CLI "/oneagent/senducitocli"

typedef enum _REQ_TYPE
{
        CR_REQ = 0,
        CR_RESP,
        JID_NOTIF
}REQ_TYPE;

typedef struct _x_msg_hdr
{
        char type;
        char len;
        char value[0];
}x_msg_hdr;

typedef enum _X_OPTION_TYPE
{
        X_USERNAME = 0,
        X_PASSWORD,
        X_CRID,
        X_FROM,
        X_STATUS,
        X_JID,
        X_INSTANCE
}X_OPTION_TYPE;
typedef struct _x_msg_option
{
        char type;
        char len;
        char value[0];
}x_msg_option;

#define X_BUFSIZE 1024
#define X_OPTION_HDR_SZ 2 //8 bytes
#define X_MSG_HDR_SZ 2 //8 bytes
#define X_JID_SZ 256
#define X_JID_UNAME_SZ 256
#define X_JID_DOMAIN_SZ 64
#define X_JID_RESOURCE_SZ 64
#define X_CR_UNAME_SZ 256
#define X_CR_PWD_SZ 256

void master_destroy( struct sched *sc );
struct sched *xmpp_master = NULL;

#endif
