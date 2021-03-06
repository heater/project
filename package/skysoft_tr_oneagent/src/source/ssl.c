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
 * \file ssl.c
 *
 */
#ifdef __ENABLE_SSL__

#define AIC_TWC     1       // AIC modification for TWC acs

#include <string.h>
#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ssl23.h>
#include <openssl/ssl2.h>

#include "log.h"
#include "connection.h"
#include "ssl.h"
#include "war_string.h"
#include "network.h"
#include "tr_uciconfig.h" //ASKEY SH add
#include "apps.h" //ASKEY SH add

static char password[80] = "";
char ca_cert[FILE_PATH_LEN + 1] = "";
static char client_cert[FILE_PATH_LEN + 1] = "";
static char client_key[FILE_PATH_LEN + 1] = "";

#ifdef AIC_TWC
int  ssl_acs_TWC = 0;   // [AIC] SSL : 0 = 0 auth(TWC), 1 = 1-way auth(TWC), 2 = 2-way auth(CHT)
#endif

int set_ssl_config( const char *name, const char *value )
{
    if( war_strcasecmp( name, "SSLPassword" ) == 0 ) {
        war_snprintf( password, sizeof( password ), "%s", value );
    } else if( war_strcasecmp( name, "CACert" ) == 0 ) {
        war_snprintf( ca_cert, sizeof( ca_cert ), "%s", value );
    } else if( war_strcasecmp( name, "ClientCert" ) == 0 ) {
        war_snprintf( client_cert, sizeof( client_cert ), "%s", value );
    } else if( war_strcasecmp( name, "ClientKey" ) == 0 ) {
        war_snprintf( client_key, sizeof( client_key ), "%s", value );
    }

    return 0;
}


static int password_cb( char *buf, int buf_len, int rwflag, void *userdata )
{
    const char *pass;
    pass = ( const char * ) userdata;
    return strlen( pass ) > buf_len ? -1 : war_snprintf( buf, buf_len, "%s", pass );
}

static int verify_cb( int ok, X509_STORE_CTX *store )
{
    if( !ok ) {
        X509 *cert;
        int depth;
        int err;
        char data[256];
        cert = X509_STORE_CTX_get_current_cert( store );
        depth = X509_STORE_CTX_get_error_depth( store );
        err = X509_STORE_CTX_get_error( store );
        X509_NAME_oneline( X509_get_issuer_name( cert ), data, sizeof( data ) );
        X509_NAME_oneline( X509_get_subject_name( cert ), data, sizeof( data ) );
    }

    return ok;
}

void destroy_ssl_connection( struct connection *conn )
{
    if( conn->ssl ) {
        SSL_set_shutdown( conn->ssl, 2 );
        SSL_shutdown( conn->ssl );
        SSL_free( conn->ssl );
    }

    if( conn->ctx ) {
        SSL_CTX_free( conn->ctx );
    }

    conn->ssl = NULL;
    conn->ctx = NULL;
}

int setup_ssl_connection( struct connection *conn )
{
#ifdef AIC_TWC //ASKEY SH add start ==>TODO
	char dmacs[32] = {0};
	char canum[32] = {0};
	char caenbl[32] = {0};
	char caidname[256] = {0};
	char caenblname[256] = {0};
	char caid[32] = {0};
	int i = 0;
	char name[256] = {0};
	int ret = 0;

	do_uci_get(DM_X_CHARTER_COM_ACSIdentifier, dmacs);
	tr_log(LOG_DEBUG,"Device_ManagementServer.X_CHARTER_COM_ACSIdentifier=[%s]",dmacs);
	
	do_uci_get(DM_X_TWC_COM_RootCertificateNumberOfEntries, canum);
	tr_log(LOG_DEBUG,"Device_ManagementServer.X_TWC_COM_RootCertificateNumberOfEntries=[%s]",canum);
	for(i=1; i<=atoi(canum); i++)
	{
	#if 0
		sprintf(caidname, "trconf.Device_ManagementServer_X_TWC_COM_RootCertificate_template.X_CHARTER_COM_ACSIdentifier%d", i);		
		tr_log(LOG_DEBUG,"caidname=[%s]",caidname);
		do_uci_get(caidname, caid);
		tr_log(LOG_DEBUG,"caid=[%s]",caid);
		if(strcmp(caid,dmacs)==0){
	#endif
		if (strcmp(dmacs,"TWC") == 0)
		{
			tr_log(LOG_DEBUG,"write_vendor_file");
			write_vendor_file(i);
			sprintf(name, "%s%d", DMXt_Enabled, i);
			ret = readFromNonvolatileFlashFile(name,caenbl);
			if(ret)
				do_uci_get(name, caenbl);
		}
		else
		{
			sprintf(caenblname, "trconf.Device_ManagementServer_X_TWC_COM_RootCertificate_template.Enabled%d", i);
			do_uci_get(caenblname, caenbl);
		}
		tr_log(LOG_DEBUG,"caenbl=[%s]",caenbl);
		if(strcmp(caenbl,"1")==0){
			FILE *fp = NULL;
			char filename[256] = {0};
			sprintf(filename, "/oneagent/conf/ca%d", i);
			fp = fopen(filename,"r");
			if((fp != NULL) && (strcmp(dmacs,"TWC") == 0))
			{
				tr_log(LOG_DEBUG,"CA exist and TWC");
				ssl_acs_TWC=1;
				sprintf(ca_cert,"/oneagent/conf/ca%d.pem",i);
				fclose(fp);
				break;
			}
			if (fp != NULL)
				fclose(fp);
		}
		//}
	}
#endif //ASKEY SH add end
    conn->ssl = NULL;
    conn->ctx = NULL;

    if( SSL_library_init() != 1 ) {
        tr_log( LOG_ERROR, "Init ssl library failed!" );
        return -1;
    }

    SSL_load_error_strings();
#if 1
    conn->ctx = SSL_CTX_new( SSLv23_client_method() );

    if( conn->ctx == NULL ) {
        tr_log( LOG_ERROR, "Create SSL/TLS context failed" );
        return -1;
    } else {
        SSL_CTX_set_options( conn->ctx, SSL_OP_NO_SSLv2 );
    }

#else

    if( ( conn->ctx = SSL_CTX_new( SSLv3_method() ) ) == NULL ) {
        tr_log( LOG_WARNING, "Create SSLv3 context failed, try TLSv1" );

        if( ( conn->ctx = SSL_CTX_new( TLSv1_method() ) ) == NULL ) {
            tr_log( LOG_ERROR, "Create TLSv1 context failed" );
            return -1;
        }
    }

#endif
#ifdef AIC_TWC
    if (ssl_acs_TWC) {
        SSL_CTX_set_verify( conn->ctx, SSL_VERIFY_PEER, verify_cb );
        SSL_CTX_set_verify_depth( conn->ctx, 5 );
        tr_log( LOG_WARNING, "ACS_SSL Authentication enabled." );
    }
#else
#ifndef __OS_ANDROID
    SSL_CTX_set_verify( conn->ctx, SSL_VERIFY_PEER, verify_cb );
#else
    SSL_CTX_set_verify( conn->ctx, SSL_VERIFY_NONE, verify_cb );
#endif
    SSL_CTX_set_verify_depth( conn->ctx, 1 );
#endif 

#ifdef AIC_TWC
    if (ssl_acs_TWC != 0) 
#endif
    if( ca_cert[0] && SSL_CTX_load_verify_locations( conn->ctx, ca_cert, NULL ) != 1 ) {
        tr_log( LOG_ERROR, "Loading CA cert file failed" );
        goto error;
    }

    SSL_CTX_set_default_passwd_cb_userdata( conn->ctx, ( char * ) password );
    SSL_CTX_set_default_passwd_cb( conn->ctx, password_cb );

    if( client_cert[0] && SSL_CTX_use_certificate_file( conn->ctx, client_cert, SSL_FILETYPE_PEM ) != 1 ) {
        tr_log( LOG_ERROR, "Loading client cert file failed" );
    }

    if( client_key[0] && SSL_CTX_use_PrivateKey_file( conn->ctx, client_key, SSL_FILETYPE_PEM ) != 1 ) {
        tr_log( LOG_ERROR, "Loading client key file failed" );
    }

#ifdef AIC_TWC
    if (ssl_acs_TWC == 2) 
#endif
    if( SSL_CTX_check_private_key( conn->ctx ) != 1 ) {
        tr_log( LOG_ERROR, "Check private key and cert file failed" );
    }

    //make block socket before SSL_connect()
    if( ( conn->ssl = SSL_new( conn->ctx ) ) == NULL || SSL_set_fd( conn->ssl, conn->fd ) != 1 || SSL_connect( conn->ssl ) != 1 ) {
        tr_log( LOG_ERROR, "SSL socket connection failed: %s", ERR_error_string( ERR_get_error(), NULL ) );
        goto error;
    }

    /* Get the server's certificate (optional) */
    {
        X509 *server_cert;
        char cn[sizeof( conn->host )] = "";

#ifdef AIC_TWC
        if (ssl_acs_TWC != 0) 
#endif
        if( SSL_get_verify_result( conn->ssl ) != X509_V_OK ) {
            tr_log( LOG_ERROR, "Certificate doesn't verify: %s", ERR_error_string( ERR_get_error(), NULL ) );
            goto error;
        }

        server_cert = SSL_get_peer_certificate( conn->ssl );

        if( server_cert != NULL ) {
            X509_NAME_get_text_by_NID( X509_get_subject_name( server_cert ), NID_commonName, cn, sizeof( cn ) );
            X509_free( server_cert );
#ifdef AIC_TWC
            tr_log( LOG_ERROR, "Server certificate CommonName = %s", cn);             
#endif

            /* comment this to fix ssl connection issue, as workssys acs changed domain name */
            /*
            if( strcasecmp( cn, conn->host ) ) {
                tr_log( LOG_ERROR, "Server certificate CommonName(%s) does not math host name(%s)", cn, conn->host );
                goto error;
            }
            */
        } else {
            tr_log( LOG_ERROR, "Get server certificate failed" );
            goto error;
        }
    }
    return 0;
error:
    destroy_ssl_connection( conn );
    return -1;
}

#endif
