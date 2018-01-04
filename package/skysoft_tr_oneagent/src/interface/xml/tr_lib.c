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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#include "war_thread.h"
#include "xml.h"
#include "tr.h"
#include "log.h"
#include "tr_strings.h"
#include "tr_lib.h"
#include "war_string.h"
#include "war_time.h"
#include "war_errorcode.h"
#include "event.h"
#include "sendtocli.h"
#include "cli.h"
#include "inform.h"
#include "do.h"

#include "tr69_handler.h"
#include "ucimap.h"
#include "fw_upgrade.h"
#include "apps.h"

#ifdef TR196
#include "cm.h"
#endif

#ifdef __V4_2
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifdef USE_DYNAMIC
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <dlfcn.h>
#else
#ifndef __DYNAMIC_H
#include "dynamic.h"
#endif
#endif
#endif

#ifdef ALIAS
struct alias_map *alias_head = NULL;
struct alias_map *alias_prev = NULL;
#endif //ALIAS
static struct node *root = NULL; /* MOT root node */
static int count = 0; /* The session reference counter */
static char xml_file_path[256];
static int change = 0; /* Flag indicates if or not the MOT has been changed */
static int factory_resetted = 0; /* Flag indicates if or not factory is required in real world device, it MUST be a permanent flag that can cross reboot. */
//ASKEY SH add/s
int portmappingmodifyflag = 0;
int staticipmodifyflag = 0;
int routingipv4modifyflag = 0;
int qosclassficationmodifyflag = 0;
int qosappmodifyflag = 0;
int qosqueuemodifyflag = 0;
int qosshapermodifyflag = 0;
int GREFiltermodifyflag = 0;
int GREInterfacemodifyflag = 0;
int dhcpserveroptionsmodifyflag = 0;
int dhcpv6Sentoptionmodifyflag= 0;
int xmppconnectionmodifyflag = 0;

int processMaxInstanceNum = 0;

extern a_LanmappingInfo lan_map[];

void x_get_current_time(char *tstr,int len )
{
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	strftime(tstr, len, "%c", tm);
	tr_log(LOG_DEBUG,"current time %s",tstr );
}

void x_xmpp_agent_stop(int instance )
{
	int ret=0;
	char cmd[256]={0},pid_str[64]={0};

	sprintf(cmd,"%s%d.clientpid",XMPP_CON, instance );

	ret = do_uci_get( cmd, pid_str);
	tr_log(LOG_DEBUG,"cmd_str[%s][%s], ret %d",cmd,pid_str,ret );

	if(ret)
	{
		return;
	}

	tr_log(LOG_DEBUG,"bringdown xmpp connection");
	sprintf(cmd,"kill -9 %s &",pid_str );
	system(cmd);
	return;
}

void x_xmpp_agent_start(int instance )
{
	int ret=0,allowedInstance;
	char value[256]={0};
	char *index=NULL;
	char cmd[256]={0};

	//get the enabled status
	sprintf(cmd,"%s%d.Enable",XMPP_CON, instance );

	ret = do_uci_get( cmd, value);
	if(ret)
	{
			return;
	}
	tr_log(LOG_DEBUG,"cmd_str[%s][%s]",cmd,value);

	//if disabled then stop
	if((strcmp(value, "0" )==0)||(strcmp(value, "false" )==0) )
	{
		return;
	}
 

	//check if the connection is allowed
	ret = do_uci_get(DM_ConnReqXMPPConnection , value);
	tr_log(LOG_DEBUG,"cmd_str[%s][%s], ret %d",DM_ConnReqXMPPConnection ,value,ret );

	if(ret)
	{
		return;
	}

	tr_log(LOG_DEBUG,"path_name[%s]",value);
	index = parseTemplate(value,".Connection." );
	if(index)
	{
		allowedInstance = atoi(index);
		tr_log(LOG_DEBUG,"allowed instance[%d] instance[%d]", allowedInstance, instance );

		if(allowedInstance == instance )
		{
			tr_log(LOG_DEBUG,"bringup xmpp connection[%d]",instance);
			sprintf(cmd,"xmpp_agent %d &",instance);
			system(cmd);
		}
		return;
	}
}


void x_xmpp_agent_restart(char *index)
{
	int instance=atoi(index),ret;
	char value[32]={0},cmd[256]={0};

	//get the enabled status
	sprintf(cmd,"%s%d.Enable",XMPP_CON, instance );

	ret = do_uci_get( cmd, value);
	if(ret)
	{
		return;
	}
	tr_log(LOG_DEBUG,"cmd_str[%s][%s]",cmd,value);

	//if disabled then stop
	if((strcmp(value, "0" )==0)||(strcmp(value, "false" )==0) )
	{
		x_xmpp_agent_stop(instance );
	}
	//if enabled then restart
	if((strcmp(value, "1" )==0)||(strcmp(value, "true" )==0) )
	{
		x_xmpp_agent_stop(instance );
		x_xmpp_agent_start(instance );
	}
}

//ASKEY SH add/e

static void xml_tag2node( struct xml *tag, struct node *n );

static struct node *last_child( struct node *parent );

static struct node *xml2tree( const char *file_path );
static unsigned int nocc_str2code( const char *str );
//static unsigned int type_str2code(const char *str);
//static const char *type_code2str(unsigned int code);
static int __tree2xml( struct node *tree, FILE *fp, int *level );
static int tree2xml( struct node *tree, const char *file_path );
static void lib_destroy_tree( node_t node );

static int set_logic_relative_values( node_t node, char *alias );

#ifdef __V4_2

#define MAX_LOCATE_DEPTH 4
#define PATH_LEN 256

void *handle; /* Dynamic library handle */

/* Define data_type */
#define VALUE_TYPE_ANY                  0x00
#define VALUE_TYPE_STRING               0x01
#define VALUE_TYPE_INT                  0x02
#define VALUE_TYPE_UNSIGNED_INT         0x03
#define VALUE_TYPE_BOOLEAN              0x04
#define VALUE_TYPE_DATE_TIME            0x05
#define VALUE_TYPE_BASE_64              0x06

/*!
 * \brief To generate a \b locate from a path
 *
 * To generate a \b location from \a path, the result will be saved in the \a location
 *
 * \param path The path which the calculation's based on
 * \param locate The pointer points to the memory which stores the result
 * \depth depth The number of locate cells in the memory pointed by \a locate
 *
 * \return 0
 */

int path_2_locate( const char *path, int *locate, int depth )
{
    int i;
    char *d;
    char tmp_name[PATH_LEN];

    for( i = 0; i < depth; i++ ) {
        locate[i] = 0;
    }

    i = 0;
    d = strchr( path, '.' );

    while( d && i < depth ) {
        if( *path <= '9' && *path > '0' ) {
            if( d - path >= PATH_LEN ) {
                tr_log( LOG_NOTICE, "Too long object/paraemter node name" );
                break;
            }

            memcpy( tmp_name, path, d - path );
            tmp_name[d - path] = '\0';
            locate[i] = atoi( tmp_name );
            i++;
        }

        path = d + 1;
        d = strchr( path, '.' );
    }

    return 0;
}

/*!
 * \brief Generate the full name
 *
 * Generate the full name
 *
 * \param p The target parameter
 * \param full_name Recive the full name
 *
 * \return AGENT_SUCCESS
 */

int get_param_full_name( struct node *p, char full_name[] )
{
    struct node *o;
    char tmp_name[PATH_LEN];
    sprintf( full_name, "%s", p->name );
    o = p->parent;

    while( o ) {
        sprintf( tmp_name, "%s.", o->name );
        strcat( tmp_name, full_name );
        sprintf( full_name, "%s", tmp_name );
        o = o->parent;
    }

    return 0;
}

#endif //__V4_2

#ifdef ALIAS
TR_LIB_API struct alias_map *lib_get_alias_head() {
    return alias_head;
}
#endif //ALIAS

static void xml_tag2node( struct xml *tag, struct node *n )
{
    int i;

    for( i = 0; i < tag->attr_count; i++ ) {
        if( war_strcasecmp( tag->attributes[i].attr_name, "name" ) == 0 ) {
            war_snprintf( n->name, sizeof( n->name ), "%s", tag->attributes[i].attr_value );
        } else if( war_strcasecmp( tag->attributes[i].attr_name, "rw" ) == 0 ) {
            if( war_strcasecmp( tag->attributes[i].attr_value, "1" ) == 0 || war_strcasecmp( tag->attributes[i].attr_value, "true" ) == 0 ) {
                n->rw = 1;
            }
        } else if( war_strcasecmp( tag->attributes[i].attr_name, "getc" ) == 0 ) {
            if( war_strcasecmp( tag->attributes[i].attr_value, "1" ) == 0 || war_strcasecmp( tag->attributes[i].attr_value, "true" ) == 0 ) {
                n->getc = 1;
            }
        } else if( war_strcasecmp( tag->attributes[i].attr_name, "noc" ) == 0 ) {
            n->noc = atoi( tag->attributes[i].attr_value );
        } else if( war_strcasecmp( tag->attributes[i].attr_name, "nocc" ) == 0 ) {
            n->nocc = nocc_str2code( tag->attributes[i].attr_value );
        } else if( war_strcasecmp( tag->attributes[i].attr_name, "nin" ) == 0 ) {
            n->nin = atoi( tag->attributes[i].attr_value );
        } else if( war_strcasecmp( tag->attributes[i].attr_name, "il" ) == 0 ) {
            n->il = atoi( tag->attributes[i].attr_value );
        } else if( war_strcasecmp( tag->attributes[i].attr_name, "acl" ) == 0 ) {
            war_snprintf( n->acl, sizeof( n->acl ), "%s", tag->attributes[i].attr_value );
        } else if( war_strcasecmp( tag->attributes[i].attr_name, "type" ) == 0 ) {
            //n->type = type_str2code(tag->attributes[i].attr_value);
            war_snprintf( n->type, sizeof( n->type ), "%s", tag->attributes[i].attr_value );
#ifdef __V4_2
        } else if( war_strcasecmp( tag->attributes[i].attr_name, "add" ) == 0 ) {
            n->dev.obj.add = dlsym( handle, tag->attributes[i].attr_value );
        } else if( war_strcasecmp( tag->attributes[i].attr_name, "del" ) == 0 ) {
            n->dev.obj.del = dlsym( handle, tag->attributes[i].attr_value );
        } else if( war_strcasecmp( tag->attributes[i].attr_name, "get" ) == 0 ) {
            n->dev.param.get = dlsym( handle, tag->attributes[i].attr_value );
        } else if( war_strcasecmp( tag->attributes[i].attr_name, "set" ) == 0 ) {
            n->dev.param.set = dlsym( handle, tag->attributes[i].attr_value );
#endif
        }

#ifdef __V4_2

        if( dlerror() != NULL ) {
            tr_log( LOG_ERROR, "dlerror" );
            dlclose( handle );
            exit( -1 );
        }

#endif
    }

    // if(tag->value)  //gspring: segmentation fault
    if( tag->value[0] != '\0' ) {
        war_snprintf( n->value, sizeof( n->value ), "%s", tag->value );
    }

    // malloc listeners space
    n->listener_count = 0;
    n->listener_addr = ( char ** ) malloc( 16 * sizeof( char * ) );

    if( n->listener_addr == NULL ) {
        tr_log( LOG_ERROR, "failed to create memory space for n->listener_addr" );
    }

    for( i = 0; i < 16; i++ ) {
        n->listener_addr[i] = ( char * ) malloc( sizeof( ( struct listener * ) 0 )->addr * sizeof( char ) );

        if( n->listener_addr[i] == NULL ) {
            tr_log( LOG_ERROR, "failed to create memory space for n->listener_addr[%d]", i );
        }
    }
}

static struct node *last_child( struct node *parent ) {

    struct node *child = parent->children;

    while( child && child->brother ) {
        child = child->brother;
    }

    return child;
}

static struct node *xml2tree( const char *file_path ) {

    struct node *internal_root = NULL;

    struct node *cur = NULL;
    FILE *fp;
    char *buf = NULL;
    size_t len = 0;

#ifdef __V4_2
    char dlpath[PATH_LEN];
    tr_full_name( "libdev.so", dlpath, sizeof( dlpath ) );
    handle = dlopen( dlpath, RTLD_LAZY );

    if( handle == NULL ) {
        exit( -1 );
    }

#endif

    fp = tr_fopen( file_path, "r" );

    if( fp == NULL ) {
        char bak[256];
        war_snprintf( bak, sizeof( bak ), "%s.bak", file_path );
        fp = tr_fopen( bak, "r" );
    }

    if( fp ) {
        fseek( fp, 0, SEEK_END );
        len = ftell( fp );
        fseek( fp, 0, SEEK_SET );
        buf = malloc( len + 1 );

        if( buf == NULL ) {
            tr_log( LOG_ERROR, "Out of memory!" );
        } else {
            struct xml tag;
            char *left;
            tr_fread( buf, 1, len, fp );
            buf[len] = '\0';
            left = buf;

            while( xml_next_tag( &left, &tag ) == XML_OK ) {
                if( war_strcasecmp( tag.name, "node" ) == 0 ) {
                    if( internal_root == NULL ) {
                        internal_root = calloc( 1, sizeof( *internal_root ) );

                        if( internal_root == NULL ) {
                            tr_log( LOG_ERROR, "Out of memory!" );
                            break;
                        } else {
                            xml_tag2node( &tag, internal_root );
                        }

                        cur = internal_root;
                    } else {
                        struct node *n;
                        struct node *brother;
                        n = calloc( 1, sizeof( *n ) );

                        if( n == NULL ) {
                            tr_log( LOG_ERROR, "Out of memory!" );
                            break;
                        } else {
                            xml_tag2node( &tag, n );
                        }

                        n->parent = cur;
                        brother = last_child( n->parent );

                        if( brother ) {
                            brother->brother = n;
                        } else {
                            cur->children = n;
                        }

                        cur = n;
#ifdef ALIAS
                        struct alias_map *alias_current = NULL;
						/* ASKEY ADD/s */
                        if( war_strcasecmp( n->name, "Alias" ) == 0)
                        {
                           tr_log( LOG_DEBUG, "( n->parent )->name %s path %s ", ( n->parent )->name, lib_node2path( n->parent ));
						   if  (node_is_instance_askey( n->parent ) == 1 )
						   {
						       tr_log( LOG_DEBUG, "( n->parent )->name %s is askey instance", ( n->parent )->name);
						   }
                        }
						/* ASKEY ADD/e */
                        if( war_strcasecmp( n->name, "Alias" ) == 0 && war_strcasecmp( ( n->parent )->name, "template" ) != 0 && node_is_instance_askey( n->parent ) == 1 ) {
                            alias_current = ( struct alias_map * ) malloc( sizeof( struct alias_map ) );
                            alias_current->next = NULL;
                            war_snprintf( alias_current->uri, sizeof( alias_current->uri ), "%s", lib_node2path( n->parent ) );
                            war_snprintf( alias_current->alias, sizeof( alias_current->alias ), "%s[%s].", lib_node2path( ( n->parent )->parent ), n->value );

							tr_log( LOG_DEBUG, "alias_current->uri %s alias_current->alias %s",alias_current->uri,alias_current->alias);
							
                            if( alias_head == NULL ) {
                                alias_head = alias_current;
                            } else {
                                alias_prev->next = alias_current;
                            }

                            alias_prev = alias_current;
                        }

#endif //ALIAS
                    }
                } else if( war_strcasecmp( tag.name, "/node" ) == 0 ) {
                    cur = cur->parent;

                    if( cur == NULL ) {
                        break;
                    }
                } else if( war_strcasecmp( tag.name, "?xml" ) ) {
                    tr_log( LOG_WARNING, "Invalid XML tag!" );
                    break;
                }
            }
        }
    }

#ifdef ALIAS
    add_static_inform_parameter( "InformParameter", Alias_Based_Addressing );
#endif //ALIAS

    if( fp ) {
        fclose( fp );
    }

    if( buf ) {
        free( buf );
    }

#if 0 /* Printf xml config file in console */

    if( internal_root ) {
        int level = 0;
        __tree2xml( internal_root, stdout, &level );
    }

#endif


    return internal_root;
}

static char *nocc_table[] = {"", "0", "1", "2", "!0", "!1", "!2"};

static unsigned int nocc_str2code( const char *str )
{
    unsigned int i;

    for( i = sizeof( nocc_table ) / sizeof( nocc_table[0] ) - 1; i > 0; i-- ) {
        if( strcmp( ( char * ) str, nocc_table[i] ) == 0 ) {
            return i;
        }
    }

    return 0;
}

static const char *nocc_code2str( unsigned int code )
{
    if( code < sizeof( nocc_table ) / sizeof( nocc_table[0] ) && code >= 0 ) {
        return nocc_table[code];
    } else {
        return nocc_table[0];
    }
}

/*
static char * type_table[] = {"string", "int", "unsignedInt", "boolean", "dateTime", "base64", "node", "any"};

static unsigned int type_str2code(const char *str)
{
int i;

for(i = sizeof(type_table) / sizeof(type_table[0]) - 1; i >= 0; i--) {
if(strcmp((char *)str, type_table[i]) == 0) {
return i;
}
}

tr_log(LOG_WARNING, "type of %s incorrect", str);
return 0;
}

static const char *type_code2str(unsigned int code)
{
if(code < sizeof(type_table) / sizeof(type_table[0]) && code >= 0)
return type_table[code];
else
return type_table[0];
}
*/

static int __tree2xml( struct node *tree, FILE *fp, int *level )
{
#ifdef __V4_2
    int i;
    Dl_info info1, info2;
    info1.dli_fname = 0;
    info1.dli_sname = 0;
    info1.dli_fbase = 0;
    info1.dli_saddr = 0;
    info2.dli_fname = 0;
    info2.dli_sname = 0;
    info2.dli_fbase = 0;
    info2.dli_saddr = 0;

    if( !tree || !fp ) {
        return -1;
    }

    for( i = *level; i > 0; i-- ) {
        fprintf( fp, "    " );
    }

    if( strcmp( tree->type, "node" ) == 0 ) {
        struct node *n;

        if( tree->rw ) {
            if( war_strcasecmp( tree->name, "template" ) == 0 ) {
                fprintf( fp, "<node name='template' rw='1' type='node'>\n" );
            } else {
                if( !tree->dev.obj.add || !tree->dev.obj.del ) {
                    tr_log( LOG_NOTICE, "add del function pointer is null!" );
                    fprintf( fp, "<node name='%s' rw='1' type='node'>\n'", tree->name );
                } else {
                    if( dladdr( tree->dev.obj.add, &info1 ) == 0 || info1.dli_saddr != tree->dev.obj.add ) {
                        tr_log( LOG_ERROR, "Resole add() function name failed!" );
                    } else if( dladdr( tree->dev.obj.del, &info2 ) == 0 || info2.dli_saddr != tree->dev.obj.del ) {
                        tr_log( LOG_ERROR, "Resole del() function name failed!" );
                    } else {
                        fprintf( fp, "<node name='%s' rw='1' nin='%d' il='%d' type='node' add='%s' del='%s'>\n", tree->name, tree->nin, tree->il, info1.dli_sname, info2.dli_sname );
                    }
                }
            }
        } else {
            fprintf( fp, "<node name='%s' rw='0' type='node'>\n", tree->name );
        }

        ( *level ) ++;

        for( n = tree->children; n; n = n->brother ) {
            __tree2xml( n, fp, level );
        }

        ( *level )--;

        for( i = *level; i > 0; i-- ) {
            fprintf( fp, "    " );
        }

        fprintf( fp, "</node>\n" );
    } else {
        char *v = xml_str2xmlstr( tree->value );

        if( dladdr( ( void * ) tree->dev.param.get, &info1 ) && dladdr( ( void * ) tree->dev.param.set, &info2 ) ) {  // info1.dli_saddr != tree->dev.param.get)
            fprintf( fp, "<node name='%s' rw='%d' getc='%d' noc='%d' nocc='%s' acl='%s' type='%s' get='%s' set='%s'>%s</node>\n",
                     tree->name, tree->rw, tree->getc, tree->noc, nocc_code2str( tree->nocc ), tree->acl, tree->type, info1.dli_sname, info2.dli_sname, v ? v : tree->value );
        } else {
            fprintf( fp, "<node name='%s' rw='%d' getc='%d' noc='%d' nocc='%s' acl='%s' type='%s' get='%s'>%s</node>\n",
                     tree->name, tree->rw, tree->getc, tree->noc, nocc_code2str( tree->nocc ), tree->acl, tree->type, info1.dli_sname, v ? v : tree->value );
        }

        if( v ) {
            free( v );
        }
    }

    return 0;
#else
    int i;

    for( i = *level; i > 0; i-- ) {
        fprintf( fp, "    " );
    }

    //if(tree->type == TYPE_NODE) {
    if( strcmp( tree->type, "node" ) == 0 ) {
        struct node *n;

        if( tree->rw ) {
            fprintf( fp, "<node name='%s' rw='1' nin='%d' il='%d' type='node'>\n", tree->name, tree->nin, tree->il );
        } else {
            fprintf( fp, "<node name='%s' rw='0' type='node'>\n", tree->name );
        }

        ( *level ) ++;

        for( n = tree->children; n; n = n->brother ) {
            __tree2xml( n, fp, level );
        }

        ( *level )--;

        for( i = *level; i > 0; i-- ) {
            fprintf( fp, "    " );
        }

        fprintf( fp, "</node>\n" );
    } else {
        char *v = xml_str2xmlstr( tree->value );
        fprintf( fp, "<node name='%s' rw='%d' getc='%d' noc='%d' nocc='%s' acl='%s' type='%s'>%s</node>\n",
                 tree->name, tree->rw, tree->getc, tree->noc, nocc_code2str( tree->nocc ), tree->acl, tree->type, v ? v : tree->value );

        //tree->name, tree->rw, tree->getc, tree->noc, nocc_code2str(tree->nocc), tree->acl, type_code2str(tree->type), tree->value);
        if( v ) {
            free( v );
        }
    }

    return 0;
#endif
}

static int tree2xml( struct node *tree, const char *file_path )
{
    FILE *fp;
    int res;
    int level = 0;

    if( !tr_exist( FLAG_TREE_TO_XML ) ){
        tr_create( FLAG_TREE_TO_XML );
    }

    if( factory_resetted ) {
        /*
         * Factory reset the device. In this sample, we just replace the xml file
         * with the default xml file.
         */
        char bak[512];
        FILE *src, *dst;
        war_snprintf( bak, sizeof( bak ), "%s.bak", file_path );
        dst = tr_fopen( file_path, "w" );
        src = tr_fopen( bak, "r" );

        if( dst && src ) {
            int len;

            while( ( len = fread( bak, 1, sizeof( bak ), src ) ) > 0 ) {
                if( tr_fwrite( bak, 1, len, dst ) != len ) {
                    tr_log( LOG_ERROR, "Write xml file failed: %s", war_strerror( war_geterror() ) );
                    break;
                }
            }
        } else {
            tr_log( LOG_ERROR, "fopen xml_file fail: %s", war_strerror( war_geterror() ) );
        }

        if( dst ) {
            fclose( dst );
        }

        if( src ) {
            fclose( src );
        }

        factory_resetted = 0;
        return 0;
    }

    fp = tr_fopen( file_path, "w" );

    if( fp == NULL ) {
        return -1;
    }

    fprintf( fp, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" );
    res = __tree2xml( tree, fp, &level );
    fflush( fp );
    fclose( fp );
	
    system("sync");

    if( tr_exist( FLAG_TREE_TO_XML ) ){
        tr_remove(FLAG_TREE_TO_XML);
    }
		
    return res;
}

/*!
 * \brief Initiate the library
 *
 * \param arg The configuration item value
 * \return 0 when success, or less return -1
 *
 * \remark if this function returns an error, TRAgent will exit abnormally.
 */

TR_LIB_API int lib_init( const char *arg )
{
    war_snprintf( xml_file_path, sizeof( xml_file_path ), "%s", arg );

    if( ( root = xml2tree( arg ) ) != NULL ) {
        return 0;
    } else {
        return -1;
    }
}

/*!
 * \fn lib_start_session
 * Notify the library that TRAgent will start a session
 *
 * \return 0 when success, -1 when any error occurred
 * \remark The TRAgent notify the library that it will start a session which does not
 * exactly mean that TRAgent will launch a DM session with server, it lets the
 * library to be ready for process incoming operations. Note that the TRAgent may call
 * this function before it calls the lib_end_session, so this function MUST remember
 * the reference count. For example, if the library stores all data in a sqlite
 * database, generally, this callback function opens the database if the counter is zero
 * and sets the count to 1, else just increase the counter by 1. In lib_end_session, it
 * decreases the counter by 1, and then check if it is zero. If yes, then close the
 * sqlite database, or do nothing if less.
 */

TR_LIB_API int lib_start_session( void )
{
    /* May need to lock the MO Tree and/or open the database */
    return ++count;
}

/*!
 * \fn lib_end_session
 * Notify the library that the session is over
 *
 * \return N/A
 */
TR_LIB_API int lib_end_session( void )
{
    /* May need to unlock the MO Tree and/or close the database */
    if( count > 0 ) {
        count--;
    }

    if( count == 0 ) {
        change = 0;
        tree2xml( root, xml_file_path );
    }

    return 0;
}

/*!
 * \brief Notify the device to do factory reset
 *
 * \return always be 0
 * \remark The TRAgent just notifies device to do factory reset operation. In this
 * function, device MUST NOT do factory reset immediately. It should just set some
 * flags to indicate it will do it. Because the TRAgent MUST complete the session
 * with DM server. Once the session ends, TRAgent will call the lib_reboot to reboot
 * the device.
 */

TR_LIB_API int lib_factory_reset( void )
{
    tr_log( LOG_NOTICE, "Fctory reset" );
    //factory_resetted = 1;
	char cmd[256] = {0};
	strcpy(cmd,"/sbin/reset_to_factory_settings.sh");
	tr_log( LOG_DEBUG, "Do factory reset==================cmd=%s" ,cmd);
	system(cmd);
    //tr_remove(xml_file_path);
    return 0;
}

/*!
 * \fn lib_reboot
 * \brief Reboot the device
 *
 * \return always be 0
 */
TR_LIB_API int lib_reboot( void )
{
    tr_log( LOG_NOTICE, "Reboot system" );
    system("reboot"); //ASKEY add
    return 0;
}

/*!
 * \fn lib_agent_reboot
 * \brief Reboot TR Agent
 *
 * \return always be 0
 */
TR_LIB_API int lib_agent_reboot( void )
{
    tr_log( LOG_NOTICE, "Reboot TR Agent" );
    system("killall -SIGUSR1 oneagent_mon");
    return 0;
}

#ifdef TR196
TR_LIB_API int lib_get_parent_node( node_t child, node_t *parent )
{
    *parent = child->parent;
    return 0;
}

#endif

//ASKEY add/s
TR_LIB_API int lib_read_mapfile(char* filename, mapInfo_t* mapInfos, int num)
{
    int i = 0;
	char szinstance[16];
	char value[256];
	int  instance;
	
    FILE* fp = tr_fopen(filename,"r");
	
	if (fp)
	{
	   while(!feof(fp))
	   {  
	      memset(szinstance,0,16);
		  memset(value,0,256);
	      fscanf(fp,"%s %*s %s",szinstance,value);\
		  printf("mapfile instance %s : value %s\n", szinstance,value);
	      instance  = atoi(szinstance);
	      if (instance > 0)
	      {
	         mapInfos[i].valid = 1;
		     mapInfos[i].instance = instance;
		     strcpy(mapInfos[i].value, value);
		     i++;
	       }
	   	}
	    tr_fclose(fp);

		return 0;
	}
	else
	{
	   return -1;
	}
}

TR_LIB_API int lib_save_mapfile(char* filename, mapInfo_t* mapInfos, int num)
{
    int i;
    /* save mapping info */
	FILE* fp = tr_fopen(filename,"w");
	if (fp)
	{
	   for(i=0;i<num;i++)
	   {
	      if (mapInfos[i].valid)
	      {
	        tr_log(LOG_NOTICE,"lib_save_mapfile 1: %d = %s\n",mapInfos[i].instance,mapInfos[i].value);
		    fprintf(fp,"%d = %s\n",mapInfos[i].instance,mapInfos[i].value);
	      }
	   }
	   
	   tr_fclose(fp);
	   return 0;
	 }

	 return -1;
}
	
TR_LIB_API int lib_getvalue_mapfile_byinstance(char* filename,char *value, int inst)
{
    int i = 0;
	int instance;
	char szinstance[16];
	char szvalue[256];
	
	FILE *fp = tr_fopen(filename,"r");
	if (fp)
	{
	   /* need add get mapping info from mapping file */
		   while(!feof(fp))
		   {
			  fscanf(fp,"%s %*s %s",szinstance,szvalue);
			  instance	= atoi(szinstance);
			  if (instance == inst)
			  {
			    /* get value by elinkname*/
				printf("value = %s \n", szvalue);
				strcpy(value,szvalue);
				tr_fclose(fp);
				return 0;
			  }
			   i++;
			}
		   tr_fclose(fp);
	  }
	  
      return -1;
}

TR_LIB_API int lib_update_mapfile(char * mapfilename,char *value, int inst)
{
    int i = 0;
	mapInfo_t mapInfos[MAXMAPITEMS];
	
	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(mapfilename,mapInfos,MAXMAPITEMS);

	/* update */
    for(i=0;i<MAXMAPITEMS;i++)
    {
		if (mapInfos[i].instance == inst)
		{
			strcpy(mapInfos[i].value, value);
			break;
		}
    }
	
	lib_save_mapfile(mapfilename,mapInfos,MAXMAPITEMS);
	  
	return 0;
}
//ASKEY add/e

TR_LIB_API int lib_get_child_node( node_t parent, const char *name, node_t *child )
{
    *child = NULL;

    if( name == NULL ) {
        *child = parent->children;
        return 0;
    } else {
        node_t n;

        for( n = parent->children; n; n = n->brother ) {
            if( strcmp( n->name, name ) == 0 ) {
                *child = n;
                return 0;
            }
        }

        return -1;
    }
}

static node_t resolve_node( char *path, node_t from )
{
    char *dot;
    node_t n;
    dot = strchr( path, '.' );

    if( dot ) {
        *dot = '\0';
        dot++;
    }

    if( from ) {
        for( n = from; n; n = n->brother ) {
            if( strcmp( n->name, path ) == 0 ) {
                if( dot == NULL || *dot == '\0' ) {
                    return n;
                } else {
                    return resolve_node( dot, n->children );
                }
            }
        }
    }

    return NULL;
}

/*!
 * \brief Resolve the MOT node path to an internal structure(node_t)
 *
 * \param path The path of the MOT node, for example "InternetGatewayDevice.A.B.C"
 * \param node The internal presentation of the MOT node
 *
 * \return 0 when success, 1 when the node does not existing, -1 when any error
 */

TR_LIB_API int lib_resolve_node( const char *path, node_t *node )
{
    if( path[0] == '\0' ) {
	 	 *node = root;
	 	 return 0;
    } else {
	 	 char _path[256];
	 	 war_snprintf( _path, sizeof( _path ), "%s", path );
	 	 *node = resolve_node( _path, root );

        if( *node ) {
	 	 	return 0;
        } else {
            		return 1;
		 }
	 }
}

// object changes notification function
void lib_handle_tr_update( node_t node, char *name, const char *value, char *op )
{
    int i, iport, fd = -1, res = 0;
    char *host, *port;
    char addr[32];
    struct sockaddr_in listen;
    char content[512];
    memset( &listen, 0, sizeof( listen ) );
    listen.sin_family = AF_INET;

    while( node != NULL ) {
        for( i = 0; i < node->listener_count; i++ ) {
            strncpy( addr, node->listener_addr[i], sizeof( addr ) );
            host = addr;
            port = strchr( host, ':' );
            *port = '\0';
            port++;
            iport = atoi( port );
            listen.sin_port = htons( ( short ) iport );
            listen.sin_addr.s_addr = inet_addr( host );

            if( strcmp( op, "set" ) == 0 ) {
                war_snprintf( content, sizeof( content ), "POST HTTP/1.1\r\nHOST: %s:%s\r\nContent-Length: %d\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nop=%s&name=%s&value=%s\r\n", host, port, strlen( name ) + strlen( value ) + strlen( op ) + 16, op, name, value );
            } else {
                war_snprintf( content, sizeof( content ), "POST HTTP/1.1\r\nHOST: %s:%s\r\nContent-Length: %d\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nop=%s&name=%s\r\n", host, port, strlen( name ) + strlen( op ) + 10, op, name );
            }

            fd = socket( AF_INET, SOCK_STREAM, 0 );
            tr_log( LOG_DEBUG, "sending to listener %s:\n%s", node->listener_addr[i], content );

            if( fd >= 0 && connect( fd, ( struct sockaddr * ) &listen, sizeof( listen ) ) == 0 ) {
                send( fd, content, strlen( content ), 0 );
                tr_log( LOG_DEBUG, "sent message successfully" );
            } else {
                res -= 1;
                tr_log( LOG_ERROR, "sent message failed" );
            }
        }

        node = node->parent;
    }
}

/*!
 * \brief To retrieve a given(by name) property of the target node
 *
 * \param node The node whose property to be retrieved
 * \param name The property's name
 * \param prop The buffer to save the property, all properties will be transfered
 * as string between TRAgent and the library
 *
 * \return 0 when success, -1 when any error
 */

TR_LIB_API int lib_get_property( node_t node, const char *name, char prop[PROPERTY_LENGTH] )
{
    if( war_strcasecmp( name, "rw" ) == 0 ) {
        war_snprintf( prop, PROPERTY_LENGTH, "%d", node->rw );
    } else if( war_strcasecmp( name, "getc" ) == 0 ) {
        war_snprintf( prop, PROPERTY_LENGTH, "%d", node->getc );
    } else if( war_strcasecmp( name, "nin" ) == 0 ) {
        war_snprintf( prop, PROPERTY_LENGTH, "%d", node->nin );
    } else if( war_strcasecmp( name, "il" ) == 0 ) {
        war_snprintf( prop, PROPERTY_LENGTH, "%d", node->il );
    } else if( war_strcasecmp( name, "acl" ) == 0 ) {
        war_snprintf( prop, PROPERTY_LENGTH, "%s", node->acl );
    } else if( war_strcasecmp( name, "type" ) == 0 ) {
        war_snprintf( prop, PROPERTY_LENGTH, "%s", node->type );
    } else if( war_strcasecmp( name, "noc" ) == 0 ) {
        war_snprintf( prop, PROPERTY_LENGTH, "%d", node->noc );
    } else if( war_strcasecmp( name, "nocc" ) == 0 ) {
        war_snprintf( prop, PROPERTY_LENGTH, "%s", nocc_code2str( node->nocc ) );
    } else if( war_strcasecmp( name, "name" ) == 0 ) {
        war_snprintf( prop, PROPERTY_LENGTH, "%s", node->name );
    } else {
        return -1;
    }

    return 0;
}

#if 1	// Askey
#define MAX_PATH_TEMPLATE_LENGTH 256
int path_num_2_template( const char *path_num, char *path_template)
{
	const char *pn;
	char *pt;
    char *d;

	pn = path_num;
	pt = path_template;
    d = strchr( pn, '.' );
	
    while( d ) {
        if( *pn <= '9' && *pn > '0' ) {
			memcpy(pt, "template.", strlen("template."));
			pt = pt + strlen("template.");
        }
		else{
			memcpy(pt, pn, d - pn + 1);
			pt = pt + (d - pn + 1);
		}

        pn = d + 1;
        d = strchr( pn, '.' );
    }
	
	memcpy(pt, pn, strlen(path_num) - (pn - path_num));	
	pt = pt + strlen(path_num) - (pn - path_num);
	path_template[pt - path_template] = '\0';

    return 0;
}


int lib_get_value_from_table(char *pp, char *v)
{
	int i;
	char path_template[MAX_PATH_TEMPLATE_LENGTH] = "";
	//tr_log( LOG_ERROR, "pp is %s!",pp );
	//tr_log(LOG_ERROR,"v is %s",v);

	int ret = 0;
	path_num_2_template(pp, path_template);
	for (i=0 ; (tr69_param[i].get_proc != 0) ; i++)
	{
		if (!strcmp(path_template, tr69_param[i].path_name)) {
		    // set default value from table if no value found in conf/tr.xml 	
			if (strlen(v))
				strcpy(v, tr69_param[i].default_value);
			// call get_xxx
			ret = tr69_param[i].get_proc(pp, v);
			return(ret);
		}
	}
	strcpy(v, "Unknown_Parameter");
	return(1);
}

int lib_set_value_to_uci(char *pp,char *v)
{
	int i;
	char path_template[MAX_PATH_TEMPLATE_LENGTH] = "";
	int ret = 0;
	//printf("the pp is %s \n",pp);
	//printf("value of the v is :%s\n",v);
	//tr_log( LOG_ERROR, "pp is [%s] !",pp );
	//tr_log(LOG_ERROR,"v is [%s]",v);

	//system("echo \"set value to uci\" >> /etc/hello.txt");
	path_num_2_template(pp, path_template);
	for (i=0 ; (tr69_param[i].get_proc != 0) ; i++)
	{
		if (!strcmp(path_template, tr69_param[i].path_name)) 
		{
			if(tr69_param[i].set_proc != 0)
			{
				tr_log(LOG_DEBUG,"do the set-function");
				ret = tr69_param[i].set_proc(pp, v);
				tr_log(LOG_DEBUG,"ret[%d]\n",ret);
				return (ret);
			}
		}
		//tr_log(LOG_ERROR,"search the dest node ");
		
	}
	return (-1);
}
#endif

/*!
 * \fn lib_get_value
 * \brief Retrieve a leaf node's value
 *
 * \param node The node whose value to be retrieved
 * \param value The buffer to save the value's pointer
 *
 * \return 0 when success, -1 when any error
 *
 * \remark This function MUST allocate a block memory from heap to hold the value
 * and save the pointer in the parameter value. Any type of data will be transfered
 * in string between TRAgent and callback functions, for example the node type is
 * integer -123, then the callback function should return the value as "-123"
 */

TR_LIB_API int lib_get_value( node_t node, char **value )
{
#ifdef __V4_2
    char full_path[256];
    int res = 0;
    int locate[MAX_LOCATE_DEPTH];
    int value_type = 0;
    int value_len = 0;
    get_param_full_name( node, full_path );
    path_2_locate( full_path, locate, sizeof( locate ) / sizeof( locate[0] ) );

    if( node->dev.param.get ) {
        res = node->dev.param.get( locate, sizeof( locate ) / sizeof( locate[0] ),
                                   value, &value_len, &value_type );

        if( res != -1 ) {
            res = 0;
        }
    } else {
        res = -1;
    }

    return res;
#else
    int len;
    int ret; 
#if 1 	// Askey
    char *pp;
    pp = lib_node2path(node);
    if (!pp)
    	return -1;
    //lib_get_value_from_table(pp, (char *)(&(node->value)));
	char retvalue[2048]; /* ASKEY MOD, changed 256 to 2048*/
    ret = lib_get_value_from_table(pp, retvalue);
	/* if (strlen(retvalue) > 0) */
	if (!ret)
	{
	   strcpy(node->value,retvalue);
	}
#endif
    
    len = strlen( node->value );
    *value = malloc( len + 1 );

    if( *value == NULL ) {
        tr_log( LOG_ERROR, "Out of memory!" );
        return -1;
    }

    war_snprintf( *value, len + 1, "%s", node->value );
    return 0;
#endif
}

/*!
 * \fn lib_destroy_value
 * To free the memory allocated by lib_get_value()
 *
 * \param value The memory's pointer
 * \return N/A
 */
TR_LIB_API void lib_destroy_value( char *value )
{
    if( value ) {
        free( value );
    }
}

static  void free_tree( struct node *tree )
{
    if( tree ) {
        if( tree->children ) {
            free_tree( tree->children );
            tree->children = NULL;
        }

        if( tree->brother ) {
            free_tree( tree->brother );
            tree->brother = NULL;
        }

        free( tree );
    }
}

static struct node *duplicate_tree( struct node *node ) {
    int len;
    int error = 0;

    struct node *to = NULL;

    struct node *from = NULL;

    struct node *tmp = NULL;

    len = sizeof( struct node );
    to = malloc( len );

    if( to == NULL ) {
        tr_log( LOG_ERROR, "Out memory!" );
    } else {
        memcpy( to, node, len );
        to->parent = NULL;
        to->brother = NULL;
        to->children = NULL;

        for( from = node->children; from; from = from->brother ) {
            tmp = duplicate_tree( from );

            if( tmp == NULL ) {
                error = 1;
                break;
            }

            tmp->brother = to->children;
            to->children = tmp;
            tmp->parent = to;
        }
    }

    if( error == 1 ) {
        free_tree( to );
        to = NULL;
    }

    return to;
}

node_t lib_get_child( node_t parent, char *name )
{
    node_t cur, next;

    for( cur = parent->children; cur; cur = next ) {
        if( strcmp( cur->name, name ) == 0 ) {
            break;
        }

        next = cur->brother;
    }

    return cur ? cur : NULL;
}

/*!
 * \fn lib_ao
 * \brief Add an object instance according to the path
 *
 * \param parent The parent node which the new instance(a sub tree) will be added under
 * \param nin The current instance number, the callback function MUST use it as the
 * new instance's root node name.
 *
 * \return 0 when success, -1 when any error
 */

TR_LIB_API int lib_ao( node_t parent, int nin, char *alias )
{
    int res = 0;
    node_t node0;
    node_t to = NULL;
#ifdef __V4_2
    char full_path[256];
    int locate[MAX_LOCATE_DEPTH];
    get_param_full_name( parent, full_path );
    path_2_locate( full_path, locate, sizeof( locate ) / sizeof( locate[0] ) );

    if( parent->dev.obj.add ) {
        res = parent->dev.obj.add( locate, sizeof( locate ) / sizeof( locate[0] ), nin );
    } else {
        return -1;
    }

#endif
    node0 = lib_get_child( parent, "template" );

    if( node0 ) {
        to = duplicate_tree( node0 );

        if( to ) {
            war_snprintf( to->name, sizeof( to->name ), "%d", nin );
            to->brother = parent->children;
            parent->children = to;
            to->parent = parent;
            res = 0;
#ifdef ALIAS
            struct alias_map *alias_current = NULL;
            node_t alias_node;

            if( ( alias_node = lib_get_child( to , "Alias" ) ) != NULL ) {
                set_logic_relative_values( to, alias );
                alias_current = ( struct alias_map * ) malloc( sizeof( struct alias_map ) );
                alias_current->next =  NULL;
                war_snprintf( alias_current->uri, sizeof( alias_current->uri ), "%s", lib_node2path( to ) );
                war_snprintf( alias_current->alias, sizeof( alias_current->alias ), "%s[%s].", lib_node2path( to->parent ), alias_node->value );

                if( alias_head == NULL ) {
                    alias_head = alias_current;
                } else {
                    alias_prev->next = alias_current;
                }

                alias_prev = alias_current;
            }

#endif //ALIAS
        }
    }

    // notify listeners change of add object
    if( res == 0 ) {
        lib_handle_tr_update( parent, lib_node2path( to ), NULL, "add" );
    }

    return res;
}


static void lib_destroy_tree( node_t node )
{
    node_t child;

    for( ; node->children; ) {
        child = node->children;
        node->children = child->brother;
        lib_destroy_tree( child );
    }

    free( node );
}
//ASKEY add
#if 0
int lib_add_ethlink_object(node_t node,int instance)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i,j;
    tr_log(LOG_NOTICE,"lib_add_ethlink_object 1: %s",node->name);
	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(EthLinkMap,mapInfos,MAXMAPITEMS); 

	/* 
	  * need to get a new eth link 
	  *
	  *  to do sth  
	  *
	  *and add in mapping file*/

	char paraname[128];
    node_t target;
	
	  sprintf(paraname,"Device.Ethernet.Link.%d.Name", instance);
	  if (lib_resolve_node(paraname,&target) == 0)
	  {
		  lib_set_value(target,"eth3-t");
	  }
			 
    for(i=0;i<MAXMAPITEMS;i++)
    {
       if (mapInfos[i].valid == 0)
       {
          mapInfos[i].valid = 1;
          
		  mapInfos[i].instance = instance;

		  strcpy(mapInfos[i].value,"eth3-t");
		  break;
       }
     }

    lib_save_mapfile(EthLinkMap,mapInfos,MAXMAPITEMS);

	return 0;
}

int lib_del_ethlink_object(node_t node)
{
    mapInfo_t mapInfos[MAXMAPITEMS];
	int i,j;
	char elinkname[128];
	int instance;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(EthLinkMap,mapInfos,MAXMAPITEMS); 
   
	
    char paraname[128];
	node_t target;
	
    instance = atoi(node->name);
	printf("lib_del_ethlink_object : node->name :%s\n",node->name);
#if 0	
	sprintf(paraname,"Device.Ethernet.Link.%d.Name", instance);
    if (lib_resolve_node(paraname,&target) == 0)
	{
	   printf("lib_del_ethlink_object : target value :%s %s \n",target->value,target->name);
	   strcpy(elinkname,target->value);
    }
#endif
    node_t child;

    memset(elinkname,0,sizeof(elinkname));
    for( ; node->children; ) 
	{
        child = node->children;
        node->children = child->brother;

		if (strcmp(child->name, "Name") == 0)
		{
		   strcpy(elinkname,child->value);
		   break;
		}
		
    }

	printf("elinkname :%s\n", elinkname);
	for(i=0;i<32;i++) //32 need to change
    {
       if ((mapInfos[i].valid) && (mapInfos[i].instance == instance) 
	   	&& (strcmp(mapInfos[i].value,elinkname) == 0))
       {
          mapInfos[i].valid = 0;
          /* delete real ether link by elinkname */
		  /* need to do */
		
       }
    }

	lib_save_mapfile(EthLinkMap,mapInfos,MAXMAPITEMS);
	
	return 0;
}
#endif

int add_dhcpv6sendoption_entry(uint32_t instance)
{
	char OptionNumberOfEntries[256] = {0};
	char name[256] = {0};
	char tmpbuf[256]={0};
	char cmdbuf[256]={0};
	char value[64] = {0};

	sprintf(name, "trconf.Device_DHCPv6_Clinet_template_SendOption_%d", instance); 
	do_uci_get(name,value);
	tr_log( LOG_NOTICE, "name: %s", name);
	tr_log( LOG_NOTICE, "value: %s", value);
	
	if(strcmp(value, "acs") != 0)
	{
		memset(OptionNumberOfEntries, 0, sizeof(OptionNumberOfEntries));
		do_uci_get(DDCt_SentOptionNumberOfEntries_3549, OptionNumberOfEntries);
		sprintf(tmpbuf, "%d", atoi(OptionNumberOfEntries)+1);
		do_uci_set(DDCt_SentOptionNumberOfEntries_3549, tmpbuf);

		do_uci_add("trconf","acs",tmpbuf);
		sprintf(cmdbuf, "trconf.%s", tmpbuf);
		sprintf(name,"Device_DHCPv6_Clinet_template_SendOption_%d", instance);
		do_uci_rename(cmdbuf, name);
		do_uci_commit(MS);
	}
}


int add_dhcpserveroption_entry(uint32_t instance)
{
	char OptionNumberOfEntries[256] = {0};
	char name[256] = {0};
	char tmpbuf[256]={0};
	char cmdbuf[256]={0};
	char value[64] = {0};

	sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d", instance);	
	do_uci_get(name,value);
	tr_log( LOG_NOTICE, "name: %s", name);
	tr_log( LOG_NOTICE, "value: %s", value);
	
	if(strcmp(value, "acs") != 0)
	{
	memset(OptionNumberOfEntries, 0, sizeof(OptionNumberOfEntries));
	do_uci_get(DDSPt_OptionNumberOfEntries, OptionNumberOfEntries);
	sprintf(tmpbuf, "%d", atoi(OptionNumberOfEntries)+1);
	do_uci_set(DDSPt_OptionNumberOfEntries, tmpbuf);

	do_uci_add("trconf","acs",tmpbuf);
	sprintf(cmdbuf, "trconf.%s", tmpbuf);
	sprintf(name,"Device_DHCPv4_Server_Pool_template_Option_%d", instance);
	do_uci_rename(cmdbuf, name);
	do_uci_commit(MS);
	}
}

int delete_dhcpv6sendoption_entry(char *tag)
{
	char name[128]={0};
	char buff[256] = {0};
	char tmpbuf[256] = {0};
	char *p = NULL;
	char OptionNumberOfEntries[256] = {0};
	int i;

	do_uci_get(DDCt_SentOptionNumberOfEntries_3549, OptionNumberOfEntries);
	printf("OptionNumberOfEntries = %s\n", OptionNumberOfEntries);
	for(i=1; i<=atoi(OptionNumberOfEntries); i++)
	{
		sprintf(name, "trconf.Device_DHCPv6_Clinet_template_SendOption_%d.Tag", i);		
		tr_log( LOG_NOTICE, "name: %s", name);
		do_uci_get(name, buff);
		if(strcmp(tag, buff) == 0)
		{
			sprintf(name, "trconf.Device_DHCPv6_Clinet_template_SendOption_%d", i); 
			printf("name = %s\n", name);
			do_uci_delete(name,NULL);	
		}
	}
	
	if(atoi(OptionNumberOfEntries) > 0)
	{
		sprintf(tmpbuf, "%d", (atoi(OptionNumberOfEntries)-1));
		printf("tmpbuf = %s\n", tmpbuf);
		do_uci_set(DDCt_SentOptionNumberOfEntries_3549, tmpbuf);
	}
	do_uci_commit(MS);
	set_dhcpv6_clinet_sentoption();
}


int delete_dhcpserveroption_entry(char *tag)
{
	char name[128]={0};
	char buff[256] = {0};
	char tmpbuf[256] = {0};
	char *p = NULL;
	char OptionNumberOfEntries[256] = {0};
	int i;

	do_uci_get(DDSPt_OptionNumberOfEntries, OptionNumberOfEntries);
	printf("OptionNumberOfEntries = %s\n", OptionNumberOfEntries);
	for(i=1; i<=atoi(OptionNumberOfEntries); i++)
	{
		sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Tag", i);		
		tr_log( LOG_NOTICE, "name: %s", name);
		do_uci_get(name, buff);
		if(strcmp(tag, buff) == 0)
		{
			sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d", i); 
			printf("name = %s\n", name);
			do_uci_delete(name,NULL);	
		}
	}
	
	if(atoi(OptionNumberOfEntries) > 0)
	{
		sprintf(tmpbuf, "%d", (atoi(OptionNumberOfEntries)-1));
		printf("tmpbuf = %s\n", tmpbuf);
		do_uci_set(DDSPt_OptionNumberOfEntries, tmpbuf);
	}
	do_uci_commit(MS);
	set_dhcp_option();
}
int lib_add_dhcpv6sendoptions_object(node_t node, uint32_t instance)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i = 0,j = 0;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(RouterDHCPv6clinetOptionMap, mapInfos, MAXMAPITEMS); 
	
	/* 
	  * need to get a new eth link 
	  *
	  *  to do sth	
	  *
	  *and add in mapping file*/
	
	char paraname[128];
	node_t target;
	char value[256] = {0};

	for(i=0,j=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 1)
		{
			j++;
		}
	}

	if (j >= node->il){
		tr_log(LOG_NOTICE,"Number is larger than node->il");
		return -1;
	}

	add_dhcpv6sendoption_entry(instance);
	sprintf(paraname,"Device.DHCPv6.Client.1.SentOption.%d.Tag", instance);
	tr_log(LOG_NOTICE,"lib_add_dhcpv6sendoptions_object: full path name %s",paraname);
	sprintf(value, "%d", 255-instance); 	
	if (lib_resolve_node(paraname,&target) == 0)
	{
		lib_set_value(target, value);
	}

	for(i=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 0)
		{
			mapInfos[i].valid = 1;
			mapInfos[i].instance = instance;
			strcpy(mapInfos[i].value, value ); //init key vlaue
			break;
		}
	}
	
	lib_save_mapfile(RouterDHCPv6clinetOptionMap,mapInfos,MAXMAPITEMS);
	return 0;
}

int set_xmpp_connection_defaults( uint32_t instance)
{
	int ret = 0;
	char cmd[64]={0},alias[32]={0},date[64];

	sprintf(cmd,X_CONNECTION".%d.Enable",instance);
	ret = do_uci_set(cmd,"false");

	sprintf(cmd,X_CONNECTION".%d.Alias",instance);
	sprintf(alias,"cpe-%d",instance);

	ret = do_uci_set(cmd,alias);
	sprintf(cmd,X_CONNECTION".%d.Username",instance);
	ret = do_uci_set(cmd,"iotina2");
	sprintf(cmd,X_CONNECTION".%d.Password",instance);
	ret = do_uci_set(cmd,"hello123");

	sprintf(cmd,X_CONNECTION".%d.Domain",instance);
	ret = do_uci_set(cmd,"chatme.im");
	sprintf(cmd,X_CONNECTION".%d.Resource",instance);
	ret = do_uci_set(cmd,"desktop");

	sprintf(cmd,X_CONNECTION".%d.ServerConnectAlgorithm",instance);
	ret = do_uci_set(cmd,"DNS-SRV");
	sprintf(cmd,X_CONNECTION".%d.KeepAliveInterval",instance);
	ret = do_uci_set(cmd,"-1");

	sprintf(cmd,X_CONNECTION".%d.UseTLS",instance);
	ret = do_uci_set(cmd,"-1");

	sprintf(cmd,X_CONNECTION".%d.Status",instance);
	ret = do_uci_set(cmd,"disabled");

	sprintf(cmd,X_CONNECTION".%d.LastChangeDate",instance);
	x_get_current_time(date,64 );
	ret = do_uci_set(cmd,date);

	return 0;
}

int inc_dec_xmpp_entries( const char *path, int increment)
{
	char cmd[64]={0}, n_c[32]={0};
	int ret = 0,n_i;

	//increment the number of connection
	ret = do_uci_get( path , &n_c);
	if(ret)
	{
		return -1;
	}

	if(strcmp(n_c, "" )==0)
		n_i=0;
	else
		n_i = atoi(n_c);
	
	if(increment )
		sprintf(n_c,"%d", ++n_i);
	else
		sprintf(n_c,"%d", --n_i);

	//create an instance in uci connection config
	ret = do_uci_set(path ,n_c );
	if(ret)
	{
		return -1;
	}
	return 0;
}

int lib_add_xmpp_connection_object(node_t node, uint32_t instance)
{
	char cmd[64]={0};
	int ret = 0,n_conn_i;
	char n_conn[32]={0};

	sprintf(cmd,X_CONNECTION".%d",instance);
	//create an instance in uci connection config
	ret = do_uci_set(cmd,"connection");

	ret = set_xmpp_connection_defaults(instance );

	if(ret)
	{
		printf("uci : Set error");
		return (-1);
	}
	else
	{
		ret = do_uci_commit(X_CONNECTION);
		if(ret)
		{
				return (-1);
		}
#if 1
		inc_dec_xmpp_entries( DX_ConnectionNumberOfEntries,1);
#endif
	}

	return ret;
}

int lib_add_dhcpserveroptions_object(node_t node, uint32_t instance)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i = 0,j = 0;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(RouterDHCPv4ServerOptionMap, mapInfos, MAXMAPITEMS); 
	
	/* 
	  * need to get a new eth link 
	  *
	  *  to do sth	
	  *
	  *and add in mapping file*/
	
	char paraname[128];
	node_t target;
	char value[256] = {0};
	
	for(i=0,j=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 1)
		{
			j++;
		}
	}

	if (j >= node->il){
		tr_log(LOG_NOTICE,"Number is larger than node->il");
		return -1;
	}
	

	add_dhcpserveroption_entry(instance);
	sprintf(paraname,"Device.DHCPv4.Server.Pool.1.Option.%d.Tag", instance);
	tr_log(LOG_NOTICE,"lib_add_dhcpserveroptions_object: full path name %s",paraname);
	sprintf(value, "%d", 255-instance);		
	if (lib_resolve_node(paraname,&target) == 0)
	{
		lib_set_value(target, value);
	}

	for(i=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 0)
		{
			mapInfos[i].valid = 1;
			mapInfos[i].instance = instance;
			strcpy(mapInfos[i].value, value ); //init key vlaue
			break;
		}
	}
	
	lib_save_mapfile(RouterDHCPv4ServerOptionMap,mapInfos,MAXMAPITEMS);
	return 0;
}

int lib_del_xmpp_connection_object(node_t node)
{
	int instance,ret=0;
	char cmd[64]={0};

	instance = atoi(node->name);
	printf("lib_del_xmpp_connection_object : node->name :%s\n",node->name);

	sprintf(cmd,X_CONNECTION".%d",instance);
	//create an instance in uci connection config
	ret = do_uci_delete(cmd,NULL);

	if(ret)
	{
		printf("uci : Set error");
		return (-1);
	}
	else
	{
		char curXmpp[256]={0}, value[256]={0},*index;
		int runningInstance=0;

		ret = do_uci_commit(X_CONNECTION);
		if(ret)
		{
			return (-1);
		}
		inc_dec_xmpp_entries( DX_ConnectionNumberOfEntries,0);

		//if this is the selected connection, set "ConnReqXMPPConnection" to an empty string
		ret = do_uci_get(DM_ConnReqXMPPConnection, curXmpp);
		if(ret)
		{
			return -1;
	   	}

		index = parseTemplate(curXmpp,".Connection." );
		if(index)
		{
			runningInstance = atoi(index);
			if(instance == runningInstance)
			{
				//set to empty string
				ret = do_uci_set(DM_ConnReqXMPPConnection, value);
				if(ret)
				{
					return (-1);
				}
			}
		}
		ret = do_uci_commit(X_CONNECTION);
		if(ret)
		{
				return (-1);
		}

		x_xmpp_agent_stop(runningInstance );
	}
	return 0;
}

int lib_del_dhcpv6sendoptions_object(node_t node)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i,j;
	char Tag[128];
	int instance;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(RouterDHCPv6clinetOptionMap,mapInfos,MAXMAPITEMS); 
	
	char paraname[128];
	node_t target;
	
	instance = atoi(node->name);
	printf("lib_del_dhcpv6sendoptions_object : node->name :%s\n",node->name);
	node_t child;

	memset(Tag,0,sizeof(Tag));
	for( ; node->children; ) 
	{
		child = node->children;
		node->children = child->brother;

		if (strcmp(child->name, "Tag") == 0)
		{
		   strcpy(Tag,child->value);
		   break;
		}
		
	}
	printf("Tag :%s\n", Tag);
	for(i=0;i<MAXMAPITEMS;i++)
	{
	   if ((mapInfos[i].valid) && (mapInfos[i].instance == instance) && (strcmp(mapInfos[i].value,Tag) == 0))
	   {
		  delete_dhcpv6sendoption_entry(mapInfos[i].value);
		  mapInfos[i].valid = 0;
	   }
	}
	
	lib_save_mapfile(RouterDHCPv6clinetOptionMap,mapInfos,MAXMAPITEMS);

	return 0;
}


int lib_del_dhcpserveroptions_object(node_t node)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i,j;
	char Tag[128];
	int instance;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(RouterDHCPv4ServerOptionMap,mapInfos,MAXMAPITEMS); 
	
	char paraname[128];
	node_t target;
	
	instance = atoi(node->name);
	printf("lib_del_dhcpserveroptions_object : node->name :%s\n",node->name);
	node_t child;

	memset(Tag,0,sizeof(Tag));
	for( ; node->children; ) 
	{
		child = node->children;
		node->children = child->brother;

		if (strcmp(child->name, "Tag") == 0)
		{
		   strcpy(Tag,child->value);
		   break;
		}
		
	}
	printf("Tag :%s\n", Tag);
	for(i=0;i<MAXMAPITEMS;i++)
	{
	   if ((mapInfos[i].valid) && (mapInfos[i].instance == instance) && (strcmp(mapInfos[i].value,Tag) == 0))
	   {
		  delete_dhcpserveroption_entry(mapInfos[i].value);
		  mapInfos[i].valid = 0;
	   }
	}
	
	lib_save_mapfile(RouterDHCPv4ServerOptionMap,mapInfos,MAXMAPITEMS);

	return 0;
}

int lib_add_Device_DHCPv4_Server_Pool_1_StaticAddress_object(node_t node, char * path, uint32_t instance)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i = 0,j = 0;
	char cmd[128] = {0};
	//tr_log(LOG_NOTICE,"lib_add_Device_DHCPv4_Server_Pool_1_StaticAddress_object: node->name %s",node->name);
	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(DHCPv4ServerPool1StaticAddressMap,mapInfos,MAXMAPITEMS);
	
	char paraname[128] = {0};
	node_t target;
	char ipaddr[32] = {0};

	for(i=0,j=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 1)
		{
			j++;
		}
	}

	if (j >= node->il){
		tr_log(LOG_NOTICE,"Number is larger than node->il");
		return -1;
	}
	
	sprintf(paraname,"%s%d.Yiaddr", path, instance);
	tr_log(LOG_NOTICE,"lib_add_Device_DHCPv4_Server_Pool_1_StaticAddress_object: full path name %s",paraname);
	sprintf(ipaddr, "%d.%d.%d.%d", instance+1, instance, instance, instance); //init key vlaue

	for(i=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 0)
		{
			mapInfos[i].valid = 1;
			tr_log(LOG_NOTICE,"lib_add_Device_DHCPv4_Server_Pool_1_StaticAddress_object: instance %d",instance);
			mapInfos[i].instance = instance;
			strcpy(mapInfos[i].value,ipaddr ); //init key vlaue
			sprintf(cmd, "echo ff:ff:ff:ff:ff:ff %s >> /etc/ethers", ipaddr); //create a tmp item
			system(cmd);
			break;
		}
	}
	
	lib_save_mapfile(DHCPv4ServerPool1StaticAddressMap,mapInfos,MAXMAPITEMS);

	if (lib_resolve_node(paraname,&target) == 0)
	{
		lib_set_value(target,ipaddr);
	}
	
	return 0;
}

int lib_del_Device_DHCPv4_Server_Pool_1_StaticAddress_object(node_t node)
{
    mapInfo_t mapInfos[MAXMAPITEMS];
	int i,j;
	char value[128];
	int instance;
	node_t child;
	char paraname[128];
	node_t target;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(DHCPv4ServerPool1StaticAddressMap,mapInfos,MAXMAPITEMS);

    instance = atoi(node->name); //get index number
	printf("lib_del_Device_DHCPv4_Server_Pool_1_StaticAddress_object : node->name :%s\n",node->name);
    

    memset(value,0,sizeof(value));
    for( ; node->children; ) 
	{
        child = node->children;
        node->children = child->brother;

		if (strcmp(child->name, "Yiaddr") == 0) //get key value
		{
		   strcpy(value,child->value);
		   break;
		}
		
    }

	for(i=0;i<MAXMAPITEMS;i++)
    {
       if ((mapInfos[i].valid) && (mapInfos[i].instance == instance)
	   	&& (strcmp(mapInfos[i].value,value) == 0)) 
       {
          mapInfos[i].valid = 0;
          /* delete real static ip info by node value */
		  set_DHCPv4_Server_Pool_1_StaticAddress_info(value, NULL, "del");
       }
    }

	lib_save_mapfile(DHCPv4ServerPool1StaticAddressMap,mapInfos,MAXMAPITEMS);
	
	return 0;
}

int get_GREInterface_Alias(char key[][256])
{
	int ret = 0;
	int i = 0;
	char RemoteEndpoints[256] = {0};
	char value[64] = {0};
	char name[256] = {0};
	char *p = NULL;
	char *q = NULL;
	char tmpbuf[256]={0};
	char cmdbuf[256]={0};
	
	memset(RemoteEndpoints,0,sizeof(RemoteEndpoints));

	ret = do_uci_get("trconf.Device_GRE_Tunnel_template.RemoteEndpoints", RemoteEndpoints);
	tr_log( LOG_NOTICE, "RemoteEndpoints: %s", RemoteEndpoints);


	if(RemoteEndpoints[0] != '\0')
	{
		q = RemoteEndpoints;
		while((p = strchr(q, ',')) != NULL)
		{
			sprintf(key[i],"grenet%d", i);
			i++;
			q = p + 1;			
			do_uci_add("trconf","acs",tmpbuf);
			sprintf(cmdbuf, "trconf.%s", tmpbuf);
			sprintf(name,"Device_GRE_Tunnel_Interface_%d", i);
			tr_log( LOG_NOTICE, "name: %s", name);
			do_uci_rename(cmdbuf, name);
		}
		sprintf(key[i],"grenet%d", i);
		i++;
		do_uci_add("trconf","acs",tmpbuf);
		sprintf(cmdbuf, "trconf.%s", tmpbuf);
		sprintf(name,"Device_GRE_Tunnel_Interface_%d", i);
		tr_log( LOG_NOTICE, "name: %s", name);
		do_uci_rename(cmdbuf, name);
		do_uci_commit(MS);
	}
	return i;
}

int get_GREFilter_Alias(char key[][256])
{
	int ret = 0;
	int i = 0;
	int j = 0;
	char Order[32] = {0};
	char FilterNumberOfEntries[256] = {0};
	char value[64] = {0};
	char name[256] = {0};

	memset(FilterNumberOfEntries,0,sizeof(FilterNumberOfEntries));

	ret = do_uci_get("trconf.Device_GRE.FilterNumberOfEntries", FilterNumberOfEntries);
	if(ret)
	{
		return i;
	}
	tr_log( LOG_NOTICE, "FilterNumberOfEntries: %d", atoi(FilterNumberOfEntries));

	while(i < atoi(FilterNumberOfEntries))
	{
		memset(Order,0,sizeof(Order));
		memset(value,0,sizeof(value));
		j++;
		sprintf(name, "trconf.Device_GRE_Filter_%d", j);	
		do_uci_get(name,value);
		tr_log( LOG_NOTICE, "name: %s", name);
		tr_log( LOG_NOTICE, "value: %s", value);
		
		if(strcmp(value, "acs") == 0)
		{
			sprintf(name, "trconf.Device_GRE_Filter_%d.Order", j);		
			tr_log( LOG_NOTICE, "name: %s", name);
			do_uci_get(name, Order);
			
			sprintf(key[i],"%s", Order);	
			tr_log( LOG_NOTICE, "key[%d]: %s", i, key[i]);
			i++;
		}
	}
	return i;
}

int get_QoSShaper_Alias(char key[][256])
{
	int ret = 0;
	int i = 0;
	int j = 0;
	char Alias[32] = {0};
	char ShaperNumberOfEntries[256] = {0};
	char value[64] = {0};
	char name[256] = {0};

	memset(ShaperNumberOfEntries,0,sizeof(ShaperNumberOfEntries));

	memset(name,0,sizeof(name));
	ret = do_uci_get(SHAPERNUMBEROFENTRIES_PATH, ShaperNumberOfEntries);
	if(ret)
	{
		return i;
	}
	tr_log( LOG_NOTICE, "ShaperNumberOfEntries: %d", atoi(ShaperNumberOfEntries));

	while(i < atoi(ShaperNumberOfEntries))
	{
		memset(Alias,0,sizeof(Alias));
		memset(value,0,sizeof(value));
		j++;
		sprintf(name, "shaper.Device_QoS_Shaper_%d", j); 	
		do_uci_get(name,value);
		tr_log( LOG_NOTICE, "name: %s", name);
		tr_log( LOG_NOTICE, "value: %s", value);

		if(j > 16)
		{
			break;
		}
		
		if(strcmp(value, "shaper") == 0)
		{
			sprintf(name, "shaper.Device_QoS_Shaper_%d.Alias", j);		
			tr_log( LOG_NOTICE, "name: %s", name);
			do_uci_get(name, Alias);
			
			sprintf(key[i],"%s", Alias);	
			tr_log( LOG_NOTICE, "key[%d]: %s", i, key[i]);
			i++;
		}
	}
	return i;
}

int get_QoSQueue_Alias(char key[][256])
{
	int ret = 0;
	int i = 0;
	int j = 0;
	char Alias[32] = {0};
	char QueueNumberOfEntries[256] = {0};
	char value[64] = {0};
	char name[256] = {0};
	char MaxQueueEntries[256] = {0};

	memset(QueueNumberOfEntries,0,sizeof(QueueNumberOfEntries));
	memset(MaxQueueEntries,0,sizeof(MaxQueueEntries));

	ret = do_uci_get("qos.number.MaxQueueEntries", MaxQueueEntries);
	ret = do_uci_get("qos.number.QueueNumberOfEntries", QueueNumberOfEntries);
	if(ret)
	{
		return i;
	}
	tr_log( LOG_NOTICE, "QueueNumberOfEntries: %s", QueueNumberOfEntries);

	while(j < atoi(QueueNumberOfEntries))
	{
		memset(Alias,0,sizeof(Alias));
		memset(value,0,sizeof(value));
		j++;
		sprintf(name, "qos.queue%d", j);		
		do_uci_get(name,value);
		tr_log( LOG_NOTICE, "name: %s", name);
		tr_log( LOG_NOTICE, "value: %s", value);
		
		if(i >= atoi(MaxQueueEntries))
		{
			break;
		}
		
		if(strcmp(value, "queue") == 0)
		{
			sprintf(name, "qos.queue%d.Alias", j);		
			tr_log( LOG_NOTICE, "name: %s", name);
			do_uci_get(name, Alias);
			
			sprintf(key[i],"%s", Alias);	
			tr_log( LOG_NOTICE, "key[%d]: %s", i, key[i]);
			i++;
		}

	}
	return i;
}

int get_QoSApp_Alias(char key[][256])
{
	int ret = 0;
	int i = 0;
	int j = 0;
	char Alias[32] = {0};
	char AppNumberOfEntries[256] = {0};
	char value[64] = {0};
	char name[256] = {0};

	memset(AppNumberOfEntries,0,sizeof(AppNumberOfEntries));

	ret = do_uci_get(DQ_AppNumberOfEntries, AppNumberOfEntries);
	if(ret)
	{
		return i;
	}
	tr_log( LOG_NOTICE, "AppNumberOfEntries: %d", atoi(AppNumberOfEntries));

	while(i < atoi(AppNumberOfEntries))
	{
		memset(Alias,0,sizeof(Alias));
		memset(value,0,sizeof(value));
		j++;
		sprintf(name, "trconf.Device_QoS_App_%d", j); 	
		do_uci_get(name,value);
		tr_log( LOG_NOTICE, "name: %s", name);
		tr_log( LOG_NOTICE, "value: %s", value);
		
		if(strcmp(value, "acs") == 0)
		{
			sprintf(name, "trconf.Device_QoS_App_%d.Alias", j);		
			tr_log( LOG_NOTICE, "name: %s", name);
			do_uci_get(name, Alias);
			
			sprintf(key[i],"%s", Alias);	
			tr_log( LOG_NOTICE, "key[%d]: %s", i, key[i]);
			i++;
		}
	}
	return i;
}


int get_QoSClassification_Alias(char key[][256])
{
	int ret = 0;
	int i = 0;
	int j = 0;
	char Alias[32] = {0};
	char MaxClassificationEntries[256] = {0};
	char value[64] = {0};
	char name[256] = {0};

	memset(Alias,0,sizeof(Alias));
	memset(MaxClassificationEntries,0,sizeof(MaxClassificationEntries));

	ret = do_uci_get("qos.number.MaxClassificationEntries", MaxClassificationEntries);
	if(ret)
	{
		return i;
	}
	tr_log( LOG_NOTICE, "MaxClassificationEntries: %d", atoi(MaxClassificationEntries));

	while(j < atoi(MaxClassificationEntries))
	{
		memset(Alias,0,sizeof(Alias));
		memset(value,0,sizeof(value));
		j++;
		sprintf(name, "qos.cf%d", j);		
		do_uci_get(name,value);
		tr_log( LOG_NOTICE, "name: %s", name);
		tr_log( LOG_NOTICE, "value: %s", value);
		
		if(strcmp(value, "ClassificationList") == 0)
		{
			sprintf(name, "qos.cf%d.Alias", j);		
			tr_log( LOG_NOTICE, "name: %s", name);
			do_uci_get(name, Alias);
			
			sprintf(key[i],"%s", Alias);	
			tr_log( LOG_NOTICE, "key[%d]: %s", i, key[i]);
			i++;
		}
	}
	return i;
}

int get_RouterIPv4_DestIPAddress(char DestIPAddresstable[][256])
{
	FILE *fp = NULL;
	char buff[256] = {0};
	char tmpbuf[256] = {0};
	char destIP[256] = {0};
	char destIP1[256] = {0};
	char name[128] = {0};
	int i = 0;
	int j = 0;
	int found = 0;
	
	system("route -n >/tmp/routeipv4");	

	fp = fopen("/tmp/routeipv4", "r");

	if(fp != NULL)
	{
		fgets(buff, sizeof(buff), fp);
		fgets(buff, sizeof(buff), fp);
		while(fgets(buff, sizeof(buff), fp))
		{
			sscanf(buff, "%s %*s", destIP);
			strcpy(DestIPAddresstable[i], destIP);
			i++;
		}
		fclose(fp);
	}

	memset(destIP,0,sizeof(destIP));
	do_uci_get("staticrt.staticrt.listnum", tmpbuf);

	for(j=0; j<atoi(tmpbuf); j++)
	{	
		sprintf(name,"staticrt.routelist_%d.hostip",j);
		do_uci_get(name,destIP);
		fp = fopen("/tmp/routeipv4", "r");
		found = 0;		
		if(fp != NULL)
		{
			while(fgets(buff, sizeof(buff), fp))
			{
				sscanf(buff, "%s %*s", destIP1);
				if(strcmp(destIP1, destIP) == 0)
				{
					found = 1;
					break;
				}
			}
			fclose(fp);
		}
		tr_log(LOG_DEBUG,"########found[%d]",found);
		if(found == 0)
		{
			strcpy(DestIPAddresstable[i], destIP);
			i++;
		}
	}
	return i;	
}

int get_RouterIPv6_num()
{
	FILE *fp = NULL;
    char line[512] = {0};
    int i = 0;
	
	if((fp=popen("route -A inet6 -n","r")) != NULL){
		fgets(line,sizeof(line)-1,fp); //ingor first line
		fgets(line,sizeof(line)-1,fp); //ingor second line
		while(fgets(line,sizeof(line)-1,fp)){
			if (strstr(line, "lo") != NULL) //ingor lo interface
				continue;
			if (strstr(line, "ath") != NULL) //ingor wifi interface
				continue;
			if (i < MAXMAPITEMS){
				i++;
			}
			else
				break;
    	}
    	pclose(fp);
	}

	return i;
}

int get_IPsecTunnel_Alias(char key[][256])
{
	FILE *fp = NULL;
	char line[512] = {0};
	int found = 0;
	char desip[128] = {0};
	char inf[32] = {0};
	
	if((fp=popen("ipsec setup status","r")) != NULL)
	{
		while(fgets(line,sizeof(line)-1,fp))
		{
			if(strstr(line, "tunnels up") != NULL)
			{
				found = 1;
			}
		}
		pclose(fp);
	}

	if(found == 1)
	{
		strcpy(key[0], "cpe-IPsecTunnel_1");
		return 1;
	}
	else
	{
		return 0;
	}
}

int get_RouterIPv6_DestIPAddress(char key[][256])
{
	FILE *fp = NULL;
    char line[512] = {0};
    int i = 0;
	char desip[128] = {0};
	char inf[32] = {0};
	
	if((fp=popen("route -A inet6 -n","r")) != NULL){
		fgets(line,sizeof(line)-1,fp); //ingor first line
		fgets(line,sizeof(line)-1,fp); //ingor second line
		while(fgets(line,sizeof(line)-1,fp)){
			memset(desip, 0, sizeof(desip));
			memset(desip, 0, sizeof(inf));
			sscanf(line,"%s %*s %*s %*s %*s %*s %s", desip, inf);
			if (strstr(inf, "lo") != NULL) //ingor lo interface
				continue;
			if (strstr(inf, "ath") != NULL) //ingor wifi interface
				continue;
			i++;
			if (i < MAXMAPITEMS){
				sprintf(key[i-1],"%s|%s", desip, inf); //using Destination ip and interface as the key value
			}
			else
				break;
    	}
    	pclose(fp);
	}

	return i;
}

#define MAX_PF_ELEM 256
int get_PortMapping_InternalPort(char InternalPorttable[][256])
{
	int i = 0;
	int j = 0;
	int ret = -1;
	char linebuf[128] = {0};
	char tmparray[64] = {0};
	char valbuf[64] = {0};
	char valbuf1[64] = {0};
	char *ptr = NULL;

	for(i=0; i<MAX_PF_ELEM; i++)
	{
		sprintf(tmparray, "firewall_nat.pf%d", i);
		sprintf(linebuf, "%s.port_range", tmparray);
		tr_log(LOG_DEBUG,"linebuf [%s]",linebuf);
		ret = do_uci_get(linebuf, valbuf);
		if (ret != 0)
		{
			continue;
		}

		ptr = strchr(valbuf, ':');
		if(ptr != NULL)
		{
			*ptr = '\0';
		}

		sprintf(linebuf, "%s.protocol", tmparray);
		tr_log(LOG_DEBUG,"linebuf [%s]",linebuf);
		ret = do_uci_get(linebuf, valbuf1);

		sprintf(InternalPorttable[j], "%s_%s", valbuf, valbuf1);
		j++;
	}

	/*fp = fopen("/etc/portforwarding_save.txt", "r");

	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp))
		{
			s = buff;
			while((p = strstr(s, "PortRange")) != NULL)
			{
				q = strchr(p, ':');
				r = strchr(p, ',');
				if(q != NULL && s != NULL)
				{
					*(r-1) = '\0';
					ptr = strchr(q+2, ':');
					if(ptr != NULL)
					{
						*ptr = '\0';
					}
					strcpy(InternalPorttable[i], q+2);
					i++;
					s = r + 1;
				}
				
			}
		}
		fclose(fp);
	}*/
	return j;
}

#define NET_FW_PORTFWD_ENABLE 		"firewall_nat.port_fwd.enabled"
#define NET_FW_PORTFWD_NUM 			"firewall_nat.port_fwd.element_count"
#define NET_FW_PORTFWD_MAXINDEX 	"firewall_nat.port_fwd.max_index"

int add_portmapping_entry()
{
	int i = 0;
	int ret = -1;
	char num_val[16] = {0};
	char secname[64] = {0};
	char linebuf[512] = {0};
	char tmparray[128] = {0};
	char index[16] = {0};

	ret = do_uci_get(NET_FW_PORTFWD_MAXINDEX, num_val);

	sprintf(tmparray,"pf%d", atoi(num_val)+1);
	sprintf(linebuf, "firewall_nat.%s", tmparray);
	do_uci_set(linebuf, "port_fwd");
	tr_log(LOG_DEBUG,"linebuf [%s]",linebuf);

	memset(linebuf, 0, sizeof(linebuf));

	sprintf(linebuf, "firewall_nat.%s.port_range", tmparray);
	do_uci_set(linebuf, "0");
	memset(linebuf, 0, sizeof(linebuf));

	sprintf(linebuf, "firewall_nat.%s.local_port", tmparray);
	do_uci_set(linebuf, "0");
	memset(linebuf, 0, sizeof(linebuf));

	sprintf(linebuf, "firewall_nat.%s.srv_name", tmparray);
	do_uci_set(linebuf, "None");
	memset(linebuf, 0, sizeof(linebuf));

	sprintf(linebuf, "firewall_nat.%s.local_ip", tmparray);
	do_uci_set(linebuf, "0.0.0.0");
	memset(linebuf, 0, sizeof(linebuf));

	sprintf(linebuf, "firewall_nat.%s.protocol", tmparray);
	do_uci_set(linebuf, "2");
	memset(linebuf, 0, sizeof(linebuf));

	sprintf(linebuf, "firewall_nat.%s.index", tmparray);
	sprintf(index, "%d", atoi(num_val)+1);
	do_uci_set(linebuf, index);
	
	memset(linebuf, 0, sizeof(linebuf));
	sprintf(linebuf, "firewall_nat.%s.is_enable", tmparray);
	do_uci_set(linebuf, "0");

	sprintf(tmparray,"%d", atoi(num_val)+1);
	do_uci_set(NET_FW_PORTFWD_MAXINDEX, tmparray);

	do_uci_get(NET_FW_PORTFWD_NUM, num_val);
	sprintf(tmparray,"%d", atoi(num_val)+1);
	do_uci_set(NET_FW_PORTFWD_NUM, tmparray);

	/*fp = fopen("/etc/portforwarding_save.txt", "r");
	if(fp != NULL)
	{
		fgets(buff, sizeof(buff), fp);
		s = buff;
		printf("s: %s\n", s);
	
		p = strstr(buff, "IsEnable");
		if(p != NULL)
		{
			q = strchr(p, ',');
			if(q != NULL)
				strncpy(isenable, p-1, q- (p-1));
	
			printf("isenable: %s\n", isenable);
			
		}
		
		while((p = strstr(s, "ServiceName")) != NULL)
		{
			if((q = strchr(p, '}')) != NULL)
			{
				strncpy(entry[i], p-2, (q+1) - (p-2));
				i++;
				s = q + 1;
			}
		}
		fclose(fp);
	}
	else
	{
		strcpy(isenable, "\"IsEnable\":0");
	}
	
	sprintf(buff, "{%s,\"PortForwardList\":[", isenable);
	printf("buff: %s\n", buff);
	
	for(j=0; j<i; j++)
	{
		strcat(buff, entry[j]);
		strcat(buff, ",");
	}
	
	
	strcat(buff, "{\"ServiceName\":\"tmp\",\"PortRange\":\"0\",\"LocalIp\":\"1.1.1.1\",\"LocalPort\":\"0\",\"Protocol\":\"1\"}]}");
	
	fp = fopen("/etc/portforwarding_save.txt", "w");
	if(fp != NULL)
	{
		fputs(buff, fp);
		fclose(fp);
	}*/
}

int lib_add_portmapping_object(node_t node, uint32_t instance)
{
	char buff[8192] = {0};
	FILE *fp = NULL;
	char *p = NULL;
	char *q = NULL;
	char *s = NULL;
	char entry[32][1024] = {0};
	int i = 0;
	int j = 0;
	char isenable[32] = {0};
	
	mapInfo_t mapInfos[MAXMAPITEMS];
    tr_log(LOG_NOTICE,"lib_add_portmapping_object 1: %s",node->name);
	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(PortMappingMap,mapInfos,MAXMAPITEMS); 

	char paraname[128];
	node_t target;

	for(i=0,j=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 1)
		{
			j++;
		}
	}

	if (j >= node->il){
		tr_log(LOG_NOTICE,"Number is larger than node->il");
		return -1;
	}

	for(i=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 0)
		{
			mapInfos[i].valid = 1;

			mapInfos[i].instance = instance;

			strcpy(mapInfos[i].value,"0_2"); //tmp value 
			add_portmapping_entry();
			break;
		}
	}

    lib_save_mapfile(PortMappingMap,mapInfos,MAXMAPITEMS);	
	
	sprintf(paraname,"Device.NAT.PortMapping.%d.ExternalPort", instance);
	if (lib_resolve_node(paraname,&target) == 0)
	{
		lib_set_value(target,"0"); //tmp value
	}

	return 0;
}

int delete_portmapping_entry(char *ExternalPort)
{
	int i = 0;
	int ret = -1;
	char linebuf[128] = {0};
	char tmparray[64] = {0};
	char valbuf[64] = {0};
	char valbuf1[64] = {0};
	char port_protocol[256] = {0};
	char *ptr = NULL;

	tr_log(LOG_DEBUG,"set ExternalPort [%s]",ExternalPort);

	for(i=0; i<MAX_PF_ELEM; i++)
	{
		sprintf(tmparray, "firewall_nat.pf%d", i);
		sprintf(linebuf, "%s.port_range", tmparray);
		tr_log(LOG_DEBUG,"linebuf [%s]",linebuf);
		ret = do_uci_get(linebuf, valbuf);
		if (ret != 0)
		{
			continue;
		}
		ptr = strchr(valbuf, ':');
		if(ptr != NULL)
		{
			*ptr = '\0';
		}
		sprintf(linebuf, "%s.protocol", tmparray);
		tr_log(LOG_DEBUG,"linebuf [%s]",linebuf);
		ret = do_uci_get(linebuf, valbuf1);
		sprintf(port_protocol, "%s_%s", valbuf, valbuf1);
		if(strcmp(port_protocol, ExternalPort) == 0)
		{
			do_uci_delete(tmparray,NULL);	
			break;
		}
	}
	system("/lib/firewall/firewall_nat.sh");

	/*fp = fopen("/etc/portforwarding_save.txt", "r");
	if(fp != NULL)
	{
		fgets(buff, sizeof(buff), fp);
		s = buff;
		printf("s: %s\n", s);

		p = strstr(buff, "IsEnable");
		if(p != NULL)
		{
			q = strchr(p, ',');
			if(q != NULL)
				strncpy(isenable, p-1, q- (p-1));

			printf("isenable: %s\n", isenable);
			
		}
		
		while((p = strstr(s, "ServiceName")) != NULL)
		{
			if((q = strchr(p, '}')) != NULL)
			{
				strncpy(entry[i], p-2, (q+1) - (p-2));
				i++;
				s = q + 1;
			}
		}
		fclose(fp);
	}
	
	sprintf(buff, "{%s,\"PortForwardList\":[", isenable);
	printf("buff: %s\n", buff);

	char portrage[1024] = {0};
	int tmpflag = 0;
	
	for(j=0; j<i; j++)
	{
		if((p = strstr(entry[j], "PortRange")) != NULL)
		{
			q = strchr(p, ':');
			s = strchr(p, ',');
			if(q != NULL && s != NULL)
			{
				memset(portrage, 0, sizeof(portrage));
				strncpy(portrage, q+2, (s-1)-(q+2));
				printf("portrage: %s\n", portrage);
			}
		}

		if ((p = strstr(portrage, ":")) != NULL)
			*p = '\0';

		if(strcmp(portrage, ExternalPort) == 0)
		{
			continue;
		}
		printf("entry[j]: %s\n", entry[j]);
		strcat(buff, entry[j]);
		strcat(buff, ",");
		tmpflag++;
	}
	if(tmpflag != 0)
	{
		p = strrchr(buff, ',');
		if(p != NULL)
		{
			*p = '\0';
		}
	}
 	strcat(buff, "]}");

	fp = fopen("/etc/portforwarding_save.txt", "w");
	if(fp != NULL)
	{
		fputs(buff, fp);
		fclose(fp);
	}*/
}

int lib_del_portmapping_object(node_t node)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i,j;
	char ExternalPort[128] = {0};
	char protocol[128] = {0};
	char port_protocol[256] = {0};
	int instance;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(PortMappingMap,mapInfos,MAXMAPITEMS); 
	
	char paraname[128] = {0};
	node_t target;
	int count = 0;
	int found = 0;
	
	instance = atoi(node->name);
	printf("lib_del_portmapping_object : node->name :%s\n",node->name);
	node_t child;

	memset(ExternalPort,0,sizeof(ExternalPort));
	for( ; node->children; ) 
	{
		found = 0;
		child = node->children;
		node->children = child->brother;

		if (strcmp(child->name, "ExternalPort") == 0)
		{
		   strcpy(ExternalPort,child->value);
		   count++;
		}
		if (strcmp(child->name, "Protocol") == 0)
		{
			if(strcasecmp(child->value, "tcp") == 0)
			{
				strcpy(protocol, "0");
				found = 1;
			}
			else if(strcasecmp(child->value, "udp") == 0)
			{
				strcpy(protocol, "1");
				found = 1;
			}
			else if(strcasecmp(child->value, "both") == 0)
			{
				strcpy(protocol, "2");
				found = 1;
			}
			if (found == 1)
				count++;
		}
		//printf("========found protocol count=[%d]=====\n", count);
		if(count == 2)
		{
			//printf("========found protocol =====\n");
			sprintf(port_protocol, "%s_%s", ExternalPort, protocol);
			//printf("========found protocol =====port_protocol=[%s]\n", port_protocol);
			break;
		}
		
	}
	printf("port_protocol :%s\n", port_protocol);
	for(i=0;i<MAXMAPITEMS;i++)
	{
		//printf("mapInfos[i].valid=[%d], mapInfos[i].instance=[%d], instance=[%d]\n", mapInfos[i].valid, mapInfos[i].instance, instance);
		//printf("mapInfos[i].value=[%s], port_protocol=[%s]\n", mapInfos[i].value, port_protocol);
	   if ((mapInfos[i].valid) && (mapInfos[i].instance == instance) 
		&& (strcmp(mapInfos[i].value,port_protocol) == 0))
	   {
		  mapInfos[i].valid = 0;
		  delete_portmapping_entry(port_protocol);
	   }
	}
	
	lib_save_mapfile(PortMappingMap,mapInfos,MAXMAPITEMS);

	return 0;
}

int delete_GREFilter_entry(int instance)
{
	char name[128]={0};
	char buff[256] = {0};
	char tmpbuf[256] = {0};
	char *p = NULL;
	char FilterNumberOfEntries[256] = {0};

	sprintf(name, "trconf.Device_GRE_Filter_%d", instance);	
	printf("name = %s\n", name);
	do_uci_delete(name,NULL);	
	
	do_uci_get("trconf.Device_GRE.FilterNumberOfEntries", FilterNumberOfEntries);
	if(atoi(FilterNumberOfEntries) > 0)
	{
		sprintf(tmpbuf, "%d", (atoi(FilterNumberOfEntries)-1));
		do_uci_set("trconf.Device_GRE.FilterNumberOfEntries", tmpbuf);
	}
	do_uci_commit(MS);
}

int delete_qosShaper_entry(int instance)
{
	char name[128]={0};
	char buff[256] = {0};
	char tmpbuf[256] = {0};
	char *p = NULL;
	char ShaperNumberOfEntries[256] = {0};

	sprintf(name, "shaper.Device_QoS_Shaper_%d", instance);	
	printf("name = %s\n", name);
	do_uci_delete(name,NULL);
	do_uci_commit(SHAPER);
	
	do_uci_get(SHAPERNUMBEROFENTRIES_PATH, ShaperNumberOfEntries);
	if(atoi(ShaperNumberOfEntries) > 0)
	{
		sprintf(tmpbuf, "%d", (atoi(ShaperNumberOfEntries)-1));
		do_uci_set(SHAPERNUMBEROFENTRIES_PATH, tmpbuf);
	}
	do_uci_commit(QOSNUMBERENTRIES);
}

int delete_qosQueue_entry(char* Alias)
{
	char name[128]={0};
	char buff[256] = {0};
	char tmpbuf[256] = {0};
	char *p = NULL;
	char QueueNumberOfEntries[256] = {0};
	char MaxQueueEntries[256] = {0};
	int ret = 0;
	int i;
	char linebuf[128] = {0};
	char tmparray[64] = {0};
	char valbuf[64] = {0};
	
	ret = do_uci_get("qos.number.MaxQueueEntries", MaxQueueEntries);
	printf("MaxQueueEntries :%d\n", atoi(MaxQueueEntries));
	for(i=1; i<atoi(MaxQueueEntries); i++)
	{
		sprintf(tmparray, "qos.queue%d", i);
		sprintf(linebuf, "%s.Alias", tmparray);
		do_uci_get(linebuf, valbuf);
		tr_log(LOG_DEBUG,"linebuf [%s]",linebuf);
		tr_log(LOG_DEBUG,"valbuf [%s]",valbuf);

		if(strcmp(valbuf, Alias) == 0)
		{
			do_uci_delete(tmparray,NULL);	
			break;
		}
	}
	
	do_uci_get(QUEUENUMBEROFENTRIES_PATH, QueueNumberOfEntries);
	if(atoi(QueueNumberOfEntries) > 0)
	{
		sprintf(tmpbuf, "%d", (atoi(QueueNumberOfEntries)-1));
		do_uci_set(QUEUENUMBEROFENTRIES_PATH, tmpbuf);
	}
	do_uci_commit(QOSNUMBERENTRIES);
}

int delete_qosApp_entry(int instance)
{
	char name[128]={0};
	char buff[256] = {0};
	char tmpbuf[256] = {0};
	char *p = NULL;
	char AppNumberOfEntries[256] = {0};

	sprintf(name, "trconf.Device_QoS_App_%d", instance);	
	printf("name = %s\n", name);
	do_uci_delete(name,NULL);	
	
	do_uci_get(DQ_AppNumberOfEntries, AppNumberOfEntries);
	if(atoi(AppNumberOfEntries) > 0)
	{
		sprintf(tmpbuf, "%d", (atoi(AppNumberOfEntries)-1));
		do_uci_set(DQ_AppNumberOfEntries, tmpbuf);
	}
	do_uci_commit(MS);
}


int delete_qosclassfication_entry(char *Alias)
{
	char name[128]={0};
	char tmpbuf[256] = {0};
	char linebuf[128] = {0};
	char valbuf[64] = {0};
	char ClassificationNumberOfEntries[256] = {0};
	char MaxClassificationEntries[256] = {0};
	int i = 0;

	do_uci_get("qos.number.MaxClassificationEntries", MaxClassificationEntries);
	while(i < atoi(MaxClassificationEntries))
	{
		i++;
		sprintf(tmpbuf, "qos.cf%d", i);
		sprintf(linebuf, "%s.Alias", tmpbuf);
		do_uci_get(linebuf, valbuf);
		tr_log(LOG_DEBUG,"linebuf [%s]",linebuf);
		tr_log(LOG_DEBUG,"valbuf [%s]",valbuf);

		if(strcmp(valbuf, Alias) == 0)
		{
			do_uci_delete(tmpbuf,NULL);	
			break;
		}
	}
	
	do_uci_get(CLASSIFICATIONNUMBEROFENTRIES_PATH, ClassificationNumberOfEntries);
	if(atoi(ClassificationNumberOfEntries) > 0)
	{
		sprintf(tmpbuf, "%d", (atoi(ClassificationNumberOfEntries)-1));
		do_uci_set(CLASSIFICATIONNUMBEROFENTRIES_PATH, tmpbuf);
	}
	do_uci_commit(QOSNUMBERENTRIES);
}

int lib_del_GREFilter_object(node_t node)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i,j;
	char Order[32];
	int instance;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(GREFilterMap,mapInfos,MAXMAPITEMS); 

	char paraname[128];
	node_t target;
	
	instance = atoi(node->name);
	printf("lib_del_GRETunnel_object : node->name :%s\n",node->name);
	node_t child;

	memset(Order,0,sizeof(Order));
	for( ; node->children; ) 
	{
		child = node->children;
		node->children = child->brother;

		if (strcmp(child->name, "Order") == 0)
		{
		   strcpy(Order,child->value);
		   break;
		}
		
	}
	printf("Order :%s\n", Order);
	for(i=0;i<MAXMAPITEMS;i++)
	{
	   if ((mapInfos[i].valid) && (mapInfos[i].instance == instance) && (strcmp(mapInfos[i].value,Order) == 0))
	   {
		  delete_GREFilter_entry(mapInfos[i].instance);
		  mapInfos[i].valid = 0;
	   }
	}
	
	lib_save_mapfile(GREFilterMap,mapInfos,MAXMAPITEMS);

	return 0;
}

int lib_del_qosShaper_object(node_t node)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i,j;
	char Alias[128];
	int instance;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(QoSShaperMap,mapInfos,MAXMAPITEMS); 
	
	char paraname[128];
	node_t target;
	
	instance = atoi(node->name);
	printf("lib_del_qosShaper_object : node->name :%s\n",node->name);
	node_t child;

	memset(Alias,0,sizeof(Alias));
	for( ; node->children; ) 
	{
		child = node->children;
		node->children = child->brother;

		if (strcmp(child->name, "Alias") == 0)
		{
		   strcpy(Alias,child->value);
		   break;
		}
		
	}
	printf("Alias :%s\n", Alias);
	for(i=0;i<MAXMAPITEMS;i++)
	{
	   if ((mapInfos[i].valid) && (mapInfos[i].instance == instance) && (strcmp(mapInfos[i].value,Alias) == 0))
	   {
		  delete_qosShaper_entry(mapInfos[i].instance);
		  mapInfos[i].valid = 0;
	   }
	}
	
	lib_save_mapfile(QoSShaperMap,mapInfos,MAXMAPITEMS);

	return 0;
}

int lib_del_qosQueue_object(node_t node)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i,j;
	char Alias[128];
	int instance;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(QoSQueueMap,mapInfos,MAXMAPITEMS); 
   
	char paraname[128];
	node_t target;
	
	instance = atoi(node->name);
	printf("lib_del_qosQueue_object : node->name :%s\n",node->name);
	node_t child;

	memset(Alias,0,sizeof(Alias));
	for( ; node->children; ) 
	{
		child = node->children;
		node->children = child->brother;

		if (strcmp(child->name, "Alias") == 0)
		{
		   strcpy(Alias,child->value);
		   break;
		}
	}
	printf("Alias :%s\n", Alias);
	for(i=0;i<MAXMAPITEMS;i++)
	{
	   if ((mapInfos[i].valid) && (mapInfos[i].instance == instance) && (strcmp(mapInfos[i].value,Alias) == 0))
	   {
		  delete_qosQueue_entry(Alias);
		  mapInfos[i].valid = 0;
	   }
	}
	
	lib_save_mapfile(QoSQueueMap,mapInfos,MAXMAPITEMS);

	return 0;
}

int lib_del_qosApp_object(node_t node)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i,j;
	char Alias[128];
	int instance;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(QoSAppMap,mapInfos,MAXMAPITEMS); 
   
	char paraname[128];
	node_t target;
	
	instance = atoi(node->name);
	printf("lib_del_qosApp_object : node->name :%s\n",node->name);
	node_t child;

	memset(Alias,0,sizeof(Alias));
	for( ; node->children; ) 
	{
		child = node->children;
		node->children = child->brother;

		if (strcmp(child->name, "Alias") == 0)
		{
		   strcpy(Alias,child->value);
		   break;
		}
	}
	printf("Alias :%s\n", Alias);
	for(i=0;i<MAXMAPITEMS;i++)
	{
	   if ((mapInfos[i].valid) && (mapInfos[i].instance == instance) && (strcmp(mapInfos[i].value,Alias) == 0))
	   {
		  delete_qosApp_entry(mapInfos[i].instance);
		  mapInfos[i].valid = 0;
	   }
	}
	
	lib_save_mapfile(QoSAppMap,mapInfos,MAXMAPITEMS);

	return 0;
}


int lib_del_qosclassfication_object(node_t node)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i,j;
	char Alias[128];
	int instance;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(QoSClassificationMap,mapInfos,MAXMAPITEMS); 
   
	
	char paraname[128];
	node_t target;
	
	instance = atoi(node->name);
	printf("lib_del_qosclassfication_object : node->name :%s\n",node->name);
	node_t child;

	memset(Alias,0,sizeof(Alias));
	for( ; node->children; ) 
	{
		child = node->children;
		node->children = child->brother;

		if (strcmp(child->name, "Alias") == 0)
		{
		   strcpy(Alias,child->value);
		   break;
		}
		
	}
	printf("Alias :%s\n", Alias);
	for(i=0;i<MAXMAPITEMS;i++)
	{
	   if ((mapInfos[i].valid) && (mapInfos[i].instance == instance) && (strcmp(mapInfos[i].value,Alias) == 0))
	   {
		  delete_qosclassfication_entry(mapInfos[i].value);
		  mapInfos[i].valid = 0;
	   }
	}
	
	lib_save_mapfile(QoSClassificationMap,mapInfos,MAXMAPITEMS);

	return 0;
}

int delete_routingipv4_entry(char *routing)
{
	int found = 0;
	char name[128]={0};
	char buff[256] = {0};
	char tmpbuf[256] = {0};

	found = isStaticRoute(routing);
	sprintf(name,"network.staticrt_%d", (found-1));
	printf("found = %d\n", found);
	printf("name = %s\n", name);
	do_uci_delete(name,NULL);	
	sprintf(name,"staticrt.routelist_%d", (found-1));
	printf("name = %s\n", name);
	do_uci_delete(name,NULL);
	do_uci_get("staticrt.staticrt.listnum", buff);
	if(atoi(buff) > 0)
	{
		sprintf(tmpbuf, "%d", (atoi(buff)-1));
		do_uci_set("staticrt.staticrt.listnum", tmpbuf);
		system("ubus call network reload");
	}
	
}
int lib_del_routingipv4_object(node_t node)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i,j;
	char DestIPAddress[128];
	int instance;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(RouterIPv4Map,mapInfos,MAXMAPITEMS); 
   
	
	char paraname[128];
	node_t target;
	
	instance = atoi(node->name);
	printf("lib_del_portmapping_object : node->name :%s\n",node->name);
	node_t child;

	memset(DestIPAddress,0,sizeof(DestIPAddress));
	for( ; node->children; ) 
	{
		child = node->children;
		node->children = child->brother;

		if (strcmp(child->name, "DestIPAddress") == 0)
		{
		   strcpy(DestIPAddress,child->value);
		   break;
		}
		
	}
	printf("DestIPAddress :%s\n", DestIPAddress);
	for(i=0;i<MAXMAPITEMS;i++)
	{
	   if ((mapInfos[i].valid) && (mapInfos[i].instance == instance))
	   {
		  //delete_routingipv4_entry(mapInfos[i].value);
		  mapInfos[i].valid = 0;
	   }
	}
	
	lib_save_mapfile(RouterIPv4Map,mapInfos,MAXMAPITEMS);

	return 0;
}

int add_GREFilter_entry(uint32_t instance)
{
	char FilterNumberOfEntries[256] = {0};
	char name[256] = {0};
	char tmpbuf[256]={0};
	char cmdbuf[256]={0};

	memset(FilterNumberOfEntries, 0, sizeof(FilterNumberOfEntries));
	do_uci_get("trconf.Device_GRE.FilterNumberOfEntries", FilterNumberOfEntries);
	sprintf(tmpbuf, "%d", atoi(FilterNumberOfEntries)+1);
	do_uci_set("trconf.Device_GRE.FilterNumberOfEntries", tmpbuf);

	do_uci_add("trconf","acs",tmpbuf);
	sprintf(cmdbuf, "trconf.%s", tmpbuf);
	sprintf(name,"Device_GRE_Filter_%d", instance);
	do_uci_rename(cmdbuf, name);
	do_uci_commit(MS);
}

//uci_tmp_config_name  queue_template.template
int add_template_node(int index,char *uci_tmp_config_name, char *created_qos_name)
{
        int ret_rename=0;
        int ret_commit=0;
        char file_input[64]={0};//file :exp:  /etc/config/queue_template
        char file_output[64]={0};//file: exp: /etc/config/queue
	
        char old_config_name[64]={0};// queue_template
        char new_config_name[64]={0};//queue

        char old_section_name[64]={0};//template
        char new_section_name[64]={0};//Device_QoS_Queue_%d
		
        char old_config_path[64]={0};//queue_template.template
        char new_config_path[64]={0};//queue.Device_QoS_Queue_%d
        char tmp_config_path[64]={0};//queue_template.Device_QoS_Queue_%d   //old_section_name Has been modified.

        char nothing[64]={0};
        memset (file_input,0,sizeof(file_input));
        memset (file_output,0,sizeof(file_output));
        
        memset (old_config_name,0,sizeof(old_config_name));
        memset (new_config_name,0,sizeof(new_config_name));
        memset (old_section_name,0,sizeof(old_section_name));
        memset (new_section_name,0,sizeof(new_section_name));
		
        memset (old_config_path,0,sizeof(old_config_path));         
        memset (new_config_path,0,sizeof(new_config_path));
    
        memset (tmp_config_path,0,sizeof(tmp_config_path));
        memset (nothing,0,sizeof(nothing));
        //old section name
        sprintf(old_section_name,"template");

        //new section name
        if(strcmp(uci_tmp_config_name, "queue_template") == 0)
                sprintf(new_section_name,"Device_QoS_Queue_%d",index);
        if(strcmp(uci_tmp_config_name, "classification_template") == 0)
                sprintf(new_section_name,"Device_QoS_Classification_%d",index);
        if(strcmp(uci_tmp_config_name, "shaper_template") == 0)
                sprintf(new_section_name,"Device_QoS_Shaper_%d",index);
        //old_config_name for commit uci config
        sprintf(old_config_name,uci_tmp_config_name);

        PR_DEBUG("1   old_section_name=%s\n",old_section_name);
        PR_DEBUG("1   new_section_name=%s\n",new_section_name);

        //old config modify section name       
        sprintf(old_config_path,"%s.template",uci_tmp_config_name);//queue_template.template
        PR_DEBUG("2   old_config_path =%s\n",old_config_path);

        sprintf(new_config_path,"%s.%s",created_qos_name,new_section_name);//queue.Device_QoS_Queue_%d
        PR_DEBUG("2   new_config_path =%s\n",new_config_path);
    
        //modify old_config_path section name to Device_QoS_Queue_%d
        ret_rename = do_uci_rename(old_config_path, new_section_name);
        //commit the modify section name to file
        ret_commit = do_uci_commit(old_config_name);
        PR_DEBUG("3   Enter? [ret_rename=%d]  [ret_commit=%d]\n", ret_rename ,ret_commit);

        PR_DEBUG("3   Check if new section exists? 0=Yes ===%d\n", do_uci_get(new_config_path,nothing));
	
        //copy template node for creat new uci file(queue ,  classifcation)
        if(do_uci_get(new_config_path,nothing)!=0)//new section is not exists, so we creat it
        {
                PR_DEBUG("3   new section is not exists, so we creat it\n");
                if(ret_rename==0 && ret_commit==0)
                {
                    FILE *fi,*fo;
                        char c;
                        sprintf(file_input, "%s%s",TABLE_PATH,uci_tmp_config_name);
                        sprintf(file_output, "%s%s",TABLE_PATH,created_qos_name);
                        PR_DEBUG("TABLE_PATH=%s\n",TABLE_PATH);
                        PR_DEBUG("file_input=%s\n",file_input);
                        PR_DEBUG("file_output=%s\n",file_output);
                        
                        fi=fopen(file_input,"r");
                        fo=fopen(file_output,"ab");
                        while(fscanf(fi,"%c",&c)!=EOF)
                            fprintf(fo,"%c",c);
                                fclose(fi);
                                fclose(fo);
                                PR_DEBUG("Created Success!\n");
                }
                else
                {
                    PR_DEBUG("Created Fail!\n");
                    return -1;
                }
        }
        else
        {
                PR_DEBUG("3   new section is exists, so we needn't creat it\n");
        }
                        //modify section name
                
        sprintf(tmp_config_path,"%s.%s",old_config_name,new_section_name);
        PR_DEBUG("4   tmp_config_path=%s\n",tmp_config_path);
                    
        ret_rename = do_uci_rename(tmp_config_path,old_section_name);
        //sava the modify section name to file
        ret_commit = do_uci_commit(old_config_name);
        if(ret_rename==0 && ret_commit==0)
        {
                PR_DEBUG("5   Reset Success! [ret_rename=%d]  [ret_commit=%d]\n", ret_rename,ret_commit);
                return 0;
        }
        else
        {
                PR_DEBUG("5   Reset Fail  [ret_rename=%d]  [ret_commit=%d]\n", ret_rename,ret_commit);
                return -1;
        }
}

int add_qosShaper_entry(uint32_t instance)
{
	char ShaperNumberOfEntries[256] = {0};
	char name[256] = {0};
	char tmpbuf[256]={0};
	char cmdbuf[256]={0};
	
	int   shaper_number=instance;
	char template_name[64]={0};
	char qos_name[64]={0};
	tr_log(LOG_NOTICE,"ShaperNumberOfEntries XXXXX==%s\n",ShaperNumberOfEntries);
	sprintf(template_name,"shaper_template");
	sprintf(qos_name,"shaper");          
	add_template_node(shaper_number,template_name,qos_name);//for shaper
	//int add_template_node(int index,char *uci_tmp_config_name, char *created_qos_name)

	memset(ShaperNumberOfEntries, 0, sizeof(ShaperNumberOfEntries));
	do_uci_get(SHAPERNUMBEROFENTRIES_PATH, ShaperNumberOfEntries);
	tr_log(LOG_NOTICE,"ShaperNumberOfEntries before OOOOO==%s\n",ShaperNumberOfEntries);
	sprintf(tmpbuf, "%d", atoi(ShaperNumberOfEntries)+1);
	do_uci_set(SHAPERNUMBEROFENTRIES_PATH, tmpbuf);
	do_uci_commit(QOSNUMBERENTRIES);

/*	do_uci_add("trconf","acs",tmpbuf);
	sprintf(cmdbuf, "trconf.%s", tmpbuf);
	sprintf(name,"Device_QoS_Shaper_%d", instance);
	do_uci_rename(cmdbuf, name);
	sprintf(name, "Shaper.Device_QoS_Shaper_%d.Enable", instance);	
	do_uci_set(name, "0");
	do_uci_commit(MS);

*/
	
}

int add_qosqueue_entry(uint32_t instance)
{
	char QueueNumberOfEntries[256] = {0};
	char name[256] = {0};
	char tmpbuf[256]={0};
	char cmdbuf[256]={0};

	memset(QueueNumberOfEntries, 0, sizeof(QueueNumberOfEntries));
	do_uci_get(QUEUENUMBEROFENTRIES_PATH, QueueNumberOfEntries);
	sprintf(tmpbuf, "%d", atoi(QueueNumberOfEntries)+1);
	do_uci_set(QUEUENUMBEROFENTRIES_PATH, tmpbuf);
	
	do_uci_add("qos","queue",tmpbuf);
	sprintf(cmdbuf, "qos.%s", tmpbuf);
	sprintf(name,"queue%d", instance);
	do_uci_rename(cmdbuf, name);
	sprintf(name, "qos.queue%d.Enable", instance);	
	do_uci_set(name, "0");
	sprintf(name, "qos.queue%d.Alias", instance);	
	sprintf(tmpbuf, "cpe-%d", instance); 		
	do_uci_set(name, tmpbuf);
	do_uci_commit("qos");
}

int add_qosApp_entry(uint32_t instance)
{
	char AppNumberOfEntries[256] = {0};
	char name[256] = {0};
	char tmpbuf[256]={0};
	char cmdbuf[256]={0};

	memset(AppNumberOfEntries, 0, sizeof(AppNumberOfEntries));
	do_uci_get(DQ_AppNumberOfEntries, AppNumberOfEntries);
	sprintf(tmpbuf, "%d", atoi(AppNumberOfEntries)+1);
	do_uci_set(DQ_AppNumberOfEntries, tmpbuf);

	do_uci_add("trconf","acs",tmpbuf);
	sprintf(cmdbuf, "trconf.%s", tmpbuf);
	sprintf(name,"Device_QoS_App_%d", instance);
	do_uci_rename(cmdbuf, name);
	sprintf(name, "trconf.Device_QoS_App_%d.Enable", instance);	
	do_uci_set(name, "0");
	do_uci_commit(MS);
}

int add_qosclassfication_entry(uint32_t instance)
{
	char ClassificationNumberOfEntries[256] = {0};
	char MaxClassificationEntries[256] = {0};
	char name[256] = {0};
	char tmpbuf[256]={0};
	char cmdbuf[256]={0};
	int j = 0;
	int entrynum = 0;

	memset(ClassificationNumberOfEntries, 0, sizeof(ClassificationNumberOfEntries));
	memset(MaxClassificationEntries, 0, sizeof(MaxClassificationEntries));
	do_uci_get("qos.number.ClassificationNumberOfEntries", ClassificationNumberOfEntries);
	do_uci_get("qos.number.MaxClassificationEntries", MaxClassificationEntries);
	sprintf(tmpbuf, "%d", atoi(ClassificationNumberOfEntries)+1);
	do_uci_set("qos.number.ClassificationNumberOfEntries", tmpbuf);

	memset(tmpbuf,0,sizeof(tmpbuf));
	sprintf(name, "qos.cf%d", instance);		
	do_uci_get(name,tmpbuf);
	
	if(strcmp(tmpbuf, "ClassificationList") != 0)
	{
		entrynum = instance;
	}
	else
	{
		while(j < atoi(MaxClassificationEntries))
		{
			memset(tmpbuf,0,sizeof(tmpbuf));
			j++;
			sprintf(name, "qos.cf%d", j);		
			do_uci_get(name,tmpbuf);
			tr_log( LOG_NOTICE, "name: %s", name);
			tr_log( LOG_NOTICE, "value: %s", tmpbuf);

			if(strcmp(tmpbuf, "ClassificationList") != 0)
			{
				entrynum = j;
				break;
			}
		}
	}

	do_uci_add("qos","ClassificationList",tmpbuf);
	sprintf(cmdbuf, "qos.%s", tmpbuf);
	sprintf(name,"cf%d", entrynum);
	tr_log( LOG_NOTICE, "name: %s", name);
	do_uci_rename(cmdbuf, name);
	sprintf(name, "qos.cf%d.Enable", entrynum);		
	do_uci_set(name, "0");
	sprintf(name, "qos.cf%d.Name", entrynum);	
	sprintf(tmpbuf, "TR%d", entrynum); 		
	do_uci_set(name, tmpbuf);
	sprintf(name, "qos.cf%d.Alias", entrynum);
	sprintf(tmpbuf, "cpe-%d", entrynum);
	do_uci_set(name, tmpbuf);
	/*sprintf(name, "qos.cf%d.TrafficClass", entrynum);
	do_uci_set(name, "20");*/
	do_uci_commit(QOSNUMBERENTRIES);
	return entrynum;
}

int lib_add_GREFilter_object(node_t node, uint32_t instance)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i = 0,j = 0;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(GREFilterMap, mapInfos, MAXMAPITEMS); 
	
	/* 
	  * need to get a new eth link 
	  *
	  *  to do sth	
	  *
	  *and add in mapping file*/
	
	char paraname[128];
	node_t target;
	char value[256] = {0};

	for(i=0,j=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 1)
		{
			j++;
		}
	}

	if (j >= node->il){
		tr_log(LOG_NOTICE,"Number is larger than node->il");
		return -1;
	}

	add_GREFilter_entry(instance);
	sprintf(paraname,"Device.GRE.Filter.%d.Order", instance);
	tr_log(LOG_NOTICE,"lib_add_GREFilter_object: full path name %s",paraname);
	sprintf(value, "%d", instance);		
	if (lib_resolve_node(paraname,&target) == 0)
	{
		lib_set_value(target, value);
	}

	for(i=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 0)
		{
			mapInfos[i].valid = 1;
			mapInfos[i].instance = instance;
			strcpy(mapInfos[i].value, value ); //init key vlaue
			break;
		}
	}
	
	lib_save_mapfile(GREFilterMap,mapInfos,MAXMAPITEMS);
	return 0;
}

int lib_add_qosShaper_object(node_t node, uint32_t instance)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i = 0,j = 0;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(QoSShaperMap, mapInfos, MAXMAPITEMS); 
	
	/* 
	  * need to get a new eth link 
	  *
	  *  to do sth	
	  *
	  *and add in mapping file*/
	
	char paraname[128];
	node_t target;
	char value[256] = {0};

	for(i=0,j=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 1)
		{
			j++;
		}
	}

	if (j >= node->il){
		tr_log(LOG_NOTICE,"Number is larger than node->il");
		return -1;
	}

	add_qosShaper_entry(instance);
	sprintf(paraname,"Device.QoS.Shaper.%d.Alias", instance);
	tr_log(LOG_NOTICE,"lib_add_qosShaper_object: full path name %s",paraname);
	tr_log(LOG_ERROR,"lib_add_qosShaper_object: full path name %s",paraname);
	sprintf(value, "cpe-QoSShaper_%d", instance);
	PR_DEBUG("lib_add_qosShaper_object instance==%d value==%s\n", instance,value);
	if (lib_resolve_node(paraname,&target) == 0)
	{
		lib_set_value(target, value);
	}

	for(i=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 0)
		{
			mapInfos[i].valid = 1;
			mapInfos[i].instance = instance;
			strcpy(mapInfos[i].value, value ); //init key vlaue
			break;
		}
	}
	
	lib_save_mapfile(QoSShaperMap,mapInfos,MAXMAPITEMS);
	return 0;
}

int lib_add_qosQueue_object(node_t node, uint32_t instance)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i = 0,j = 0;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(QoSQueueMap, mapInfos, MAXMAPITEMS); 
	
	/* 
	  * need to get a new eth link 
	  *
	  *  to do sth	
	  *
	  *and add in mapping file*/
	
	char paraname[128];
	node_t target;
	char value[256] = {0};

	for(i=0,j=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 1)
		{
			j++;
		}
	}

	if (j >= node->il){
		tr_log(LOG_NOTICE,"Number is larger than node->il");
		return -1;
	}

	add_qosqueue_entry(instance);
	sprintf(paraname,"Device.QoS.Queue.%d.Alias", instance);
	tr_log(LOG_NOTICE,"lib_add_qosQueue_object: full path name %s",paraname);
	sprintf(value, "cpe-%d", instance); 		
	if (lib_resolve_node(paraname,&target) == 0)
	{
		lib_set_value(target, value);
	}

	for(i=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 0)
		{
			mapInfos[i].valid = 1;
			mapInfos[i].instance = instance;
			strcpy(mapInfos[i].value, value ); //init key vlaue
			break;
		}
	}
	
	lib_save_mapfile(QoSQueueMap,mapInfos,MAXMAPITEMS);
	return 0;
}

int lib_add_qosApp_object(node_t node, uint32_t instance)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i = 0,j = 0;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(QoSAppMap, mapInfos, MAXMAPITEMS); 
	
	/* 
	  * need to get a new eth link 
	  *
	  *  to do sth	
	  *
	  *and add in mapping file*/
	
	char paraname[128];
	node_t target;
	char value[256] = {0};

	for(i=0,j=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 1)
		{
			j++;
		}
	}

	if (j >= node->il){
		tr_log(LOG_NOTICE,"Number is larger than node->il");
		return -1;
	}

	add_qosApp_entry(instance);
	sprintf(paraname,"Device.QoS.App.%d.Alias", instance);
	tr_log(LOG_NOTICE,"lib_add_qosApp_object: full path name %s",paraname);
	sprintf(value, "cpe-QoSApp_%d", instance);
	tr_log(LOG_NOTICE,"In lib_add_qosApp_object() : instance==%d value==%s\n", instance,value);
	if (lib_resolve_node(paraname,&target) == 0)
	{
		lib_set_value(target, value);
	}

	for(i=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 0)
		{
			mapInfos[i].valid = 1;
			mapInfos[i].instance = instance;
			strcpy(mapInfos[i].value, value ); //init key vlaue
			break;
		}
	}
	
	lib_save_mapfile(QoSAppMap,mapInfos,MAXMAPITEMS);
	return 0;
}


int lib_add_qosclassfication_object(node_t node, uint32_t instance)
{
	mapInfo_t mapInfos[MAXMAPITEMS];
	int i = 0,j = 0;
	int entrynum = 0;

	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(QoSClassificationMap, mapInfos, MAXMAPITEMS); 
	
	/* 
	  * need to get a new eth link 
	  *
	  *  to do sth	
	  *
	  *and add in mapping file*/
	
	char paraname[128];
	node_t target;
	char value[256] = {0};

	for(i=0,j=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 1)
		{
			j++;
		}
	}

	if (j >= node->il){
		tr_log(LOG_NOTICE,"Number is larger than node->il");
		return -1;
	}

	entrynum = add_qosclassfication_entry(instance);
	sprintf(paraname,"Device.QoS.Classification.%d.Alias", instance);
	tr_log(LOG_NOTICE,"lib_add_qosclassfication_object: full path name %s",paraname);
	sprintf(value, "cpe-%d", entrynum); 		
	if (lib_resolve_node(paraname,&target) == 0)
	{
		lib_set_value(target, value);
	}

	for(i=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 0)
		{
			mapInfos[i].valid = 1;
			mapInfos[i].instance = instance;
			strcpy(mapInfos[i].value, value ); //init key vlaue
			break;
		}
	}
	
	lib_save_mapfile(QoSClassificationMap,mapInfos,MAXMAPITEMS);
	return 0;
}

int add_routingipv4_entry()
{
	char buff[128] = {0};
	char name[128] = {0};
	char tmpbuf[128] = {0};
	char cmdbuf[128] = {0};
	char en[64] = {0};
	char linebuf[128] = {0};
	int ret = 0;

	do_uci_get("staticrt.staticrt.enable", en);

	if (atoi(en) == 0)
		return -1;
	
	do_uci_get("staticrt.staticrt.listnum", buff);
	sprintf(tmpbuf, "%d", (atoi(buff)+1));
	do_uci_set("staticrt.staticrt.listnum", tmpbuf);
	tr_log(LOG_NOTICE,"+++++++++++++++buff:%s, tmpbuf:%s\n", buff, tmpbuf);

	ret = do_uci_add("staticrt","staticrt",tmpbuf);
	sprintf(linebuf, "staticrt.%s", tmpbuf);
	sprintf(name,"%s%d","routelist_",atoi(buff));
	tr_log(LOG_NOTICE,"+++++++++++++++name:%s, linebuf:%s\n", name, linebuf);
	ret = do_uci_rename(linebuf, name);
	
	sprintf(name,"%s%d.hostip","staticrt.routelist_",atoi(buff));
	tr_log(LOG_NOTICE,"+++++++++++++++name:%s\n",name);
	
	ret = do_uci_set(name,"1.255.255.255"); //tmp value, after adding, MUST rewrite this value
	sprintf(name,"%s%d.netmask","staticrt.routelist_",atoi(buff));
	tr_log(LOG_NOTICE,"+++++++++++++++name:%s\n",name);
	ret = do_uci_set(name,"255.255.255.255");
	sprintf(name,"%s%d.gateway","staticrt.routelist_",atoi(buff));
	tr_log(LOG_NOTICE,"+++++++++++++++name:%s\n",name);
	ret = do_uci_set(name,"1.1.1.1");
	sprintf(name,"%s%d.metric","staticrt.routelist_",atoi(buff));
	tr_log(LOG_NOTICE,"+++++++++++++++name:%s\n",name);
	ret = do_uci_set(name,"0");
	sprintf(name,"%s%d.interface","staticrt.routelist_",atoi(buff));
	tr_log(LOG_NOTICE,"+++++++++++++++name:%s\n",name);
	ret = do_uci_set(name,"1");

	do_uci_add("network","route",tmpbuf);
	sprintf(cmdbuf, "network.%s", tmpbuf);
	sprintf(name,"staticrt_%d",atoi(buff));
	do_uci_rename(cmdbuf, name);
		
	sprintf(name,"network.staticrt_%d.interface", atoi(buff));
	do_uci_set(name, "lan");
	sprintf(name,"network.staticrt_%d.target", atoi(buff));
	do_uci_set(name, "1.255.255.255");
	sprintf(name,"network.staticrt_%d.netmask", atoi(buff));
	do_uci_set(name, "255.255.255.255");
	sprintf(name,"network.staticrt_%d.gateway", atoi(buff));
	do_uci_set(name, "1.1.1.1");
	sprintf(name,"network.staticrt_%d.metric", atoi(buff));
	do_uci_set(name, "0");
	do_uci_commit("staticrt");
	do_uci_commit("network");

	return 1;
}

int lib_add_routingipv4_object(node_t node, uint32_t instance)
{
	char buff[8192] = {0};
	FILE *fp = NULL;
	char *p = NULL;
	char *q = NULL;
	char *s = NULL;
	char entry[32][1024] = {0};
	int i = 0;
	int j = 0;
	char isenable[32] = {0};
	
	mapInfo_t mapInfos[MAXMAPITEMS];
    tr_log(LOG_NOTICE,"lib_add_routingipv4_object 1: %s",node->name);
	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(RouterIPv4Map,mapInfos,MAXMAPITEMS); 

	char paraname[128];
	node_t target;

	for(i=0,j=0;i<MAXMAPITEMS;i++)
	{
		if (mapInfos[i].valid == 1)
		{
			j++;
		}
	}

	if (j >= node->il){
		tr_log(LOG_NOTICE,"Number is larger than node->il");
		return -1;
	}

	sprintf(paraname,"Device.Routing.Router.1.IPv4Forwarding.%d.DestIPAddress", instance);
    tr_log(LOG_NOTICE,"paraname: %s", paraname);
	if (add_routingipv4_entry() == 1){
		for(i=0;i<MAXMAPITEMS;i++)
		{
			if (mapInfos[i].valid == 0)
			{
				mapInfos[i].valid = 1;

				mapInfos[i].instance = instance;

				strcpy(mapInfos[i].value,"1.255.255.255");
				break;
			}
		}

	    lib_save_mapfile(RouterIPv4Map,mapInfos,MAXMAPITEMS);

		if (lib_resolve_node(paraname,&target) == 0) //Must do after the 'lib_save_mapfile'
		{
			lib_set_value(target,"1.255.255.255"); //tmp value
		}
	}
	return 0;
}

/*!
 * \brief after lib_ao, user need to do sth
 *
 * \param node The instance sub tree's root node
 * \return 0 
 */
int lib_ao_commit(node_t node, uint32_t instance)
{
	char *path = NULL;
	int ret = 0;
	
	path = lib_node2path(node);

	if (path)
	{
		printf("Do lib_ao_commit: path=%s, instance=%d\n", path, instance);
		if (strncmp(path,"Device.NAT.PortMapping.",strlen("Device.NAT.PortMapping.")) == 0)
		{
			printf("lib_add_portmapping_object entry\n");
			if(portmappingmodifyflag == 0)
				ret = lib_add_portmapping_object(node, instance);
		}
		if (strncmp(path,"Device.Routing.Router.1.IPv4Forwarding.",strlen("Device.Routing.Router.1.IPv4Forwarding.")) == 0)
		{
			printf("lib_add_routingipv4_object routingipv4modifyflag: %d\n", routingipv4modifyflag);
			if(routingipv4modifyflag == 0)
				ret = lib_add_routingipv4_object(node, instance);
		}

		if (strncmp(path,"Device.QoS.Classification.",strlen("Device.QoS.Classification.")) == 0)
		{
			printf("lib_add_qosclassfication_object qosclassficationmodifyflag: %d\n", qosclassficationmodifyflag);
			if(qosclassficationmodifyflag == 0)
				ret = lib_add_qosclassfication_object(node, instance);
		}

		if (strncmp(path,"Device.QoS.App.",strlen("Device.QoS.App.")) == 0)
		{
			printf("lib_add_qosApp_object lib_add_qosApp_object: %d\n", qosappmodifyflag);
			if(qosappmodifyflag == 0)
				ret = lib_add_qosApp_object(node, instance);
		}

		if (strncmp(path,"Device.QoS.Queue.",strlen("Device.QoS.Queue.")) == 0)
		{
			printf("lib_add_qosQueue_object qosqueuemodifyflag: %d\n", qosqueuemodifyflag);
			if(qosqueuemodifyflag == 0)
				ret = lib_add_qosQueue_object(node, instance);
		}

		/*if (strncmp(path,"Device.QoS.Shaper.",strlen("Device.QoS.Shaper.")) == 0)
		{
			printf("lib_add_qosShaper_object qosshapermodifyflag: %d\n", qosshapermodifyflag);
			if(qosshapermodifyflag == 0)
				ret = lib_add_qosShaper_object(node, instance);
		}*/

		if (strncmp(path,"Device.GRE.Filter.",strlen("Device.GRE.Filter.")) == 0)
		{
			printf("lib_add_GREFilter_object GREFiltermodifyflag: %d\n", GREFiltermodifyflag);
			if(GREFiltermodifyflag == 0)
				ret = lib_add_GREFilter_object(node, instance);
		}
		
		/*if (strncmp(path,"Device.Ethernet.Link",strlen("Device.Ethernet.Link")) == 0)
		{
			lib_add_ethlink_object(node,instance);
		}*/
		if (strncmp(path,"Device.DHCPv4.Server.Pool.1.StaticAddress",strlen("Device.DHCPv4.Server.Pool.1.StaticAddress")) == 0)
		{
			if(staticipmodifyflag == 0)
				ret = lib_add_Device_DHCPv4_Server_Pool_1_StaticAddress_object(node, path, instance);
		}

		if (strncmp(path,"Device.DHCPv6.Client.1.SentOption.",strlen("Device.DHCPv6.Client.1.SentOption.")) == 0)
		{
			if(dhcpv6Sentoptionmodifyflag == 0)
				ret = lib_add_dhcpv6sendoptions_object(node, instance);
		}
		
		if (strncmp(path,"Device.DHCPv4.Server.Pool.1.Option.",strlen("Device.DHCPv4.Server.Pool.1.Option.")) == 0)
		{
			printf("lib_add_dhcpserveroptions_object dhcpserveroptionsmodifyflag: %d\n", dhcpserveroptionsmodifyflag);
			if(dhcpserveroptionsmodifyflag == 0)
				ret = lib_add_dhcpserveroptions_object(node, instance);
		}

		if (strncmp(path,"Device.XMPP.Connection.",strlen("Device.XMPP.Connection.")) == 0)
		{
			printf("lib_add_xmpp_connection_object xmppconnectionmodifyflag: %d\n", xmppconnectionmodifyflag);
			if(xmppconnectionmodifyflag == 0)
				lib_add_xmpp_connection_object(node, instance);
		}
	}
	return ret;
}

/*!
 * \brief after lib_do, user need to do sth
 *
 * \param node The instance sub tree's root node
 * \return 0 
 */
int lib_do_commit(node_t node)
{
    char* path;
	
	path = lib_node2path(node);

	printf("lib_do_commit path:%s\n",path);

	if (path)
	{
	    if (strncmp(path,"Device.NAT.PortMapping.",strlen("Device.NAT.PortMapping.")) == 0)
	    {
	       printf("lib_del_portmapping_object entry\n");
	       lib_del_portmapping_object(node);
	    }

		if (strncmp(path,"Device.Routing.Router.1.IPv4Forwarding.",strlen("Device.Routing.Router.1.IPv4Forwarding.")) == 0)
		{
			printf("lib_del_routingipv4_object entry\n");
			lib_del_routingipv4_object(node);
		}

		if (strncmp(path,"Device.QoS.Classification.",strlen("Device.QoS.Classification.")) == 0)
		{
			printf("lib_del_qosclassfication_object entry\n");
			lib_del_qosclassfication_object(node);
		}
		
		if (strncmp(path,"Device.QoS.App.",strlen("Device.QoS.App.")) == 0)
		{
			printf("lib_del_qosApp_object entry\n");
			lib_del_qosApp_object(node);
		}

		if (strncmp(path,"Device.QoS.Queue.",strlen("Device.QoS.Queue.")) == 0)
		{
			printf("lib_del_qosQueue_object entry\n");
			lib_del_qosQueue_object(node);
		}

		/*if (strncmp(path,"Device.QoS.Shaper.",strlen("Device.QoS.Shaper.")) == 0)
		{
			printf("lib_del_qosShaper_object entry\n");
			lib_del_qosShaper_object(node);
		}*/

		if (strncmp(path,"Device.DHCPv4.Server.Pool.1.Option.",strlen("Device.DHCPv4.Server.Pool.1.Option.")) == 0)
		{
			printf("lib_del_dhcpserveroptions_object entry\n");
			lib_del_dhcpserveroptions_object(node);
		}

		if (strncmp(path,"Device.GRE.Filter.",strlen("Device.GRE.Filter.")) == 0)
		{
			printf("lib_del_GREFilter_object entry\n");
			lib_del_GREFilter_object(node);
		}

		if (strncmp(path,"Device.DHCPv6.Client.1.SentOption.",strlen("Device.DHCPv6.Client.1.SentOption.")) == 0)
		{
			printf("lib_del_dhcpv6sendoptions_object entry\n");
			lib_del_dhcpv6sendoptions_object(node);
		}

	    /*if (strncmp(path,"Device.Ethernet.Link",strlen("Device.Ethernet.Link")) == 0)
	    {
	       printf("lib_del_ethlink_object entry\n");
	       lib_del_ethlink_object(node);
	    }*/
	    
		if (strncmp(path,"Device.DHCPv4.Server.Pool.1.StaticAddress",strlen("Device.DHCPv4.Server.Pool.1.StaticAddress")) == 0)
	    {
	       printf("lib_del_Device_DHCPv4_Server_Pool_1_StaticAddress_object entry\n");
	       lib_del_Device_DHCPv4_Server_Pool_1_StaticAddress_object(node);
	    }

		if (strncmp(path,"Device.XMPP.Connection.",strlen("Device.XMPP.Connection.")) == 0)
		{
			printf("lib_del_xmpp_connection_object\n");
			lib_del_xmpp_connection_object(node);
		}
	}
}
//ASKEY end

/*!
 * \brief Delete an object instance which created by lib_ao
 *
 * \param node The instance sub tree's root node
 * \return 0 when success, -1 when any error
 */

TR_LIB_API int lib_do( node_t node )
{
    int res = 0;
#ifdef __V4_2
    int ins_num ;
    char full_path[256];
    char *ins = NULL;
    int locate[MAX_LOCATE_DEPTH];
    get_param_full_name( node, full_path );
    ins = strrchr( full_path, '.' );

    if( ins == NULL ) {
        return -1;
    }

    ins_num = atoi( ins + 1 );
    * ( ins + 1 ) = '\0';
    path_2_locate( full_path, locate, sizeof( locate ) / sizeof( locate[0] ) );

    if( node->parent->dev.obj.del ) {
        res = node->parent->dev.obj.del( locate, sizeof( locate ) / sizeof( locate[0] ), ins_num );
    } else {
        res = -1;
    }

#endif

    if( node->parent ) {
        node_t prev;

        if( node->parent->children == node ) {
            node->parent->children = node->brother;
            change = 1;
        } else {
            for( prev = node->parent->children; prev; prev = prev->brother ) {
                if( prev->brother == node ) {
                    prev->brother = node->brother;
                    change = 1;
                    break;
                }
            }
        }

        if( change ) {
            node->brother = NULL;
#ifdef ALIAS
            struct alias_map *alias_current;
            struct alias_map *alias_last;
            alias_current = alias_head;
            alias_last = alias_current;

            while( alias_current != NULL ) {
                if( war_strcasecmp( alias_current->uri, lib_node2path( node ) ) == 0 ) {
                    if( alias_current == alias_head ) {
                        alias_head = alias_current->next;
                        free( alias_current );
                        break;
                    } else {
                        alias_last->next = alias_current->next;
                        free( alias_current );
                        break;
                    }
                }

                alias_last = alias_current;
                alias_current = alias_current->next;
            }

#endif //ALIAS
            lib_handle_tr_update( node, lib_node2path( node ), NULL, "delete" );
            lib_do_commit(node);
            lib_destroy_tree( node );
        }
    } else {
        return -1;
    }

    return res;
    /*
     #else
     if(node->parent) {
     node_t prev;

     if(node->parent->children == node) {
     node->parent->children = node->brother;
     change = 1;
     } else {
     for(prev = node->parent->children; prev; prev = prev->brother) {
     if(prev->brother == node) {
     prev->brother = node->brother;
     change = 1;
     break;
     }
     }
     }

     if(change) {
     node->brother = NULL;
     lib_destroy_tree(node);
     }
     } else {
     return -1;
     }

     return 0;
     #endif
     */
}

/*!
 * \fn lib_set_property
 * \brief Replace a given property of a given node
 *
 * \param node The node whose property will be replaced
 * \param name The property name
 * \param prop The new property value
 *
 * \return 0 when success, -1 when any error
 */

TR_LIB_API int lib_set_property( node_t node, const char *name, const char prop[PROPERTY_LENGTH] )
{
    if( war_strcasecmp( name, "noc" ) == 0 ) {
        unsigned int tmp;
        tmp = atoi( prop );

        if( node->noc != tmp ) {
            node->noc = tmp;
            change = 1;
        }
    } else if( war_strcasecmp( name, "acl" ) == 0 ) {
        if( strcmp( node->acl, prop ) ) {
            war_snprintf( node->acl, sizeof( node->acl ), "%s", prop );
            change = 1;
        }
    } else if( war_strcasecmp( name, "nin" ) == 0 ) {
        node->nin = atoi( prop );
        change = 1;
    } else {
        return -1;
    }

    return 0;
}

/*!
 * \fn lib_set_value
 * Replace a given leaf node's value
 *
 * \param node The node whose value will be replaced
 * \param value The new value
 *
 * \return 0 when success, -1 when any error
 * \remark As the same as lib_get_value(), any type value will be transfered as string
 * between TRAgent and this callback function
 */
TR_LIB_API int lib_set_value( node_t node, const char *value )
{
#ifdef __V4_2
    /* Transfer node to device API todo */
    char full_path[256];
    int res = 0;
    int locate[MAX_LOCATE_DEPTH];
    int  value_type = 0;
    get_param_full_name( node, full_path );
    path_2_locate( full_path, locate, sizeof( locate ) / sizeof( locate[0] ) );

    if( strcmp( value, node->value ) ) {
        if( war_strcasecmp( full_path, PARAMETERKEY ) != 0 ) {
            if( node->dev.param.set ) {
                res = node->dev.param.set( locate, sizeof( locate ) / sizeof( locate[0] ), ( char * ) value, strlen( value ), value_type );

                if( res != -1 ) {
                    res = 0;
                }
            } else {
                return -1;
            }
        }

        tr_log( LOG_NOTICE, "set value:%s", value );
        war_snprintf( node->value, sizeof( node->value ), "%s", value );
        tr_log( LOG_NOTICE, "set node value:%s", node->value );
        change = 1;
    }

    return res;
#else

        tr_log(LOG_DEBUG,"node->name[%s], node->value[%s]\n", node->name, node->value);

    if(!strcmp(node->name,"ConnectionRequestPassword")){/*ignore whether the value is changed or not*/

#if 1 
        /*write the value to the uci config file.skysoft*/
        char *pp;
        int ret = 0;
        pp = lib_node2path(node);
        if (!pp)
        	return -1;
        //ret = lib_set_value_to_uci(pp,value);
        /* ASKEY add, for set true and false bool value */
        if (strcmp(node->type,"boolean") == 0)
        {
        	if (strcasecmp(value,"true") == 0)
        	{
        		ret = lib_set_value_to_uci(pp,"1");
        	}
        	else if (strcasecmp(value,"false") == 0)
        	{
        		ret = lib_set_value_to_uci(pp,"0");
        	}
        	else
        	{
        		ret = lib_set_value_to_uci(pp,value);
        	}
        }
        else
        {
        	ret = lib_set_value_to_uci(pp,value);
        }
        if (ret == -1)
        	return -1;

		#if 0 //Remove to the below, here will make the lib_resolve_node(paraname,&target) target.value is null, ASKEY SH James
           if (ret == 1)
        	return 1;
		#endif
           /* parameter value scape out */
        if (ret == -2)
        	return -2;
        //#else
        war_snprintf( node->value, sizeof( node->value ), "%s", value );
        // notify listeners change of parameter value
        lib_handle_tr_update( node, lib_node2path( node ), value, "set" );

		if (ret == 1)
        	return 1;

#endif
            change = 1;


    }else{
    //Modify by Tony, for multiple parameter set
		//if( strcmp( value, node->value )  ){
#if 1 
        	/*write the value to the uci config file.skysoft*/
        	char *pp;
        	int ret = 0;
            pp = lib_node2path(node);
        	if (!pp)
            	return -1;
        	//ret = lib_set_value_to_uci(pp,value);
        	/* ASKEY add, for set true and false bool value */
        	if (strcmp(node->type,"boolean") == 0)
        	{
        		if (strcasecmp(value,"true") == 0)
        		{
        			ret = lib_set_value_to_uci(pp,"1");
        		}
        		else if (strcasecmp(value,"false") == 0)
        		{
        			ret = lib_set_value_to_uci(pp,"0");
        		}
        		else
        		{
        			ret = lib_set_value_to_uci(pp,value);
        		}
        	}
        	else
        	{
        		ret = lib_set_value_to_uci(pp,value);
        	}
        	if (ret == -1)
        		return -1;

			#if 0 //Remove to the below, here will make the lib_resolve_node(paraname,&target) target.value is null, ASKEY SH James
               if (ret == 1)
        		return 1;
			#endif
               /* parameter value scape out */
        	if (ret == -2)
        		return -2;
			
			if (ret == -3) //ASKEY SH add, for send error code 9001(Request denied)
				return -3;
        //#else
        	war_snprintf( node->value, sizeof( node->value ), "%s", value );
        	// notify listeners change of parameter value
        	lib_handle_tr_update( node, lib_node2path( node ), value, "set" );

			if (ret == 1)
        		return 1;

#endif
                change = 1;
		//}
    }

    
    if( set_logic_relative_values( node, NULL ) < 0 ) {
        return -1;
    }

#ifdef ALIAS

    if( strcmp( node->name, "Alias" ) == 0 && node_is_instance( node->parent ) == 1 ) {
        struct alias_map *alias_current;
        alias_current = lib_get_alias_head();

        while( alias_current != NULL ) {
            if( strcmp( alias_current->uri, lib_node2path( node->parent ) ) == 0 ) {
                war_snprintf( alias_current->alias, sizeof( alias_current->alias ), "%s[%s].", lib_node2path( node->parent->parent ), node->value );
            }

            alias_current = alias_current->next;
        }
    }

#endif //ALIAS
#endif

    return 0;
}

/*!
 * \fn lib_current_time
 * \brief Get the current system time
 *
 * \return The time in format require by TR069 protocol
 *
 * \remark Customer does not need to reimplement the function, just copy from the
 * simulator, we have tested it under linux and windows XP. We define it in the
 * library just hope it'll be more portable.
 */
TR_LIB_API const char *lib_current_time()
{
    static char str_time[32] = "";
    /* char buf[20];

    struct tm *tm;
    time_t t, tz;
    char minus;

    war_time(&t);


    tm = war_gmtime(&t);
    tz = war_mktime(tm);
    tm = war_localtime(&t);
    t = war_mktime(tm);

    tz = t - tz;

    war_strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm);

    if(tz < 0) {
    minus = '-';
    tz = -tz;
    } else {
     minus = '+';
    }

    war_snprintf(cur, sizeof(cur), "%s%c%02d:%02d", buf, minus, (int)(tz / 3600), (int)((tz / 60) % 60));
    */
    struct tm *tp;
    char *format = "%Y-%m-%dT%H:%M:%S";
    int minus_value;
    int local_hour, local_min, local_yday;
    time_t t;
    /* For WINCE 1109 inform time CurrentTime>2009-11-03T15:57:12-08:00</CurrentTime> format */
    war_time( &t );
    tp = war_localtime( &t );

    if( war_strftime( str_time, 20, format, tp ) == 0 ) {
        tr_log( LOG_ERROR, "Don't copy any string to buffer" );
        return str_time;
    }

    local_hour = tp->tm_hour;
    local_min = tp->tm_min;
    local_yday = tp->tm_yday;
    tp = war_gmtime( &t );
    minus_value = ( local_hour * 60 + local_min ) - ( tp->tm_hour * 60 + tp->tm_min );

    if( tp->tm_yday > local_yday ) {
        minus_value -= 24 * 60;
    } else if( tp->tm_yday < local_yday ) {
        minus_value += 24 * 60;
    }

    if( minus_value > 0 ) {
        war_snprintf( str_time + strlen( str_time ), 7, "+%02d:%02d", minus_value / 60, minus_value % 60 );
    } else if( minus_value < 0 ) {
        minus_value = abs( minus_value );
        war_snprintf( str_time + strlen( str_time ), 7, "-%02d:%02d", minus_value / 60, minus_value % 60 );
    }

    return str_time;
}

/*!
 * \fn lib_node2path
 * \brief Resolve the node structure to a string path - converting with lib_resolve_node()
 *
 * \param node The node to be resolved
 *
 * \return The string path of the node.
 * \remark The string MUST be located in static or global scope. The library MUST NOT
 * allocate memory to store the path, or less that will be a memory leak, because
 * the TRAgent will not free it.
 *
 * \remark Do not care about thread safe, the TRAgent just a single thread application
 */
TR_LIB_API char *lib_node2path( node_t node )
{
    static char path[256];
    int index;
    int len;
    memset( path, 0, sizeof( path ) );

    for( index = sizeof( path ) - 1; node; node = node->parent ) {
        //if(node->type == TYPE_NODE) {
        if( strcmp( node->type , "node" ) == 0 ) {
            path[--index] = '.';
        }

        len = strlen( node->name );

        if( index >= len ) {
            memcpy( path + index - len, node->name, len );
            index -= len;
        } else {
            return NULL;
        }
    }

    return path + index;
}

// ASKEY add
int get_process_pid (char pid[][256])
{
    FILE *fp = NULL;
    char line[128] = {0};
    int i = 0, j = 0, len = 0;

	if ((fp = popen("ls /proc/ | grep ^[0-9]*$ | sort -n", "r")) != NULL) {
    	while (fgets(line, sizeof(line), fp)){
        	i++;
			if (i < MAXMAPITEMS){
				len = strlen(line);
				for (j = 0; j<= len; j++){
					if (line[j] == '\n')
						line[j] = '\0';
				}
				strcpy(pid[i-1], line);
			}
			else
				break;
    	}
    	pclose(fp);
	}

    return i;
}

int get_IndividualPacketResult_PacketSendTime(char PacketSendTime[][256])
{
	FILE *fp = NULL;
	char buff[1024] = {0};
	int i = 0;

	fp = fopen("/tmp/udpechoresult", "r");

	if(fp != NULL)
	{
		
		while(fgets(buff, sizeof(buff), fp))
		{
			if(strstr(buff, "PacketSendTime") != NULL)
			{
				sprintf(PacketSendTime[i], "%d", ++i);
			}
		}
		fclose(fp);
	}
	return i;
}

int get_RootDevice_USN(char USN[][256])
{
	int ret = 0;
	FILE *fp = NULL;
	char buff[128];
	char *p= NULL;
	int i = 0;

	ret = upnpdevice();
	if(ret)
	{
		return -1;
	}

	fp = fopen("/tmp/NOTIFY", "r");

	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp) && i < 255)
		{
			if(strcasestr(buff, "USN") != NULL)
			{
				p = strchr(buff, ':');
				if(p != NULL)
				{
					sprintf(USN[i], "%s", p+1);
					i++;
				}
			}
		}
		fclose(fp);
	}
	return i;
}

int get_DiscoveryDevice_USN(char USN[][256])
{
	int ret = 0;
	FILE *fp = NULL;
	char buff[128];
	char *p= NULL;
	int i = 0;

	ret = upnpdevice();
	if(ret)
	{
		return -1;
	}

	fp = fopen("/tmp/upnpdevice", "r");

	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp) && i < 255)
		{
			if((strstr(buff, "UDN") != NULL))
			{
				p = strchr(buff, '=');
				if(p != NULL)
				{
					sprintf(USN[i], "%s", p+1);
					i++;
				}
			}
		}
		fclose(fp);
	}
	return i;
}

int get_DeviceDescription_URLBase(char URLBase[][256])
{
	int ret = 0;
	FILE *fp = NULL;
	char buff[128];
	char *p= NULL;
	int i = 0;

	ret = upnpdevice();
	if(ret)
	{
		return -1;
	}

	fp = fopen("/tmp/upnpdevice", "r");

	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp))
		{
			if(strstr(buff, "deviceType") != NULL)
			{
				p = strchr(buff, '=');
				if(p != NULL)
				{
					sprintf(URLBase[i], "%s", p+1);
					i++;
				}
			}
		}
		fclose(fp);
	}
	return i;
}

int get_DeviceInstance_UDN(char USN[][256])
{
	int ret = 0;
	FILE *fp = NULL;
	char buff[128];
	char *p= NULL;
	int i = 0;

	ret = upnpdevice();
	if(ret)
	{
		return -1;
	}

	fp = fopen("/tmp/upnpdevice", "r");

	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp))
		{
			if(strstr(buff, "UDN") != NULL)
			{
				p = strchr(buff, '=');
				if(p != NULL)
				{
					sprintf(USN[i], "%s", p+1);
					i++;
				}
			}
		}
		fclose(fp);
	}
	return i;
}

int get_ServiceInstance_ServiceId(char ServiceId[][256])
{
	int ret = 0;
	FILE *fp = NULL;
	char buff[128];
	char *p= NULL;
	int i = 0;

	ret = upnpservice();
	if(ret)
	{
		return -1;
	}

	fp = fopen("/tmp/upnpservice", "r");

	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp))
		{
			if(strstr(buff, "serviceId") != NULL)
			{
				p = strchr(buff, '=');
				if(p != NULL)
				{
					sprintf(ServiceId[i], "%s", p+1);
					i++;
				}
			}
		}
		fclose(fp);
	}
	return i;
}

int get_ActivePort_localIP(char LocalIPtable[][256])
{
	FILE *fp = NULL;
	char buff[1024] = {0};
	char localIP[128] = {0};
	char remoteIP[128] = {0};
	char state[128] = {0};
	int i = 0;
	
	system("netstat -n -t > /tmp/netstatresult");
	system("netstat -n -t -l >> /tmp/netstatresult");

	fp = fopen("/tmp/netstatresult", "r");
	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp))
		{
			if(strstr(buff, "tcp") != NULL)
			{
				sscanf(buff, "%*s %*s %*s %s %s %s", localIP, remoteIP, state);
				if(strcmp(state, "LISTEN") == 0 || strcmp(state, "ESTABLISHED") == 0)
				{
					sprintf(LocalIPtable[i], "%s_%s_%s", localIP, remoteIP, state);
					i++;
				}
			}
		}
		fclose(fp);
	}
	unlink("/tmp/netstatresult");	
	return i;
}

int get_RouteHops_HostAddress(char HostAddresstable[][256])
{
	FILE *fp = NULL;
	char buff[1024] = {0};
	int i = 0;
	char *p = NULL;
	char *q = NULL;
	
	fp = fopen("/tmp/tracerouteresult", "r");

	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp))
		{
			if(strstr(buff, "traceroute to") != NULL)
			{
				continue;
			}

			p = strrchr(buff, '(');
			q = strrchr(buff, ')');

			if(p != NULL && q != NULL)
			{
				strncpy(HostAddresstable[i], p+1, q-p-1);
				
				tr_log(LOG_DEBUG,"###########################################HostAddresstable[i][%s]",HostAddresstable[i]);
				i++;
			}
		}
		fclose(fp);
	}
	return i;
}

int get_AssociatedDevice_MAC(char *path, char mactable[][256])
{
	char *p = NULL, *q = NULL;
	char buff[1024] = {0};
	char tmp[128] = {0};
	char mac[18] = {0};
	char modestr[64] = {0};
	char inf[32] = {0};
	FILE *fp = NULL;
	int i = 0;
	
	p = parseTemplate(path, ".AccessPoint.");

	if (p == NULL)
		return -1;

	getWiFiInterfaceNameWithInstanceNum(p, inf);
	sprintf(buff, "wlanconfig %s list sta> /tmp/%sAssociated", inf, inf);
	sprintf(tmp, "/tmp/%sAssociated", inf);
	
	tr_log(LOG_DEBUG,"################################################buff[%s]",buff);
	tr_log(LOG_DEBUG,"################################################tmp[%s]",tmp);
	system(buff);

	fp = fopen(tmp, "r");
	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp))
		{
			if(strstr(buff, "unable to get station information") != NULL)
			{
				//modify by Tony for remove the object list in acs server page.
				//return -1;
				return i;
			}
			if(strstr(buff, "ADDR") != NULL)
			{
				continue;
			}
			strncpy(mac, buff, strlen("xx:xx:xx:xx:xx:xx"));
			tr_log(LOG_DEBUG,"################################################mac[%s]",mac);
			if ((q = strstr(buff, "IEEE80211")) != NULL){
				strcpy(modestr, q);
				if ((q = strstr(modestr, " ")) != NULL)
					*q = '\0';
			}
			i++;
			//strcpy(mactable[i-1], mac);
			sprintf(mactable[i-1], "%s|%s", mac, modestr);
		}
		fclose(fp);
	}

	/*modify by Tony for remove the object list in acs server page.*/
	/*if(i == 0)
	{
		return -1;
	}*/
	
	return i;
}

int get_DHCPv4_Server_Pool_Client_mac(char mac[][256], int index)
{
	FILE *fp = NULL;
    char line[128] = {0};
    int i = 0;
	char ipsubnet[32] = {0};
	char clientip[32] = {0};
	char clientmac[32] = {0};
	char path[64] = {0};
	char *ptr = NULL;

	//to get ip subnet
	if (index == 1)
		strcpy(path, "dhcp.lan.start");
	else
		sprintf(path, "dhcp.lan%d.start", index-1);
	do_uci_get(path, ipsubnet);
	if (strcmp(ipsubnet, "") != 0){
		if ((ptr = strrchr(ipsubnet, '.')) != NULL)
			*ptr = '\0';
		printf("==########=====ipsubnet1=%s\n", ipsubnet);
	}

	if((fp=fopen("/tmp/dhcp.leases","r")) != NULL){
    	while (fgets(line, sizeof(line), fp)){
			memset(clientip, 0, sizeof(clientip));
			memset(clientmac, 0, sizeof(clientmac));
			sscanf(line,"%*s %s %s %*s",clientmac, clientip);
			if (strcmp(clientip, "") != 0){
				if ((ptr = strrchr(clientip, '.')) != NULL)
					*ptr = '\0';
					printf("==########=====clientip=%s\n", clientip);
					if (strcmp(ipsubnet, clientip) == 0){
					i++;
					if (i < MAXMAPITEMS){
						strcpy(mac[i-1], clientmac);
					}
					else
						break;
    			}
			}
    	}
    	fclose(fp);
	}

	return i;
}

int get_Device_ManagementServer_ManageableDevice(char mac[][256])
{
	FILE *fp = NULL;
	FILE *fp2 = NULL;
    char line[128] = {0};
	char macaddr[64] = {0};
	char filename[128] = {0};
    int i = 0;
	
	if((fp=fopen("/tmp/dhcp.leases","r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp)){
			memset(macaddr, 0, sizeof(macaddr));
			memset(filename, 0, sizeof(filename));
			sscanf(line,"%*s %s %*s", macaddr);
			sprintf(filename, "/tmp/%s_option125", macaddr);
			if ((fp2=fopen(filename,"r")) != NULL){
				if (i < MAXMAPITEMS){
					strcpy(mac[i], macaddr);
					i ++;
				}
				else
					break;
				fclose(fp2);
			}
    	}
    	fclose(fp);
	}

	return i;
}



int get_DHCPv4_Server_Pool_1_Client_options(char *clientip, char options[][256])
{
	FILE *fp = NULL;
	FILE *fp1 = NULL;
	char buffer[1024] = {0};
	char tag[3] = {0};
	char length[3] = {0};
	char value[512] = {0};
	char *endptr;
	int i = 4;
	int n = 0;
	char tmpname[32] = {0};
	
	sprintf(tmpname, "/tmp/%s", clientip);
	fp = fopen(tmpname, "r");

	if(fp != NULL)
	{
		fgets(buffer, sizeof(buffer), fp);
		printf("buffer: %s\n", buffer);
		fclose(fp); 	

		memset(tmpname, 0, sizeof(tmpname));
		sprintf(tmpname, "/tmp/%s_optinos", clientip);
		unlink(tmpname);	
		fp1 = fopen(tmpname, "w");	
		if(fp1 != NULL)
		{
			while(strcasecmp(tag, "ff") != 0 && strcmp(tag, "00") != 0)
			{
				strncpy(tag, &buffer[i*2], 2);
				i++;
				strncpy(length, &buffer[i*2], 2);
				i++;
				strncpy(value, &buffer[i*2], strtol(length, &endptr, 16)*2);
				i = i + strtol(length, &endptr, 16);
				if(strcasecmp(tag, "ff") != 0 && strcmp(tag, "00") != 0)
				{
					strcpy(options[n], tag);
					fprintf(fp1, "option:%s,%s\n", tag, value);
					n++;
				}
				memset(value, 0, sizeof(value));
			}
			fclose(fp1); 	
		}
	}
	
	return n;
}


int get_DHCPv4_Server_Pool_1_StaticAddress_ip(char ip[][256])
{	
	FILE *fp = NULL;
    char line[128] = {0};
    int i = 0;
	char * ptr = NULL;
	
	if((fp=fopen("/etc/ethers","r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp)){
			i++;
			if (i < MAXMAPITEMS){
				if((ptr = strstr(line,"\n")) != NULL)
					*ptr = '\0';
				if(strcmp(line, "") == 0){
					i--;
					continue;
				}
				sscanf(line,"%*s %s",ip[i-1]);
				tr_log(LOG_DEBUG,"get_DHCPv4_Server_Pool_1_StaticAddress_ip:index=%d,  dhcpv4 ip [%s], line=%s\n",i-1, ip[i-1], line);
			}
			else
				break;
    	}
    	fclose(fp);
	}
	else
		return 0;

	return i;
}

int check_brctl_showmacs(char *interface, char *mac)
{
	FILE *fp = NULL;
    char line[512] = {0};
    char cmd[512] = {0};
	char info[4][32];
	int found = 0;

	sprintf(cmd, "brctl showmacs %s", interface);
	if((fp=popen(cmd,"r")) != NULL)
	{
		fgets(line,sizeof(line),fp);
		while(fgets(line,sizeof(line),fp))
		{
			//tr_log(LOG_DEBUG,"line[%s]",line);
			//tr_log(LOG_DEBUG,"mac[%s]",mac);
			if(strstr(line, mac) != NULL)
			{
				sscanf(line,"%s %s %s %s",info[0], info[1], info[2], info[3]);
				//tr_log(LOG_DEBUG,"info[3][%s]",info[3]);
				//tr_log(LOG_DEBUG,"info[2][%s]",info[2]);
				//tr_log(LOG_DEBUG,"info[3][%d]",atoi(info[3]));
				//tr_log(LOG_DEBUG,"info[1][%s]",info[1]);
				//tr_log(LOG_DEBUG,"info[0][%s]",info[0]);
				if(strcmp(info[2], "no") == 0)
				{
					if(atoi(info[3]) < 120)
					{
						found = 1;
						break;
					}
				}	
			}
		}
    	pclose(fp);
	}
	return found;
}

int check_ip_neigh_show(char *ip, char *mac)
{
	FILE *fp = NULL;
    char line[512] = {0};
	char info[6][32];
	int found = 0;
	
	if((fp=popen("ip neigh show","r")) != NULL)
	{
		while(fgets(line,sizeof(line),fp))
		{
			//tr_log(LOG_DEBUG,"line[%s]",line);
			if(strstr(line, mac) != NULL)
			{
				sscanf(line,"%s %s %s %s %s %s",info[0], info[1], info[2], info[3], info[4], info[5]);
				//tr_log(LOG_DEBUG,"info[5][%s]",info[5]);
				//tr_log(LOG_DEBUG,"info[4][%s]",info[4]);
				//tr_log(LOG_DEBUG,"info[0][%s]",info[0]);
				//tr_log(LOG_DEBUG,"ip[%s]",ip);
				if(strcmp(info[0], ip) == 0)
				{
					if(strcmp(info[5], "REACHABLE") == 0)
					{
						found = 1;
						break;
					}
					else if(strcmp(info[5], "STALE") == 0)
					{
						if(check_brctl_showmacs(info[2], info[4]) == 1)
						{
							found = 1;
							break;
						}
					}
				}	
			}
		}
    	pclose(fp);
	}
	return found;
}

int get_Hosts_ip(char ip[][256])
{	
	FILE *fp = NULL;
    char line[128] = {0};
    char cmd[128] = {0};
	char info[6][32];
    int i = 0;
	char * ptr = NULL;
	
	if((fp=fopen("/proc/net/arp","r")) != NULL){
		fgets(line,sizeof(line)-1,fp); //get one line
		while(fgets(line,sizeof(line)-1,fp)){
			i++;
			if (i < MAXMAPITEMS){
				sscanf(line,"%s %s %s %s %s %s",info[0], info[1], info[2], info[3], info[4], info[5]);
				if ((ptr = strstr(info[5], "\n")) != NULL)
					*ptr = '\0';
				if (strncmp(info[5], "br-lan", strlen("br-lan")) != 0){
					i--;
					continue;
				}
				if (strcmp(info[3], "00:00:00:00:00:00") == 0)
				{
					i--;
					continue;
				}
				sprintf(cmd, "arping %s -c 3 -b -I br-lan 2> /dev/null", info[0]);
				//tr_log( LOG_NOTICE, "cmd: %s", cmd);
				system(cmd);
				sprintf(cmd, "arping %s -c 3 -b -I br-lan1 2> /dev/null", info[0]);
				//tr_log( LOG_NOTICE, "cmd: %s", cmd);
				system(cmd);
				sprintf(cmd, "arping %s -c 3 -b -I br-lan2 2> /dev/null", info[0]);
				//tr_log( LOG_NOTICE, "cmd: %s", cmd);
				system(cmd);
				sprintf(cmd, "arping %s -c 3 -b -I br-lan3 2> /dev/null", info[0]);
				//tr_log( LOG_NOTICE, "cmd: %s", cmd);
				system(cmd);
				if(check_ip_neigh_show(info[0], info[3]) != 1)
				{
					i--;
					continue;
				}
				else
					strcpy(ip[i-1], info[3]);
			}
			else
				break;
    	}
    	fclose(fp);
	}
	else
		return 0;

	return i;
}

#if 0
int get_USBHostsDevice(char key[][128], char *ubsnum)
{
	FILE *fp = NULL;
	char cmd[64] = {0};
    char line[128] = {0};
	char ProductID[32] = {0};
    int i = 0;
	char * ptr = NULL;

	sprintf(cmd, "lsusb -s %s:", ubsnum);
	if((fp=popen(cmd, "r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp)){
			i++;
			if (i < MAXMAPITEMS){
				if (strstr(line, "root hub") != NULL){ //ingor
					i--;
					continue;
				}
				memset(ProductID, 0, sizeof(ProductID));
				sscanf(line,"%*s %*s %*s %*s %*s %s %*s",ProductID);
				if ((ptr = strstr(ProductID, "\n") != NULL))
					*ptr = '\0';
				strcpy(key[i-1], ProductID);
			}
			else
				break;
    	}
    	pclose(fp);
	}
	else
		return 0;

	return i;
}
#else
//result value is 1 or 0 (only upport one usb device)
int get_USBHostsDevice(char key[][256], char *busnum)
{
	FILE *fp = NULL;
	char usbpath[128] = {0};
    char line[128] = {0};
	char * ptr = NULL;

	if (atoi(busnum) == 1)
		strcpy(usbpath, "/sys/bus/platform/devices/xhci-hcd.0/usb1/1-1/serial");
	else if (atoi(busnum) == 3)
		strcpy(usbpath, "/sys/bus/platform/devices/xhci-hcd.1/usb3/3-1/serial");
	else
		return 0;
	
	if((fp=fopen(usbpath, "r")) != NULL){
		fgets(line,sizeof(line)-1,fp);
		if ((ptr = strstr(line, "\n")) != NULL)
			*ptr = '\0';
		strcpy(key[0], line);
		fclose(fp);
		return 1;
	}
	else
		return 0;

}
#endif

int get_Device_RouterAdvertisement_InterfaceSetting_Option_type(char tag[][256])
{	
	FILE *fp = NULL;
    char line[128] = {0};
    int i = 0;
	char * ptr = NULL;

	char value[32] = {0};
	do_uci_get("radvd.@interface[0].ignore", value);
	if (atoi(value) == 1) //disable
		return 0;
	
	if((fp=fopen("/var/etc/radvd.conf","r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp)){
			if ((ptr = strstr(line, "prefix")) != NULL){
				strcpy(tag[i], "3"); //option type is 3
				i ++;
			}
			if ((ptr = strstr(line, "RDNSS")) != NULL){
				strcpy(tag[i], "25"); //option type is 25
				i ++;
			}
    	}

		//always in for this type
		strcpy(tag[i], "1"); //option type is 1
		i ++;
    	fclose(fp);
	}
	else
		return 0;

	return i;
}

int get_Device_DHCPv6_Server_Pool_1_Client_address(char addr[][256])
{	
	FILE *fp = NULL;
    char line[128] = {0};
    int i = 0;
	char *ptr = NULL, *ptr2 = NULL;
	
	if((fp=popen("cat /var/lib/dibbler/server-cache.xml | grep duid","r")) != NULL){
		while(fgets(line,sizeof(line)-1,fp)){
			if ((ptr = strstr(line, ">")) != NULL){
				if ((ptr2 = strstr(ptr, "<")) != NULL){
					*ptr2 = '\0';
					strcpy(addr[i], ptr+1);
					printf("================debug========addr[%d]=%s, ptr+1=%s\n", i, addr[i], ptr+1);
					i ++;
				}
			}
		}
    	pclose(fp);
	}
	else
		return 0;

	return i;
}

int get_Device_DHCPv6_Clinet_SendOptions(char key[][256])
{
	int ret = 0;
	int i = 0;
	int j = 0;
	char Tag[32] = {0};
	char OptionNumberOfEntries[256] = {0};
	char value[64] = {0};
	char name[256] = {0};
	char linebuffer[512] = { 0 };
	char dhcp_option[128] = {0};
	char *p = NULL;
	char *buf = NULL;
	char tmpbuf[256]={0};
	char cmdbuf[256]={0};

	memset(OptionNumberOfEntries,0,sizeof(OptionNumberOfEntries));

	ret = do_uci_get(DDCt_SentOptionNumberOfEntries_3549, OptionNumberOfEntries);
	if(ret)
	{
		return i;
	}
	tr_log( LOG_NOTICE, "OptionNumberOfEntries: %d", atoi(OptionNumberOfEntries));

	while(i < atoi(OptionNumberOfEntries))
	{
		memset(Tag,0,sizeof(Tag));
		memset(value,0,sizeof(value));
		j++;
		sprintf(name, "trconf.Device_DHCPv6_Clinet_template_SendOption_%d", j);	
		do_uci_get(name,value);
		tr_log( LOG_NOTICE, "name: %s", name);
		tr_log( LOG_NOTICE, "value: %s", value);
		
		if(strcmp(value, "acs") == 0)
		{
			sprintf(name, "trconf.Device_DHCPv6_Clinet_template_SendOption_%d.Tag", j);		
			tr_log( LOG_NOTICE, "name: %s", name);
			do_uci_get(name, Tag);
			sprintf(key[i],"%s", Tag);	
			tr_log( LOG_NOTICE, "key[%d]: %s", i, key[i]);
			i++;
		}
	}
	return i;
}


int get_Device_DHCPv4_Server_Options(char key[][256])
{
	int ret = 0;
	int i = 0;
	int j = 0;
	char Tag[32] = {0};
	char OptionNumberOfEntries[256] = {0};
	char value[64] = {0};
	char name[256] = {0};
	char DnsServer[32] = {0};
	char DefGateway[32] = {0};
	char WinsServer[32] = {0};
	char linebuffer[512] = { 0 };
	char dhcp_option[128] = {0};
	char *p = NULL;
	char *buf = NULL;
	char tmpbuf[256]={0};
	char cmdbuf[256]={0};
	int DnsServer_done = 0;
	int DefGateway_done = 0;
	int WinsServer_done = 0;
	int count = 1;

	memset(OptionNumberOfEntries,0,sizeof(OptionNumberOfEntries));

	ret = do_uci_get(DDSPt_OptionNumberOfEntries, OptionNumberOfEntries);
	if(ret)
	{
		return i;
	}
	tr_log( LOG_NOTICE, "OptionNumberOfEntries: %d", atoi(OptionNumberOfEntries));

	while(i < atoi(OptionNumberOfEntries))
	{
		memset(Tag,0,sizeof(Tag));
		memset(value,0,sizeof(value));
		j++;
		sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d", j); 	
		do_uci_get(name,value);
		tr_log( LOG_NOTICE, "name: %s", name);
		tr_log( LOG_NOTICE, "value: %s", value);
		
		if(strcmp(value, "acs") == 0)
		{
			sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Tag", j);		
			tr_log( LOG_NOTICE, "name: %s", name);
			do_uci_get(name, Tag);
			
			sprintf(key[i],"%s", Tag);	
			if(atoi(Tag) == 3)
			{
				DefGateway_done = 1;
			}
			if(atoi(Tag) == 6)
			{
				DnsServer_done = 1;
			}
			if(atoi(Tag) == 44)
			{
				WinsServer_done = 1;
			}
			tr_log( LOG_NOTICE, "key[%d]: %s", i, key[i]);
			i++;
		}
	}
	
	memset(DnsServer, 0x00, sizeof(DnsServer));
	memset(DefGateway, 0x00, sizeof(DefGateway));
	memset(WinsServer, 0x00, sizeof(WinsServer));
	memset(linebuffer, 0x00, sizeof(linebuffer));
	do_uci_get("dhcp.lan.dhcp_option", linebuffer);
	if (linebuffer[0] != 0) 
	{
		buf = linebuffer;
		while ((p = strtok(buf, " ")) != NULL) 
		{
			tr_log( LOG_NOTICE, "p: %s", p);
			if ((p[0] == '3') && (p[1] == ',')) 
			{
				strcpy(DefGateway, p + 2);
			}

			if ((p[0] == '6') && (p[1] == ',')) {
				strcpy(DnsServer, p + 2);
			}
			if ((p[0] == '4') && (p[1] == '4') && (p[2] == ',')) {
				strcpy(WinsServer, p + 3);
			}
			buf = NULL;
		}
	}

	if (DefGateway[0] != 0 && DefGateway_done != 1) 
	{
		j++;
		do_uci_add("trconf","acs",tmpbuf);
		sprintf(cmdbuf, "trconf.%s", tmpbuf);
		sprintf(name,"Device_DHCPv4_Server_Pool_template_Option_%d", j);
		do_uci_rename(cmdbuf, name);
		sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Enable", j); 
		do_uci_set(name, "1");
		sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Tag", j); 
		do_uci_set(name, "3");
		sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Value", j); 
		do_uci_set(name, DefGateway);
		do_uci_commit(MS);
		strcpy(key[i],"3");	
		i++;
	}
	if (DnsServer[0] != 0 && DnsServer_done != 1) 
	{
		j++;
		do_uci_add("trconf","acs",tmpbuf);
		sprintf(cmdbuf, "trconf.%s", tmpbuf);
		sprintf(name,"Device_DHCPv4_Server_Pool_template_Option_%d", j);
		do_uci_rename(cmdbuf, name);
		sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Enable", j); 
		do_uci_set(name, "1");
		sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Tag", j); 
		do_uci_set(name, "6");
		sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Value", j); 
		do_uci_set(name, DnsServer);
		do_uci_commit(MS);
		strcpy(key[i],"6");	
		i++;
	}
	if (WinsServer[0] != 0 && WinsServer_done != 1) 
	{
		j++;
		do_uci_add("trconf","acs",tmpbuf);
		sprintf(cmdbuf, "trconf.%s", tmpbuf);
		sprintf(name,"Device_DHCPv4_Server_Pool_template_Option_%d", j);
		do_uci_rename(cmdbuf, name);
		sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Enable", j); 
		do_uci_set(name, "1");
		sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Tag", j); 
		do_uci_set(name, "44");
		sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Value", j); 
		do_uci_set(name, WinsServer);
		do_uci_commit(MS);
		strcpy(key[i],"44");	
		i++;
	}

	sprintf(tmpbuf, "%d", i);
	tr_log( LOG_NOTICE, "tmpbuf: %d", atoi(tmpbuf));
	do_uci_set(DDSPt_OptionNumberOfEntries, tmpbuf);

	count = 1;
	while(count <= i)
	{
		memset(Tag,0,sizeof(Tag));
		memset(value,0,sizeof(value));
		tr_log( LOG_NOTICE, "count: %d", count);
		sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d", count); 	
		do_uci_get(name,value);
		tr_log( LOG_NOTICE, "name: %s", name);
		tr_log( LOG_NOTICE, "value: %s", value);
		
		if(strcmp(value, "acs") == 0)
		{
			sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Tag", count);		
			tr_log( LOG_NOTICE, "name: %s", name);
			do_uci_get(name, Tag);
			
			if(atoi(Tag) == 3 && DefGateway[0] != 0)
			{
				sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Value", count); 
				do_uci_set(name, DefGateway);
				do_uci_commit(MS);
			}
			if(atoi(Tag) == 6 && DnsServer[0] != 0)
			{
				sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Value", count); 
				do_uci_set(name, DnsServer);
				do_uci_commit(MS);
			}
			if(atoi(Tag) == 44 && WinsServer[0] != 0)
			{
				sprintf(name, "trconf.Device_DHCPv4_Server_Pool_template_Option_%d.Value", count); 
				do_uci_set(name, WinsServer);
				do_uci_commit(MS);
			}
		}
		count++;
	}	

	return i;
}

int get_Device_DHCPv6ClientServer_Entry(char addr[][256])
{	
	int i = 0;
	FILE *fp = NULL;
    char line[128] = {0};
	char *ptr = NULL;

	if (getDHCPv6ClientLinkStatus()){	
		if ((fp=popen("cat /tmp/dhcp6cServerIP","r")) != NULL){
			if (fgets(line,sizeof(line)-1,fp)){
				if ((ptr = strstr(line, "\n")) != NULL){
					*ptr = '\0';
					strcpy(addr[0], line);
					i = 1;
				}
			}
    		pclose(fp);
		}
	}

	return i;
}

int get_Device_DHCPv6ClientReceivedOption_Entry(char options[][256])
{	
	FILE *fp = NULL;
	FILE *fp1 = NULL;
	char buffer[4096] = {0};
	char tag[5] = {0};
	char length[5] = {0};
	char value[512] = {0};
	char *endptr;
	int i = 0;
	int n = 0;
	char tmpname[256] = {0};
    char line[128] = {0};
	char *ptr = NULL;
	char addr[128] = {0};

	if (getDHCPv6ClientLinkStatus())
	{
		if ((fp=popen("cat /tmp/dhcp6cServerIP","r")) != NULL)
		{
			if (fgets(line,sizeof(line)-1,fp))
			{
				if ((ptr = strstr(line, "\n")) != NULL)
				{
					*ptr = '\0';
					strcpy(addr, line);
				}
			}
    		pclose(fp);
		}

		sprintf(tmpname, "/tmp/%s_options", addr);
		fp = fopen(tmpname, "r");

		if(fp != NULL)
		{
			memset(buffer, 0, sizeof(buffer));
			fgets(buffer, sizeof(buffer), fp);
			printf("buffer: %s\n", buffer);
			fclose(fp);

			memset(tmpname, 0, sizeof(tmpname));
			sprintf(tmpname, "/tmp/%s_optinos_parse", "dhcpv6");
			unlink(tmpname);	
			fp1 = fopen(tmpname, "w");
			if(fp1 != NULL)
			{
				do
				{
					memset(tag, 0, sizeof(tag));
					memset(length, 0, sizeof(length));
					memset(value, 0, sizeof(value));
					strncpy(tag, &buffer[i*2], 4);
					printf("######### tony debug tag: %s\n", tag);
					i = i + 2;
					if(tag[0] != '\0')
					{
						strncpy(length, &buffer[i*2], 4);
						printf("######### tony debug length: %s\n", length);
						i = i + 2;
						if(strtol(length, &endptr, 16) > 1536)
						{
							break;
						}
						strncpy(value, &buffer[i*2], strtol(length, &endptr, 16)*2);
						i = i + strtol(length, &endptr, 16);
						if(i > 1536)
						{
							break;
						}
						strcpy(options[n], tag);
						fprintf(fp1, "option:%s,%s\n", tag, value);
						n++;
						printf("######### tony debug i: %d\n", i);
					}
				}while(tag[0] != '\0');
				fclose(fp1);
			}
		}
	}
	return n;
}

int get_Device_DHCPv6ServerPool_Entry(char var[][256])
{	
	int i = 0;

	if (getDHCPv6ServerPoolStatus()){
		strcpy(var[0], "1");
		i = 1;
	}

	return i;
}

int get_Device_InterfaceStack_Entry(char var[][256])
{	
	int i = 0, j = 0;
	int en1 = 0, en2 = 0;
	int portnum = 2;
	int bridgemode = 0;
	char value[32] = {0};
	char buff[128] = {0};
	char index[32] = {0};
	
	en1 = _get_endporint_5g_enable();
	en2 = _get_endporint_24g_enable();
	if (en1 == -1 && en2 == -1)
		return i;
	else{
		if (en1 == 1 || en2 == 1)
			bridgemode = 1;
		else
			bridgemode = 0;
	}

	if (bridgemode == 0 || bridgemode == 1){ //routing and bridging
		//for ether lan interface
		sprintf(var[i], "%d|Device.IP.Interface.%d|" ETHERNET_LAN_LINK_PATH "|LAN_IP_Interface|LAN_Ethernet_Link", i+1, lan_map[0].num);
		i++;
		sprintf(var[i], "%d|" ETHERNET_LAN_LINK_PATH "|Device.Bridging.Bridge.1.Port.1|LAN_Ethernet_Link|LAN_Bridge1_Port1", i+1);
		i++;
		sprintf(var[i], "%d|Device.Bridging.Bridge.1.Port.1|Device.Bridging.Bridge.1.Port.%d|LAN_Bridge1_Port1|LAN_Bridge1_Port2", i+1, portnum);
		i++;
		sprintf(var[i], "%d|Device.Bridging.Bridge.1.Port.%d|" ETHERNET_LAN_INTERFACE_PATH "|LAN_Bridge1_Port%d|LAN_Ethernet_Interface", i+1, portnum, portnum);
		i++;
		//WLA 5G interface
		for (j = WIFI5G_START_INSTANCE_NUM; j <= WIFI5G_END_INSTANCE_NUM; j ++){
			memset(value, 0, sizeof(value));
			do_uci_get("wireless.wifi0.disabled", value);
			if (strcmp(value, "0") != 0)
				break;
			memset(value, 0, sizeof(value));
			memset(buff, 0, sizeof(buff));
			memset(index, 0, sizeof(index));
			sprintf(index, "%d", j);
			getSSIDuciConfig(index, buff, "ath_enable");
			do_uci_get(buff, value);
			if (strcmp(value, "1") != 0)
				break;
			portnum ++;
			sprintf(var[i], "%d|Device.Bridging.Bridge.1.Port.1|Device.Bridging.Bridge.1.Port.%d|LAN_Bridge1_Port1|LAN_Bridge1_Port%d", i+1, portnum, portnum);
			i++;
			sprintf(var[i], "%d|Device.Bridging.Bridge.1.Port.%d|Device.WiFi.SSID.%d|LAN_Bridge1_Port%d|LAN_WLAN5G%d", i+1, portnum, j, portnum, j);
			i++;
			sprintf(var[i], "%d|Device.WiFi.SSID.%d|" WIFI_RADIO_5G_PATH "|LAN_WLAN5G%d|LAN_WLAN5G_Radio", i+1, j, j);
			i++;
		}
		//WLA 2.4G interface
		for (j = WIFI24G_START_INSTANCE_NUM; j <= WIFI24G_END_INSTANCE_NUM; j ++){
			memset(value, 0, sizeof(value));
			do_uci_get("wireless.wifi1.disabled", value);
			if (strcmp(value, "0") != 0)
				break;
			memset(value, 0, sizeof(value));
			memset(buff, 0, sizeof(buff));
			memset(index, 0, sizeof(index));
			sprintf(index, "%d", j);
			getSSIDuciConfig(index, buff, "ath_enable");
			do_uci_get(buff, value);
			if (strcmp(value, "1") != 0)
				break;
			portnum ++;
			sprintf(var[i], "%d|Device.Bridging.Bridge.1.Port.1|Device.Bridging.Bridge.1.Port.%d|LAN_Bridge1_Port1|LAN_Bridge1_Port%d", i+1, portnum, portnum);
			i++;
			sprintf(var[i], "%d|Device.Bridging.Bridge.1.Port.%d|Device.WiFi.SSID.%d|LAN_Bridge1_Port%d|LAN_WLAN2.4G%d", i+1, portnum, j, portnum, j);
			i++;
			sprintf(var[i], "%d|Device.WiFi.SSID.%d|" WIFI_RADIO_24G_PATH "|LAN_WLAN2.4G%d|LAN_WLAN2.4G_Radio", i+1, j, j);
			i++;
		}
		//for WAN
		if (bridgemode == 0){ //only on routing mode
			if (checkEthWanUpDown() == 1){
				sprintf(var[i], "%d|" IP_WAN_INTERFACE_PATH "|" ETHERNET_WAN_LINK_PATH "|WAN_IP_Interface|WAN_Ethernet_Link", i+1);
				i++;
				sprintf(var[i], "%d|" ETHERNET_WAN_LINK_PATH "|" ETHERNET_WAN_INTERFACE_PATH "|WAN_Ethernet_Link|WAN_Ethernet_Interface", i+1);
				i++;
			}
		}
		else{
			if (checkEthWanUpDown() == 1){
				portnum ++;
				sprintf(var[i], "%d|Device.Bridging.Bridge.1.Port.1|Device.Bridging.Bridge.1.Port.%d|LAN_Bridge1_Port1|LAN_Bridge1_Port%d", i+1, portnum, portnum);
				i++;
				sprintf(var[i], "%d|Device.Bridging.Bridge.1.Port.%d|" ETHERNET_WAN_INTERFACE_PATH "|LAN_Bridge1_Port%d|LAN_Ethernet_Interface2", i+1, portnum, portnum);
				i++;
			}
		}	
	}

	return i;
}

int get_Device_Bridging_Bridge_1_Port_Entry(char var[][256])
{	
	int i = 0, j = 0, x = 0;
	int en1 = 0, en2 = 0;
	int bridgemode = 0;
	char value[32] = {0};
	char buff[128] = {0};
	char index[32] = {0};
	char lowerlayinf[256] = {0};
	char inf[32] = {0};
	
	en1 = _get_endporint_5g_enable();
	en2 = _get_endporint_24g_enable();
	if (en1 == -1 && en2 == -1)
		return i;
	else{
		if (en1 == 1 || en2 == 1)
			bridgemode = 1;
		else
			bridgemode = 0;
	}

	if (bridgemode == 0 || bridgemode == 1){ //routing and bridging
		//for ether br-lan interface
		sprintf(var[i], "br-lan|1|%s", ETHERNET_LAN_INTERFACE_PATH);
		x = i;
		i++;
		//for ether br-lan interface
		sprintf(var[i], "eth1|0|%s", ETHERNET_LAN_INTERFACE_PATH);
		i++;
		//WLA 5G interface
		memset(value, 0, sizeof(value));
		do_uci_get("wireless.wifi0.disabled", value);
		if (strcmp(value, "0") == 0){
			for (j = WIFI5G_START_INSTANCE_NUM; j <= WIFI5G_END_INSTANCE_NUM; j ++){
				memset(value, 0, sizeof(value));
				memset(buff, 0, sizeof(buff));
				memset(index, 0, sizeof(index));
				sprintf(index, "%d", j);
				getSSIDuciConfig(index, buff, "ath_enable");
				do_uci_get(buff, value);
				if (strcmp(value, "1") != 0)
					break;
				memset(inf, 0, sizeof(inf));
				getWiFiInterfaceNameWithInstanceNum(index, inf);
				sprintf(var[i], "%s|0|%s", inf, WIFI_RADIO_5G_PATH);
				i++;
			}
			sprintf(lowerlayinf,"%s,%s", lowerlayinf, WIFI_RADIO_5G_PATH);
		}
		//WLA 2.4G interface
		memset(value, 0, sizeof(value));
		do_uci_get("wireless.wifi1.disabled", value);
		if (strcmp(value, "0") == 0){
			for (j = WIFI24G_START_INSTANCE_NUM; j <= WIFI24G_END_INSTANCE_NUM; j ++){
				memset(value, 0, sizeof(value));
				memset(buff, 0, sizeof(buff));
				memset(index, 0, sizeof(index));
				sprintf(index, "%d", j);
				getSSIDuciConfig(index, buff, "ath_enable");
				do_uci_get(buff, value);
				if (strcmp(value, "1") != 0)
					break;
				memset(inf, 0, sizeof(inf));
				getWiFiInterfaceNameWithInstanceNum(index, inf);
				sprintf(var[i], "%s|0|%s", inf, WIFI_RADIO_24G_PATH);
				i++;
			}
			sprintf(lowerlayinf,"%s,%s", lowerlayinf, WIFI_RADIO_24G_PATH);
		}
		//for WAN
		if (bridgemode == 1){ //only on routing mode
			if (checkEthWanUpDown() == 1){
				sprintf(var[i], "eth0|0|%s", ETHERNET_WAN_INTERFACE_PATH);
				i++;
				sprintf(lowerlayinf,"%s,%s", lowerlayinf, ETHERNET_WAN_INTERFACE_PATH);
			}
		}
		sprintf(var[x], "%s%s", var[x], lowerlayinf);
	}

	return i;
}

int get_Device_WiFiNeighboringWiFiDiagnostic_Entry(char entry[][256])
{
	int i = 0;
	FILE *fp = NULL;
	char buff[256] = {0};
	char *p = NULL;
	
	fp = fopen("/tmp/ath0_scan_result", "r");

	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp) && i < 255)
		{
			if(strstr(buff, "Cell") != NULL && strstr(buff, "- Address:") != NULL)
			{
				p = strchr(buff, ':');
				if(p != NULL)
				{
					strcpy(entry[i], p+2);
					printf("entry[i]: %s\n", entry[i]);				
				}
				i++;
			}
		}
		fclose(fp);
	}

	fp = fopen("/tmp/ath1_scan_result", "r");
	if(fp != NULL)
	{
		while(fgets(buff, sizeof(buff), fp) && i < 255)
		{
			if(strstr(buff, "Cell") != NULL && strstr(buff, "- Address:") != NULL)
			{
				p = strchr(buff, ':');
				if(p != NULL)
				{
					strcpy(entry[i], p+2);
					printf("entry[i]: %s\n", entry[i]);				
				}
				i++;
			}
		}
		fclose(fp);
	}
	return i;
}

int get_Device_NSLookupDiagnostics_Result_Entry(char entry[][256])
{	
	FILE *fp = NULL;
    char line[128] = {0};
    int i = 0, j = 0;
	char *ptr = NULL;
	
	if((fp=popen("cat /tmp/NSLookupDiagnostics.ResultNumber","r")) != NULL){
		if(fgets(line,sizeof(line)-1,fp)){
			if ((ptr = strstr(line, "\n")) != NULL){
				*ptr = '\0';
				i = atoi(line);
			}
		}
		else
		{
			pclose(fp);
			return 0;
		}
    	pclose(fp);
	}
	else
		return 0;

	for (j = 0; j < i; j ++)
		strcpy(entry[j], "1");

	return i;
}

int get_Device_IEEE1905ALInterface_Entry(char entry[][256])
{
	FILE *fp = NULL;
    char line[256] = {0};
    int i = 0;
    char inf[32] = {0};
    char mac[32] = {0};

	if((fp=popen("hyctl show","r")) != NULL)
	{
		fgets(line,sizeof(line)-1,fp);
		fgets(line,sizeof(line)-1,fp);
		while(fgets(line, sizeof(line), fp))
		{
			tr_log( LOG_NOTICE, "line: %s", line);
			if(i == 0)
			{
				sscanf(line,"%*s %*s %*s %s %*s %*s %*s %*s", inf);
			}
			else
			{
				sscanf(line,"%s %*s %*s %*s %*s", inf);
			}
			tr_log( LOG_NOTICE, "inf: %s", inf);
			getInfaceMac(inf, mac);
			tr_log( LOG_NOTICE, "inf: %s", mac);
			strcpy(entry[i], mac);
			i++;
		}
		pclose(fp);
	}
	else
	{
		return 0;
	}
	if(i > 0)
	{
		i = i - 1;
	}
	return i;
}

int lib_init_writeable_children(node_t node,char* path,char* key,char keyvalue[][256],int number,char* mapfilename)
{
    mapInfo_t mapInfos[MAXMAPITEMS];
	char line[128];
	int i,j;
	char exsit;
	int instance;
	char szinstance[128];
	char elinkname[128];

    if ((path == NULL) || (key == NULL))
    {
        return -1;
    }
	
	memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	lib_read_mapfile(mapfilename,mapInfos,MAXMAPITEMS); 


    /* delete mapping file info which not in real links */
    for(i=0;i<MAXMAPITEMS;i++)
    {
        exsit = 0;
		if (mapInfos[i].valid)
		{
		   tr_log(LOG_NOTICE,"+++++++++++++++%s: %s, %d",path, mapInfos[i].value, mapInfos[i].instance);
           for(j=0;j<number;j++)
           {
              if (strcmp(keyvalue[j],mapInfos[i].value) == 0)
              {
                  exsit = 1;
              }
           }

		    if (!exsit)
		    {
		       mapInfos[i].valid = 0;
		    }
		}
    }

	lib_save_mapfile(mapfilename,mapInfos,MAXMAPITEMS);
	
    node_t c,curc;
	
	char paraname[128];
	char paraname1[128];
    node_t target;
	char port_protocol[256] = {0};
	char protocol[32] = {0};

	char nodename[MAXMAPITEMS][128];
	int  nodenum = 0;

	/*delete instance object from tree which not in mapping file */
    for( c = node->children; c; c = curc ) {
		curc = c->brother;
        if( strcmp( c->name, "template" ) != 0 ) {
            instance = atoi(c->name);
			sprintf(paraname,"%s%d.%s",path,instance,key);
			tr_log(LOG_NOTICE,"paraname: %s, c->name: %s ",paraname,c->name);

			if(strstr(paraname, "Device.NAT.PortMapping") != NULL)
			{
				node_t tmpnode;
				char *tmpvalue = NULL;
				int ret = 0;
				
				sprintf(paraname1,"%s%d.%s",path,instance,"Protocol");
				tr_log(LOG_NOTICE,"paraname1: %s, c->name: %s ",paraname1,c->name);

				if( lib_resolve_node( paraname1, &tmpnode ) == 0 ) 
				{
					ret = lib_get_value( tmpnode, &tmpvalue );

					if( ret != 0 ) 
					{
						tr_log( LOG_ERROR, "Get %s failed!", paraname1 );
					} 
					else 
					{
						if(strcasecmp(tmpvalue, "tcp") == 0)
						{
							strcpy(protocol, "0");
						}
						else if(strcasecmp(tmpvalue, "udp") == 0)
						{
							strcpy(protocol, "1");
						}
						else if(strcasecmp(tmpvalue, "both") == 0)
						{
							strcpy(protocol, "2");
						}
					}
					tr_log(LOG_NOTICE,"protocol: %s",protocol);
					lib_destroy_value( tmpvalue );
				}
			}
			
		    if (lib_resolve_node(paraname,&target) == 0)
		    {
		       tr_log(LOG_NOTICE,"+++++++++++++++ 2: %s, %d",target->value,instance);
		       exsit = 0;
		       for(i=0;i<MAXMAPITEMS;i++)
		       {
		           if (mapInfos[i].valid)
		           {
						if(strstr(paraname, "Device.NAT.PortMapping") != NULL)
						{
							
							sprintf(port_protocol, "%s_%s", target->value, protocol);
							tr_log(LOG_DEBUG,"port_protocol [%s]",port_protocol);
							tr_log(LOG_NOTICE,"+++++++++++++++%s: %d, %s, %d",path,i,mapInfos[i].value,mapInfos[i].instance);
							if ((mapInfos[i].instance == instance) && (strcasecmp(mapInfos[i].value,port_protocol) == 0))
							{
							   exsit = 1;
							   break;
							}
							
							if ((mapInfos[i].instance != instance) && (strcasecmp(mapInfos[i].value,port_protocol) == 0))
							{
							   mapInfos[i].instance = instance;
							   exsit = 1;
							   break;
							}					  
						}
						else
						{
				              tr_log(LOG_NOTICE,"+++++++++++++++%s: %d, %s, %d",path,i,mapInfos[i].value,mapInfos[i].instance);
				              if ((mapInfos[i].instance == instance) && (strcasecmp(mapInfos[i].value,target->value) == 0))
				              {
				                 exsit = 1;
								 break;
				              }

							  if ((mapInfos[i].instance != instance) && (strcasecmp(mapInfos[i].value,target->value) == 0))
							  {
							     mapInfos[i].instance = instance;
								 exsit = 1;
								 break;
							  }						
						}

		           }
		       }

			   if (!exsit)
			   {
			      tr_log(LOG_NOTICE,"+++++++++++++++%s: %s, %d",path,target->value,instance);
			      lib_do(c);
			   }
			   else
			   {
				   	if(strstr(paraname, "Device.NAT.PortMapping") != NULL)
				   	{
					   	strcpy(nodename[nodenum],port_protocol);
				   	}
				   	else
				   	{
					   	strcpy(nodename[nodenum],target->value);
				   	}
				  nodenum++;
			   }
		    }
        }
    }

    /*delete mapping file items which not in node tree */
	for(i=0;i<MAXMAPITEMS;i++)
	{
	    if (mapInfos[i].valid)
		{
		   exsit = 0;
		   for(j=0;j<nodenum;j++)
		   {
		      if (strcasecmp(mapInfos[i].value,nodename[j]) == 0)
		      {
		         exsit = 1;
		      }
		   }

		   if (!exsit)
		   {
		      mapInfos[i].valid = 0;
		   }
	    }
	}

	char objectpath[256];
	strcpy(objectpath,path);

	/* if instance number > node->il, you can set node il value in tr.xml */
	if (number > node->il)
	{
	    number = node->il;
	}
	
	/* add others real links not in mapping file */
	for(i=0;i<number;i++)
	{
	    exsit = 0;
	    for(j=0;j<MAXMAPITEMS;j++)
	    {
	        if (mapInfos[j].valid)
			{
			   if (strcmp(keyvalue[i],mapInfos[j].value) == 0)
			   {
			      exsit = 1;
				  break;
			   }
	        }
	    }

		if (!exsit)
		{
		  int in = add_object(objectpath,strlen(objectpath));
		  if ( in > 0)
		  {
		     sprintf(paraname,"%s%d.%s",path,in,key);
		     if (lib_resolve_node(paraname,&target) == 0)
		     {
		        for(j=0;j<MAXMAPITEMS;j++)
			    {
	               if (!mapInfos[j].valid)
	               {
	                  mapInfos[j].valid = 1;
				      mapInfos[j].instance = in;
				      strcpy(mapInfos[j].value,keyvalue[i]);
				      break;
	                }
		        }
				lib_save_mapfile(mapfilename,mapInfos,MAXMAPITEMS);
		        lib_set_value(target,keyvalue[i]);
			 }
		  }
		}
	}
	
	return 0;
}

#if 0
int lib_init_ethlink_children(node_t node)
{
    char reallinks[2][128];
	
	strcpy(reallinks[0],"eth0");
	strcpy(reallinks[1],"eth1");
	return lib_init_writeable_children(node,"Device.Ethernet.Link.","Name",reallinks,2,EthLinkMap);
}
#endif

int lib_init_readonly_children(node_t node,char* path,char* key,char keyvalue[][256],int number,char* mapfilename)
{
    mapInfo_t mapInfos[MAXMAPITEMS];
    int i = 0;
	node_t* temp;

    if ((path == NULL) || (key == NULL))
    {
        return -1;
    }
	
    memset(mapInfos,0,sizeof(mapInfo_t)*MAXMAPITEMS);
	
    /* delete all instance object */
	int nodenumber = lib_get_children(node,&temp);
    tr_log(LOG_NOTICE,"lib_get_children : %d", nodenumber);
	if (nodenumber > 0)
	{
	   for(i=0;i<nodenumber;i++)
	   {
	      lib_do(temp[i]); //clean old object
	   }

	   lib_destroy_children(temp); //free memory

	   node->nin = 1;
	}

    /* if instance number > node->il, you can set node il value in tr.xml */
	if (number > node->il)
	{
	    number = node->il;
	}

    printf("lib_init_readonly_children number %d \n", number);
	int res;
	for (i=0;i<number;i++)
	{
	    res = lib_ao( node, node->nin, NULL ); //add object
	    if (res == 0)
	    {
	       char paraname[128];
		   node_t target;
		   
		   sprintf(paraname,"%s%d.%s", path,node->nin,key);
		   printf("paraname: %s \n", paraname);
		   if (lib_resolve_node(paraname,&target) == 0) //find node of 'paraname'
		   {
		     //char szvalue[128];
			 //sprintf(szvalue,"%d",i);
			 mapInfos[i].valid = 1; //always
			 mapInfos[i].instance = node->nin; //save to mapping tree
			 strcpy(mapInfos[i].value, keyvalue[i]);
		     lib_set_value(target,keyvalue[i]); //save to tree
		   }
           else
           {
              tr_log(LOG_NOTICE,"lib resolve_node failed : %s", paraname);
           }
	       node->nin++;
	    }
	}
	lib_commit_transaction();

    lib_save_mapfile(mapfilename,mapInfos,MAXMAPITEMS);
	
	return 0;
}

/*!
 * \fn lib_init_process_children
 * \brief init process object instance children 
 *
 * \param node The parent node
 *
 * \return 0
 *
 */
int lib_init_process_children(node_t node)
{
   char keyvalue[MAXMAPITEMS][256];
   int  number = 0;
   
   number = get_process_pid(keyvalue);

   processMaxInstanceNum = node->il;

   return lib_init_readonly_children(node,"Device.DeviceInfo.ProcessStatus.Process.","PID",keyvalue,number,ProcessMap);
}

int lib_init_IndividualPacketResult_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	char enable[32] = {0};

	do_uci_get(DIDU_EnableIndividualPacketResults, enable);
	if(atoi(enable) != 1)
	{
		return 0;
	}

	number = get_IndividualPacketResult_PacketSendTime(keyvalue);

	return lib_init_readonly_children(node,"Device.IP.Diagnostics.UDPEchoDiagnostics.IndividualPacketResult.","PacketSendTime",keyvalue,number,IndividualPacketResultMap);
}

int lib_init_RootDevice_children(node_t node)
{
   char keyvalue[MAXMAPITEMS][256];
   int  number = 0;
   
   number = get_RootDevice_USN(keyvalue);

   return lib_init_readonly_children(node,"Device.UPnP.Discovery.RootDevice.","USN",keyvalue,number,RootDeviceMap);
}

int lib_init_DiscoveryDevice_children(node_t node)
{
   char keyvalue[MAXMAPITEMS][256];
   int  number = 0;
   
   number = get_DiscoveryDevice_USN(keyvalue);

   return lib_init_readonly_children(node,"Device.UPnP.Discovery.Device.","USN",keyvalue,number,DiscoveryDeviceMap);
}

int lib_init_DeviceDescription_children(node_t node)
{
   char keyvalue[MAXMAPITEMS][256];
   int  number = 0;
   
   number = get_DeviceDescription_URLBase(keyvalue);

   return lib_init_readonly_children(node,"Device.UPnP.Description.DeviceDescription.","URLBase",keyvalue,number,DeviceDescriptionMap);
}

int lib_init_DeviceInstance_children(node_t node)
{
   char keyvalue[MAXMAPITEMS][256];
   int  number = 0;
   
   number = get_DeviceInstance_UDN(keyvalue);

   return lib_init_readonly_children(node,"Device.UPnP.Description.DeviceInstance.","UDN",keyvalue,number,DeviceInstanceMap);
}

int lib_init_ServiceInstance_children(node_t node)
{
   char keyvalue[MAXMAPITEMS][256];
   int  number = 0;
   
   number = get_ServiceInstance_ServiceId(keyvalue);

   return lib_init_readonly_children(node,"Device.UPnP.Description.ServiceInstance.","ServiceId",keyvalue,number,ServiceInstanceMap);
}

int lib_init_Device_ManagementServer_ManageableDevice_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_Device_ManagementServer_ManageableDevice(keyvalue);

	return lib_init_readonly_children(node,"Device.ManagementServer.ManageableDevice.","Host",keyvalue,number,ManagementServerManageableDeviceMapMap);
}

int lib_init_RouterIPv4_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	int ret = 0;	
	number = get_RouterIPv4_DestIPAddress(keyvalue);
	routingipv4modifyflag = 1;
	ret = lib_init_writeable_children(node,"Device.Routing.Router.1.IPv4Forwarding.","DestIPAddress",keyvalue,number,RouterIPv4Map);
	routingipv4modifyflag = 0;
	return ret;
}

int lib_init_GREInterface_children(node_t node)
{
	tr_log( LOG_NOTICE, "path: %s", "Device.GRE.Tunnel.1.Interface." );
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	int ret = 0;	
	number = get_GREInterface_Alias(keyvalue);
	tr_log( LOG_NOTICE, "number: %d", number );
	GREInterfacemodifyflag = 1;
	ret = lib_init_readonly_children(node,"Device.GRE.Tunnel.1.Interface.","Name",keyvalue,number,GREInterfaceMap);
	GREInterfacemodifyflag = 0;
	return ret;
}

int lib_init_GREFilter_children(node_t node)
{
	tr_log( LOG_NOTICE, "path: %s", "Device.GRE.Filter." );
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	int ret = 0;	
	number = get_GREFilter_Alias(keyvalue);
	tr_log( LOG_NOTICE, "number: %d", number );
	GREFiltermodifyflag = 1;
	ret = lib_init_writeable_children(node,"Device.GRE.Filter.","Order",keyvalue,number,GREFilterMap);
	GREFiltermodifyflag = 0;
	return ret;
}

int lib_init_QoSShaper_children(node_t node)
{
	tr_log( LOG_NOTICE, "path: %s", "Device.QoS.Shaper." );
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	int ret = 0;
	number = get_QoSShaper_Alias(keyvalue);
	tr_log( LOG_NOTICE, "number: %d", number );
	qosshapermodifyflag = 1;
	ret = lib_init_writeable_children(node,"Device.QoS.Shaper.","Alias",keyvalue,number,QoSShaperMap);
	qosshapermodifyflag = 0;
	return ret;
}

int lib_init_QoSQueue_children(node_t node)
{
	tr_log( LOG_NOTICE, "path: %s", "Device.QoS.Queue." );
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	int ret = 0;	
	number = get_QoSQueue_Alias(keyvalue);
	tr_log( LOG_NOTICE, "number: %d", number );
	qosqueuemodifyflag = 1;
	ret = lib_init_writeable_children(node,"Device.QoS.Queue.","Alias",keyvalue,number,QoSQueueMap);
	qosqueuemodifyflag = 0;
	return ret;
}

int lib_init_QoSApp_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	int ret = 0;	
	number = get_QoSApp_Alias(keyvalue);
	tr_log( LOG_NOTICE, "number: %d", number );
	qosappmodifyflag = 1;
	ret = lib_init_writeable_children(node,"Device.QoS.App.","Alias",keyvalue,number,QoSAppMap);
	qosappmodifyflag = 0;
	return ret;
}


int lib_init_QoSClassification_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	int ret = 0;	
	number = get_QoSClassification_Alias(keyvalue);
	tr_log( LOG_NOTICE, "number: %d", number );
	qosclassficationmodifyflag = 1;
	ret = lib_init_writeable_children(node,"Device.QoS.Classification.","Alias",keyvalue,number,QoSClassificationMap);
	qosclassficationmodifyflag = 0;
	return ret;
}

int lib_init_RouterIPv6_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	
	number = get_RouterIPv6_DestIPAddress(keyvalue);
	
	return lib_init_readonly_children(node,"Device.Routing.Router.1.IPv6Forwarding.","DestIPPrefix",keyvalue,number,RouterIPv6Map);
}

int lib_init_IPsecTunnel_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	
	number = get_IPsecTunnel_Alias(keyvalue);
	
	return lib_init_readonly_children(node,"Device.IPsec.Tunnel.","Alias",keyvalue,number,IPsecTunnelMap);
}

int lib_init_PortMapping_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	int  ret = 0;
	tr_log( LOG_NOTICE, "path: %s", "lib_init_PortMapping_children" );
	
	number = get_PortMapping_InternalPort(keyvalue);
	tr_log(LOG_DEBUG,"################################################number[%d]",number);
	tr_log(LOG_DEBUG,"################################################keyvalue[%s]",keyvalue[0]);
	portmappingmodifyflag = 1;
	ret = lib_init_writeable_children(node,"Device.NAT.PortMapping.","ExternalPort",keyvalue,number,PortMappingMap);
	portmappingmodifyflag = 0;
	return ret;
}

int lib_init_ActivePort_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	
	number = get_ActivePort_localIP(keyvalue);
	tr_log(LOG_DEBUG,"################################################number[%d]",number);
	tr_log(LOG_DEBUG,"################################################keyvalue[%s]",keyvalue[0]);
	
	return lib_init_readonly_children(node,"Device.IP.ActivePort.","LocalIPAddress",keyvalue,number,ActivePortMap);
}

int lib_init_RouteHops_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	
	number = get_RouteHops_HostAddress(keyvalue);
	tr_log(LOG_DEBUG,"################################################number[%d]",number);
	tr_log(LOG_DEBUG,"################################################keyvalue[%s]",keyvalue[0]);
	
	return lib_init_readonly_children(node,"Device.IP.Diagnostics.TraceRoute.RouteHops.","HostAddress",keyvalue,number,RouteHopsMap);
}

int lib_init_AssociatedDevice_children_frmgetv(char* path, node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;

	printf("==============James debug========lib_init_AssociatedDevice_children_frmgetv, path=%s\n",path);
	
	if (strncmp(path,"Device.WiFi.AccessPoint.10101.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10101.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10101.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap1);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10102.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10102.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10102.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap2);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10103.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10103.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10103.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap3);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10104.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10104.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10104.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap4);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10105.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10105.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10105.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap5);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10106.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10106.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10106.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap6);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10107.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10107.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10107.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap7);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10108.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10108.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10108.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap8);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10001.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10001.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10001.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap9);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10002.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10002.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10002.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap10);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10003.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10003.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10003.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap11);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10004.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10004.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10004.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap12);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10005.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10005.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10005.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap13);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10006.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10006.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10006.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap14);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10007.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10007.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10007.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap15);
		}
	}
	else if(strncmp(path,"Device.WiFi.AccessPoint.10008.AssociatedDevice.",strlen(path)) == 0)
	{
		if (lib_resolve_node("Device.WiFi.AccessPoint.10008.AssociatedDevice", &node) == 0)
		{
			number = get_AssociatedDevice_MAC(path, keyvalue);
			if(number < 0)
			{
				return -1;
			}	
			return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10008.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap16);
		}
	}		
}

int lib_init_AssociatedDevice_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
    char* path;
	
	path = lib_node2path(node);
	
	if (strcmp(path,"Device.WiFi.AccessPoint.10101.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10101.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap1);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10102.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10102.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap2);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10103.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10103.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap3);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10104.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10104.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap4);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10105.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10105.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap5);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10106.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10106.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap6);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10107.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10107.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap7);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10108.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10108.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap8);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10001.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10001.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap9);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10002.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10002.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap10);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10003.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10003.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap11);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10004.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10004.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap12);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10005.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10005.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap13);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10006.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10006.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap14);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10007.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10007.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap15);
	}
	else if (strcmp(path,"Device.WiFi.AccessPoint.10008.AssociatedDevice.") == 0)
	{
		number = get_AssociatedDevice_MAC(path, keyvalue);
		if(number < 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.WiFi.AccessPoint.10008.AssociatedDevice.","MACAddress",keyvalue,number,AssociatedDeviceMap16);
	}
}

int lib_init_Device_DHCPv4_Server_Pool_1_Client_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_DHCPv4_Server_Pool_Client_mac(keyvalue, 1);

	return lib_init_readonly_children(node,"Device.DHCPv4.Server.Pool.1.Client.","Chaddr",keyvalue,number,DHCPv4ServerPool1ClientMap);
}

int lib_init_Device_DHCPv4_Server_Pool_2_Client_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_DHCPv4_Server_Pool_Client_mac(keyvalue, 2);

	return lib_init_readonly_children(node,"Device.DHCPv4.Server.Pool.2.Client.","Chaddr",keyvalue,number,DHCPv4ServerPool2ClientMap);
}

int lib_init_Device_DHCPv4_Server_Pool_3_Client_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_DHCPv4_Server_Pool_Client_mac(keyvalue, 3);

	return lib_init_readonly_children(node,"Device.DHCPv4.Server.Pool.3.Client.","Chaddr",keyvalue,number,DHCPv4ServerPool3ClientMap);
}

int lib_init_Device_DHCPv4_Server_Pool_4_Client_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_DHCPv4_Server_Pool_Client_mac(keyvalue, 4);

	return lib_init_readonly_children(node,"Device.DHCPv4.Server.Pool.4.Client.","Chaddr",keyvalue,number,DHCPv4ServerPool4ClientMap);
}

int lib_init_Device_DHCPv6ClientSendOption_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	int ret = 0;
	number = get_Device_DHCPv6_Clinet_SendOptions(keyvalue);
	tr_log( LOG_NOTICE, "number: %d", number );
	dhcpv6Sentoptionmodifyflag = 1;
	ret = lib_init_writeable_children(node,"Device.DHCPv6.Client.1.SentOption.","Tag",keyvalue,number,RouterDHCPv6clinetOptionMap);
	dhcpv6Sentoptionmodifyflag = 0;
	return ret;
}

int lib_init_Device_DHCPv4_Server_Pool_1_Client_Option_children(node_t node, char *tmpname)
{
    char *path;
    char *p = NULL;
	char tmp[256] = {0};
	char newpath[256] = {0};
	int ret = 0;
    char *value;
    node_t tmpnode;
	char clientip[32] = {0};
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	char mapfilename[256] = {0};
	
	path = lib_node2path(node);

	p = strstr(path, "Option");
	if(p != NULL)
	{
		strncpy(tmp, path, p-path);
		sprintf(newpath, "%sIPv4Address.1.IPAddress", tmp);
		if( lib_resolve_node( newpath, &tmpnode ) == 0 ) 
		{
			ret = lib_get_value( tmpnode, &value );
		
			if( ret != 0 ) 
			{
				tr_log( LOG_ERROR, "Get %s failed!", newpath );
			} 
			else 
			{
				strcpy(clientip, value);
			}
		
			lib_destroy_value( value );
		}
	}

	number = get_DHCPv4_Server_Pool_1_Client_options(clientip, keyvalue);
	sprintf(mapfilename, "DHCPv4ServerPool1Client_%s_OptionsMap.mapping", clientip);
	return lib_init_readonly_children(node, tmpname, "Tag", keyvalue, number, mapfilename);
}

int lib_init_Device_DHCPv4_Server_Pool_1_StaticAddress_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	int ret = 0;
   
	number = get_DHCPv4_Server_Pool_1_StaticAddress_ip(keyvalue);

	staticipmodifyflag = 1;
	ret = lib_init_writeable_children(node,"Device.DHCPv4.Server.Pool.1.StaticAddress.","Yiaddr",keyvalue,number,DHCPv4ServerPool1StaticAddressMap);
	staticipmodifyflag = 0;
	return ret;
}

int lib_init_Device_Hosts_SHost_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_Hosts_ip(keyvalue);

	return lib_init_readonly_children(node,"Device.Hosts.Host.","PhysAddress",keyvalue,number,HostsHostMap);
}

int lib_init_Device_USBHosts_Device_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
    char* path;
	
	path = lib_node2path(node);
   
	if (strcmp(path,"Device.USB.USBHosts.Host.1.Device.") == 0)
	{
		number = get_USBHostsDevice(keyvalue, "1"); // 1 is the usb bus number
		if(number <= 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.USB.USBHosts.Host.1.Device.","SerialNumber",keyvalue,number,USBHosts1Map);
	}
	else if (strcmp(path,"Device.USB.USBHosts.Host.2.Device.") == 0)
	{
		number = get_USBHostsDevice(keyvalue, "3"); // 3 is the usb bus number
		if(number <= 0)
		{
			return -1;
		}	
		return lib_init_readonly_children(node,"Device.USB.USBHosts.Host.2.Device.","SerialNumber",keyvalue,number,USBHosts2Map);
	}
}

int lib_init_Device_RouterAdvertisement_InterfaceSetting_1_Option_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_Device_RouterAdvertisement_InterfaceSetting_Option_type(keyvalue);

	return lib_init_readonly_children(node,"Device.RouterAdvertisement.InterfaceSetting.1.Option.","Tag",keyvalue,number,RouterAdvertisementInterfaceSetting1OptionMap);
}

int lib_init_Device_DHCPv6_Server_Pool_1_Client_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_Device_DHCPv6_Server_Pool_1_Client_address(keyvalue);

	return lib_init_readonly_children(node,"Device.DHCPv6.Server.Pool.1.Client.","SourceAddress",keyvalue,number,DHCPv6ServerPool1ClientMap);
}

int lib_init_Device_DHCPv4_Server_Option_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
	int ret = 0;
	number = get_Device_DHCPv4_Server_Options(keyvalue);
	tr_log( LOG_NOTICE, "number: %d", number );
	dhcpserveroptionsmodifyflag = 1;
	ret = lib_init_writeable_children(node,"Device.DHCPv4.Server.Pool.1.Option.","Tag",keyvalue,number,RouterDHCPv4ServerOptionMap);
	dhcpserveroptionsmodifyflag = 0;
	return ret;
}

int lib_init_Device_NSLookupDiagnostics_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_Device_NSLookupDiagnostics_Result_Entry(keyvalue);

	return lib_init_readonly_children(node,"Device.DNS.Diagnostics.NSLookupDiagnostics.Result.","Status",keyvalue,number,NSLookupDiagnosticsMap);
}

int lib_init_Device_DHCPv6ClientServer_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_Device_DHCPv6ClientServer_Entry(keyvalue);

	return lib_init_readonly_children(node,"Device.DHCPv6.Client.1.Server.","SourceAddress",keyvalue,number,DHCPv6ClientServerMap);
}

int lib_init_Device_DHCPv6ClientReceivedOption_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_Device_DHCPv6ClientReceivedOption_Entry(keyvalue);

	return lib_init_readonly_children(node,"Device.DHCPv6.Client.1.ReceivedOption.","Tag",keyvalue,number,DHCPv6ClientReceivedOptionMap);
}

int lib_init_Device_DHCPv6ServerPool_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_Device_DHCPv6ServerPool_Entry(keyvalue);

	return lib_init_readonly_children(node,"Device.DHCPv6.Server.Pool.","Order",keyvalue,number,DHCPv6ServerPoolMap);
}

int lib_init_Device_InterfaceStack_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_Device_InterfaceStack_Entry(keyvalue);

	return lib_init_readonly_children(node,"Device.InterfaceStack.","HigherAlias",keyvalue,number,InterfaceStackMap);
}

int lib_init_Device_Bridging_Bridge_1_Port_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_Device_Bridging_Bridge_1_Port_Entry(keyvalue);

	return lib_init_readonly_children(node,"Device.Bridging.Bridge.1.Port.","Name",keyvalue,number,BridgingBridge1PortMap);
}

int lib_init_Device_WiFiNeighboringWiFiDiagnostic_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_Device_WiFiNeighboringWiFiDiagnostic_Entry(keyvalue);

	return lib_init_readonly_children(node,"Device.WiFi.NeighboringWiFiDiagnostic.Result.","BSSID",keyvalue,number,WiFiNeighboringWiFiDiagnosticMap);
}

int lib_init_Device_IEEE1905_AL_Interface_children(node_t node)
{
	char keyvalue[MAXMAPITEMS][256];
	int  number = 0;
   
	number = get_Device_IEEE1905ALInterface_Entry(keyvalue);

	return lib_init_readonly_children(node,"Device.IEEE1905.AL.Interface.","InterfaceId",keyvalue,number,IEEE1905ALInterfaceMap);
}

/*!
 * \fn lib_dynamic_init_children_frmgetv
 * \brief init instance object at getparametervalue
 *
 * \param path
 *
 * \return 0
 *
 */
int lib_dynamic_init_children_frmgetv(char* path)
{
    node_t node;
    if (path)
    {
		/* every readonly instance object can init like process */ 
		if (strncmp(path,"Device.DeviceInfo.ProcessStatus.Process.",strlen(path)) == 0)
	    {
			if (lib_resolve_node("Device.DeviceInfo.ProcessStatus.Process", &node) == 0)
			{
				lib_init_process_children(node);
			}
		}

		if (strncmp(path,"Device.IP.Diagnostics.UDPEchoDiagnostics.IndividualPacketResult.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.IP.Diagnostics.UDPEchoDiagnostics.IndividualPacketResult", &node) == 0)
			{
				lib_init_IndividualPacketResult_children(node);
			}
		}

		if (strncmp(path,"Device.UPnP.Discovery.RootDevice.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.UPnP.Discovery.RootDevice", &node) == 0)
			{
				lib_init_RootDevice_children(node);
			}
		}

		if (strncmp(path,"Device.UPnP.Discovery.Device.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.UPnP.Discovery.Device", &node) == 0)
			{
				lib_init_DiscoveryDevice_children(node);
			}
		}

		if (strncmp(path,"Device.UPnP.Description.DeviceDescription.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.UPnP.Description.DeviceDescription", &node) == 0)
			{
				lib_init_DeviceDescription_children(node);
			}
		}

		if (strncmp(path,"Device.UPnP.Description.DeviceInstance.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.UPnP.Description.DeviceInstance", &node) == 0)
			{
				lib_init_DeviceInstance_children(node);
			}
		}

		if (strncmp(path,"Device.UPnP.Description.ServiceInstance.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.UPnP.Description.ServiceInstance", &node) == 0)
			{
				lib_init_ServiceInstance_children(node);
			}
		}

		/* support add/del instance object can init like */
		/*if (strcmp(path,"Device.Ethernet.Link.") == 0)
		{
			 lib_init_ethlink_children(node);
		}*/

		if (strncmp(path,"Device.IP.ActivePort.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.IP.ActivePort", &node) == 0)
			{
				lib_init_ActivePort_children(node);
			}
		}

		if (strncmp(path,"Device.NAT.PortMapping.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.NAT.PortMapping", &node) == 0)
			{
				lib_init_PortMapping_children(node);
			}
		}

		if (strncmp(path,"Device.Routing.Router.1.IPv4Forwarding.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.Routing.Router.1.IPv4Forwarding", &node) == 0)
			{
				lib_init_RouterIPv4_children(node);
			}
		}

		if (strncmp(path,"Device.QoS.Classification.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.QoS.Classification", &node) == 0)
			{
				lib_init_QoSClassification_children(node);
			}
		}

		if (strncmp(path,"Device.QoS.App.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.QoS.App", &node) == 0)
			{
				lib_init_QoSApp_children(node);
			}
		}

		if (strncmp(path,"Device.QoS.Queue.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.QoS.Queue", &node) == 0)
			{
				lib_init_QoSQueue_children(node);
			}
		}

		/*if (strncmp(path,"Device.QoS.Shaper.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.QoS.Shaper", &node) == 0)
			{
				lib_init_QoSShaper_children(node);
			}
		}*/

		if (strncmp(path,"Device.GRE.Filter.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.GRE.Filter", &node) == 0)
			{
				lib_init_GREFilter_children(node);
			}
		}

		if (strncmp(path,"Device.GRE.Tunnel.1.Interface.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.GRE.Tunnel.1.Interface", &node) == 0)
			{
				lib_init_GREInterface_children(node);
			}
		}

		if (strncmp(path,"Device.Routing.Router.1.IPv6Forwarding.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.Routing.Router.1.IPv6Forwarding", &node) == 0)
			{
				lib_init_RouterIPv6_children(node);
			}
		}

		if (strncmp(path,"Device.IPsec.Tunnel.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.IPsec.Tunnel", &node) == 0)
			{
				lib_init_IPsecTunnel_children(node);
			}
		}

		if (strncmp(path,"Device.IP.Diagnostics.TraceRoute.RouteHops.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.IP.Diagnostics.TraceRoute.RouteHops", &node) == 0)
			{
				lib_init_RouteHops_children(node);
			}
		}

		if (strncmp(path,"Device.ManagementServer.ManageableDevice.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.ManagementServer.ManageableDevice", &node) == 0)
			{
				lib_init_Device_ManagementServer_ManageableDevice_children(node);
			}
		}

		if (strncmp(path,"Device.DHCPv4.Server.Pool.1.Client.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.DHCPv4.Server.Pool.1.Client", &node) == 0)
			{
				lib_init_Device_DHCPv4_Server_Pool_1_Client_children(node);
			}
		}

		if (strncmp(path,"Device.DHCPv4.Server.Pool.2.Client.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.DHCPv4.Server.Pool.2.Client", &node) == 0)
			{
				lib_init_Device_DHCPv4_Server_Pool_2_Client_children(node);
			}
		}

		if (strncmp(path,"Device.DHCPv4.Server.Pool.3.Client.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.DHCPv4.Server.Pool.3.Client", &node) == 0)
			{
				lib_init_Device_DHCPv4_Server_Pool_3_Client_children(node);
			}
		}

		if (strncmp(path,"Device.DHCPv4.Server.Pool.4.Client.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.DHCPv4.Server.Pool.4.Client", &node) == 0)
			{
				lib_init_Device_DHCPv4_Server_Pool_4_Client_children(node);
			}
		}

		if (strncmp(path,"Device.DHCPv4.Server.Pool.1.StaticAddress.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.DHCPv4.Server.Pool.1.StaticAddress", &node) == 0)
			{
				lib_init_Device_DHCPv4_Server_Pool_1_StaticAddress_children(node);
			}
		}
		
		if (strncmp(path,"Device.Hosts.Host.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.Hosts.Host", &node) == 0)
			{
				lib_init_Device_Hosts_SHost_children(node);
			}
		}
		
		if (strncmp(path,"Device.RouterAdvertisement.InterfaceSetting.1.Option.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.RouterAdvertisement.InterfaceSetting.1.Option", &node) == 0)
			{
				lib_init_Device_RouterAdvertisement_InterfaceSetting_1_Option_children(node);
			}
		}
		
		if (strncmp(path,"Device.DHCPv6.Server.Pool.1.Client.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.DHCPv6.Server.Pool.1.Client", &node) == 0)
			{
				lib_init_Device_DHCPv6_Server_Pool_1_Client_children(node);
			}
		}
		
		if (strncmp(path,"Device.DHCPv4.Server.Pool.1.Option.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.DHCPv4.Server.Pool.1.Option", &node) == 0)
			{
				lib_init_Device_DHCPv4_Server_Option_children(node);
			}
		}
		
		if (strncmp(path,"Device.DNS.Diagnostics.NSLookupDiagnostics.Result.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.DNS.Diagnostics.NSLookupDiagnostics.Result", &node) == 0)
			{
				lib_init_Device_NSLookupDiagnostics_children(node);
			}
		}

		if (strncmp(path,"Device.DHCPv6.Client.1.Server.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.DHCPv6.Client.1.Server", &node) == 0)
			{
				lib_init_Device_DHCPv6ClientServer_children(node);
			}
		}
		
		if (strncmp(path,"Device.DHCPv6.Client.1.ReceivedOption.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.DHCPv6.Client.1.ReceivedOption", &node) == 0)
			{
				lib_init_Device_DHCPv6ClientReceivedOption_children(node);
			}
		}

		if (strncmp(path,"Device.DHCPv6.Client.1.SentOption.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.DHCPv6.Client.1.SentOption", &node) == 0)
			{
				lib_init_Device_DHCPv6ClientSendOption_children(node);
			}
		}

		if (strncmp(path,"Device.DHCPv6.Server.Pool.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.DHCPv6.Server.Pool", &node) == 0)
			{
				lib_init_Device_DHCPv6ServerPool_children(node);
			}
		}

		if (strncmp(path,"Device.InterfaceStack.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.InterfaceStack", &node) == 0)
			{
				lib_init_Device_InterfaceStack_children(node);
			}
		}

		if (strncmp(path,"Device.Bridging.Bridge.1.Port.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.Bridging.Bridge.1.Port", &node) == 0)
			{
				lib_init_Device_Bridging_Bridge_1_Port_children(node);
			}
		}

		if (strncmp(path,"Device.WiFi.NeighboringWiFiDiagnostic.Result.",strlen(path)) == 0)
		{
			if (lib_resolve_node("Device.WiFi.NeighboringWiFiDiagnostic.Result", &node) == 0)
			{
				lib_init_Device_WiFiNeighboringWiFiDiagnostic_children(node);
			}
		}

		if ((strncmp(path,"Device.WiFi.AccessPoint.",strlen("Device.WiFi.AccessPoint.")) == 0) || (strncmp(path,"Device.WiFi.AccessPoint.",strlen(path)) == 0))
		{
			/* init all object instance at  Device.WiFi.AccessPoint*/
			lib_init_AssociatedDevice_children_frmgetv(path, node);
		}

		if ((strncmp(path,"Device.USB.USBHosts.Host.",strlen(path)) == 0) ||(strncmp(path,"Device.USB.USBHosts.Host.",strlen("Device.USB.USBHosts.Host.")) == 0))
		{
			/* init all object instance at Device.USB.USBHosts.Host*/
		}

		if (strstr(path,"Device.DHCPv4.Server.Pool.1.Client.") != NULL && strstr(path,"Option") != NULL)
		{
			int client_num = get_DHCPv4_Server_Pool_Client_num(1);
			int count;
			char tmpname[256];
			
			for(count=1; count<=client_num; count++)
			{
				memset(tmpname, 0, sizeof(tmpname));
				sprintf(tmpname, "Device.DHCPv4.Server.Pool.1.Client.%d.Option.", count);
				
				if (strcmp(path,tmpname) == 0)
				{
					if (lib_resolve_node(tmpname, &node) == 0)
					{
						lib_init_Device_DHCPv4_Server_Pool_1_Client_Option_children(node, tmpname);
					}
				}
			}
		}
	}
    return 0;
}

/*!
 * \fn lib_dynamic_init_children
 * \brief init instance object
 *
 * \param node The parent node
 *
 * \return 0
 *
 */

int lib_dynamic_init_children(node_t node)
{
    char* path;	

    path = lib_node2path(node);

	//tr_log( LOG_NOTICE, "path: %s", path ); //AKSEY SH, need more time to show this log inifo,which will make the 'Receive http message ret 0'
	if (path)
	{
	    /* every readonly instance object can init like process */ 
	    if (strcmp(path,"Device.DeviceInfo.ProcessStatus.Process.") == 0)
	    {
	       lib_init_process_children(node);
	    }

	    if (strcmp(path,"Device.IP.Diagnostics.UDPEchoDiagnostics.IndividualPacketResult.") == 0)
	    {
	       lib_init_IndividualPacketResult_children(node);
	    }

	    if (strcmp(path,"Device.UPnP.Discovery.RootDevice.") == 0)
	    {
	       lib_init_RootDevice_children(node);
	    }

	    if (strcmp(path,"Device.UPnP.Discovery.Device.") == 0)
	    {
	       lib_init_DiscoveryDevice_children(node);
	    }

	    if (strcmp(path,"Device.UPnP.Description.DeviceDescription.") == 0)
	    {
	       lib_init_DeviceDescription_children(node);
	    }

	    if (strcmp(path,"Device.UPnP.Description.DeviceInstance.") == 0)
	    {
	       lib_init_DeviceInstance_children(node);
	    }

	    if (strcmp(path,"Device.UPnP.Description.ServiceInstance.") == 0)
	    {
	       lib_init_ServiceInstance_children(node);
	    }

		/* support add/del instance object can init like */
		/*if (strcmp(path,"Device.Ethernet.Link.") == 0)
		{
		   lib_init_ethlink_children(node);
		}*/

		if (strcmp(path,"Device.IP.ActivePort.") == 0)
    	{
			lib_init_ActivePort_children(node);
    	}

	    if (strcmp(path,"Device.NAT.PortMapping.") == 0)
    	{
			lib_init_PortMapping_children(node);
    	}

	    if (strcmp(path,"Device.Routing.Router.1.IPv4Forwarding.") == 0)
    	{
			lib_init_RouterIPv4_children(node);
    	}

	    if (strcmp(path,"Device.QoS.Classification.") == 0)
    	{
			lib_init_QoSClassification_children(node);
    	}

	    if (strcmp(path,"Device.QoS.App.") == 0)
    	{
			lib_init_QoSApp_children(node);
    	}

	    if (strcmp(path,"Device.QoS.Queue.") == 0)
    	{
			lib_init_QoSQueue_children(node);
    	}

	    /*if (strcmp(path,"Device.QoS.Shaper.") == 0)
    	{
			lib_init_QoSShaper_children(node);
    	}*/

	    if (strcmp(path,"Device.GRE.Filter.") == 0)
    	{
			lib_init_GREFilter_children(node);
    	}

	    if (strcmp(path,"Device.GRE.Tunnel.1.Interface.") == 0)
    	{
			lib_init_GREInterface_children(node);
    	}

		if (strcmp(path,"Device.Routing.Router.1.IPv6Forwarding.") == 0)
    	{
			lib_init_RouterIPv6_children(node);
    	}

		if (strcmp(path,"Device.IPsec.Tunnel.") == 0)
    	{
			lib_init_IPsecTunnel_children(node);
    	}

		if (strcmp(path,"Device.IP.Diagnostics.TraceRoute.RouteHops.") == 0)
    	{
			lib_init_RouteHops_children(node);
    	}

		if (strstr(path,"AccessPoint") != NULL && strstr(path,"AssociatedDevice") != NULL)
		{
			lib_init_AssociatedDevice_children(node);
		}

		if (strcmp(path,"Device.ManagementServer.ManageableDevice.") == 0)
		{
		   lib_init_Device_ManagementServer_ManageableDevice_children(node);
		}

		if (strcmp(path,"Device.DHCPv4.Server.Pool.1.Client.") == 0)
		{
		   lib_init_Device_DHCPv4_Server_Pool_1_Client_children(node);
		}

		if (strcmp(path,"Device.DHCPv4.Server.Pool.2.Client.") == 0)
		{
		   lib_init_Device_DHCPv4_Server_Pool_2_Client_children(node);
		}

		if (strcmp(path,"Device.DHCPv4.Server.Pool.3.Client.") == 0)
		{
		   lib_init_Device_DHCPv4_Server_Pool_3_Client_children(node);
		}

		if (strcmp(path,"Device.DHCPv4.Server.Pool.4.Client.") == 0)
		{
		   lib_init_Device_DHCPv4_Server_Pool_4_Client_children(node);
		}

		if (strcmp(path,"Device.DHCPv4.Server.Pool.1.StaticAddress.") == 0)
		{
		   lib_init_Device_DHCPv4_Server_Pool_1_StaticAddress_children(node);
		}
		
		if (strcmp(path,"Device.Hosts.Host.") == 0)
		{
		   lib_init_Device_Hosts_SHost_children(node);
		}
		
		if (strstr(path,"Device.USB.USBHosts.Host.") != NULL)
		{
		   lib_init_Device_USBHosts_Device_children(node);
		}
		
		if (strcmp(path,"Device.RouterAdvertisement.InterfaceSetting.1.Option.") == 0)
		{
		   lib_init_Device_RouterAdvertisement_InterfaceSetting_1_Option_children(node);
		}
		
		if (strcmp(path,"Device.DHCPv6.Server.Pool.1.Client.") == 0)
		{
		   lib_init_Device_DHCPv6_Server_Pool_1_Client_children(node);
		}
		
		if (strcmp(path,"Device.DHCPv4.Server.Pool.1.Option.") == 0)
		{
		   lib_init_Device_DHCPv4_Server_Option_children(node);
		}
		if (strcmp(path,"Device.DNS.Diagnostics.NSLookupDiagnostics.Result.") == 0)
		{
		   lib_init_Device_NSLookupDiagnostics_children(node);
		}
		
		if (strcmp(path,"Device.DHCPv6.Client.1.Server.") == 0)
		{
		   lib_init_Device_DHCPv6ClientServer_children(node);
		}
		
		if (strcmp(path,"Device.DHCPv6.Client.1.ReceivedOption.") == 0)
		{
		   lib_init_Device_DHCPv6ClientReceivedOption_children(node);
		}

		if (strcmp(path,"Device.DHCPv6.Client.1.SentOption.") == 0)
		{
			lib_init_Device_DHCPv6ClientSendOption_children(node);
		}
		
		if (strcmp(path,"Device.DHCPv6.Server.Pool.") == 0)
		{
		   lib_init_Device_DHCPv6ServerPool_children(node);
		}

		if (strcmp(path,"Device.InterfaceStack.") == 0)
		{
		   lib_init_Device_InterfaceStack_children(node);
		}

		if (strcmp(path,"Device.Bridging.Bridge.1.Port.") == 0)
		{
		   lib_init_Device_Bridging_Bridge_1_Port_children(node);
		}

		if (strcmp(path,"Device.WiFi.NeighboringWiFiDiagnostic.Result.") == 0)
		{
		   lib_init_Device_WiFiNeighboringWiFiDiagnostic_children(node);
		}

		if (strcmp(path,"Device.IEEE1905.AL.Interface.") == 0)
		{
		   lib_init_Device_IEEE1905_AL_Interface_children(node);
		}

		if (strstr(path,"Device.DHCPv4.Server.Pool.1.Client.") != NULL && strstr(path,"Option") != NULL)
		{
			int client_num = get_DHCPv4_Server_Pool_Client_num(1);
			int count;
			char tmpname[256];
			
			for(count=1; count<=client_num; count++)
			{
				memset(tmpname, 0, sizeof(tmpname));
				sprintf(tmpname, "Device.DHCPv4.Server.Pool.1.Client.%d.Option.", count);
				
				if (strcmp(path,tmpname) == 0)
				{
				   lib_init_Device_DHCPv4_Server_Pool_1_Client_Option_children(node, tmpname);
				}
			}
		}
	}

	return 0;
}

static int lib_init_mapping_file( int len, node_t node )
{
	if( len > 0 ) {
		int count;
		int res = METHOD_SUCCESSED;
		node_t *children = NULL;
		
		lib_dynamic_init_children(node);
		
		count = lib_get_children( node, &children );

		if( count > 0 ) {
			int i;

			for( i = 0; i < count && res == METHOD_SUCCESSED; i++ ) {
				res = lib_init_mapping_file( len, children[i] );
			}
		}

		if( children ) {
			lib_destroy_children( children );
		}

		return res;
	}

	return METHOD_SUCCESSED;
}

/* init all mapping files */
int lib_init_mapping_files( void )
{
	int res = -1;
	char *path = "Device.";
	int len = strlen(path);
	node_t node;
	
	res = lib_resolve_node(path, &node);
	if( res != 0 )
		return res;
	res = lib_init_mapping_file( len, node );
	return res;
}

//ASKEY end

/*!
 * \fn lib_get_children
 * \brief Get an interior node's children list
 *
 * \param node The parent node
 * \param children The buffer stores the children list
 *
 * \return The children number when success, -1 when any error
 *
 */
TR_LIB_API int lib_get_children( node_t node, node_t **children )
{
    int number = 0;
    node_t c;

    for( c = node->children; c; c = c->brother ) {
        if( strcmp( c->name, "template" ) != 0 ) {
            number++;
        }
    }

    if( number > 0 ) {
        int i;
        *children = calloc( number, sizeof( node_t ) );

        if( *children == NULL ) {
            return -1;
        }

        for( i = 0, c = node->children; c; c = c->brother ) {
            if( strcmp( c->name, "template" ) != 0 ) {
                ( *children ) [i++] = c;
            }
        }
    }

    return number;
}

/*!
 * \fn lib_destroy_children
 * \brief Destroy the children returned by callback function lib_get_children
 *
 * \param children The children list
 * \return N/A
 */

TR_LIB_API void lib_destroy_children( node_t *children )
{
    if( children ) {
        free( children );
    }
}

/*!
 * \fn lib_disk_free_space
 * \brief Get the available disk space of the device
 * \param type The type of target disk space to be released
 * \return The disk space size in byte
 */

TR_LIB_API int lib_disk_free_space( const char *type )
{
    if( war_strcasecmp( type, "1 Firmware Upgrade Image" ) == 0 ) {
        return 50 * 1024 * 1024;    //50M
    } else if( war_strcasecmp( type, "2 Web Content" ) == 0 ) {
        return 10 * 1024 * 1024;    //10 M
    } else if( war_strcasecmp( type, "3 Vendor Configuration File" ) == 0 ) {
        return 100 * 1024;    //100 K
    } else if( war_strcasecmp( type, "X 00256D 3GPP Configuration File" ) == 0 ) {
        return 1024 * 1024;    //1M
    } else {
        return -1;
    }
}

/*!
 * \fn lib_download_complete
 * \brief Notify the device that download some file complete
 *
 *  \param type The file type
 *  \param path The path the file was saved
 *  \param cmd_key The command key that CPE MUST echo from CLI
 *
 *  \return 1 means need reboot the device, 0 means OK and do not need to reboot the device, -1 means error
 */

TR_LIB_API int lib_download_complete( const char *type, const char *path, const char *cmd_key )
{
#if 0
    if( war_strcasecmp( type, "1 Firmware Upgrade Image" ) == 0 ||
        war_strcasecmp( type, "3 Vendor Configuration File" ) == 0 ) {
        tr_log( LOG_WARNING, "Need reboot after complete download: %s", type );
        return 1;
    }
#endif

	if( war_strcasecmp( type, "1 Firmware Upgrade Image" ) == 0 ){
		//Add by tony for A TransferComplete message sent in a subsequent Session.
		system("echo 1 > /tmp/waitacs");
		do_uci_set("trconf.Device_ManagementServer.sent_transfer_complete_event", "1");
		do_uci_set("trconf.Device_ManagementServer.sent_transfer_complete_cmd_key", cmd_key);
		do_uci_commit(MS);
		system("echo 1 > /tmp/beforreboot_transfer");
		//Add end
		if(!process_fw_upgrade( path ))
			return 1;
		else
		{
			//Add by tony for A TransferComplete message sent in a subsequent Session.
			do_uci_set("trconf.Device_ManagementServer.sent_transfer_complete_event", "0");
			do_uci_commit(MS);
			//Add end
			return -1;
		}
	}
	else if( war_strcasecmp( type, "3 Vendor Configuration File" ) == 0 ){
		system("echo 1 > /tmp/waitacs");
		if(!process_config( path )) //ASKEY add
			return 1;
		else
			return -1;
	}
	
#ifdef TR196
    else if( war_strcasecmp( type, "X 00256D 3GPP Configuration File" ) == 0 ) {
        process_cm( path );
        return 1;
    }

#endif
    else {
        return 0;
    }
}

/*!
 * \fn lib_commit_transaction
 * \brief Commit a transaction
 *
 * \return 0 when success, -1 when any error
 *
 * \remark The library does not need to care about atomic operation. TRAgent has
 * implemented it. But, think about some device implement the MOT in XML document or
 * some other likely techniques, some operations may change the XML document,
 * this function is the only chance to write back the MOT to file system. If the
 * device implements the MOT in some other techniques for example sqlite database,
 * it does need to do anything.
 */
TR_LIB_API int lib_commit_transaction( void )
{
    tr_log( LOG_DEBUG, "Commit transaction!" );

    if( change ) {
        change = 0;
        return tree2xml( root, xml_file_path );
    }

    return 0;
}

static int ip_ping()
{
    node_t node;
    pthread_detach( pthread_self() );
    tr_log( LOG_DEBUG, "Start IP Ping test" );
    war_sleep( 10 );
    tr_log( LOG_DEBUG, "IP Ping test over" );
    lib_start_session();
    lib_resolve_node( IP_PING, &node );
    lib_set_value( node, "Complete" );
    lib_end_session();
    tr069_cli( "http://127.0.0.1:1234/add/event/", "code=8 DIAGNOSTICS COMPLETE&cmdkey=" );
    pthread_exit( 0 );
    return 0;
}

/*!
 * \fn lib_start_ip_ping
 * \brief Start the IP Ping diagnostics
 *
 * \return N/A
 */
void lib_start_ip_ping( void )
{
#if 1
    pthread_t id;
    pthread_create( &id, NULL, ( void * ) ip_ping, NULL );
#endif
#if 0
    HANDLE id;
    id = CreateThread( NULL, 0, ip_ping, NULL, 0, NULL );
#endif
#if 0
    taskSpawn( "task_IPPING", 90, 0, TASK_STACK_SIZE, ( FUNCPTR ) ip_ping, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0 );
#endif
    return ;
}

#if 0
void lib_start_ip_ping( void )
{
    node_t node;
    tr_log( LOG_DEBUG, "Start IP Ping test" );
    lib_start_session();
    lib_resolve_node( IP_PING, &node );
    lib_set_value( node, "Complete" );
    lib_end_session();
    system( "./sendtocli http://127.0.0.1:1234/add/event/ \"code=8 DIAGNOSTICS COMPLETE&cmdkey=\"" );
}

#endif

/*!
 * \fn lib_stop_ip_ping
 * \Brief Stop the IP Ping diagnostics
 *
 * \return N/A
 */
void lib_stop_ip_ping( void )
{
    tr_log( LOG_DEBUG, "Stop IP Ping test" );
}

static int trace_route()
{
    node_t node;
    pthread_detach( pthread_self() );
    tr_log( LOG_DEBUG, "Start trace route test!" );
    war_sleep( 10 );
    tr_log( LOG_DEBUG, "trace route test over!" );
    lib_start_session();
    lib_resolve_node( TRACE_ROUTE, &node );
    lib_set_value( node, "Complete" );
    lib_end_session();
    tr069_cli( "http://127.0.0.1:1234/add/event/", "code=8 DIAGNOSTICS COMPLETE&cmdkey=" );
    pthread_exit( 0 );
    return 0;
}

/*!
 * \fn lib_start_trace_route
 * \brief Start the trace route diagnostics
 *
 * \return N/A
 */
void lib_start_trace_route( void )
{
#if 1
    pthread_t id;
    pthread_create( &id, NULL, ( void * ) trace_route, NULL );
#endif
#if 0
    HANDLE id;
    id = CreateThread( NULL, 0, trace_route, NULL, 0, NULL );
#endif
#if 0
    taskSpawn( "task_TRACEROUTE", 90, 0, TASK_STACK_SIZE, ( FUNCPTR ) trace_route, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0 );
#endif
    return;
}

#if 0
void lib_start_trace_route( void )
{
    node_t node;
    tr_log( LOG_DEBUG, "Start trace route test" );
    lib_start_session();
    lib_resolve_node( TRACE_ROUTE, &node );
    lib_set_value( node, "Complete" );
    lib_end_session();
    system( "./sendtocli http://127.0.0.1:1234/add/event/ \"code=8 DIAGNOSTICS COMPLETE&cmdkey=\"" );
}

#endif

/*!
 * \fn lib_stop_trace_route
 * \brief Stop the trace route Diagnostics
 *
 * \return N/A
 */
void lib_stop_trace_route( void )
{
    tr_log( LOG_DEBUG, "Stop trace route test" );
}

/* Add to DSL DIAGNOSTICS */
static int wan_dsl_diagnostics( char *path )
{
    node_t node;
    pthread_detach( pthread_self() );
    tr_log( LOG_DEBUG, "Start dsl_diagnostics test %s", path );
    war_sleep( 10 );
    tr_log( LOG_DEBUG, "dsl_dignostic test over" );
    lib_start_session();
    lib_resolve_node( path, &node );
    lib_set_value( node, "Complete" );
    lib_end_session();
    tr069_cli( "http://127.0.0.1:1234/add/event/", "code=8 DIAGNOSTICS COMPLETE&cmdkey=" );
    free(path);
    pthread_exit( 0 );
    return 0;
}

/*!
 * \brief Start the dsl diagnostics
 *
 * \return N/A
 */
void lib_start_wan_dsl_diagnostics( char *path )
{
#if 1
    pthread_t id;
    pthread_create( &id, NULL, ( void * ) wan_dsl_diagnostics, path );
#endif
#if 0
    HANDLE id;
    id = CreateThread( NULL, 0, dsl_diagnostics, path, 0, NULL );
#endif
#if 0
    taskSpawn( "task_DSLDIAG", 90, 0, TASK_STACK_SIZE, ( FUNCPTR ) dsl_diagnostics, path, 0, 0, 0, 0, 0, 0, 0, 0 , 0 );
#endif
    return;
}

/*!
 * \brief Stop the dsl diagnostics
 *
 * \return N/A
 */
void lib_stop_wan_dsl_diagnostics( char *path )
{
    tr_log( LOG_DEBUG, "Stop dsl_diagnostics test %s", path );
}

static int atm_diagnostics( char *path )
{
    node_t node;
    pthread_detach( pthread_self() );
    tr_log( LOG_DEBUG, "Start atm_diagnostics test %s", path );
    war_sleep( 10 );
    tr_log( LOG_DEBUG, "atm_dignostic test over" );
    lib_start_session();
    lib_resolve_node( path, &node );
    lib_set_value( node, "Complete" );
    lib_end_session();
    tr069_cli( "http://127.0.0.1:1234/add/event/", "code=8 DIAGNOSTICS COMPLETE&cmdkey=" );
    free( path );
    pthread_exit( 0 );
    return 0;
}

/*!
 * \brief Start the atm diagnostics
 *
 * \return N/A
 */
void lib_start_wan_atmf5loopback_diagnostics( char *path )
{
#if 1
    pthread_t id;
    pthread_create( &id, NULL, ( void * ) atm_diagnostics, path );
#endif
#if 0
    HANDLE id;
    id = CreateThread( NULL, 0, atm_diagnostics, path, 0, NULL );
#endif
#if 0
    taskSpawn( "task_ATMDIAG", 90, 0, TASK_STACK_SIZE, ( FUNCPTR ) atm_diagnostics, path, 0, 0, 0, 0, 0, 0, 0, 0 , 0 );
#endif
    return ;
}

/*!
 * \brief Stop the atm diagnostics
 *
 * \return N/A
 */
void lib_stop_wan_atmf5loopback_diagnostics( char *path )
{
    tr_log( LOG_DEBUG, "Stop atm_diagnostics test %s", path );
}

#ifdef TR157
/* Add for NSLookup diag */
static int nslookup_diagnostics()
{
    node_t node;
    pthread_detach( pthread_self() );
    tr_log( LOG_DEBUG, "Start nslookup_diagnostics test" );
    war_sleep( 10 );
    tr_log( LOG_DEBUG, "nslookup_dignostic test over" );
    lib_start_session();
    lib_resolve_node( NS_DIAGNOSTICS, &node );
    lib_set_value( node, "Complete" );
    lib_end_session();
    tr069_cli( "http://127.0.0.1:1234/add/event/", "code=8 DIAGNOSTICS COMPLETE&cmdkey=" );
    pthread_exit( 0 );
    return 0;
}

/*!
 * \brief Start the NS lookup diagnostics
 *
 * \return N/A
 */
void lib_start_nslookup_diagnostics()
{
#if 1
    pthread_t id;
    pthread_create( &id, NULL, ( void * ) nslookup_diagnostics, NULL );
#endif
#if 0
    HANDLE id;
    id = CreateThread( NULL, 0, nslookup_diagnostics, NULL, 0, NULL );
#endif
#if 0
    taskSpawn( "task_NSDIAG", 90, 0, TASK_STACK_SIZE, ( FUNCPTR ) nslookup_diagnostics, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0 );
#endif
    return ;
}

/*!
 * \brief Stop the NS lookup diagnostics
 *
 * \return N/A
 */
void lib_stop_nslookup_diagnostics()
{
    tr_log( LOG_DEBUG, "Stop nslookup_diagnostics test" );
}

/* Add for Selftest diag */
static int selftest_diagnostics()
{
    node_t node;
    pthread_detach( pthread_self() );
    tr_log( LOG_DEBUG, "Start selftest_diagnostics test" );
    war_sleep( 10 );
    tr_log( LOG_DEBUG, "selftest_dignostic test over" );
    lib_start_session();
	char sysUpTime[128] = {0};
	char cpuUsage[32] = {0};
	char memFree[128] = {0};
	char rstString[256] = {0};
	struct sysinfo info;
	memset(&info, 0, sizeof(struct sysinfo));
	sysinfo(&info);
	info.freeram /= 1024; //changed to KByte
	sprintf(memFree, "%u", info.freeram);
	getDeviceUpTime("/proc/uptime", sysUpTime);
	getCpuUsage(cpuUsage);
	sprintf(rstString, "System UP Time %ss, CPU Loading %s%%, Memory Free %sKByte", sysUpTime, cpuUsage, memFree);
	do_uci_set(DS_Results, rstString);
    //lib_resolve_node( SELF_DIAGNOSTICS, &node );
    //lib_set_value( node, "Complete" );
    do_uci_set(DS_DiagnosticsState, "Complete");
	do_uci_commit(MS);
    lib_end_session();
    //tr069_cli( "http://127.0.0.1:1234/add/event/", "code=8 DIAGNOSTICS COMPLETE&cmdkey=" );
    sentEventforDiagnostic();
	//pthread_exit( 0 ); //TODO
    return 0;
}

/*!
 * \brief Start the self test diagnostics
 *
 * \return N/A
 */
void lib_start_selftest_diagnostics()
{
#if 1
    pthread_t id;
    pthread_create( &id, NULL, ( void * ) selftest_diagnostics, NULL );
#endif
#if 0
    HANDLE id;
    id = CreateThread( NULL, 0, selftest_diagnostics, NULL, 0, NULL );
#endif
#if 0
    taskSpawn( "task_SELFDIAG", 90, 0, TASK_STACK_SIZE, ( FUNCPTR ) selftest_diagnostics, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0 );
#endif
    return ;
}

/*!
 * \brief Stop the self test diagnostics
 *
 * \return N/A
 */
void lib_stop_selftest_diagnostics()
{
    tr_log( LOG_DEBUG, "Stop selftest_diagnostics test" );
}

#endif

/*!
 * \brief Get an NIC interface's IP address
 *
 * \param inter The interface name, for example "eth0"
 * \param ip The buffer stores the interface's IP, like "1.2.3.4"
 * \param ip_len The buffer length
 */
TR_LIB_API void lib_get_interface_ip( const char *inter, char *ip, int ip_len )
{
    war_snprintf( ip, ip_len, "0.0.0.0" );
}

/*!
 * \brief Get an interface total traffic quantity in byte
 *
 * \param inter The interface name
 * \param direction TRAFFIC_OUTBOUND or TRAFFIC_INBOUNT
 *
 * \return The traffic quantity of the interface
 */
TR_LIB_API unsigned int lib_get_interface_traffic( const char *inter, int direction )
{
    static unsigned int dummy_traffic = 0;
    dummy_traffic += 30000;
    return dummy_traffic;
}

/*!
 * \brief Get session timer
 *
 * \return session timer value
 */
TR_LIB_API int lib_get_wib_session_timer()
{
    /* Time to trigger WIB */
    return 5;
}

/*!
 * \brief Get WIB server URL
 * \param wib_url The buffer which stores WIB URL
 * \param len The WIB URL buffer length
 */
TR_LIB_API int lib_get_wib_url( char *wib_url, int len )
{
    //char *mac = "000102030405";
    char *mac = "00123F3046E0";
    war_snprintf( wib_url, len, "http://172.31.0.119/wib/bootstrap?version=0&msid=%s&protocol={1}", mac );
    return 0;
}

/*!
 * \brief Get an EMSK for WIB decrypt
 *
 * \param emsk The EMSK value
 * \return Always be 0;
 */
TR_LIB_API int lib_get_emsk( char **emsk )
{
    //wib decrypt EMSK
    char *tmp = malloc( 5 );
    war_snprintf( tmp, 5, "%s", "wkss" );
    *emsk = tmp;
    return 0;
}

static int set_logic_relative_values( node_t node, char *alias )
{
#ifdef TR111
    node_t nnode;
    const char *nvalue = "false";
    char *path;
    path = lib_node2path( node );

    if( !strcmp( path, STUN_ENABLE ) ) {
        lib_resolve_node( NAT_DETECTED, &nnode );
        lib_set_value( nnode, nvalue );
    }
#endif //TR111

#ifdef ALIAS
    node_t alias_node;

    if( ( alias_node = lib_get_child( node, "Alias" ) ) != NULL ) {
        if( alias == NULL ) {
            war_snprintf( alias_node->value, sizeof( alias_node->name ), "cpe-%s", node->name );
        } else {
            war_snprintf( alias_node->value, sizeof( alias_node->name ), "%s", alias );
        }
    }
#endif //ALIAS
    return 0;
}

/*!
 * \brief uninstall DU instance
 *
 * \param instace Instance number at DU MOT
 * \param path Location of package
 * \param uuid UUID of DU
 *
 * \return 0 confirm success; others no
 */
TR_LIB_API int lib_du_uninstall( const char *cmd_key, int number, const char *uuid, const char *version, const char *ee_ref )
{
    return 0;
}

TR_LIB_API int lib_du_install( const char *cmd_key, int number, const char *uuid, const char *url, const char *ee_ref, const char *fn )
{
    return 0;
}

TR_LIB_API int lib_du_update( const char *cmd_key, int number, const char *instance_number, const char *url, const char *fn )
{
    return 0;
}

TR_LIB_API int lib_generate_dynamic_upload_file( const char *name, const char *path )
{
    /*skysoft add /s*/
    int ret = -1;
    FILE * fp_2g,*fp_5g, *fp;
    char *wifi_analysis_file = "/tmp/wifiAnalysis.log";
    char *nonewifi_analysis_file = "/tmp/noneWifiAnalysis.log";
    char buffer[8192] = {0};
    char enabled[1] = {0};
    int spectral_enabled = 0;
	
    /*skysoft add /e*/
    
    //ASKEY add/s
    if( war_strcasecmp( name, "2 Vendor Log File" ) == 0 ){
        strcpy(path,"/tmp/syslog/messages");
    }
    else if( war_strcasecmp( name, "1 Vendor Configuration File" ) == 0 ){
        system("sysupgrade -b /tmp/conf.tar.gz");
        tr_log( LOG_NOTICE, "======do backup config file================");
        strcpy(path,"/tmp/conf.tar.gz");
    }//ASKEY add/e
	/*skysoft add /s*/
    else if(war_strcasecmp( name, "X B4EEB4 WiFi Analysis File" ) == 0){
            /*get the analysis log data of the wifi include 2g and 5g*/
            /*5g*/
            system("iwpriv ath0 acsreport 1");
            sleep(17);
            if(fp_5g = popen("wifitool ath0 acsreport", "r")){
                memset(buffer,0x00,sizeof(buffer));
                fread(buffer,1,8192,fp_5g); 
            }
            if(!(fp = fopen(wifi_analysis_file,"w"))){
                return -1;
            }
            fwrite("THE CONTANT OF THE 5G\n",1,22,fp);
            fwrite(buffer,1,8192,fp);
            // fwrite("--------------------------------------------------\n",1,51,fp);

            /*2.4G*/
            system("iwpriv ath1 acsreport 1");
            sleep(5);
            if( fp_2g = popen("wifitool ath1 acsreport", "r")){
                memset(buffer,0x00,sizeof(buffer));
                fread(buffer,1,8192,fp_2g);
            }
            fwrite("THE CONTANT OF THE 2G\n",1,22,fp);
            fwrite(buffer,1,8192,fp);

            fclose(fp);
            pclose(fp_2g);
            pclose(fp_5g);
            strcpy(path,wifi_analysis_file);

    }
    else if(war_strcasecmp( name, "X B4EEB4 None WiFi Analysis File" ) == 0){	
            /*for analysis data of the none wifi*/     
            /*check the status of the nonewifi spectral analysis*/
            ret = do_uci_get("wireless.wlg.spectral_enable",enabled);
            if(ret){
                ret = do_uci_get("wireless.wla.spectral_enable",enabled);
                if(ret){
                	/*The spectral analysis module is disabled*/
                    ;
                }
            }
            if(strcmp(enabled,"1")){
                /*the 5G and 2.4G is all disabled*/
                fp = fopen(nonewifi_analysis_file,"w");
                if(fp){
                    fwrite("The \"Spectral Analysis\" is disabled,please enable it at first.",1,62,fp);
                    fclose(fp);
                }
                strcpy(path,nonewifi_analysis_file);
            }else{
                /*The 2.4G or 5G is enabled*/
                strcpy(path, "/tmp/syslog/spectral.log");
            }
    }
    else if(war_strcasecmp( name, "X B4EEB4 Reboot And Crash Log File" ) == 0){
            /*for the reboot/crash cause log  uploading*/          
            strcpy(path, "/etc/config/rebootInfo");        
    }else if(war_strcasecmp( name, "X B4EEB4 Historical Client Info Log File") == 0 ){
            strcpy(path, "/tmp/syslog/down_link_sta_log");
    }else if(war_strcasecmp( name, "X B4EEB4 Online Client Info Log File" ) == 0 ){
            strcpy(path, "/tmp/syslog/sta_info_log");
    }else if(war_strcasecmp( name, "X B4EEB4 Radio And SSID Info Log File") == 0  ){
            strcpy(path, "/tmp/syslog/radio_info_log");
    }
	else if(strcasestr(name, "4 Vendor Log File") != NULL)
	{
		char index[32] = {0};
		char pathname[256] = {0};
		char tmpvalue[256] = {0};
		int res = 0;

		sscanf(name,"%*s %*s %*s %*s %s", index);
		tr_log(LOG_DEBUG,"index[%s]",index);
		sprintf(pathname, "Device.DeviceInfo.VendorLogFile.%d.Name", atoi(index));		
		tr_log(LOG_DEBUG,"pathname[%s]",pathname);
		GET_NODE_VALUE( pathname, tmpvalue );
		tr_log(LOG_DEBUG,"tmpvalue[%s]",tmpvalue);
		strcpy(path, tmpvalue);
		tr_log(LOG_DEBUG,"path[%s]",path);
	}
	/*skysoft add/e*/
    
    return 0;
}

TR_LIB_API int lib_remove_dynamic_upload_file( const char *path )
{
    return 0;
}

TR_LIB_API unsigned int lib_schedule_download_random_time( const char *file_type, unsigned int start, unsigned int end )
{
    return start; //start immediately
}

TR_LIB_API int lib_schedule_download_confirmation( const char *cmd_key, const char *user_msg, const char *file_type, unsigned int start, unsigned int end )
{
    tr_log( LOG_NOTICE, "Download(cmd_key=%s) confirmation needed:\n------------%s-----------\nPlease confirm it through the CLI", cmd_key, user_msg );
    return 0;
}

TR_LIB_API int lib_cpe_idle()
{
    tr_log( LOG_ERROR, "CPE busy" );
    return 1;
}

TR_LIB_API int lib_get_session_count()
{
    return count;
}

