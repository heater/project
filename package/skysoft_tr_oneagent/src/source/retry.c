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
 * \file retry.c
 *
 * \brief The session retry mechanism implementation of the TR069 protocol.
 */

#include <stdlib.h>


#include "log.h"
#include "retry.h"
#include "event.h"
#include "ev_sched.h"
#include "session.h"
#include "war_math.h"
#include "war_time.h"

#include "tr_lib.h"
#include "apps.h"

static int retry_count = 0;
static int retry_ipv6_count = 0; //ASKEY SH add
static int boot_retry_count = 0; /* The counter for deliver the 1 BOOT event. */
static int retrying = 0;
static float last_min_interval = 0;

static int retry_intv = 5;
static int retry_multi = 2000;
//ASKEY SH add/s
extern int try_ipv6;
extern int ipv6_exist;
extern int ipv4_exist;
//ASKEY SH add/e

static void retry_timeout( struct sched *sc );

int in_retry()
{
    return retrying;
}

/* ASKEY ADD/s*/
int get_retrycount()
{
    return retry_count;
}
/* ASKEY ADD/e*/

/*!
 * \fn inc_boot_retry_count
 * \brief Increase the boot retry counter by 1 if it is not greater than 10
 * \return N/A
 */
static void inc_boot_retry_count( void )
{
    /* TR-069 Amendent 2 Page 18, the boot retry count can not greater than 10 */
    if( boot_retry_count < 10 ) {
        boot_retry_count++;
    }
}

/*!
 * \fn inc_retry_count
 * \brief Increase the retry counter
 * \return N/A
 */
static void inc_retry_count( void )
{
    struct event *e;
    e = get_event( S_EVENT_BOOT, NULL );

    if( e ) {
        inc_boot_retry_count();
    }
	a_infinfo wandeviceinfo;
	a_infinfo wan6deviceinfo;
			
	memset(&wandeviceinfo, 0, sizeof(wandeviceinfo));
	memset(&wan6deviceinfo, 0, sizeof(wan6deviceinfo));
	getInterfaceInfo("wan", &wandeviceinfo); 
	getInterfaceInfo("wan6", &wan6deviceinfo); 
	tr_log( LOG_DEBUG, "******************* wandeviceinfo.status: %d", wandeviceinfo.status);
	tr_log( LOG_DEBUG, "******************* wan6deviceinfo.status: %d", wan6deviceinfo.status);
	
	if (wandeviceinfo.status != 0 || wan6deviceinfo.status != 0 )//Check wan status befor increase retry count.
	{
		retry_count++;
	}
}


/*!
 * \fn retry_timeout
 * \brief The callback function for retry scheduler timeout.
 * \param sc The retry scheduler.
 * \return N/A
 */
static void retry_timeout( struct sched *sc )
{
    sc->need_destroy = 1;
    retrying = 0;

	//ASKEY SH add/s
	if(ipv6_exist == 1)
	{
		if(try_ipv6 == 1)
		{
			try_ipv6 = 0;
		}
		else if(try_ipv6 == 0)
		{
			try_ipv6 = 1;
		}
	}
	//ASKEY SH add/e

    if( create_session() != 0 ) {
        retry_later();
    }
}

/*!
 * \fn retry_interval
 * \brief Calculate the time(how many seconds to wait before retry the session) to wait
 * \return N/A
 */
static int retry_interval( void )
{
    float mtpr, res;
    war_srandom( war_time( NULL ) );
    /*
     * TR069 Amendent 2 Page 18:
     * Post reboot session retry count         Wait interval range (min-max seconds)
     * #1                                      5-10
     * #2                                      10-20
     * #3                                      20-40
     * #4                                      40-80
     * #5                                      80-160
     * #6                                      160-320
     * #7                                      320-640
     * #8                                      640-1280
     * #9                                      1280-2560
     * #10 and subsequent                      2560-5120
       i = 1 << (boot_retry_count > 0 ? boot_retry_count - 1 : 0);
       res = i * 5;
       res = res + (war_random() % res);
     */
    /*
     * TR069 A3 Page 29:
     * #1 5-10          m - m.(k/1000)
     * #2 10-20             m.(k/1000) - m.(k/1000)2
     * #3 20-40             m.(k/1000)2 - .(k/1000)3
     * #4 40-80             m.(k/1000)3 -  m.(k/1000)4
     * #5 80-160            m.(k/1000)4 -  m.(k/1000)5
     * #6 160-320           m.(k/1000)5 -  m.(k/1000)6
     * #7 320-640           m.(k/1000)6 - m.(k/1000)7
     * #8 640-1280          m.(k/1000)7 - m.(k/1000)8
     * #9 1280-2560             m.(k/1000)8 - m.(k/1000)9
     * #10 and subsequent 2560-5120     m.(k/1000)9 - m.(k/1000)10
     */

    if( retry_multi < 1000 ) {
        retry_multi = 2000;
        tr_log( LOG_DEBUG, "CWMPRetryIntervalMultiplier smaller than 1000, set to 2000" );
    }
    mtpr = (float)retry_multi / 1000;

    if( boot_retry_count == 1 || retry_count == 1 ) {
        last_min_interval = retry_intv;
    }

    else if( retry_count < 11 ) {
        last_min_interval *= mtpr;
    }
    
    res = last_min_interval;
    if( ( last_min_interval * ( mtpr - 1 ) ) >= 1 ) {
        tr_log( LOG_DEBUG, "retry count %d, interval from %d to %d\n", retry_count, (int)res, (int)(res+res*(mtpr-1)) );
        res += ( war_random() % (int)( res * ( mtpr - 1 ) + 1) );
    }
    return (int)res;
}


/*!
 * \fn reset_retry_count
 * \brief Reset the retry counter after each successful session
 * \return N/A
 */
void reset_retry_count( void )
{
    retry_count = 0;
	retry_ipv6_count = 0; //ASKEY SH add
}

/*!
 * \fn get_retry_count
 * \brief Get the retry count to construct the <b>inform</b> method.
 * \return retry count
 */
int get_retry_count( void )
{
    return retry_count;
}

//ASKEY SH add/s
int get_retry_ipv6_count( void )
{
    return retry_ipv6_count;
}
//ASKEY SH add/e

/*!
 * \fn retry_later
 * \brief Retry the session. If the current session failed, call this API to retry it(after retry_interval).
 * \return N/A
 */
void retry_later( void )
{
    int ret;
    char *value;
    node_t node;
    lib_start_session();

    if( lib_resolve_node( RETRY_MULTI, &node ) == 0 ) {
        ret = lib_get_value( node, &value );

        if( ret != 0 ) {
            tr_log( LOG_ERROR, "Get %s failed, use default value", RETRY_MULTI );
        } else {
            retry_multi = atoi( value );
#ifdef CODE_DEBUG
            tr_log( LOG_DEBUG, "%s = %d", RETRY_MULTI, retry_multi );
#endif
        }

        lib_destroy_value( value );
        value = NULL;
    }

    if( lib_resolve_node( RETRY_INTERVAL, &node ) == 0 ) {
        ret = lib_get_value( node, &value );

        if( ret != 0 ) {
            tr_log( LOG_ERROR, "Get %s failed, use default value", RETRY_INTERVAL );
        } else {
            retry_intv = atoi( value );
#ifdef CODE_DEBUG
            tr_log( LOG_DEBUG, "%s = %d", RETRY_INTERVAL, retry_intv );
#endif
        }

        lib_destroy_value( value );
    }

    lib_end_session();

    if( retrying == 0 ) {
        static struct sched *retry;
		//ASKEY SH mod/s
		if(!((ipv6_exist == 1) && (ipv4_exist == 1) && (try_ipv6 == 1)))
		{
			inc_retry_count();
		}

		if((ipv6_exist == 1) && (ipv4_exist == 1) && (try_ipv6 == 1))
		{
			retry_ipv6_count++;
		}
		
		//ASKEY SH mod/e
        retry = calloc( 1, sizeof( *retry ) );

        if( retry == NULL ) {
            tr_log( LOG_ERROR, "Out of memory!" );
        } else {
            int seconds;
            /* Retry scheduler just need wait for timeout then create a new session */
            retry->type = SCHED_WAITING_TIMEOUT;
            retry->on_timeout = retry_timeout; /* Timeout callback function */
	    	/*ASKEY SH mod/s, for ACS6  -> ACS4 -> Waiting an interval  -> ACS6 #1 -> ACS4 #1 -> Waiting an interval  -> ACS6 #2 -> ACS4 #2 ->  Waiting an Interval*/
            if((ipv6_exist == 1) && (ipv4_exist == 1) && (try_ipv6 == 1))
	    	{
                seconds = 1;
	    	}
	    	else
	    	{
	        	seconds = retry_interval();
	    	}
			tr_log( LOG_DEBUG, "******************* ipv4_exist: %d", ipv4_exist);
			tr_log( LOG_DEBUG, "******************* ipv6_exist: %d", ipv6_exist);

            if((ipv6_exist == 1) && (ipv4_exist == 1))
        	{
				if(seconds != 1)
				{
					if(retry_count == 1)
					{
						seconds = last_min_interval - 3;
					}
					else
					{
						seconds = last_min_interval;
					}
				}
        	}
	    	/*ASKEY SH mod/e*/

            retry->timeout = current_time() + seconds;
            add_sched( retry );
#ifdef CODE_DEBUG
            tr_log( LOG_DEBUG, "Retry session after %d second%s", seconds, seconds > 1 ? "s" : "" );
#endif
            retrying = 1;
        }
    }
}
