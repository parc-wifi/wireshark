/* tap.c
 * packet tap interface   2002 Ronnie Sahlberg
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include "epan/packet_info.h"
#include "epan/dfilter/dfilter.h"
#include <epan/tap.h>

static gboolean tapping_is_active=FALSE;
int num_tap_filters=0;

typedef struct _tap_dissector_t {
	struct _tap_dissector_t *next;
	char *name;
} tap_dissector_t;
static tap_dissector_t *tap_dissector_list=NULL;

/*
 * This is the list of free and used packets queued for a tap.
 * It is implemented here explicitely instead of using GLib objects
 * in order to be as fast as possible as we need to build and tear down the
 * queued list at least once for each packet we see, thus we must be able
 * to build and tear it down as fast as possible.
 */
typedef struct _tap_packet_t {
	int tap_id;
	packet_info *pinfo;
	const void *tap_specific_data;
} tap_packet_t;

#define TAP_PACKET_QUEUE_LEN 100
static tap_packet_t tap_packet_array[TAP_PACKET_QUEUE_LEN];
static guint tap_packet_index;

typedef struct _tap_listener_t {
	struct _tap_listener_t *next;
	int tap_id;
	int needs_redraw;
	dfilter_t *code;
	void *tapdata;
	tap_reset_cb reset;
	tap_packet_cb packet;
	tap_draw_cb draw;
} tap_listener_t;
static volatile tap_listener_t *tap_listener_queue=NULL;

/* structure to keep track of what tap listeners have registered
   command-line arguments.
 */
typedef struct _tap_cmd_arg {
	struct _tap_cmd_arg *next;
	const char *cmd;
	void (*func)(const char *arg);
} tap_cmd_arg;
static tap_cmd_arg *tap_cmd_arg_list=NULL;

/* structure to keep track of what taps have been specified on the
   command line.
 */
typedef struct {
	tap_cmd_arg *tca;
	char *arg;
} tap_requested;
static GSList *taps_requested = NULL;

/* **********************************************************************
 * Init routine only called from epan at application startup
 * ********************************************************************** */
/* This function is called once when ethereal starts up and is used
   to init any data structures we may need later.
*/
void
tap_init(void)
{
	tap_packet_index=0;

	return;
}

/* **********************************************************************
 * Function called from tap to register the tap's command-line argument
 * and initialization routine
 * ********************************************************************** */
void
register_tap_listener_cmd_arg(const char *cmd, void (*func)(const char *arg))
{
	tap_cmd_arg *newtca;

	newtca=g_malloc(sizeof(tap_cmd_arg));
	newtca->next=tap_cmd_arg_list;
	tap_cmd_arg_list=newtca;
	newtca->cmd=cmd;
	newtca->func=func;
}

/* **********************************************************************
 * Function called for a tap command-line argument
 * ********************************************************************** */
gboolean
process_tap_cmd_arg(char *optarg)
{
	tap_cmd_arg *tca;
	tap_requested *tr;

	for(tca=tap_cmd_arg_list;tca;tca=tca->next){
		if(!strncmp(tca->cmd,optarg,strlen(tca->cmd))){
			tr=g_malloc(sizeof (tap_requested));
			tr->tca = tca;
			tr->arg=g_strdup(optarg);
			taps_requested=g_slist_append(taps_requested, tr);
			return TRUE;
		}
	}
	return FALSE;
}

/* **********************************************************************
 * Function to list all possible tap command-line arguments
 * ********************************************************************** */
void
list_tap_cmd_args(void)
{
	tap_cmd_arg *tca;

	for(tca=tap_cmd_arg_list;tca;tca=tca->next){
		fprintf(stderr,"     %s\n",tca->cmd);
	}
}

/* **********************************************************************
 * Function to process taps requested with command-line arguments
 * ********************************************************************** */
void
start_requested_taps(void)
{
	tap_requested *tr;

	while(taps_requested){
		tr=taps_requested->data;
		(*tr->tca->func)(tr->arg);
		g_free(tr->arg);
		g_free(tr);
		taps_requested=g_slist_remove(taps_requested, tr);
	}
}

/* **********************************************************************
 * Functions called from dissector when made tappable
 * ********************************************************************** */
/* the following two functions are used from dissectors to
   1, register the ability to tap packets from this subdissector
   2, push packets encountered by the subdissector to anyone tapping
*/

/* This function registers that a dissector has the packet tap ability
   available.  The name parameter is the name of this tap and extensions can
   use open_tap(char *name,... to specify that it wants to receive packets/
   events from this tap.

   This function is only to be called once, when the dissector initializes.

   The return value from this call is later used as a parameter to the
   tap_packet(unsinged int *tap_id,...
   call so that the tap subsystem knows to which tap point this tapped
   packet is associated.
*/  
int
register_tap(const char *name)
{
	tap_dissector_t *td, *tdl;
	int i;

	td=g_malloc(sizeof(tap_dissector_t));
	td->next=NULL;
	td->name = g_strdup(name);

	if(!tap_dissector_list){
		tap_dissector_list=td;
		i=1;
	} else {
		for(i=2,tdl=tap_dissector_list;tdl->next;i++,tdl=tdl->next)
			;
		tdl->next=td;
	}
	return i;
}


/* Everytime the dissector has finished dissecting a packet (and all
   subdissectors have returned) and if the dissector has been made "tappable"
   it will push some data to everyone tapping this layer by a call
   to tap_queue_packet().
   The first parameter is the tap_id returned by the register_tap()
   call for this dissector (so the tap system can keep track of who it came
   from and who is listening to it)
   The second is the packet_info structure which many tap readers will find
   interesting.
   The third argument is specific to each tap point or NULL if no additional 
   data is available to this tap.  A tap point in say IP will probably want to
   push the IP header structure here. Same thing for TCP and ONCRPC.
  
   The pinfo and the specific pointer are what is supplied to every listener
   in the read_callback() call made to every one currently listening to this
   tap.
 
   The tap reader is responsible to know how to parse any structure pointed 
   to by the tap specific data pointer.
*/
void 
tap_queue_packet(int tap_id, packet_info *pinfo, const void *tap_specific_data)
{
	tap_packet_t *tpt;

	if(!tapping_is_active){
		return;
	}

	tpt=&tap_packet_array[tap_packet_index];
	tpt->tap_id=tap_id;
	tpt->pinfo=pinfo;
	tpt->tap_specific_data=tap_specific_data;
	tap_packet_index++;
}





/* **********************************************************************
 * Functions used by file.c to drive the tap subsystem
 * ********************************************************************** */
/* This function is used to delete/initialize the tap queue and prime an
   epan_dissect_t with all the filters for tap listeners.
   To free the tap queue, we just prepend the used queue to the free queue.
*/
void
tap_queue_init(epan_dissect_t *edt)
{
	tap_listener_t *tl;

	/* nothing to do, just return */
	if(!tap_listener_queue){
		return;
	}

	tapping_is_active=TRUE;

	tap_packet_index=0;

	/* loop over all tap listeners and build the list of all
	   interesting hf_fields */
	for(tl=(tap_listener_t *)tap_listener_queue;tl;tl=tl->next){
		if(tl->code){
			epan_dissect_prime_dfilter(edt, tl->code);
		}
	}
}

/* this function is called after a packet has been fully dissected to push the tapped
   data to all extensions that has callbacks registered.
*/
void 
tap_push_tapped_queue(epan_dissect_t *edt)
{
	tap_packet_t *tp;
	tap_listener_t *tl;
	guint i;

	/* nothing to do, just return */
	if(!tapping_is_active){
		return;
	}

	tapping_is_active=FALSE;

	/* nothing to do, just return */
	if(!tap_packet_index){
		return;
	}

	/* loop over all tap listeners and call the listener callback
	   for all packets that match the filter. */
	for(i=0;i<tap_packet_index;i++){
		for(tl=(tap_listener_t *)tap_listener_queue;tl;tl=tl->next){
			tp=&tap_packet_array[i];
			if(tp->tap_id==tl->tap_id){
				int passed=TRUE;
				if(tl->code){
					passed=dfilter_apply_edt(tl->code, edt);
				}
				if(passed && tl->packet){
					tl->needs_redraw|=tl->packet(tl->tapdata, tp->pinfo, edt, tp->tap_specific_data);
				}
			}
		}
	}
}

/* This function is called when we need to reset all tap listeners, for example
   when we open/start a new capture or if we need to rescan the packet list.
*/
void
reset_tap_listeners(void)
{
	tap_listener_t *tl;

	for(tl=(tap_listener_t *)tap_listener_queue;tl;tl=tl->next){
		if(tl->reset){
			tl->reset(tl->tapdata);
		}
		tl->needs_redraw=1;
	}

}


/* This function is called when we need to redraw all tap listeners, for example
   when we open/start a new capture or if we need to rescan the packet list.
   this one should be called from a low priority thread say once every 3 seconds
 
   If draw_all is true, redraw all aplications regardless if they have 
   changed or not.
*/
void
draw_tap_listeners(gboolean draw_all)
{
	tap_listener_t *tl;

	for(tl=(tap_listener_t *)tap_listener_queue;tl;tl=tl->next){
		if(tl->needs_redraw || draw_all){
			if(tl->draw){
				tl->draw(tl->tapdata);
			}
		}
		tl->needs_redraw=0;
	}
}



/* **********************************************************************
 * Functions used by tap to
 * 1, register that a really simple extension is available for use by
 *    ethereal. 
 * 2, start tapping from a subdissector 
 * 3, close an already open tap
 * ********************************************************************** */
/* this function will return the tap_id for the specific protocol tap
   or 0 if no such tap was found.
 */
int 
find_tap_id(const char *name)
{
	tap_dissector_t *td;
	int i;

	for(i=1,td=tap_dissector_list;td;i++,td=td->next) {
		if(!strcmp(td->name,name)){
			return i;
		}
	}
	return 0;
}

/* this function attaches the tap_listener to the named tap.
 * function returns :
 *     NULL: ok.
 * non-NULL: error, return value points to GString containing error
 *           message.
 */
GString *
register_tap_listener(const char *tapname, void *tapdata, const char *fstring, tap_reset_cb reset, tap_packet_cb packet, tap_draw_cb draw)
{
	tap_listener_t *tl;
	int tap_id;
	GString *error_string;

	tap_id=find_tap_id(tapname);
	if(!tap_id){
		error_string = g_string_new("");
		g_string_sprintf(error_string, "Tap %s not found", tapname);
		return error_string;
	}

	tl=g_malloc(sizeof(tap_listener_t));
	tl->code=NULL;
	tl->needs_redraw=1;
	if(fstring){
		if(!dfilter_compile(fstring, &tl->code)){
			error_string = g_string_new("");
			g_string_sprintf(error_string,
			    "Filter \"%s\" is invalid - %s",
			    fstring, dfilter_error_msg);
			g_free(tl);
			return error_string;
		} else {
			num_tap_filters++;
		}
	}

	tl->tap_id=tap_id;
	tl->tapdata=tapdata;
	tl->reset=reset;
	tl->packet=packet;
	tl->draw=draw;
	tl->next=(tap_listener_t *)tap_listener_queue;

	tap_listener_queue=tl;

	return NULL;
}

/* this function removes a tap listener
 */
void
remove_tap_listener(void *tapdata)
{
	tap_listener_t *tl=NULL,*tl2;

	if(!tap_listener_queue){
		return;
	}

	if(tap_listener_queue->tapdata==tapdata){
		tl=(tap_listener_t *)tap_listener_queue;
		tap_listener_queue=tap_listener_queue->next;
	} else {
		for(tl2=(tap_listener_t *)tap_listener_queue;tl2->next;tl2=tl2->next){
			if(tl2->next->tapdata==tapdata){
				tl=tl2->next;
				tl2->next=tl2->next->next;
				break;
			}
			
		}
	}

	if(tl){
		if(tl->code){
			dfilter_free(tl->code);
			num_tap_filters--;
		}
		g_free(tl);
	}

	return;
}

/*
 * Return TRUE if we have tap listeners, FALSE otherwise.
 * Checking "num_tap_filters" isn't the right way to check whether we need
 * to do any dissection in order to run taps, as not all taps necessarily
 * have filters, and "num_tap_filters" is the number of tap filters, not
 * the number of tap listeners; it's only the right way to check whether
 * we need to build a protocol tree when doing dissection.
 */
gboolean
have_tap_listeners(void)
{
	return tap_listener_queue != NULL;
}
