/* timeline.c
 * Routines to implement a GTK2 timeline view of radiotap data
 *
 * Copyright (C) 2012 Palo Alto Research Center Incorporated and
 * Samsung Electronics Co., Ltd.  All rights reserved.
 * Author Simon Barber
 *
 * $Id$
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "string.h"

#include <stdio.h>
#include <math.h>
#include <gtk/gtk.h>
#include <glib.h>

#include "gui_utils.h"
#include "packet_list_store.h"
#include "epan/column_info.h"
#include "epan/prefs.h"
#include <epan/packet.h>
#include <epan/epan_dissect.h>
#include "../ui_util.h"
#include "../progress_dlg.h"
#include "../simple_dialog.h"
#include "../main_statusbar.h"
#include "epan/emem.h"
#include "globals.h"
#include "epan/column.h"
#include "epan/strutil.h"
#include "color.h"
#include "color_filters.h"
#include "color_utils.h"
#include "../log.h"
#include <epan/dissectors/packet-ieee80211-radiotap.h>

#ifdef HAVE_LIBPCAP
#include "../capture_ui_utils.h"
#include "../capture-pcap-util.h"
#include "../capture_ifinfo.h"
#include "../capture.h"
#include "../capture_sync.h"
#endif

/* pixels hight for rendered timeline */
#define TIMELINE_HEIGHT 16

static gint icon_width, icon_height;

static int radiotap_proto_id;
static GtkAllocation allocation; /* size of view */

/* global variable for the timelines window */
static GtkVBox *vbox;

static int active_timelines = 0;
struct timeline {
	guint64 start;
	guint64 end;
	GtkDrawingArea *draw;
	GtkLabel *left;
	GtkLabel *center;
	GtkLabel *right;
	GtkFixed *below;
	GtkWidget *selection;
	int first_packet; /* first packet displayed */
	GtkWidget *from; /* left selection arrow */
	GtkWidget *to; /* right selection arrow */
};
#define MAX_TIMELINES 16
static struct timeline timelines[MAX_TIMELINES];

static void render_pixel(GdkWindow *window, GdkGC *gc, gint x, float r, float g, float b)
{
	GdkColor color;
	const int fraction = 0.8 * 65535;
	const int base = 0.1 * 65535;
	color.red = r*fraction + base;
	color.green = g*fraction + base;
	color.blue = b*fraction + base;
	gdk_gc_set_rgb_fg_color(gc, &color);
	gdk_draw_rectangle(window, gc, TRUE,
			x, 0, 1, TIMELINE_HEIGHT);
}

static gboolean
expose_event_callback (GtkWidget *widget,
					   GdkEventExpose *event _U_,
					   struct timeline *tl)
{
	GdkWindow *window = gtk_widget_get_window(widget);
	GtkStyle *style = gtk_widget_get_style(widget);
	GdkGC *gc = style->fg_gc[gtk_widget_get_state(widget)];

	unsigned int packet;
	float zoom;
	int last_x=-1;
	float r=1.0, g=1.0, b=1.0;

	gtk_widget_get_allocation(widget, &allocation);
	zoom = ((float) allocation.width)/(tl->end - tl->start);

	/* draw the grey lines along the packet lines, and between them */
	gdk_gc_set_rgb_fg_color(gc, &WHITE);
	gdk_draw_rectangle(window, gc, TRUE, 0, 0, allocation.width, TIMELINE_HEIGHT);

	for(packet = tl->first_packet; packet < cfile.count; packet++) {
		frame_data *fdata = frame_data_sequence_find(cfile.frames, packet);
		struct _radiotap_info *ri = p_get_proto_data(fdata, radiotap_proto_id);
		float x, width;
		GdkColor color;

		x = ((gint64) (ri->start - tl->start))*zoom;

		/* is there a previous anti-aliased pixel to output */
		if (last_x >= 0 && ((int) x) != last_x) {
			/* write it out now */
			render_pixel(window, gc, last_x, r,g,b);
			last_x = -1;
			r = g = b = 1.0;
		}

		/* is this packet past the right edge of the window? */
		if (x >= allocation.width) {
			break;
		}

		width = (ri->end - ri->start)*zoom;

		/* is this packet completely to the left of the displayed area? */
		if ((x + width) < 0.0)
			continue;

		/* remember the first displayed packet */
		if (tl->first_packet < 0)
			tl->first_packet = packet;

		if (fdata->color_filter) {
			const color_filter_t *cft = fdata->color_filter;
			color_t_to_gdkcolor(&color, &cft->fg_color);
		} else {
			color.red = color.green = color.blue = 0;
		}

		// clip rectangle to left of window
		if (x < 0) {
			width += x;
			x = 0;
		}

		/* does this rectangle fit within one pixel? */
		if (((int) x) == ((int) (x+width))) {
			/* accumulate it for later rendering */
			last_x = x;
			r = r - width + width * color.red / 65535.0;
			g = g - width + width * color.green / 65535.0;
			b = b - width + width * color.blue / 65535.0;
		} else {
			/* it spans more than 1 pixel.
			 * first accumulate the part that does fit */
			float partial = ((int) x) + 1 - x;
			r = r - partial + partial * color.red / 65535.0;
			g = g - partial + partial * color.green / 65535.0;
			b = b - partial + partial * color.blue / 65535.0;
			/* and render it */
			render_pixel(window, gc, (int) x, r,g,b);
			last_x = -1;
			r = g = b = 1.0;
			x += partial;
			width -= partial;
			/* are there any whole pixels of width left to draw? */
			if (width >= 1.0) {
				gdk_gc_set_rgb_fg_color(gc, &color);
				gdk_draw_rectangle(window, gc, TRUE,
						(gint) x, 0, (gint) width, TIMELINE_HEIGHT);
				x += (int) width;
				width -= (int) width;
				/* is there a partial pixel left */
				if (width > 0.0) {
					last_x = x;
					r = r - width + width * color.red / 65535.0;
					g = g - width + width * color.green / 65535.0;
					b = b - width + width * color.blue / 65535.0;
				}
			}
		}
	}

	gdk_gc_set_rgb_fg_color(gc, &BLACK);
	return TRUE;
}

/* given an x position find which packet that corresponds to.
 * if it's inter frame space the subsequent packet is returned */
static frame_data *find_packet(struct timeline *tl, gint x)
{
	guint64 x_time = tl->start + (((float) x)*(tl->end - tl->start)/allocation.width);
	guint32 packet;

	for(packet = tl->first_packet; packet < cfile.count; packet++) {
		frame_data *fdata = frame_data_sequence_find(cfile.frames, packet);
		struct _radiotap_info *ri = p_get_proto_data(fdata, radiotap_proto_id);

		if (x_time < ri->end)
			return fdata;
	}
	return NULL;
}

static void add_timeline(guint64 start, guint64 end);

gint last_x;
int start_x = -1;

static gboolean drawing_area_button_press_callback(GtkWidget* widget _U_,
							GdkEventButton * event, struct timeline *tl _U_)
{
	last_x = start_x = event->x;
	return FALSE;
}

static inline int fround(double x) {
	return (int) (x >= 0 ? x+0.5 : x-0.5);
}

static void move_selected(struct timeline *tl, struct _radiotap_info *ri)
{
	float position = -100;

	if (ri) {
		position = ((((float) ri->start) + ri->end)/2 - tl->start)*allocation.width/(tl->end-tl->start);
		if (position < -100 || position > allocation.width + 100) {
			position = -100;
		}
	}

	gtk_fixed_move(tl->below, tl->selection, (gint) position - icon_width/2, 0);
}

void update_selection_markers(struct timeline *tl)
{
	struct timeline *next = tl+1;
	float zoom = allocation.width/(float) (tl->end - tl->start);
	gint x_from = (next->start - tl->start) * zoom;
	gint x_to = (next->end - tl->start) * zoom;

	if (x_from < 100 || x_from > allocation.width + 100)
		x_from = -100;

	if (x_to < 100 || x_to > allocation.width + 100)
		x_to = -100;

	gtk_fixed_move(tl->below, tl->from, x_from - icon_width, 0);
	gtk_fixed_move(tl->below, tl->to, x_to, 0);
}

static gboolean drawing_area_motion_callback(GtkWidget* widget,
							GdkEventMotion * event, struct timeline *tl)
{
	int moved_x = (last_x - event->x);
	float zoom = ((float) tl->end - tl->start)/(allocation.width);
	gint64 shift = moved_x * zoom;
	int clipped_shift;

	/* is button 1 down */
	if (!(event->state & GDK_BUTTON1_MASK))
		return FALSE;

	if (abs(start_x - event->x) > 1)
		start_x = -1;

	last_x = event->x;

	/* clip the movement so we can't scroll off the end */
	if (tl->start+shift < timelines[0].start) {
		shift = timelines[0].start - tl->start;
	} else if (tl->end + shift > timelines[0].end) {
		shift = timelines[0].end - tl->end;
	}

	/* convert the clipped movement back into pixels */
	clipped_shift = fround(shift / zoom);
	/* move the start/end points */
	tl->start += shift;
	tl->end += shift;

	/* scroll the pixels on the screen */
	gdk_window_scroll(gtk_widget_get_window(widget), -clipped_shift, 0);

	/* move the selected marker too */
	move_selected(tl, p_get_proto_data(cfile.current_frame, radiotap_proto_id));

	/* move any selection markers too */
	if (tl->from && !tl->to) {
		GtkAllocation alloc;
		gtk_widget_get_allocation(tl->from, &alloc);
		gtk_fixed_move(tl->below, tl->from, alloc.x-moved_x, 0);
	} else if (tl->from && tl->to) {
		update_selection_markers(tl);
	}

	/* and update the selection markers on the previous timeline */
	if (tl > timelines)
		update_selection_markers(tl-1);

	return FALSE;
}

static gboolean drawing_area_button_release_callback(GtkWidget* widget,
							GdkEventButton * event _U_, struct timeline *tl _U_)
{
	/* force a redraw to correct aliasing/rounding effects introduced by scrolling */
	gtk_widget_queue_draw(widget);

	if (start_x >= 0 && abs(start_x - event->x) <= 1) {
		/* this was a click, not a drag. */
		packet_list_select_row_from_data(find_packet(tl, start_x));
	}
	start_x = -1;

	return FALSE;
}

static GtkWidget *drag_icon = NULL;

/* callbacks for clicks on marker arrows */
static gboolean marker_button_press_callback(GtkWidget* widget,
							GdkEventButton * event, struct timeline *tl _U_)
{
printf("%s %d\n", __func__, (int) event->x);
	drag_icon = widget;
	last_x = event->x;
	return TRUE;
}

static gboolean marker_motion_callback(GtkWidget* icon,
							GdkEventMotion * event, struct timeline *tl)
{
	gint x = event->x;
	struct timeline *next = tl+1;
	float zoom = (tl->end-tl->start)/(float) allocation.width;

printf("%s %d\n", __func__, x);

	if (!(event->state & GDK_BUTTON1_MASK) || drag_icon != icon)
		return FALSE;

	/* todo: clip movement to acceptable range */

	if (icon == tl->from) {
printf("from\n");
		next->start = tl->start + zoom*x/allocation.width;
		x -= icon_width;
	} else {
printf("to\n");
		next->end = tl->start + zoom*x/allocation.width;
	}

	gtk_fixed_move(tl->below, icon, x, 0);

	gtk_widget_queue_draw((GtkWidget *) next->draw);
	/* move the selected marker too */
	move_selected(next, p_get_proto_data(cfile.current_frame, radiotap_proto_id));

	/* move any selection markers too */
	if (next->from && !next->to) {
//		GtkAllocation alloc;
//		gtk_widget_get_allocation(tl->from, &alloc);
//		gtk_fixed_move(tl->below, tl->from, alloc.x+moved_x, 0);
	} else if (next->from && next->to) {
		update_selection_markers(next);
	}

	return TRUE;
}

/* creates a left or right position marker */
static GtkWidget *create_marker(struct timeline *tl, const int which)
{
	GtkWidget *icon;
	const gchar *icon_name = which ? GTK_STOCK_GOTO_LAST : GTK_STOCK_GOTO_FIRST;

	icon = gtk_image_new_from_icon_name(icon_name, GTK_ICON_SIZE_MENU);
	gtk_widget_set_has_window(icon, TRUE);
	gtk_widget_add_events(icon, GDK_BUTTON_PRESS_MASK
							  	 | GDK_POINTER_MOTION_MASK);
	g_signal_connect(icon, "button-press-event",
			G_CALLBACK(marker_button_press_callback), tl);
	g_signal_connect(icon, "motion-notify-event",
	        G_CALLBACK(marker_motion_callback), tl);

	gtk_widget_show(icon);
	gtk_fixed_put(tl->below, icon, last_x - (which ? 0 : icon_width), 0);

	drag_icon = icon;

	return icon;
}

/* callbacks for clicks on area below the timeline */
static gboolean below_button_press_callback(GtkWidget* widget _U_,
							GdkEventButton * event, struct timeline *tl)
{
	last_x = event->x;

	if (tl->from == NULL) {
		/* first click - create new 'from' marker */
		tl->from = create_marker(tl, 0);
	} else if (tl->to == NULL) {
		/* second click - create second marker, and new timeline */
		GtkAllocation alloc;
		gint from_x;
		float left_x, right_x;

		gtk_widget_get_allocation(tl->from, &alloc);
		from_x = alloc.x + icon_width;

		if (last_x == from_x) {
			/* clicked on the same place as the first marker - ignore the click */
			return FALSE;
		}
		if (last_x > from_x) {
			tl->to = create_marker(tl, 1);
			left_x = from_x;
			right_x = last_x;
		} else {
			/* user clicked to the left of the first marker
			 * so we need to swap the markers */
			tl->to = tl->from;
			gtk_image_set_from_icon_name((GtkImage *) tl->to, GTK_STOCK_GOTO_LAST, GTK_ICON_SIZE_MENU);
			gtk_fixed_move(tl->below, tl->to, from_x, 0);

			/* and create a new marker */
			tl->from = create_marker(tl, 0);
			left_x = last_x;
			right_x = from_x;
		}

		/* create the new timeline */
		add_timeline(tl->start + (tl->end-tl->start)*left_x/allocation.width,
				tl->start + (tl->end-tl->start)*right_x/allocation.width);
	} else {
		/* both markers exist - do nothing */
		return FALSE;
	}
	return TRUE;
}


#define ui64fmt "%'llu"
static gchar *display_time(const char *prefix, guint64 microseconds)
{
	static gchar buf[128];
	gchar *str=buf+sprintf(buf, "%s\n", prefix);

	if (microseconds >= 24*60*60*1000000UL) {
		guint64 days = microseconds / (24*60*60*1000000UL);
		str += sprintf(str, ui64fmt " day%s ", days, days>1 ? "s":"");
		microseconds -= days * 24*60*60*1000000UL;
	}

	if (microseconds >= 60*60*1000000UL) {
		int hours = microseconds / (60*60*1000000UL);
		str += sprintf(str, "%'d hour%s ", hours, hours>1 ? "s":"");
		microseconds -= hours * 60*60*1000000UL;
	}

	if (microseconds >= 60*1000000UL) {
		int mins = microseconds / (60*1000000UL);
		str += sprintf(str, "%'d min%s ", mins, mins>1 ? "s":"");
		microseconds -= mins * 60*1000000UL;
	}

	if (microseconds >= 1000000) {
		sprintf(str, ui64fmt ".%06d s", microseconds / 1000000UL, (int) (microseconds % 1000000UL));
	} else if (microseconds >= 1000) {
		sprintf(str, ui64fmt ".%03d ms", microseconds / 1000UL, (int) (microseconds % 1000UL));
	} else {
		sprintf(str, ui64fmt " us", microseconds);
	}

	return buf;
}

static gboolean query_tooltip_callback(GtkDrawingArea  *draw _U_,
											gint        x,
											gint        y _U_,
											gboolean    keyboard_mode _U_,
											GtkTooltip *tooltip,
											struct timeline *tl _U_)
{
	frame_data *fdata = find_packet(tl, x);
	struct _radiotap_info *ri = p_get_proto_data(fdata, radiotap_proto_id);
	char buf[256], *ptr = buf;

	ptr += sprintf(ptr, "packet %d\nduration %s", fdata->num, display_time("", ri->end - ri->start));
	if (ri->ifs) {
		ptr += sprintf(ptr, "\nifs %d us", (int) ri->ifs);
	}
	gtk_tooltip_set_text(tooltip, buf);
	return TRUE;
}

static void add_timeline(guint64 start, guint64 end)
{
	struct timeline *tl = &timelines[active_timelines++];
	GtkVBox *vb;
	GtkHBox *hb;
	guint32 packet;

	tl->start = start;
	tl->end = end;

	/* find the first packet in this time range */
	for(packet = 1; packet < cfile.count; packet++) {
		frame_data *fdata = frame_data_sequence_find(cfile.frames, packet);
		struct _radiotap_info *ri = p_get_proto_data(fdata, radiotap_proto_id);
		if ((ri->end) >= start)
			break;
	}
	tl->first_packet = packet;

	/* vbox to contain all the timeline elements */
	vb = (GtkVBox *) gtk_vbox_new(FALSE, 0);

	/* create an hbox with the text labels in it */
	hb = (GtkHBox *) gtk_hbox_new(FALSE, 0);
	tl->left = (GtkLabel *) gtk_label_new(display_time("start", start));
	gtk_box_pack_start(GTK_BOX(hb), (GtkWidget *) tl->left, FALSE, FALSE, 4);
	tl->center = (GtkLabel *) gtk_label_new(display_time("width", end-start));
	gtk_label_set_justify(tl->center, GTK_JUSTIFY_CENTER);
	gtk_box_pack_start(GTK_BOX(hb), (GtkWidget *) tl->center, TRUE, TRUE, 0);
	tl->right = (GtkLabel *) gtk_label_new(display_time("end", end));
	gtk_label_set_justify(tl->right, GTK_JUSTIFY_RIGHT);
	gtk_box_pack_start(GTK_BOX(hb), (GtkWidget *) tl->right, FALSE, FALSE, 4);

	/* add the hbox to the timeline vbox */
	gtk_box_pack_start(GTK_BOX(vb), (GtkWidget *) hb, TRUE, TRUE, 0);

	/* create a drawing area where we will render the packets */
	tl->draw = (GtkDrawingArea *) gtk_drawing_area_new();
	gtk_widget_set_size_request((GtkWidget *) tl->draw, -1, TIMELINE_HEIGHT);
	g_signal_connect((GObject *) tl->draw, "expose_event",
						G_CALLBACK (expose_event_callback), tl);

	/* we want tooltip events, to provide tooltips */
	g_object_set((GObject *) tl->draw, "has-tooltip", TRUE, NULL);
	g_signal_connect((GObject *) tl->draw, "query-tooltip",
						G_CALLBACK (query_tooltip_callback), tl);

	/* we want mouse events, to allow selection, etc */
	gtk_widget_add_events((GtkWidget *) tl->draw,
								GDK_BUTTON_PRESS_MASK
							  | GDK_BUTTON_RELEASE_MASK
							  | GDK_POINTER_MOTION_MASK);
	g_signal_connect(tl->draw, "button-press-event",
	                    G_CALLBACK (drawing_area_button_press_callback), tl);
	g_signal_connect(tl->draw, "button-release-event",
	                    G_CALLBACK (drawing_area_button_release_callback), tl);
	g_signal_connect(tl->draw, "motion-notify-event",
	                    G_CALLBACK (drawing_area_motion_callback), tl);

	/* add the drawing area into the timeline vbox */
	gtk_box_pack_start(GTK_BOX(vb), (GtkWidget *) tl->draw, TRUE, TRUE, 0);

	/* create a selection area for the arrow pointers */
	tl->below = (GtkFixed *) gtk_fixed_new();
	gtk_fixed_set_has_window(tl->below, TRUE);
	/* we want mouse events, to allow selection, etc */
	gtk_widget_add_events((GtkWidget *) tl->below,
								GDK_BUTTON_PRESS_MASK);
	/* register these as after callbacks so clicks on the icons go to
	 * the icon's handlers first. */
	g_signal_connect_after(tl->below, "button-press-event",
	                    G_CALLBACK (below_button_press_callback), tl);

	tl->selection = gtk_image_new_from_icon_name(GTK_STOCK_GO_UP, GTK_ICON_SIZE_MENU);
	gtk_fixed_put(tl->below, tl->selection, 100, 0);
	move_selected(tl, p_get_proto_data(cfile.current_frame, radiotap_proto_id));

	gtk_box_pack_start(GTK_BOX(vb), (GtkWidget *) tl->below, TRUE, TRUE, 0);

	/* add the new timeline to the top level multiple timelines vbox */
	gtk_box_pack_start(GTK_BOX(vbox), (GtkWidget *) vb, TRUE, TRUE, 0);

	gtk_widget_show_all((GtkWidget *) vb);
}

static void
timeline_cf_cb_file_read_finished(capture_file *cf)
{
	frame_data *fdata = frame_data_sequence_find(cf->frames, 1);
	struct _radiotap_info *first, *last;

	/* move this out to main somewhere */
	gtk_widget_show((GtkWidget *) vbox);

	first = p_get_proto_data(fdata, radiotap_proto_id);

	fdata = frame_data_sequence_find(cf->frames, cf->count);
	last = p_get_proto_data(fdata, radiotap_proto_id);

	add_timeline(first->start, last->end);
}

static void packet_selected_callback(capture_file *cf)
{
	frame_data *fdata = cf->current_frame;
	struct _radiotap_info *ri = p_get_proto_data(fdata, radiotap_proto_id);
	int i;
	for (i = 0; i < active_timelines; i++)
		move_selected(&timelines[i], ri);
}

static void timeline_cf_callback(gint event, gpointer data, gpointer user_data _U_)
{
    switch(event) {
    case(cf_cb_file_closing):
        g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: Closing");
        break;
    case(cf_cb_file_closed):
        g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: Closed");
        break;
    case(cf_cb_file_read_started):
        g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: Read started");
        break;
    case(cf_cb_file_read_finished):
        g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: Read finished");
        timeline_cf_cb_file_read_finished(data);
        break;
    case(cf_cb_packet_selected):
    	packet_selected_callback((capture_file *) data);
        break;
    case(cf_cb_packet_unselected):
        break;
    case(cf_cb_field_unselected):
        break;
    case(cf_cb_file_save_started):
        g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: Save started");
        break;
    case(cf_cb_file_save_finished):
        g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: Save finished");
        break;
    case(cf_cb_file_save_stopped):
        g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: Save stopped");
        break;
    case(cf_cb_file_save_failed):
        g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: Save failed");
        break;
    default:
        g_warning("timeline_cf_callback: event %u unknown", event);
//        g_assert_not_reached();
    }
}

#ifdef HAVE_LIBPCAP
static void
timeline_capture_callback(gint event, capture_options *capture_opts _U_, gpointer user_data _U_)
{
    switch(event) {
    case(capture_cb_capture_prepared):
        g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: capture prepared");
        break;
    case(capture_cb_capture_update_started):
        g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: capture update started");
        break;
    case(capture_cb_capture_update_continue):
        /*g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: capture update continue");*/
        break;
    case(capture_cb_capture_update_finished):
        /*g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: capture update finished");*/
        break;
    case(capture_cb_capture_fixed_started):
        g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: capture fixed started");
        break;
    case(capture_cb_capture_fixed_continue):
        g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: capture fixed continue");
        break;
    case(capture_cb_capture_fixed_finished):
        g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: capture fixed finished");
        break;
    case(capture_cb_capture_stopping):
        g_log(LOG_DOMAIN_TIMELINE, G_LOG_LEVEL_DEBUG, "Callback: capture stopping");
        /* Beware: this state won't be called, if the capture child
         * closes the capturing on it's own! */
        break;
    default:
        g_warning("timeline_capture_callback: event %u unknown", event);
        g_assert_not_reached();
    }
}
#endif

void
timeline_init(void)
{
	radiotap_proto_id = proto_get_id_by_filter_name("radiotap");

	cf_callback_add(timeline_cf_callback, NULL);
#ifdef HAVE_LIBPCAP
	capture_callback_add(timeline_capture_callback, NULL);
#endif
}


GtkWidget *
timeline_create(void)
{
	gtk_icon_size_lookup(GTK_ICON_SIZE_MENU, &icon_width, &icon_height);
	vbox = (GtkVBox *) gtk_vbox_new(TRUE, 8);
	return (GtkWidget *) vbox;
}
