/* file.h
 * Definitions for file structures and routines
 *
 * $Id: file.h,v 1.18 1999/07/07 22:51:39 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __FILE_H__
#define __FILE_H__

#include <sys/types.h>
#include <sys/time.h>

#include <wtap.h>
#include <pcap.h>

typedef struct bpf_program bpf_prog;

typedef struct _capture_file {
  FILE       *fh;        /* Capture file */
  gchar      *filename;  /* filename */
  long        f_len;     /* File length */
  guint16     cd_t;      /* Capture data type */
  guint32     vers;      /* Version.  For tcpdump minor is appended to major */
  guint32     count;     /* Packet count */
  guint32     drops;     /* Dropped packets */
  guint32     esec;      /* Elapsed seconds */
  guint32     eusec;     /* Elapsed microseconds */
  guint32     snap;      /* Captured packet length */
  gchar      *iface;     /* Interface */
  gchar      *save_file; /* File that user saved capture to */
  gint        user_saved;/* Was capture file saved by user yet? */
  wtap       *wth;       /* Wiretap session */
  gchar      *dfilter;   /* Display filter string */
  gchar      *cfilter;   /* Capture filter string */
  bpf_prog    fcode;     /* Compiled capture filter program */
  GNode      *dfcode;    /* Compiled display filter program */ 
  /* XXX - I'm cheating for now. I'll hardcode 65536 here until I re-arrange
   * more header files so that ethereal.h is split up into two files, a
   * generic header and a gtk+-speficic header (or the gtk+ definitions are
   * moved to different header files) --gilbert
   */
  /*guint8      pd[MAX_PACKET_SIZE];*/  /* Packet data */
  guint8      pd[65536];  /* Packet data */
  GList      *plist;     /* Packet list */
  frame_data *cur;       /* Frame data for current list item */
  column_info  cinfo;    /* Column formatting information */
} capture_file;


/*
 * "open_cap_file()" can return:
 *
 * 0 on success;
 *
 * a positive "errno" value on an open failure;
 *
 * a negative number, indicating the type of error, on other failures.
 */
#define	OPEN_CAP_FILE_NOT_REGULAR	-1	/* not a plain file */
#define	OPEN_CAP_FILE_UNKNOWN_FORMAT	-2	/* not a capture file in a known format */

int  open_cap_file(char *, capture_file *);
void close_cap_file(capture_file *, void *, guint);
int  load_cap_file(char *, capture_file *);
int  tail_cap_file(char *, capture_file *);
/* size_t read_frame_header(capture_file *); */

void filter_packets(capture_file *);
void change_time_formats(capture_file *);

/* Moves or copies a file. Returns 0 on failure, 1 on success */
int file_mv(char *from, char *to);

/* Copies a file. Returns 0 on failure, 1 on success */
int file_cp(char *from, char *to);

char *file_open_error_message(int, int);
char *file_read_error_message(int);
char *file_write_error_message(int);

#endif /* file.h */



