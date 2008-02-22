/* column.c
 * Routines for handling column preferences
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/nstime.h>
#include <epan/dfilter/dfilter.h>
#include "cfile.h"
#include <epan/column.h>
#include <epan/packet.h>

/* Given a format number (as defined in packet.h), returns its equivalent
   string */
const gchar *
col_format_to_string(gint fmt) {
  const gchar *slist[] = {
    "%m",
    "%t",
    "%Rt",
    "%At",
    "%Yt",
    "%Tt",
    "%Gt",
    "%rct",
    "%dct",
    "%s",
    "%rs",
    "%us",
    "%hs",
    "%rhs",
    "%uhs",
    "%ns",
    "%rns",
    "%uns",
    "%d",
    "%rd",
    "%ud",
    "%hd",
    "%rhd",
    "%uhd",
    "%nd",
    "%rnd",
    "%und",
    "%S",
    "%rS",
    "%uS",
    "%D",
    "%rD",
    "%uD",
    "%p",
    "%i",
    "%L",
    "%B",
    "%XO",
    "%XR",
    "%I",
    "%c",
    "%Xs",
    "%Xd",
    "%V",
    "%x",
    "%e",
    "%H",
    "%P",
    "%y",
    "%z",
    "%q",
    "%f",
    "%U",
    "%E",
    "%C",
    "%l",
    "%a",
    "%F",
    "%Cus"
  };

  if (fmt < 0 || fmt >= NUM_COL_FMTS)
    return NULL;

  return(slist[fmt]);
}

/* Given a format number (as defined in packet.h), returns its
  description */
static const gchar *dlist[NUM_COL_FMTS] = {
	"Number",                                   /* COL_NUMBER */
	"Time (format as specified)",               /* COL_CLS_TIME */
	"Relative time",                            /* COL_REL_TIME */
	"Absolute time",                            /* COL_ABS_TIME */
	"Absolute date and time",                   /* COL_ABS_DATE_TIME */
	"Delta time",                               /* COL_DELTA_TIME */
	"Delta time displayed",                     /* COL_DELTA_TIME_DIS */
	"Relative time (conversation)",             /* COL_REL_CONV_TIME */
	"Delta time (conversation)",                /* COL_DELTA_CONV_TIME */
	"Source address",                           /* COL_DEF_SRC */
	"Src addr (resolved)",                      /* COL_RES_SRC */
	"Src addr (unresolved)",                    /* COL_UNRES_SRC */
	"Hardware src addr",                        /* COL_DEF_DL_SRC */
	"Hw src addr (resolved)",                   /* COL_RES_DL_SRC*/
	"Hw src addr (unresolved)",                 /* COL_UNRES_DL_SRC */
	"Network src addr",                         /* COL_DEF_NET_SRC */
	"Net src addr (resolved)",                  /* COL_RES_NET_SRC */
	"Net src addr (unresolved)",                /* COL_UNRES_NET_SRC */
	"Destination address",                      /* COL_DEF_DST */
	"Dest addr (resolved)",                     /* COL_RES_DST */
	"Dest addr (unresolved)",                   /* COL_UNRES_DST */
	"Hardware dest addr",                       /* COL_DEF_DL_DST */
	"Hw dest addr (resolved)",                  /* COL_RES_DL_DST */
	"Hw dest addr (unresolved)",                /* COL_UNRES_DL_DST */
	"Network dest addr",                        /* COL_DEF_NET_DST */
	"Net dest addr (resolved)",                 /* COL_RES_NET_DST */
	"Net dest addr (unresolved)",               /* COL_UNRES_NET_DST */
	"Source port",                              /* COL_DEF_SRC_PORT */
	"Src port (resolved)",                      /* COL_RES_SRC_PORT */
	"Src port (unresolved)",                    /* COL_UNRES_SRC_PORT */
	"Destination port",                         /* COL_DEF_DST_PORT */
	"Dest port (resolved)",                     /* COL_RES_DST_PORT */
	"Dest port (unresolved)",                   /* COL_UNRES_DST_PORT */
	"Protocol",                                 /* COL_PROTOCOL */
	"Information",                              /* COL_INFO */
	"Packet length (bytes)" ,                   /* COL_PACKET_LENGTH */
	"Cumulative Bytes" ,                        /* COL_CUMULATIVE_BYTES */
	"Fibre Channel OXID",                       /* COL_OXID */
	"Fibre Channel RXID",                       /* COL_RXID */
	"FW-1 monitor if/direction",                /* COL_IF_DIR */
	"Circuit ID",                               /* COL_CIRCUIT_ID */
	"Cisco Src PortIdx",                        /* COL_SRCIDX */
	"Cisco Dst PortIdx",                        /* COL_DSTIDX */
	"Cisco VSAN",                               /* COL_VSAN */
	"IEEE 802.11 TX rate",                      /* COL_TX_RATE */
	"IEEE 802.11 RSSI",                         /* COL_RSSI */
	"HP-UX Subsystem",                          /* COL_HPUX_SUBSYS */
	"HP-UX Device ID",                          /* COL_HPUX_DEVID */
	"DCE/RPC call (cn_call_id / dg_seqnum)",    /* COL_DCE_CALL */
	"DCE/RPC context ID (cn_ctx_id)",           /* COL_DCE_CTX */
	"802.1Q VLAN id",                           /* COL_8021Q_VLAN_ID */
	"IP DSCP Value",                            /* COL_DSCP_VALUE */
	"L2 COS Value (802.1p)",                    /* COL_COS_VALUE */
	"TEI",                                      /* XXX - why is it missing in column_utils.c and elsewhere? */
	"Frame Relay DLCI",                         /* COL_FR_DLCI */
	"GPRS BSSGP TLLI",                          /* COL_BSSGP_TLLI */
	"Expert Info Severity",                     /* COL_EXPERT */
	"Frequency/Channel",                        /* COL_FREQ_CHAN */
	"Custom"                                    /* COL_CUSTOM */
};

const gchar *
col_format_desc(gint fmt) {
  g_assert((fmt >= 0) && (fmt < NUM_COL_FMTS));
  return(dlist[fmt]);
}

/* Marks each array element true if it can be substituted for the given
   column format */
void
get_column_format_matches(gboolean *fmt_list, gint format) {

  /* Get the obvious: the format itself */
  if ((format >= 0) && (format < NUM_COL_FMTS))
    fmt_list[format] = TRUE;

  /* Get any formats lower down on the chain */
  switch (format) {
    case COL_DEF_SRC:
      fmt_list[COL_RES_DL_SRC] = TRUE;
      fmt_list[COL_RES_NET_SRC] = TRUE;
      break;
    case COL_RES_SRC:
      fmt_list[COL_RES_DL_SRC] = TRUE;
      fmt_list[COL_RES_NET_SRC] = TRUE;
      break;
    case COL_UNRES_SRC:
      fmt_list[COL_UNRES_DL_SRC] = TRUE;
      fmt_list[COL_UNRES_NET_SRC] = TRUE;
      break;
    case COL_DEF_DST:
      fmt_list[COL_RES_DL_DST] = TRUE;
      fmt_list[COL_RES_NET_DST] = TRUE;
      break;
    case COL_RES_DST:
      fmt_list[COL_RES_DL_DST] = TRUE;
      fmt_list[COL_RES_NET_DST] = TRUE;
      break;
    case COL_UNRES_DST:
      fmt_list[COL_UNRES_DL_DST] = TRUE;
      fmt_list[COL_UNRES_NET_DST] = TRUE;
      break;
    case COL_DEF_DL_SRC:
      fmt_list[COL_RES_DL_SRC] = TRUE;
      break;
    case COL_DEF_DL_DST:
      fmt_list[COL_RES_DL_DST] = TRUE;
      break;
    case COL_DEF_NET_SRC:
      fmt_list[COL_RES_NET_SRC] = TRUE;
      break;
    case COL_DEF_NET_DST:
      fmt_list[COL_RES_NET_DST] = TRUE;
      break;
    case COL_DEF_SRC_PORT:
      fmt_list[COL_RES_SRC_PORT] = TRUE;
      break;
    case COL_DEF_DST_PORT:
      fmt_list[COL_RES_DST_PORT] = TRUE;
      break;
    case COL_OXID:
      fmt_list[COL_OXID] = TRUE;
      break;
    case COL_RXID:
      fmt_list[COL_RXID] = TRUE;
      break;
    case COL_IF_DIR:
      fmt_list[COL_IF_DIR] = TRUE;
      break;
    case COL_CIRCUIT_ID:
      fmt_list[COL_CIRCUIT_ID] = TRUE;
      break;
    case COL_SRCIDX:
      fmt_list[COL_SRCIDX] = TRUE;
      break;
    case COL_DSTIDX:
      fmt_list[COL_DSTIDX] = TRUE;
      break;
    case COL_VSAN:
      fmt_list[COL_VSAN] = TRUE;
      break;
    case COL_TX_RATE:
      fmt_list[COL_TX_RATE] = TRUE;
      break;
    case COL_RSSI:
      fmt_list[COL_RSSI] = TRUE;
      break;
    case COL_HPUX_SUBSYS:
      fmt_list[COL_HPUX_SUBSYS] = TRUE;
      break;
    case COL_HPUX_DEVID:
      fmt_list[COL_HPUX_DEVID] = TRUE;
      break;
    case COL_DCE_CALL:
      fmt_list[COL_DCE_CALL] = TRUE;
      break;
    case COL_DCE_CTX:
      fmt_list[COL_DCE_CTX] = TRUE;
      break;
    case COL_8021Q_VLAN_ID:
      fmt_list[COL_8021Q_VLAN_ID] = TRUE;
      break;
    case COL_DSCP_VALUE:
      fmt_list[COL_DSCP_VALUE] = TRUE;
      break;
    case COL_COS_VALUE:
      fmt_list[COL_COS_VALUE] = TRUE;
      break;
    case COL_TEI:
      fmt_list[COL_TEI] = TRUE;
      break;
    case COL_FR_DLCI:
      fmt_list[COL_FR_DLCI] = TRUE;
      break;
    case COL_BSSGP_TLLI:
      fmt_list[COL_BSSGP_TLLI] = TRUE;
      break;
    case COL_EXPERT:
      fmt_list[COL_EXPERT] = TRUE;
      break;
    case COL_FREQ_CHAN:
      fmt_list[COL_FREQ_CHAN] = TRUE;
      break;
    case COL_CUSTOM:
      fmt_list[COL_CUSTOM] = TRUE;
      break;
    default:
      break;
  }
}

/* Returns a string representing the longest possible value for
   a timestamp column type. */
static const char *
get_timestamp_column_longest_string(gint type, gint precision)
{

	switch(type) {
	case(TS_ABSOLUTE_WITH_DATE):
		switch(precision) {
			case(TS_PREC_AUTO_SEC):
			case(TS_PREC_FIXED_SEC):
				return "0000-00-00 00:00:00";
				break;
			case(TS_PREC_AUTO_DSEC):
			case(TS_PREC_FIXED_DSEC):
				return "0000-00-00 00:00:00.0";
				break;
			case(TS_PREC_AUTO_CSEC):
			case(TS_PREC_FIXED_CSEC):
				return "0000-00-00 00:00:00.00";
				break;
			case(TS_PREC_AUTO_MSEC):
			case(TS_PREC_FIXED_MSEC):
				return "0000-00-00 00:00:00.000";
				break;
			case(TS_PREC_AUTO_USEC):
			case(TS_PREC_FIXED_USEC):
				return "0000-00-00 00:00:00.000000";
				break;
			case(TS_PREC_AUTO_NSEC):
			case(TS_PREC_FIXED_NSEC):
				return "0000-00-00 00:00:00.000000000";
				break;
			default:
				g_assert_not_reached();
		}
			break;
	case(TS_ABSOLUTE):
		switch(precision) {
			case(TS_PREC_AUTO_SEC):
			case(TS_PREC_FIXED_SEC):
				return "00:00:00";
				break;
			case(TS_PREC_AUTO_DSEC):
			case(TS_PREC_FIXED_DSEC):
				return "00:00:00.0";
				break;
			case(TS_PREC_AUTO_CSEC):
			case(TS_PREC_FIXED_CSEC):
				return "00:00:00.00";
				break;
			case(TS_PREC_AUTO_MSEC):
			case(TS_PREC_FIXED_MSEC):
				return "00:00:00.000";
				break;
			case(TS_PREC_AUTO_USEC):
			case(TS_PREC_FIXED_USEC):
				return "00:00:00.000000";
				break;
			case(TS_PREC_AUTO_NSEC):
			case(TS_PREC_FIXED_NSEC):
				return "00:00:00.000000000";
				break;
			default:
				g_assert_not_reached();
		}
		break;
	case(TS_RELATIVE):	/* fallthrough */
	case(TS_DELTA):
	case(TS_DELTA_DIS):
		switch(precision) {
			case(TS_PREC_AUTO_SEC):
			case(TS_PREC_FIXED_SEC):
				return "0000";
				break;
			case(TS_PREC_AUTO_DSEC):
			case(TS_PREC_FIXED_DSEC):
				return "0000.0";
				break;
			case(TS_PREC_AUTO_CSEC):
			case(TS_PREC_FIXED_CSEC):
				return "0000.00";
				break;
			case(TS_PREC_AUTO_MSEC):
			case(TS_PREC_FIXED_MSEC):
				return "0000.000";
				break;
			case(TS_PREC_AUTO_USEC):
			case(TS_PREC_FIXED_USEC):
				return "0000.000000";
				break;
			case(TS_PREC_AUTO_NSEC):
			case(TS_PREC_FIXED_NSEC):
				return "0000.000000000";
				break;
			default:
				g_assert_not_reached();
		}
		break;
	case(TS_EPOCH):
        /* This is enough to represent 2^63 (signed 64-bit integer) + fractions */
		switch(precision) {
			case(TS_PREC_AUTO_SEC):
			case(TS_PREC_FIXED_SEC):
				return "0000000000000000000";
				break;
			case(TS_PREC_AUTO_DSEC):
			case(TS_PREC_FIXED_DSEC):
				return "0000000000000000000.0";
				break;
			case(TS_PREC_AUTO_CSEC):
			case(TS_PREC_FIXED_CSEC):
				return "0000000000000000000.00";
				break;
			case(TS_PREC_AUTO_MSEC):
			case(TS_PREC_FIXED_MSEC):
				return "0000000000000000000.000";
				break;
			case(TS_PREC_AUTO_USEC):
			case(TS_PREC_FIXED_USEC):
				return "0000000000000000000.000000";
				break;
			case(TS_PREC_AUTO_NSEC):
			case(TS_PREC_FIXED_NSEC):
				return "0000000000000000000.000000000";
				break;
			default:
				g_assert_not_reached();
		}
		break;
	case(TS_NOT_SET):
		return "0000.000000";
		break;
	default:
		g_assert_not_reached();
	}

	/* never reached, satisfy compiler */
	return "";
}

/* Returns the longer string of the column title or the hard-coded width of
 * its contents for building the packet list layout. */
const gchar *
get_column_width_string(gint format, gint col)
{
	if(strlen(get_column_longest_string(format)) >
	   strlen(get_column_title(col)))
		return get_column_longest_string(format);
	else
		return get_column_title(col);
}

/* Returns a string representing the longest possible value for a
   particular column type.  See also get_column_width_string() above.

   Except for the COL...SRC and COL...DST columns, these are used
   only when a capture is being displayed while it's taking place;
   they are arguably somewhat fragile, as changes to the code that
   generates them don't cause these widths to change, but that's
   probably not too big a problem, given that the sizes are
   recomputed based on the actual data in the columns when the capture
   is done, and given that the width for COL...SRC and COL...DST columns
   is somewhat arbitrary in any case.  We should probably clean
   that up eventually, though. */
const char *
get_column_longest_string(gint format)
{
  switch (format) {
    case COL_NUMBER:
      return "0000000";
      break;
    case COL_CLS_TIME:
      return get_timestamp_column_longest_string(timestamp_get_type(), timestamp_get_precision());
      break;
    case COL_ABS_DATE_TIME:
      return get_timestamp_column_longest_string(TS_ABSOLUTE_WITH_DATE, timestamp_get_precision());
      break;
    case COL_ABS_TIME:
      return get_timestamp_column_longest_string(TS_ABSOLUTE, timestamp_get_precision());
      break;
    case COL_REL_TIME:
      return get_timestamp_column_longest_string(TS_RELATIVE, timestamp_get_precision());
      break;
    case COL_DELTA_TIME:
      return get_timestamp_column_longest_string(TS_DELTA, timestamp_get_precision());
      break;
    case COL_DELTA_TIME_DIS:
      return get_timestamp_column_longest_string(TS_DELTA_DIS, timestamp_get_precision());
      break;
    case COL_REL_CONV_TIME:	/* 'abuse' TS_RELATIVE to set the time format */
    case COL_DELTA_CONV_TIME:	/* for the conversation related time columns */
      return get_timestamp_column_longest_string(TS_RELATIVE, timestamp_get_precision());
      break;
    case COL_DEF_SRC:
    case COL_RES_SRC:
    case COL_UNRES_SRC:
    case COL_DEF_DL_SRC:
    case COL_RES_DL_SRC:
    case COL_UNRES_DL_SRC:
    case COL_DEF_NET_SRC:
    case COL_RES_NET_SRC:
    case COL_UNRES_NET_SRC:
    case COL_DEF_DST:
    case COL_RES_DST:
    case COL_UNRES_DST:
    case COL_DEF_DL_DST:
    case COL_RES_DL_DST:
    case COL_UNRES_DL_DST:
    case COL_DEF_NET_DST:
    case COL_RES_NET_DST:
    case COL_UNRES_NET_DST:
      return "00000000.000000000000"; /* IPX-style */
      break;
    case COL_DEF_SRC_PORT:
    case COL_RES_SRC_PORT:
    case COL_UNRES_SRC_PORT:
    case COL_DEF_DST_PORT:
    case COL_RES_DST_PORT:
    case COL_UNRES_DST_PORT:
      return "000000";
      break;
    case COL_PROTOCOL:
      return "Protocol";	/* not the longest, but the longest is too long */
      break;
    case COL_PACKET_LENGTH:
      return "00000";
      break;
    case COL_CUMULATIVE_BYTES:
      return "00000000";
      break;
    case COL_RXID:
    case COL_OXID:
      return "000000";
      break;
    case COL_IF_DIR:
      return "i 00000000 I";
      break;
    case COL_CIRCUIT_ID:
      return "000000";
      break;
    case COL_SRCIDX:
    case COL_DSTIDX:
      return "0000000";
      break;
    case COL_VSAN:
     return "000000";
      break;
    case COL_TX_RATE:
      return "108.0";
      break;
    case COL_RSSI:
      return "100";
      break;
    case COL_HPUX_SUBSYS:
      return "OTS9000-TRANSPORT";
      break;
    case COL_HPUX_DEVID:
      return "0000";
      break;
    case COL_DCE_CALL:
      return "0000";
      break;
    case COL_DCE_CTX:
      return "0000";
      break;
    case COL_8021Q_VLAN_ID:
      return "0000";
      break;
    case COL_DSCP_VALUE:
      return "00";
      break;
    case COL_COS_VALUE:
      return "0";
      break;
    case COL_TEI:
      return "127";
      break;
    case COL_FR_DLCI:
      return "8388608";
      break;
    case COL_BSSGP_TLLI:
      return "0xffffffff";
      break;
    case COL_EXPERT:
      return "ERROR";
      break;
    case COL_FREQ_CHAN:
      return "9999 MHz [A 999]";
      break;
    case COL_CUSTOM:
      return "0000000000";	/* not the longest, but the longest is too long */
      break;
    default: /* COL_INFO */
      return "Source port: kerberos-master  Destination port: kerberos-master";
      break;
  }
}

/* Returns the longest possible width, in characters, for a particular
   column type. */
gint
get_column_char_width(gint format)
{
  return strlen(get_column_longest_string(format));
}

gint
get_column_format(gint col) {
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  cfmt = (fmt_data *) clp->data;

  return(get_column_format_from_str(cfmt->fmt));
}

gint
get_column_format_from_str(gchar *str) {
  gint i;

  for (i = 0; i < NUM_COL_FMTS; i++) {
    if (strcmp(str, col_format_to_string(i)) == 0)
      return i;
  }
  return -1;	/* illegal */
}

gchar *
get_column_title(gint col) {
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->title);
}

gchar *
get_column_custom_field(gint col) {
  GList    *clp = g_list_nth(prefs.col_list, col);
  fmt_data *cfmt;

  cfmt = (fmt_data *) clp->data;

  return(cfmt->custom_field);
}

void
build_column_format_array(capture_file *cfile, gboolean reset_fences)
{
  int i, j;

  col_setup(&cfile->cinfo, prefs.num_cols);

  for (i = 0; i < cfile->cinfo.num_cols; i++) {
    cfile->cinfo.col_fmt[i] = get_column_format(i);
    cfile->cinfo.col_title[i] = g_strdup(get_column_title(i));
    if (cfile->cinfo.col_fmt[i] == COL_CUSTOM) {
      cfile->cinfo.col_custom_field[i] = g_strdup(get_column_custom_field(i));
    } else {
      cfile->cinfo.col_custom_field[i] = NULL;
    }
    cfile->cinfo.fmt_matx[i] = (gboolean *) g_malloc0(sizeof(gboolean) *
						     NUM_COL_FMTS);
    get_column_format_matches(cfile->cinfo.fmt_matx[i],
			      cfile->cinfo.col_fmt[i]);
    cfile->cinfo.col_data[i] = NULL;

    if (cfile->cinfo.col_fmt[i] == COL_INFO)
      cfile->cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar) *
						  COL_MAX_INFO_LEN);
    else
      cfile->cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);

    if(reset_fences)
      cfile->cinfo.col_fence[i] = 0;

    cfile->cinfo.col_expr[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
    cfile->cinfo.col_expr_val[i] = (gchar *) g_malloc(sizeof(gchar) *
						     COL_MAX_LEN);
  }

  for (i = 0; i < cfile->cinfo.num_cols; i++) {
    for (j = 0; j < NUM_COL_FMTS; j++) {
      if (!cfile->cinfo.fmt_matx[i][j])
	      continue;

      if (cfile->cinfo.col_first[j] == -1)
        cfile->cinfo.col_first[j] = i;

      cfile->cinfo.col_last[j] = i;
    }
  }
}
