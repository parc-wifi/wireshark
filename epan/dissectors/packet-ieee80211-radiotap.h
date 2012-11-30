/*
 * packet-ieee80211-radiotap.h
 *	Declarations for packet-ieee80211-radiotap.c
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copyright (C) 2012 Palo Alto Research Center Incorporated and
 * Samsung Electronics Co., Ltd.  All rights reserved.
 * Author Simon Barber
 *
 * Copied from README.developer
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

void capture_radiotap(const guchar *pd, int offset, int len, packet_counts *ld);
void proto_register_radiotap(void);
void proto_reg_handoff_radiotap(void);

struct _radiotap_info {
  guint64 ifs; /* inter frame space before this frame in us */
  guint64 start; /* start of frame in us */
  guint64 end; /* end of frame in us */
};

#define NO_TSFT 0xFFFFFFFFFFFFFFFFL
