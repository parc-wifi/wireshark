/* packet_list.cpp
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/epan.h>
#include <epan/epan_dissect.h>

#include <epan/column_info.h>
#include <epan/column.h>
#include <epan/packet.h>

#include "packet_list.h"
#include "monospace_font.h"
#include "proto_tree.h"

#include "qt_ui_utils.h"

#include "ui/main_statusbar.h"
#include "ui/recent.h"
#include "ui/recent_utils.h"
#include "ui/ui_util.h"

#include <QTreeWidget>
#include <QTabWidget>
#include <QTextEdit>
#include <QScrollBar>

// If we ever add the ability to open multiple capture files we might be
// able to use something like QMap<capture_file *, PacketList *> to match
// capture files against packet lists and models.
static PacketList *gbl_cur_packet_list = NULL;

guint
packet_list_append(column_info *cinfo, frame_data *fdata, packet_info *pinfo)
{
    Q_UNUSED(cinfo);
    Q_UNUSED(pinfo);

    if (!gbl_cur_packet_list)
        return 0;

    /* fdata should be filled with the stuff we need
     * strings are built at display time.
     */
    guint visible_pos;

    visible_pos = gbl_cur_packet_list->packetListModel()->appendPacket(fdata);
    return visible_pos;
}

// Copied from ui/gtk/packet_list.c
void packet_list_resize_column(gint col)
{
    // xxx qtshark
//    gint col_width;
//    const gchar *long_str;

g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: packet_list_resize_column %d", col);
//    long_str = packet_list_get_widest_column_string(packetlist, col);
//    if(!long_str || strcmp("",long_str)==0)
//        /* If we get an empty string leave the width unchanged */
//        return;
//    column = gtk_tree_view_get_column (GTK_TREE_VIEW(packetlist->view), col);
//    col_width = get_default_col_size (packetlist->view, long_str);
//    gtk_tree_view_column_set_fixed_width(column, col_width);
}

void
packet_list_select_first_row(void)
{
    if (!gbl_cur_packet_list)
        return;
    gbl_cur_packet_list->goFirstPacket();
    gbl_cur_packet_list->setFocus();
}

void
packet_list_select_last_row(void)
{
    if (!gbl_cur_packet_list)
        return;
    gbl_cur_packet_list->goLastPacket();
    gbl_cur_packet_list->setFocus();
}

/*
 * Given a frame_data structure, scroll to and select the row in the
 * packet list corresponding to that frame.  If there is no such
 * row, return FALSE, otherwise return TRUE.
 */
gboolean
packet_list_select_row_from_data(frame_data *fdata_needle)
{
    int row = gbl_cur_packet_list->packetListModel()->visibleIndexOf(fdata_needle);
    if (row >= 0) {
        gbl_cur_packet_list->setCurrentIndex(gbl_cur_packet_list->packetListModel()->index(row,0));
        return TRUE;
    }

    return FALSE;
}

gboolean
packet_list_check_end(void)
{
    if (gbl_cur_packet_list) {
        QScrollBar *sb = gbl_cur_packet_list->verticalScrollBar();
        if (sb && sb->isVisible() && sb->value() == sb->maximum()) {
            return TRUE;
        }
    }
    return FALSE;
}

void
packet_list_clear(void)
{
    if (gbl_cur_packet_list) {
        gbl_cur_packet_list->clear();
    }
}

void
packet_list_enable_color(gboolean enable)
{
    if (gbl_cur_packet_list && gbl_cur_packet_list->packetListModel()) {
        gbl_cur_packet_list->packetListModel()->setColorEnabled(enable);
        gbl_cur_packet_list->update();
    }
}

void
packet_list_freeze(void)
{
    if (gbl_cur_packet_list) {
        gbl_cur_packet_list->setUpdatesEnabled(false);
    }
}

void
packet_list_thaw(void)
{
    if (gbl_cur_packet_list) {
        gbl_cur_packet_list->setUpdatesEnabled(true);
    }

    packets_bar_update();
}

void
packet_list_recreate_visible_rows(void)
{
    if (gbl_cur_packet_list && gbl_cur_packet_list->packetListModel()) {
        gbl_cur_packet_list->packetListModel()->recreateVisibleRows();
    }
}

frame_data *
packet_list_get_row_data(gint row)
{
    if (gbl_cur_packet_list && gbl_cur_packet_list->packetListModel()) {
        return gbl_cur_packet_list->packetListModel()->getRowFdata(row);
    }
    return NULL;
}

void
packet_list_moveto_end(void)
{
    if (gbl_cur_packet_list)
        gbl_cur_packet_list->goLastPacket();
}

/* Redraw the packet list *and* currently-selected detail */
void
packet_list_queue_draw(void)
{
    if (gbl_cur_packet_list)
        gbl_cur_packet_list->updateAll();
}

void
packet_list_recent_write_all(FILE *rf) {
    if (!gbl_cur_packet_list)
        return;

    gbl_cur_packet_list->writeRecent(rf);
}

#define MIN_COL_WIDTH_STR "...."

PacketList::PacketList(QWidget *parent) :
    QTreeView(parent),
    proto_tree_(NULL),
    byte_view_tab_(NULL),
    cap_file_(NULL)
{
    setItemsExpandable(FALSE);
    setRootIsDecorated(FALSE);
    setSortingEnabled(TRUE);
    setUniformRowHeights(TRUE);
    setAccessibleName("Packet list");

    packet_list_model_ = new PacketListModel(this, cap_file_);
    setModel(packet_list_model_);
    packet_list_model_->setColorEnabled(true); // We don't yet fetch color settings.
//    packet_list_model_->setColorEnabled(recent.packet_list_colorize);

    g_assert(gbl_cur_packet_list == NULL);
    gbl_cur_packet_list = this;
}

void PacketList::setProtoTree (ProtoTree *proto_tree) {
    proto_tree_ = proto_tree;

    connect(proto_tree_, SIGNAL(goToFrame(int)), this, SLOT(goToPacket(int)));
}

void PacketList::setByteViewTab (ByteViewTab *byte_view_tab) {
    byte_view_tab_ = byte_view_tab;

    connect(proto_tree_, SIGNAL(currentItemChanged(QTreeWidgetItem*,QTreeWidgetItem*)),
            byte_view_tab_, SLOT(protoTreeItemChanged(QTreeWidgetItem*)));
}

PacketListModel *PacketList::packetListModel() const {
    return packet_list_model_;
}

void PacketList::showEvent (QShowEvent *event) {
    Q_UNUSED(event);

    if (!cap_file_) return;

    for (int i = 0; i < cap_file_->cinfo.num_cols; i++) {
        int fmt, col_width;
        const char *long_str;

        fmt = get_column_format(i);
        long_str = get_column_width_string(fmt, i);
        if (long_str) {
            col_width = get_monospace_text_size(long_str, TRUE);
        } else {
            col_width = get_monospace_text_size(MIN_COL_WIDTH_STR, TRUE);
        }
        setColumnWidth(i, col_width);
    }
}

void PacketList::selectionChanged (const QItemSelection & selected, const QItemSelection & deselected) {
    QTreeView::selectionChanged(selected, deselected);

    if (!cap_file_) return;

    if (proto_tree_) {
        int row = selected.first().top();
        cf_select_packet(cap_file_, row);

        if (!cap_file_->edt && !cap_file_->edt->tree) {
            return;
        }

        proto_tree_->fillProtocolTree(cap_file_->edt->tree);
    }

    if (byte_view_tab_ && cap_file_->edt) {
        GSList *src_le;
        struct data_source *source;

        byte_view_tab_->clear();

        for (src_le = cap_file_->edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
            source = (struct data_source *)src_le->data;
            byte_view_tab_->addTab(get_data_source_name(source), get_data_source_tvb(source), cap_file_->edt->tree, proto_tree_, cap_file_->current_frame->flags.encoding);
        }
        byte_view_tab_->setCurrentIndex(0);
    }
}

// Redraw the packet list and detail
void PacketList::updateAll() {
    update();

    if (cap_file_ && selectedIndexes().length() > 0) {
        cf_select_packet(cap_file_, selectedIndexes()[0].row());
    }
}

void PacketList::clear() {
    //    packet_history_clear();
    packet_list_model_->clear();
    proto_tree_->clear();
    byte_view_tab_->clear();

    /* XXX is this correct in all cases?
     * Reset the sort column, use packetlist as model in case the list is frozen.
     */
    gbl_cur_packet_list->sortByColumn(0, Qt::AscendingOrder);
}

void PacketList::writeRecent(FILE *rf) {
    gint col, width, col_fmt;
    gchar xalign;

    fprintf (rf, "%s:", RECENT_KEY_COL_WIDTH);
    for (col = 0; col < packet_list_model_->columnCount(); col++) {
        if (col > 0) {
            fprintf (rf, ",");
        }
        col_fmt = get_column_format(col);
        if (col_fmt == COL_CUSTOM) {
            fprintf (rf, " %%Cus:%s,", get_column_custom_field(col));
        } else {
            fprintf (rf, " %s,", col_format_to_string(col_fmt));
        }
        width = columnWidth(col);
        xalign = recent_get_column_xalign (col);
        if (width == 0) {
            /* We have not initialized the packet list yet, use old values */
            width = recent_get_column_width (col);
        }
        fprintf (rf, " %d", width);
        if (xalign != COLUMN_XALIGN_DEFAULT) {
            fprintf (rf, ":%c", xalign);
        }
    }
    fprintf (rf, "\n");

}

// Slots

void PacketList::setCaptureFile(capture_file *cf)
{
    cap_file_ = cf;
    packet_list_model_->setCaptureFile(cf);
}

void PacketList::goNextPacket(void) {
    setCurrentIndex(moveCursor(MoveDown, Qt::NoModifier));
}

void PacketList::goPreviousPacket(void) {
    setCurrentIndex(moveCursor(MoveUp, Qt::NoModifier));
}

void PacketList::goFirstPacket(void) {
    setCurrentIndex(moveCursor(MoveHome, Qt::NoModifier));
}

void PacketList::goLastPacket(void) {
    setCurrentIndex(moveCursor(MoveEnd, Qt::NoModifier));
}

void PacketList::goToPacket(int packet) {
    if (packet > 0 && packet <= packet_list_model_->rowCount()) {
        setCurrentIndex(packet_list_model_->index(packet - 1, 0));
    }
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
