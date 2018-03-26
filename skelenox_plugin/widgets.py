"""
    Skelenox: the collaborative IDA Pro Agent

    This file is part of Polichombr
        (c) ANSSI-FR 2018

    Description:
        Implements the UI widgets
"""

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QVBoxLayout

import idc
import idaapi

from .config import SkelConfig
from .connection import SkelIDAConnection


class SkelNotePad(QtWidgets.QWidget):
    """
        Abstract edit widget
    """
    skel_conn = None
    skel_settings = None
    editor = None

    def __init__(self, parent, settings_filename):
        super(SkelNotePad, self).__init__()

        self.skel_settings = SkelConfig(settings_filename)

        self.skel_conn = SkelIDAConnection(self.skel_settings)
        self.skel_conn.get_online()

        self.counter = 0
        self.editor = None
        self.PopulateForm()

    def PopulateForm(self):
        layout = QVBoxLayout()
        label = QtWidgets.QLabel()
        label.setText("Notes about sample %s" % idc.retrieve_input_file_md5())

        self.editor = QtWidgets.QTextEdit()

        self.editor.setFontFamily(self.skel_settings.notepad_font_name)
        self.editor.setFontPointSize(self.skel_settings.notepad_font_size)

        text = self.skel_conn.get_abstract()
        self.editor.setPlainText(text)

        # editor.setAutoFormatting(QtWidgets.QTextEdit.AutoAll)
        self.editor.textChanged.connect(self._OnTextChange)

        layout.addWidget(label)
        layout.addWidget(self.editor)
        self.setLayout(layout)

    def _OnTextChange(self):
        """
        Push the abstract every 10 changes
        """
        self.counter += 1
        remote_text = self.skel_conn.get_abstract()
        if remote_text is None:
            remote_text = ""
        diff_len = len(self.editor.toPlainText())
        diff_len -= len(remote_text)
        text = self.editor.toPlainText()
        self.skel_conn.push_abstract(text)
        self.counter = 0


class SkelFunctionInfosList(QtWidgets.QTableWidget):
    """
        Simple list widget to display proposed names
    """
    ADDR_COLINDEX = 0
    CURNAME_COLINDEX = 1
    MACHOC_COLINDEX = 2
    PNAME_COLINDEX = 3

    class SkelFuncListItem(object):
        def __init__(self,
                     address=None,
                     curname=None,
                     machoc=None,
                     proposed=None):
            self.address = address
            self.curname = curname
            self.machoc = machoc
            self.proposed = proposed

        def get_widgets(self):
            widgets = {}
            widgets["address"] = QtWidgets.QTableWidgetItem(self.address)
            widgets["curname"] = QtWidgets.QTableWidgetItem(self.curname)
            widgets["machoc"] = QtWidgets.QTableWidgetItem(self.machoc)
            widgets["proposed"] = QtWidgets.QTableWidgetItem(self.proposed)

            return widgets

    def __init__(self, settings_filename):
        super(SkelFunctionInfosList, self).__init__()

        self.config = SkelConfig(settings_filename)
        self.skel_conn = SkelIDAConnection(self.config)
        self.skel_conn.get_online()

    def showEvent(self, event):
        super(SkelFunctionInfosList, self).showEvent(event)
        self.init_table()
        self.populate_table()

    def extract_names(self, ranges):
        renames = []
        for rows in ranges:
            for row in range(rows.topRow(), rows.bottomRow()+1):
                addr = self.item(row, self.ADDR_COLINDEX).text()
                name = self.item(row, self.PNAME_COLINDEX).text()
                renames.append({"addr": int(addr, 16),
                                "name": name.encode("ascii")})
        return renames

    def import_names(self, ranges):
        renames = self.extract_names(ranges)
        for new_name in renames:
            idaapi.set_name(new_name["addr"],
                            new_name["name"],
                            idaapi.SN_AUTO)

    def contextMenuEvent(self, event):
        """
            Two supported actions:
                - Refresh (get a new list of proposed names)
                - Import (rename selected subs with the proposed names)
        """
        menu = QtWidgets.QMenu(self)
        import_action = menu.addAction("Import selection in database")
        refresh_action = menu.addAction("Refresh from server")
        action = menu.exec_(self.mapToGlobal(event.pos()))
        if action == import_action:
            ranges = self.selectedRanges()
            self.import_names(ranges)
        elif action == refresh_action:
            self.clearContents()
            self.populate_table()

    def init_table(self):
        """
        Set the initial header
        """
        self.setColumnCount(4)
        self.setRowCount(1)
        labels = ["Address", "Current Name", "machoc", "proposed name"]
        self.setHorizontalHeaderLabels(labels)

    def add_items_to_table(self, items):
        for item_index, item in enumerate(items):
            widgets = item.get_widgets()
            self.setItem(item_index,
                         self.ADDR_COLINDEX,
                         widgets["address"])
            self.setItem(item_index,
                         self.CURNAME_COLINDEX,
                         widgets["curname"])
            self.setItem(item_index,
                         self.MACHOC_COLINDEX,
                         widgets["machoc"])
            self.setItem(item_index,
                         self.PNAME_COLINDEX,
                         widgets["proposed"])

    def populate_table(self):
        """
            Download the list of proposed names and display it
        """
        functions = self.skel_conn.get_proposed_names()
        items = []
        for func in functions:
            func_name = idc.get_name(func["address"])
            for name in func["proposed_names"]:
                item = self.SkelFuncListItem(
                    hex(func["address"]),
                    func_name,
                    hex(func["machoc_hash"]),
                    name)
                items.append(item)
        self.setRowCount(len(items))
        self.add_items_to_table(items)


class SkelFunctionInfos(QtWidgets.QWidget):
    """
        Widgets that displays machoc names for the current sample
    """
    skel_settings = None
    funcinfos_table = None

    def __init__(self, parent, settings_filename):
        super(SkelFunctionInfos, self).__init__()
        self.skel_settings = SkelConfig(settings_filename)
        self.settings_filename = settings_filename
        self.PopulateForm()

    def PopulateForm(self):
        layout = QVBoxLayout()
        label = QtWidgets.QLabel()
        label.setText("Proposed function names for sample %s" %
                      idc.retrieve_input_file_md5())

        self.funcinfos_table = SkelFunctionInfosList(self.settings_filename)

        layout.addWidget(label)
        layout.addWidget(self.funcinfos_table)
        self.setLayout(layout)
