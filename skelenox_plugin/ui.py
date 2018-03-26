"""
    Skelenox: the collaborative IDA Pro Agent

    This file is part of Polichombr
        (c) ANSSI-FR 2018

    Description:
        This is the main form for the plugin
"""
import logging

import idaapi


from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QVBoxLayout

from .widgets import SkelNotePad
from .widgets import SkelFunctionInfos

logger = logging.getLogger(__name__)


class SkelUI(idaapi.PluginForm):
    """
        Skelenox UI is contained in a new tab widget.
    """

    def __init__(self, settings_filename):
        super(SkelUI, self).__init__()
        self.parent = None
        self.settings_filename = settings_filename

        self.notepad = None
        self.funcinfos = None
        self.tabs = None

    def OnCreate(self, form):
        logger.debug("Called UI initialization")
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def Show(self):
        options = idaapi.PluginForm.WCLS_CLOSE_LATER
        options = options | idaapi.PluginForm.WOPN_RESTORE
        options = options | idaapi.PluginForm.WCLS_SAVE
        return idaapi.PluginForm.Show(self, "Skelenox UI", options=options)

    def PopulateForm(self):
        self.tabs = QtWidgets.QTabWidget()
        layout = QVBoxLayout()
        layout.addWidget(self.tabs)

        self.notepad = SkelNotePad(self, self.settings_filename)
        self.funcinfos = SkelFunctionInfos(self, self.settings_filename)

        self.tabs.addTab(self.notepad, "Notepad")
        self.tabs.addTab(self.funcinfos, "Func Infos")

        self.parent.setLayout(layout)

    def OnClose(self, form):
        logger.debug("UI is terminating")
        self.tabs = None

    def Close(self, options=idaapi.PluginForm.WCLS_SAVE):
        idaapi.PluginForm.Close(self, options)
