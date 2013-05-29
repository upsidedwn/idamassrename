
# FastRename
# 16/5/2013
# Chang Yin Hong
# Version 0.1
#
# TODO:
# 1. Make confirmation diff display non editable
# 2. Fix problem where diff display vanishes on copying from display
# 3. Highlight lines in diff display which have been changed
# 4. Implement proper checking for successful creation/finding of custviewers

import re
import difflib
import unicodedata
import idc
from idaapi import PluginForm
from PySide import QtGui, QtCore

HOTKEY = 'Ctrl-r'

# -----------------------------------------------------------------------
# This is an example illustrating how to use customview in Python
# The sample will allow you to open an assembly file and display it in color
# (c) Hex-Rays
# ----------------------------------------------------------------------
class asm_colorizer_t(object):
    def is_id(self, ch):
        return ch == '_' or ch.isalpha() or '0' <= ch <= '9'

    def get_identifier(self, line, x, e):
        i = x
        is_digit = line[i].isdigit()
        while i < e:
            ch = line[i]
            if not self.is_id(ch):
                if ch != '.' or not is_digit:
                    break
            i += 1
        return (i, line[x:i])

    def get_quoted_string(self, line, x, e):
        quote = line[x]
        i = x + 1
        while i < e:
            ch = line[i]
            if ch == '\\' and line[i+1] == quote:
                i += 1
            elif ch == quote:
                i += 1 # also take the quote
                break
            i += 1
        return (i, line[x:i])

    def colorize(self, lines):
        for line in lines:
            line = line.rstrip()
            if not line:
                self.add_line()
                continue
            x = 0
            e = len(line)
            s = ""
            while x < e:
                ch = line[x]
                # String?
                if ch == '"' or ch == "'":
                    x, w = self.get_quoted_string(line, x, e)
                    s += self.as_string(w)
                # Tab?
                elif ch == '\t':
                    s += ' ' * 4
                    x += 1
                # Comment?
                elif ch == ';':
                    s += self.as_comment(line[x:])
                    # Done with this line
                    break
                elif ch == '.' and x + 1 < e:
                    x, w = self.get_identifier(line, x + 1, e)
                    s += self.as_directive(ch + w)
                # Identifiers?
                elif self.is_id(ch):
                    x, w = self.get_identifier(line, x, e)
                    # Number?
                    if ch.isdigit():
                        s += self.as_num(w)
                    # Other identifier
                    else:
                        s += self.as_id(w)
                # Output as is
                else:
                    s += ch
                    x += 1
            self.add_line(s)

# -----------------------------------------------------------------------

class asmview_t(idaapi.simplecustviewer_t, asm_colorizer_t):
    def Create(self, windowname):
        # Create the customview
        if not idaapi.simplecustviewer_t.Create(self, windowname):
            return False

        self.instruction_list = idautils.GetInstructionList()
        self.instruction_list.extend(["ret"])
        self.register_list    = idautils.GetRegisterList()
        self.register_list.extend(["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"])

        self.id_close   = self.AddPopupMenu("Close")

        return True

    def add_line(self, s=None):
        if not s:
            s = ""
        self.AddLine(s)

    def as_comment(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_RPTCMT)

    def as_id(self, s):
        t = s.lower()
        if t in self.register_list:
            return idaapi.COLSTR(s, idaapi.SCOLOR_REG)
        elif t in self.instruction_list:
            return idaapi.COLSTR(s, idaapi.SCOLOR_INSN)
        else:
            return s

    def as_string(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_STRING)

    def as_num(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_NUMBER)

    def as_directive(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_KEYWORD)

    def OnPopupMenu(self, menu_id):
        """
        A context (or popup) menu item was executed.
        @param menu_id: ID previously registered with AddPopupMenu()
        @return: Boolean
        """
        if self.id_close == menu_id:
            self.Close()
            return True
        return False

    def OnDblClick(self, shift):
        curr_word = self.GetCurrentWord()
        address = idaapi.str2ea(curr_word)
        if address != idaapi.BADADDR:
            idaapi.jumpto(address)
        return True

def get_modified_name(raw_original, raw_modified):
    raw_original_list = re.split(r'[^a-zA-Z0-9_:]+', raw_original)
    raw_modified_list = re.split(r'[^a-zA-Z0-9_:]+', raw_modified)
    if len(raw_original_list) != len(raw_modified_list):
        print '[!] Differing number of words when split: \n\t"%s"\n\t"%s"' % (raw_original, raw_modified)
        return (None, None)
    for i in range(0, len(raw_original_list)):
        if raw_original_list[i] != raw_modified_list[i]:
            return (raw_original_list[i], raw_modified_list[i])
    print '[!] Unable to find a difference, this should not happen: \n\t"%s"\n\t"%s"' % (raw_original, raw_modified)
    return (None, None)

def do_diff(original_string, modified_string):
    original_list = original_string.split()
    modified_list = modified_string.split()

    if len(original_list) != len(modified_list):
        print '[!] Differing number of words when splitting original and modified text.'
        print '[!] Unable to handle this, exiting'
        return None

    modification_dict = {}
    for i in range(0, len(original_list)):
        if original_list[i].strip() != modified_list[i].strip():
            (original_name, modified_name) = get_modified_name(original_list[i], modified_list[i])
            if original_name and modified_name:
                if original_name not in modification_dict:
                    modification_dict[original_name] = modified_name
                else:
                    existing_name = modification_dict[original_name]
                    if existing_name != modified_name:
                        print '[!] Multiple modifications to the same name %s and %s' % (original_name, modified_name)
            else:
                print '[!] Unable to match name %s and %s' % (original_name, modified_name)
                #print original_list[i], modified_list[i]

    new_modification_dict = {}
    for original, modified in modification_dict.iteritems():
        if idc.LocByName(original) != idaapi.BADADDR:
            #print '%s --> %s' % (original, modified)
            new_modification_dict[original] = modified
    return new_modification_dict

def to_ascii(unicode_string):
    return unicodedata.normalize('NFKD', unicode_string).encode('ascii', 'ignore')

class DiffTableItem(QtGui.QTableWidgetItem):
    colorArray = [QtGui.QColor(200, 0, 0), QtGui.QColor(0, 150, 0)]
    textArray = ['Unselected', 'Selected']
    def __init__(self, key):
        super(DiffTableItem, self).__init__(key)
        self.selected = 0
        self.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsEditable)
        self.toggleSelectedColor()

    def toggleSelectedColor(self):
        self.selected ^= 1
        self.setData(QtCore.Qt.BackgroundRole, DiffTableItem.colorArray[self.selected])
    
    def toggleText(self):
        self.setText(DiffTableItem.textArray[self.selected])

class GlobalSymbolRenameClass(PluginForm):
    def OnCreate(self, form):
        # Get parent widget
        self.parent = self.FormToPySideWidget(form)
        self.modifiedEdit = None
        self.originalEdit = None
        self.tabs = None
        self.orgCustViewer = None
        self.modCustViewer = None
        self.diffTable = None
        self.PopulateForm()

    def DoToggleSelect(self, row, column):
        if column > 1:
            for i in range(0, 3):
                self.diffTable.item(row, i).toggleSelectedColor()
            self.diffTable.item(row, 2).toggleText()

    def ClearTable(self):
        self.diffTable.clear()

    def DoDiff(self):
        # We need to do this to convert from unicode to ascii strings that idaapi can use
        original_string = to_ascii(self.originalEdit.toPlainText())
        modified_string = to_ascii(self.modifiedEdit.toPlainText())
        # Do the actual diffing
        modification_dict = do_diff(original_string, modified_string)

        # Add lines to the output
        self.orgCustViewer.ClearLines()
        self.modCustViewer.ClearLines()

        lines = original_string.split('\n')
        self.orgCustViewer.colorize(lines)
        lines = modified_string.split('\n')
        self.modCustViewer.colorize(lines)

        self.ClearTable()
        self.diffTable.setColumnCount(3)
        self.diffTable.setRowCount(len(modification_dict))
        self.diffTable.setHorizontalHeaderLabels(['Original Symbol Name', 'Modified Symbol Name', 'Toggle Selection'])
        self.diffTable.horizontalHeader().setResizeMode(QtGui.QHeaderView.Stretch)
        try:
            self.diffTable.cellPressed.connect(self.DoToggleSelect, type = QtCore.Qt.UniqueConnection)
        except RuntimeError as e:
            # We have connected before
            pass


        row_num = 0
        for key, value in modification_dict.iteritems():
            tmp_item = DiffTableItem(key)
            self.diffTable.setItem(row_num, 0, tmp_item)
            tmp_item = DiffTableItem(value)
            self.diffTable.setItem(row_num, 1, tmp_item)
            tmp_item = DiffTableItem('Selected')
            tmp_item.setFlags(QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsUserCheckable)
            self.diffTable.setItem(row_num, 2, tmp_item)
            row_num += 1

        # Switch tabs to the result tab
        self.tabs.setCurrentIndex(1)

    def DoRename(self):
        numRows = self.diffTable.rowCount()
        sel_mod_dict = {}
        for i in range(0, numRows):
            if self.diffTable.item(i, 0).selected == 1:
                org = to_ascii(self.diffTable.item(i, 0).text())
                mod = to_ascii(self.diffTable.item(i, 1).text())
                sel_mod_dict[org] = mod

        has_error = False
        for key, value in sel_mod_dict.iteritems():
            if idc.LocByName(key) == idaapi.BADADDR:
                print '[!] Unable to rename %s to %s, symbol name not found' % (key, value)
                has_error = True
                if idc.LocByName(value) != idaapi.BADADDR:
                    print '[!] Unable to rename %s to %s, symbol name already exists' % (key, value)
                    has_error = True
        if has_error:
            print '[!] No items have been renamed'
            return False

        allretval = 1
        for key, value in sel_mod_dict.iteritems():
            address = idc.LocByName(key)
            retval = MakeNameEx(address, value, idc.SN_NOWARN)
            if not retval:
                print '[!] Failed to rename %s to %s' % (key, value)
            allretval &= retval

        # Maybe something should be done about this ie. provide some form of capability to allow renaming to be done
        if allretval:
            print '[!] Successfully renamed %d items' % len(sel_mod_dict)
        else:
            print '[!] An error was encountered while renaming items'

    def CreateContainer(self, title, layout):
        widget = QtGui.QWidget()
        widget.setWindowTitle(title)
        widget.setLayout(layout)
        return widget

    def GetByTitle(self, title):
        qapp = QtCore.QCoreApplication.instance()
        tlw = qapp.topLevelWidgets()
        for widget in tlw:
            if widget.windowTitle() == title:
                return widget

    def PopulateForm(self):
        # For tab 1 (Text input screen)
        self.originalEdit = QtGui.QTextEdit()
        originalLayout = QtGui.QVBoxLayout()
        originalLayout.addWidget(QtGui.QLabel("Original text"))
        originalLayout.addWidget(self.originalEdit)

        self.modifiedEdit = QtGui.QTextEdit()
        modifiedLayout = QtGui.QVBoxLayout()
        modifiedLayout.addWidget(QtGui.QLabel("Modified Text"))
        modifiedLayout.addWidget(self.modifiedEdit)

        combinedEditLayout = QtGui.QHBoxLayout()
        combinedEditLayout.addLayout(originalLayout)
        combinedEditLayout.addLayout(modifiedLayout)

        diffLayout = QtGui.QVBoxLayout()
        diffLayout.addLayout(combinedEditLayout)
        scanBtn = QtGui.QPushButton("Scan for modifications")
        scanBtn.setToolTip("Enumerate symbols which have been modified (this will not modify the IDB)")
        try:
            scanBtn.clicked.connect(self.DoDiff, type = QtCore.Qt.UniqueConnection)
        except RuntimeError:
            pass
        diffLayout.addWidget(scanBtn)

        # For tab 2 (Confirmation screen)
        confirmationLayoutTop = QtGui.QHBoxLayout()
        #self.orgCustViewer = idaapi.simplecustviewer_t()
        self.orgCustViewer = asmview_t()
        self.orgCustViewer.Create('OCVCOCVC')
        qorgCustViewer = self.GetByTitle('OCVCOCVC')

        #self.modCustViewer = idaapi.simplecustviewer_t()
        self.modCustViewer = asmview_t()
        self.modCustViewer.Create('MCVCMCVC')
        qmodCustViewer = self.GetByTitle('MCVCMCVC')

        confirmationLayoutTop.addWidget(qorgCustViewer)
        confirmationLayoutTop.addWidget(qmodCustViewer)

        confirmationLayout = QtGui.QVBoxLayout()
        confirmationLayout.addLayout(confirmationLayoutTop)
        self.diffTable = QtGui.QTableWidget()
        confirmationLayout.addWidget(self.diffTable)
        confBtn = QtGui.QPushButton("Rename selected symbols")
        confBtn.setToolTip("Confirm the rename of the selected symbols (this will modify your IDB!)")
        try:
            confBtn.clicked.connect(self.DoRename, type = QtCore.Qt.UniqueConnection)
        except RuntimeError:
            pass
        confirmationLayout.addWidget(confBtn)

        # Implement check for None/Errors here
        #print qorgCustViewer, qmodCustViewer

        diffContainer = self.CreateContainer('Input', diffLayout)
        confirmationContainer = self.CreateContainer('Confirmation', confirmationLayout)

        tabWidget = QtGui.QTabWidget()
        tabWidget.addTab(diffContainer, 'Input')
        tabWidget.addTab(confirmationContainer, 'Detected Modifications')
        self.tabs = tabWidget

        mainLayout = QtGui.QVBoxLayout()
        mainLayout.addWidget(tabWidget)
        self.parent.setLayout(mainLayout)

    def OnClose(self, form):
        self.ClearTable()
        if self.orgCustViewer:
            self.orgCustViewer.Show()
            self.orgCustViewer.Close()
        if self.modCustViewer:
            self.modCustViewer.Show()
            self.modCustViewer.Close()

def main():
    gsrc = GlobalSymbolRenameClass()
    gsrc.Show("Mass Rename")

if __name__ == "__main__":
    idaapi.CompileLine('static __MassRename() { RunPythonStatement("main()"); }')
    idc.AddHotkey(HOTKEY, '__MassRename')

