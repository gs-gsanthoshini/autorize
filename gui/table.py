#!/usr/bin/env python
# -*- coding: utf-8 -*- 

from java.awt import Color
from java.lang import String
from java.lang import Integer
from java.lang import Runnable
from javax.swing import JTable
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import RowFilter
from javax.swing import JCheckBox
from javax.swing import GroupLayout
from javax.swing import ListSelectionModel
from java.awt.event import MouseAdapter
from java.awt.event import ItemListener
from javax.swing.table import AbstractTableModel
from javax.swing.event import ListSelectionListener

from helpers.filters import expand, collapse

class TableFilter():
    def __init__(self, extender):
        self._extender = extender

    def draw(self):
        """
        init show tab
        """

        filterLModified = JLabel("Modified:")
        filterLModified.setBounds(10, 10, 100, 30)

        filterLUnauthenticated = JLabel("Unauthenticated:")
        filterLUnauthenticated.setBounds(250, 10, 100, 30)

        self._extender.showAuthBypassModified = JCheckBox(self._extender.BYPASSSED_STR)
        self._extender.showAuthBypassModified.setBounds(10, 35, 200, 30)
        self._extender.showAuthBypassModified.setSelected(True)
        self._extender.showAuthBypassModified.addItemListener(TabTableFilter(self._extender))

        self._extender.showAuthPotentiallyEnforcedModified = JCheckBox("Is enforced???")
        self._extender.showAuthPotentiallyEnforcedModified.setBounds(10, 60, 200, 30)
        self._extender.showAuthPotentiallyEnforcedModified.setSelected(True)
        self._extender.showAuthPotentiallyEnforcedModified.addItemListener(TabTableFilter(self._extender))

        self._extender.showAuthEnforcedModified = JCheckBox(self._extender.ENFORCED_STR)
        self._extender.showAuthEnforcedModified.setBounds(10, 85, 200, 30)
        self._extender.showAuthEnforcedModified.setSelected(True)
        self._extender.showAuthEnforcedModified.addItemListener(TabTableFilter(self._extender))

        self._extender.showAuthBypassUnauthenticated = JCheckBox(self._extender.BYPASSSED_STR)
        self._extender.showAuthBypassUnauthenticated.setBounds(250, 35, 200, 30)
        self._extender.showAuthBypassUnauthenticated.setSelected(True)
        self._extender.showAuthBypassUnauthenticated.addItemListener(TabTableFilter(self._extender))

        self._extender.showAuthPotentiallyEnforcedUnauthenticated = JCheckBox("Is enforced???")
        self._extender.showAuthPotentiallyEnforcedUnauthenticated.setBounds(250, 60, 200, 30)
        self._extender.showAuthPotentiallyEnforcedUnauthenticated.setSelected(True)
        self._extender.showAuthPotentiallyEnforcedUnauthenticated.addItemListener(TabTableFilter(self._extender))

        self._extender.showAuthEnforcedUnauthenticated = JCheckBox(self._extender.ENFORCED_STR)
        self._extender.showAuthEnforcedUnauthenticated.setBounds(250, 85, 200, 30)
        self._extender.showAuthEnforcedUnauthenticated.setSelected(True)
        self._extender.showAuthEnforcedUnauthenticated.addItemListener(TabTableFilter(self._extender))

        self._extender.showDisabledUnauthenticated = JCheckBox("Disabled")
        self._extender.showDisabledUnauthenticated.setBounds(250, 110, 200, 30)
        self._extender.showDisabledUnauthenticated.setSelected(True)
        self._extender.showDisabledUnauthenticated.addItemListener(TabTableFilter(self._extender))        

        self._extender.filterPnl = JPanel()
        layout = GroupLayout(self._extender.filterPnl)
        self._extender.filterPnl.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)

        layout.setHorizontalGroup(layout.createSequentialGroup()
            .addGroup(layout.createParallelGroup()
                .addComponent(
                    filterLModified,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.showAuthBypassModified,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.showAuthPotentiallyEnforcedModified,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.showAuthEnforcedModified,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
            )
            .addGroup(layout.createParallelGroup()
                .addComponent(
                    filterLUnauthenticated,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.showAuthBypassUnauthenticated,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.showAuthPotentiallyEnforcedUnauthenticated,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.showAuthEnforcedUnauthenticated,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    self._extender.showDisabledUnauthenticated,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
            )
        )
        
        
        layout.setVerticalGroup(layout.createSequentialGroup()
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(
                    filterLModified,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
                .addComponent(
                    filterLUnauthenticated,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                    GroupLayout.PREFERRED_SIZE,
                )
            )
            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addGroup(layout.createSequentialGroup()
                    .addComponent(
                        self._extender.showAuthBypassModified,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                    .addComponent(
                        self._extender.showAuthPotentiallyEnforcedModified,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                    .addComponent(
                        self._extender.showAuthEnforcedModified,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                )
                .addGroup(layout.createSequentialGroup()
                    .addComponent(
                        self._extender.showAuthBypassUnauthenticated,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                    .addComponent(
                        self._extender.showAuthPotentiallyEnforcedUnauthenticated,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                    .addComponent(
                        self._extender.showAuthEnforcedUnauthenticated,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                    .addComponent(
                        self._extender.showDisabledUnauthenticated,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                        GroupLayout.PREFERRED_SIZE,
                    )
                )
            )
        )

class TabTableFilter(ItemListener):
    def __init__(self, extender):
        self._extender = extender

    def itemStateChanged(self, e):
        self._extender.tableSorter.sort()

class TableModel(AbstractTableModel):
    def __init__(self, extender):
        self._extender = extender

    def removeRows(self, rows):
        rows.sort(reverse=True)
        for row in rows:
            self._extender._log.pop(row)
        self.fireTableDataChanged()

    def getRowCount(self):
        try:
            return self._extender._log.size()
        except:
            return 0

    def getColumnCount(self):
        # CHANGED: Added 5 new columns for verb status codes (GET, POST, PUT, DELETE, PATCH)
        return 14  # Was 9, now 14

    def getColumnName(self, columnIndex):
        # CHANGED: Added column names for GET, POST, PUT, DELETE, PATCH
        data = ['ID','Method', 'URL', 'Orig. Len', 'Modif. Len', "Unauth. Len",
                "Authz. Status", "Unauth. Status", "GET", "POST", "PUT", "DELETE", "PATCH", "Verb Bypasses"]
        try:
            return data[columnIndex]
        except IndexError:
            return ""

    def getColumnClass(self, columnIndex):
        # CHANGED: Added String type for 5 new verb columns
        data = [Integer, String, String, Integer, Integer, Integer, String, String, 
                String, String, String, String, String, String]
        try:
            return data[columnIndex]
        except IndexError:
            return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._extender._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._id
        if columnIndex == 1:
            return logEntry._method
        if columnIndex == 2:
            return logEntry._url.toString()
        if columnIndex == 3:
            response = logEntry._originalrequestResponse.getResponse()
            return len(logEntry._originalrequestResponse.getResponse()) - self._extender._helpers.analyzeResponse(response).getBodyOffset()
        if columnIndex == 4:
            response = logEntry._requestResponse.getResponse()
            return len(logEntry._requestResponse.getResponse()) - self._extender._helpers.analyzeResponse(response).getBodyOffset()
        if columnIndex == 5:
            if logEntry._unauthorizedRequestResponse is not None:
                response = logEntry._unauthorizedRequestResponse.getResponse()
                return len(logEntry._unauthorizedRequestResponse.getResponse()) - self._extender._helpers.analyzeResponse(response).getBodyOffset()
            else:
                return 0
        if columnIndex == 6:
            return logEntry._enfocementStatus   
        if columnIndex == 7:
            return logEntry._enfocementStatusUnauthorized
        # NEW: Columns 8-12 show individual verb status codes
        if columnIndex == 8:
            # GET status
            return getattr(logEntry, '_getStatus', '')
        if columnIndex == 9:
            # POST status
            return getattr(logEntry, '_postStatus', '')
        if columnIndex == 10:
            # PUT status
            return getattr(logEntry, '_putStatus', '')
        if columnIndex == 11:
            # DELETE status
            return getattr(logEntry, '_deleteStatus', '')
        if columnIndex == 12:
            # PATCH status
            return getattr(logEntry, '_patchStatus', '')
        if columnIndex == 13:
            # Verb Bypasses summary
            if hasattr(logEntry, '_verbBypasses'):
                return logEntry._verbBypasses
            else:
                return "Testing..."
        return ""

class TableSelectionListener(ListSelectionListener):
    """Class Responsible for the multi-row deletion"""
    def __init__(self, extender):
        self._extender = extender

    def valueChanged(self, e):
        rows = [i for i in self._table.getSelectedRows()]
        self._extender.tableModel.removeRows(rows)

class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self._extender.tableModel = TableModel(extender)
        self.setModel(self._extender.tableModel)
        self.addMouseListener(Mouseclick(self._extender))
        self.getColumnModel().getColumn(0).setPreferredWidth(450)
        self.setRowSelectionAllowed(True)
        # Enables multi-row selection
        self.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)

    def prepareRenderer(self, renderer, row, col):
        comp = JTable.prepareRenderer(self, renderer, row, col)
        value = self._extender.tableModel.getValueAt(self._extender.logTable.convertRowIndexToModel(row), col)
        
        # Color coding for authorization status columns
        if col == 6 or col == 7:
            if value == self._extender.BYPASSSED_STR:
                comp.setBackground(Color(255, 153, 153))
                comp.setForeground(Color.BLACK)
            elif value == self._extender.IS_ENFORCED_STR:
                comp.setBackground(Color(255, 204, 153))
                comp.setForeground(Color.BLACK)
            elif value == self._extender.ENFORCED_STR:
                comp.setBackground(Color(204, 255, 153))
                comp.setForeground(Color.BLACK)
        
        # NEW: Color coding for individual verb columns (8-12: GET, POST, PUT, DELETE, PATCH)
        elif col >= 8 and col <= 12:
            if value and value != '':
                statusCode = str(value).strip()
                
                # Red for bypass (2xx success codes = VULNERABILITY!)
                if statusCode.startswith('200') or statusCode.startswith('201') or statusCode.startswith('202') or statusCode.startswith('204'):
                    comp.setBackground(Color(255, 100, 100))  # Bright Red
                    comp.setForeground(Color.WHITE)
                
                # Green for secure (401, 403 = properly blocked)
                elif statusCode.startswith('401') or statusCode.startswith('403'):
                    comp.setBackground(Color(144, 238, 144))  # Light Green
                    comp.setForeground(Color.BLACK)
                
                # Yellow for server errors (5xx)
                elif statusCode.startswith('500') or statusCode.startswith('502') or statusCode.startswith('503') or statusCode.startswith('504'):
                    comp.setBackground(Color(255, 255, 153))  # Yellow
                    comp.setForeground(Color.BLACK)
                
                # White for other status codes
                else:
                    comp.setBackground(Color.WHITE)
                    comp.setForeground(Color.BLACK)
            else:
                # Gray for not tested/empty
                comp.setBackground(Color(220, 220, 220))  # Light Gray
                comp.setForeground(Color(100, 100, 100))  # Dark Gray text
        
        # Color coding for Verb Bypasses summary column (13)
        elif col == 13:
            if value and value.startswith("🚨"):
                comp.setBackground(Color(255, 100, 100))
                comp.setForeground(Color.WHITE)
            elif value == "None":
                comp.setBackground(Color(200, 255, 200))
                comp.setForeground(Color.BLACK)
            else:
                comp.setBackground(Color(255, 255, 200))
                comp.setForeground(Color.BLACK)
        
        # Default coloring for other columns
        else:
            comp.setForeground(Color.BLACK)
            comp.setBackground(Color.WHITE)

        # Highlight selected rows
        selectedRows = self._extender.logTable.getSelectedRows()
        if row in selectedRows:
            comp.setBackground(Color(201, 215, 255))
            comp.setForeground(Color.BLACK)

        return comp
    
    def changeSelection(self, row, col, toggle, extend):
        # show the log entry for the selected row
        logEntry = self._extender._log.get(self._extender.logTable.convertRowIndexToModel(row))
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._originalrequestViewer.setMessage(logEntry._originalrequestResponse.getRequest(), True)
        self._extender._originalresponseViewer.setMessage(logEntry._originalrequestResponse.getResponse(), False)

        if logEntry._unauthorizedRequestResponse is not None:
            self._extender._unauthorizedrequestViewer.setMessage(logEntry._unauthorizedRequestResponse.getRequest(), True)
            self._extender._unauthorizedresponseViewer.setMessage(logEntry._unauthorizedRequestResponse.getResponse(), False)
        else:
            self._extender._unauthorizedrequestViewer.setMessage("Request disabled", True)
            self._extender._unauthorizedresponseViewer.setMessage("Response disabled", False)

        self._extender._currentlyDisplayedItem = logEntry

        if col == 3:
            collapse(self._extender, self._extender.modified_requests_tabs)
            collapse(self._extender, self._extender.unauthenticated_requests_tabs)
            expand(self._extender, self._extender.original_requests_tabs)
        elif col == 4 or col == 6:
            collapse(self._extender, self._extender.original_requests_tabs)
            collapse(self._extender, self._extender.unauthenticated_requests_tabs)
            expand(self._extender, self._extender.modified_requests_tabs)
        elif col == 5 or col == 7:
            collapse(self._extender, self._extender.original_requests_tabs)
            collapse(self._extender, self._extender.modified_requests_tabs)
            expand(self._extender, self._extender.unauthenticated_requests_tabs)
        else:
            collapse(self._extender, self._extender.original_requests_tabs)
            collapse(self._extender, self._extender.modified_requests_tabs)
            collapse(self._extender, self._extender.unauthenticated_requests_tabs)

        JTable.changeSelection(self, row, col, toggle, extend)
        return

class LogEntry:
    def __init__(self, id, requestResponse, method, url, originalrequestResponse, enforcementStatus, unauthorizedRequestResponse, enforcementStatusUnauthorized, verbBypasses="Testing..."):
        self._id = id
        self._requestResponse = requestResponse
        self._originalrequestResponse = originalrequestResponse
        self._method = method
        self._url = url
        self._enfocementStatus = enforcementStatus
        self._unauthorizedRequestResponse = unauthorizedRequestResponse
        self._enfocementStatusUnauthorized = enforcementStatusUnauthorized
        self._verbBypasses = verbBypasses
        
        # NEW: Initialize verb status code fields
        self._getStatus = ''
        self._postStatus = ''
        self._putStatus = ''
        self._deleteStatus = ''
        self._patchStatus = ''
        return

class Mouseclick(MouseAdapter):
    def __init__(self, extender):
        self._extender = extender

    def mouseReleased(self, evt):
        if evt.button == 3:
            self._extender.menu.show(evt.getComponent(), evt.getX(), evt.getY())

class TableRowFilter(RowFilter):
    def __init__(self, extender):
        self._extender = extender

    def include(self, entry):
        if self._extender.showAuthBypassModified.isSelected() and self._extender.BYPASSSED_STR == entry.getValue(6):
            return True
        elif self._extender.showAuthPotentiallyEnforcedModified.isSelected() and self._extender.IS_ENFORCED_STR == entry.getValue(6):
            return True
        elif self._extender.showAuthEnforcedModified.isSelected() and self._extender.ENFORCED_STR == entry.getValue(6):
            return True
        elif self._extender.showAuthBypassUnauthenticated.isSelected() and self._extender.BYPASSSED_STR == entry.getValue(7):
            return True
        elif self._extender.showAuthPotentiallyEnforcedUnauthenticated.isSelected() and self._extender.IS_ENFORCED_STR == entry.getValue(7):
            return True
        elif self._extender.showAuthEnforcedUnauthenticated.isSelected() and self._extender.ENFORCED_STR == entry.getValue(7):
            return True
        elif self._extender.showDisabledUnauthenticated.isSelected() and "Disabled" == entry.getValue(7):
            return True
        else:
            return False

class UpdateTableEDT(Runnable):
    def __init__(self,extender,action,firstRow,lastRow):
        self._extender=extender
        self._action=action
        self._firstRow=firstRow
        self._lastRow=lastRow

    def run(self):
        if self._action == "insert":
            self._extender.tableModel.fireTableRowsInserted(self._firstRow, self._lastRow)
        elif self._action == "update":
            self._extender.tableModel.fireTableRowsUpdated(self._firstRow, self._lastRow)
        elif self._action == "delete":
            self._extender.tableModel.fireTableRowsDeleted(self._firstRow, self._lastRow)
        else:
            print("Invalid action in UpdateTableEDT")
