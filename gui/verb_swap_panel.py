#!/usr/bin/env python
# -*- coding: utf-8 -*- 

"""
Verb Swap GUI Component
Provides UI controls for HTTP verb swapping functionality
"""

from javax.swing import JButton
from javax.swing import JComboBox
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import GroupLayout
from java.awt.event import ActionListener
from java.awt.event import ItemListener

from helpers.verb_swap import get_verb_mappings, swap_http_verb, get_verb_from_request
from authorization.authorization import checkAuthorization
from helpers.http import IHttpRequestResponseImplementation

class VerbSwapPanel():
    def __init__(self, extender):
        self._extender = extender

    def draw(self):
        """
        Initialize verb swap UI panel
        """
        verbSwapLabel = JLabel("Verb Swap:")
        verbSwapLabel.setBounds(10, 10, 100, 30)

        # Create dropdown with verb mappings
        verb_mappings = get_verb_mappings()
        mapping_strings = ["%s → %s" % (old, new) for old, new in verb_mappings]
        self._extender.verbSwapDropdown = JComboBox(mapping_strings)
        self._extender.verbSwapDropdown.setBounds(10, 35, 150, 30)

        # Create swap button
        self._extender.verbSwapButton = JButton("Swap Verb & Test")
        self._extender.verbSwapButton.setBounds(165, 35, 150, 30)
        self._extender.verbSwapButton.setEnabled(False)  # Initially disabled
        self._extender.verbSwapButton.addActionListener(VerbSwapAction(self._extender))

        # Info label
        infoLabel = JLabel("Select a request in the table to enable verb swapping")
        infoLabel.setBounds(10, 70, 400, 30)

        self._extender.verbSwapPnl = JPanel()
        self._extender.verbSwapPnl.setLayout(None)
        self._extender.verbSwapPnl.add(verbSwapLabel)
        self._extender.verbSwapPnl.add(self._extender.verbSwapDropdown)
        self._extender.verbSwapPnl.add(self._extender.verbSwapButton)
        self._extender.verbSwapPnl.add(infoLabel)

        return self._extender.verbSwapPnl


class VerbSwapAction(ActionListener):
    """
    Action listener for the Verb Swap button
    """
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        """
        Handle verb swap button click
        """
        selectedRows = self._extender.logTable.getSelectedRows()
        
        if len(selectedRows) == 0:
            return  # No request selected
        
        # Get selected mapping from dropdown
        mapping = self._extender.verbSwapDropdown.getSelectedItem()
        parts = mapping.split(" → ")
        if len(parts) != 2:
            return
        
        old_verb = parts[0].strip()
        new_verb = parts[1].strip()
        
        # Process each selected request
        for row in selectedRows:
            modelRow = self._extender.logTable.convertRowIndexToModel(row)
            logEntry = self._extender._log.get(modelRow)
            
            # Get the original request
            originalRequest = logEntry._originalrequestResponse.getRequest()
            currentVerb = get_verb_from_request(self._extender._helpers, originalRequest)
            
            # Check if the current verb matches the selected old verb
            if currentVerb == old_verb:
                # Swap the verb
                swappedRequest = swap_http_verb(
                    self._extender._helpers, 
                    originalRequest, 
                    new_verb
                )
                
                # Create new request response with swapped verb
                httpService = logEntry._originalrequestResponse.getHttpService()
                newRequestResponse = IHttpRequestResponseImplementation(
                    httpService, 
                    swappedRequest, 
                    None
                )
                
                # Send through Autorize for testing
                from authorization.authorization import send_request_to_autorize
                from thread import start_new_thread
                start_new_thread(send_request_to_autorize, (self._extender, newRequestResponse,))
