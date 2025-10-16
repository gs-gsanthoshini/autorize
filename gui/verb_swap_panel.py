#!/usr/bin/env python
# -*- coding: utf-8 -*- 

from javax.swing import JButton, JCheckBox, JLabel, JPanel, JTextArea, JScrollPane, BorderFactory
from java.awt import Color
from java.awt.event import ActionListener, ItemListener
from helpers.verb_swap import swap_http_verb, get_verb_from_request
from helpers.http import IHttpRequestResponseImplementation
from thread import start_new_thread

class VerbSwapPanel():
    def __init__(self, extender):
        self._extender = extender
        self._extender.autoVerbSwapEnabled = False
        self._extender.verbSwapStats = {'total_tested': 0, 'bypasses_found': 0, 'status_200': 0, 'status_403': 0, 'status_401': 0, 'status_500': 0, 'status_other': 0}

    def draw(self):
        titleLabel = JLabel("<html><b>Automatic Verb Swap Configuration (IMPROVED)</b></html>")
        titleLabel.setBounds(10, 10, 500, 30)
        self._extender.autoVerbSwapCheckbox = JCheckBox("Auto Verb Swap (Test all methods automatically)")
        self._extender.autoVerbSwapCheckbox.setBounds(10, 50, 500, 30)
        self._extender.autoVerbSwapCheckbox.addItemListener(AutoVerbSwapToggle(self._extender))
        verbsLabel = JLabel("HTTP Methods to Test:")
        verbsLabel.setBounds(10, 90, 200, 30)
        self._extender.testGET = JCheckBox("GET")
        self._extender.testGET.setSelected(True)
        self._extender.testGET.setBounds(10, 120, 80, 30)
        self._extender.testPOST = JCheckBox("POST")
        self._extender.testPOST.setSelected(True)
        self._extender.testPOST.setBounds(100, 120, 80, 30)
        self._extender.testPUT = JCheckBox("PUT")
        self._extender.testPUT.setSelected(True)
        self._extender.testPUT.setBounds(190, 120, 80, 30)
        self._extender.testDELETE = JCheckBox("DELETE")
        self._extender.testDELETE.setSelected(True)
        self._extender.testDELETE.setBounds(280, 120, 100, 30)
        self._extender.testPATCH = JCheckBox("PATCH")
        self._extender.testPATCH.setSelected(True)
        self._extender.testPATCH.setBounds(390, 120, 100, 30)
        self._extender.testAllVerbsButton = JButton("Test All Requests with All Verbs")
        self._extender.testAllVerbsButton.setBounds(10, 160, 250, 35)
        self._extender.testAllVerbsButton.addActionListener(TestAllVerbsAction(self._extender))
        self._extender.clearVerbSwapButton = JButton("Clear Verb Swap Results")
        self._extender.clearVerbSwapButton.setBounds(270, 160, 220, 35)
        self._extender.clearVerbSwapButton.addActionListener(ClearVerbSwapAction(self._extender))
        self._extender.verbSwapStatusLabel = JLabel("Status: Ready (Analytics auto-filtered)")
        self._extender.verbSwapStatusLabel.setBounds(10, 205, 600, 30)
        statsLabel = JLabel("<html><b>Verb Swap Statistics:</b></html>")
        statsLabel.setBounds(10, 245, 200, 30)
        self._extender.verbSwapStatsArea = JTextArea()
        self._extender.verbSwapStatsArea.setEditable(False)
        self._extender.verbSwapStatsArea.setBounds(10, 275, 600, 150)
        self._extender.verbSwapStatsArea.setBorder(BorderFactory.createLineBorder(Color.GRAY))
        self.updateStatsDisplay()
        scrollStats = JScrollPane(self._extender.verbSwapStatsArea)
        scrollStats.setBounds(10, 275, 600, 150)
        instructionsText = "IMPROVED VERSION Features:\n1. Enable Auto Verb Swap to test all HTTP methods\n2. Analytics domains are AUTO-SKIPPED\n3. Detailed logging in Output tab\n4. Statistics count ALL tests\n5. Progress indicators show Testing 1/4 2/4\n6. Results: Red=Bypass Green=Secure Yellow=Skipped\n\nCheck Output tab for logs"
        instructionsArea = JTextArea(instructionsText)
        instructionsArea.setEditable(False)
        instructionsArea.setWrapStyleWord(True)
        instructionsArea.setLineWrap(True)
        instructionsArea.setBackground(Color(245, 245, 245))
        instructionsArea.setBounds(10, 435, 600, 120)
        instructionsArea.setBorder(BorderFactory.createLineBorder(Color.GRAY))
        scrollInstructions = JScrollPane(instructionsArea)
        scrollInstructions.setBounds(10, 435, 600, 120)
        self._extender.verbSwapPnl = JPanel()
        self._extender.verbSwapPnl.setLayout(None)
        self._extender.verbSwapPnl.add(titleLabel)
        self._extender.verbSwapPnl.add(self._extender.autoVerbSwapCheckbox)
        self._extender.verbSwapPnl.add(verbsLabel)
        self._extender.verbSwapPnl.add(self._extender.testGET)
        self._extender.verbSwapPnl.add(self._extender.testPOST)
        self._extender.verbSwapPnl.add(self._extender.testPUT)
        self._extender.verbSwapPnl.add(self._extender.testDELETE)
        self._extender.verbSwapPnl.add(self._extender.testPATCH)
        self._extender.verbSwapPnl.add(self._extender.testAllVerbsButton)
        self._extender.verbSwapPnl.add(self._extender.clearVerbSwapButton)
        self._extender.verbSwapPnl.add(self._extender.verbSwapStatusLabel)
        self._extender.verbSwapPnl.add(statsLabel)
        self._extender.verbSwapPnl.add(scrollStats)
        self._extender.verbSwapPnl.add(scrollInstructions)
        return self._extender.verbSwapPnl

    def updateStatsDisplay(self):
        stats = self._extender.verbSwapStats
        if stats['total_tested'] > 0:
            bypass_percentage = (float(stats['bypasses_found']) / float(stats['total_tested'])) * 100
        else:
            bypass_percentage = 0.0
        statsText = "\nTotal Verb Tests: %d\nBypasses Found: %d (%.1f%%)\n\nStatus Code Breakdown:\n 200 OK: %d\n 403 Forbidden: %d\n 401 Unauthorized: %d\n 500 Server Error: %d\n Other: %d\n\nNote: Statistics count EVERY verb test\nCheck Output tab for logs" % (stats['total_tested'], stats['bypasses_found'], bypass_percentage, stats['status_200'], stats['status_403'], stats['status_401'], stats['status_500'], stats['status_other'])
        self._extender.verbSwapStatsArea.setText(statsText)

class AutoVerbSwapToggle(ItemListener):
    def __init__(self, extender):
        self._extender = extender
    def itemStateChanged(self, e):
        self._extender.autoVerbSwapEnabled = self._extender.autoVerbSwapCheckbox.isSelected()
        if self._extender.autoVerbSwapEnabled:
            self._extender.verbSwapStatusLabel.setText("Status: Auto Verb Swap ENABLED - Analytics auto-filtered, check Output tab for logs")
            print("[Verb Swap] AUTO VERB SWAP ENABLED")
        else:
            self._extender.verbSwapStatusLabel.setText("Status: Auto Verb Swap DISABLED")
            print("[Verb Swap] Auto Verb Swap DISABLED")

class TestAllVerbsAction(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    def actionPerformed(self, event):
        start_new_thread(self.testAllRequests, ())
    def testAllRequests(self):
        self._extender.verbSwapStatusLabel.setText("Status: Testing all requests...")
        selected_verbs = []
        if self._extender.testGET.isSelected():
            selected_verbs.append('GET')
        if self._extender.testPOST.isSelected():
            selected_verbs.append('POST')
        if self._extender.testPUT.isSelected():
            selected_verbs.append('PUT')
        if self._extender.testDELETE.isSelected():
            selected_verbs.append('DELETE')
        if self._extender.testPATCH.isSelected():
            selected_verbs.append('PATCH')
        if len(selected_verbs) == 0:
            self._extender.verbSwapStatusLabel.setText("Status: Error - No methods selected")
            return
        total_requests = self._extender._log.size()
        tested_count = 0
        for i in range(total_requests):
            logEntry = self._extender._log.get(i)
            originalRequest = logEntry._originalrequestResponse.getRequest()
            currentVerb = get_verb_from_request(self._extender._helpers, originalRequest)
            httpService = logEntry._originalrequestResponse.getHttpService()
            for new_verb in selected_verbs:
                if new_verb != currentVerb:
                    try:
                        swappedRequest = swap_http_verb(self._extender._helpers, originalRequest, new_verb)
                        newRequestResponse = IHttpRequestResponseImplementation(httpService, swappedRequest, None)
                        from authorization.authorization import send_request_to_autorize
                        send_request_to_autorize(self._extender, newRequestResponse)
                        tested_count += 1
                    except:
                        pass
        self._extender.verbSwapStatusLabel.setText("Status: Completed! Tested %d variations" % tested_count)

class ClearVerbSwapAction(ActionListener):
    def __init__(self, extender):
        self._extender = extender
    def actionPerformed(self, event):
        self._extender.verbSwapStats = {'total_tested': 0, 'bypasses_found': 0, 'status_200': 0, 'status_403': 0, 'status_401': 0, 'status_500': 0, 'status_other': 0}
        statsText = "\nTotal Verb Tests: 0\nBypasses Found: 0 (0.0%)\n\nStatus Code Breakdown:\n 200 OK: 0\n 403 Forbidden: 0\n 401 Unauthorized: 0\n 500 Server Error: 0\n Other: 0\n\nNote: Statistics count EVERY verb test\nCheck Output tab for logs"
        self._extender.verbSwapStatsArea.setText(statsText)
        self._extender.verbSwapStatusLabel.setText("Status: Statistics cleared")
