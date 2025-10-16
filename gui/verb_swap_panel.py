#!/usr/bin/env python
# -*- coding: utf-8 -*- 

"""
Enhanced Verb Swap GUI Component with Automatic Testing
IMPROVED VERSION with better statistics and messaging
"""

from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing import JLabel
from javax.swing import JPanel
from javax.swing import JTextArea
from javax.swing import JScrollPane
from javax.swing import BorderFactory
from java.awt import Color
from java.awt.event import ActionListener
from java.awt.event import ItemListener

from helpers.verb_swap import swap_http_verb, get_verb_from_request
from helpers.http import IHttpRequestResponseImplementation
from thread import start_new_thread

class VerbSwapPanel():
    def __init__(self, extender):
        self._extender = extender
        self._extender.autoVerbSwapEnabled = False
        self._extender.verbSwapStats = {
            'total_tested': 0,
            'bypasses_found': 0,
            'status_200': 0,
            'status_403': 0,
            'status_401': 0,
            'status_500': 0,
            'status_other': 0
        }

    def draw(self):
        """
        Initialize enhanced verb swap UI panel with automatic testing
        """
        # Title
        titleLabel = JLabel("<html><b>Automatic Verb Swap Configuration (IMPROVED)</b></html>")
        titleLabel.setBounds(10, 10, 500, 30)

        # Auto Verb Swap Checkbox
        self._extender.autoVerbSwapCheckbox = JCheckBox("Auto Verb Swap (Test all methods automatically)")
        self._extender.autoVerbSwapCheckbox.setBounds(10, 50, 500, 30)
        self._extender.autoVerbSwapCheckbox.addItemListener(AutoVerbSwapToggle(self._extender))

        # Verbs to Test Label
        verbsLabel = JLabel("HTTP Methods to Test:")
        verbsLabel.setBounds(10, 90, 200, 30)

        # Verb Checkboxes
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

        # Test All Button
        self._extender.testAllVerbsButton = JButton("Test All Requests with All Verbs")
        self._extender.testAllVerbsButton.setBounds(10, 160, 250, 35)
        self._extender.testAllVerbsButton.addActionListener(TestAllVerbsAction(self._extender))

        # Clear Results Button
        self._extender.clearVerbSwapButton = JButton("Clear Verb Swap Results")
        self._extender.clearVerbSwapButton.setBounds(270, 160, 220, 35)
        self._extender.clearVerbSwapButton.addActionListener(ClearVerbSwapAction(self._extender))

        # Status Label
        self._extender.verbSwapStatusLabel = JLabel("Status: Ready (Analytics auto-filtered)")
        self._extender.verbSwapStatusLabel.setBounds(10, 205, 600, 30)

        # Statistics Panel
        statsLabel = JLabel("<html><b>Verb Swap Statistics:</b></html>")
        statsLabel.setBounds(10, 245, 200, 30)

        self._extender.verbSwapStatsArea = JTextArea()
        self._extender.verbSwapStatsArea.setEditable(False)
        self._extender.verbSwapStatsArea.setBounds(10, 275, 600, 150)
        self._extender.verbSwapStatsArea.setBorder(BorderFactory.createLineBorder(Color.GRAY))
        self.updateStatsDisplay()

        scrollStats = JScrollPane(self._extender.verbSwapStatsArea)
        scrollStats.setBounds(10, 275, 600, 150)

        # Instructions
        instructionsArea = JTextArea(
            "IMPROVED VERSION Features:\n" +
            "1. Enable 'Auto Verb Swap' to automatically test all HTTP methods\n" +
            "2. Analytics domains (bam.nr-data, aptrinsic, gainsight, etc.) are AUTO-SKIPPED\n" +
            "3. Detailed console logging in Output tab shows exactly what's being tested\n" +
            "4. Statistics now count ALL tests (not just bypasses)\n" +
            "5. Progress indicators show Testing (1/4)... → Testing (2/4)... etc.\n" +
            "6. Results in main table: Red = Bypass found, Green = Secure, Yellow = Skipped\n\n" +
            "Check the Output tab (Extender → Extensions → Autorize → Output) to see detailed logs!"
        )
        instructionsArea.setEditable(False)
        instructionsArea.setWrapStyleWord(True)
        instructionsArea.setLineWrap(True)
        instructionsArea.setBackground(Color(245, 245, 245))
        instructionsArea.setBounds(10, 435, 600, 120)
        instructionsArea.setBorder(BorderFactory.createLineBorder(Color.GRAY))

        scrollInstructions = JScrollPane(instructionsArea)
        scrollInstructions.setBounds(10, 435, 600, 120)

        # Create Panel
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
        """Update the statistics display - IMPROVED VERSION"""
        stats = self._extender.verbSwapStats
        
        # Calculate percentage if tests were run
        if stats['total_tested'] > 0:
            bypass_percentage = (float(stats['bypasses_found']) / float(stats['total_tested'])) * 100
        else:
            bypass_percentage = 0.0
        
        statsText = """
Total Verb Tests:          %d
Bypasses Found:            %d  (%.1f%%)
        
Status Code Breakdown:
  200 OK:                  %d
  403 Forbidden:           %d
  401 Unauthorized:        %d
  500 Server Error:        %d
  Other:                   %d

Note: Statistics count EVERY verb test, not just bypasses.
Check Output tab for detailed logs of each test!
""" % (
            stats['total_tested'],
            stats['bypasses_found'],
            bypass_percentage,
            stats['status_200'],
            stats['status_403'],
            stats['status_401'],
            stats['status_500'],
            stats['status_other']
        )
        self._extender.verbSwapStatsArea.setText(statsText)


class AutoVerbSwapToggle(ItemListener):
    """Toggle automatic verb swapping"""
    def __init__(self, extender):
        self._extender = extender

    def itemStateChanged(self, e):
        self._extender.autoVerbSwapEnabled = self._extender.autoVerbSwapCheckbox.isSelected()
        if self._extender.autoVerbSwapEnabled:
            self._extender.verbSwapStatusLabel.setText("Status: Auto Verb Swap ENABLED - Analytics auto-filtered, check Output tab for logs")
            print("[Verb Swap] ============================================================")
            print("[Verb Swap] AUTO VERB SWAP ENABLED")
            print("[Verb Swap] All new requests will be automatically tested")
            print("[Verb Swap] Analytics domains will be automatically skipped")
            print("[Verb Swap] Watch this Output tab for detailed test logs")
            print("[Verb Swap] ============================================================")
        else:
            self._extender.verbSwapStatusLabel.setText("Status: Auto Verb Swap DISABLED")
            print("[Verb Swap] Auto Verb Swap DISABLED")


class TestAllVerbsAction(ActionListener):
    """Test all requests in table with all selected verbs"""
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        start_new_thread(self.testAllRequests, ())

    def testAllRequests(self):
        print("[Verb Swap] ============================================================")
        print("[Verb Swap] BATCH TESTING ALL REQUESTS")
        print("[Verb Swap] ============================================================")
        
        self._extender.verbSwapStatusLabel.setText("Status: Testing all requests with all verbs...")
        
        # Get selected verbs
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
            print("[Verb Swap] ERROR: No HTTP methods selected!")
            self._extender.verbSwapStatusLabel.setText("Status: Error - No HTTP methods selected!")
            return

        print("[Verb Swap] Selected methods: " + str(selected_verbs))

        # Test all requests
        total_requests = self._extender._log.size()
        tested_count = 0
        skipped_count = 0

        print("[Verb Swap] Total requests in table: " + str(total_requests))

        for i in range(total_requests):
            logEntry = self._extender._log.get(i)
            originalRequest = logEntry._originalrequestResponse.getRequest()
            currentVerb = get_verb_from_request(self._extender._helpers, originalRequest)
            httpService = logEntry._originalrequestResponse.getHttpService()
            
            # Check if analytics URL
            try:
                urlString = str(self._extender._helpers.analyzeRequest(originalRequest).getUrl())
                ANALYTICS_DOMAINS = ['bam.nr-data', 'aptrinsic', 'gainsight', 'newrelic', 'google-analytics']
                
                if any(domain in urlString.lower() for domain in ANALYTICS_DOMAINS):
                    print("[Verb Swap] Skipping analytics URL: " + urlString[:80])
                    skipped_count += 1
                    continue
            except:
                pass

            # Test with each selected verb (except current verb)
            for new_verb in selected_verbs:
                if new_verb != currentVerb:
                    try:
                        swappedRequest = swap_http_verb(
                            self._extender._helpers,
                            originalRequest,
                            new_verb
                        )
                        
                        newRequestResponse = IHttpRequestResponseImplementation(
                            httpService,
                            swappedRequest,
                            None
                        )
                        
                        from authorization.authorization import send_request_to_autorize
                        send_request_to_autorize(self._extender, newRequestResponse)
                        tested_count += 1
                    except Exception as e:
                        print("[Verb Swap] Error testing verb " + new_verb + ": " + str(e))

        print("[Verb Swap] ============================================================")
        print("[Verb Swap] BATCH TEST COMPLETE")
        print("[Verb Swap] Total requests: " + str(total_requests))
        print("[Verb Swap] Skipped (analytics): " + str(skipped_count))
        print("[Verb Swap] Tested: " + str(tested_count) + " verb variations")
        print("[Verb Swap] ============================================================")
        
        self._extender.verbSwapStatusLabel.setText("Status: Completed! Tested %d verb variations (skipped %d analytics)" % (tested_count, skipped_count))


class ClearVerbSwapAction(ActionListener):
    """Clear verb swap statistics"""
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, event):
        print("[Verb Swap] Clearing statistics...")
        
        self._extender.verbSwapStats = {
            'total_tested': 0,
            'bypasses_found': 0,
            'status_200': 0,
            'status_403': 0,
            'status_401': 0,
            'status_500': 0,
            'status_other': 0
        }
        
        # Update display
        stats = self._extender.verbSwapStats
        statsText = """
Total Verb Tests:          0
Bypasses Found:            0  (0.0%)
        
Status Code Breakdown:
  200 OK:                  0
  403 Forbidden:           0
  401 Unauthorized:        0
  500 Server Error:        0
  Other:                   0

Note: Statistics count EVERY verb test, not just bypasses.
Check Output tab for detailed logs of each test!
"""
        self._extender.verbSwapStatsArea.setText(statsText)
        self._extender.verbSwapStatusLabel.setText("Status: Statistics cleared")
        
        print("[Verb Swap] Statistics cleared successfully")
