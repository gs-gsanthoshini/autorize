#!/usr/bin/env python
# -*- coding: utf-8 -*-

from operator import truediv
import sys
reload(sys)

if (sys.version_info[0] == 2):
    sys.setdefaultencoding('utf8')

sys.path.append("..")

from helpers.http import get_authorization_header_from_message, get_cookie_header_from_message, isStatusCodesReturned, makeMessage, makeRequest, getResponseBody, IHttpRequestResponseImplementation
from gui.table import LogEntry, UpdateTableEDT
from javax.swing import SwingUtilities
from java.net import URL
import re

def tool_needs_to_be_ignored(self, toolFlag):
    for i in range(0, self.IFList.getModel().getSize()):
        if self.IFList.getModel().getElementAt(i).split(":")[0] == "Ignore spider requests":
            if (toolFlag == self._callbacks.TOOL_SPIDER):
                return True
        if self.IFList.getModel().getElementAt(i).split(":")[0] == "Ignore proxy requests":
            if (toolFlag == self._callbacks.TOOL_PROXY):
                return True
        if self.IFList.getModel().getElementAt(i).split(":")[0] == "Ignore target requests":
            if (toolFlag == self._callbacks.TOOL_TARGET):
                return True
    return False

def capture_last_cookie_header(self, messageInfo):
    cookies = get_cookie_header_from_message(self, messageInfo)
    if cookies:
        self.lastCookiesHeader = cookies
        self.fetchCookiesHeaderButton.setEnabled(True)

def capture_last_authorization_header(self, messageInfo):
    authorization = get_authorization_header_from_message(self, messageInfo)
    if authorization:
        self.lastAuthorizationHeader = authorization
        self.fetchAuthorizationHeaderButton.setEnabled(True)

def valid_tool(self, toolFlag):
    return (toolFlag == self._callbacks.TOOL_PROXY or
            (toolFlag == self._callbacks.TOOL_REPEATER and
            self.interceptRequestsfromRepeater.isSelected()))

def handle_304_status_code_prevention(self, messageIsRequest, messageInfo):
    should_prevent = False
    if self.prevent304.isSelected():
        if messageIsRequest:
            requestHeaders = list(self._helpers.analyzeRequest(messageInfo).getHeaders())
            newHeaders = list()
            for header in requestHeaders:
                if not "If-None-Match:" in header and not "If-Modified-Since:" in header:
                    newHeaders.append(header)
                    should_prevent = True
        if should_prevent:
            requestInfo = self._helpers.analyzeRequest(messageInfo)
            bodyBytes = messageInfo.getRequest()[requestInfo.getBodyOffset():]
            bodyStr = self._helpers.bytesToString(bodyBytes)
            messageInfo.setRequest(self._helpers.buildHttpMessage(newHeaders, bodyStr))

def message_not_from_autorize(self, messageInfo):
    return not self.replaceString.getText() in self._helpers.analyzeRequest(messageInfo).getHeaders()

def no_filters_defined(self):
    return self.IFList.getModel().getSize() == 0

def message_passed_interception_filters(self, messageInfo):
    urlString = str(self._helpers.analyzeRequest(messageInfo).getUrl())
    reqInfo = self._helpers.analyzeRequest(messageInfo)
    reqBodyBytes = messageInfo.getRequest()[reqInfo.getBodyOffset():]
    bodyStr = self._helpers.bytesToString(reqBodyBytes)

    resInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
    resBodyBytes = messageInfo.getResponse()[resInfo.getBodyOffset():]
    resStr = self._helpers.bytesToString(resBodyBytes)

    message_passed_filters = True
    for i in range(0, self.IFList.getModel().getSize()):
        interceptionFilter = self.IFList.getModel().getElementAt(i)
        interceptionFilterTitle = interceptionFilter.split(":")[0]
        if interceptionFilterTitle == "Scope items only":
            currentURL = URL(urlString)
            if not self._callbacks.isInScope(currentURL):
                message_passed_filters = False

        if interceptionFilterTitle == "URL Contains (simple string)":
            if interceptionFilter[30:] not in urlString:
                message_passed_filters = False

        if interceptionFilterTitle == "URL Contains (regex)":
            regex_string = interceptionFilter[22:]
            if re.search(regex_string, urlString, re.IGNORECASE) is None:
                message_passed_filters = False

        if interceptionFilterTitle == "URL Not Contains (simple string)":
            if interceptionFilter[34:] in urlString:
                message_passed_filters = False

        if interceptionFilterTitle == "URL Not Contains (regex)":
            regex_string = interceptionFilter[26:]
            if not re.search(regex_string, urlString, re.IGNORECASE) is None:
                message_passed_filters = False

        if interceptionFilterTitle == "Request Body contains (simple string)":
            if interceptionFilter[40:] not in bodyStr:
                message_passed_filters = False

        if interceptionFilterTitle == "Request Body contains (regex)":
            regex_string = interceptionFilter[32:]
            if re.search(regex_string, bodyStr, re.IGNORECASE) is None:
                message_passed_filters = False

        if interceptionFilterTitle == "Request Body NOT contains (simple string)":
            if interceptionFilter[44:] in bodyStr:
                message_passed_filters = False

        if interceptionFilterTitle == "Request Body Not contains (regex)":
            regex_string = interceptionFilter[36:]
            if not re.search(regex_string, bodyStr, re.IGNORECASE) is None:
                message_passed_filters = False

        if interceptionFilterTitle == "Response Body contains (simple string)":
            if interceptionFilter[41:] not in resStr:
                message_passed_filters = False

        if interceptionFilterTitle == "Response Body contains (regex)":
            regex_string = interceptionFilter[33:]
            if re.search(regex_string, resStr, re.IGNORECASE) is None:
                message_passed_filters = False

        if interceptionFilterTitle == "Response Body NOT contains (simple string)":
            if interceptionFilter[45:] in resStr:
                message_passed_filters = False

        if interceptionFilterTitle == "Response Body Not contains (regex)":
            regex_string = interceptionFilter[37:]
            if not re.search(regex_string, resStr, re.IGNORECASE) is None:
                message_passed_filters = False

        if interceptionFilterTitle == "Header contains":
            for header in list(resInfo.getHeaders()):
                if interceptionFilter[17:] in header:
                    message_passed_filters = False

        if interceptionFilterTitle == "Header doesn't contain":
            for header in list(resInfo.getHeaders()):
                if not interceptionFilter[17:] in header:
                    message_passed_filters = False

        if interceptionFilterTitle == "Only HTTP methods (newline separated)":
            filterMethods = interceptionFilter[39:].split("\n")
            filterMethods = [x.lower() for x in filterMethods]
            reqMethod = str(self._helpers.analyzeRequest(messageInfo).getMethod())
            if reqMethod.lower() not in filterMethods:
                message_passed_filters = False

        if interceptionFilterTitle == "Ignore HTTP methods (newline separated)":
            filterMethods = interceptionFilter[41:].split("\n")
            filterMethods = [x.lower() for x in filterMethods]
            reqMethod = str(self._helpers.analyzeRequest(messageInfo).getMethod())
            if reqMethod.lower() in filterMethods:
                message_passed_filters = False

        if interceptionFilterTitle == "Ignore OPTIONS requests":
            reqMethod = str(self._helpers.analyzeRequest(messageInfo).getMethod())
            if reqMethod == "OPTIONS":
                message_passed_filters = False

    return message_passed_filters

def handle_message(self, toolFlag, messageIsRequest, messageInfo):
    if tool_needs_to_be_ignored(self, toolFlag):
        return

    capture_last_cookie_header(self, messageInfo)
    capture_last_authorization_header(self, messageInfo)

    if (self.intercept and valid_tool(self, toolFlag) or toolFlag == "AUTORIZE"):
        handle_304_status_code_prevention(self, messageIsRequest, messageInfo)

        if not messageIsRequest:
            if message_not_from_autorize(self, messageInfo):
                if self.ignore304.isSelected():
                    if isStatusCodesReturned(self, messageInfo, ["304", "204"]):
                        return

                if no_filters_defined(self):
                    checkAuthorization(self, messageInfo,
                    self._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders(),
                                            self.doUnauthorizedRequest.isSelected())
                else:
                    if message_passed_interception_filters(self, messageInfo):
                        checkAuthorization(self, messageInfo,self._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders(),self.doUnauthorizedRequest.isSelected())

def send_request_to_autorize(self, messageInfo):
    if messageInfo.getResponse() is None:
        message = makeMessage(self, messageInfo,False,False)
        requestResponse = makeRequest(self, messageInfo, message)
        checkAuthorization(self, requestResponse,self._helpers.analyzeResponse(requestResponse.getResponse()).getHeaders(),self.doUnauthorizedRequest.isSelected())
    else:
        request = messageInfo.getRequest()
        response = messageInfo.getResponse()
        httpService = messageInfo.getHttpService()
        newHttpRequestResponse = IHttpRequestResponseImplementation(httpService,request,response)
        newHttpRequestResponsePersisted = self._callbacks.saveBuffersToTempFiles(newHttpRequestResponse)
        checkAuthorization(self, newHttpRequestResponsePersisted,self._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders(),self.doUnauthorizedRequest.isSelected())

def auth_enforced_via_enforcement_detectors(self, filters, requestResponse, andOrEnforcement):
    response = requestResponse.getResponse()
    analyzedResponse = self._helpers.analyzeResponse(response)
    auth_enforced = False
    if andOrEnforcement == "And":
        andEnforcementCheck = True
        auth_enforced = True
    else:
        andEnforcementCheck = False
        auth_enforced = False

    for filter in filters:
        filter = self._helpers.bytesToString(bytes(filter))
        filter_kv = filter.split(":", 1)
        inverse = "NOT" in filter_kv[0]
        filter_kv[0] = filter_kv[0].replace(" NOT", "")
        filter = ":".join(filter_kv)

        if filter.startswith("Status code equals: "):
            statusCode = filter[20:]
            filterMatched = inverse ^ isStatusCodesReturned(self, requestResponse, statusCode)

        elif filter.startswith("Headers (simple string): "):
            filterMatched = inverse ^ (filter[25:] in self._helpers.bytesToString(requestResponse.getResponse()[0:analyzedResponse.getBodyOffset()]))

        elif filter.startswith("Headers (regex): "):
            regex_string = filter[17:]
            p = re.compile(regex_string, re.IGNORECASE)
            filterMatched = inverse ^ bool(p.search(self._helpers.bytesToString(requestResponse.getResponse()[0:analyzedResponse.getBodyOffset()])))

        elif filter.startswith("Body (simple string): "):
            filterMatched = inverse ^ (filter[22:] in self._helpers.bytesToString(requestResponse.getResponse()[analyzedResponse.getBodyOffset():]))

        elif filter.startswith("Body (regex): "):
            regex_string = filter[14:]
            p = re.compile(regex_string, re.IGNORECASE)
            filterMatched = inverse ^ bool(p.search(self._helpers.bytesToString(requestResponse.getResponse()[analyzedResponse.getBodyOffset():])))

        elif filter.startswith("Full response (simple string): "):
            filterMatched = inverse ^ (filter[31:] in self._helpers.bytesToString(requestResponse.getResponse()))

        elif filter.startswith("Full response (regex): "):
            regex_string = filter[23:]
            p = re.compile(regex_string, re.IGNORECASE)
            filterMatched = inverse ^ bool(p.search(self._helpers.bytesToString(requestResponse.getResponse())))

        elif filter.startswith("Full response length: "):
            filterMatched = inverse ^ (str(len(response)) == filter[22:].strip())

        if andEnforcementCheck:
            if auth_enforced and not filterMatched:
                auth_enforced = False
        else:
            if not auth_enforced and filterMatched:
                auth_enforced = True

    return auth_enforced

def checkBypass(self, oldStatusCode, newStatusCode, oldContent,
                 newContent, filters, requestResponse, andOrEnforcement):
    if oldStatusCode == newStatusCode:
        auth_enforced = 0
        if len(filters) > 0:
            auth_enforced = auth_enforced_via_enforcement_detectors(self, filters, requestResponse, andOrEnforcement)
        if auth_enforced:
            return self.ENFORCED_STR
        elif oldContent == newContent:
            return self.BYPASSSED_STR
        else:
            return self.IS_ENFORCED_STR
    else:
        return self.ENFORCED_STR

def checkAuthorization(self, messageInfo, originalHeaders, checkUnauthorized):
    if checkUnauthorized:
        messageUnauthorized = makeMessage(self, messageInfo, True, False)
        requestResponseUnauthorized = makeRequest(self, messageInfo, messageUnauthorized)
        unauthorizedResponse = requestResponseUnauthorized.getResponse()
        analyzedResponseUnauthorized = self._helpers.analyzeResponse(unauthorizedResponse)
        statusCodeUnauthorized = analyzedResponseUnauthorized.getHeaders()[0]
        contentUnauthorized = getResponseBody(self, requestResponseUnauthorized)

    message = makeMessage(self, messageInfo, True, True)
    requestResponse = makeRequest(self, messageInfo, message)
    newResponse = requestResponse.getResponse()
    analyzedResponse = self._helpers.analyzeResponse(newResponse)

    oldStatusCode = originalHeaders[0]
    newStatusCode = analyzedResponse.getHeaders()[0]
    oldContent = getResponseBody(self, messageInfo)
    newContent = getResponseBody(self, requestResponse)

    EDFilters = self.EDModel.toArray()

    impression = checkBypass(self, oldStatusCode, newStatusCode, oldContent, newContent, EDFilters, requestResponse, self.AndOrType.getSelectedItem())

    if checkUnauthorized:
        EDFiltersUnauth = self.EDModelUnauth.toArray()
        impressionUnauthorized = checkBypass(self, oldStatusCode, statusCodeUnauthorized, oldContent, contentUnauthorized, EDFiltersUnauth, requestResponseUnauthorized, self.AndOrTypeUnauth.getSelectedItem())

    self._lock.acquire()

    row = self._log.size()
    method = self._helpers.analyzeRequest(messageInfo.getRequest()).getMethod()

    if checkUnauthorized:
        self._log.add(LogEntry(self.currentRequestNumber,self._callbacks.saveBuffersToTempFiles(requestResponse), method, self._helpers.analyzeRequest(requestResponse).getUrl(),messageInfo,impression,self._callbacks.saveBuffersToTempFiles(requestResponseUnauthorized),impressionUnauthorized))
    else:
        self._log.add(LogEntry(self.currentRequestNumber,self._callbacks.saveBuffersToTempFiles(requestResponse), method, self._helpers.analyzeRequest(requestResponse).getUrl(),messageInfo,impression,None,"Disabled"))

    SwingUtilities.invokeLater(UpdateTableEDT(self,"insert",row,row))
    self.currentRequestNumber = self.currentRequestNumber + 1
    
    currentLogEntry = self._log.get(row)
    
    self._lock.release()
    
    from thread import start_new_thread
    start_new_thread(auto_verb_swap_test, (self, currentLogEntry, messageInfo, originalHeaders))

def checkAuthorizationV2(self, messageInfo):
    checkAuthorization(self, messageInfo, self._extender._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders(), self._extender.doUnauthorizedRequest.isSelected())

def retestAllRequests(self):
    self.logTable.setAutoCreateRowSorter(True)
    for i in range(self.tableModel.getRowCount()):
        logEntry = self._log.get(self.logTable.convertRowIndexToModel(i))
        handle_message(self, "AUTORIZE", False, logEntry._originalrequestResponse)

def auto_verb_swap_test(self, logEntry, messageInfo, originalHeaders):
    """
    IMPROVED AUTO VERB SWAP with:
    - Auto-filtering of analytics domains
    - Detailed console logging
    - Better statistics tracking
    - Progress indicators
    - Better error handling
    """
    
    if not hasattr(self, 'autoVerbSwapEnabled') or not self.autoVerbSwapEnabled:
        logEntry._verbBypasses = "Disabled"
        try:
            row_index = self._log.indexOf(logEntry)
            SwingUtilities.invokeLater(UpdateTableEDT(self, "update", row_index, row_index))
        except:
            pass
        return
    
    try:
        urlString = str(self._helpers.analyzeRequest(messageInfo.getRequest()).getUrl())
    except:
        urlString = "Unknown URL"
    
    # AUTO-FILTER ANALYTICS DOMAINS
    ANALYTICS_DOMAINS = ['bam.nr-data', 'aptrinsic', 'gainsight', 'newrelic', 'google-analytics', 'googletagmanager', 'facebook.net', 'doubleclick.net', 'static']
    
    if any(domain in urlString.lower() for domain in ANALYTICS_DOMAINS):
        print("[Verb Swap] ============================================================")
        print("[Verb Swap] SKIPPING ANALYTICS URL")
        print("[Verb Swap] URL: " + urlString[:100])
        print("[Verb Swap] Reason: Matches analytics domain - not testing")
        print("[Verb Swap] ============================================================")
        logEntry._verbBypasses = "Skipped (analytics)"
        try:
            row_index = self._log.indexOf(logEntry)
            SwingUtilities.invokeLater(UpdateTableEDT(self, "update", row_index, row_index))
        except:
            pass
        return
    
    from helpers.verb_swap import swap_http_verb, get_verb_from_request
    from helpers.http import makeRequest
    from java.lang import Runnable
    
    print("[Verb Swap] ============================================================")
    print("[Verb Swap] STARTING VERB SWAP TEST")
    print("[Verb Swap] Request ID: " + str(logEntry._id))
    print("[Verb Swap] URL: " + urlString[:100])
    
    selected_verbs = []
    if hasattr(self, 'testGET') and self.testGET.isSelected():
        selected_verbs.append('GET')
    if hasattr(self, 'testPOST') and self.testPOST.isSelected():
        selected_verbs.append('POST')
    if hasattr(self, 'testPUT') and self.testPUT.isSelected():
        selected_verbs.append('PUT')
    if hasattr(self, 'testDELETE') and self.testDELETE.isSelected():
        selected_verbs.append('DELETE')
    if hasattr(self, 'testPATCH') and self.testPATCH.isSelected():
        selected_verbs.append('PATCH')
    
    if len(selected_verbs) == 0:
        print("[Verb Swap] ERROR: No HTTP methods selected!")
        print("[Verb Swap] ============================================================")
        logEntry._verbBypasses = "No methods selected"
        try:
            row_index = self._log.indexOf(logEntry)
            SwingUtilities.invokeLater(UpdateTableEDT(self, "update", row_index, row_index))
        except:
            pass
        return
    
    try:
        originalRequest = messageInfo.getRequest()
        currentVerb = get_verb_from_request(self._helpers, originalRequest)
        print("[Verb Swap] Original method: " + currentVerb)
        print("[Verb Swap] Will test: " + str(selected_verbs))
    except Exception as e:
        print("[Verb Swap] ERROR getting original verb: " + str(e))
        logEntry._verbBypasses = "Error: Cannot get verb"
        try:
            row_index = self._log.indexOf(logEntry)
            SwingUtilities.invokeLater(UpdateTableEDT(self, "update", row_index, row_index))
        except:
            pass
        return
    
    bypassed_verbs = []
    tested_count = 0
    total_to_test = len([v for v in selected_verbs if v != currentVerb])
    
    print("[Verb Swap] Total verbs to test: " + str(total_to_test))
    print("[Verb Swap] ------------------------------------------------------------")
    
    for new_verb in selected_verbs:
        if new_verb == currentVerb:
            print("[Verb Swap] Skipping " + new_verb + " (same as original)")
            continue
        
        tested_count += 1
        
        # Update progress
        logEntry._verbBypasses = "Testing (" + str(tested_count) + "/" + str(total_to_test) + ")"
        try:
            row_index = self._log.indexOf(logEntry)
            SwingUtilities.invokeLater(UpdateTableEDT(self, "update", row_index, row_index))
        except:
            pass
        
        print("[Verb Swap] [" + str(tested_count) + "/" + str(total_to_test) + "] Testing: " + new_verb)
        
        try:
            swappedRequest = swap_http_verb(self._helpers, originalRequest, new_verb)
            requestResponse = makeRequest(self, messageInfo, swappedRequest)
            
            if requestResponse.getResponse() is not None:
                analyzedResponse = self._helpers.analyzeResponse(requestResponse.getResponse())
                statusCode = analyzedResponse.getHeaders()[0]
                
                print("[Verb Swap]     Response: " + statusCode)
                
                # Count ALL tests in statistics
                if hasattr(self, 'verbSwapStats'):
                    self.verbSwapStats['total_tested'] += 1
                
                if "200" in statusCode or "201" in statusCode or "202" in statusCode or "204" in statusCode:
                    bypassed_verbs.append(new_verb)
                    print("[Verb Swap]     Result: BYPASS FOUND!")
                    if hasattr(self, 'verbSwapStats'):
                        self.verbSwapStats['bypasses_found'] += 1
                        self.verbSwapStats['status_200'] += 1
                elif "403" in statusCode:
                    print("[Verb Swap]     Result: Blocked (403 Forbidden)")
                    if hasattr(self, 'verbSwapStats'):
                        self.verbSwapStats['status_403'] += 1
                elif "401" in statusCode:
                    print("[Verb Swap]     Result: Blocked (401 Unauthorized)")
                    if hasattr(self, 'verbSwapStats'):
                        self.verbSwapStats['status_401'] += 1
                elif "500" in statusCode:
                    print("[Verb Swap]     Result: Server Error (500)")
                    if hasattr(self, 'verbSwapStats'):
                        self.verbSwapStats['status_500'] += 1
                else:
                    print("[Verb Swap]     Result: Other status")
                    if hasattr(self, 'verbSwapStats'):
                        self.verbSwapStats['status_other'] += 1
            else:
                print("[Verb Swap]     Result: NO RESPONSE")
                
        except Exception as e:
            print("[Verb Swap]     ERROR: " + str(e))
            import traceback
            traceback.print_exc()
    
    print("[Verb Swap] ------------------------------------------------------------")
    
    if len(bypassed_verbs) > 0:
        logEntry._verbBypasses = "🚨 " + ", ".join(bypassed_verbs)
        print("[Verb Swap] FINAL RESULT: BYPASSES FOUND - " + ", ".join(bypassed_verbs))
    else:
        if tested_count > 0:
            logEntry._verbBypasses = "None"
            print("[Verb Swap] FINAL RESULT: No bypasses found (secure)")
        else:
            logEntry._verbBypasses = "Not tested"
            print("[Verb Swap] FINAL RESULT: No verbs tested")
    
    print("[Verb Swap] Test complete for request ID: " + str(logEntry._id))
    print("[Verb Swap] ============================================================")
    
    try:
        row_index = self._log.indexOf(logEntry)
        SwingUtilities.invokeLater(UpdateTableEDT(self, "update", row_index, row_index))
    except Exception as e:
        print("[Verb Swap] ERROR updating table: " + str(e))
    
    if hasattr(self, 'verbSwapStatsArea'):
        try:
            from gui.verb_swap_panel import VerbSwapPanel
            panel = VerbSwapPanel(self)
            
            class UpdateStatsRunnable(Runnable):
                def __init__(self, extender, panel):
                    self._extender = extender
                    self._panel = panel
                
                def run(self):
                    self._panel.updateStatsDisplay()
            
            SwingUtilities.invokeLater(UpdateStatsRunnable(self, panel))
        except Exception as e:
            print("[Verb Swap] ERROR updating statistics: " + str(e))
