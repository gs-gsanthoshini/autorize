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
import time

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
    
    self._lock.release()
    
    try:
        from thread import start_new_thread
        
        def delayed_verb_swap_test():
            time.sleep(0.1)
            try:
                currentLogEntry = self._log.get(row)
                auto_verb_swap_test(self, currentLogEntry, messageInfo, originalHeaders)
            except Exception as e:
                print("[Verb Swap] Error in background thread: " + str(e))
        
        start_new_thread(delayed_verb_swap_test, ())
    except Exception as e:
        print("[Verb Swap] Error starting background thread: " + str(e))

def checkAuthorizationV2(self, messageInfo):
    checkAuthorization(self, messageInfo, self._extender._helpers.analyzeResponse(messageInfo.getResponse()).getHeaders(), self._extender.doUnauthorizedRequest.isSelected())

def retestAllRequests(self):
    self.logTable.setAutoCreateRowSorter(True)
    for i in range(self.tableModel.getRowCount()):
        logEntry = self._log.get(self.logTable.convertRowIndexToModel(i))
        handle_message(self, "AUTORIZE", False, logEntry._originalrequestResponse)

def auto_verb_swap_test(self, logEntry, messageInfo, originalHeaders):
    print("[Verb Swap] Starting test for request ID: " + str(logEntry._id))
    
    if not hasattr(self, 'autoVerbSwapEnabled'):
        print("[Verb Swap] autoVerbSwapEnabled attribute does not exist!")
        logEntry._verbBypasses = "None"
        try:
            row_index = self._log.indexOf(logEntry)
            SwingUtilities.invokeLater(UpdateTableEDT(self, "update", row_index, row_index))
        except:
            pass
        return
    
    if not self.autoVerbSwapEnabled:
        print("[Verb Swap] Auto Verb Swap is DISABLED")
        logEntry._verbBypasses = "None"
        try:
            row_index = self._log.indexOf(logEntry)
            SwingUtilities.invokeLater(UpdateTableEDT(self, "update", row_index, row_index))
        except:
            pass
        return
    
    print("[Verb Swap] Auto Verb Swap is ENABLED - proceeding with tests")
    
    try:
        from helpers.verb_swap import swap_http_verb, get_verb_from_request
        from helpers.http import makeRequest
        from java.lang import Runnable
        print("[Verb Swap] Successfully imported verb_swap helpers")
    except Exception as e:
        import traceback
        print("=" * 60)
        print("[Verb Swap] IMPORT ERROR")
        print("Error: " + str(e))
        traceback.print_exc()
        print("=" * 60)
        logEntry._verbBypasses = "Error: Import failed"
        return
    
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
    
    print("[Verb Swap] Selected verbs to test: " + str(selected_verbs))
    
    if len(selected_verbs) == 0:
        print("[Verb Swap] No verbs selected!")
        logEntry._verbBypasses = "None"
        try:
            row_index = self._log.indexOf(logEntry)
            SwingUtilities.invokeLater(UpdateTableEDT(self, "update", row_index, row_index))
        except:
            pass
        return
    
    try:
        originalRequest = messageInfo.getRequest()
        currentVerb = get_verb_from_request(self._helpers, originalRequest)
        print("[Verb Swap] Current verb: " + currentVerb)
    except Exception as e:
        import traceback
        print("=" * 60)
        print("[Verb Swap] ERROR getting current verb")
        print("Error: " + str(e))
        traceback.print_exc()
        print("=" * 60)
        logEntry._verbBypasses = "Error: Cannot get verb"
        return
    
    bypassed_verbs = []
    tested_count = 0
    
    for new_verb in selected_verbs:
        if new_verb == currentVerb:
            print("[Verb Swap] Skipping " + new_verb + " (same as original)")
            continue
        
        print("[Verb Swap] Testing verb: " + new_verb)
        
        try:
            swappedRequest = swap_http_verb(self._helpers, originalRequest, new_verb)
            requestResponse = makeRequest(self, messageInfo, swappedRequest)
            tested_count += 1
            
            if requestResponse.getResponse() is not None:
                analyzedResponse = self._helpers.analyzeResponse(requestResponse.getResponse())
                statusCode = analyzedResponse.getHeaders()[0]
                print("[Verb Swap] " + new_verb + " returned: " + statusCode)
                
                if "200" in statusCode or "201" in statusCode or "202" in statusCode:
                    bypassed_verbs.append(new_verb)
                    print("[Verb Swap] BYPASS FOUND with " + new_verb + "!")
                    if hasattr(self, 'verbSwapStats'):
                        self.verbSwapStats['bypasses_found'] += 1
                        self.verbSwapStats['status_200'] += 1
                        self.verbSwapStats['total_tested'] += 1
                elif "403" in statusCode:
                    if hasattr(self, 'verbSwapStats'):
                        self.verbSwapStats['status_403'] += 1
                        self.verbSwapStats['total_tested'] += 1
                elif "401" in statusCode:
                    if hasattr(self, 'verbSwapStats'):
                        self.verbSwapStats['status_401'] += 1
                        self.verbSwapStats['total_tested'] += 1
                elif "500" in statusCode:
                    if hasattr(self, 'verbSwapStats'):
                        self.verbSwapStats['status_500'] += 1
                        self.verbSwapStats['total_tested'] += 1
                else:
                    if hasattr(self, 'verbSwapStats'):
                        self.verbSwapStats['status_other'] += 1
                        self.verbSwapStats['total_tested'] += 1
            else:
                print("[Verb Swap] " + new_verb + " returned NO RESPONSE")
                
        except Exception as e:
            import traceback
            print("=" * 60)
            print("[Verb Swap] ERROR testing verb: " + new_verb)
            print("Error message: " + str(e))
            print("Full traceback:")
            traceback.print_exc()
            print("=" * 60)
    
    if len(bypassed_verbs) > 0:
        logEntry._verbBypasses = "🚨 " + ", ".join(bypassed_verbs)
        print("[Verb Swap] RESULT: Bypasses found - " + ", ".join(bypassed_verbs))
    else:
        if tested_count > 0:
            logEntry._verbBypasses = "None"
            print("[Verb Swap] RESULT: No bypasses found")
        else:
            logEntry._verbBypasses = "Not tested"
            print("[Verb Swap] RESULT: Not tested (no verbs to test)")
    
    try:
        row_index = self._log.indexOf(logEntry)
        SwingUtilities.invokeLater(UpdateTableEDT(self, "update", row_index, row_index))
        print("[Verb Swap] Table updated successfully")
    except Exception as e:
        print("[Verb Swap] Error updating table: " + str(e))
    
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
            print("[Verb Swap] Statistics updated")
        except Exception as e:
            print("[Verb Swap] Error updating statistics: " + str(e))
    
    print("[Verb Swap] Test completed for request ID: " + str(logEntry._id))
