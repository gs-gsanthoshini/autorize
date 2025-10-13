#!/usr/bin/env python
# -*- coding: utf-8 -*- 

from burp import IContextMenuFactory

from java.util import LinkedList
from javax.swing import JMenuItem
from javax.swing import JMenu
from java.awt.event import ActionListener

from authorization.authorization import send_request_to_autorize
from helpers.http import get_cookie_header_from_message, get_authorization_header_from_message
from helpers.verb_swap import swap_http_verb, get_verb_mappings, get_verb_from_request
from helpers.http import IHttpRequestResponseImplementation

from thread import start_new_thread

class MenuImpl(IContextMenuFactory):
    def __init__(self, extender):
        self._extender = extender

    def createMenuItems(self, invocation):
        responses = invocation.getSelectedMessages()
        if responses > 0:
            ret = LinkedList()
            requestMenuItem = JMenuItem("Send request to Autorize")
            cookieMenuItem = JMenuItem("Send Cookie header to Autorize")
            authMenuItem = JMenuItem("Send Authorization header to Autorize")
            
            # Create Verb Swap submenu
            verbSwapMenu = JMenu("Swap HTTP Verb")
            verb_mappings = get_verb_mappings()
            
            for response in responses:
                requestMenuItem.addActionListener(HandleMenuItems(self._extender,response, "request"))
                cookieMenuItem.addActionListener(HandleMenuItems(self._extender, response, "cookie"))
                authMenuItem.addActionListener(HandleMenuItems(self._extender, response, "authorization"))
                
                # Add verb swap menu items
                for old_verb, new_verb in verb_mappings:
                    verbSwapItem = JMenuItem("%s → %s" % (old_verb, new_verb))
                    verbSwapItem.addActionListener(HandleVerbSwap(self._extender, response, old_verb, new_verb))
                    verbSwapMenu.add(verbSwapItem)
            
            ret.add(requestMenuItem)
            ret.add(cookieMenuItem)
            ret.add(authMenuItem)
            ret.add(verbSwapMenu)
            return ret
        return None

class HandleMenuItems(ActionListener):
    def __init__(self, extender, messageInfo, menuName):
        self._extender = extender
        self._menuName = menuName
        self._messageInfo = messageInfo

    def actionPerformed(self, e):
        if self._menuName == "request":
            start_new_thread(send_request_to_autorize, (self._extender, self._messageInfo,))

        if self._menuName == "cookie":
            self._extender.replaceString.setText(get_cookie_header_from_message(self._extender, self._messageInfo))
        
        if self._menuName == "authorization":
            self._extender.replaceString.setText(get_authorization_header_from_message(self._extender, self._messageInfo))

class HandleVerbSwap(ActionListener):
    """
    Handler for verb swap context menu items
    """
    def __init__(self, extender, messageInfo, old_verb, new_verb):
        self._extender = extender
        self._messageInfo = messageInfo
        self._old_verb = old_verb
        self._new_verb = new_verb

    def actionPerformed(self, e):
        # Get the request
        request = self._messageInfo.getRequest()
        currentVerb = get_verb_from_request(self._extender._helpers, request)
        
        # Check if current verb matches
        if currentVerb == self._old_verb:
            # Swap the verb
            swappedRequest = swap_http_verb(
                self._extender._helpers, 
                request, 
                self._new_verb
            )
            
            # Create new request response
            httpService = self._messageInfo.getHttpService()
            newRequestResponse = IHttpRequestResponseImplementation(
                httpService, 
                swappedRequest, 
                None
            )
            
            # Send through Autorize for testing
            start_new_thread(send_request_to_autorize, (self._extender, newRequestResponse,))