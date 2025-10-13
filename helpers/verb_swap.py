#!/usr/bin/env python
# -*- coding: utf-8 -*- 

"""
Verb Swap Helper Module
Handles HTTP verb/method swapping for authorization testing
"""

def swap_http_verb(helpers, request_bytes, new_verb):
    """
    Swaps the HTTP verb/method in a request
    
    Args:
        helpers: Burp helpers object
        request_bytes: Original request as byte array
        new_verb: New HTTP verb to use (e.g., 'GET', 'POST', 'PUT', 'DELETE', 'PATCH')
    
    Returns:
        Modified request as byte array
    """
    # Convert bytes to string for manipulation
    request_info = helpers.analyzeRequest(request_bytes)
    headers = request_info.getHeaders()
    body_offset = request_info.getBodyOffset()
    
    # Get the original body
    body = request_bytes[body_offset:]
    
    # Modify the first header line (contains the HTTP method)
    first_line = headers[0]
    parts = first_line.split(' ')
    
    if len(parts) >= 3:
        old_verb = parts[0]
        uri = parts[1]
        http_version = parts[2]
        
        # Create new first line with swapped verb
        new_first_line = "%s %s %s" % (new_verb, uri, http_version)
        headers[0] = new_first_line
        
        # Handle special cases when swapping verbs
        modified_headers = []
        content_length_removed = False
        
        for header in headers:
            header_lower = header.lower()
            
            # If swapping TO GET or DELETE, remove Content-Length and Content-Type
            if new_verb in ['GET', 'DELETE']:
                if header_lower.startswith('content-length:'):
                    content_length_removed = True
                    continue
                elif header_lower.startswith('content-type:') and old_verb in ['POST', 'PUT', 'PATCH']:
                    continue
            
            # If swapping FROM GET to POST/PUT/PATCH, add Content-Type if missing
            if old_verb == 'GET' and new_verb in ['POST', 'PUT', 'PATCH']:
                if not any(h.lower().startswith('content-type:') for h in headers):
                    modified_headers.append(header)
                    if header == headers[-1]:  # After last header
                        modified_headers.append('Content-Type: application/x-www-form-urlencoded')
                    continue
            
            modified_headers.append(header)
        
        # Build the new request
        if new_verb in ['GET', 'DELETE'] or content_length_removed:
            # Remove body for GET and DELETE
            new_request = helpers.buildHttpMessage(modified_headers, None)
        else:
            # Keep body for POST, PUT, PATCH
            new_request = helpers.buildHttpMessage(modified_headers, body)
        
        return new_request
    
    # If parsing failed, return original request
    return request_bytes


def get_verb_mappings():
    """
    Returns default verb swap mappings
    
    Returns:
        List of tuples containing (from_verb, to_verb) mappings
    """
    return [
        ('POST', 'GET'),
        ('PUT', 'POST'),
        ('DELETE', 'GET'),
        ('PATCH', 'GET'),
        ('GET', 'POST'),
        ('PATCH', 'POST'),
        ('DELETE', 'POST'),
        ('PUT', 'GET'),
    ]


def get_verb_from_request(helpers, request_bytes):
    """
    Extracts the HTTP verb from a request
    
    Args:
        helpers: Burp helpers object
        request_bytes: Request as byte array
    
    Returns:
        HTTP verb as string (e.g., 'GET', 'POST')
    """
    request_info = helpers.analyzeRequest(request_bytes)
    return request_info.getMethod()