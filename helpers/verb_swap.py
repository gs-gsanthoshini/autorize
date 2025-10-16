#!/usr/bin/env python
# -*- coding: utf-8 -*- 

"""
Verb Swap Helper Module - IMPROVED VERSION
Handles HTTP verb/method swapping for authorization testing
Enhanced with better logging and error handling
"""

def swap_http_verb(helpers, request_bytes, new_verb):
    """
    Swaps the HTTP verb/method in a request
    
    IMPROVED VERSION with:
    - Better error handling
    - More robust header parsing
    - Support for edge cases
    
    Args:
        helpers: Burp helpers object
        request_bytes: Original request as byte array
        new_verb: New HTTP verb to use (e.g., 'GET', 'POST', 'PUT', 'DELETE', 'PATCH')
    
    Returns:
        Modified request as byte array
    """
    try:
        # Convert bytes to string for manipulation
        request_info = helpers.analyzeRequest(request_bytes)
        headers = list(request_info.getHeaders())
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
            content_type_exists = False
            
            for header in headers:
                header_lower = header.lower()
                
                # Check if Content-Type exists
                if header_lower.startswith('content-type:'):
                    content_type_exists = True
                
                # If swapping TO GET or DELETE, remove Content-Length and Content-Type
                if new_verb in ['GET', 'DELETE', 'HEAD']:
                    if header_lower.startswith('content-length:'):
                        content_length_removed = True
                        continue
                    elif header_lower.startswith('content-type:') and old_verb in ['POST', 'PUT', 'PATCH']:
                        continue
                
                modified_headers.append(header)
            
            # If swapping FROM GET/DELETE to POST/PUT/PATCH, add Content-Type if missing
            if old_verb in ['GET', 'DELETE', 'HEAD'] and new_verb in ['POST', 'PUT', 'PATCH']:
                if not content_type_exists:
                    # Add Content-Type before the empty line that separates headers from body
                    modified_headers.append('Content-Type: application/x-www-form-urlencoded')
            
            # Build the new request
            if new_verb in ['GET', 'DELETE', 'HEAD'] or content_length_removed:
                # Remove body for GET, DELETE, and HEAD
                new_request = helpers.buildHttpMessage(modified_headers, None)
            else:
                # Keep body for POST, PUT, PATCH
                new_request = helpers.buildHttpMessage(modified_headers, body)
            
            return new_request
        else:
            # If parsing failed, return original request
            print("[Verb Swap Helper] WARNING: Could not parse HTTP request line: " + first_line)
            return request_bytes
            
    except Exception as e:
        print("[Verb Swap Helper] ERROR in swap_http_verb: " + str(e))
        import traceback
        traceback.print_exc()
        return request_bytes


def get_verb_mappings():
    """
    Returns default verb swap mappings
    
    These are common patterns for testing verb tampering:
    - Try GET instead of POST (bypass forms)
    - Try POST instead of GET (add body to GET)
    - Try PUT/DELETE/PATCH as alternatives
    
    Returns:
        List of tuples containing (from_verb, to_verb) mappings
    """
    return [
        ('POST', 'GET'),
        ('POST', 'PUT'),
        ('POST', 'DELETE'),
        ('POST', 'PATCH'),
        ('GET', 'POST'),
        ('GET', 'PUT'),
        ('GET', 'DELETE'),
        ('PUT', 'GET'),
        ('PUT', 'POST'),
        ('PUT', 'DELETE'),
        ('DELETE', 'GET'),
        ('DELETE', 'POST'),
        ('PATCH', 'GET'),
        ('PATCH', 'POST'),
    ]


def get_verb_from_request(helpers, request_bytes):
    """
    Extracts the HTTP verb from a request
    
    IMPROVED VERSION with error handling
    
    Args:
        helpers: Burp helpers object
        request_bytes: Request as byte array
    
    Returns:
        HTTP verb as string (e.g., 'GET', 'POST')
        Returns 'UNKNOWN' if parsing fails
    """
    try:
        request_info = helpers.analyzeRequest(request_bytes)
        return request_info.getMethod()
    except Exception as e:
        print("[Verb Swap Helper] ERROR in get_verb_from_request: " + str(e))
        return "UNKNOWN"


def is_verb_swap_likely_to_succeed(original_verb, target_verb, url_string):
    """
    Predicts if a verb swap is likely to succeed based on common patterns
    
    NEW FUNCTION - helps prioritize which verbs to test
    
    Args:
        original_verb: Original HTTP method
        target_verb: Target HTTP method to test
        url_string: URL being tested
    
    Returns:
        Boolean indicating if swap is likely to work
    """
    # Admin/delete/remove operations often vulnerable to GET
    admin_keywords = ['admin', 'delete', 'remove', 'destroy', 'drop']
    if target_verb == 'GET' and any(keyword in url_string.lower() for keyword in admin_keywords):
        return True
    
    # APIs often accept multiple verbs
    if '/api/' in url_string.lower():
        return True
    
    # RESTful endpoints are good candidates
    if original_verb in ['POST', 'PUT', 'PATCH'] and target_verb in ['GET', 'PUT', 'PATCH', 'DELETE']:
        return True
    
    return False


def get_recommended_verbs_to_test(original_verb, url_string):
    """
    Returns a prioritized list of verbs to test based on the original verb and URL
    
    NEW FUNCTION - smart testing order
    
    Args:
        original_verb: Original HTTP method
        url_string: URL being tested
    
    Returns:
        List of verbs to test, in priority order
    """
    all_verbs = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
    recommended = []
    
    # Remove original verb
    all_verbs = [v for v in all_verbs if v != original_verb]
    
    # If it's a POST, GET is highest priority
    if original_verb == 'POST':
        recommended.extend(['GET', 'PUT', 'DELETE', 'PATCH'])
    
    # If it's a GET, POST is highest priority
    elif original_verb == 'GET':
        recommended.extend(['POST', 'PUT', 'DELETE'])
    
    # For PUT, try PATCH and POST
    elif original_verb == 'PUT':
        recommended.extend(['PATCH', 'POST', 'GET', 'DELETE'])
    
    # For DELETE, try GET (dangerous if works!)
    elif original_verb == 'DELETE':
        recommended.extend(['GET', 'POST', 'PUT'])
    
    # Add any remaining verbs
    for verb in all_verbs:
        if verb not in recommended:
            recommended.append(verb)
    
    return recommended


def format_verb_swap_result(original_verb, tested_verbs, bypassed_verbs):
    """
    Formats the verb swap test results into a readable string
    
    NEW FUNCTION - better result formatting
    
    Args:
        original_verb: Original HTTP method
        tested_verbs: List of verbs that were tested
        bypassed_verbs: List of verbs that resulted in bypasses
    
    Returns:
        Formatted string describing results
    """
    if len(bypassed_verbs) == 0:
        return "None (all %d verbs blocked)" % len(tested_verbs)
    else:
        return "🚨 " + ", ".join(bypassed_verbs) + " (%d/%d bypassed)" % (len(bypassed_verbs), len(tested_verbs))


# Export commonly used functions
__all__ = [
    'swap_http_verb',
    'get_verb_from_request',
    'get_verb_mappings',
    'is_verb_swap_likely_to_succeed',
    'get_recommended_verbs_to_test',
    'format_verb_swap_result'
]
