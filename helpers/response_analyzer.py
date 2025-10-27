#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Response Analyzer for Autorize
Implements fully automatic two-check system to reduce false positives
No manual review needed - code decides everything automatically
"""

import re
from difflib import SequenceMatcher

class ResponseAnalyzer:
    
    # Error keywords that indicate authorization is enforced
    ERROR_KEYWORDS = [
        "unauthorized", "forbidden", "access denied",
        "not allowed", "permission denied", "not authorized",
        "insufficient privileges", "access restricted",
        "login required", "authentication required",
        "you don't have permission", "not permitted",
        "invalid token", "access forbidden", "denied"
    ]
    
    def __init__(self, helpers):
        self._helpers = helpers
    
    def analyze_authorization(self, original_response, modified_response):
        """
        Main analysis function - implements 2-check system
        Returns: dict with status, confidence, reason, similarity
        """
        # Extract status codes
        original_status = self._get_status_code(original_response)
        modified_status = self._get_status_code(modified_response)
        
        # CHECK 1: Status Code Analysis (Fast Check)
        if modified_status in [401, 403, 404, 500, 503]:
            return {
                'status': 'ENFORCED',
                'confidence': 'HIGH',
                'reason': 'Modified returned {} - Access blocked'.format(modified_status),
                'similarity': 0,
                'original_status': original_status,
                'modified_status': modified_status
            }
        
        # Both returned success codes
        if modified_status in [200, 201, 204] and original_status in [200, 201, 204]:
            
            # CHECK 2: Calculate Response Similarity
            similarity = self._calculate_similarity(original_response, modified_response)
            
            # High Similarity (>= 80%) = Clear Bypass
            if similarity >= 80:
                return {
                    'status': 'BYPASSED',
                    'confidence': 'HIGH',
                    'reason': 'Both returned {}; {}% similar content'.format(modified_status, similarity),
                    'similarity': similarity,
                    'original_status': original_status,
                    'modified_status': modified_status
                }
            
            # Medium Similarity (50-79%) - Check for error keywords
            elif similarity >= 50:
                # CHECK 3: Automatic Keyword Detection
                if self._has_error_keywords(modified_response):
                    return {
                        'status': 'ENFORCED',
                        'confidence': 'HIGH',
                        'reason': 'Error keywords found; {}% similar'.format(similarity),
                        'similarity': similarity,
                        'original_status': original_status,
                        'modified_status': modified_status
                    }
                else:
                    # No error keywords, still similar = Suspicious Bypass
                    return {
                        'status': 'BYPASSED',
                        'confidence': 'MEDIUM',
                        'reason': 'Both returned {}; {}% similar; No blocking detected'.format(modified_status, similarity),
                        'similarity': similarity,
                        'original_status': original_status,
                        'modified_status': modified_status
                    }
            
            # Low Similarity (< 50%) = Different responses = Enforced
            else:
                return {
                    'status': 'ENFORCED',
                    'confidence': 'HIGH',
                    'reason': 'Only {}% similar - Different responses'.format(similarity),
                    'similarity': similarity,
                    'original_status': original_status,
                    'modified_status': modified_status
                }
        
        # Different status codes = Enforced
        return {
            'status': 'ENFORCED',
            'confidence': 'HIGH',
            'reason': 'Status codes differ ({} vs {})'.format(original_status, modified_status),
            'similarity': 0,
            'original_status': original_status,
            'modified_status': modified_status
        }
    
    def _get_status_code(self, response):
        """Extract HTTP status code from response"""
        try:
            if response:
                response_info = self._helpers.analyzeResponse(response.getResponse())
                status_line = str(response_info.getHeaders()[0])
                # Extract status code (e.g., "HTTP/1.1 200 OK" -> 200)
                match = re.search(r'\s(\d{3})\s', status_line)
                if match:
                    return int(match.group(1))
            return 0
        except:
            return 0
    
    def _calculate_similarity(self, original_response, modified_response):
        """
        Calculate similarity percentage between two responses
        Returns: 0-100 (percentage)
        """
        try:
            # Get response bodies
            original_body = self._get_response_body(original_response)
            modified_body = self._get_response_body(modified_response)
            
            # Remove dynamic content before comparison
            original_clean = self._remove_dynamic_content(original_body)
            modified_clean = self._remove_dynamic_content(modified_body)
            
            # Calculate similarity using SequenceMatcher
            similarity = SequenceMatcher(None, original_clean, modified_clean).ratio()
            
            return int(similarity * 100)
        except:
            return 0
    
    def _get_response_body(self, response):
        """Extract response body as string"""
        try:
            if response:
                response_bytes = response.getResponse()
                response_info = self._helpers.analyzeResponse(response_bytes)
                body_offset = response_info.getBodyOffset()
                body_bytes = response_bytes[body_offset:]
                return self._helpers.bytesToString(body_bytes)
            return ""
        except:
            return ""
    
    def _remove_dynamic_content(self, content):
        """
        Remove dynamic content that changes between requests
        (timestamps, tokens, session IDs, etc.)
        """
        if not content:
            return ""
        
        try:
            # Remove timestamps (various formats)
            content = re.sub(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}', 'TIMESTAMP', content)
            content = re.sub(r'\d{10,13}', 'TIMESTAMP', content)  # Unix timestamps
            
            # Remove UUIDs
            content = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID', content, flags=re.IGNORECASE)
            
            # Remove session tokens (common patterns)
            content = re.sub(r'(session|token|csrf|nonce)["\s:=]+[a-zA-Z0-9+/=]{20,}', 'TOKEN', content, flags=re.IGNORECASE)
            
            # Remove JWTs
            content = re.sub(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'JWT', content)
            
            return content
        except:
            return content
    
    def _has_error_keywords(self, response):
        """
        Check if response contains error keywords indicating access is blocked
        Returns: True if error keywords found
        """
        try:
            body = self._get_response_body(response).lower()
            
            for keyword in self.ERROR_KEYWORDS:
                if keyword in body:
                    return True
            
            return False
        except:
            return False
