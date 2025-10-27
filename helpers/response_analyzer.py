#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Response Analyzer for Autorize - IMPROVED VERSION with Clear Confidence Levels
Author: Enhanced by gs-gsanthoshini
Date: 2025-10-27
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
        "invalid token", "access forbidden", "denied",
        "please login", "authentication failed", "access violation"
    ]
    
    def __init__(self, helpers):
        self._helpers = helpers
    
    def analyze_authorization(self, original_response, modified_response):
        """
        Main analysis function - implements 2-check system with 5 confidence levels
        Returns: dict with status, confidence, reason, similarity
        """
        original_status = self._get_status_code(original_response)
        modified_status = self._get_status_code(modified_response)
        
        # CHECK 1: Status Code Analysis - Access Blocked
        if modified_status in [401, 403, 404]:
            return {
                'status': 'ENFORCED',
                'confidence': 'SECURE',
                'reason': 'Blocked with {} - Authorization working'.format(modified_status),
                'similarity': 0,
                'original_status': original_status,
                'modified_status': modified_status
            }
        
        # Server Error - Might be blocking
        if modified_status in [500, 503]:
            return {
                'status': 'ENFORCED',
                'confidence': 'ERROR',
                'reason': 'Server error {} - Might be blocking'.format(modified_status),
                'similarity': 0,
                'original_status': original_status,
                'modified_status': modified_status
            }
        
        # Both returned success codes
        if modified_status in [200, 201, 204] and original_status in [200, 201, 204]:
            
            # CHECK 2: Calculate Response Similarity
            similarity = self._calculate_similarity(original_response, modified_response)
            
            # CRITICAL: 95-100% Similar = Definite Bypass!
            if similarity >= 95:
                return {
                    'status': 'BYPASSED',
                    'confidence': 'CRITICAL',
                    'reason': 'CRITICAL: {}% identical - Definite bypass!'.format(similarity),
                    'similarity': similarity,
                    'original_status': original_status,
                    'modified_status': modified_status
                }
            
            # HIGH: 80-94% Similar = Very Likely Bypass
            elif similarity >= 80:
                return {
                    'status': 'BYPASSED',
                    'confidence': 'HIGH',
                    'reason': 'HIGH RISK: {}% similar - Likely bypass'.format(similarity),
                    'similarity': similarity,
                    'original_status': original_status,
                    'modified_status': modified_status
                }
            
            # MEDIUM: 65-79% Similar = Suspicious
            elif similarity >= 65:
                # CHECK 3: Keyword Detection
                if self._has_error_keywords(modified_response):
                    return {
                        'status': 'ENFORCED',
                        'confidence': 'SECURE',
                        'reason': 'Error keywords found; {}% similar'.format(similarity),
                        'similarity': similarity,
                        'original_status': original_status,
                        'modified_status': modified_status
                    }
                else:
                    return {
                        'status': 'BYPASSED',
                        'confidence': 'MEDIUM',
                        'reason': 'MEDIUM: {}% similar - Suspicious'.format(similarity),
                        'similarity': similarity,
                        'original_status': original_status,
                        'modified_status': modified_status
                    }
            
            # LOW: 50-64% Similar = Needs Review
            elif similarity >= 50:
                if self._has_error_keywords(modified_response):
                    return {
                        'status': 'ENFORCED',
                        'confidence': 'SECURE',
                        'reason': 'Error keywords found; {}% similar'.format(similarity),
                        'similarity': similarity,
                        'original_status': original_status,
                        'modified_status': modified_status
                    }
                else:
                    return {
                        'status': 'BYPASSED',
                        'confidence': 'LOW',
                        'reason': 'LOW: {}% similar - Needs manual review'.format(similarity),
                        'similarity': similarity,
                        'original_status': original_status,
                        'modified_status': modified_status
                    }
            
            # Less than 50% similar = Different responses = Secure
            else:
                return {
                    'status': 'ENFORCED',
                    'confidence': 'SECURE',
                    'reason': 'Only {}% similar - Properly blocked'.format(similarity),
                    'similarity': similarity,
                    'original_status': original_status,
                    'modified_status': modified_status
                }
        
        # Different status codes = Enforced
        return {
            'status': 'ENFORCED',
            'confidence': 'SECURE',
            'reason': 'Different status codes ({} vs {})'.format(original_status, modified_status),
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
        (timestamps, tokens, session IDs, UUIDs, JWTs, etc.)
        """
        if not content:
            return ""
        
        try:
            # Remove timestamps (various formats)
            content = re.sub(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(\.\d+)?Z?', 'TIMESTAMP', content)
            content = re.sub(r'\d{10,13}', 'TIMESTAMP', content)  # Unix timestamps
            
            # Remove UUIDs
            content = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID', content, flags=re.IGNORECASE)
            
            # Remove session tokens
            content = re.sub(r'(session|token|csrf|nonce|_token|authenticity_token)["\s:=]+[a-zA-Z0-9+/=_-]{20,}', 'TOKEN', content, flags=re.IGNORECASE)
            
            # Remove JWTs
            content = re.sub(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'JWT', content)
            
            # Remove request IDs
            content = re.sub(r'(request_id|requestId|trace_id|traceId)["\s:=]+[a-zA-Z0-9-]+', 'REQUEST_ID', content, flags=re.IGNORECASE)
            
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
