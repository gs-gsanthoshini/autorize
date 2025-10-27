import re
from difflib import SequenceMatcher

class ResponseAnalyzer:
    ERROR_KEYWORDS = ["unauthorized", "forbidden", "access denied"]

    def analyze_authorization(self, response):
        if any(keyword in response.lower() for keyword in self.ERROR_KEYWORDS):
            return False
        return True

    def calculate_similarity(self, text1, text2):
        return SequenceMatcher(None, text1, text2).ratio()