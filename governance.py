import re

class AIGovernanceGuard:
    def __init__(self):
        # Patterns for API Keys, Passwords, Injection phrases
        self.pii_patterns = [
            r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"  # Emails
        ]
        self.injection_terms = [
            "ignore previous instructions",
            "system override",
            "you are now unfiltered",
            "jailbreak"
        ]

    def validate_input(self, user_prompt: str) -> tuple[bool, str]:
        # 1. Prompt Injection Check
        for term in self.injection_terms:
            if term in user_prompt.lower():
                return False, f"Governance Alert: Prompt rejected due to potential injection keyword ('{term}')."
        
        # 2. PII / Secret Masking
        cleaned_prompt = user_prompt
        for pattern in self.pii_patterns:
            cleaned_prompt = re.sub(pattern, "[REDACTED_SENSITIVE_DATA]", cleaned_prompt)
            
        return True, cleaned_prompt

    def sanitize_output(self, llm_response: str) -> str:
        # Prevent hallucinated execution commands or credentials in response
        for pattern in self.pii_patterns:
            llm_response = re.sub(pattern, "[REDACTED_SECRET]", llm_response)
        return llm_response