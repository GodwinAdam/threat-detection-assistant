import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_AUDIT_LOG_PATH = Path(__file__).parent / "audit_log.jsonl"

logger = logging.getLogger("governance")


class AIGovernanceGuard:
    def __init__(self, audit_log_path: Path | str = DEFAULT_AUDIT_LOG_PATH):
        # Patterns for API Keys, Secrets, Tokens, PII
        self.pii_patterns = [
            r"(?i)api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?",
            r"(?i)aws_?(?:access_?key_?id|secret_?access_?key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{16,}['\"]?",
            r"\bAKIA[0-9A-Z]{16}\b",
            r"(?i)bearer\s+[A-Za-z0-9\-_.]{20,}",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Emails
        ]
        self.injection_terms = [
            "ignore previous instructions",
            "ignore all previous instructions",
            "disregard previous instructions",
            "system override",
            "you are now unfiltered",
            "jailbreak",
        ]
        self.audit_log_path = Path(audit_log_path)

    # --- Access control -------------------------------------------------
    def authorize(self, caller_id: str) -> bool:
        """Checks caller_id against GOVERNANCE_ALLOWED_CALLERS (comma-separated).

        If the env var is unset, the guard is open by default — this is a
        single allow-list, not RBAC, and is meant as a hook to wire real
        identity/role checks into, not a complete access-control system.
        """
        allowed = os.environ.get("GOVERNANCE_ALLOWED_CALLERS")
        if not allowed:
            self._audit("authz_check", f"caller={caller_id!r} allowed=True (no allow-list configured)")
            return True
        allowed_ids = {c.strip() for c in allowed.split(",") if c.strip()}
        is_allowed = caller_id in allowed_ids
        self._audit("authz_check", f"caller={caller_id!r} allowed={is_allowed}")
        return is_allowed

    # --- Input / output screening ---------------------------------------
    def validate_input(self, user_prompt: str) -> tuple[bool, str]:
        normalized = self._normalize(user_prompt)

        # 1. Prompt Injection Check
        for term in self.injection_terms:
            if term in normalized:
                self._audit("input_blocked", f"matched injection term: {term!r}")
                return False, f"Governance Alert: Prompt rejected due to potential injection keyword ('{term}')."

        # 2. PII / Secret Masking
        cleaned_prompt = user_prompt
        for pattern in self.pii_patterns:
            cleaned_prompt, n = re.subn(pattern, "[REDACTED_SENSITIVE_DATA]", cleaned_prompt)
            if n:
                self._audit("input_redacted", f"pattern matched {n} time(s): {pattern}")

        return True, cleaned_prompt

    def sanitize_output(self, llm_response: str) -> str:
        # Prevent hallucinated execution commands or credentials in response
        for pattern in self.pii_patterns:
            llm_response, n = re.subn(pattern, "[REDACTED_SECRET]", llm_response)
            if n:
                self._audit("output_redacted", f"pattern matched {n} time(s): {pattern}")
        return llm_response

    # --- Auditability -----------------------------------------------------
    @staticmethod
    def _normalize(text: str) -> str:
        return re.sub(r"\s+", " ", text.lower()).strip()

    def _audit(self, event: str, detail: str) -> None:
        """Appends a structured audit entry. Never logs raw matched values —
        only the pattern/term and a count — so the audit log itself can't
        become a secondary leak of the secrets it's recording the redaction of.
        """
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "detail": detail,
        }
        try:
            with open(self.audit_log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            logger.warning("Could not write audit log entry: %s", entry)
