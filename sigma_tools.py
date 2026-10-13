import logging
import re

import yaml

logger = logging.getLogger("sigma_tools")

MAX_RULE_SIZE = 50_000  # chars — guards against oversized/abusive payloads


def parse_sigma_rule(rule_yaml_str: str) -> dict:
    """Parses a raw YAML Sigma Rule and extracts detection logic & metadata."""
    if len(rule_yaml_str) > MAX_RULE_SIZE:
        return {"error": "Rule exceeds maximum allowed size", "status_code": 413}
    try:
        rule = yaml.safe_load(rule_yaml_str)
        if not isinstance(rule, dict):
            return {"error": "Rule did not parse to a mapping", "status_code": 400}
        result = {
            "title": rule.get("title", "Unknown"),
            "status": rule.get("status", "experimental"),
            "tags": rule.get("tags", []),
            "detection": rule.get("detection", {}),
            "status_code": 200,
        }
        logger.info("parse_sigma_rule ok title=%r tags=%s", result["title"], result["tags"])
        return result
    except yaml.YAMLError as e:
        logger.warning("parse_sigma_rule failed: %s", e)
        return {"error": str(e), "status_code": 400}


def calculate_coverage_gap(detected_techniques: list[str], target_framework: list[str]) -> dict:
    """Compares currently covered techniques against a baseline list to identify gaps."""
    detected_set = {t.upper() for t in detected_techniques}
    target_set = {t.upper() for t in target_framework}

    missing = sorted(target_set - detected_set)
    covered = sorted(detected_set & target_set)
    coverage_pct = round((len(covered) / len(target_set)) * 100, 2) if target_set else 0.0

    result = {
        "covered_techniques": covered,
        "missing_techniques": missing,
        "coverage_percentage": f"{coverage_pct}%",
    }
    logger.info("calculate_coverage_gap covered=%s missing=%s", covered, missing)
    return result


def normalize_sigma_tag_to_technique_id(tag: str) -> str | None:
    """Converts a Sigma ATT&CK tag like 'attack.t1059.001' into 'T1059.001'."""
    match = re.match(r"attack\.t(\d{4}(?:\.\d{3})?)", tag.strip().lower())
    if not match:
        return None
    return f"T{match.group(1)}"
