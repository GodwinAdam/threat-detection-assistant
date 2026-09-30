import yaml
from mcp.server.mcpserver import MCPServer

# In v2.x, FastMCP is renamed to MCPServer
mcp = MCPServer("Threat-Detection-MCP")

@mcp.tool()
def parse_sigma_rule(rule_yaml_str: str) -> dict:
    """Parses a raw YAML Sigma Rule and extracts detection logic & metadata."""
    try:
        rule = yaml.safe_load(rule_yaml_str)
        return {
            "title": rule.get("title", "Unknown"),
            "status": rule.get("status", "experimental"),
            "tags": rule.get("tags", []),
            "detection": rule.get("detection", {}),
            "status_code": 200
        }
    except Exception as e:
        return {"error": str(e), "status_code": 400}

@mcp.tool()
def calculate_coverage_gap(detected_techniques: list[str], target_framework: list[str]) -> dict:
    """Compares currently covered techniques against a baseline list to identify gaps."""
    detected_set = set(detected_techniques)
    target_set = set(target_framework)
    
    missing = list(target_set - detected_set)
    coverage_pct = round((len(detected_set & target_set) / len(target_set)) * 100, 2) if target_set else 0
    
    return {
        "covered_techniques": list(detected_set & target_set),
        "missing_techniques": missing,
        "coverage_percentage": f"{coverage_pct}%"
    }

if __name__ == "__main__":
    mcp.run()