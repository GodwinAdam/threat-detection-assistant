from mcp.server.mcpserver import MCPServer

from sigma_tools import calculate_coverage_gap as _calculate_coverage_gap
from sigma_tools import parse_sigma_rule as _parse_sigma_rule

# In v2.x, FastMCP is renamed to MCPServer
mcp = MCPServer("Threat-Detection-MCP")


@mcp.tool()
def parse_sigma_rule(rule_yaml_str: str) -> dict:
    """Parses a raw YAML Sigma Rule and extracts detection logic & metadata."""
    return _parse_sigma_rule(rule_yaml_str)


@mcp.tool()
def calculate_coverage_gap(detected_techniques: list[str], target_framework: list[str]) -> dict:
    """Compares currently covered techniques against a baseline list to identify gaps."""
    return _calculate_coverage_gap(detected_techniques, target_framework)


if __name__ == "__main__":
    mcp.run()
