"""Wazuh AI SOC Lab Lesson 5 — MCP server abuse harness.

5-pattern adversarial test suite. The student's MCP server must pass all 5.

Tests speak raw JSON-RPC 2.0 over stdio against the server. Configure via
the MCP_SERVER_CMD env var, e.g.:

    export MCP_SERVER_CMD="python -m my_wazuh_mcp"
    pytest tests/abuse/

The harness spec is MCP 2025-06-18.
"""
