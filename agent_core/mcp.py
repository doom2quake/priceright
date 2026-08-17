"""Model Context Protocol (MCP) helpers.

Two directions, both optional and gracefully degrading:
  * `mcp_toolset(...)` lets an agent *consume* its tools from a stdio MCP server
    (returns an ADK `McpToolset`, or None if MCP isn't installed / is disabled),
    so tools can be served out-of-process without the core hard-depending on it.
  * `serve_stdio(tools, name)` *serves* a list of plain functions as an MCP
    stdio server (used by an app's `python -m app.mcp_server` entry point).

Install the extra: `pip install 'agent-core[mcp]'`.

Schema compatibility. ADK has moved where a function declaration keeps its
parameter schema: google-adk 2.7.1 fills `parameters_json_schema` and leaves
`parameters` as None, older releases do the opposite. `tool_input_schema` reads
whichever is present and always returns a JSON-Schema object, so a parameterised
tool served over MCP advertises its arguments instead of an empty schema.
`tests/test_mcp.py` pins both shapes against the installed ADK.
"""

from __future__ import annotations

import inspect
import os
import sys
from typing import Callable, Optional, Sequence


def _enabled(env_flag: str) -> bool:
    return os.getenv(env_flag, "").strip().lower() in {"1", "true", "yes", "on"}


def mcp_toolset(
    server_module: str,
    *,
    tool_filter: Optional[Sequence[str]] = None,
    env_flag: str = "AGENT_MCP_TOOLS",
):
    """Return an ADK McpToolset backed by a stdio MCP server, or None.

    Launches `python -m <server_module>` as a stdio MCP server and exposes its
    tools to the agent. Enabled via `env_flag`. Degrades to None (so the agent
    falls back to in-process function tools) if `mcp` isn't installed or anything
    goes wrong - the working core never hard-depends on it.
    """
    if not _enabled(env_flag):
        return None
    try:
        from google.adk.tools.mcp_tool import McpToolset
        from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
        from mcp import StdioServerParameters

        return McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(command=sys.executable, args=["-m", server_module])
            ),
            tool_filter=list(tool_filter) if tool_filter else None,
        )
    except Exception as exc:  # pragma: no cover - optional path
        print(f"[agent-core] MCP toolset unavailable ({exc}); using in-process tools.")
        return None


_EMPTY_SCHEMA = {"type": "object", "properties": {}}


def _jsonify_schema(node):
    """Convert a genai `Schema.model_dump()` into JSON Schema.

    ADK's older declaration shape returns a `google.genai.types.Schema`, whose
    dumped `type` values are enum names ("OBJECT", "STRING") and whose keys use
    snake_case. MCP clients expect JSON Schema, so lower-case the types and
    rename the handful of keys that differ. Unknown keys pass through.
    """
    if isinstance(node, list):
        return [_jsonify_schema(v) for v in node]
    if not isinstance(node, dict):
        return node
    out = {}
    for key, value in node.items():
        if value is None:
            continue
        if key == "type" and isinstance(value, str):
            out["type"] = value.lower()
        elif key == "any_of":
            out["anyOf"] = _jsonify_schema(value)
        elif key == "property_ordering":
            continue
        else:
            out[key] = _jsonify_schema(value)
    return out


def tool_input_schema(function_tool) -> dict:
    """JSON Schema for an ADK `FunctionTool`'s parameters.

    google-adk moved the declaration's parameter schema: current versions
    (verified on google-adk 2.7.1) populate `parameters_json_schema` and leave
    `parameters` as None, while older ones populate `parameters` with a genai
    `Schema`. Reading only `parameters` yields an empty MCP input schema, which
    makes every parameterised tool unusable over MCP, so both shapes are handled
    and the result is always a JSON-Schema object.
    """
    if function_tool is None:
        return dict(_EMPTY_SCHEMA)
    try:
        decl = function_tool._get_declaration()
    except Exception:
        return dict(_EMPTY_SCHEMA)
    if decl is None:
        return dict(_EMPTY_SCHEMA)

    schema = getattr(decl, "parameters_json_schema", None)
    if isinstance(schema, dict) and schema:
        out = dict(schema)
    else:
        params = getattr(decl, "parameters", None)
        if params is None:
            return dict(_EMPTY_SCHEMA)
        dumped = params.model_dump(exclude_none=True) if hasattr(params, "model_dump") else params
        out = _jsonify_schema(dumped) if isinstance(dumped, dict) else {}

    if not out:
        return dict(_EMPTY_SCHEMA)
    out.setdefault("type", "object")
    out.setdefault("properties", {})
    return out


def serve_stdio(tools: Sequence[Callable], name: str = "agent-core-tools") -> None:
    """Serve `tools` (plain functions) as an MCP stdio server. Blocks.

    Minimal wrapper: converts each function to an MCP tool via ADK's adapter and
    runs a stdio server. Call from an app's `if __name__ == "__main__":` guard.
    """
    import asyncio

    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent

    try:
        from google.adk.tools.function_tool import FunctionTool
    except Exception:  # pragma: no cover
        FunctionTool = None  # type: ignore

    server = Server(name)
    wrapped = {t.__name__: (FunctionTool(t) if FunctionTool else None, t) for t in tools}

    @server.list_tools()
    async def _list():  # noqa: ANN202
        from mcp.types import Tool

        out = []
        for fname, (ft, raw) in wrapped.items():
            out.append(Tool(name=fname, description=(raw.__doc__ or fname).strip(),
                            inputSchema=tool_input_schema(ft)))
        return out

    @server.call_tool()
    async def _call(tool_name: str, arguments: dict):  # noqa: ANN202
        entry = wrapped.get(tool_name)
        if entry is None:
            return [TextContent(type="text", text=f"unknown tool {tool_name!r}")]
        _, raw = entry
        try:
            result = raw(**(arguments or {}))
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:
            # One bad call must not take the stdio server down.
            return [TextContent(type="text", text=f"tool error: {exc.__class__.__name__}: {exc}")]
        return [TextContent(type="text", text=str(result))]

    async def _run():
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(_run())
