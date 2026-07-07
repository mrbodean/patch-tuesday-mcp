"""Tests for server wiring: tool registration metadata and the health route."""

import httpx
from fastmcp import Client

from patch_tuesday_mcp import __version__
from patch_tuesday_mcp.server import mcp


async def test_tool_metadata_and_schema():
    async with Client(mcp) as client:
        tools = await client.list_tools()
        tool = next(t for t in tools if t.name == "msrc_search")

        assert tool.title == "Search Microsoft Security Updates"
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.idempotentHint is True
        assert tool.annotations.openWorldHint is True

        limit_schema = tool.inputSchema["properties"]["limit"]
        assert limit_schema["maximum"] == 100
        assert limit_schema["minimum"] == 0
        assert tool.inputSchema["properties"]["offset"]["minimum"] == 0


async def test_health_route():
    app = mcp.http_app(stateless_http=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__
