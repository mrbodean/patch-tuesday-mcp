"""Tests for server wiring: tool registration metadata and the health route."""

import logging

import httpx
from fastmcp import Client

from patch_tuesday_mcp import __version__, server
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


def test_cors_origins_defaults_to_all(monkeypatch):
    monkeypatch.delenv("MCP_CORS_ORIGINS", raising=False)
    assert server._cors_origins() == ["*"]


def test_cors_origins_parses_allowlist(monkeypatch):
    monkeypatch.setenv("MCP_CORS_ORIGINS", "https://a.example.com, https://b.example.com")
    assert server._cors_origins() == ["https://a.example.com", "https://b.example.com"]


def test_cors_origins_blank_falls_back_to_all(monkeypatch):
    monkeypatch.setenv("MCP_CORS_ORIGINS", "   ")
    assert server._cors_origins() == ["*"]


def test_trusted_proxies_parsing(monkeypatch):
    monkeypatch.delenv("MCP_TRUSTED_PROXIES", raising=False)
    assert server._trusted_proxies() == frozenset()
    monkeypatch.setenv("MCP_TRUSTED_PROXIES", "10.0.0.1, 10.0.0.2 ,")
    assert server._trusted_proxies() == frozenset({"10.0.0.1", "10.0.0.2"})


def test_env_flag_parsing(monkeypatch):
    monkeypatch.delenv("MCP_TRUST_X_FORWARDED_FOR", raising=False)
    assert server._env_flag("MCP_TRUST_X_FORWARDED_FOR", True) is True
    assert server._env_flag("MCP_TRUST_X_FORWARDED_FOR", False) is False
    for truthy in ("1", "true", "YES", "On"):
        monkeypatch.setenv("MCP_TRUST_X_FORWARDED_FOR", truthy)
        assert server._env_flag("MCP_TRUST_X_FORWARDED_FOR", False) is True
    for falsy in ("0", "false", "no", "off"):
        monkeypatch.setenv("MCP_TRUST_X_FORWARDED_FOR", falsy)
        assert server._env_flag("MCP_TRUST_X_FORWARDED_FOR", True) is False


def test_uvicorn_limits_defaults(monkeypatch):
    monkeypatch.delenv("MCP_LIMIT_CONCURRENCY", raising=False)
    monkeypatch.delenv("MCP_TIMEOUT_KEEP_ALIVE", raising=False)
    assert server._uvicorn_limits() == {"limit_concurrency": 40, "timeout_keep_alive": 15}


def test_uvicorn_limits_env_overrides(monkeypatch):
    monkeypatch.setenv("MCP_LIMIT_CONCURRENCY", "100")
    monkeypatch.setenv("MCP_TIMEOUT_KEEP_ALIVE", "5")
    assert server._uvicorn_limits() == {"limit_concurrency": 100, "timeout_keep_alive": 5}


def test_uvicorn_limits_zero_disables_concurrency_cap(monkeypatch):
    monkeypatch.setenv("MCP_LIMIT_CONCURRENCY", "0")
    assert server._uvicorn_limits()["limit_concurrency"] is None


def test_log_level_env(monkeypatch):
    monkeypatch.delenv("MCP_LOG_LEVEL", raising=False)
    assert server._log_level() == logging.WARNING
    monkeypatch.setenv("MCP_LOG_LEVEL", "debug")
    assert server._log_level() == logging.DEBUG
    monkeypatch.setenv("MCP_LOG_LEVEL", "bogus")
    assert server._log_level() == logging.WARNING


async def test_lifespan_shutdown_closes_shared_client(monkeypatch):
    closed = []

    async def fake_aclose():
        closed.append(True)

    monkeypatch.setattr(server.http_client, "aclose", fake_aclose)

    async def app(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    wrapped = server._ClientCleanup(app)
    messages = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    await wrapped({"type": "lifespan"}, receive, send)
    assert closed == [True], "shared httpx client must be closed on shutdown"
    assert {"type": "lifespan.shutdown.complete"} in sent
