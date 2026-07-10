"""Tests for server wiring: tool registration metadata and the health route."""

import asyncio
import os
import socket
import subprocess
import sys

import httpx
import pytest
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


async def test_triage_prompt_is_registered():
    async with Client(mcp) as client:
        prompts = await client.list_prompts()
        prompt = next((p for p in prompts if p.name == "monthly_triage"), None)
        assert prompt is not None
        assert prompt.title == "Monthly Patch Tuesday Triage"
        arg_names = {a.name for a in (prompt.arguments or [])}
        assert {"product_profile", "month"} <= arg_names


async def test_triage_prompt_renders_workflow_with_scope():
    async with Client(mcp) as client:
        result = await client.get_prompt(
            "monthly_triage", {"product_profile": "identity-core"}
        )
        text = result.messages[0].content.text
        # Single-tool workflow with the profile threaded into the example calls.
        assert "msrc_search" in text
        assert 'product_profile="identity-core"' in text
        # Covers the required analyst workflow sections.
        for needle in ("Publicly disclosed", "KEV", "exploited", "Endpoint"):
            assert needle in text


async def test_triage_prompt_defaults_to_whole_release():
    async with Client(mcp) as client:
        result = await client.get_prompt("monthly_triage", {})
        text = result.messages[0].content.text
        assert "whole release" in text
        # No dangling profile argument when none is supplied.
        assert "product_profile=" not in text


# --- main() transport bootstrap ---------------------------------------------
#
# main()'s HTTP branch composes the real middleware stack (CORS -> rate limit
# -> body limit -> MCP app) and hands it to uvicorn.run. We patch uvicorn.run
# to capture that composed app instead of blocking, then drive it through
# httpx so the actual wiring is exercised end to end.


def _capture_http_app(monkeypatch, **env) -> object:
    """Run server.main() in HTTP mode, capturing the composed ASGI app."""
    import uvicorn

    captured: dict = {}

    def fake_run(app, host=None, port=None, log_level=None):
        captured["app"] = app

    monkeypatch.setattr(uvicorn, "run", fake_run)
    monkeypatch.setenv("MCP_TRANSPORT", "http")
    monkeypatch.delenv("APPLICATIONINSIGHTS_CONNECTION_STRING", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, str(value))
    server.main()
    assert "app" in captured, "main() did not invoke uvicorn.run in HTTP mode"
    return captured["app"]


async def test_main_http_serves_health_through_full_stack(monkeypatch):
    app = _capture_http_app(
        monkeypatch,
        RATE_LIMIT_RPM=0,  # transparent so /health is deterministic
        MCP_MAX_BODY_BYTES=50,
        MCP_CORS_ORIGINS="https://triage.example.com",
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Health route reachable through CORS + body-limit wrappers.
        health = await client.get("/health")
        assert health.status_code == 200
        assert health.json()["version"] == __version__

        # Body-limit middleware from main() rejects an oversized POST.
        too_big = await client.post("/mcp", content=b"x" * 200)
        assert too_big.status_code == 413

        # CORS allowlist from main() is honored on a preflight.
        preflight = await client.options(
            "/mcp",
            headers={
                "Origin": "https://triage.example.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert preflight.headers.get("access-control-allow-origin") == (
            "https://triage.example.com"
        )


async def test_main_http_enforces_rate_limit(monkeypatch):
    app = _capture_http_app(
        monkeypatch,
        RATE_LIMIT_RPM=1,
        MCP_MAX_BODY_BYTES=50,
        MCP_TRUST_X_FORWARDED_FOR="false",  # exercise the direct-peer-only branch
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Oversized bodies never reach the MCP app: the first is allowed by the
        # limiter then rejected for size (413); the second is rate limited (429).
        first = await client.post("/mcp", content=b"x" * 200)
        second = await client.post("/mcp", content=b"x" * 200)
    assert first.status_code == 413
    assert second.status_code == 429


def test_main_stdio_is_default_transport(monkeypatch):
    monkeypatch.delenv("MCP_TRANSPORT", raising=False)
    captured: dict = {}

    def fake_run(transport=None, show_banner=None):
        captured["transport"] = transport

    monkeypatch.setattr(server.mcp, "run", fake_run)
    server.main()
    assert captured["transport"] == "stdio"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_http_server_subprocess_end_to_end_mcp_call():
    """Boot the real HTTP transport in a subprocess and make a live MCP call."""
    port = _free_port()
    env = os.environ.copy()
    env.update(
        {
            "MCP_TRANSPORT": "http",
            "MCP_HOST": "127.0.0.1",
            "MCP_PORT": str(port),
            "RATE_LIMIT_RPM": "0",
            "PYTHONIOENCODING": "utf-8",
        }
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", "from patch_tuesday_mcp.server import main; main()"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        # Wait for the server to accept connections and report healthy.
        async with httpx.AsyncClient(base_url=base) as probe:
            for _ in range(60):
                if proc.poll() is not None:
                    out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
                    pytest.fail(f"server exited early (code {proc.returncode}):\n{out}")
                try:
                    resp = await probe.get("/health", timeout=1.0)
                    if resp.status_code == 200 and resp.json()["status"] == "ok":
                        break
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.5)
            else:
                pytest.fail("HTTP server did not become healthy in time")

        # A genuine MCP handshake over real HTTP against the running server.
        async with Client(f"{base}/mcp") as client:
            tools = await client.list_tools()
            assert any(t.name == "msrc_search" for t in tools)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
