"""Shared httpx AsyncClient so feeds reuse connections.

Supersedence chain walks issue up to ~30 sequential requests to the same
hosts; a per-request client would pay a fresh TLS handshake for each.
"""

import asyncio

import httpx

_client: httpx.AsyncClient | None = None
_client_loop: asyncio.AbstractEventLoop | None = None


def get_client() -> httpx.AsyncClient:
    """Return the shared client, creating it lazily.

    Recreated if the running event loop changed (connections are bound to the
    loop they were opened on), which only happens across test cases.
    """
    global _client, _client_loop
    loop = asyncio.get_running_loop()
    if _client is None or _client.is_closed or _client_loop is not loop:
        _client = httpx.AsyncClient(
            follow_redirects=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
        _client_loop = loop
    return _client
