"""Request body size limiting for the HTTP transport.

A public MCP endpoint parses JSON-RPC bodies from anyone; without a cap, a
single oversized POST could exhaust container memory. Legitimate msrc_search
calls are well under a kilobyte.
"""

import json

DEFAULT_MAX_BODY_BYTES = 256 * 1024


class BodyLimitMiddleware:
    """ASGI middleware rejecting request bodies over max_bytes with 413.

    Rejects early on the declared Content-Length when present. Otherwise the
    body is buffered (bounded by max_bytes) and replayed to the app, so
    chunked uploads cannot dodge the cap and oversized requests are rejected
    cleanly before the app starts processing.
    """

    def __init__(self, app, max_bytes: int = DEFAULT_MAX_BODY_BYTES, on_rejected=None):
        self.app = app
        self.max_bytes = max_bytes
        # Optional callback invoked with the request path on each 413, so
        # rejections are observable in telemetry
        self.on_rejected = on_rejected

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.max_bytes <= 0:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        declared = next(
            (v for k, v in scope.get("headers", []) if k.lower() == b"content-length"),
            b"",
        ).decode("latin-1")
        if declared.isdigit() and int(declared) > self.max_bytes:
            await self._send_413(send, path)
            return

        # Buffer the request body (bounded by max_bytes) so the limit holds
        # even without a trustworthy Content-Length header
        messages = []
        received = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] != "http.request":
                break  # http.disconnect: hand through to the app
            received += len(message.get("body", b""))
            if received > self.max_bytes:
                await self._send_413(send, path)
                return
            if not message.get("more_body"):
                break

        async def replay():
            if messages:
                return messages.pop(0)
            return await receive()

        await self.app(scope, replay, send)

    async def _send_413(self, send, path: str = "") -> None:
        if self.on_rejected is not None:
            self.on_rejected(path)
        body = json.dumps({"error": "request body too large"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
