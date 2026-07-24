from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcp_aauth import DualAuthMiddleware, dual_authentication


def recording_authentication(
    name: str, calls: list[str], *, allow: bool = True
) -> Callable[[ASGIApp], ASGIApp]:
    def factory(app: ASGIApp) -> ASGIApp:
        async def authenticate(scope: Scope, receive: Receive, send: Send) -> None:
            calls.append(name)
            if allow:
                await app(scope, receive, send)
                return

            await send({"type": "http.response.start", "status": 401, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        return authenticate

    return factory


async def invoke(
    app: ASGIApp,
    headers: list[tuple[bytes, bytes]],
) -> list[Message]:
    messages: list[Message] = []
    request_sent = False

    async def receive() -> Message:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        messages.append(message)

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "server": ("example.com", 443),
        "client": ("127.0.0.1", 1234),
    }
    await app(scope, receive, send)
    return messages


@pytest.fixture
def downstream() -> ASGIApp:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"mcp"})

    return app


@pytest.mark.asyncio
async def test_bearer_credentials_use_only_oauth(downstream: ASGIApp) -> None:
    calls: list[str] = []
    app = DualAuthMiddleware(
        downstream,
        oauth_authentication=recording_authentication("oauth", calls),
        aauth_authentication=recording_authentication("aauth", calls),
    )
    messages = await invoke(app, [(b"authorization", b"Bearer token")])
    assert calls == ["oauth"]
    assert messages[0]["status"] == 200


@pytest.mark.asyncio
async def test_signature_credentials_use_only_aauth(downstream: ASGIApp) -> None:
    calls: list[str] = []
    app = DualAuthMiddleware(
        downstream,
        oauth_authentication=recording_authentication("oauth", calls),
        aauth_authentication=recording_authentication("aauth", calls),
    )
    messages = await invoke(app, [(b"signature-input", b'sig1=("@method")')])
    assert calls == ["aauth"]
    assert messages[0]["status"] == 200


@pytest.mark.asyncio
async def test_selected_authenticator_can_reject_request(
    downstream: ASGIApp,
) -> None:
    calls: list[str] = []
    app = DualAuthMiddleware(
        downstream,
        oauth_authentication=recording_authentication("oauth", calls, allow=False),
        aauth_authentication=recording_authentication("aauth", calls),
    )
    messages = await invoke(app, [(b"authorization", b"Bearer invalid")])
    assert calls == ["oauth"]
    assert messages[0]["status"] == 401


@pytest.mark.asyncio
async def test_missing_credentials_returns_both_challenges(
    downstream: ASGIApp,
) -> None:
    calls: list[str] = []
    app = DualAuthMiddleware(
        downstream,
        oauth_authentication=recording_authentication("oauth", calls),
        aauth_authentication=recording_authentication("aauth", calls),
        resource_metadata_url="https://example.com/.well-known/oauth-protected-resource",
    )
    messages = await invoke(app, [])
    assert calls == []
    assert messages[0]["status"] == 401
    headers = dict(messages[0]["headers"])
    assert headers[b"www-authenticate"] == (
        b'Bearer error="invalid_token", '
        b'error_description="Authentication required", '
        b'resource_metadata="https://example.com/.well-known/'
        b'oauth-protected-resource"'
    )
    assert headers[b"aauth-requirement"] == b"requirement=agent-token"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "error_code"),
    [
        (
            [(b"authorization", b"Bearer token"), (b"signature", b"sig1=:abc=:")],
            "mixed_credentials",
        ),
        (
            [
                (b"authorization", b"Bearer one"),
                (b"authorization", b"Bearer two"),
            ],
            "multiple_authorization_headers",
        ),
    ],
)
async def test_ambiguous_credentials_reject_without_authentication(
    downstream: ASGIApp,
    headers: list[tuple[bytes, bytes]],
    error_code: str,
) -> None:
    calls: list[str] = []
    app = DualAuthMiddleware(
        downstream,
        oauth_authentication=recording_authentication("oauth", calls),
        aauth_authentication=recording_authentication("aauth", calls),
    )
    messages = await invoke(app, headers)
    assert calls == []
    assert messages[0]["status"] == 400
    assert json.loads(messages[1]["body"])["error"] == error_code


@pytest.mark.asyncio
async def test_unsupported_scheme_returns_both_challenges(
    downstream: ASGIApp,
) -> None:
    calls: list[str] = []
    app = DualAuthMiddleware(
        downstream,
        oauth_authentication=recording_authentication("oauth", calls),
        aauth_authentication=recording_authentication("aauth", calls),
    )
    messages = await invoke(app, [(b"authorization", b"Basic credentials")])
    assert calls == []
    assert messages[0]["status"] == 401
    headers = dict(messages[0]["headers"])
    assert b"www-authenticate" in headers
    assert headers[b"aauth-requirement"] == b"requirement=agent-token"


def test_factory_matches_sdk_authentication_hook(downstream: ASGIApp) -> None:
    factory = dual_authentication(
        oauth_authentication=recording_authentication("oauth", []),
        aauth_authentication=recording_authentication("aauth", []),
    )
    assert isinstance(factory(downstream), DualAuthMiddleware)
