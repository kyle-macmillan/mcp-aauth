from __future__ import annotations

from collections.abc import Callable, Iterator

import httpx2
import pytest
from aauth_edocs import (
    HttpRequest,
    SigningKey,
    issue_agent_token,
    sign,
    static_resolver,
)
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server import MCPServer
from mcp.server.auth.middleware.bearer_auth import (
    BearerAuthBackend,
    RequireAuthMiddleware,
)
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import Context
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from mcp_aauth import aauth_agent_authentication, dual_authentication

pytestmark = pytest.mark.anyio


class RejectingTokenVerifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        raise AssertionError("the built-in bearer verifier must not run")


class AAuthRequestSigner(httpx2.Auth):
    def __init__(self, key: SigningKey, token: str) -> None:
        self.key = key
        self.token = token

    def auth_flow(self, request: httpx2.Request) -> Iterator[httpx2.Request]:
        signed = sign(
            HttpRequest(request.method, str(request.url)),
            self.key,
            self.token,
        )
        for name in ("Signature-Key", "Signature-Input", "Signature"):
            request.headers[name] = signed.headers[name]
        yield request


def recording_authentication(
    name: str,
    calls: list[str],
) -> Callable[[ASGIApp], ASGIApp]:
    def factory(app: ASGIApp) -> ASGIApp:
        async def authenticate(scope: Scope, receive: Receive, send: Send) -> None:
            calls.append(name)
            await app(scope, receive, send)

        return authenticate

    return factory


def dual_auth_factory(calls: list[str]) -> Callable[[ASGIApp], ASGIApp]:
    return dual_authentication(
        oauth_authentication=recording_authentication("oauth", calls),
        aauth_authentication=recording_authentication("aauth", calls),
    )


@pytest.mark.parametrize(
    ("headers", "expected_authenticator"),
    [
        ({"Authorization": "Bearer token"}, "oauth"),
        (
            {
                "Signature-Key": 'sig=jwt;jwt="token"',
                "Signature-Input": 'sig=("@method")',
                "Signature": "sig=:YWJj:",
            },
            "aauth",
        ),
    ],
)
async def test_selected_authenticator_allows_an_mcp_request(
    headers: dict[str, str],
    expected_authenticator: str,
) -> None:
    """The SDK hook and dual router compose so either credential type can complete an MCP request."""
    calls: list[str] = []
    server = MCPServer("dual-auth")
    app = server.streamable_http_app(
        authentication_middleware_factory=dual_auth_factory(calls),
    )
    url = "http://127.0.0.1:8000/mcp"
    transport = httpx2.ASGITransport(app=app)

    async with server.session_manager.run():
        async with (
            httpx2.AsyncClient(transport=transport, base_url=url, headers=headers) as http_client,
            Client(streamable_http_client(url, http_client=http_client), mode="legacy") as client,
        ):
            result = await client.list_tools()

    assert result.tools == []
    assert calls
    assert set(calls) == {expected_authenticator}


@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [
        ({}, 401),
        (
            {
                "Authorization": "Bearer token",
                "Signature-Key": 'sig=jwt;jwt="token"',
            },
            400,
        ),
    ],
)
async def test_invalid_credential_selection_stops_before_mcp(
    headers: dict[str, str],
    expected_status: int,
) -> None:
    """Missing or mixed credentials are rejected by the dual router before an authenticator or MCP runs."""
    calls: list[str] = []
    server = MCPServer("dual-auth")
    app = server.streamable_http_app(
        authentication_middleware_factory=dual_auth_factory(calls),
    )
    transport = httpx2.ASGITransport(app=app)

    async with httpx2.AsyncClient(transport=transport, base_url="https://example.com") as http_client:
        response = await http_client.post("/mcp", headers=headers, json={})

    assert response.status_code == expected_status
    assert calls == []


async def test_signed_agent_reaches_mcp_tool_with_verified_identity() -> None:
    ap = "https://ap.example"
    ps = "https://ps.example"
    agent = "assistant@ap.example"
    ap_key = SigningKey.generate(kid="ap-1")
    agent_key = SigningKey.generate(kid="agent-1")
    resolver = static_resolver({ap: ap_key.public_jwk})
    agent_token = issue_agent_token(
        issuer=ap,
        agent=agent,
        agent_jwk=agent_key.public_jwk,
        key=ap_key,
        ps=ps,
    )

    server = MCPServer("aauth")

    @server.tool()
    def authenticated_agent(ctx: Context) -> str:
        request = ctx.request_context.request
        return request.scope["aauth"].claims["sub"]

    def oauth_authentication(app: ASGIApp) -> ASGIApp:
        required = RequireAuthMiddleware(app, required_scopes=[])
        return AuthenticationMiddleware(
            required,
            backend=BearerAuthBackend(RejectingTokenVerifier()),
        )

    app = server.streamable_http_app(
        authentication_middleware_factory=dual_authentication(
            oauth_authentication=oauth_authentication,
            aauth_authentication=aauth_agent_authentication(
                key_resolver=resolver,
            ),
        ),
    )
    url = "http://127.0.0.1:8000/mcp"
    transport = httpx2.ASGITransport(app=app)

    async with server.session_manager.run():
        async with (
            httpx2.AsyncClient(
                transport=transport,
                base_url=url,
                auth=AAuthRequestSigner(agent_key, agent_token),
            ) as http_client,
            Client(
                streamable_http_client(url, http_client=http_client),
                mode="legacy",
            ) as client,
        ):
            result = await client.call_tool("authenticated_agent", {})

    assert result.content[0].text == agent


async def test_oauth_metadata_remains_outside_custom_authentication() -> None:
    """The custom endpoint wrapper does not intercept the SDK's OAuth protected-resource metadata route."""
    calls: list[str] = []
    server = MCPServer(
        "dual-auth",
        auth=AuthSettings(
            issuer_url="https://auth.example.com",
            resource_server_url="http://127.0.0.1/mcp",
        ),
        token_verifier=RejectingTokenVerifier(),
    )
    app = server.streamable_http_app(
        authentication_middleware_factory=dual_auth_factory(calls),
    )
    transport = httpx2.ASGITransport(app=app)

    async with httpx2.AsyncClient(transport=transport, base_url="http://127.0.0.1") as http_client:
        response = await http_client.get("/.well-known/oauth-protected-resource/mcp")

    assert response.status_code == 200
    assert response.json()["resource"] == "http://127.0.0.1/mcp"
    assert calls == []
