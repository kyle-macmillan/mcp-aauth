from __future__ import annotations

import json

import pytest
from aauth_edocs import (
    AAuthError,
    HttpRequest,
    SigningKey,
    issue_auth_token,
    issue_agent_token,
    sign,
    sign_server,
    static_resolver,
)
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcp_aauth import (
    aauth_agent_authentication,
    aauth_authorization,
    verify_aauth_agent,
    verify_aauth_authorization,
)

AP = "https://ap.example"
PS = "https://ps.example"
RESOURCE = "https://resource.example"
AGENT = "assistant@ap.example"


def asgi_scope(request: HttpRequest) -> Scope:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": request.method,
        "scheme": "https",
        "path": "/documents",
        "raw_path": b"/documents",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (name.encode("ascii"), value.encode("latin-1"))
            for name, value in request.headers.raw_items()
        ],
        "server": ("127.0.0.1", 443),
        "client": ("127.0.0.1", 1234),
    }


async def invoke(
    app: ASGIApp,
    scope: Scope,
) -> list[Message]:
    messages: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        messages.append(message)

    await app(scope, receive, send)
    return messages


@pytest.fixture
def keys() -> tuple[SigningKey, SigningKey, SigningKey]:
    return (
        SigningKey.generate(kid="ap-1"),
        SigningKey.generate(kid="agent-1"),
        SigningKey.generate(kid="ps-1"),
    )


def test_verifies_agent_jwt_request(keys) -> None:
    ap_key, agent_key, ps_key = keys
    resolver = static_resolver({AP: ap_key.public_jwk, PS: ps_key.public_jwk})
    token = issue_agent_token(
        issuer=AP,
        agent=AGENT,
        agent_jwk=agent_key.public_jwk,
        key=ap_key,
        ps=PS,
    )
    request = sign(
        HttpRequest("GET", f"{RESOURCE}/documents", {"host": "resource.example"}),
        agent_key,
        token,
    )

    verified = verify_aauth_agent(asgi_scope(request), resolver)

    assert verified.claims["sub"] == AGENT


def test_rejects_jwks_uri_signature_key_scheme(keys) -> None:
    _, _, ps_key = keys
    resolver = static_resolver({PS: ps_key.public_jwk})
    request = sign_server(
        HttpRequest("GET", f"{RESOURCE}/documents", {"host": "resource.example"}),
        ps_key,
        PS,
        "aauth-person.json",
    )

    with pytest.raises(AAuthError, match="require Signature-Key scheme jwt") as captured:
        verify_aauth_agent(asgi_scope(request), resolver)

    assert captured.value.code == "invalid_signature"


def test_rejects_non_agent_jwt(keys) -> None:
    _, agent_key, ps_key = keys
    resolver = static_resolver({PS: ps_key.public_jwk})
    token = issue_auth_token(
        issuer=PS,
        dwk="aauth-person.json",
        aud=RESOURCE,
        agent=AGENT,
        cnf_jwk=agent_key.public_jwk,
        sub="alice",
        key=ps_key,
    )
    request = sign(
        HttpRequest("GET", f"{RESOURCE}/documents", {"host": "resource.example"}),
        agent_key,
        token,
    )

    with pytest.raises(AAuthError, match="expected typ aa-agent\\+jwt") as captured:
        verify_aauth_agent(asgi_scope(request), resolver)

    assert captured.value.code == "invalid_token"


def test_verifies_standard_auth_token_and_expected_claims(keys) -> None:
    _, agent_key, ps_key = keys
    resolver = static_resolver({PS: ps_key.public_jwk})
    token = issue_auth_token(
        issuer=PS,
        dwk="aauth-access.json",
        aud=RESOURCE,
        agent=AGENT,
        cnf_jwk=agent_key.public_jwk,
        scope="identity@1",
        source_agent="aauth:source@ap.example",
        edoc_id="doc-123",
        controllers=("https://as-a.example",),
        key=ps_key,
    )
    request = sign(
        HttpRequest("POST", f"{RESOURCE}/documents", {"host": "resource.example"}),
        agent_key,
        token,
    )

    verified = verify_aauth_authorization(
        asgi_scope(request),
        resolver,
        issuer=PS,
        audience=RESOURCE,
        expected_claims={"scope": "identity@1", "edoc_id": "doc-123"},
    )

    assert verified.claims["agent"] == AGENT


@pytest.mark.parametrize(
    ("issuer", "audience", "expected_claims", "message"),
    [
        ("https://other.example", RESOURCE, None, "issuer"),
        (PS, "https://other.example", None, "aud"),
        (PS, RESOURCE, {"edoc_id": "doc-456"}, "edoc_id"),
    ],
)
def test_authorization_rejects_binding_mismatch(
    keys, issuer, audience, expected_claims, message
) -> None:
    _, agent_key, ps_key = keys
    resolver = static_resolver({PS: ps_key.public_jwk})
    token = issue_auth_token(
        issuer=PS,
        dwk="aauth-access.json",
        aud=RESOURCE,
        agent=AGENT,
        cnf_jwk=agent_key.public_jwk,
        scope="identity@1",
        source_agent="aauth:source@ap.example",
        edoc_id="doc-123",
        controllers=("https://as-a.example",),
        key=ps_key,
    )
    request = sign(
        HttpRequest("POST", f"{RESOURCE}/documents", {"host": "resource.example"}),
        agent_key,
        token,
    )

    with pytest.raises(AAuthError, match=message):
        verify_aauth_authorization(
            asgi_scope(request),
            resolver,
            issuer=issuer,
            audience=audience,
            expected_claims=expected_claims,
        )


def test_authorization_rejects_agent_token(keys) -> None:
    ap_key, agent_key, ps_key = keys
    resolver = static_resolver({AP: ap_key.public_jwk, PS: ps_key.public_jwk})
    token = issue_agent_token(
        issuer=AP,
        agent=AGENT,
        agent_jwk=agent_key.public_jwk,
        key=ap_key,
        ps=PS,
    )
    request = sign(
        HttpRequest("POST", f"{RESOURCE}/documents", {"host": "resource.example"}),
        agent_key,
        token,
    )

    with pytest.raises(AAuthError, match="expected typ aa-auth"):
        verify_aauth_authorization(
            asgi_scope(request),
            resolver,
            issuer=PS,
            audience=RESOURCE,
        )


@pytest.mark.asyncio
async def test_middleware_passes_verified_agent_to_downstream(keys) -> None:
    ap_key, agent_key, ps_key = keys
    resolver = static_resolver({AP: ap_key.public_jwk, PS: ps_key.public_jwk})
    token = issue_agent_token(
        issuer=AP,
        agent=AGENT,
        agent_jwk=agent_key.public_jwk,
        key=ap_key,
        ps=PS,
    )
    request = sign(
        HttpRequest("GET", f"{RESOURCE}/documents", {"host": "resource.example"}),
        agent_key,
        token,
    )
    seen: list[Scope] = []

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(scope)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    app = aauth_agent_authentication(key_resolver=resolver)(downstream)

    messages = await invoke(app, asgi_scope(request))

    assert messages[0]["status"] == 200
    assert seen[0]["aauth"].claims["sub"] == AGENT


@pytest.mark.asyncio
async def test_authorization_middleware_passes_verified_claims(keys) -> None:
    _, agent_key, ps_key = keys
    resolver = static_resolver({PS: ps_key.public_jwk})
    token = issue_auth_token(
        issuer=PS,
        dwk="aauth-access.json",
        aud=RESOURCE,
        agent=AGENT,
        cnf_jwk=agent_key.public_jwk,
        scope="identity@1",
        source_agent="aauth:source@ap.example",
        edoc_id="doc-123",
        controllers=("https://as-a.example",),
        key=ps_key,
    )
    request = sign(
        HttpRequest("POST", f"{RESOURCE}/documents", {"host": "resource.example"}),
        agent_key,
        token,
    )
    seen: list[Scope] = []

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(scope)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    app = aauth_authorization(
        key_resolver=resolver,
        issuer=PS,
        audience=RESOURCE,
    )(downstream)

    messages = await invoke(app, asgi_scope(request))

    assert messages[0]["status"] == 200
    assert seen[0]["aauth"].claims["edoc_id"] == "doc-123"


@pytest.mark.asyncio
async def test_middleware_rejects_invalid_signature_before_downstream(keys) -> None:
    ap_key, agent_key, ps_key = keys
    resolver = static_resolver({AP: ap_key.public_jwk, PS: ps_key.public_jwk})
    token = issue_agent_token(
        issuer=AP,
        agent=AGENT,
        agent_jwk=agent_key.public_jwk,
        key=ap_key,
        ps=PS,
    )
    request = sign(
        HttpRequest("GET", f"{RESOURCE}/documents", {"host": "resource.example"}),
        agent_key,
        token,
    )
    scope = asgi_scope(request)
    scope["method"] = "DELETE"
    called = False

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal called
        called = True

    messages = await invoke(
        aauth_agent_authentication(key_resolver=resolver)(downstream),
        scope,
    )

    assert called is False
    assert messages[0]["status"] == 401
    assert json.loads(messages[1]["body"])["error"] == "invalid_signature"


@pytest.mark.asyncio
async def test_middleware_rejects_jwks_uri_before_downstream(keys) -> None:
    _, _, ps_key = keys
    resolver = static_resolver({PS: ps_key.public_jwk})
    request = sign_server(
        HttpRequest("GET", f"{RESOURCE}/documents", {"host": "resource.example"}),
        ps_key,
        PS,
        "aauth-person.json",
    )
    called = False

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal called
        called = True

    messages = await invoke(
        aauth_agent_authentication(key_resolver=resolver)(downstream),
        asgi_scope(request),
    )

    assert called is False
    assert messages[0]["status"] == 401
    assert json.loads(messages[1]["body"])["error"] == "invalid_signature"


@pytest.mark.asyncio
async def test_middleware_returns_400_for_malformed_http_scope(keys) -> None:
    ap_key, _, _ = keys
    scope = asgi_scope(
        HttpRequest("GET", f"{RESOURCE}/documents", {"host": "resource.example"})
    )
    scope["headers"] = []
    called = False

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal called
        called = True

    messages = await invoke(
        aauth_agent_authentication(
            key_resolver=static_resolver({AP: ap_key.public_jwk})
        )(downstream),
        scope,
    )

    assert called is False
    assert messages[0]["status"] == 400
    assert json.loads(messages[1]["body"])["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_middleware_passes_non_http_scope_through(keys) -> None:
    ap_key, _, _ = keys
    seen: list[Scope] = []

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(scope)

    scope: Scope = {"type": "lifespan", "asgi": {"version": "3.0"}}
    messages = await invoke(
        aauth_agent_authentication(
            key_resolver=static_resolver({AP: ap_key.public_jwk})
        )(downstream),
        scope,
    )

    assert messages == []
    assert seen == [scope]
