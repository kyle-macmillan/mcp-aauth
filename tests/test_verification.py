from __future__ import annotations

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
from starlette.types import Scope

from mcp_aauth import verify_aauth_agent

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
