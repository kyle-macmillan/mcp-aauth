from __future__ import annotations

import httpx2
from aauth_edocs import (
    HttpRequest,
    SigningKey,
    issue_agent_token,
    static_resolver,
    verify,
)

from mcp_aauth import AAuthAgentHTTPAuth


def test_signs_final_request_and_covered_headers() -> None:
    ap = "https://ap.example"
    agent = "assistant@ap.example"
    ap_key = SigningKey.generate(kid="ap-1")
    agent_key = SigningKey.generate(kid="agent-1")
    token = issue_agent_token(
        issuer=ap,
        agent=agent,
        agent_jwk=agent_key.public_jwk,
        key=ap_key,
        ps="https://ps.example",
    )
    request = httpx2.Request(
        "POST",
        "https://resource.example/mcp?session=1",
        headers={
            "Authorization": "AAuth resource-token",
            "AAuth-Mission": 'approver="https://ps.example";s256="digest"',
        },
    )

    signed_request = next(
        AAuthAgentHTTPAuth(
            key=agent_key,
            token=token,
            now=lambda: 1000.0,
        ).auth_flow(request)
    )

    for name in ("Signature-Key", "Signature-Input", "Signature"):
        assert name in signed_request.headers

    verified = verify(
        HttpRequest(
            signed_request.method,
            str(signed_request.url),
            (
                (name.decode("ascii"), value.decode("latin-1"))
                for name, value in signed_request.headers.raw
            ),
        ),
        static_resolver({ap: ap_key.public_jwk}),
        now=lambda: 1000.0,
    )

    assert {"authorization", "aauth-mission"} <= set(verified.covered)
