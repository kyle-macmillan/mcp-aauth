"""Thin application helpers for the in-memory eDocs MCP demo.

Authorization transport and policy remain ordinary AAuth.  This module only
maps an application operation to eDocs claims and enforces those claims when
the operation is invoked.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from aauth_edocs import (
    AAuthError,
    FunctionDescriptor,
    SigningKey,
    VerifiedRequest,
    issue_resource_token,
)
from aauth_edocs.errors import DENIED, INVALID_REQUEST, INVALID_TOKEN
from aauth_edocs.httpsig import KeyResolver
from aauth_edocs.keys import jwk_thumbprint
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .verification import aauth_agent_authentication


@dataclass(frozen=True)
class EdocsResource:
    issuer: str
    sentinel: str
    source_agent: str
    key: SigningKey
    controllers: tuple[str, ...]
    documents: Mapping[str, Any]
    functions: Mapping[str, FunctionDescriptor]

    def authorize(
        self,
        verified_agent: VerifiedRequest,
        *,
        scope: str,
        edoc_id: str,
    ) -> str:
        """Issue the proposed dataflow as a Sentinel-audience resource token."""
        if not isinstance(scope, str) or len(scope.split()) != 1:
            raise AAuthError(INVALID_REQUEST, 400, "exactly one function scope is required")
        if scope not in self.functions:
            raise AAuthError(DENIED, 403, "function is not registered")
        if edoc_id not in self.documents:
            raise AAuthError(DENIED, 403, "eDoc does not exist")

        agent = verified_agent.claims.get("sub")
        agent_jwk = (verified_agent.claims.get("cnf") or {}).get("jwk")
        if not isinstance(agent, str) or not agent or not isinstance(agent_jwk, dict):
            raise AAuthError(INVALID_TOKEN, 401, "verified agent identity is incomplete")

        return issue_resource_token(
            issuer=self.issuer,
            aud=self.sentinel,
            agent=agent,
            agent_jkt=jwk_thumbprint(agent_jwk),
            scope=scope,
            source_agent=self.source_agent,
            edoc_id=edoc_id,
            controllers=self.controllers,
            key=self.key,
        )

    def identity(
        self,
        authorization: VerifiedRequest,
        *,
        edoc_id: str,
        destination_agent: str,
    ) -> Any:
        """Enforce the final decision and return the requested eDoc unchanged."""
        claims = authorization.claims
        expected = {
            "iss": self.sentinel,
            "aud": self.issuer,
            "source_agent": self.source_agent,
            "scope": "identity@1",
            "edoc_id": edoc_id,
            "agent": destination_agent,
            "controllers": list(self.controllers),
        }
        for name, value in expected.items():
            if claims.get(name) != value:
                raise AAuthError(
                    INVALID_TOKEN,
                    401,
                    f"authorization {name} does not match the invocation",
                )
        if edoc_id not in self.documents:
            raise AAuthError(DENIED, 403, "eDoc does not exist")
        return self.documents[edoc_id]


class EdocsResourceApplication:
    """Add a signed resource-token endpoint in front of an MCP ASGI app."""

    def __init__(
        self,
        resource: EdocsResource,
        mcp_app: ASGIApp,
        *,
        key_resolver: KeyResolver,
        resource_token_path: str = "/resource-token",
    ) -> None:
        self.resource = resource
        self.mcp_app = mcp_app
        self.resource_token_path = resource_token_path
        self.signed_resource_token_app = aauth_agent_authentication(
            key_resolver=key_resolver
        )(self._resource_token)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] == "http"
            and scope.get("path") == self.resource_token_path
        ):
            await self.signed_resource_token_app(scope, receive, send)
            return
        await self.mcp_app(scope, receive, send)

    async def _resource_token(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope.get("method") != "POST":
            await _send_json(send, 405, {"error": "method_not_allowed"})
            return
        try:
            body = await _read_json(receive)
            if set(body) != {"scope", "edoc_id"}:
                raise AAuthError(
                    INVALID_REQUEST,
                    400,
                    "request must contain exactly scope and edoc_id",
                )
            token = self.resource.authorize(
                scope["aauth"],
                scope=body["scope"],
                edoc_id=body["edoc_id"],
            )
        except AAuthError as error:
            await _send_json(send, error.status, error.body())
            return
        except (TypeError, ValueError, json.JSONDecodeError):
            await _send_json(
                send,
                400,
                {"error": INVALID_REQUEST, "detail": "JSON object required"},
            )
            return
        await _send_json(send, 200, {"resource_token": token})


async def _read_json(receive: Receive) -> dict:
    chunks = []
    while True:
        message: Message = await receive()
        if message["type"] != "http.request":
            continue
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            break
    value = json.loads(b"".join(chunks))
    if not isinstance(value, dict):
        raise TypeError("JSON object required")
    return value


async def _send_json(send: Send, status: int, value: dict) -> None:
    body = json.dumps(value, separators=(",", ":")).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
