"""Thin application helpers for the in-memory eDocs MCP demo.

Authorization transport and policy remain ordinary AAuth.  This module only
maps an application operation to eDocs claims and enforces those claims when
the operation is invoked.
"""

from __future__ import annotations

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
from aauth_edocs.keys import jwk_thumbprint


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
