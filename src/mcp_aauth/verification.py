from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping

from aauth_edocs import (
    AGENT_TYP,
    AUTH_TYP,
    AAuthError,
    VerifiedRequest,
    verify,
    verify_auth_token,
)
from aauth_edocs.errors import INVALID_REQUEST, INVALID_SIGNATURE, INVALID_TOKEN
from aauth_edocs.httpsig import KeyResolver
from starlette.types import ASGIApp, Receive, Scope, Send

from .middleware import MiddlewareFactory
from .request import ASGIRequestError, aauth_request_from_scope


def verify_aauth_agent(
    scope: Scope,
    key_resolver: KeyResolver,
    *,
    now: Callable[[], float] = time.time,
    signature_window: int = 60,
) -> VerifiedRequest:
    """Verify an ASGI request authenticated by an AAuth agent JWT."""
    verified = verify(
        aauth_request_from_scope(scope),
        key_resolver,
        now=now,
        window=signature_window,
    )

    if verified.token is None:
        raise AAuthError(
            INVALID_SIGNATURE,
            401,
            "MCP AAuth agent requests require Signature-Key scheme jwt",
        )
    if verified.header.get("typ") != AGENT_TYP:
        raise AAuthError(
            INVALID_TOKEN,
            401,
            f"expected typ {AGENT_TYP}, got {verified.header.get('typ')}",
        )

    return verified


def verify_aauth_authorization(
    scope: Scope,
    key_resolver: KeyResolver,
    *,
    issuer: str,
    audience: str,
    expected_claims: Mapping[str, object] | None = None,
    now: Callable[[], float] = time.time,
    signature_window: int = 60,
) -> VerifiedRequest:
    """Verify a request carrying a standard AAuth authorization token.

    The HTTP signature proves possession of the key in ``cnf.jwk``.  Issuer,
    audience, and optional application claim bindings are checked exactly.
    """
    verified = verify(
        aauth_request_from_scope(scope),
        key_resolver,
        now=now,
        window=signature_window,
    )
    if verified.token is None:
        raise AAuthError(
            INVALID_SIGNATURE,
            401,
            "MCP AAuth authorization requests require Signature-Key scheme jwt",
        )
    if verified.header.get("typ") != AUTH_TYP:
        raise AAuthError(
            INVALID_TOKEN,
            401,
            f"expected typ {AUTH_TYP}, got {verified.header.get('typ')}",
        )

    claims = verify_auth_token(
        verified.token,
        key_resolver,
        aud=audience,
        signing_jwk=(verified.claims.get("cnf") or {}).get("jwk"),
        now=now,
    )
    if claims.get("iss") != issuer:
        raise AAuthError(INVALID_TOKEN, 401, "auth token issuer mismatch")
    for name, expected in (expected_claims or {}).items():
        if claims.get(name) != expected:
            raise AAuthError(
                INVALID_TOKEN,
                401,
                f"auth token {name} does not match the request",
            )
    return verified


class AAuthAgentMiddleware:
    """Authenticate an HTTP request as an AAuth agent."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        key_resolver: KeyResolver,
        now: Callable[[], float] = time.time,
        signature_window: int = 60,
    ) -> None:
        self.app = app
        self.key_resolver = key_resolver
        self.now = now
        self.signature_window = signature_window

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        try:
            verified = verify_aauth_agent(
                scope,
                self.key_resolver,
                now=self.now,
                signature_window=self.signature_window,
            )
        except ASGIRequestError as error:
            await _send_error(
                send,
                AAuthError(INVALID_REQUEST, 400, error.detail),
            )
            return
        except AAuthError as error:
            await _send_error(send, error)
            return

        authenticated_scope = dict(scope)
        authenticated_scope["aauth"] = verified
        await self.app(authenticated_scope, receive, send)


def aauth_agent_authentication(
    *,
    key_resolver: KeyResolver,
    now: Callable[[], float] = time.time,
    signature_window: int = 60,
) -> MiddlewareFactory:
    """Build middleware that authenticates requests as AAuth agents."""

    def wrap(app: ASGIApp) -> ASGIApp:
        return AAuthAgentMiddleware(
            app,
            key_resolver=key_resolver,
            now=now,
            signature_window=signature_window,
        )

    return wrap


class AAuthAuthorizationMiddleware:
    """Authenticate an HTTP request carrying a standard AAuth auth token."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        key_resolver: KeyResolver,
        issuer: str,
        audience: str,
        expected_claims: Mapping[str, object] | None = None,
        now: Callable[[], float] = time.time,
        signature_window: int = 60,
    ) -> None:
        self.app = app
        self.key_resolver = key_resolver
        self.issuer = issuer
        self.audience = audience
        self.expected_claims = expected_claims
        self.now = now
        self.signature_window = signature_window

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        try:
            verified = verify_aauth_authorization(
                scope,
                self.key_resolver,
                issuer=self.issuer,
                audience=self.audience,
                expected_claims=self.expected_claims,
                now=self.now,
                signature_window=self.signature_window,
            )
        except ASGIRequestError as error:
            await _send_error(
                send,
                AAuthError(INVALID_REQUEST, 400, error.detail),
            )
            return
        except AAuthError as error:
            await _send_error(send, error)
            return

        authenticated_scope = dict(scope)
        authenticated_scope["aauth"] = verified
        await self.app(authenticated_scope, receive, send)


def aauth_authorization(
    *,
    key_resolver: KeyResolver,
    issuer: str,
    audience: str,
    expected_claims: Mapping[str, object] | None = None,
    now: Callable[[], float] = time.time,
    signature_window: int = 60,
) -> MiddlewareFactory:
    """Build generic middleware for standard AAuth authorization tokens."""

    def wrap(app: ASGIApp) -> ASGIApp:
        return AAuthAuthorizationMiddleware(
            app,
            key_resolver=key_resolver,
            issuer=issuer,
            audience=audience,
            expected_claims=expected_claims,
            now=now,
            signature_window=signature_window,
        )

    return wrap


async def _send_error(send: Send, error: AAuthError) -> None:
    body = json.dumps(error.body(), separators=(",", ":")).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": error.status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
