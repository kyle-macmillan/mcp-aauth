from __future__ import annotations

import json
from collections.abc import Callable

from starlette.types import ASGIApp, Receive, Scope, Send

from .routing import CredentialRoute, CredentialRoutingError, classify_credentials

MiddlewareFactory = Callable[[ASGIApp], ASGIApp]


class DualAuthMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        oauth_authentication: MiddlewareFactory,
        aauth_authentication: MiddlewareFactory,
        resource_metadata_url: str | None = None,
    ) -> None:
        self.app = app
        self.oauth_app = oauth_authentication(app)
        self.aauth_app = aauth_authentication(app)
        self.resource_metadata_url = resource_metadata_url

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        try:
            route = classify_credentials(scope["headers"])
        except CredentialRoutingError as error:
            if error.code == "unsupported_authorization_scheme":
                await self._send_error(
                    send,
                    status=401,
                    code=error.code,
                    detail=error.detail,
                    include_challenges=True,
                )
            else:
                await self._send_error(
                    send,
                    status=400,
                    code=error.code,
                    detail=error.detail,
                )
            return

        if route is CredentialRoute.OAUTH:
            await self.oauth_app(scope, receive, send)
            return

        if route is CredentialRoute.AAUTH:
            await self.aauth_app(scope, receive, send)
            return

        await self._send_error(
            send,
            status=401,
            code="authentication_required",
            detail="request does not contain authentication credentials",
            include_challenges=True,
        )

    async def _send_error(
        self,
        send: Send,
        *,
        status: int,
        code: str,
        detail: str,
        include_challenges: bool = False,
    ) -> None:
        body = json.dumps(
            {"error": code, "error_description": detail},
            separators=(",", ":"),
        ).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]

        if include_challenges:
            bearer_challenge = (
                'Bearer error="invalid_token", '
                'error_description="Authentication required"'
            )
            if self.resource_metadata_url is not None:
                bearer_challenge += (
                    f', resource_metadata="{self.resource_metadata_url}"'
                )
            headers.extend(
                [
                    (b"www-authenticate", bearer_challenge.encode("latin-1")),
                    (b"aauth-requirement", b"requirement=agent-token"),
                ]
            )

        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": body})


def dual_authentication(
    *,
    oauth_authentication: MiddlewareFactory,
    aauth_authentication: MiddlewareFactory,
    resource_metadata_url: str | None = None,
) -> MiddlewareFactory:
    def wrap(app: ASGIApp) -> ASGIApp:
        return DualAuthMiddleware(
            app,
            oauth_authentication=oauth_authentication,
            aauth_authentication=aauth_authentication,
            resource_metadata_url=resource_metadata_url,
        )

    return wrap
