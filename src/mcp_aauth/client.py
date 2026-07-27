from __future__ import annotations

import inspect
import time
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator

import httpx2
from aauth_edocs import (
    ApprovalRequired,
    AuthorizationCoordinator,
    HttpRequest,
    SigningKey,
    parse_requirement,
    sign,
)
from aauth_edocs.headers import AUTH_TOKEN

_SIGNATURE_HEADERS = ("Signature-Key", "Signature-Input", "Signature")


class AAuthAgentHTTPAuth(httpx2.Auth):
    """Sign requests and optionally coordinate an AAuth challenge/retry.

    Without ``coordinator`` this retains the original signing-only behavior.
    With one, an ``auth-token`` resource challenge is exchanged at the Person
    Server, deferred approval is surfaced to the trusted host callback, and
    the request is retried with the resulting resource-scoped token.
    """

    def __init__(
        self,
        *,
        key: SigningKey,
        token: str,
        now: Callable[[], float] = time.time,
        coordinator: AuthorizationCoordinator | None = None,
        on_approval_required: (
            Callable[[ApprovalRequired], None | Awaitable[None]] | None
        ) = None,
    ) -> None:
        self.key = key
        self.token = token
        self.now = now
        self.coordinator = coordinator
        self.on_approval_required = on_approval_required

    def auth_flow(
        self, request: httpx2.Request
    ) -> Generator[httpx2.Request, httpx2.Response, None]:
        resource_url = str(request.url)
        cached = self.coordinator.token_for(resource_url) if self.coordinator else None
        response = yield self._sign(request, cached or self.token)

        if self.coordinator is None:
            return

        if response.status_code == 403 and cached is not None:
            self.coordinator.invalidate(resource_url)
            yield self._sign(request, self.token)
            return

        if response.status_code != 401:
            return

        requirement_header = response.headers.get("AAuth-Requirement")
        if not requirement_header:
            return
        requirement, params = parse_requirement(requirement_header)
        resource_token = params.get("resource-token")
        if requirement != AUTH_TOKEN or not isinstance(resource_token, str):
            return

        result = self.coordinator.begin(
            resource_token,
            resource_url=resource_url,
        )
        if isinstance(result, ApprovalRequired):
            if self.on_approval_required is None:
                return
            self.on_approval_required(result)
            result = self.coordinator.complete(result)

        yield self._sign(request, result)

    async def async_auth_flow(
        self, request: httpx2.Request
    ) -> AsyncGenerator[httpx2.Request, httpx2.Response]:
        """Async challenge flow that can pause for a host without blocking."""
        resource_url = str(request.url)
        cached = self.coordinator.token_for(resource_url) if self.coordinator else None
        response = yield self._sign(request, cached or self.token)

        if self.coordinator is None:
            return

        if response.status_code == 403 and cached is not None:
            self.coordinator.invalidate(resource_url)
            yield self._sign(request, self.token)
            return

        if response.status_code != 401:
            return

        requirement_header = response.headers.get("AAuth-Requirement")
        if not requirement_header:
            return
        requirement, params = parse_requirement(requirement_header)
        resource_token = params.get("resource-token")
        if requirement != AUTH_TOKEN or not isinstance(resource_token, str):
            return

        result = await self.coordinator.begin_async(
            resource_token,
            resource_url=resource_url,
        )
        if isinstance(result, ApprovalRequired):
            if self.on_approval_required is None:
                return
            callback_result = self.on_approval_required(result)
            if inspect.isawaitable(callback_result):
                await callback_result
            result = await self.coordinator.complete_async(result)

        yield self._sign(request, result)

    def _sign(self, request: httpx2.Request, token: str) -> httpx2.Request:
        aauth_request = HttpRequest(
            request.method,
            str(request.url),
            (
                (name.decode("ascii"), value.decode("latin-1"))
                for name, value in request.headers.raw
            ),
        )
        sign(aauth_request, self.key, token, now=self.now)

        for name in _SIGNATURE_HEADERS:
            request.headers[name] = aauth_request.headers[name]

        return request
