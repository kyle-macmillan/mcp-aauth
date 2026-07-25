from __future__ import annotations

import time
from collections.abc import Callable, Iterator

import httpx2
from aauth_edocs import HttpRequest, SigningKey, sign

_SIGNATURE_HEADERS = ("Signature-Key", "Signature-Input", "Signature")


class AAuthAgentHTTPAuth(httpx2.Auth):
    """Sign each HTTP request using an agent's key and agent token."""

    def __init__(
        self,
        *,
        key: SigningKey,
        token: str,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.key = key
        self.token = token
        self.now = now

    def auth_flow(self, request: httpx2.Request) -> Iterator[httpx2.Request]:
        aauth_request = HttpRequest(
            request.method,
            str(request.url),
            (
                (name.decode("ascii"), value.decode("latin-1"))
                for name, value in request.headers.raw
            ),
        )
        sign(aauth_request, self.key, self.token, now=self.now)

        for name in _SIGNATURE_HEADERS:
            request.headers[name] = aauth_request.headers[name]

        yield request
