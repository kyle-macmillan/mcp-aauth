from __future__ import annotations

from typing import Literal
from urllib.parse import quote

from aauth_edocs import HttpHeaders, HttpRequest
from starlette.types import Scope

ASGIRequestErrorCode = Literal[
    "not_http_scope",
    "missing_host_header",
    "multiple_host_headers",
    "invalid_request_target",
]


class ASGIRequestError(ValueError):
    """An ASGI request cannot be represented faithfully for AAuth verification."""

    def __init__(self, code: ASGIRequestErrorCode, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def aauth_request_from_scope(scope: Scope) -> HttpRequest:
    """Convert an HTTP ASGI scope into the request view verified by AAuth."""
    if scope["type"] != "http":
        raise ASGIRequestError(
            "not_http_scope",
            "AAuth request conversion requires an HTTP scope",
        )

    try:
        headers = HttpHeaders(
            (
                name.decode("ascii"),
                value.decode("latin-1"),
            )
            for name, value in scope["headers"]
        )
    except UnicodeDecodeError as error:
        raise ASGIRequestError(
            "invalid_request_target",
            "request target cannot be represented as an AAuth URL",
        ) from error

    host_values = headers.get_all("host")
    if not host_values:
        raise ASGIRequestError(
            "missing_host_header",
            "request does not contain a Host header",
        )
    if len(host_values) > 1:
        raise ASGIRequestError(
            "multiple_host_headers",
            "request contains multiple Host headers",
        )

    try:
        scheme = scope["scheme"]
        authority = host_values[0].strip().encode("latin-1").decode("ascii")
        raw_path = scope.get("raw_path")
        path = (
            raw_path.decode("ascii")
            if raw_path is not None
            else quote(scope["path"], safe="/:@-._~!$&'()*+,;=")
        )
        query = scope["query_string"].decode("ascii")
    except (KeyError, UnicodeDecodeError) as error:
        raise ASGIRequestError(
            "invalid_request_target",
            "request target cannot be represented as an AAuth URL",
        ) from error

    url = f"{scheme}://{authority}{path}"
    if query:
        url += f"?{query}"

    return HttpRequest(
        method=scope["method"],
        url=url,
        headers=headers,
    )
