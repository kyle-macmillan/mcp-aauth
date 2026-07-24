from __future__ import annotations

from collections.abc import Iterable
from enum import Enum
from typing import Literal

Header = tuple[bytes, bytes]
RoutingErrorCode = Literal[
    "mixed_credentials",
    "multiple_authorization_headers",
    "unsupported_authorization_scheme",
]

_AAUTH_SIGNATURE_HEADERS = {
    b"signature",
    b"signature-input",
    b"signature-key",
}


class CredentialRoute(str, Enum):
    NONE = "none"
    OAUTH = "oauth"
    AAUTH = "aauth"


class CredentialRoutingError(ValueError):
    def __init__(self, code: RoutingErrorCode, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _authorization_scheme(value: bytes) -> bytes:
    stripped = value.strip()
    if not stripped:
        return b""
    return stripped.split(None, 1)[0].lower()


def classify_credentials(headers: Iterable[Header]) -> CredentialRoute:
    authorization_values: list[bytes] = []
    has_aauth_signature = False

    for name, value in headers:
        lowercase_name = name.lower()

        if lowercase_name == b"authorization":
            authorization_values.append(value)
        elif lowercase_name in _AAUTH_SIGNATURE_HEADERS:
            has_aauth_signature = True

    schemes = {_authorization_scheme(value) for value in authorization_values}

    has_oauth = b"bearer" in schemes
    has_aauth = has_aauth_signature or b"aauth" in schemes

    if has_oauth and has_aauth:
        raise CredentialRoutingError(
            "mixed_credentials",
            "request contains both OAuth and AAuth credentials",
        )

    if len(authorization_values) > 1:
        raise CredentialRoutingError(
            "multiple_authorization_headers",
            "request contains multiple Authorization headers",
        )

    if schemes and not schemes <= {b"bearer", b"aauth"}:
        scheme = next(iter(schemes))
        display_scheme = scheme.decode("ascii", errors="replace") or "<empty>"
        raise CredentialRoutingError(
            "unsupported_authorization_scheme",
            f"unsupported Authorization scheme: {display_scheme}",
        )

    if has_oauth:
        return CredentialRoute.OAUTH

    if has_aauth:
        return CredentialRoute.AAUTH

    return CredentialRoute.NONE
