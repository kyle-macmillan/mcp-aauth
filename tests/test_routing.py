import pytest

from mcp_aauth import (
    CredentialRoute,
    CredentialRoutingError,
    classify_credentials,
)


def test_no_credentials_routes_to_none() -> None:
    assert classify_credentials([]) is CredentialRoute.NONE


def test_unrelated_headers_route_to_none() -> None:
    headers = [
        (b"content-type", b"application/json"),
        (b"accept", b"application/json"),
    ]

    assert classify_credentials(headers) is CredentialRoute.NONE


@pytest.mark.parametrize(
    "value",
    [
        b"Bearer token",
        b"bearer token",
        b"BEARER token",
    ],
)
def test_bearer_authorization_routes_to_oauth(value: bytes) -> None:
    headers = [(b"authorization", value)]

    assert classify_credentials(headers) is CredentialRoute.OAUTH


@pytest.mark.parametrize(
    "name",
    [
        b"signature-key",
        b"signature-input",
        b"signature",
        b"Signature-Key",
    ],
)
def test_any_signature_header_routes_to_aauth(name: bytes) -> None:
    headers = [(name, b"value")]

    assert classify_credentials(headers) is CredentialRoute.AAUTH


def test_aauth_authorization_scheme_routes_to_aauth() -> None:
    headers = [(b"authorization", b"AAuth token")]

    assert classify_credentials(headers) is CredentialRoute.AAUTH


def test_oauth_and_signature_headers_are_rejected_as_mixed() -> None:
    headers = [
        (b"authorization", b"Bearer token"),
        (b"signature-key", b"value"),
    ]

    with pytest.raises(CredentialRoutingError) as captured:
        classify_credentials(headers)

    assert captured.value.code == "mixed_credentials"


def test_bearer_and_aauth_authorization_headers_are_rejected_as_mixed() -> None:
    headers = [
        (b"authorization", b"Bearer oauth-token"),
        (b"authorization", b"AAuth aauth-token"),
    ]

    with pytest.raises(CredentialRoutingError) as captured:
        classify_credentials(headers)

    assert captured.value.code == "mixed_credentials"


def test_duplicate_bearer_headers_are_rejected() -> None:
    headers = [
        (b"authorization", b"Bearer first"),
        (b"authorization", b"Bearer second"),
    ]

    with pytest.raises(CredentialRoutingError) as captured:
        classify_credentials(headers)

    assert captured.value.code == "multiple_authorization_headers"


def test_unknown_authorization_scheme_is_rejected() -> None:
    headers = [(b"authorization", b"Basic credentials")]

    with pytest.raises(CredentialRoutingError) as captured:
        classify_credentials(headers)

    assert captured.value.code == "unsupported_authorization_scheme"


def test_unknown_authorization_scheme_is_not_hidden_by_aauth_signature() -> None:
    headers = [
        (b"authorization", b"Basic credentials"),
        (b"signature-key", b"value"),
    ]

    with pytest.raises(CredentialRoutingError) as captured:
        classify_credentials(headers)

    assert captured.value.code == "unsupported_authorization_scheme"
