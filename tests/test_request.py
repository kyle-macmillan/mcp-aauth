from __future__ import annotations

import pytest
from starlette.types import Scope

from mcp_aauth import ASGIRequestError, aauth_request_from_scope


def http_scope(
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
    path: str = "/documents",
    raw_path: bytes | None = b"/documents",
    query_string: bytes = b"",
) -> Scope:
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": path,
        "query_string": query_string,
        "root_path": "",
        "headers": headers or [(b"host", b"documents.example")],
        "server": ("127.0.0.1", 443),
        "client": ("127.0.0.1", 1234),
    }
    if raw_path is not None:
        scope["raw_path"] = raw_path
    return scope


def test_http_scope_becomes_aauth_request() -> None:
    scope = http_scope(
        headers=[
            (b"host", b"documents.example"),
            (b"content-type", b"application/json"),
        ],
        raw_path=b"/documents/123",
        query_string=b"view=summary",
    )

    request = aauth_request_from_scope(scope)

    assert request.method == "GET"
    assert request.url == "https://documents.example/documents/123?view=summary"
    assert request.headers["content-type"] == "application/json"


def test_repeated_headers_remain_in_wire_order() -> None:
    scope = http_scope(
        headers=[
            (b"host", b"documents.example"),
            (b"x-example", b"first"),
            (b"X-Example", b"second"),
        ]
    )

    request = aauth_request_from_scope(scope)

    assert request.headers.get_all("x-example") == ["first", "second"]
    assert request.headers.raw_items() == [
        ("host", "documents.example"),
        ("x-example", "first"),
        ("X-Example", "second"),
    ]


def test_host_lookup_is_case_insensitive() -> None:
    request = aauth_request_from_scope(
        http_scope(headers=[(b"Host", b"documents.example")])
    )

    assert request.url == "https://documents.example/documents"


def test_raw_path_preserves_percent_encoding() -> None:
    request = aauth_request_from_scope(
        http_scope(path="/documents/a b", raw_path=b"/documents/a%20b")
    )

    assert request.url == "https://documents.example/documents/a%20b"


def test_missing_raw_path_percent_encodes_decoded_path() -> None:
    request = aauth_request_from_scope(
        http_scope(path="/documents/a b", raw_path=None)
    )

    assert request.url == "https://documents.example/documents/a%20b"


def test_query_string_is_preserved() -> None:
    request = aauth_request_from_scope(
        http_scope(query_string=b"search=a%20b&redirect=%2Farchive")
    )

    assert request.url == (
        "https://documents.example/documents"
        "?search=a%20b&redirect=%2Farchive"
    )


def test_missing_host_is_rejected() -> None:
    with pytest.raises(ASGIRequestError) as captured:
        aauth_request_from_scope(http_scope(headers=[(b"accept", b"*/*")]))

    assert captured.value.code == "missing_host_header"


def test_multiple_host_fields_are_rejected() -> None:
    with pytest.raises(ASGIRequestError) as captured:
        aauth_request_from_scope(
            http_scope(
                headers=[
                    (b"host", b"documents.example"),
                    (b"Host", b"other.example"),
                ]
            )
        )

    assert captured.value.code == "multiple_host_headers"


def test_non_http_scope_is_rejected() -> None:
    scope: Scope = {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "scheme": "wss",
        "path": "/documents",
        "raw_path": b"/documents",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"host", b"documents.example")],
        "server": ("127.0.0.1", 443),
        "client": ("127.0.0.1", 1234),
        "subprotocols": [],
    }

    with pytest.raises(ASGIRequestError) as captured:
        aauth_request_from_scope(scope)

    assert captured.value.code == "not_http_scope"


def test_non_ascii_request_target_is_rejected() -> None:
    with pytest.raises(ASGIRequestError) as captured:
        aauth_request_from_scope(http_scope(raw_path=b"/documents/\xff"))

    assert captured.value.code == "invalid_request_target"
