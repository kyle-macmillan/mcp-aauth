from __future__ import annotations

import asyncio

import httpx2
import pytest
from aauth_edocs import (
    ApprovalRequired,
    HttpRequest,
    SigningKey,
    build_requirement,
    issue_agent_token,
    static_resolver,
    verify,
)

from mcp_aauth import AAuthAgentHTTPAuth


def test_signs_final_request_and_covered_headers() -> None:
    ap = "https://ap.example"
    agent = "assistant@ap.example"
    ap_key = SigningKey.generate(kid="ap-1")
    agent_key = SigningKey.generate(kid="agent-1")
    token = issue_agent_token(
        issuer=ap,
        agent=agent,
        agent_jwk=agent_key.public_jwk,
        key=ap_key,
        ps="https://ps.example",
    )
    request = httpx2.Request(
        "POST",
        "https://resource.example/mcp?session=1",
        headers={
            "Authorization": "AAuth resource-token",
            "AAuth-Mission": 'approver="https://ps.example";s256="digest"',
        },
    )

    signed_request = next(
        AAuthAgentHTTPAuth(
            key=agent_key,
            token=token,
            now=lambda: 1000.0,
        ).auth_flow(request)
    )

    for name in ("Signature-Key", "Signature-Input", "Signature"):
        assert name in signed_request.headers

    verified = verify(
        HttpRequest(
            signed_request.method,
            str(signed_request.url),
            (
                (name.decode("ascii"), value.decode("latin-1"))
                for name, value in signed_request.headers.raw
            ),
        ),
        static_resolver({ap: ap_key.public_jwk}),
        now=lambda: 1000.0,
    )

    assert {"authorization", "aauth-mission"} <= set(verified.covered)


class FakeCoordinator:
    def __init__(self, final_token, *, pending=False):
        self.final_token = final_token
        self.pending = pending
        self.begun = []
        self.completed = []
        self.invalidated = []

    def token_for(self, resource_url):
        return None

    def invalidate(self, resource_url):
        self.invalidated.append(resource_url)

    def begin(self, resource_token, *, resource_url):
        self.begun.append((resource_token, resource_url))
        if self.pending:
            return ApprovalRequired(
                pending_url="https://ps.example/opaque/1",
                resource_origin="https://resource.example",
                headers={},
            )
        return self.final_token

    def complete(self, approval):
        self.completed.append(approval)
        return self.final_token

    async def begin_async(self, resource_token, *, resource_url):
        return self.begin(resource_token, resource_url=resource_url)

    async def complete_async(self, approval):
        return self.complete(approval)


def _signature_key_token(request):
    return request.headers["Signature-Key"].split("jwt=", 1)[1].strip('"')


def test_exchanges_resource_challenge_and_retries():
    key = SigningKey.generate(kid="agent")
    coordinator = FakeCoordinator("final-token")
    auth = AAuthAgentHTTPAuth(
        key=key,
        token="agent-token",
        coordinator=coordinator,
    )
    flow = auth.auth_flow(httpx2.Request("POST", "https://resource.example/mcp"))
    first = next(flow)
    assert _signature_key_token(first) == "agent-token"

    retry = flow.send(
        httpx2.Response(
            401,
            headers={
                "AAuth-Requirement": build_requirement(
                    "auth-token",
                    resource_token="resource-token",
                )
            },
        )
    )
    assert coordinator.begun == [
        ("resource-token", "https://resource.example/mcp")
    ]
    assert _signature_key_token(retry) == "final-token"


def test_surfaces_pending_approval_before_retry():
    key = SigningKey.generate(kid="agent")
    coordinator = FakeCoordinator("final-token", pending=True)
    approvals = []
    auth = AAuthAgentHTTPAuth(
        key=key,
        token="agent-token",
        coordinator=coordinator,
        on_approval_required=approvals.append,
    )
    flow = auth.auth_flow(httpx2.Request("POST", "https://resource.example/mcp"))
    next(flow)

    retry = flow.send(
        httpx2.Response(
            401,
            headers={
                "AAuth-Requirement": build_requirement(
                    "auth-token",
                    resource_token="resource-token",
                )
            },
        )
    )
    assert len(approvals) == 1
    assert coordinator.completed == approvals
    assert _signature_key_token(retry) == "final-token"


def test_pending_without_host_callback_does_not_poll_or_retry():
    key = SigningKey.generate(kid="agent")
    coordinator = FakeCoordinator("final-token", pending=True)
    auth = AAuthAgentHTTPAuth(
        key=key,
        token="agent-token",
        coordinator=coordinator,
    )
    flow = auth.auth_flow(httpx2.Request("POST", "https://resource.example/mcp"))
    next(flow)

    with pytest.raises(StopIteration):
        flow.send(
            httpx2.Response(
                401,
                headers={
                    "AAuth-Requirement": build_requirement(
                        "auth-token",
                        resource_token="resource-token",
                    )
                },
            )
        )
    assert coordinator.completed == []


@pytest.mark.anyio
async def test_async_http_client_retries_after_coordinated_approval():
    key = SigningKey.generate(kid="agent")
    coordinator = FakeCoordinator("final-token", pending=True)
    approvals = []
    attempts = []

    async def app(scope, receive, send):
        headers = {
            name.decode("ascii").lower(): value.decode("latin-1")
            for name, value in scope["headers"]
        }
        attempts.append(headers["signature-key"])
        if 'jwt="final-token"' not in headers["signature-key"]:
            requirement = build_requirement(
                "auth-token",
                resource_token="resource-token",
            ).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"aauth-requirement", requirement)],
                }
            )
        else:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [],
                }
            )
        await send({"type": "http.response.body", "body": b""})

    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url="https://resource.example",
        auth=AAuthAgentHTTPAuth(
            key=key,
            token="agent-token",
            coordinator=coordinator,
            on_approval_required=approvals.append,
        ),
    ) as client:
        response = await client.get("/mcp")

    assert response.status_code == 200
    assert len(attempts) == 2
    assert 'jwt="agent-token"' in attempts[0]
    assert 'jwt="final-token"' in attempts[1]
    assert coordinator.completed == approvals


@pytest.mark.anyio
async def test_async_host_callback_can_wait_without_blocking_other_tasks():
    key = SigningKey.generate(kid="agent")
    coordinator = FakeCoordinator("final-token", pending=True)
    approval_started = asyncio.Event()
    allow_approval = asyncio.Event()
    unrelated_work_completed = asyncio.Event()

    async def approval_callback(_approval):
        approval_started.set()
        await allow_approval.wait()

    async def app(scope, receive, send):
        headers = {
            name.decode("ascii").lower(): value.decode("latin-1")
            for name, value in scope["headers"]
        }
        final = 'jwt="final-token"' in headers["signature-key"]
        response_headers = []
        if not final:
            response_headers.append(
                (
                    b"aauth-requirement",
                    build_requirement(
                        "auth-token",
                        resource_token="resource-token",
                    ).encode(),
                )
            )
        await send(
            {
                "type": "http.response.start",
                "status": 200 if final else 401,
                "headers": response_headers,
            }
        )
        await send({"type": "http.response.body", "body": b""})

    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url="https://resource.example",
        auth=AAuthAgentHTTPAuth(
            key=key,
            token="agent-token",
            coordinator=coordinator,
            on_approval_required=approval_callback,
        ),
    ) as client:
        request_task = asyncio.create_task(client.get("/mcp"))
        await approval_started.wait()

        async def unrelated_work():
            await asyncio.sleep(0)
            unrelated_work_completed.set()

        await unrelated_work()
        assert unrelated_work_completed.is_set()
        assert not request_task.done()

        allow_approval.set()
        response = await request_task

    assert response.status_code == 200


@pytest.mark.anyio
async def test_async_approval_wait_can_be_cancelled():
    key = SigningKey.generate(kid="agent")
    coordinator = FakeCoordinator("final-token", pending=True)
    approval_started = asyncio.Event()
    wait_forever = asyncio.Event()

    async def approval_callback(_approval):
        approval_started.set()
        await wait_forever.wait()

    async def app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (
                        b"aauth-requirement",
                        build_requirement(
                            "auth-token",
                            resource_token="resource-token",
                        ).encode(),
                    )
                ],
            }
        )
        await send({"type": "http.response.body", "body": b""})

    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url="https://resource.example",
        auth=AAuthAgentHTTPAuth(
            key=key,
            token="agent-token",
            coordinator=coordinator,
            on_approval_required=approval_callback,
        ),
    ) as client:
        request_task = asyncio.create_task(client.get("/mcp"))
        await approval_started.wait()
        request_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request_task

    assert coordinator.completed == []
