from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx2
import pytest
from flask import Flask

from aauth_edocs import (
    AAuthError,
    ControllerPolicy,
    Dataflow,
    ExactRule,
    FunctionDescriptor,
    HttpRequest,
    ResourceBinding,
    SentinelRegistry,
    SigningKey,
    VerifiedRequest,
    build_metadata,
    create_sentinel,
    issue_agent_token,
    issue_auth_token,
    issue_conditional_auth_token,
    issue_resource_token,
    sign,
    static_resolver,
)
from aauth_edocs.agent import TransportResponse
from aauth_edocs.asrv import create_as
from aauth_edocs.errors import DENIED, INVALID_REQUEST, INVALID_TOKEN
from aauth_edocs.httpsig import KeyResolver
from aauth_edocs.keys import jwk_thumbprint
from aauth_edocs.ids import DWK_ACCESS
from aauth_edocs.ps import create_ps
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from mcp_aauth import (
    AAuthAgentHTTPAuth,
    aauth_agent_authentication,
    aauth_authorization,
)

AP = "http://ap.local"
RESOURCE = "http://resource.local"
PS = "http://ps.local"
SENTINEL = "http://sentinel.local"
AS_A = "http://as-a.local"
AS_B = "http://as-b.local"
AGENT = "aauth:assistant@ap.local"
SOURCE = "aauth:source@ap.local"
EDOC_ID = "doc-123"
FUNCTION = "identity@1"


@dataclass(frozen=True)
class DemoResource:
    """Test application state, deliberately not part of mcp_aauth."""

    issuer: str
    sentinel: str
    source_agent: str
    destination_agent: str
    key: SigningKey
    controllers: tuple[str, ...]
    documents: Mapping[str, Any]
    functions: Mapping[str, FunctionDescriptor]

    def proposed_dataflow_token(
        self, verified_agent: VerifiedRequest, *, scope: str, edoc_id: str
    ) -> str:
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

    def identity(self, authorization: VerifiedRequest, *, edoc_id: str) -> Any:
        expected = {
            "iss": self.sentinel,
            "aud": self.issuer,
            "source_agent": self.source_agent,
            "scope": FUNCTION,
            "edoc_id": edoc_id,
            "agent": self.destination_agent,
            "controllers": list(self.controllers),
        }
        for name, value in expected.items():
            if authorization.claims.get(name) != value:
                raise AAuthError(
                    INVALID_TOKEN,
                    401,
                    f"authorization {name} does not match the invocation",
                )
        if edoc_id not in self.documents:
            raise AAuthError(DENIED, 403, "eDoc does not exist")
        return self.documents[edoc_id]


class DemoApplication:
    """Test-only composition of a proposed-dataflow endpoint and MCP."""

    def __init__(
        self,
        resource: DemoResource,
        mcp_app: ASGIApp,
        *,
        key_resolver: KeyResolver,
    ) -> None:
        self.resource = resource
        self.mcp_app = mcp_app
        self.proposal_app = aauth_agent_authentication(
            key_resolver=key_resolver
        )(self._proposal)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path") == "/resource-token":
            await self.proposal_app(scope, receive, send)
            return
        await self.mcp_app(scope, receive, send)

    async def _proposal(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("method") != "POST":
            await send_json(send, 405, {"error": "method_not_allowed"})
            return
        try:
            body = await read_json(receive)
            if set(body) != {"scope", "edoc_id"}:
                raise AAuthError(
                    INVALID_REQUEST,
                    400,
                    "request must contain exactly scope and edoc_id",
                )
            token = self.resource.proposed_dataflow_token(
                scope["aauth"],
                scope=body["scope"],
                edoc_id=body["edoc_id"],
            )
        except AAuthError as error:
            await send_json(send, error.status, error.body())
            return
        except (TypeError, ValueError, json.JSONDecodeError):
            await send_json(
                send,
                400,
                {"error": INVALID_REQUEST, "detail": "JSON object required"},
            )
            return
        await send_json(send, 200, {"resource_token": token})


async def read_json(receive: Receive) -> dict:
    chunks = []
    while True:
        message: Message = await receive()
        if message["type"] == "http.request":
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
    value = json.loads(b"".join(chunks))
    if not isinstance(value, dict):
        raise TypeError("JSON object required")
    return value


async def send_json(send: Send, status: int, value: dict) -> None:
    body = json.dumps(value, separators=(",", ":")).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class LoopbackTransport:
    def __init__(self) -> None:
        self.clients = {}

    def add(self, issuer: str, app: Flask) -> None:
        self.clients[urlsplit(issuer).netloc] = app.test_client()

    def request(self, method, url, headers=None, json=None):
        client = self.clients.get(urlsplit(url).netloc)
        if client is None:
            return TransportResponse(404, {}, {"error": "unknown host"})
        response = client.open(
            url,
            method=method,
            headers=headers or {},
            json=json,
        )
        return TransportResponse(
            response.status_code,
            dict(response.headers),
            response.get_json(silent=True),
        )

    def get(self, url):
        return self.request("GET", url)


def metadata_app(issuer: str, dwk: str, key: SigningKey) -> Flask:
    app = Flask(issuer)

    @app.get(f"/.well-known/{dwk}")
    def metadata():
        return dict(build_metadata(issuer, jwks_uri=f"{issuer}/jwks.json"))

    @app.get("/jwks.json")
    def jwks():
        return {"keys": [key.public_jwk]}

    return app


def world(*, conditional: bool = False):
    transport = LoopbackTransport()
    keys = {
        name: SigningKey.generate(kid=name)
        for name in ("ap", "resource", "ps", "sentinel", "as-a", "as-b", "agent")
    }
    descriptor = FunctionDescriptor(
        id=FUNCTION,
        description="Return the eDoc unchanged",
        implementation_uri="memory://identity",
        digest="sha256:identity",
    )
    proposal = Dataflow(SOURCE, FUNCTION, EDOC_ID, AGENT)
    prerequisite = Dataflow(SOURCE, "prepare@1", "doc-input", AGENT)
    registry = SentinelRegistry(
        resource_bindings={
            SOURCE: ResourceBinding(
                source_ps="http://source-ps.local",
                resource_issuer=RESOURCE,
                resource_jkt=keys["resource"].thumbprint,
            )
        },
        controllers={(RESOURCE, EDOC_ID): (AS_A, AS_B)},
        functions={FUNCTION: descriptor},
    )
    policy_a = ControllerPolicy((ExactRule(proposal),))
    policy_b = ControllerPolicy(
        (ExactRule(proposal, prerequisite if conditional else None),)
    )

    transport.add(AP, metadata_app(AP, "aauth-agent.json", keys["ap"]))
    transport.add(RESOURCE, metadata_app(RESOURCE, "aauth-resource.json", keys["resource"]))
    transport.add(
        AS_A,
        create_as(
            AS_A,
            key=keys["as-a"],
            transport=transport,
            sentinel=SENTINEL,
            controller_policy=policy_a,
        ),
    )
    transport.add(
        AS_B,
        create_as(
            AS_B,
            key=keys["as-b"],
            transport=transport,
            sentinel=SENTINEL,
            controller_policy=policy_b,
        ),
    )
    transport.add(
        SENTINEL,
        create_sentinel(
            issuer=SENTINEL,
            registry=registry,
            key=keys["sentinel"],
            transport=transport,
        ),
    )
    transport.add(
        PS,
        create_ps(
            PS,
            key=keys["ps"],
            person="alice",
            policy=lambda _agent, _resource: "pending",
            transport=transport,
        ),
    )

    agent_token = issue_agent_token(
        issuer=AP,
        agent=AGENT,
        agent_jwk=keys["agent"].public_jwk,
        ps=PS,
        key=keys["ap"],
    )
    resource = DemoResource(
        issuer=RESOURCE,
        sentinel=SENTINEL,
        source_agent=SOURCE,
        destination_agent=AGENT,
        key=keys["resource"],
        controllers=(AS_A, AS_B),
        documents={EDOC_ID: {"message": "hello"}},
        functions={FUNCTION: descriptor},
    )
    resolver = static_resolver(
        {
            AP: keys["ap"].public_jwk,
            SENTINEL: keys["sentinel"].public_jwk,
            AS_A: keys["as-a"].public_jwk,
            AS_B: keys["as-b"].public_jwk,
        }
    )
    return transport, keys, registry, proposal, resource, resolver, agent_token


async def proposed_resource_token_http(
    resource, resolver, keys, agent_token, downstream, body=None
):
    app = DemoApplication(
        resource,
        downstream,
        key_resolver=resolver,
    )
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url="http://127.0.0.1:8000",
        auth=AAuthAgentHTTPAuth(key=keys["agent"], token=agent_token),
    ) as client:
        return await client.post(
            "/resource-token",
            json=body or {"scope": FUNCTION, "edoc_id": EDOC_ID},
        )


def request_ps_authorization(transport, keys, agent_token, resource_token):
    request = sign(
        HttpRequest("POST", f"{PS}/token", {"host": "ps.local"}),
        keys["agent"],
        agent_token,
    )
    return transport.request(
        "POST",
        request.url,
        headers=request.headers,
        json={"resource_token": resource_token},
    )


def approve(transport, pending_url):
    assert transport.request("POST", f"{PS}/login", json={"person": "alice"}).status_code == 200
    pid = urlsplit(pending_url).path.rsplit("/", 1)[-1]
    return transport.request(
        "POST",
        f"{PS}/consent/{pid}",
        json={"decision": "grant"},
    )


def final_token(keys, **changes):
    values = {
        "issuer": SENTINEL,
        "dwk": DWK_ACCESS,
        "aud": RESOURCE,
        "agent": AGENT,
        "cnf_jwk": keys["agent"].public_jwk,
        "scope": FUNCTION,
        "source_agent": SOURCE,
        "edoc_id": EDOC_ID,
        "controllers": (AS_A, AS_B),
        "key": keys["sentinel"],
    }
    values.update(changes)
    return issue_auth_token(**values)


async def invoke_identity(resource, resolver, signing_key, token, *, edoc_id=EDOC_ID):
    executions = {"count": 0}
    server = MCPServer("edocs-negative")

    @server.tool()
    def identity(requested_edoc_id: str, ctx: Context) -> str:
        authorization = ctx.request_context.request.scope["aauth"]
        document = resource.identity(
            authorization,
            edoc_id=requested_edoc_id,
        )
        executions["count"] += 1
        return document["message"]

    app = server.streamable_http_app(
        authentication_middleware_factory=aauth_authorization(
            key_resolver=resolver,
            issuer=SENTINEL,
            audience=RESOURCE,
        )
    )
    url = "http://127.0.0.1:8000/mcp"
    try:
        async with server.session_manager.run():
            async with (
                httpx2.AsyncClient(
                    transport=httpx2.ASGITransport(app=app),
                    base_url=url,
                    auth=AAuthAgentHTTPAuth(key=signing_key, token=token),
                ) as http_client,
                Client(
                    streamable_http_client(url, http_client=http_client),
                    mode="legacy",
                ) as client,
            ):
                result = await client.call_tool(
                    "identity",
                    {"requested_edoc_id": edoc_id},
                )
        return result, None, executions["count"]
    except BaseException as error:
        return None, error, executions["count"]


@pytest.mark.anyio
async def test_full_aauth_edocs_mcp_authorization_flow():
    transport, keys, registry, proposal, resource, resolver, agent_token = world()

    server = MCPServer("edocs-demo")

    @server.tool()
    def identity(edoc_id: str, ctx: Context) -> str:
        authorization = ctx.request_context.request.scope["aauth"]
        return resource.identity(authorization, edoc_id=edoc_id)["message"]

    mcp_app = server.streamable_http_app(
        authentication_middleware_factory=aauth_authorization(
            key_resolver=resolver,
            issuer=SENTINEL,
            audience=RESOURCE,
        )
    )
    app = DemoApplication(
        resource,
        mcp_app,
        key_resolver=resolver,
    )
    token_response = await proposed_resource_token_http(
        resource, resolver, keys, agent_token, mcp_app
    )
    assert token_response.status_code == 200
    resource_token = token_response.json()["resource_token"]

    pending = request_ps_authorization(
        transport, keys, agent_token, resource_token
    )
    assert pending.status_code == 202
    approved = approve(transport, pending.headers["Location"])
    assert approved.status_code == 200

    final = transport.get(pending.headers["Location"])
    assert final.status_code == 200
    auth_token = final.json()["auth_token"]

    url = "http://127.0.0.1:8000/mcp"
    asgi_transport = httpx2.ASGITransport(app=app)

    async with server.session_manager.run():
        async with (
            httpx2.AsyncClient(
                transport=asgi_transport,
                base_url=url,
                auth=AAuthAgentHTTPAuth(key=keys["agent"], token=auth_token),
            ) as http_client,
            Client(
                streamable_http_client(url, http_client=http_client),
                mode="legacy",
            ) as client,
        ):
            result = await client.call_tool("identity", {"edoc_id": EDOC_ID})

    assert result.content[0].text == "hello"
    assert proposal in registry.materialized


@pytest.mark.anyio
async def test_missing_controller_prerequisite_denies_before_mcp():
    transport, keys, registry, proposal, resource, resolver, agent_token = world(
        conditional=True
    )
    async def downstream(scope, receive, send):
        raise AssertionError("MCP app should not be called")

    token_response = await proposed_resource_token_http(
        resource, resolver, keys, agent_token, downstream
    )
    assert token_response.status_code == 200
    resource_token = token_response.json()["resource_token"]
    pending = request_ps_authorization(
        transport, keys, agent_token, resource_token
    )

    recorded = approve(transport, pending.headers["Location"])
    denied = transport.get(pending.headers["Location"])

    assert recorded.status_code == 200
    assert recorded.json() == {"status": "recorded"}
    assert denied.status_code == 403
    assert denied.json()["error"] == "denied"
    assert "has not materialized" in denied.json()["detail"]
    assert proposal not in registry.materialized


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"scope": "unknown@1", "edoc_id": EDOC_ID}, 403),
        ({"scope": FUNCTION, "edoc_id": "missing"}, 403),
        ({"scope": f"{FUNCTION} other@1", "edoc_id": EDOC_ID}, 400),
        (
            {
                "scope": FUNCTION,
                "edoc_id": EDOC_ID,
                "source_agent": "client-controlled",
            },
            400,
        ),
    ],
)
async def test_resource_token_endpoint_rejects_invalid_proposals(body, status):
    _, keys, _, _, resource, resolver, agent_token = world()

    async def downstream(scope, receive, send):
        raise AssertionError("MCP app should not be called")

    response = await proposed_resource_token_http(
        resource, resolver, keys, agent_token, downstream, body
    )

    assert response.status_code == status


@pytest.mark.anyio
async def test_resource_token_endpoint_requires_signed_agent_request():
    _, _, _, _, resource, resolver, _ = world()

    async def downstream(scope, receive, send):
        raise AssertionError("MCP app should not be called")

    app = DemoApplication(
        resource,
        downstream,
        key_resolver=resolver,
    )
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url="http://127.0.0.1:8000",
    ) as client:
        response = await client.post(
            "/resource-token",
            json={"scope": FUNCTION, "edoc_id": EDOC_ID},
        )

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_signature"


@pytest.mark.anyio
async def test_mcp_rejects_invalid_authorization_envelopes_before_execution():
    _, keys, _, _, resource, resolver, _ = world()
    other_key = SigningKey.generate(kid="other-agent")
    controller_token = final_token(
        keys,
        issuer=AS_A,
        key=keys["as-a"],
    )
    wrong_audience = final_token(keys, aud="http://other-resource.local")
    conditional = issue_conditional_auth_token(
        issuer=AS_A,
        aud=SENTINEL,
        agent=AGENT,
        cnf_jwk=keys["agent"].public_jwk,
        scope=FUNCTION,
        source_agent=SOURCE,
        edoc_id=EDOC_ID,
        controllers=(AS_A, AS_B),
        prerequisite=Dataflow(SOURCE, "prepare@1", "doc-input", AGENT),
        key=keys["as-a"],
    )
    cases = [
        ("controller issuer", controller_token, keys["agent"]),
        ("wrong audience", wrong_audience, keys["agent"]),
        ("conditional token", conditional, keys["agent"]),
        ("wrong proof key", final_token(keys), other_key),
    ]

    for label, token, signing_key in cases:
        result, error, executions = await invoke_identity(
            resource,
            resolver,
            signing_key,
            token,
        )
        assert error is not None, label
        assert result is None, label
        assert executions == 0, label


@pytest.mark.anyio
async def test_mcp_rejects_dataflow_mismatches_before_execution():
    _, keys, _, _, resource, resolver, _ = world()
    cases = [
        ("wrong eDoc", final_token(keys, edoc_id="doc-456"), EDOC_ID),
        ("wrong function", final_token(keys, scope="other@1"), EDOC_ID),
        (
            "wrong source",
            final_token(keys, source_agent="aauth:other-source@ap.local"),
            EDOC_ID,
        ),
        (
            "wrong destination",
            final_token(keys, agent="aauth:other@ap.local"),
            EDOC_ID,
        ),
    ]

    for label, token, requested_edoc_id in cases:
        result, error, executions = await invoke_identity(
            resource,
            resolver,
            keys["agent"],
            token,
            edoc_id=requested_edoc_id,
        )
        assert error is None, label
        assert result.is_error, label
        assert executions == 0, label
