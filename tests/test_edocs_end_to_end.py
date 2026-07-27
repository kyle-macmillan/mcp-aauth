from __future__ import annotations

from urllib.parse import urlsplit

import httpx2
import pytest
from flask import Flask

from aauth_edocs import (
    ControllerPolicy,
    Dataflow,
    ExactRule,
    FunctionDescriptor,
    HttpRequest,
    ResourceBinding,
    SentinelRegistry,
    SigningKey,
    build_metadata,
    create_sentinel,
    issue_agent_token,
    sign,
    static_resolver,
)
from aauth_edocs.agent import TransportResponse
from aauth_edocs.asrv import create_as
from aauth_edocs.ps import create_ps
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from starlette.types import Scope

from mcp_aauth import (
    AAuthAgentHTTPAuth,
    EdocsResource,
    aauth_authorization,
    verify_aauth_agent,
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


def asgi_scope(request: HttpRequest) -> Scope:
    parts = urlsplit(request.url)
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": request.method,
        "scheme": parts.scheme,
        "path": parts.path,
        "raw_path": parts.path.encode(),
        "query_string": parts.query.encode(),
        "root_path": "",
        "headers": [
            (name.encode("ascii"), value.encode("latin-1"))
            for name, value in request.headers.raw_items()
        ],
        "server": (parts.hostname, parts.port or 80),
        "client": ("127.0.0.1", 1234),
    }


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
    resource = EdocsResource(
        issuer=RESOURCE,
        sentinel=SENTINEL,
        source_agent=SOURCE,
        key=keys["resource"],
        controllers=(AS_A, AS_B),
        documents={EDOC_ID: {"message": "hello"}},
        functions={FUNCTION: descriptor},
    )
    resolver = static_resolver(
        {
            AP: keys["ap"].public_jwk,
            SENTINEL: keys["sentinel"].public_jwk,
        }
    )
    return transport, keys, registry, proposal, resource, resolver, agent_token


def proposed_resource_token(resource, resolver, keys, agent_token):
    request = sign(
        HttpRequest("POST", f"{RESOURCE}/authorize", {"host": "resource.local"}),
        keys["agent"],
        agent_token,
    )
    verified_agent = verify_aauth_agent(asgi_scope(request), resolver)
    return resource.authorize(
        verified_agent,
        scope=FUNCTION,
        edoc_id=EDOC_ID,
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


@pytest.mark.anyio
async def test_full_aauth_edocs_mcp_authorization_flow():
    transport, keys, registry, proposal, resource, resolver, agent_token = world()
    resource_token = proposed_resource_token(resource, resolver, keys, agent_token)

    pending = request_ps_authorization(
        transport, keys, agent_token, resource_token
    )
    assert pending.status_code == 202
    approved = approve(transport, pending.headers["Location"])
    assert approved.status_code == 200

    final = transport.get(pending.headers["Location"])
    assert final.status_code == 200
    auth_token = final.json()["auth_token"]

    server = MCPServer("edocs-demo")

    @server.tool()
    def identity(edoc_id: str, ctx: Context) -> str:
        authorization = ctx.request_context.request.scope["aauth"]
        return resource.identity(
            authorization,
            edoc_id=edoc_id,
            destination_agent=authorization.claims["agent"],
        )["message"]

    app = server.streamable_http_app(
        authentication_middleware_factory=aauth_authorization(
            key_resolver=resolver,
            issuer=SENTINEL,
            audience=RESOURCE,
        )
    )
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


def test_missing_controller_prerequisite_denies_before_mcp():
    transport, keys, registry, proposal, resource, resolver, agent_token = world(
        conditional=True
    )
    resource_token = proposed_resource_token(resource, resolver, keys, agent_token)
    pending = request_ps_authorization(
        transport, keys, agent_token, resource_token
    )

    denied = approve(transport, pending.headers["Location"])

    assert denied.status_code == 403
    assert denied.json()["error"] == "denied"
    assert proposal not in registry.materialized
