from __future__ import annotations

import time
from collections.abc import Callable

from aauth_edocs import AGENT_TYP, AAuthError, VerifiedRequest, verify
from aauth_edocs.errors import INVALID_SIGNATURE, INVALID_TOKEN
from aauth_edocs.httpsig import KeyResolver
from starlette.types import Scope

from .request import aauth_request_from_scope


def verify_aauth_agent(
    scope: Scope,
    key_resolver: KeyResolver,
    *,
    now: Callable[[], float] = time.time,
    signature_window: int = 60,
) -> VerifiedRequest:
    """Verify an ASGI request authenticated by an AAuth agent JWT."""
    verified = verify(
        aauth_request_from_scope(scope),
        key_resolver,
        now=now,
        window=signature_window,
    )

    if verified.token is None:
        raise AAuthError(
            INVALID_SIGNATURE,
            401,
            "MCP AAuth agent requests require Signature-Key scheme jwt",
        )
    if verified.header.get("typ") != AGENT_TYP:
        raise AAuthError(
            INVALID_TOKEN,
            401,
            f"expected typ {AGENT_TYP}, got {verified.header.get('typ')}",
        )

    return verified
