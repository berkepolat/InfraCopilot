from __future__ import annotations

import httpx

from eeap_shared.utils.service import build_service_app

from .auth_routes import router as auth_router
from .config import settings
from .context import GatewayState
from .proxy import router as proxy_router
from .ratelimit import RateLimiter
from .security import JwtIssuer

http_client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=3.0),
                                limits=httpx.Limits(max_connections=200, max_keepalive_connections=50))

app = build_service_app(
    settings,
    title="EEAP API Gateway",
    routers=[auth_router, proxy_router],
    outbox_schema="iam",
    on_shutdown=[http_client.aclose],
)

app.state.gateway = GatewayState(
    settings=settings,
    engine=app.state.engine,
    issuer=JwtIssuer(settings.jwt_signing_key(), settings.jwt_public_key(), settings.jwt_issuer,
                     settings.jwt_audience, settings.access_token_ttl_seconds),
    limiter=RateLimiter(app.state.redis),
    http=http_client,
    internal_private_key=settings.internal_token_private_key(),
)
