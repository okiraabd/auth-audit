"""
discovery/wordlist.py — Curated API route wordlist for auth-aware endpoint discovery.

Organised into categories so the route_discoverer can prioritise auth-signal
paths first.  This list is intentionally focused (~350 entries) on paths most
likely to reveal authentication signals (401, 403, live JSON, login form, etc.)
rather than trying to be exhaustive.

If kiterunner (kr) is available it can be used instead for a much larger corpus
(520k routes).  This wordlist serves as the always-available fallback.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Auth / Identity paths — highest priority for detecting auth signals
# ---------------------------------------------------------------------------
AUTH_PATHS: list[str] = [
    "/login",
    "/signin",
    "/sign-in",
    "/auth",
    "/auth/login",
    "/auth/signin",
    "/auth/token",
    "/auth/callback",
    "/auth/logout",
    "/auth/me",
    "/oauth/token",
    "/oauth/authorize",
    "/oauth2/token",
    "/oauth2/authorize",
    "/token",
    "/tokens",
    "/access_token",
    "/api/auth",
    "/api/auth/login",
    "/api/auth/token",
    "/api/auth/me",
    "/api/login",
    "/api/signin",
    "/api/token",
    "/api/session",
    "/api/sessions",
    "/api/logout",
    "/api/user",
    "/api/me",
    "/api/profile",
    "/api/account",
    "/api/accounts",
    "/session",
    "/sessions",
    "/logout",
    "/signout",
    "/user/login",
    "/user/signin",
    "/users/login",
    "/users/signin",
    "/v1/auth",
    "/v1/auth/login",
    "/v1/auth/token",
    "/v1/login",
    "/v1/token",
    "/v1/session",
    "/v2/auth",
    "/v2/auth/token",
    "/v2/login",
    "/v2/token",
    "/api/v1/auth",
    "/api/v1/auth/token",
    "/api/v1/login",
    "/api/v1/token",
    "/api/v1/session",
    "/api/v2/auth",
    "/api/v2/auth/token",
    "/api/v2/login",
    "/api/v2/token",
    "/identity/connect/token",
    "/connect/token",
    "/iam/token",
    "/security/token",
    "/jwt/token",
    "/sso",
    "/sso/login",
    "/cas/login",
    "/saml/login",
    "/saml/acs",
    "/oidc/token",
    "/openid/token",
    "/admin/login",
    "/admin/auth",
    "/dashboard/login",
]

# ---------------------------------------------------------------------------
# Common REST API paths — discover live endpoints
# ---------------------------------------------------------------------------
API_PATHS: list[str] = [
    "/",
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/v1",
    "/v2",
    "/v3",
    "/rest",
    "/rest/v1",
    "/rest/v2",
    "/api/v1/users",
    "/api/v1/user",
    "/api/v2/users",
    "/api/v1/accounts",
    "/api/v1/me",
    "/api/v1/profile",
    "/api/v1/settings",
    "/api/v1/config",
    "/api/v1/status",
    "/api/v1/health",
    "/api/v1/info",
    "/api/v1/version",
    "/api/v1/ping",
    "/api/v1/data",
    "/api/v1/items",
    "/api/v1/resources",
    "/api/v1/records",
    "/api/v1/search",
    "/api/v1/list",
    "/api/v1/admin",
    "/api/users",
    "/api/user",
    "/api/accounts",
    "/api/profile",
    "/api/settings",
    "/api/config",
    "/api/status",
    "/api/health",
    "/api/info",
    "/api/version",
    "/api/ping",
    "/api/search",
    "/api/list",
    "/api/data",
    "/api/admin",
    "/v1/users",
    "/v1/user",
    "/v1/accounts",
    "/v1/profile",
    "/v1/settings",
    "/v1/config",
    "/v1/data",
    "/v1/admin",
    "/users",
    "/user",
    "/accounts",
    "/account",
    "/profile",
    "/me",
    "/settings",
    "/config",
    "/admin",
    "/dashboard",
    "/data",
    "/search",
    "/items",
]

# ---------------------------------------------------------------------------
# Health / Status paths — detect if service is alive behind 404
# ---------------------------------------------------------------------------
HEALTH_PATHS: list[str] = [
    "/health",
    "/health/live",
    "/health/ready",
    "/healthz",
    "/livez",
    "/readyz",
    "/status",
    "/status/health",
    "/ping",
    "/pong",
    "/alive",
    "/ready",
    "/info",
    "/version",
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/metrics",
    "/metrics",
    "/.well-known/health",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/__health",
    "/__status",
    "/__ping",
    "/_health",
    "/_status",
    "/_ping",
]

# ---------------------------------------------------------------------------
# API documentation paths — detect open docs
# ---------------------------------------------------------------------------
DOCS_PATHS: list[str] = [
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger.json",
    "/swagger.yaml",
    "/openapi",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs.json",
    "/api/docs",
    "/api/swagger",
    "/api/openapi.json",
    "/v1/swagger.json",
    "/v1/openapi.json",
    "/api/v1/swagger.json",
    "/api/v1/openapi.json",
    "/redoc",
    "/docs",
    "/documentation",
    "/api/redoc",
    "/api/documentation",
]

# ---------------------------------------------------------------------------
# GraphQL paths
# ---------------------------------------------------------------------------
GRAPHQL_PATHS: list[str] = [
    "/graphql",
    "/gql",
    "/api/graphql",
    "/api/gql",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/api/query",
    "/graphql/v1",
]

# ---------------------------------------------------------------------------
# Admin / Management paths — rarely public, often auth-gated
# ---------------------------------------------------------------------------
ADMIN_PATHS: list[str] = [
    "/admin",
    "/admin/",
    "/admin/api",
    "/admin/login",
    "/admin/dashboard",
    "/management",
    "/management/health",
    "/manage",
    "/console",
    "/control",
    "/panel",
    "/cp",
    "/backend",
    "/internal",
    "/private",
    "/secure",
    "/portal",
    "/ops",
    "/operator",
]

# ---------------------------------------------------------------------------
# Aggregate — ordered by relevance for auth signal discovery
# ---------------------------------------------------------------------------
BUILTIN_API_PATHS: list[str] = (
    AUTH_PATHS
    + HEALTH_PATHS
    + DOCS_PATHS
    + GRAPHQL_PATHS
    + API_PATHS
    + ADMIN_PATHS
)

# Deduplicate while preserving order
_seen: set[str] = set()
_deduped: list[str] = []
for _p in BUILTIN_API_PATHS:
    if _p not in _seen:
        _seen.add(_p)
        _deduped.append(_p)
BUILTIN_API_PATHS = _deduped
