"""
utils/urls.py — URL normalisation and manipulation helpers.

All functions are pure (no I/O, no side effects) so they can be unit-tested
in isolation and used freely in any tier without concern for ordering or
async context.

Public API:
  normalise_domain(raw)            → clean FQDN string
  build_probe_url(domain, path)    → full https/http URL string
  is_auth_path(path)               → bool
  is_external_domain(url, origin)  → bool
  classify_redirect_chain(chain)   → summary dict
  extract_domain_from_url(url)     → hostname string
"""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

# ---------------------------------------------------------------------------
# Known authentication path fragments — used by is_auth_path()
# ---------------------------------------------------------------------------

_AUTH_PATH_FRAGMENTS: frozenset[str] = frozenset(
    {
        "/login",
        "/signin",
        "/sign-in",
        "/auth",
        "/authenticate",
        "/sso",
        "/oauth",
        "/oauth2",
        "/oidc",
        "/saml",
        "/cas",
        "/idp",
        "/logout",
        "/signout",
        "/sign-out",
        "/account/login",
        "/user/login",
        "/users/sign_in",
        "/admin/login",
        "/wp-login.php",
        "/wp-admin",
    }
)

# Known external auth provider hostnames (partial match — startswith / endswith)
_AUTH_PROVIDER_HOSTS: tuple[str, ...] = (
    "accounts.google.com",
    "login.microsoftonline.com",
    "login.live.com",
    "auth0.com",
    "okta.com",
    "onelogin.com",
    "pingidentity.com",
    "keycloak",       # self-hosted; match by substring
    "authelia",
    "authentik",
    "vouch",
    "oauth2-proxy",
    "dex.",
)


# ---------------------------------------------------------------------------
# Core normalisation
# ---------------------------------------------------------------------------


def normalise_domain(raw: str) -> str:
    """
    Extract and normalise a clean FQDN from a raw domain string.

    Handles inputs like:
      - ``"example.com"``           → ``"example.com"``
      - ``"https://example.com/"``  → ``"example.com"``
      - ``"Example.COM:443"``       → ``"example.com"``
      - ``"  api.service.io  "``    → ``"api.service.io"``

    Port numbers are stripped — the probe scheme determines the effective port.

    Raises:
        ValueError: If no valid hostname can be extracted.
    """
    raw = raw.strip()
    if not raw:
        raise ValueError("Cannot normalise an empty string.")

    # Prepend a dummy scheme so urlparse handles host:port correctly
    if "://" not in raw:
        working = "https://" + raw
    else:
        working = raw

    try:
        parsed = urlparse(working)
        hostname = parsed.hostname  # lowercased, port stripped
    except Exception as exc:
        raise ValueError(f"Cannot parse domain from {raw!r}: {exc}") from exc

    if not hostname:
        raise ValueError(f"Cannot extract hostname from {raw!r}.")

    # Reject bare IP-like strings that lack a TLD (optional strictness)
    return hostname


def extract_domain_from_url(url: str) -> str:
    """
    Extract the hostname from a full URL string.

    >>> extract_domain_from_url("https://api.example.com/v1/users?page=2")
    'api.example.com'
    """
    return normalise_domain(url)


# ---------------------------------------------------------------------------
# Probe URL construction
# ---------------------------------------------------------------------------


def build_probe_url(domain: str, path: str, scheme: str = "https") -> str:
    """
    Construct a full probe URL from a domain and a path.

    Args:
        domain: Clean FQDN (no scheme). e.g. ``"example.com"``
        path:   Path starting with ``/``. e.g. ``"/api/v1"``
        scheme: ``"https"`` (default) or ``"http"``.

    Returns:
        A full URL string. e.g. ``"https://example.com/api/v1"``

    >>> build_probe_url("example.com", "/login")
    'https://example.com/login'
    >>> build_probe_url("example.com", "/api", scheme="http")
    'http://example.com/api'
    """
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{domain}{path}"


# ---------------------------------------------------------------------------
# Auth signal helpers
# ---------------------------------------------------------------------------


def is_auth_path(path: str) -> bool:
    """
    Return True if the path is a known authentication / login endpoint.

    Matches by checking whether the path starts with any of the known
    auth path fragments (case-insensitive).

    >>> is_auth_path("/login")
    True
    >>> is_auth_path("/api/v1/users")
    False
    """
    lower = path.lower().rstrip("/")
    return any(lower == frag or lower.startswith(frag + "/") for frag in _AUTH_PATH_FRAGMENTS)


def is_external_domain(url: str, origin_domain: str) -> bool:
    """
    Return True if ``url`` resolves to a different domain than ``origin_domain``.

    Used to detect external auth redirects (e.g. redirect to Keycloak, Authelia).

    >>> is_external_domain("https://keycloak.internal/auth/realms/master", "myapp.internal")
    True
    >>> is_external_domain("https://myapp.internal/login", "myapp.internal")
    False
    """
    try:
        target_host = extract_domain_from_url(url)
        origin_host = normalise_domain(origin_domain)
    except ValueError:
        return False
    return target_host != origin_host


def is_known_auth_provider(url: str) -> bool:
    """
    Return True if the URL's hostname matches a known auth provider pattern.

    Checks both exact suffix matches and substring matches for self-hosted
    providers whose hostnames vary (e.g. ``keycloak.company.internal``).

    >>> is_known_auth_provider("https://accounts.google.com/o/oauth2/auth")
    True
    >>> is_known_auth_provider("https://keycloak.internal/auth")
    True
    """
    try:
        host = extract_domain_from_url(url).lower()
    except ValueError:
        return False

    return any(provider in host for provider in _AUTH_PROVIDER_HOSTS)


# ---------------------------------------------------------------------------
# Redirect chain analysis
# ---------------------------------------------------------------------------


def classify_redirect_chain(
    chain: list[str],
    origin_domain: str,
) -> dict:
    """
    Summarise a redirect chain from the perspective of ``origin_domain``.

    Args:
        chain:         Ordered list of intermediate redirect URLs (not including
                       the initial request URL or the final response URL).
        origin_domain: The domain being probed (used to detect external hops).

    Returns:
        A dict with keys:
          ``hop_count``          — number of redirects
          ``has_auth_path``      — True if any URL is an auth path
          ``is_external``        — True if any redirect crossed to another domain
          ``auth_provider_hit``  — True if a known auth provider was reached
          ``redirect_targets``   — list of all URLs in the chain
    """
    hop_count = len(chain)
    has_auth = any(is_auth_path(urlparse(u).path) for u in chain)
    is_external = any(is_external_domain(u, origin_domain) for u in chain)
    auth_provider = any(is_known_auth_provider(u) for u in chain)

    return {
        "hop_count": hop_count,
        "has_auth_path": has_auth,
        "is_external": is_external,
        "auth_provider_hit": auth_provider,
        "redirect_targets": chain,
    }
