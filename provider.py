"""Cloudflare AI Gateway on an unmodified Hermes, with or without Cloudflare Access.

Hermes sees an ordinary ``api_key`` provider, so the main agent AND every auxiliary route build
their client through :meth:`GatewayProfile.create_client`. Two auth modes:

- ``access`` (a gateway on a custom domain behind Cloudflare Access): the bearer is the signed-in
  user's Access application token from :class:`GatewaySession`. A non-secret pooled marker
  satisfies Hermes' credential gate and is never sent.
- ``token`` (``gateway.ai.cloudflare.com`` / ``api.cloudflare.com``, which Access cannot front):
  the bearer is the key Hermes resolves for ``CLOUDFLARE_AI_GATEWAY_TOKEN`` — a Cloudflare API
  token for an authenticated gateway using stored keys or unified billing, or the upstream
  provider's key for an unauthenticated gateway.
"""
import logging
from urllib.parse import urlsplit

import httpx
from openai import OpenAI
from providers.base import ProviderProfile

from .catalog import chat_models
from .session import PROVIDER, GatewaySession

logger = logging.getLogger(__name__)

TOKEN_ENV = "CLOUDFLARE_AI_GATEWAY_TOKEN"
PLACEHOLDER = "cloudflare-access"
POOL_SOURCE = "manual:cloudflare_access"
# Cloudflare-operated gateway hosts; a customer's Access application cannot sit in front of them.
CLOUDFLARE_HOSTS = ("gateway.ai.cloudflare.com", "api.cloudflare.com")
MODES = ("access", "token")
# Access service tokens are not allowed: every request must carry the signed-in user's identity,
# even if config (model.extra_headers, custom provider headers) supplies a service token.
SERVICE_TOKEN_HEADERS = ("cf-access-client-id", "cf-access-client-secret")


def https_url(value):
    value = str(value or "").strip().rstrip("/")
    u = urlsplit(value)
    if (u.scheme != "https" or not u.hostname or u.username or u.password or u.query
            or u.fragment or u.port not in (None, 443) or not u.path
            or any(c.isspace() for c in value) or "\\" in value):
        raise ValueError("providers.cloudflare-ai-gateway.base_url must be an HTTPS inference URL "
                         "such as https://ai.example.com/compat")
    return u._replace(netloc=u.netloc.lower()).geturl()


def _section():
    from hermes_cli.config import load_config
    return (load_config().get("providers") or {}).get(PROVIDER) or {}


def auth_mode(base_url, section=None):
    """``auth`` from config when set, else ``token`` on Cloudflare-operated hosts, ``access`` otherwise."""
    explicit = str((section if section is not None else _section()).get("auth") or "").strip().lower()
    if explicit in MODES:
        return explicit
    return "token" if urlsplit(base_url).hostname in CLOUDFLARE_HOSTS else "access"


def configured_settings():
    """``providers.cloudflare-ai-gateway`` in config.yaml: ``base_url`` (required), ``model``, ``auth``."""
    section = _section()
    base_url = https_url(section.get("base_url"))
    return base_url, str(section.get("model") or "").strip(), auth_mode(base_url, section)


def session_for(base_url):
    from hermes_constants import get_hermes_home
    return GatewaySession(get_hermes_home(), base_url)


class EndpointTransport(httpx.BaseTransport):
    """Sends only to the configured endpoint, and never with Access service-token headers."""

    def __init__(self, base_url):
        self.base_url = base_url
        self.inner = httpx.HTTPTransport()

    def handle_request(self, request):
        if not str(request.url).split("?", 1)[0].startswith(self.base_url + "/"):
            raise ValueError("Refusing to send gateway credentials outside the configured inference endpoint.")
        for name in SERVICE_TOKEN_HEADERS:
            request.headers.pop(name, None)
        return self.inner.handle_request(request)

    def close(self):
        self.inner.close()


class AccessTransport(EndpointTransport):
    """Also retries a 401 once after renewing the Access token.

    A 401 comes from Access at the edge, before the gateway runs anything, so resending the same
    request with a renewed token cannot duplicate work.
    """

    def __init__(self, session, interactive=True):
        super().__init__(session.base_url)
        self.session = session
        self.interactive = interactive

    def handle_request(self, request):
        response = super().handle_request(request)
        if response.status_code != 401:
            return response
        self.session.reject(request.headers.get("Authorization", ""))
        token = self.session.renew()
        if token is None:
            if self.interactive:
                self.session.start_sign_in()
            return response
        response.close()
        request.headers["Authorization"] = "Bearer " + token
        return self.inner.handle_request(request)


def _client(api_key, base_url, transport, kwargs):
    allowed = {k: v for k, v in kwargs.items() if k in ("timeout", "max_retries", "default_headers")}
    return OpenAI(api_key=api_key, base_url=base_url,
                  http_client=httpx.Client(transport=transport, follow_redirects=False,
                                           timeout=kwargs.get("timeout") or 600), **allowed)


def make_client(session, interactive=True, **kwargs):
    return _client(lambda: session.bearer(interactive), session.base_url, AccessTransport(session, interactive), kwargs)


def make_token_client(base_url, api_key, **kwargs):
    if not api_key or api_key == PLACEHOLDER:
        raise ValueError(f"Set {TOKEN_ENV} (Settings → Providers → Keys) to your Cloudflare API token "
                         "or provider key for this gateway.")
    return _client(api_key, base_url, EndpointTransport(base_url), kwargs)


def classify(error, *, status_code, error_code, message, body, model):
    """Sign-in required (or a rejected token) is terminal for the turn: no retries, no fallback."""
    if getattr(error, "relogin_required", False) or status_code == 401:
        return {"reason": "auth", "retryable": False, "should_fallback": False,
                "should_rotate_credential": False}
    return None


class GatewayProfile(ProviderProfile):
    def create_client(self, **kwargs):
        base_url = str(kwargs.get("base_url") or "").rstrip("/")
        if not base_url:
            raise ValueError("Set providers.cloudflare-ai-gateway.base_url in config.yaml.")
        base_url = https_url(base_url)
        if auth_mode(base_url) == "token":
            return make_token_client(base_url, kwargs.get("api_key"), **kwargs)
        return make_client(session_for(base_url), **kwargs)

    def fetch_models(self, *, api_key=None, base_url=None, timeout=8):
        """The live gateway catalog, or None. None (not a one-item list) makes Hermes treat
        ``fallback_models`` as a short-lived placeholder instead of caching it as the catalog."""
        base, selected, mode = configured_settings()
        try:
            if mode == "token":
                client = make_token_client(base, api_key, timeout=timeout, max_retries=0)
            else:
                client = make_client(session_for(base), interactive=False, timeout=timeout, max_retries=0)
            with client:
                ids = [m.id for m in client.models.list().data]
        except Exception:
            return None
        return chat_models(ids, selected) if selected else sorted(ids)

    # Used by the Desktop half's backend routes (dashboard/plugin_api.py).
    def auth_mode(self):
        return configured_settings()[2]

    def access_session(self):
        return session_for(configured_settings()[0])


def ensure_credential_marker():
    """Access mode: satisfy Hermes' "has a credential" gate with no ``.env`` entry.

    An ``api_key`` provider is only selectable once Hermes finds a credential for it, and under
    Desktop's multi-profile hosting only the profile's own stores count (never ``os.environ``).
    This non-secret pooled row is that credential; it is never sent (see ``create_client``).
    Token mode removes it, so the real token is the one Hermes resolves.
    """
    from agent.credential_pool import AUTH_TYPE_API_KEY, PooledCredential, load_pool
    try:
        mode = configured_settings()[2]
    except ValueError:
        return  # no gateway configured yet
    pool = load_pool(PROVIDER)
    markers = [i for i, entry in enumerate(pool.entries(), 1) if entry.source == POOL_SOURCE]
    if mode == "token":
        for index in reversed(markers):
            pool.remove_index(index)
    elif not markers:
        pool.add_entry(PooledCredential(
            provider=PROVIDER, id="cfaccess", label="Cloudflare Access sign-in", auth_type=AUTH_TYPE_API_KEY,
            priority=0, source=POOL_SOURCE, access_token=PLACEHOLDER))


def profile():
    try:
        base_url, model, _ = configured_settings()
    except Exception:
        base_url, model = "", ""
    try:
        ensure_credential_marker()
    except Exception:  # discovery can run mid-import of hermes_cli.auth; plugin_api.py retries at startup
        logger.debug("Deferred the Cloudflare credential marker", exc_info=True)
    return GatewayProfile(
        name=PROVIDER, display_name="Cloudflare AI Gateway",
        description="Cloudflare AI Gateway, with Cloudflare Access sign-in or an API token",
        auth_type="api_key", env_vars=(TOKEN_ENV,), base_url=base_url,
        api_mode="chat_completions", fallback_models=(model,) if model else (),
        signup_url="https://developers.cloudflare.com/ai-gateway/usage/chat-completion/",
        classify_api_error=classify)
