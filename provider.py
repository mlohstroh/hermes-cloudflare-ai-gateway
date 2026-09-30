"""Cloudflare AI Gateway behind Cloudflare Access, on an unmodified Hermes.

Hermes sees an ordinary ``api_key`` provider (so the main agent AND every auxiliary route build
their client through :meth:`GatewayProfile.create_client`). A non-secret pooled marker satisfies
Hermes' credential gate (no ``.env`` entry); it is never sent. The only bearer on the wire is the Access
application JWT, read from :class:`GatewaySession` before every request.
"""
from urllib.parse import urlsplit

import logging

import httpx
from openai import OpenAI
from providers.base import ProviderProfile

from .catalog import chat_models
from .session import PROVIDER, GatewaySession

logger = logging.getLogger(__name__)

PLACEHOLDER_ENV = "CLOUDFLARE_AI_GATEWAY_TOKEN"  # declared only so Hermes registers an api_key provider
PLACEHOLDER = "cloudflare-access"
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


def configured_settings():
    """``providers.cloudflare-ai-gateway`` in config.yaml: ``base_url`` (required), ``model``."""
    from hermes_cli.config import load_config
    section = (load_config().get("providers") or {}).get(PROVIDER) or {}
    return https_url(section.get("base_url")), str(section.get("model") or "").strip()


def session_for(base_url):
    from hermes_constants import get_hermes_home
    return GatewaySession(get_hermes_home(), base_url)


class AccessTransport(httpx.BaseTransport):
    """Keeps the Access bearer on the configured endpoint and retries a 401 once after renewal.

    A 401 comes from Access at the edge, before the gateway runs anything, so resending the same
    request with a renewed token cannot duplicate work.
    """

    def __init__(self, session, interactive=True):
        self.session = session
        self.interactive = interactive
        self.inner = httpx.HTTPTransport()

    def handle_request(self, request):
        if not str(request.url).split("?", 1)[0].startswith(self.session.base_url + "/"):
            raise ValueError("Refusing to send Access credentials outside the configured inference endpoint.")
        for name in SERVICE_TOKEN_HEADERS:
            request.headers.pop(name, None)
        response = self.inner.handle_request(request)
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

    def close(self):
        self.inner.close()


def make_client(session, interactive=True, **kwargs):
    allowed = {k: v for k, v in kwargs.items() if k in ("timeout", "max_retries", "default_headers")}
    return OpenAI(api_key=lambda: session.bearer(interactive), base_url=session.base_url,
                  http_client=httpx.Client(transport=AccessTransport(session, interactive), follow_redirects=False,
                                           timeout=kwargs.get("timeout") or 600), **allowed)


def classify(error, *, status_code, error_code, message, body, model):
    """Sign-in required is terminal for the turn: no retries, no fallback, no key rotation."""
    if getattr(error, "relogin_required", False) or status_code == 401:
        return {"reason": "auth", "retryable": False, "should_fallback": False,
                "should_rotate_credential": False}
    return None


class GatewayProfile(ProviderProfile):
    def create_client(self, **kwargs):
        base_url = str(kwargs.get("base_url") or "").rstrip("/")
        if not base_url:
            raise ValueError("Set providers.cloudflare-ai-gateway.base_url in config.yaml.")
        return make_client(session_for(https_url(base_url)), **kwargs)

    def fetch_models(self, *, api_key=None, base_url=None, timeout=8):
        """The live gateway catalog, or None. None (not a one-item list) makes Hermes treat
        ``fallback_models`` as a short-lived placeholder instead of caching it as the catalog."""
        base, selected = configured_settings()
        if not base.endswith("/compat"):
            return None
        try:
            with make_client(session_for(base), interactive=False, timeout=timeout, max_retries=0) as client:
                ids = [m.id for m in client.models.list().data]
        except Exception:
            return None
        return chat_models(ids, selected) if selected else sorted(ids)

    # Used by the Desktop half's backend routes (dashboard/plugin_api.py).
    def access_session(self):
        return session_for(configured_settings()[0])


POOL_SOURCE = "manual:cloudflare_access"


def ensure_credential_marker():
    """Satisfy Hermes' "has a credential" gate with no ``.env`` entry.

    An ``api_key`` provider is only selectable once Hermes finds a credential for it, and under
    Desktop's multi-profile hosting only the profile's own stores count (never ``os.environ``).
    This non-secret pooled row is that credential; it is never sent (see ``create_client``).
    """
    from agent.credential_pool import AUTH_TYPE_API_KEY, PooledCredential, load_pool
    pool = load_pool(PROVIDER)
    if any(entry.source == POOL_SOURCE for entry in pool.entries()):
        return
    pool.add_entry(PooledCredential(
        provider=PROVIDER, id="cfaccess", label="Cloudflare Access sign-in", auth_type=AUTH_TYPE_API_KEY,
        priority=0, source=POOL_SOURCE, access_token=PLACEHOLDER))


def profile():
    try:
        base_url, model = configured_settings()
    except Exception:
        base_url, model = "", ""
    try:
        ensure_credential_marker()
    except Exception:  # discovery can run mid-import of hermes_cli.auth; plugin_api.py retries at startup
        logger.debug("Deferred the Cloudflare credential marker", exc_info=True)
    return GatewayProfile(
        name=PROVIDER, display_name="Cloudflare AI Gateway",
        description="Cloudflare AI Gateway, signed in through Cloudflare Access",
        auth_type="api_key", env_vars=(PLACEHOLDER_ENV,), base_url=base_url,
        api_mode="chat_completions", fallback_models=(model,) if model else (),
        signup_url="https://developers.cloudflare.com/ai-gateway/configuration/cloudflare-access/",
        classify_api_error=classify)
