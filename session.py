"""The Access grant for one profile: storage, silent renewal, and browser sign-in.

State lives in ``$HERMES_HOME/cloudflare-ai-gateway/session.json`` (0600), per profile, keyed
to the exact inference URL. Hermes never holds the bearer: the SDK client asks
:meth:`GatewaySession.bearer` before every request, so renewal needs no client rebuild and
never touches conversation state. The org session renews app tokens silently; only when it
ends does a browser sign-in start, surfaced to Desktop as a plugin event, and the request that
needed it waits for that sign-in instead of failing the turn.
"""
import json
import logging
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .access import SessionExpired, Transfer, discover, exchange_org_token, verify_app_token

PROVIDER = "cloudflare-ai-gateway"
SKEW = 120  # renew this many seconds before an app token expires
# How long a request waits for a browser sign-in: under Hermes' 180s stale-call watchdog, so the
# turn fails as an auth error (no retry, no fallback) rather than as an unresponsive provider.
SIGN_IN_WAIT = 150

logger = logging.getLogger(__name__)
_lock = threading.RLock()
_attempts = {}  # (home, base_url) -> SignIn in flight


def _hermes_auth_error():
    from hermes_cli.auth_constants import AuthError
    return AuthError


def _broadcast(event, payload):
    try:
        from hermes_cli.plugin_events import broadcast_plugin_event
        broadcast_plugin_event(PROVIDER, event, payload)
    except Exception:
        logger.debug("Could not broadcast %s", event, exc_info=True)


def _forget_cached_catalog():
    """Drop the picker's cached catalog (the signed-out placeholder) so the full list loads now."""
    try:
        from hermes_cli.models import clear_provider_models_cache
        clear_provider_models_cache(PROVIDER)
    except Exception:
        logger.debug("Could not clear the cached model catalog", exc_info=True)


def sign_in_required(browser_url, reason=None):
    """The typed error a turn fails with; ``classify_api_error`` maps it to a no-retry auth verdict."""
    error = _hermes_auth_error()(
        (reason or "Cloudflare Access sign-in was not finished in time.")
        + f" Sign in, then press Retry. If no browser window opened, open this link: {browser_url}",
        provider=PROVIDER, code="reauth_required", relogin_required=True)
    error.cloudflare_sign_in_url = browser_url
    return error


def origin_of(base_url):
    u = urlsplit(base_url)
    return f"https://{u.netloc}"


class SignIn:
    """One browser sign-in attempt, finished on a background thread."""

    def __init__(self, session):
        self.session = session
        self.transfer = Transfer(origin_of(session.base_url))
        self.browser_url = self.transfer.browser_url
        self.cancelled = False
        self.error = None
        self.done = threading.Event()
        threading.Thread(target=self._run, name="cloudflare-access-sign-in", daemon=True).start()

    @property
    def active(self):
        return not self.done.is_set() and time.monotonic() < self.transfer.deadline

    def _run(self):
        try:
            grant = self.transfer.wait(lambda: self.cancelled)
            grant.update(auth_domain=self.transfer.auth_domain, issuer=self.transfer.issuer,
                         audience=self.transfer.audience)
            self.session.verify_inference(grant["app_token"])
            if not self.cancelled:
                self.session.save(grant)
                _forget_cached_catalog()
                _broadcast("signin.completed", {"base_url": self.session.base_url})
        except Exception as exc:
            self.error = str(exc)
            if not self.cancelled:
                logger.warning("Cloudflare Access sign-in for %s failed: %s", self.session.base_url, exc)
                _broadcast("signin.failed", {"base_url": self.session.base_url, "message": self.error})
        finally:
            self.transfer.close()
            self.done.set()


class GatewaySession:
    def __init__(self, home, base_url):
        self.home = Path(home)
        self.base_url = base_url.rstrip("/")
        self.path = self.home / PROVIDER / "session.json"

    # ── storage ────────────────────────────────────────────────────────────
    def read(self):
        try:
            state = json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}
        return state if state.get("base_url") == self.base_url else {}

    def save(self, grant):
        with _lock:
            state = {**self.read(), **grant, "base_url": self.base_url}
            if "app_token" in grant:
                state.pop("rejected", None)  # a new app token supersedes a rejected one
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(state, f)
            os.replace(tmp, self.path)

    def clear(self):
        with _lock:
            attempt = _attempts.pop((str(self.home), self.base_url), None)
            if attempt:
                attempt.cancelled = True
            try:
                self.path.unlink()
                return True
            except FileNotFoundError:
                return False

    # ── lifecycle ──────────────────────────────────────────────────────────
    def _usable_app_token(self, state):
        if state.get("app_token") and not state.get("rejected") and state.get("app_expires_at", 0) > time.time() + SKEW:
            return state["app_token"]
        return None

    def renew(self):
        """Mint a new app token from the org session. Returns it, or None if a sign-in is needed."""
        with _lock:
            state = self.read()
            if (token := self._usable_app_token(state)) is not None:
                return token  # another thread renewed while we waited
            if not state.get("org_token") or state.get("org_expires_at", 0) <= time.time() + 30:
                return None
            origin = origin_of(self.base_url)
            try:
                with httpx.Client(timeout=15, follow_redirects=False) as client:
                    auth_domain, issuer, audience, keys = discover(origin, client)
                    token = exchange_org_token(origin, state["org_token"], auth_domain, client)
                claims = verify_app_token(token, issuer, audience, keys)
            except SessionExpired:
                self.save({"org_token": None, "org_expires_at": 0})
                return None
            self.save({"app_token": token, "app_expires_at": claims["exp"]})
            logger.info("Renewed the Cloudflare Access token for %s", self.base_url)
            return token

    def bearer(self, interactive=True, cancelled=None):
        """The current app token, renewing silently. Otherwise, for a real turn (*interactive*),
        wait for a browser sign-in; a background catalog read raises instead."""
        if (token := self._usable_app_token(self.read())) is not None:
            return token
        if (token := self.renew()) is not None:
            return token
        if not interactive:
            raise _hermes_auth_error()("Not signed in to Cloudflare Access.", provider=PROVIDER,
                                       code="reauth_required", relogin_required=True)
        return self.await_sign_in(cancelled)

    def await_sign_in(self, cancelled=None):
        """Start (or join) the browser sign-in and block until it saves a grant; returns its app
        token. Raises the no-retry sign-in error if it fails, is cancelled (sign-out), is not
        finished within :data:`SIGN_IN_WAIT`, or *cancelled()* turns true (Hermes closed the
        client: the turn was stopped)."""
        attempt = self.start_sign_in()
        deadline = time.monotonic() + SIGN_IN_WAIT
        while not attempt.done.wait(.25):
            if cancelled is not None and cancelled():
                raise sign_in_required(attempt.browser_url, "The request was stopped before Cloudflare Access sign-in finished.")
            if time.monotonic() >= deadline:
                raise sign_in_required(attempt.browser_url)
        state = self.read()
        # Any unexpired token, not _usable_app_token: Access may hand over the browser's existing
        # app token even when it is inside the renewal skew.
        if state.get("app_token") and not state.get("rejected") and state.get("app_expires_at", 0) > time.time():
            return state["app_token"]
        reason = f"Cloudflare Access sign-in failed: {attempt.error.rstrip('.')}." if attempt.error else "Cloudflare Access sign-in did not complete."
        raise sign_in_required(attempt.browser_url, reason)

    def reject(self, bearer):
        """A 401 for *bearer*: drop it only if it is still the current token (a late 401 from an
        old request must not invalidate a newer grant)."""
        with _lock:
            if bearer and bearer == "Bearer " + (self.read().get("app_token") or ""):
                self.save({"rejected": True})

    def start_sign_in(self):
        """The in-flight browser sign-in for this gateway, starting one if needed (idempotent)."""
        key = (str(self.home), self.base_url)
        with _lock:
            attempt = _attempts.get(key)
            if attempt is None or not attempt.active:
                attempt = _attempts[key] = SignIn(self)
                _broadcast("signin.required", {"base_url": self.base_url, "browser_url": attempt.browser_url})
            return attempt

    def verify_inference(self, token):
        """Access accepted the identity for this gateway (an authenticated catalog read)."""
        response = httpx.get(self.base_url + "/models", headers={"Authorization": "Bearer " + token},
                             timeout=30, follow_redirects=False)
        messages = {
            401: "The gateway rejected the Access identity. Check bearer-token authentication on the Access application.",
            403: "The gateway denied this identity. Check the Access policy.",
            404: "Signed in, but the gateway inference URL was not found.",
        }
        if response.status_code != 200:
            raise ValueError(messages.get(response.status_code,
                                          f"Signed in, but the gateway answered HTTP {response.status_code}."))

    def status(self):
        state = self.read()
        attempt = _attempts.get((str(self.home), self.base_url))
        pending = attempt is not None and attempt.active
        now = time.time()
        return {
            "base_url": self.base_url,
            "signed_in": self._usable_app_token(state) is not None
                         or bool(state.get("org_token") and state.get("org_expires_at", 0) > now + 30),
            "token_expires_at": state.get("app_expires_at"),
            "session_expires_at": state.get("org_expires_at") or state.get("app_expires_at"),
            "pending": pending,
            "browser_url": attempt.browser_url if pending else None,
            "last_error": attempt.error if attempt is not None and not pending else None,
        }
