"""Cloudflare Access protocol: encrypted browser transfer and silent org-token exchange.

Protocol reference: cloudflare/cloudflared token/{token,jwks,transfer,encrypt}.go.
Fresh NaCl keypairs bind each browser interaction to its backend attempt. The org token
(the team-domain session) is kept only to mint new app tokens without a browser, and is
only ever sent to the verified team domain.
"""
import base64
import json
import logging
import time
from urllib.parse import urlencode, urljoin, urlsplit

import httpx
import jwt
from .naclbox import PrivateKey

TRANSFER_ORIGIN = "https://login.cloudflareaccess.org"
TOKEN_COOKIE = "CF_Authorization"
APP_SESSION_COOKIE = "CF_AppSession"
LOGIN_PATH = "/cdn-cgi/access/login"
AUTHORIZED_PATH = "/cdn-cgi/access/authorized"
MAX_RESPONSE = 1024 * 1024

logger = logging.getLogger(__name__)


class SessionExpired(Exception):
    """The Access org session can no longer mint app tokens; the user must sign in again."""


def response_bytes(client, method, url, **kwargs):
    with client.stream(method, url, **kwargs) as response:
        chunks = bytearray()
        for chunk in response.iter_bytes():
            chunks.extend(chunk)
            if len(chunks) > MAX_RESPONSE:
                raise ValueError("Access response exceeded the size limit.")
        return response.status_code, response.headers, bytes(chunks)


def verify_jwt(token, keys, **kwargs):
    header = jwt.get_unverified_header(token)
    key = next((k for k in keys["keys"] if k.get("kid") == header.get("kid")), None)
    if key is None or header.get("alg") != "RS256":
        raise ValueError("Access signing key is unavailable.")
    return jwt.decode(token, jwt.PyJWK.from_dict(key).key, algorithms=["RS256"], **kwargs)


def discover(origin, client):
    """(team domain, issuer, audience, JWKS) for the Access application in front of *origin*."""
    response = client.head(origin, headers={"cf-access-metadata-request": "true"})
    token = response.headers.get("cf-access-metadata", "")
    if not token:
        raise ValueError(f"{origin} is not protected by Cloudflare Access.")
    untrusted = jwt.decode(token, options={"verify_signature": False})
    domain = untrusted.get("auth_domain", "").lower()
    if not domain.endswith(".cloudflareaccess.com") or any(c in domain for c in "/:@?#\\"):
        raise ValueError("Access metadata returned an invalid team domain.")
    issuer = f"https://{domain}"
    status, _, body = response_bytes(client, "GET", issuer + "/cdn-cgi/access/certs")
    if status != 200:
        raise ValueError("Could not retrieve Access signing keys.")
    keys = json.loads(body)
    claims = verify_jwt(token, keys, options={"verify_aud": False, "require": ["iat"]}, leeway=300)
    if (claims.get("hostname", "").lower() != urlsplit(origin).hostname
            or claims.get("type") != "match" or not claims.get("aud")
            or not isinstance(claims["aud"], str)
            or time.time() - claims["iat"] > 86400):
        raise ValueError("Access application metadata did not match this gateway.")
    return domain, issuer, claims["aud"], keys


def verify_app_token(token, issuer, audience, keys):
    return verify_jwt(token, keys, audience=audience, issuer=issuer,
                      options={"require": ["exp", "iat", "aud", "iss"]})


class Transfer:
    """One browser sign-in: open ``browser_url`` anywhere, then ``wait()`` on the backend."""

    def __init__(self, origin):
        self.origin = origin
        self.client = httpx.Client(timeout=15, follow_redirects=False)
        try:
            self.auth_domain, self.issuer, self.audience, self.keys = discover(origin, self.client)
        except Exception:
            self.client.close()
            raise
        self.private_key = PrivateKey()
        public = base64.urlsafe_b64encode(self.private_key.public_key).decode()
        params = {"token": public, "aud": self.audience}
        params["redirect_url"] = origin + "?" + urlencode(params)
        params.update(send_org_token="true", edge_token_transfer="true")
        self.browser_url = origin + "/cdn-cgi/access/cli?" + urlencode(params)
        self.poll_url = TRANSFER_ORIGIN + "/transfer/" + public
        self.deadline = time.monotonic() + 600

    def wait(self, cancelled):
        """Return the verified grant: ``{app_token, app_expires_at, org_token?, org_expires_at?}``."""
        while time.monotonic() < self.deadline and not cancelled():
            try:
                status, headers, body = response_bytes(self.client, "GET", self.poll_url, timeout=30)
            except httpx.ReadTimeout:
                continue
            if cancelled():
                break
            if status == 200:
                peer = base64.urlsafe_b64decode(headers["service-public-key"])
                payload = json.loads(self.private_key.box_open(peer, base64.b64decode(body, validate=True)))
                app = payload["app_token"]
                claims = verify_app_token(app, self.issuer, self.audience, self.keys)
                grant = {"app_token": app, "app_expires_at": claims["exp"]}
                # The org token only enables silent renewal. Without an org session to hand over,
                # Access sends a placeholder ("not-available") instead of a JWT; an org token that
                # does not verify is dropped, and the verified app token alone is still the grant.
                org = payload.get("org_token")
                if org:
                    try:
                        org_claims = verify_jwt(org, self.keys, options={"verify_aud": False, "require": ["exp"]})
                        grant.update(org_token=org, org_expires_at=org_claims["exp"])
                    except (jwt.InvalidTokenError, ValueError, KeyError):
                        logger.info("Access sent no usable org token; this sign-in will not renew silently.")
                return grant
            if status >= 500 or 300 <= status < 400:
                raise ValueError("Access token transfer failed. Please sign in again.")
            # Avoid spinning when the service answers immediately before browser approval.
            for _ in range(10):
                if cancelled():
                    break
                time.sleep(.1)
        raise ValueError("Access sign-in was cancelled or timed out.")

    def close(self):
        self.client.close()
        self.private_key = None


def exchange_org_token(origin, org_token, auth_domain, client):
    """Mint a fresh app token from the org session, as ``cloudflared`` does, without a browser.

    Follows the Access SSO redirects by hand: the org token rides only on the team domain's
    login hop, the app-session cookie only on the application's authorized hop, and no hop may
    leave those two hosts. Raises :class:`SessionExpired` when Access wants an interactive login.
    """
    app_host = urlsplit(origin).hostname
    url, app_session = origin, None
    for _ in range(10):
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in (app_host, auth_domain):
            raise SessionExpired("Access redirected outside the gateway and team domain.")
        cookies = {}
        if parts.hostname == auth_domain and parts.path.startswith(LOGIN_PATH):
            cookies[TOKEN_COOKIE] = org_token
        if parts.hostname == app_host and parts.path.startswith(AUTHORIZED_PATH) and app_session:
            cookies[APP_SESSION_COOKIE] = app_session
        headers = {"Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items())} if cookies else {}
        response = client.head(url, headers=headers)
        app_session = response.cookies.get(APP_SESSION_COOKIE) or app_session
        if parts.path.startswith(AUTHORIZED_PATH):
            token = response.cookies.get(TOKEN_COOKIE)
            if token:
                return token
            break
        location = response.headers.get("location")
        if response.status_code not in (301, 302, 303, 307, 308) or not location:
            break
        url = urljoin(url, location)
    raise SessionExpired("The Cloudflare Access session has ended.")
