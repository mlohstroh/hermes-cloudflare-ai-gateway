"""Sign-in routes for the Desktop half, mounted at /api/plugins/cloudflare-ai-gateway/.

Desktop opens the returned browser URL on the user's machine (``ctx.os.openExternal``); the
backend finishes the encrypted transfer, so this works for local and remote backends alike.
"""
from fastapi import APIRouter, HTTPException

router = APIRouter()


def _ensure_marker():
    # Mounted at backend startup, before any turn: the plugin's credential marker is in place even
    # when provider discovery ran too early in the import graph to write it.
    from providers import get_provider_profile
    profile = get_provider_profile("cloudflare-ai-gateway")
    module = __import__(type(profile).__module__, fromlist=["ensure_credential_marker"]) if profile else None
    if module is not None:
        module.ensure_credential_marker()


try:
    _ensure_marker()
except Exception:
    pass


def _profile():
    from providers import get_provider_profile
    profile = get_provider_profile("cloudflare-ai-gateway")
    if profile is None:
        raise HTTPException(503, "The cloudflare-ai-gateway provider plugin is not loaded.")
    return profile


def _session():
    profile = _profile()
    try:
        if profile.auth_mode() != "access":
            raise HTTPException(400, "This gateway uses an API token, not Cloudflare Access sign-in.")
        return profile.access_session()
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


@router.get("/status")
def status():
    try:
        mode = _profile().auth_mode()
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    return {"mode": "token"} if mode == "token" else {"mode": "access", **_session().status()}


@router.post("/sign-in")
def sign_in():
    session = _session()
    try:
        attempt = session.start_sign_in()
    except Exception as exc:
        raise HTTPException(502, f"Could not reach Cloudflare Access: {exc}") from None
    return {"mode": "access", **session.status(), "browser_url": attempt.browser_url}


@router.post("/sign-out")
def sign_out():
    session = _session()
    return {"mode": "access", "cleared": session.clear(), **session.status()}
