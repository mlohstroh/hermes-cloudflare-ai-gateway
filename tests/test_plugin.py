"""The plugin on an unmodified Hermes: real discovery, runtime, agent, auxiliary and dashboard paths.

Only the network is faked (httpx transports and the Access endpoints). Nothing in Hermes is patched.
"""
import importlib.util
import json
import shutil
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

PLUGIN = 'cloudflare-ai-gateway'
BASE = 'https://gateway.example/compat'
PLACEHOLDER = 'cloudflare-access'


@pytest.fixture
def home(tmp_path, monkeypatch):
    home = tmp_path / 'hermes'
    shutil.copytree(Path(__file__).resolve().parents[1], home / 'plugins' / PLUGIN,
                    ignore=shutil.ignore_patterns('.git', '__pycache__', '.pytest_cache', 'tests'))
    (home / 'config.yaml').write_text(
        f'model:\n  provider: {PLUGIN}\n  default: openrouter/vendor/model\n'
        f'providers:\n  {PLUGIN}:\n    base_url: {BASE}\n    model: openrouter/vendor/model\n'
        f'plugins:\n  enabled: [{PLUGIN}]\n')
    monkeypatch.setenv('HERMES_HOME', str(home))
    monkeypatch.delenv('CLOUDFLARE_AI_GATEWAY_TOKEN', raising=False)  # no .env entry is needed
    return home


@pytest.fixture
def plugin(home, monkeypatch):
    from providers import get_provider_profile
    profile = get_provider_profile(PLUGIN)
    assert profile is not None and profile.base_url == BASE
    package = type(profile).__module__.rsplit('.', 1)[0]
    session_mod = sys.modules[package + '.session']
    events = []
    monkeypatch.setattr(session_mod, '_broadcast', lambda event, payload: events.append((event, payload)))
    return profile, session_mod, events


def write_state(home, **state):
    path = home / PLUGIN / 'session.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({'base_url': BASE, **state}))


def read_state(home):
    return json.loads((home / PLUGIN / 'session.json').read_text())


@pytest.fixture
def gateway(monkeypatch):
    """Fake inference endpoint behind Access: 401 for any bearer in ``rejected``."""
    seen, rejected = [], set()
    def respond(request):
        seen.append(httpx.Request(request.method, request.url, headers=dict(request.headers)))  # snapshot: resends mutate
        if request.headers.get('authorization', '').removeprefix('Bearer ') in rejected:
            return httpx.Response(401, json={'error': 'access denied'})
        if json.loads(request.content or b'{}').get('stream'):
            chunk = {'id': 'ok', 'object': 'chat.completion.chunk', 'created': 1, 'model': 'openrouter/vendor/model',
                     'choices': [{'index': 0, 'delta': {'role': 'assistant', 'content': 'OK'}, 'finish_reason': 'stop'}]}
            return httpx.Response(200, headers={'content-type': 'text/event-stream'},
                                  content=f'data: {json.dumps(chunk)}\n\ndata: [DONE]\n\n')
        return httpx.Response(200, json={
            'id': 'ok', 'object': 'chat.completion', 'created': 1, 'model': 'openrouter/vendor/model',
            'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'OK'}, 'finish_reason': 'stop'}],
            'usage': {'prompt_tokens': 3, 'completion_tokens': 1, 'total_tokens': 4}})
    monkeypatch.setattr(httpx, 'HTTPTransport', lambda *a, **k: httpx.MockTransport(respond))
    return seen, rejected


def fake_org_exchange(monkeypatch, session_mod, token='renewed', calls=None):
    monkeypatch.setattr(session_mod, 'discover', lambda origin, client: ('team.cloudflareaccess.com', 'iss', 'aud', {}))
    def exchange(origin, org, domain, client):
        (calls if calls is not None else []).append(org)
        return token
    monkeypatch.setattr(session_mod, 'exchange_org_token', exchange)
    monkeypatch.setattr(session_mod, 'verify_app_token', lambda t, *a: {'exp': time.time() + 3600})


def agent():
    from hermes_cli.runtime_provider import resolve_runtime_provider
    from run_agent import AIAgent
    rt = resolve_runtime_provider(requested=PLUGIN)
    return AIAgent(provider=PLUGIN, model='openrouter/vendor/model', base_url=rt['base_url'], api_key=rt['api_key'],
                   api_mode=rt['api_mode'], quiet_mode=True, enabled_toolsets=[], skip_memory=True, skip_context_files=True)


def test_selectable_with_no_env_entry_under_desktop_multi_profile_hosting(home, plugin, monkeypatch):
    """Desktop serves profiles from one process: only the profile's own stores count, never os.environ."""
    from agent import secret_scope
    from hermes_cli.runtime_provider import resolve_runtime_provider
    monkeypatch.setattr(secret_scope, '_MULTIPLEX_ACTIVE', True)
    token = secret_scope.set_secret_scope({})
    try:
        runtime = resolve_runtime_provider(requested=PLUGIN)
    finally:
        secret_scope.reset_secret_scope(token)
    assert runtime['base_url'] == BASE and runtime['api_key'] == PLACEHOLDER


def test_every_client_path_sends_the_access_jwt_never_the_placeholder(home, plugin, gateway):
    seen, _ = gateway
    write_state(home, app_token='app1', app_expires_at=time.time() + 3600)
    from agent.auxiliary_client import resolve_provider_client
    from hermes_cli.runtime_provider import resolve_runtime_provider
    messages = [{'role': 'user', 'content': 'hi'}]
    main = agent()
    assert main.run_conversation('hi')['final_response'] == 'OK'
    rt = resolve_runtime_provider(requested=PLUGIN)
    for kwargs in ({}, {'main_runtime': rt}):
        aux, model = resolve_provider_client(PLUGIN, model='openrouter/vendor/model', **kwargs)
        aux.chat.completions.create(model=model, messages=messages)
    auto, model = resolve_provider_client('auto', main_runtime=rt)
    auto.chat.completions.create(model=model or 'openrouter/vendor/model', messages=messages)
    assert len(seen) >= 4
    assert {r.headers['authorization'] for r in seen} == {'Bearer app1'}
    assert all(str(r.url).startswith(BASE + '/') for r in seen)


def test_service_token_headers_never_reach_the_gateway(home, plugin, gateway):
    profile, _, _ = plugin
    seen, _ = gateway
    write_state(home, app_token='app1', app_expires_at=time.time() + 3600)
    client = profile.create_client(api_key=PLACEHOLDER, base_url=BASE, default_headers={
        'CF-Access-Client-Id': 'id.access', 'CF-Access-Client-Secret': 'secret'})
    client.chat.completions.create(model='openrouter/vendor/model', messages=[{'role': 'user', 'content': 'hi'}])
    headers = {k.lower() for k in seen[-1].headers}
    assert not headers & {'cf-access-client-id', 'cf-access-client-secret'}
    assert seen[-1].headers['authorization'] == 'Bearer app1'


def test_expired_token_renews_silently_from_the_org_session(home, plugin, gateway, monkeypatch):
    profile, session_mod, events = plugin
    seen, _ = gateway
    write_state(home, app_token='old', app_expires_at=time.time() - 1, org_token='org', org_expires_at=time.time() + 86400)
    calls = []
    fake_org_exchange(monkeypatch, session_mod, calls=calls)
    assert agent().run_conversation('hi')['final_response'] == 'OK'
    assert seen[-1].headers['authorization'] == 'Bearer renewed' and calls == ['org']
    assert read_state(home)['app_token'] == 'renewed' and events == []


def test_gateway_401_renews_and_resends_once(home, plugin, gateway, monkeypatch):
    _, session_mod, _ = plugin
    seen, rejected = gateway
    rejected.add('revoked')
    write_state(home, app_token='revoked', app_expires_at=time.time() + 3600, org_token='org', org_expires_at=time.time() + 86400)
    fake_org_exchange(monkeypatch, session_mod)
    assert agent().run_conversation('hi')['final_response'] == 'OK'
    assert [r.headers['authorization'] for r in seen] == ['Bearer revoked', 'Bearer renewed']


class FakeTransfer:
    instances = []

    def __init__(self, origin):
        self.origin, self.auth_domain, self.issuer, self.audience = origin, 'team.cloudflareaccess.com', 'iss', 'aud'
        self.browser_url = f'{origin}/cdn-cgi/access/cli?attempt={len(self.instances)}'
        self.deadline = time.monotonic() + 600
        self.approved = threading.Event()
        FakeTransfer.instances.append(self)

    def wait(self, cancelled):
        assert self.approved.wait(10)
        return {'app_token': 'signed-in', 'app_expires_at': time.time() + 3600,
                'org_token': 'org', 'org_expires_at': time.time() + 86400}

    def close(self):
        pass


def signing_in(monkeypatch, session_mod):
    FakeTransfer.instances = []
    monkeypatch.setattr(session_mod, 'Transfer', FakeTransfer)
    monkeypatch.setattr(session_mod.GatewaySession, 'verify_inference', lambda self, token: None)


def approve_when_started(events, delay=.3):
    """Play the user: wait for the sign-in to start, then finish it in the "browser"."""
    def run():
        deadline = time.monotonic() + 10
        while not FakeTransfer.instances and time.monotonic() < deadline:
            time.sleep(.02)
        time.sleep(delay)
        FakeTransfer.instances[0].approved.set()
    threading.Thread(target=run, daemon=True).start()


def test_ended_session_waits_for_sign_in_then_the_turn_continues(home, plugin, gateway, monkeypatch):
    _, session_mod, events = plugin
    seen, _ = gateway
    signing_in(monkeypatch, session_mod)
    write_state(home, app_token='old', app_expires_at=time.time() - 1)
    approve_when_started(events)
    result = agent().run_conversation('hi')
    assert result['final_response'] == 'OK' and not result.get('failed')
    assert len(FakeTransfer.instances) == 1  # one browser window
    assert [r.headers['authorization'] for r in seen] == ['Bearer signed-in']  # nothing sent before sign-in
    assert [e for e, _ in events] == ['signin.required', 'signin.completed']
    assert events[0][1]['browser_url'] == FakeTransfer.instances[0].browser_url


def test_gateway_401_without_org_session_waits_for_sign_in_and_resends(home, plugin, gateway, monkeypatch):
    _, session_mod, events = plugin
    seen, rejected = gateway
    rejected.add('revoked')
    signing_in(monkeypatch, session_mod)
    write_state(home, app_token='revoked', app_expires_at=time.time() + 3600)
    approve_when_started(events)
    assert agent().run_conversation('hi')['final_response'] == 'OK'
    assert [r.headers['authorization'] for r in seen] == ['Bearer revoked', 'Bearer signed-in']
    assert len(FakeTransfer.instances) == 1


def test_unfinished_sign_in_fails_the_turn_once_then_retry_reuses_the_agent(home, plugin, gateway, monkeypatch):
    profile, session_mod, events = plugin
    seen, _ = gateway
    signing_in(monkeypatch, session_mod)
    monkeypatch.setattr(session_mod, 'SIGN_IN_WAIT', .5)
    write_state(home, app_token='old', app_expires_at=time.time() - 1)
    from agent.error_surface import build_error_surface_from_result
    main = agent()
    client = main.client
    failed = main.run_conversation('hi')
    assert failed.get('failed') and seen == []
    assert len(FakeTransfer.instances) == 1  # no retry loop, no second browser window
    assert FakeTransfer.instances[0].browser_url in str(failed.get('error'))
    surface = build_error_surface_from_result(failed, provider=PLUGIN)
    assert surface['layer'] == 'auth' and not surface['retryable']
    assert [e for e, _ in events] == ['signin.required']

    FakeTransfer.instances[0].approved.set()
    deadline = time.monotonic() + 10
    while ('signin.completed', {'base_url': BASE}) not in events and time.monotonic() < deadline:
        time.sleep(.05)
    retried = main.run_conversation('hi')
    assert retried['final_response'] == 'OK' and main.client is client
    assert seen[-1].headers['authorization'] == 'Bearer signed-in'


def test_stopping_the_request_ends_the_sign_in_wait(home, plugin, monkeypatch):
    profile, session_mod, _ = plugin
    signing_in(monkeypatch, session_mod)
    write_state(home, app_token='old', app_expires_at=time.time() - 1)
    client = profile.create_client(api_key=PLACEHOLDER, base_url=BASE, max_retries=0)
    threading.Timer(.3, client.close).start()  # how Hermes stops a request
    started = time.monotonic()
    with pytest.raises(Exception, match='stopped before Cloudflare Access sign-in finished'):
        client.chat.completions.create(model='openrouter/vendor/model', messages=[{'role': 'user', 'content': 'hi'}])
    assert time.monotonic() - started < 5
    FakeTransfer.instances[0].approved.set()


def test_failed_sign_in_ends_the_wait_with_its_reason(home, plugin, monkeypatch):
    _, session_mod, _ = plugin
    signing_in(monkeypatch, session_mod)
    def reject(self, token):
        raise ValueError('The gateway denied this identity. Check the Access policy.')
    monkeypatch.setattr(session_mod.GatewaySession, 'verify_inference', reject)
    session = session_mod.GatewaySession(home, BASE)
    approve_when_started([], delay=0)
    with pytest.raises(Exception, match='sign-in failed: The gateway denied this identity. Check the Access policy. Sign in'):
        session.bearer()


def test_desktop_routes_are_mounted_by_hermes_and_drive_sign_in(home, plugin, monkeypatch):
    _, session_mod, _ = plugin
    FakeTransfer.instances = []
    monkeypatch.setattr(session_mod, 'Transfer', FakeTransfer)
    from hermes_cli.plugins_cmd import _get_disabled_set, _get_enabled_set
    from hermes_cli.web_server_dashboard import _discover_dashboard_plugins, _plugin_api_mount_skip_reason
    entry = next(p for p in _discover_dashboard_plugins() if p['name'] == PLUGIN)
    assert _plugin_api_mount_skip_reason(entry, _get_enabled_set(), _get_disabled_set()) is None
    spec = importlib.util.spec_from_file_location('cf_plugin_api', Path(entry['_dir']) / entry['_api_file'])
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    app = FastAPI()
    app.include_router(api.router)
    client = TestClient(app)
    assert client.get('/status').json()['signed_in'] is False
    started = client.post('/sign-in').json()
    assert started['pending'] and started['browser_url'] == FakeTransfer.instances[0].browser_url
    assert client.post('/sign-in').json()['browser_url'] == started['browser_url']  # one attempt at a time
    write_state(home, app_token='x', app_expires_at=time.time() + 3600)
    assert client.post('/sign-out').json()['cleared'] is True
    assert client.get('/status').json()['signed_in'] is False


TOKEN_BASE = 'https://gateway.ai.cloudflare.com/v1/acct123/my-gateway/compat'


@pytest.fixture
def token_home(home, monkeypatch):
    """A gateway on Cloudflare's own host (no Access), authenticated with a Cloudflare API token."""
    (home / 'config.yaml').write_text(
        f'model:\n  provider: {PLUGIN}\n  default: openrouter/vendor/model\n'
        f'providers:\n  {PLUGIN}:\n    base_url: {TOKEN_BASE}\n    model: openrouter/vendor/model\n'
        f'plugins:\n  enabled: [{PLUGIN}]\n')
    monkeypatch.setenv('CLOUDFLARE_AI_GATEWAY_TOKEN', 'cf-api-token')
    return home


def test_gateway_without_access_uses_the_configured_token_on_every_path(token_home, gateway):
    seen, _ = gateway
    from providers import get_provider_profile
    from agent.credential_pool import load_pool
    from agent.auxiliary_client import resolve_provider_client
    from hermes_cli.runtime_provider import resolve_runtime_provider
    profile = get_provider_profile(PLUGIN)
    assert profile.base_url == TOKEN_BASE and profile.auth_mode() == 'token'
    assert not [e for e in load_pool(PLUGIN).entries() if e.access_token == PLACEHOLDER]
    rt = resolve_runtime_provider(requested=PLUGIN)
    main = agent()
    assert main.run_conversation('hi')['final_response'] == 'OK'
    aux, model = resolve_provider_client(PLUGIN, model='openrouter/vendor/model', main_runtime=rt)
    aux.chat.completions.create(model=model, messages=[{'role': 'user', 'content': 'hi'}])
    assert {r.headers['authorization'] for r in seen} == {'Bearer cf-api-token'}
    assert all(str(r.url).startswith(TOKEN_BASE + '/') for r in seen)
    assert not (token_home / PLUGIN / 'session.json').exists()


def test_gateway_without_access_and_no_token_asks_for_the_token(token_home, monkeypatch):
    monkeypatch.delenv('CLOUDFLARE_AI_GATEWAY_TOKEN')
    from providers import get_provider_profile
    from hermes_cli.runtime_provider import resolve_runtime_provider
    assert get_provider_profile(PLUGIN) is not None
    with pytest.raises(Exception, match='CLOUDFLARE_AI_GATEWAY_TOKEN'):
        resolve_runtime_provider(requested=PLUGIN)
