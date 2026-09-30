import base64
import importlib
import json
import os
import sys
import time
import types
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.poly1305 import Poly1305

# The plugin's modules as a package, without running __init__ (which registers with Hermes).
_pkg = types.ModuleType('cf_gateway_under_test')
_pkg.__path__ = [str(Path(__file__).resolve().parents[1])]
sys.modules[_pkg.__name__] = _pkg
access = importlib.import_module(_pkg.__name__ + '.access')
naclbox = importlib.import_module(_pkg.__name__ + '.naclbox')
catalog = importlib.import_module(_pkg.__name__ + '.catalog')


def box_seal(sender, recipient_public, message):
    """Test-side crypto_box from the same (vector-pinned) primitives."""
    nonce = os.urandom(24)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    key = naclbox.hsalsa20(sender._key.exchange(X25519PublicKey.from_public_bytes(recipient_public)), bytes(16))
    stream = naclbox.xsalsa20_stream(key, nonce, 32 + len(message))
    ciphertext = bytes(a ^ b for a, b in zip(message, stream[32:]))
    return nonce + Poly1305.generate_tag(stream[:32], ciphertext) + ciphertext


# Produced by libsodium through PyNaCl: Box(PrivateKey(bytes(range(32, 64))), ours.public_key).encrypt(msg, bytes(range(24)))
VECTOR = {
    'ours': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    'peer_pub': '358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254',
    'boxed': '000102030405060708090a0b0c0d0e0f10111213141516170c4b22ade53e3ce72098944702defa9818f0de400c273cc02a16d8d31e8881f36ec2ef0f6cc8f0dd5fb50ad0b09bc7b09bfe53cb8859045104010f29741ea37f69c524a1fbfd67df8ce83e48092826fdc60aa2670e69a5ccf584c8cdb000c9f2d94e236e0d33d5fa6c1086c6b564ba99aade8a68e0b0dca0279378ee69d1bee7aa667f7fd029b96e61',
    'msg': '7b226170705f746f6b656e223a22766563746f722d617070222c226f72675f746f6b656e223a22766563746f722d6f7267227d' + '78' * 70,
}


def test_box_open_matches_libsodium_and_rejects_forgery():
    ours = naclbox.PrivateKey.from_bytes(bytes.fromhex(VECTOR['ours']))
    boxed = bytes.fromhex(VECTOR['boxed'])
    assert ours.box_open(bytes.fromhex(VECTOR['peer_pub']), boxed) == bytes.fromhex(VECTOR['msg'])
    forged = bytearray(boxed); forged[-1] ^= 1
    with pytest.raises(ValueError):
        ours.box_open(bytes.fromhex(VECTOR['peer_pub']), bytes(forged))


@pytest.fixture
def exchange(monkeypatch):
    signing = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing.public_key())); key['kid'] = 'test-key'
    issuer = 'https://team.cloudflareaccess.com'
    def sign(claims):
        return jwt.encode(claims, signing, algorithm='RS256', headers={'kid': 'test-key'})
    metadata = sign({'hostname':'gateway.example','auth_domain':'team.cloudflareaccess.com',
                     'aud':'application','iat':int(time.time()),'type':'match'})
    app_token = sign({'iss':issuer,'aud':['application'],'iat':int(time.time()),'exp':int(time.time()+600)})
    org_token = sign({'iss':issuer,'aud':'team','iat':int(time.time()),'exp':int(time.time()+86400)})
    requests = []
    def server(request):
        requests.append(request)
        assert 'authorization' not in request.headers
        if request.method == 'HEAD':
            return httpx.Response(302, headers={'cf-access-metadata':metadata})
        if request.url.path.endswith('/certs'):
            return httpx.Response(200, json={'keys':[key]})
        recipient = base64.urlsafe_b64decode(request.url.path.rsplit('/',1)[-1])
        peer = naclbox.PrivateKey()
        encrypted = box_seal(peer, recipient, json.dumps({'app_token':app_token,'org_token':org_token}).encode())
        return httpx.Response(200, headers={'service-public-key':base64.urlsafe_b64encode(peer.public_key).decode()},
                              content=base64.b64encode(encrypted))
    original = httpx.Client
    class Client(original):
        def __init__(self, **kwargs):
            super().__init__(transport=httpx.MockTransport(server), **kwargs)
    monkeypatch.setattr(httpx, 'Client', Client)
    return app_token, requests, sign, key


def test_native_encrypted_transfer_and_fresh_keys(exchange):
    expected, requests, _, _ = exchange
    a = access.Transfer('https://gateway.example')
    b = access.Transfer('https://gateway.example')
    assert a.browser_url != b.browser_url
    params = parse_qs(urlsplit(a.browser_url).query)
    assert params['aud'] == ['application']
    assert urlsplit(a.browser_url).path == '/cdn-cgi/access/cli'
    grant = a.wait(lambda:False)
    assert grant['app_token'] == expected and grant['org_expires_at'] > grant['app_expires_at']
    assert requests[-1].url.host == 'login.cloudflareaccess.org'
    a.close(); b.close()


def test_cancel_does_not_poll(exchange):
    _, requests, _, _ = exchange
    a = access.Transfer('https://gateway.example')
    before = len(requests)
    with pytest.raises(ValueError, match='cancelled'):
        a.wait(lambda:True)
    assert len(requests) == before
    a.close()


def test_signature_audience_issuer_expiry(exchange):
    _, _, sign, key = exchange
    claims = {'iss':'https://team.cloudflareaccess.com','aud':'application','iat':int(time.time()),'exp':int(time.time()+600)}
    for replacement in ({'aud':'other'},{'iss':'https://attacker.example'},{'exp':int(time.time()-30)}):
        with pytest.raises(jwt.InvalidTokenError):
            access.verify_jwt(sign({**claims, **replacement}), {'keys':[key]}, audience='application',issuer=claims['iss'])
    alien = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode(claims, alien, algorithm='RS256', headers={'kid':'test-key'})
    with pytest.raises(jwt.InvalidSignatureError):
        access.verify_jwt(forged, {'keys':[key]}, audience='application',issuer=claims['iss'])


def test_catalog_stays_on_configured_upstream_and_removes_non_chat():
    selected = 'openrouter/openai/gpt-4.1-mini'
    ids = [selected, selected + ':batch', selected + '-2025-04-14',
           'openai/gpt-4.1-mini', 'openrouter/openrouter/bad',
           'openrouter/openai/text-embedding-3-small', 'openrouter/openai/gpt-image-2',
           'openrouter/anthropic/claude-sonnet-4']
    assert catalog.chat_models(ids, selected) == [selected, 'openrouter/anthropic/claude-sonnet-4']


def _sso(app_token, *, org_valid=True, redirect_host='team.cloudflareaccess.com'):
    """Access SSO: app -> team login (needs org cookie) -> app authorized (sets app cookie)."""
    seen = []
    def server(request):
        seen.append(request)
        path, host = request.url.path, request.url.host
        if host == 'gateway.example' and path == '/':
            return httpx.Response(302, headers={'location': f'https://{redirect_host}/cdn-cgi/access/login/gateway.example?kid=1'})
        if path.startswith('/cdn-cgi/access/login'):
            if not org_valid or 'CF_Authorization=org' not in request.headers.get('cookie', ''):
                return httpx.Response(200, text='<html>login page</html>')
            return httpx.Response(302, headers={'location': 'https://gateway.example/cdn-cgi/access/authorized?token=x',
                                                'set-cookie': 'CF_AppSession=sess; Path=/'})
        if path.startswith('/cdn-cgi/access/authorized'):
            assert 'CF_AppSession=sess' in request.headers.get('cookie', '')
            return httpx.Response(302, headers={'location': '/', 'set-cookie': f'CF_Authorization={app_token}; Path=/; Secure'})
        raise AssertionError(request.url)
    return httpx.Client(transport=httpx.MockTransport(server), follow_redirects=False), seen


def test_org_token_exchange_sends_org_cookie_only_to_team_domain():
    client, seen = _sso('fresh-app')
    assert access.exchange_org_token('https://gateway.example', 'org', 'team.cloudflareaccess.com', client) == 'fresh-app'
    carrying = [r.url.host for r in seen if 'CF_Authorization=org' in r.headers.get('cookie', '')]
    assert carrying == ['team.cloudflareaccess.com']


def test_org_token_exchange_reports_ended_session_and_foreign_redirects():
    client, _ = _sso('fresh-app', org_valid=False)
    with pytest.raises(access.SessionExpired):
        access.exchange_org_token('https://gateway.example', 'org', 'team.cloudflareaccess.com', client)
    client, seen = _sso('fresh-app', redirect_host='attacker.example')
    with pytest.raises(access.SessionExpired):
        access.exchange_org_token('https://gateway.example', 'org', 'team.cloudflareaccess.com', client)
    assert all(r.url.host != 'attacker.example' for r in seen)
