from urllib.parse import urlencode
import secrets, hashlib, base64

def build_auth_url_bad(client_id, redirect_uri, resource):
    # ruleid: mcp-oauth-authorize-request-missing-pkce-python
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "resource": resource,
    }
    return "https://as.example.com/authorize?" + urlencode(params)

def build_auth_url_good(client_id, redirect_uri, resource):
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    # ok: mcp-oauth-authorize-request-missing-pkce-python
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "resource": resource,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return "https://as.example.com/authorize?" + urlencode(params)
