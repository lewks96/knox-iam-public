#!/usr/bin/env python3
"""End-to-end smoke test for the Knox MFA (TOTP + backup codes) login flow.

Exercises: password login, PKCE token exchange, TOTP enrollment + confirmation,
MFA-gated login, single-use mfa_token, TOTP replay protection, backup code
normalization + single use, attempt rate limiting, and unenrollment.

Prerequisites:
  - Server running locally (cargo run -p server) with compose postgres/redis up.
  - A test user with a known password, the IdentitySelf role, and NO existing
    MFA enrollment. Seed one with scripts/seed-mfa-test-user.sql or:

      TEST_USER_EMAIL / TEST_USER_PASSWORD  (default mfa.e2e@knox.test / Test@1234!)
      BASE_URL / TENANT_SLUG / BASE_DOMAIN / OAUTH_CLIENT_ID / REDIRECT_URI
        to override targets.

The tenant is carried by the Host header (`{tenant}.{BASE_DOMAIN}`), not by a
path prefix — requests still go to BASE_URL, which is axum directly rather than
the Next dev proxy. Management endpoints live under /api; /oauth2 and
/.well-known sit at the root because the issuer is the bare host.

Stdlib only - no dependencies.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE = os.environ.get("BASE_URL", "http://localhost:8080")
TENANT = os.environ.get("TENANT_SLUG", "knox-root")
# Must match the server's KNOX_BASE_DOMAIN, or the Host header resolves no tenant.
BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "lvh.me")
TENANT_HOST = f"{TENANT}.{BASE_DOMAIN}"
CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "management")
# The registered redirect URI is the tenant host at the public (UI) port, which
# is not BASE — that points at axum.
REDIRECT_URI = os.environ.get("REDIRECT_URI", f"http://{TENANT_HOST}:3000/callback")
PASSWORD = os.environ.get("TEST_USER_PASSWORD", "Test@1234!")

passed = 0


def ok(name, cond, detail=""):
    global passed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        print(f"  FAIL  {name}  {detail}")
        sys.exit(1)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def req(method, path, body=None, headers=None, form=False, expect_status=None):
    url = f"{BASE}{path}"
    # Connect to BASE but present the tenant's host, so the server resolves the
    # tenant without needing DNS or the UI proxy in the loop.
    headers = {"Host": TENANT_HOST, **(headers or {})}
    data = None
    if body is not None:
        if form:
            data = urllib.parse.urlencode(body).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with OPENER.open(r) as resp:
            return resp.status, dict(resp.headers), resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def totp(secret_b32, at=None, step=30, digits=6):
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32.upper() + pad)
    counter = int((at if at is not None else time.time()) // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[19] & 15
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# --- 0. wait for server -----------------------------------------------------
for i in range(60):
    try:
        status, _, _ = req("GET", "/sys/health")
        if status == 200:
            break
    except Exception:
        pass
    time.sleep(1)
else:
    print("server never became healthy")
    sys.exit(1)
print("server healthy")

email = os.environ.get("TEST_USER_EMAIL", "mfa.e2e@knox.test")

# --- 3. password login (no MFA enrolled yet) ---------------------------------
status, _, body = req("POST", "/api/authenticate", {"username": email, "password": PASSWORD, "client_id": CLIENT_ID})
ok("password login without MFA returns sso", status == 200 and "sso" in json.loads(body), f"{status} {body[:300]}")
sso = json.loads(body)["sso"]

# --- 4. PKCE flow for a user access token ------------------------------------
verifier = b64url(secrets.token_bytes(32))
challenge = b64url(hashlib.sha256(verifier.encode()).digest())
query = urllib.parse.urlencode(
    {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "state": "e2e_state",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scope": "IdentityRead IdentityUpdate",
        "nonce": "e2e_nonce",
    }
)
status, headers, body = req(
    "GET", f"/oauth2/authorize?{query}", headers={"Cookie": f"knox_sso={sso}"}
)
location = headers.get("Location", headers.get("location", ""))
ok("authorize redirects with code", status == 302 and "code=" in location, f"{status} {location} {body[:200]}")
code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]

status, _, body = req(
    "POST",
    "/oauth2/token",
    {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "code_verifier": verifier,
        "scope": "IdentityRead IdentityUpdate",
    },
    form=True,
)
ok("exchange code for user token", status == 200, f"{status} {body[:300]}")
user_token = json.loads(body)["access_token"]
auth_hdr = {"Authorization": f"Bearer {user_token}"}

# --- 5. TOTP enrollment -------------------------------------------------------
status, _, body = req("POST", "/api/mfa/totp/enroll", headers=auth_hdr)
ok("start TOTP enrollment", status == 200, f"{status} {body[:300]}")
enroll = json.loads(body)
ok(
    "enrollment returns otpauth uri + secret",
    enroll["otpauth_uri"].startswith("otpauth://totp/") and enroll["secret"] in enroll["otpauth_uri"],
    body[:200],
)

status, _, body = req(
    "POST", "/api/mfa/totp/confirm", {"code": totp(enroll["secret"])}, headers=auth_hdr
)
ok("confirm TOTP enrollment", status == 200, f"{status} {body[:300]}")
backup_codes = json.loads(body)["backup_codes"]
ok("got 10 backup codes", len(backup_codes) == 10, str(backup_codes))

status, _, body = req("GET", "/api/mfa/methods", headers=auth_hdr)
methods = json.loads(body)
ok(
    "methods list shows verified totp",
    status == 200 and len(methods) == 1 and methods[0]["method"] == "totp" and methods[0]["verified_at"],
    f"{status} {body[:300]}",
)

# --- 6. login now requires MFA ------------------------------------------------
status, _, body = req("POST", "/api/authenticate", {"username": email, "password": PASSWORD, "client_id": CLIENT_ID})
resp = json.loads(body)
ok(
    "login returns mfa_token + methods",
    status == 200 and "mfa_token" in resp and sorted(resp["methods"]) == ["backup_code", "totp"],
    f"{status} {body[:300]}",
)
mfa_token = resp["mfa_token"]

# wait for the next TOTP step so the confirm-time code can't collide
time.sleep(1)
code_now = totp(enroll["secret"], at=time.time() + 30)  # +1 step: within skew, not yet claimed

status, _, body = req(
    "POST",
    "/api/authenticate/mfa",
    {"mfa_token": mfa_token, "method": "totp", "code": code_now, "client_id": CLIENT_ID},
)
ok("MFA verification issues sso", status == 200 and "sso" in json.loads(body), f"{status} {body[:300]}")

# --- 7. single-use + replay protections ----------------------------------------
status, _, body = req(
    "POST",
    "/api/authenticate/mfa",
    {"mfa_token": mfa_token, "method": "totp", "code": code_now, "client_id": CLIENT_ID},
)
ok("mfa_token is single-use", status == 401, f"{status} {body[:300]}")

status, _, body = req("POST", "/api/authenticate", {"username": email, "password": PASSWORD, "client_id": CLIENT_ID})
mfa_token2 = json.loads(body)["mfa_token"]

status, _, body = req(
    "POST",
    "/api/authenticate/mfa",
    {"mfa_token": mfa_token2, "method": "totp", "code": code_now, "client_id": CLIENT_ID},
)
ok("TOTP code replay rejected", status == 401, f"{status} {body[:300]}")

status, _, body = req(
    "POST",
    "/api/authenticate/mfa",
    {"mfa_token": mfa_token2, "method": "totp", "code": "000000", "client_id": CLIENT_ID},
)
ok("wrong code rejected", status == 401, f"{status} {body[:300]}")

# backup code works on the same (not yet consumed) token, typed lowercase+dash
bc = backup_codes[0]
typed = f"{bc[:5].lower()}-{bc[5:].lower()}"
status, _, body = req(
    "POST",
    "/api/authenticate/mfa",
    {"mfa_token": mfa_token2, "method": "backup_code", "code": typed, "client_id": CLIENT_ID},
)
ok("backup code (normalized) issues sso", status == 200, f"{status} {body[:300]}")

status, _, body = req("POST", "/api/authenticate", {"username": email, "password": PASSWORD, "client_id": CLIENT_ID})
mfa_token3 = json.loads(body)["mfa_token"]
status, _, body = req(
    "POST",
    "/api/authenticate/mfa",
    {"mfa_token": mfa_token3, "method": "backup_code", "code": bc, "client_id": CLIENT_ID},
)
ok("backup code is single-use", status == 401, f"{status} {body[:300]}")

# --- 8. attempt lockout ---------------------------------------------------------
# A fresh token, so all six attempts below count against the same clean budget.
status, _, body = req("POST", "/api/authenticate", {"username": email, "password": PASSWORD, "client_id": CLIENT_ID})
mfa_token4 = json.loads(body)["mfa_token"]
last = None
for i in range(6):
    status, _, body = req(
        "POST",
        "/api/authenticate/mfa",
        {"mfa_token": mfa_token4, "method": "totp", "code": "999999", "client_id": CLIENT_ID},
    )
    last = status
ok("6th attempt rate-limited", last == 429, f"{last} {body[:300]}")

# --- 9. unenroll ----------------------------------------------------------------
method_id = methods[0]["id"]
status, _, body = req("DELETE", f"/api/mfa/methods/{method_id}", headers=auth_hdr)
ok("remove method", status == 200, f"{status} {body[:300]}")

status, _, body = req("POST", "/api/authenticate", {"username": email, "password": PASSWORD, "client_id": CLIENT_ID})
ok(
    "login after unenroll needs no MFA",
    status == 200 and "sso" in json.loads(body),
    f"{status} {body[:300]}",
)

print(f"\nAll {passed} E2E checks passed.")
