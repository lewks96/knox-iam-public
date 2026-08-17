import http from 'k6/http';
import {check, fail, sleep} from 'k6';
import {b64encode} from 'k6/encoding';
import crypto from 'k6/crypto';
import {Trend} from 'k6/metrics';

function requiredEnv(name) {
    const value = __ENV[name];
    if (!value) {
        throw new Error(`${name} must be supplied as a k6 environment variable`);
    }
    return value;
}

const BASE_URL = __ENV.BASE_URL || 'https://gentoo-vm:8443/api';  // k3d ingress via localhost
const TENANT_ID = __ENV.TENANT_ID || 'knox-root';

const ADMIN_CLIENT_ID = __ENV.ADMIN_CLIENT_ID || 'management';
const ADMIN_CLIENT_SECRET = requiredEnv('ADMIN_CLIENT_SECRET');
const ADMIN_SCOPES = __ENV.ADMIN_SCOPES || 'TenantRead IdentityRead IdentityCreate IdentityUpdate';

const OAUTH_CLIENT_ID = __ENV.OAUTH_CLIENT_ID || 'management';
const OAUTH_CLIENT_SECRET = requiredEnv('OAUTH_CLIENT_SECRET');
const OAUTH_SCOPES = __ENV.OAUTH_SCOPES || 'IdentityRead';
const REDIRECT_URI = __ENV.REDIRECT_URI || 'https://knox-local:8443/knox-root/callback';

// Local fixture only; override when running against any shared environment.
const TEST_USER_PASSWORD = __ENV.TEST_USER_PASSWORD || 'Test@1234';

const ADMIN_TOKEN_REFRESH_BUFFER_SECS = parseInt(__ENV.ADMIN_TOKEN_REFRESH_BUFFER_SECS || '10', 10);

const SLEEP_BETWEEN_STEPS = parseFloat(__ENV.SLEEP_BETWEEN_STEPS || '0.2');

// ── Per-endpoint Trend metrics ────────────────────────────────────────────────
const tAdminToken = new Trend('duration_admin_token', true);
const tCreateIdentity = new Trend('duration_create_identity', true);
const tAuthenticate = new Trend('duration_authenticate', true);
const tAuthorize = new Trend('duration_authorize', true);
const tExchangeCode = new Trend('duration_exchange_code', true);
const tRefreshToken = new Trend('duration_refresh_token', true);

export const options = {
    // Disable HTTP keep-alive to ensure better load distribution across pods
    // Each request creates a new connection, allowing kube-proxy to rebalance
    noConnectionReuse: true,
    insecureSkipTLSVerify: true,
    scenarios: {
        full_oauth_flow: {
            executor: 'ramping-vus',
            stages: [
                {duration: '30s', target: 5},  // ramp up
                {duration: '1m', target: 5},  // hold
                {duration: '30s', target: 0},  // ramp down
            ],
            gracefulRampDown: '15s',
        },
    },
    thresholds: {
        http_req_failed: ['rate<0.05'],    // less than 5% errors overall
        http_req_duration: ['p(95)<3500'],   // 95th percentile under 3.5s (Argon2 hashing)
        // Per-endpoint thresholds
        'duration_admin_token': ['p(95)<500'],
        'duration_create_identity': ['p(95)<3500'],  // Realistic for Argon2 (password hashing)
        'duration_authenticate': ['p(95)<3000'],     // Realistic for Argon2 (password verification)
        'duration_authorize': ['p(95)<500'],
        'duration_exchange_code': ['p(95)<500'],
        'duration_refresh_token': ['p(95)<500'],
    },
};

let _adminToken = null;
let _adminTokenRefreshAt = 0;  // Unix timestamp in seconds
let _adminTokenRefreshing = false;  // Simple lock to prevent race conditions

function tenantUrl(path) {
    return `${BASE_URL}/${TENANT_ID}${path}`;
}

function buildBasicAuth(clientId, clientSecret) {
    return `Basic ${b64encode(`${clientId}:${clientSecret}`)}`;
}

function generatePkce() {
    const verifierBytes = crypto.randomBytes(32);
    const verifier = b64encode(verifierBytes, 'rawurl');       // base64url, no padding
    const challenge = crypto.sha256(verifier, 'base64rawurl');  // SHA-256 → base64url, no padding
    return {verifier, challenge};
}

function randomHex(bytes) {
    return Array.from(new Uint8Array(crypto.randomBytes(bytes)))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function randomEmail() {
    return `loadtest_${randomHex(6)}@test.com`;
}

function extractQueryParam(url, param) {
    const match = url.match(new RegExp(`[?&]${param}=([^&]+)`));
    return match ? decodeURIComponent(match[1]) : null;
}

function nowSecs() {
    return Math.floor(Date.now() / 1000);
}


function fetchAdminAccessToken() {
    const start = Date.now();
    const res = http.post(
        tenantUrl('/oauth2/token'),
        `grant_type=client_credentials&scope=${encodeURIComponent(ADMIN_SCOPES)}`,
        {
            headers: {
                'Authorization': buildBasicAuth(ADMIN_CLIENT_ID, ADMIN_CLIENT_SECRET),
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            tags: {name: 'admin_token'},
        }
    );
    tAdminToken.add(Date.now() - start);

    check(res, {'[admin token] status 200': (r) => r.status === 200})
    || fail(`fetchAdminAccessToken failed: ${res.status} — ${res.body}`);

    const token = res.json('access_token');
    const expiresIn = res.json('expires_in') || 3600;

    check(res, {'[admin token] has access_token': () => !!token})
    || fail('fetchAdminAccessToken: missing access_token in response');

    _adminToken = token;
    _adminTokenRefreshAt = nowSecs() + expiresIn - ADMIN_TOKEN_REFRESH_BUFFER_SECS;

    return token;
}

function getAdminAccessToken() {
    // Wait if another VU is currently refreshing the token
    let waitCount = 0;
    while (_adminTokenRefreshing && waitCount < 100) {
        sleep(0.05);  // 50ms
        waitCount++;
    }

    // Check if we need to refresh
    if (_adminToken === null || nowSecs() >= _adminTokenRefreshAt) {
        // Double-check after waiting (another VU might have refreshed)
        if (_adminToken === null || nowSecs() >= _adminTokenRefreshAt) {
            _adminTokenRefreshing = true;
            try {
                fetchAdminAccessToken();
            } finally {
                _adminTokenRefreshing = false;
            }
        }
    }
    return _adminToken;
}

function createIdentity(adminToken, email) {
    const start = Date.now();
    const res = http.post(
        tenantUrl('/identity'),
        JSON.stringify({
            email,
            password: TEST_USER_PASSWORD,
            first_name: 'Load',
            last_name: 'Test',
        }),
        {
            headers: {
                'Authorization': `Bearer ${adminToken}`,
                'Content-Type': 'application/json',
            },
            tags: {name: 'create_identity'},
        }
    );
    tCreateIdentity.add(Date.now() - start);

    check(res, {'[create identity] status 201': (r) => r.status === 201})
    || fail(`createIdentity failed: ${res.status} — ${res.body}`);
}

function authenticate(email) {
    const start = Date.now();
    const res = http.post(
        tenantUrl('/authenticate'),
        JSON.stringify({username: email, password: TEST_USER_PASSWORD}),
        {
            headers: {'Content-Type': 'application/json'},
            redirects: 0,
            tags: {name: 'authenticate'},
        }
    );
    tAuthenticate.add(Date.now() - start);

    check(res, {'[authenticate] status 200': (r) => r.status === 200})
    || fail(`authenticate failed: ${res.status} — ${res.body}`);

    const ssoToken = res.json('sso');
    check(res, {'[authenticate] has sso token': () => !!ssoToken})
    || fail('authenticate: missing sso token in response');

    return ssoToken;
}

function authorize(ssoToken, pkce) {
    const query = [
        `client_id=${encodeURIComponent(OAUTH_CLIENT_ID)}`,
        `redirect_uri=${encodeURIComponent(REDIRECT_URI)}`,
        `state=loadtest_csrf_state`,
        `code_challenge=${encodeURIComponent(pkce.challenge)}`,
        `code_challenge_method=S256`,
        `scope=${encodeURIComponent(OAUTH_SCOPES)}`,
        `nonce=loadtest_nonce`,
    ].join('&');

    const start = Date.now();
    const res = http.get(
        tenantUrl(`/oauth2/authorize?${query}`),
        {
            headers: {'Cookie': `ssotoken=${ssoToken}`},
            redirects: 0,  // must not follow — the auth code lives in Location
            tags: {name: 'authorize'},
        }
    );
    tAuthorize.add(Date.now() - start);

    check(res, {'[authorize] status 302': (r) => r.status === 302})
    || fail(`authorize failed: ${res.status} — ${res.body}`);

    const location = res.headers['Location'] || res.headers['location'] || '';
    const code = extractQueryParam(location, 'code');

    check(res, {'[authorize] has code': () => !!code})
    || fail(`authorize: no code in Location header (got: ${location})`);

    return code;
}

function exchangeAuthCode(code, pkce) {
    const body = [
        `grant_type=authorization_code`,
        `code=${encodeURIComponent(code)}`,
        `redirect_uri=${encodeURIComponent(REDIRECT_URI)}`,
        `client_id=${encodeURIComponent(OAUTH_CLIENT_ID)}`,
        `code_verifier=${encodeURIComponent(pkce.verifier)}`,
        `scope=${encodeURIComponent(OAUTH_SCOPES)}`,
    ].join('&');

    const start = Date.now();
    const res = http.post(
        tenantUrl('/oauth2/token'),
        body,
        {
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            tags: {name: 'exchange_code'},
        }
    );
    tExchangeCode.add(Date.now() - start);

    check(res, {'[exchange code] status 200': (r) => r.status === 200})
    || fail(`exchangeAuthCode failed: ${res.status} — ${res.body}`);

    return {
        accessToken: res.json('access_token'),
        refreshToken: res.json('refresh_token'),
    };
}

function useRefreshToken(token) {
    const body = [
        `grant_type=refresh_token`,
        `client_id=${encodeURIComponent(OAUTH_CLIENT_ID)}`,
        `client_secret=${encodeURIComponent(OAUTH_CLIENT_SECRET)}`,
        `refresh_token=${encodeURIComponent(token)}`,
    ].join('&');

    const start = Date.now();
    const res = http.post(
        tenantUrl('/oauth2/token'),
        body,
        {
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            tags: {name: 'refresh_token'},
        }
    );
    tRefreshToken.add(Date.now() - start);

    check(res, {'[refresh token] status 200': (r) => r.status === 200})
    || fail(`useRefreshToken failed: ${res.status} — ${res.body}`);

    return res.json('access_token');
}

export default function () {
    const pkce = generatePkce();
    const email = randomEmail();

    const adminToken = getAdminAccessToken();
    sleep(SLEEP_BETWEEN_STEPS);

    createIdentity(adminToken, email);
    sleep(SLEEP_BETWEEN_STEPS);

    const ssoToken = authenticate(email);
    sleep(SLEEP_BETWEEN_STEPS);

    const code = authorize(ssoToken, pkce);
    sleep(SLEEP_BETWEEN_STEPS);

    const {accessToken, refreshToken} = exchangeAuthCode(code, pkce);
    check(null, {'[exchange code] has access_token': () => !!accessToken});
    sleep(SLEEP_BETWEEN_STEPS);

    if (refreshToken) {
        useRefreshToken(refreshToken);
        sleep(SLEEP_BETWEEN_STEPS);
    }
}
