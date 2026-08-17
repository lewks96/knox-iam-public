import http from 'k6/http';
import {check, fail, sleep} from 'k6';
import {b64encode} from 'k6/encoding';
import crypto from 'k6/crypto';
import {Trend} from 'k6/metrics';
import {SharedArray} from 'k6/data';

function requiredEnv(name) {
    const value = __ENV[name];
    if (!value) {
        throw new Error(`${name} must be supplied as a k6 environment variable`);
    }
    return value;
}

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const TENANT_ID = __ENV.TENANT_ID || 'knox-root';

const ADMIN_CLIENT_ID = __ENV.ADMIN_CLIENT_ID || 'management';
const ADMIN_CLIENT_SECRET = requiredEnv('ADMIN_CLIENT_SECRET');
const ADMIN_SCOPES = __ENV.ADMIN_SCOPES || 'TenantRead IdentityRead IdentityCreate IdentityUpdate';

const OAUTH_CLIENT_ID = __ENV.OAUTH_CLIENT_ID || 'management';
const OAUTH_CLIENT_SECRET = requiredEnv('OAUTH_CLIENT_SECRET');
const OAUTH_SCOPES = __ENV.OAUTH_SCOPES || 'IdentityRead';
const REDIRECT_URI = __ENV.REDIRECT_URI || 'http://localhost:8080/knox-root/callback';

// Number of users to pre-create during setup
const USER_POOL_SIZE = parseInt(__ENV.USER_POOL_SIZE || '20', 10);

// Local fixture only; override when running against any shared environment.
const USER_PASSWORD = __ENV.TEST_USER_PASSWORD || 'Test@1234';

const SLEEP_BETWEEN_STEPS = parseFloat(__ENV.SLEEP_BETWEEN_STEPS || '0.2');

// ── Per-endpoint Trend metrics ────────────────────────────────────────────────
const tAuthenticate = new Trend('duration_authenticate', true);
const tAuthorize = new Trend('duration_authorize', true);
const tExchangeCode = new Trend('duration_exchange_code', true);
const tRefreshToken = new Trend('duration_refresh_token', true);

export const options = {
    noConnectionReuse: true,

    scenarios: {
        auth_flow: {
            executor: 'ramping-vus',
            stages: [
                {duration: '30s', target: 5},
                {duration: '1m', target: 5},
                {duration: '30s', target: 0},
            ],
            gracefulRampDown: '15s',
        },
    },
    thresholds: {
        http_req_failed: ['rate<0.05'],
        http_req_duration: ['p(95)<3500'],
        'duration_authenticate': ['p(95)<3000'],
        'duration_authorize': ['p(95)<500'],
        'duration_exchange_code': ['p(95)<500'],
        'duration_refresh_token': ['p(95)<500'],
    },
};

function tenantUrl(path) {
    return `${BASE_URL}/api/${TENANT_ID}${path}`;
}

function buildBasicAuth(clientId, clientSecret) {
    return `Basic ${b64encode(`${clientId}:${clientSecret}`)}`;
}

function generatePkce() {
    const verifierBytes = crypto.randomBytes(32);
    const verifier = b64encode(verifierBytes, 'rawurl');
    const challenge = crypto.sha256(verifier, 'base64rawurl');
    return {verifier, challenge};
}

function randomHex(bytes) {
    return Array.from(new Uint8Array(crypto.randomBytes(bytes)))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function extractQueryParam(url, param) {
    const match = url.match(new RegExp(`[?&]${param}=([^&]+)`));
    return match ? decodeURIComponent(match[1]) : null;
}

// ── Setup: runs once before VUs start ────────────────────────────────────────

export function setup() {
    // Obtain admin token
    const tokenRes = http.post(
        tenantUrl('/oauth2/token'),
        `grant_type=client_credentials&scope=${encodeURIComponent(ADMIN_SCOPES)}`,
        {
            headers: {
                'Authorization': buildBasicAuth(ADMIN_CLIENT_ID, ADMIN_CLIENT_SECRET),
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        }
    );
    check(tokenRes, {'[setup] admin token status 200': (r) => r.status === 200})
    || fail(`setup: failed to obtain admin token — ${tokenRes.status} ${tokenRes.body}`);

    const adminToken = tokenRes.json('access_token');
    check(tokenRes, {'[setup] has access_token': () => !!adminToken})
    || fail('setup: missing access_token in admin token response');

    // Pre-create unique users
    const users = [];
    for (let i = 0; i < USER_POOL_SIZE; i++) {
        const email = `authtest_${randomHex(8)}@test.com`;

        const res = http.post(
            tenantUrl('/identity'),
            JSON.stringify({
                email,
                password: USER_PASSWORD,
                first_name: 'Auth',
                last_name: `Test${i}`,
            }),
            {
                headers: {
                    'Authorization': `Bearer ${adminToken}`,
                    'Content-Type': 'application/json',
                },
            }
        );

        check(res, {[`[setup] created user ${i} (201)`]: (r) => r.status === 201})
        || fail(`setup: failed to create user ${i} (${email}) — ${res.status} ${res.body}`);

        users.push({email, password: USER_PASSWORD});
    }

    console.log(`[setup] created ${users.length} users`);
    return {users};
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

function authenticate(email, password) {
    const start = Date.now();
    const res = http.post(
        tenantUrl('/authenticate'),
        JSON.stringify({username: email, password}),
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
        `state=authtest_csrf_state`,
        `code_challenge=${encodeURIComponent(pkce.challenge)}`,
        `code_challenge_method=S256`,
        `scope=${encodeURIComponent(OAUTH_SCOPES)}`,
        `nonce=authtest_nonce`,
    ].join('&');

    const start = Date.now();
    const res = http.get(
        tenantUrl(`/oauth2/authorize?${query}`),
        {
            headers: {'Cookie': `ssotoken=${ssoToken}`},
            redirects: 0,
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

// ── Default: runs per VU iteration ───────────────────────────────────────────

export default function ({users}) {
    // Pick a user from the pool, cycling by VU+iteration to spread load
    const user = users[(__VU * 1000 + __ITER) % users.length];

    const pkce = generatePkce();

    const ssoToken = authenticate(user.email, user.password);
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
