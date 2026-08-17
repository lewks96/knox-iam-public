/**
 * PKCE (Proof Key for Code Exchange) utilities using the Web Crypto API.
 * These run in the browser — no Node.js crypto module required.
 */

/**
 * Generate a cryptographically random code verifier (RFC 7636).
 * Returns a base64url-encoded string of 32 random bytes (43 chars after encoding).
 */
export function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64urlEncode(array);
}

/**
 * Derive the code challenge from a code verifier: base64url(SHA-256(verifier)).
 */
export async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64urlEncode(new Uint8Array(digest));
}

/**
 * Generate a cryptographically random state string for CSRF protection.
 */
export function generateState(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return base64urlEncode(array);
}

function base64urlEncode(bytes: Uint8Array): string {
  let str = "";
  for (const byte of bytes) {
    str += String.fromCharCode(byte);
  }
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
