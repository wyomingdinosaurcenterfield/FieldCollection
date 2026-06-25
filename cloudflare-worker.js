/**
 * WDC Field App — Cloudflare Worker Google API Proxy
 *
 * Routes all Google API calls through this Worker using a Service Account,
 * so the PWA never needs user sign-in.
 *
 * Setup:
 *   1. Deploy this file to Cloudflare Workers
 *   2. Add secret: SA_CREDENTIALS = (paste full service account JSON)
 *   3. Paste this Worker's URL into the app's Settings → Cloudflare Worker URL
 *
 * Worker routes:
 *   /gapi/*         → https://www.googleapis.com/*
 *   /gapi-upload/*  → https://www.googleapis.com/upload/*
 */

const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const SCOPES = [
  'https://www.googleapis.com/auth/spreadsheets',
  'https://www.googleapis.com/auth/drive.file',
].join(' ');

// Module-level token cache (lives for the duration of a Worker instance, ~minutes)
let _cachedToken = null;
let _cachedExpiry = 0;

// ─── JWT helpers ─────────────────────────────────────────────────────────────

function b64url(data) {
  let str;
  if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
    const bytes = new Uint8Array(data instanceof ArrayBuffer ? data : data.buffer);
    str = btoa(String.fromCharCode(...bytes));
  } else {
    str = btoa(unescape(encodeURIComponent(data)));
  }
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function importPrivateKey(pem) {
  const contents = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s+/g, '');
  const binary = atob(contents);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return crypto.subtle.importKey(
    'pkcs8',
    bytes.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

async function makeJWT(email, privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const header  = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({
    iss: email,
    sub: email,
    scope: SCOPES,
    aud: GOOGLE_TOKEN_URL,
    iat: now,
    exp: now + 3600,
  }));
  const sigInput = `${header}.${payload}`;
  const sig = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    privateKey,
    new TextEncoder().encode(sigInput)
  );
  return `${sigInput}.${b64url(sig)}`;
}

// ─── Token acquisition ────────────────────────────────────────────────────────

async function getAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (_cachedToken && _cachedExpiry > now + 60) return _cachedToken;

  const creds = JSON.parse(env.SA_CREDENTIALS);
  const key   = await importPrivateKey(creds.private_key);
  const jwt   = await makeJWT(creds.client_email, key);

  const resp = await fetch(GOOGLE_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  });
  const data = await resp.json();
  if (data.error) throw new Error(`Token error: ${data.error} — ${data.error_description}`);

  _cachedToken  = data.access_token;
  _cachedExpiry = now + (data.expires_in || 3599);
  return _cachedToken;
}

// ─── CORS headers ─────────────────────────────────────────────────────────────

function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '*';
  return {
    'Access-Control-Allow-Origin':  origin,
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Max-Age':       '86400',
  };
}

// ─── Main handler ─────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    const url  = new URL(request.url);
    const path = url.pathname;

    // Health check
    if (path === '/' || path === '') {
      return new Response('WDC Proxy OK', { headers: corsHeaders(request) });
    }

    // Route to Google API
    let googleUrl;
    if (path.startsWith('/gapi-upload/')) {
      googleUrl = 'https://www.googleapis.com/upload/' + path.slice('/gapi-upload/'.length) + url.search;
    } else if (path.startsWith('/gapi/')) {
      googleUrl = 'https://www.googleapis.com/' + path.slice('/gapi/'.length) + url.search;
    } else {
      return new Response('Not found', { status: 404, headers: corsHeaders(request) });
    }

    try {
      const token = await getAccessToken(env);

      // Forward the request — strip CF-specific headers, inject auth
      const fwdHeaders = new Headers();
      for (const [k, v] of request.headers.entries()) {
        const lk = k.toLowerCase();
        if (lk.startsWith('cf-') || lk === 'host' || lk === 'authorization') continue;
        fwdHeaders.set(k, v);
      }
      fwdHeaders.set('Authorization', `Bearer ${token}`);

      const fwdBody = (request.method !== 'GET' && request.method !== 'HEAD')
        ? request.body : undefined;

      const upstream = await fetch(googleUrl, {
        method:  request.method,
        headers: fwdHeaders,
        body:    fwdBody,
      });

      const respHeaders = new Headers(upstream.headers);
      for (const [k, v] of Object.entries(corsHeaders(request))) respHeaders.set(k, v);

      return new Response(upstream.body, {
        status:  upstream.status,
        headers: respHeaders,
      });

    } catch (err) {
      console.error('WDC Worker error:', err);
      return new Response(
        JSON.stringify({ error: err.message }),
        { status: 500, headers: { ...corsHeaders(request), 'Content-Type': 'application/json' } }
      );
    }
  },
};
