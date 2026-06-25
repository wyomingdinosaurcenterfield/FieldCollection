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
  let bytes;
  if (data instanceof ArrayBuffer) {
    bytes = new Uint8Array(data);
  } else if (ArrayBuffer.isView(data)) {
    bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  } else {
    bytes = new TextEncoder().encode(data);
  }
  let str = '';
  for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function importPrivateKey(pem) {
  // Robust cleanup: strip surrounding quotes, literal \n, all whitespace
  pem = pem.trim().replace(/^"+|"+$/g, '');       // strip leading/trailing "
  pem = pem.replace(/\\n/g, '\n');                 // literal \n → real newline
  const contents = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
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
  email = email.trim();
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

  // Accepts either two separate secrets (SA_EMAIL + SA_PRIVATE_KEY)
  // or a full service account JSON string (SA_CREDENTIALS)
  let email, privateKeyPem;
  if (env.SA_EMAIL && env.SA_PRIVATE_KEY) {
    email = env.SA_EMAIL;
    privateKeyPem = env.SA_PRIVATE_KEY;
  } else if (env.SA_CREDENTIALS) {
    const creds = typeof env.SA_CREDENTIALS === 'string'
      ? JSON.parse(env.SA_CREDENTIALS) : env.SA_CREDENTIALS;
    email = creds.client_email;
    privateKeyPem = creds.private_key;
  } else {
    throw new Error('No service account credentials configured. Add SA_EMAIL + SA_PRIVATE_KEY secrets.');
  }

  const key = await importPrivateKey(privateKeyPem);
  const jwt = await makeJWT(email, key);

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

    // Debug endpoint — tests token acquisition and reports errors
    if (path === '/health') {
      const rawKey = env.SA_PRIVATE_KEY || '';
      const cleaned = rawKey.trim().replace(/^"+|"+$/g, '').replace(/\\n/g, '\n');
      const b64 = cleaned.replace(/-----BEGIN PRIVATE KEY-----/g,'').replace(/-----END PRIVATE KEY-----/g,'').replace(/\s+/g,'');
      try {
        const token = await getAccessToken(env);
        return new Response(JSON.stringify({
          ok: true,
          token_prefix: token.slice(0, 20) + '...',
          email: env.SA_EMAIL?.trim(),
          raw_key_length: rawKey.length,
          raw_key_starts: rawKey.slice(0, 40),
          b64_length: b64.length,
          b64_sample: b64.slice(0, 20),
        }), { headers: { ...corsHeaders(request), 'Content-Type': 'application/json' } });
      } catch(err) {
        return new Response(JSON.stringify({
          ok: false,
          error: err.message,
          email: env.SA_EMAIL?.trim(),
          raw_key_length: rawKey.length,
          raw_key_starts: rawKey.slice(0, 40),
          b64_length: b64.length,
          b64_sample: b64.slice(0, 20),
        }), { status: 500, headers: { ...corsHeaders(request), 'Content-Type': 'application/json' } });
      }
    }

    // Route to Google API
    let googleUrl;
    if (path.startsWith('/gapi-upload/')) {
      googleUrl = 'https://www.googleapis.com/upload/' + path.slice('/gapi-upload/'.length) + url.search;
    } else if (path.startsWith('/gapi/')) {
      googleUrl = 'https://www.googleapis.com/' + path.slice('/gapi/'.length) + url.search;
    } else if (path.startsWith('/sheets/')) {
      googleUrl = 'https://sheets.googleapis.com/' + path.slice('/sheets/'.length) + url.search;
    } else if (path.startsWith('/drive/')) {
      googleUrl = 'https://drive.googleapis.com/' + path.slice('/drive/'.length) + url.search;
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
