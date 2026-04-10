// =============================================================================
// Constants
// =============================================================================

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const GOOGLE_UINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo";
const CF_API = "https://api.cloudflare.com/client/v4";
const SESSION_COOKIE = "__dns_sess";
const STATE_COOKIE = "__oauth_st";
const SESSION_TTL = 7 * 24 * 3600;

// =============================================================================
// JWT Helpers (Web Crypto API)
// =============================================================================

function b64u(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64uDec(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return atob(str);
}

async function makeHmacKey(secret) {
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

async function signJWT(payload, secret) {
  const header = b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64u(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const key = await makeHmacKey(secret);
  const enc = new TextEncoder();
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  const sigArr = Array.from(new Uint8Array(sigBuf));
  const sigStr = String.fromCharCode(...sigArr);
  const sig = b64u(sigStr);
  return `${data}.${sig}`;
}

async function verifyJWT(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts;
    const data = `${header}.${body}`;
    const key = await makeHmacKey(secret);
    const enc = new TextEncoder();
    const sigRaw = b64uDec(sig);
    const sigBuf = Uint8Array.from(sigRaw, (c) => c.charCodeAt(0));
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBuf,
      enc.encode(data),
    );
    if (!valid) return null;
    const payload = JSON.parse(b64uDec(body));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

// =============================================================================
// Cookie Helpers
// =============================================================================

function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const result = {};
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const idx = trimmed.indexOf("=");
    if (idx < 0) continue;
    const name = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim();
    result[name] = value;
  }
  return result;
}

function makeCookie(name, value, options = {}) {
  let cookie = `${name}=${value}`;
  if (options.maxAge !== undefined) cookie += `; Max-Age=${options.maxAge}`;
  if (options.httpOnly) cookie += "; HttpOnly";
  if (options.secure !== false) cookie += "; Secure";
  cookie += "; SameSite=Lax";
  cookie += "; Path=/";
  return cookie;
}

// =============================================================================
// Session
// =============================================================================

async function getSession(request, env) {
  const cookies = parseCookies(request);
  const token = cookies[SESSION_COOKIE];
  if (!token) return null;
  return verifyJWT(token, env.GOOGLE_CLIENT_SECRET);
}

// =============================================================================
// Node Parsing
// =============================================================================

function getNodes(env) {
  const nodes = [];
  let n = 1;
  while (true) {
    const name = env[`NODE_NAME_${n}`];
    if (!name) break;
    const host = env[`NODE_HOST_${n}`];
    if (name && host) nodes.push({ name, host });
    n++;
  }
  return nodes;
}

// =============================================================================
// DNS Type Detection
// =============================================================================

function detectDNSType(host) {
  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return "A";
  // IPv6
  if (host.includes(":")) return "AAAA";
  // Domain / CNAME
  return "CNAME";
}

// =============================================================================
// Cloudflare API
// =============================================================================

async function cfRequest(path, env, init = {}) {
  const url = `${CF_API}${path}`;
  const headers = {
    Authorization: `Bearer ${env.CF_API_TOKEN}`,
    "Content-Type": "application/json",
    ...(init.headers || {}),
  };
  const res = await fetch(url, { ...init, headers });
  return res;
}

async function findZoneId(env) {
  const parts = env.DOMAIN.split(".");
  // Try progressively shorter suffixes, stopping at the last two labels
  for (let i = 0; i <= parts.length - 2; i++) {
    const candidate = parts.slice(i).join(".");
    const res = await cfRequest(
      `/zones?name=${encodeURIComponent(candidate)}`,
      env,
    );
    const data = await res.json();
    if (data.result && data.result.length > 0) {
      return data.result[0].id;
    }
  }
  return null;
}

async function fetchCurrentDNS(env) {
  const zoneId = await findZoneId(env);
  if (!zoneId) return { zoneId: null, record: null };

  for (const type of ["A", "AAAA", "CNAME"]) {
    const res = await cfRequest(
      `/zones/${zoneId}/dns_records?type=${type}&name=${encodeURIComponent(env.DOMAIN)}`,
      env,
    );
    const data = await res.json();
    if (data.result && data.result.length > 0) {
      const r = data.result[0];
      return { zoneId, record: { id: r.id, type: r.type, content: r.content } };
    }
  }
  return { zoneId, record: null };
}

// =============================================================================
// API Handlers
// =============================================================================

async function handleGetDNS(request, env) {
  try {
    const { record } = await fetchCurrentDNS(env);
    return Response.json({ record: record || null });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}

async function handleSetDNS(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const host = (body.host || "").trim();
  if (!host) return Response.json({ error: "Missing host" }, { status: 400 });

  const type = detectDNSType(host);

  try {
    const { zoneId, record } = await fetchCurrentDNS(env);
    if (!zoneId)
      return Response.json(
        { error: "DNS zone not found for domain" },
        { status: 500 },
      );

    const payload = {
      type,
      name: env.DOMAIN,
      content: host,
      ttl: 1,
      proxied: false,
    };

    if (record) {
      if (record.type !== type) {
        // Delete old record, then create new one
        await cfRequest(`/zones/${zoneId}/dns_records/${record.id}`, env, {
          method: "DELETE",
        });
        const createRes = await cfRequest(`/zones/${zoneId}/dns_records`, env, {
          method: "POST",
          body: JSON.stringify(payload),
        });
        const createData = await createRes.json();
        if (!createData.success) {
          return Response.json(
            {
              error:
                createData.errors?.[0]?.message || "Failed to create record",
            },
            { status: 500 },
          );
        }
      } else {
        // PUT to update
        const putRes = await cfRequest(
          `/zones/${zoneId}/dns_records/${record.id}`,
          env,
          {
            method: "PUT",
            body: JSON.stringify(payload),
          },
        );
        const putData = await putRes.json();
        if (!putData.success) {
          return Response.json(
            {
              error: putData.errors?.[0]?.message || "Failed to update record",
            },
            { status: 500 },
          );
        }
      }
    } else {
      // POST new
      const postRes = await cfRequest(`/zones/${zoneId}/dns_records`, env, {
        method: "POST",
        body: JSON.stringify(payload),
      });
      const postData = await postRes.json();
      if (!postData.success) {
        return Response.json(
          { error: postData.errors?.[0]?.message || "Failed to create record" },
          { status: 500 },
        );
      }
    }

    return Response.json({ success: true, record: { type, content: host } });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 500 });
  }
}

// =============================================================================
// Auth Handlers
// =============================================================================

async function handleLogin(request, env) {
  const url = new URL(request.url);
  const state = crypto.randomUUID();
  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: new URL("/auth/callback", url.origin).href,
    response_type: "code",
    scope: "openid email",
    state,
    access_type: "online",
    prompt: "select_account",
  });

  const stateCookie = makeCookie(STATE_COOKIE, state, {
    maxAge: 600,
    httpOnly: true,
  });
  return new Response(null, {
    status: 302,
    headers: {
      Location: `${GOOGLE_AUTH_URL}?${params}`,
      "Set-Cookie": stateCookie,
    },
  });
}

async function handleCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookies = parseCookies(request);
  const origin = url.origin;

  // Clear state cookie header (used for both error and success paths)
  const clearState = makeCookie(STATE_COOKIE, "", {
    maxAge: 0,
    httpOnly: true,
  });

  // Verify state
  if (!state || !cookies[STATE_COOKIE] || state !== cookies[STATE_COOKIE]) {
    return new Response(null, {
      status: 302,
      headers: {
        Location: new URL("/auth/login", origin).href,
        "Set-Cookie": clearState,
      },
    });
  }

  if (!code) {
    return new Response(null, {
      status: 302,
      headers: {
        Location: new URL("/auth/login", origin).href,
        "Set-Cookie": clearState,
      },
    });
  }

  // Exchange code for tokens
  let tokenData;
  try {
    const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: new URL("/auth/callback", origin).href,
        grant_type: "authorization_code",
      }),
    });
    tokenData = await tokenRes.json();
  } catch {
    return new Response(null, {
      status: 302,
      headers: {
        Location: new URL("/auth/login", origin).href,
        "Set-Cookie": clearState,
      },
    });
  }

  if (!tokenData.access_token) {
    return new Response(null, {
      status: 302,
      headers: {
        Location: new URL("/auth/login", origin).href,
        "Set-Cookie": clearState,
      },
    });
  }

  // Get user info
  let userInfo;
  try {
    const uinfoRes = await fetch(GOOGLE_UINFO_URL, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    userInfo = await uinfoRes.json();
  } catch {
    return new Response(null, {
      status: 302,
      headers: {
        Location: new URL("/auth/login", origin).href,
        "Set-Cookie": clearState,
      },
    });
  }

  const email = (userInfo.email || "").toLowerCase();
  if (email !== env.GOOGLE_EMAIL.toLowerCase()) {
    return new Response(null, {
      status: 302,
      headers: {
        Location: new URL("/auth/login", origin).href,
        "Set-Cookie": clearState,
      },
    });
  }

  // Create session JWT
  const now = Math.floor(Date.now() / 1000);
  const jwt = await signJWT(
    { email, exp: now + SESSION_TTL },
    env.GOOGLE_CLIENT_SECRET,
  );
  const sessCookie = makeCookie(SESSION_COOKIE, jwt, {
    maxAge: SESSION_TTL,
    httpOnly: true,
  });

  const headers = new Headers();
  headers.append("Location", new URL("/", origin).href);
  headers.append("Set-Cookie", sessCookie);
  headers.append("Set-Cookie", clearState);
  return new Response(null, { status: 302, headers });
}

function handleLogout(request) {
  const url = new URL(request.url);
  const clearSess = makeCookie(SESSION_COOKIE, "", {
    maxAge: 0,
    httpOnly: true,
  });
  return new Response(null, {
    status: 302,
    headers: {
      Location: new URL("/", url.origin).href,
      "Set-Cookie": clearSess,
    },
  });
}

// =============================================================================
// HTML Helpers
// =============================================================================

function esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function errorPage(status, message, backHref = "/", backLabel = "Go back") {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Error ${status} — DNS Switcher</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:#0f172a; --surface:#1e293b; --border:#334155;
    --text:#f1f5f9; --muted:#94a3b8; --accent:#3b82f6;
    --error:#ef4444; --error-bg:rgba(239,68,68,.12);
  }
  body { background:var(--bg); color:var(--text); font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    min-height:100vh; display:flex; align-items:center; justify-content:center; padding:1.5rem; }
  .card { background:var(--surface); border:1px solid var(--border); border-radius:1rem;
    padding:2.5rem 2rem; max-width:400px; width:100%; text-align:center; }
  .icon { font-size:3rem; margin-bottom:1rem; }
  h1 { font-size:1.25rem; font-weight:700; color:var(--error); margin-bottom:.75rem; }
  p  { color:var(--muted); font-size:.9rem; line-height:1.6; margin-bottom:1.75rem; }
  a  { display:inline-block; background:var(--accent); color:#fff; text-decoration:none;
    padding:.6rem 1.4rem; border-radius:.5rem; font-size:.875rem; font-weight:600;
    transition:opacity .15s; }
  a:hover { opacity:.85; }
</style>
</head>
<body>
  <div class="card">
    <div class="icon">⚠️</div>
    <h1>Error ${status}</h1>
    <p>${esc(message)}</p>
    <a href="${esc(backHref)}">${esc(backLabel)}</a>
  </div>
</body>
</html>`;
  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html;charset=UTF-8" },
  });
}

// =============================================================================
// Main Page
// =============================================================================

function renderMain(env, session) {
  const nodes = getNodes(env);
  const nodesJSON = JSON.stringify(nodes);
  const emailEsc = esc(session.email);
  const domainEsc = esc(env.DOMAIN);

  const nodeCards = nodes
    .map(
      (node, i) => `
    <div class="node-card" id="node-${i}" onclick="pick(${i})">
      <span class="node-radio" id="radio-${i}"></span>
      <div class="node-info">
        <span class="node-name">${esc(node.name)}</span>
        <span class="node-host">${esc(node.host)}</span>
      </div>
    </div>`,
    )
    .join("\n");

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DNS Switcher — ${domainEsc}</title>
<style>
  *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
  :root {
    --bg:#0f172a;
    --surface:#1e293b;
    --surface2:#263348;
    --border:#334155;
    --text:#f1f5f9;
    --muted:#94a3b8;
    --accent:#3b82f6;
    --accent-bg:rgba(59,130,246,.15);
    --accent-br:rgba(59,130,246,.5);
    --pending:#f59e0b;
    --pending-bg:rgba(245,158,11,.15);
    --pending-br:rgba(245,158,11,.5);
    --error:#ef4444;
    --error-bg:rgba(239,68,68,.12);
    --success:#22c55e;
  }
  body {
    background:var(--bg);
    color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    min-height:100vh;
    display:flex;
    flex-direction:column;
    align-items:center;
    padding:2rem 1rem 3rem;
  }
  .container { width:100%; max-width:440px; }

  /* Header */
  .header { margin-bottom:1.75rem; }
  .header-top { display:flex; align-items:center; justify-content:space-between; gap:.75rem; flex-wrap:wrap; }
  .title { font-size:1.5rem; font-weight:800; letter-spacing:-.025em; }
  .domain-badge {
    background:var(--surface2);
    border:1px solid var(--border);
    color:var(--muted);
    font-size:.75rem;
    font-family:'SF Mono','Fira Code',monospace;
    padding:.25rem .6rem;
    border-radius:.375rem;
    white-space:nowrap;
    overflow:hidden;
    text-overflow:ellipsis;
    max-width:220px;
  }

  /* Status bar */
  .status-bar {
    display:flex;
    align-items:center;
    gap:.5rem;
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:.625rem;
    padding:.625rem .875rem;
    margin-top:1rem;
    font-size:.8125rem;
    color:var(--muted);
    min-height:2.5rem;
  }
  .status-dot {
    width:.5rem;
    height:.5rem;
    border-radius:50%;
    flex-shrink:0;
    background:var(--muted);
  }
  .status-bar.ok .status-dot    { background:var(--success); }
  .status-bar.err .status-dot   { background:var(--error); }
  .status-bar.loading .status-dot {
    background:var(--pending);
    animation:pulse 1.2s ease-in-out infinite;
  }
  .status-text { flex:1; }
  .status-host {
    font-family:'SF Mono','Fira Code',monospace;
    font-size:.75rem;
    color:var(--text);
    background:var(--surface2);
    padding:.15rem .45rem;
    border-radius:.3rem;
    margin-left:.25rem;
  }

  /* Section label */
  .section-label {
    font-size:.6875rem;
    font-weight:600;
    text-transform:uppercase;
    letter-spacing:.08em;
    color:var(--muted);
    margin:1.5rem 0 .5rem;
  }

  /* Node cards */
  .nodes { display:flex; flex-direction:column; gap:.5rem; }

  .node-card {
    display:flex;
    align-items:center;
    gap:.875rem;
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:.75rem;
    padding:.875rem 1rem;
    cursor:pointer;
    transition:border-color .15s, background .15s;
    user-select:none;
    -webkit-tap-highlight-color:transparent;
  }
  .node-card:hover:not(.active):not(.pending) {
    border-color:#4b5a70;
    background:var(--surface2);
  }
  .node-card.active {
    background:var(--accent-bg);
    border-color:var(--accent-br);
    cursor:default;
  }
  .node-card.pending {
    background:var(--pending-bg);
    border-color:var(--pending-br);
    cursor:default;
  }

  .node-radio {
    width:1rem;
    height:1rem;
    border-radius:50%;
    border:2px solid var(--border);
    flex-shrink:0;
    transition:border-color .15s, box-shadow .15s;
    position:relative;
  }
  .node-card.active .node-radio {
    border-color:var(--accent);
    box-shadow:inset 0 0 0 3px var(--bg), inset 0 0 0 5px var(--accent);
  }
  .node-card.pending .node-radio {
    border-color:var(--pending);
    animation:pulse 1.2s ease-in-out infinite;
  }

  .node-info { flex:1; min-width:0; }
  .node-name {
    display:block;
    font-weight:600;
    font-size:.9375rem;
    color:var(--text);
    white-space:nowrap;
    overflow:hidden;
    text-overflow:ellipsis;
    transition:color .15s;
  }
  .node-card.active .node-name   { color:var(--accent); }
  .node-card.pending .node-name  { color:var(--pending); }

  .node-host {
    display:block;
    font-family:'SF Mono','Fira Code',monospace;
    font-size:.75rem;
    color:var(--muted);
    margin-top:.125rem;
    white-space:nowrap;
    overflow:hidden;
    text-overflow:ellipsis;
  }

  /* Custom card */
  .custom-card {
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:.75rem;
    overflow:hidden;
    transition:border-color .15s, background .15s;
  }
  .custom-card.active {
    background:var(--accent-bg);
    border-color:var(--accent-br);
  }
  .custom-card.pending {
    background:var(--pending-bg);
    border-color:var(--pending-br);
  }
  .custom-header {
    display:flex;
    align-items:center;
    gap:.875rem;
    padding:.875rem 1rem;
    cursor:pointer;
    user-select:none;
    -webkit-tap-highlight-color:transparent;
  }
  .custom-header:hover .custom-label:not(.active .custom-label):not(.pending .custom-label) {
    color:var(--text);
  }
  .custom-radio {
    width:1rem;
    height:1rem;
    border-radius:50%;
    border:2px solid var(--border);
    flex-shrink:0;
    transition:border-color .15s, box-shadow .15s;
  }
  .custom-card.active .custom-radio {
    border-color:var(--accent);
    box-shadow:inset 0 0 0 3px var(--bg), inset 0 0 0 5px var(--accent);
  }
  .custom-card.pending .custom-radio {
    border-color:var(--pending);
    animation:pulse 1.2s ease-in-out infinite;
  }
  .custom-label {
    font-weight:600;
    font-size:.9375rem;
    color:var(--muted);
    flex:1;
    transition:color .15s;
  }
  .custom-card.active .custom-label  { color:var(--accent); }
  .custom-card.pending .custom-label { color:var(--pending); }
  .custom-chevron {
    color:var(--muted);
    font-size:.75rem;
    transition:transform .2s;
    line-height:1;
  }
  .custom-card.open .custom-chevron { transform:rotate(180deg); }

  .custom-body {
    display:none;
    padding:0 1rem .875rem;
  }
  .custom-card.open .custom-body { display:block; }

  .custom-input {
    width:100%;
    background:var(--surface2);
    border:1px solid var(--border);
    border-radius:.5rem;
    color:var(--text);
    font-family:'SF Mono','Fira Code',monospace;
    font-size:.8125rem;
    padding:.5rem .75rem;
    outline:none;
    transition:border-color .15s, box-shadow .15s;
  }
  .custom-input::placeholder { color:#475569; }
  .custom-input:focus {
    border-color:var(--accent-br);
    box-shadow:0 0 0 3px rgba(59,130,246,.1);
  }
  .custom-hint {
    font-size:.7rem;
    color:#475569;
    margin-top:.4rem;
    padding-left:.1rem;
  }

  /* Error message */
  .err-msg {
    display:none;
    background:var(--error-bg);
    border:1px solid rgba(239,68,68,.3);
    color:var(--error);
    border-radius:.625rem;
    padding:.625rem .875rem;
    font-size:.8rem;
    margin-top:.75rem;
  }
  .err-msg.visible { display:block; }

  /* Footer */
  .footer {
    display:flex;
    align-items:center;
    justify-content:space-between;
    flex-wrap:wrap;
    gap:.5rem;
    margin-top:1.75rem;
    padding-top:1.25rem;
    border-top:1px solid var(--border);
  }
  .footer-left {
    font-size:.8rem;
    color:var(--muted);
    display:flex;
    align-items:center;
    gap:.35rem;
    flex-wrap:wrap;
  }
  .footer-email {
    font-family:'SF Mono','Fira Code',monospace;
    font-size:.75rem;
    color:var(--text);
  }
  .footer-right {
    display:flex;
    align-items:center;
    gap:.5rem;
  }
  .btn-signout {
    background:transparent;
    border:1px solid var(--border);
    color:var(--muted);
    cursor:pointer;
    font-size:.75rem;
    padding:.3rem .7rem;
    border-radius:.4rem;
    transition:border-color .15s, color .15s;
  }
  .btn-signout:hover { border-color:#4b5a70; color:var(--text); }
  .help-link {
    font-size:.75rem;
    color:var(--muted);
    text-decoration:none;
    transition:color .15s;
  }
  .help-link:hover { color:var(--accent); }

  @keyframes pulse {
    0%,100% { opacity:1; }
    50%      { opacity:.4; }
  }
</style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div class="header">
    <div class="header-top">
      <span class="title">DNS Switcher</span>
      <span class="domain-badge" title="${domainEsc}">${domainEsc}</span>
    </div>
    <div class="status-bar loading" id="status-bar">
      <div class="status-dot"></div>
      <span class="status-text" id="status-text">Loading DNS record…</span>
    </div>
  </div>

  <!-- Node List -->
  <div class="section-label">Target Nodes</div>
  <div class="nodes" id="nodes-list">
${nodeCards}
    <!-- Custom node -->
    <div class="custom-card" id="custom-card">
      <div class="custom-header" onclick="toggleCustom()">
        <span class="custom-radio" id="custom-radio"></span>
        <span class="custom-label">Custom</span>
        <span class="custom-chevron">&#9660;</span>
      </div>
      <div class="custom-body" onclick="event.stopPropagation()">
        <input
          class="custom-input"
          id="custom-input"
          type="text"
          autocomplete="off"
          autocorrect="off"
          autocapitalize="none"
          spellcheck="false"
          placeholder="e.g. 1.2.3.4 or hostname.example.com"
        >
        <div class="custom-hint">Press Enter to apply</div>
      </div>
    </div>
  </div>

  <!-- Error message -->
  <div class="err-msg" id="err-msg"></div>

  <!-- Footer -->
  <div class="footer">
    <div class="footer-left">
      Signed in as <span class="footer-email">${emailEsc}</span>
    </div>
    <div class="footer-right">
      <a href="/help" class="help-link">Help &amp; Setup</a>
      <form action="/auth/logout" method="get" style="display:inline">
        <button type="submit" class="btn-signout">Sign out</button>
      </form>
    </div>
  </div>

</div>

<script>
const NODES = ${nodesJSON};
let curHost = null;

async function loadDNS() {
  setStatus('loading', 'Loading DNS record\u2026');
  try {
    const res  = await fetch('/api/dns');
    const data = await res.json();
    if (data.record && data.record.content) {
      curHost = data.record.content;
      const type = data.record.type;
      setStatus('ok', 'Current record \u2014 ' + type + ':');
      document.getElementById('status-text').innerHTML =
        'Current record &mdash; ' + esc(type) + ': <span class="status-host">' + esc(curHost) + '</span>';
      highlight(curHost);
    } else {
      setStatus('ok', 'No DNS record found');
      curHost = null;
      highlight(null);
    }
  } catch (err) {
    setStatus('err', 'Failed to load DNS record');
  }
}

function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function setStatus(cls, msg) {
  const bar  = document.getElementById('status-bar');
  const text = document.getElementById('status-text');
  bar.className = 'status-bar ' + cls;
  text.textContent = msg;
}

function clearHighlight() {
  for (let i = 0; i < NODES.length; i++) {
    const card = document.getElementById('node-' + i);
    if (card) card.classList.remove('active','pending');
  }
  const cc = document.getElementById('custom-card');
  if (cc) cc.classList.remove('active','pending');
}

function highlight(host) {
  clearHighlight();
  if (!host) return;
  const idx = NODES.findIndex(n => n.host === host);
  if (idx >= 0) {
    const card = document.getElementById('node-' + idx);
    if (card) card.classList.add('active');
  } else {
    const cc  = document.getElementById('custom-card');
    const inp = document.getElementById('custom-input');
    if (cc)  { cc.classList.add('active','open'); }
    if (inp) { inp.value = host; }
  }
}

async function pick(i) {
  const card = document.getElementById('node-' + i);
  if (!card) return;
  if (card.classList.contains('active') || card.classList.contains('pending')) return;
  const host = NODES[i].host;
  clearHighlight();
  card.classList.add('pending');
  setStatus('loading', 'Switching\u2026');
  try {
    const res  = await fetch('/api/dns', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ host }),
    });
    const data = await res.json();
    if (data.success) {
      curHost = host;
      card.classList.remove('pending');
      card.classList.add('active');
      setStatus('ok', 'Switched \u2014 ' + data.record.type + ':');
      document.getElementById('status-text').innerHTML =
        'Switched &mdash; ' + esc(data.record.type) + ': <span class="status-host">' + esc(host) + '</span>';
    } else {
      card.classList.remove('pending');
      showErr(data.error || 'Failed to switch DNS');
      highlight(curHost);
      setStatus('err', 'Switch failed');
    }
  } catch (err) {
    card.classList.remove('pending');
    showErr('Network error: ' + err.message);
    highlight(curHost);
    setStatus('err', 'Switch failed');
  }
}

function toggleCustom() {
  const cc  = document.getElementById('custom-card');
  const inp = document.getElementById('custom-input');
  const wasOpen = cc.classList.contains('open');
  cc.classList.toggle('open');
  if (!wasOpen && inp) setTimeout(() => inp.focus(), 50);
}

async function submitCustom() {
  const inp  = document.getElementById('custom-input');
  const cc   = document.getElementById('custom-card');
  const host = inp ? inp.value.trim() : '';
  if (!host) return;
  clearHighlight();
  if (cc)  cc.classList.add('pending','open');
  setStatus('loading', 'Switching\u2026');
  try {
    const res  = await fetch('/api/dns', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ host }),
    });
    const data = await res.json();
    if (data.success) {
      curHost = host;
      if (cc) { cc.classList.remove('pending'); cc.classList.add('active','open'); }
      setStatus('ok', 'Switched \u2014 ' + data.record.type + ':');
      document.getElementById('status-text').innerHTML =
        'Switched &mdash; ' + esc(data.record.type) + ': <span class="status-host">' + esc(host) + '</span>';
    } else {
      if (cc) cc.classList.remove('pending');
      showErr(data.error || 'Failed to switch DNS');
      highlight(curHost);
      setStatus('err', 'Switch failed');
    }
  } catch (err) {
    if (cc) cc.classList.remove('pending');
    showErr('Network error: ' + err.message);
    highlight(curHost);
    setStatus('err', 'Switch failed');
  }
}

function showErr(msg) {
  const el = document.getElementById('err-msg');
  if (!el) return;
  el.textContent = msg;
  el.classList.add('visible');
  setTimeout(() => el.classList.remove('visible'), 6000);
}

// Bind Enter key on custom input
document.addEventListener('DOMContentLoaded', function() {
  const inp = document.getElementById('custom-input');
  if (inp) inp.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); submitCustom(); }
  });
});

loadDNS();
</script>
</body>
</html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html;charset=UTF-8" },
  });
}

// =============================================================================
// Help Page
// =============================================================================

function renderHelp() {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Help &amp; Setup — DNS Switcher</title>
<style>
  *, *::before, *::after { box-sizing:border-box; margin:0; padding:0; }
  :root {
    --bg:#0f172a;
    --surface:#1e293b;
    --surface2:#263348;
    --border:#334155;
    --text:#f1f5f9;
    --muted:#94a3b8;
    --accent:#3b82f6;
    --accent-bg:rgba(59,130,246,.15);
    --success:#22c55e;
    --code-bg:#0d1525;
  }
  body {
    background:var(--bg);
    color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    line-height:1.7;
    padding:2.5rem 1rem 4rem;
  }
  .container { max-width:720px; margin:0 auto; }

  /* Breadcrumb / back */
  .back-link {
    display:inline-flex;
    align-items:center;
    gap:.35rem;
    color:var(--muted);
    text-decoration:none;
    font-size:.8125rem;
    margin-bottom:2rem;
    transition:color .15s;
  }
  .back-link:hover { color:var(--accent); }

  /* Page header */
  .page-header { margin-bottom:2.5rem; }
  .page-title  { font-size:1.875rem; font-weight:800; letter-spacing:-.03em; margin-bottom:.5rem; }
  .page-sub    { color:var(--muted); font-size:.9375rem; }

  /* Sections */
  .section { margin-bottom:2.5rem; }
  h2 {
    font-size:1.0625rem;
    font-weight:700;
    color:var(--text);
    border-bottom:1px solid var(--border);
    padding-bottom:.5rem;
    margin-bottom:1rem;
    display:flex;
    align-items:center;
    gap:.5rem;
  }
  h2 .num {
    background:var(--accent-bg);
    color:var(--accent);
    border-radius:.375rem;
    font-size:.75rem;
    font-weight:700;
    padding:.15rem .45rem;
    letter-spacing:.02em;
  }
  p  { color:var(--muted); font-size:.9rem; margin-bottom:.75rem; }
  p:last-child { margin-bottom:0; }
  li { color:var(--muted); font-size:.9rem; margin-bottom:.35rem; }
  ul, ol { padding-left:1.25rem; margin-bottom:.75rem; }

  /* Table */
  .tbl-wrap { overflow-x:auto; border-radius:.75rem; border:1px solid var(--border); margin-top:.5rem; }
  table { width:100%; border-collapse:collapse; font-size:.85rem; }
  thead th {
    background:var(--surface2);
    color:var(--muted);
    font-weight:600;
    text-align:left;
    padding:.6rem .9rem;
    font-size:.75rem;
    text-transform:uppercase;
    letter-spacing:.06em;
    border-bottom:1px solid var(--border);
  }
  tbody tr { border-bottom:1px solid var(--border); }
  tbody tr:last-child { border-bottom:none; }
  tbody tr:hover { background:rgba(255,255,255,.02); }
  td { padding:.6rem .9rem; color:var(--muted); vertical-align:top; }
  td:first-child { color:var(--text); }
  td code { background:var(--code-bg); border:1px solid var(--border); border-radius:.3rem; padding:.1rem .35rem; font-size:.78rem; font-family:'SF Mono','Fira Code',monospace; }
  .badge-yes  { color:var(--success); font-size:.75rem; font-weight:600; }
  .badge-opt  { color:var(--muted);   font-size:.75rem; }

  /* Code block */
  pre {
    background:var(--code-bg);
    border:1px solid var(--border);
    border-radius:.625rem;
    padding:1rem 1.25rem;
    overflow-x:auto;
    font-family:'SF Mono','Fira Code',monospace;
    font-size:.8125rem;
    line-height:1.65;
    color:#e2e8f0;
    margin-top:.5rem;
    margin-bottom:.75rem;
  }
  code {
    font-family:'SF Mono','Fira Code',monospace;
    font-size:.85em;
    background:var(--code-bg);
    border:1px solid var(--border);
    border-radius:.3rem;
    padding:.1rem .35rem;
    color:#e2e8f0;
  }

  /* Steps */
  .steps { list-style:none; padding:0; counter-reset:step; }
  .steps li {
    counter-increment:step;
    padding:.5rem 0 .5rem 2.25rem;
    position:relative;
    color:var(--muted);
    font-size:.9rem;
    border-bottom:1px dashed var(--border);
  }
  .steps li:last-child { border-bottom:none; }
  .steps li::before {
    content:counter(step);
    position:absolute;
    left:0;
    top:.55rem;
    width:1.4rem;
    height:1.4rem;
    background:var(--accent-bg);
    color:var(--accent);
    border-radius:50%;
    font-size:.7rem;
    font-weight:700;
    display:flex;
    align-items:center;
    justify-content:center;
    line-height:1;
  }
  .steps code { font-size:.8rem; }

  /* Note box */
  .note {
    background:var(--accent-bg);
    border:1px solid rgba(59,130,246,.3);
    border-radius:.625rem;
    padding:.75rem 1rem;
    font-size:.85rem;
    color:var(--muted);
    margin-top:.75rem;
  }
  .note strong { color:var(--accent); }

  /* Footer */
  .help-footer {
    margin-top:3rem;
    padding-top:1.5rem;
    border-top:1px solid var(--border);
    text-align:center;
    color:#475569;
    font-size:.8rem;
  }
  a { color:var(--accent); text-decoration:none; }
  a:hover { text-decoration:underline; }
  .steps a { font-weight:500; }
  .help-footer a { color:var(--muted); text-decoration:none; }
  .help-footer a:hover { color:var(--accent); text-decoration:none; }
</style>
</head>
<body>
<div class="container">

  <a href="/" class="back-link">&#8592; Back to Dashboard</a>

  <div class="page-header">
    <h1 class="page-title">Help &amp; Setup</h1>
    <p class="page-sub">Everything you need to deploy and configure DNS Switcher.</p>
  </div>

  <!-- 1. Overview -->
  <div class="section">
    <h2><span class="num">1</span> Overview</h2>
    <p>
      <strong>DNS Switcher</strong> is a Cloudflare Worker that lets an authenticated user
      instantly point a domain's DNS record to one of several preconfigured target nodes —
      or any arbitrary host — directly from a browser. It uses the Cloudflare DNS API to
      create, update, or replace <code>A</code>, <code>AAAA</code>, and <code>CNAME</code>
      records in real time.
    </p>
    <p>
      Access is protected by Google OAuth 2.0, restricted to a single trusted email address.
      Sessions are stored in a signed <code>HttpOnly</code> cookie using HMAC-SHA256 JWTs —
      no external KV or database required.
    </p>
  </div>

  <!-- 2. Prerequisites -->
  <div class="section">
    <h2><span class="num">2</span> Prerequisites</h2>
    <ul>
      <li>A <strong>Cloudflare account</strong> with the domain's DNS zone managed there — <a href="https://dash.cloudflare.com/" target="_blank" rel="noopener">dash.cloudflare.com</a>.</li>
      <li>A <strong>Google Cloud project</strong> with the OAuth consent screen configured — <a href="https://console.cloud.google.com/" target="_blank" rel="noopener">console.cloud.google.com</a>.</li>
      <li><strong>Wrangler CLI</strong> installed: <code>npm i -g wrangler</code> — <a href="https://developers.cloudflare.com/workers/wrangler/install-and-update/" target="_blank" rel="noopener">Wrangler docs</a>.</li>
      <li>Node.js 18+ (for Wrangler).</li>
    </ul>
  </div>

  <!-- 3. Environment Variables -->
  <div class="section">
    <h2><span class="num">3</span> Environment Variables</h2>
    <p>Non-sensitive values go in the <code>[vars]</code> section of <code>wrangler.toml</code>. Sensitive values must be set via <code>wrangler secret put</code> in your terminal — never store them in files.</p>
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>Variable</th>
            <th>Required</th>
            <th>Set via</th>
            <th>Description</th>
            <th>Example</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>DOMAIN</code></td>
            <td><span class="badge-yes">Yes</span></td>
            <td><code>wrangler.toml</code></td>
            <td>Domain to control DNS for</td>
            <td><code>sub.example.com</code></td>
          </tr>
          <tr>
            <td><code>GOOGLE_EMAIL</code></td>
            <td><span class="badge-yes">Yes</span></td>
            <td><code>wrangler.toml</code></td>
            <td>Google account email allowed to log in</td>
            <td><code>user@gmail.com</code></td>
          </tr>
          <tr>
            <td><code>GOOGLE_CLIENT_ID</code></td>
            <td><span class="badge-yes">Yes</span></td>
            <td><code>secret put</code></td>
            <td>Google OAuth 2.0 Client ID</td>
            <td><code>1234...apps.googleusercontent.com</code></td>
          </tr>
          <tr>
            <td><code>GOOGLE_CLIENT_SECRET</code></td>
            <td><span class="badge-yes">Yes</span></td>
            <td><code>secret put</code></td>
            <td>Google OAuth 2.0 Client Secret</td>
            <td><code>GOCSPX-...</code></td>
          </tr>
          <tr>
            <td><code>CF_API_TOKEN</code></td>
            <td><span class="badge-yes">Yes</span></td>
            <td><code>secret put</code></td>
            <td>Cloudflare API token with DNS Edit permission</td>
            <td><code>abc123...</code></td>
          </tr>
          <tr>
            <td><code>NODE_NAME_n</code></td>
            <td><span class="badge-opt">Optional</span></td>
            <td><code>wrangler.toml</code></td>
            <td>Display name for node <em>n</em> (n = 1, 2, …)</td>
            <td><code>Home Server</code></td>
          </tr>
          <tr>
            <td><code>NODE_HOST_n</code></td>
            <td><span class="badge-opt">Optional</span></td>
            <td><code>wrangler.toml</code></td>
            <td>IP address or hostname for node <em>n</em></td>
            <td><code>1.2.3.4</code></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- 4. Google OAuth Setup -->
  <div class="section">
    <h2><span class="num">4</span> Google OAuth Setup</h2>
    <ol class="steps">
      <li>Open <a href="https://console.cloud.google.com/" target="_blank" rel="noopener"><strong>Google Cloud Console</strong></a> → select or create a project.</li>
      <li>Navigate to <a href="https://console.cloud.google.com/apis/credentials/consent" target="_blank" rel="noopener"><strong>APIs &amp; Services → OAuth consent screen</strong></a>.
          Set user type to <em>External</em> and fill in the required fields. Under <strong>Test users</strong>, add the Google account email you intend to use — while the app is in Testing mode, only explicitly listed addresses can sign in.</li>
      <li>Go to <a href="https://console.cloud.google.com/apis/credentials" target="_blank" rel="noopener"><strong>APIs &amp; Services → Credentials</strong></a>.</li>
      <li>Click <strong>Create Credentials</strong> → <strong>OAuth 2.0 Client ID</strong>.</li>
      <li>Choose <strong>Web application</strong> as the application type.</li>
      <li>Under <strong>Authorized redirect URIs</strong>, add your Worker's callback URL:
          <pre>https://YOUR_WORKER_DOMAIN/auth/callback</pre>
          You will get the exact URL after running <code>wrangler deploy</code>. If you haven't deployed yet, save a placeholder here and come back to update it afterwards.
      </li>
      <li>Click <strong>Create</strong>. Copy the <strong>Client ID</strong> and <strong>Client Secret</strong>, then set them as secrets:
          <pre>wrangler secret put GOOGLE_CLIENT_ID
wrangler secret put GOOGLE_CLIENT_SECRET</pre>
      </li>
    </ol>
  </div>

  <!-- 5. Cloudflare API Token -->
  <div class="section">
    <h2><span class="num">5</span> Cloudflare API Token</h2>
    <ol class="steps">
      <li>Go to <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener"><strong>Cloudflare Dashboard → My Profile → API Tokens</strong></a>.</li>
      <li>Click <strong>Create Token</strong> → use the <a href="https://dash.cloudflare.com/profile/api-tokens/create?permissionGroupKeys=dns_records%3Aedit&name=DNS+Switcher" target="_blank" rel="noopener"><em>Edit zone DNS</em> template</a>.</li>
      <li>Under <strong>Zone Resources</strong>, select <em>Specific zone</em> → choose your domain.</li>
      <li>Click <strong>Continue to summary</strong> → <strong>Create Token</strong>.</li>
      <li>Copy the token — it's shown only once.</li>
    </ol>
  </div>

  <!-- 6. Deployment -->
  <div class="section">
    <h2><span class="num">6</span> Deployment</h2>
    <p>Create a <code>wrangler.toml</code> in your project root:</p>
    <pre>name = "cf-dns-switcher"
main = "index.js"
compatibility_date = "2024-01-01"

[vars]
DOMAIN       = "sub.example.com"
GOOGLE_EMAIL = "user@gmail.com"</pre>
    <p>Store secrets securely with Wrangler (never commit these to source control):</p>
    <pre>wrangler secret put GOOGLE_CLIENT_ID
wrangler secret put GOOGLE_CLIENT_SECRET
wrangler secret put CF_API_TOKEN</pre>
    <p>Deploy:</p>
    <pre>wrangler deploy</pre>
    <div class="note">
      <strong>After deploying:</strong> update the Google OAuth redirect URI to your Worker's
      <code>*.workers.dev</code> URL or your custom domain.
    </div>
  </div>

  <!-- 7. Node Configuration -->
  <div class="section">
    <h2><span class="num">7</span> Node Configuration</h2>
    <p>
      Define quick-switch target nodes in the <code>[vars]</code> section of
      <code>wrangler.toml</code>. Nodes are numbered starting at 1 and read
      sequentially until a gap is found.
    </p>
    <pre>[vars]
DOMAIN         = "sub.example.com"
GOOGLE_EMAIL   = "user@gmail.com"

NODE_NAME_1    = "Home Server"
NODE_HOST_1    = "203.0.113.10"

NODE_NAME_2    = "VPS Frankfurt"
NODE_HOST_2    = "198.51.100.42"

NODE_NAME_3    = "VPS Singapore"
NODE_HOST_3    = "203.0.113.55"

NODE_NAME_4    = "CDN Proxy"
NODE_HOST_4    = "cdn.example.com"</pre>
    <p>
      The <strong>Custom</strong> card at the bottom always lets you enter an arbitrary
      IP address or hostname without pre-configuring it.
    </p>
  </div>

  <!-- 8. Notes -->
  <div class="section">
    <h2><span class="num">8</span> Notes</h2>
    <ul>
      <li>
        <strong>DNS type auto-detection:</strong> The worker inspects the target value and
        automatically selects the correct record type —
        <code>A</code> for IPv4 addresses (e.g. <code>1.2.3.4</code>),
        <code>AAAA</code> for IPv6 addresses (e.g. <code>2001:db8::1</code>),
        and <code>CNAME</code> for hostnames (e.g. <code>cdn.example.com</code>).
      </li>
      <li>
        <strong>Type change handling:</strong> If you switch from an IP to a hostname (or vice
        versa), the existing record is deleted and a new one of the correct type is created.
      </li>
      <li>
        <strong>TTL:</strong> Records are created with <code>ttl: 1</code> (Cloudflare auto TTL)
        and <code>proxied: false</code> so that the real IP is exposed and propagation is fastest.
      </li>
      <li>
        <strong>Session lifetime:</strong> Login sessions last 7 days. The session secret is
        derived from your <code>GOOGLE_CLIENT_SECRET</code>, so rotating it will invalidate
        all active sessions.
      </li>
      <li>
        <strong>Zone lookup:</strong> The worker resolves your zone by progressively stripping
        subdomains from <code>DOMAIN</code> until a matching Cloudflare zone is found.
        This means it works for bare domains and any depth of subdomain.
      </li>
    </ul>
  </div>

  <div class="help-footer">
    DNS Switcher &mdash; <a href="/">Back to Dashboard</a>
  </div>

</div>
</body>
</html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html;charset=UTF-8" },
  });
}

// =============================================================================
// Main Export
// =============================================================================

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Help page is always available without auth or env checks
    if (url.pathname === "/help") return renderHelp();

    // Guard: all required env vars must be present
    const required = [
      "DOMAIN",
      "GOOGLE_EMAIL",
      "GOOGLE_CLIENT_ID",
      "GOOGLE_CLIENT_SECRET",
      "CF_API_TOKEN",
    ];
    if (required.some((k) => !env[k])) {
      return Response.redirect(new URL("/help", url.origin).href, 302);
    }

    try {
      // Auth routes (no session required)
      if (url.pathname === "/auth/login") return handleLogin(request, env);
      if (url.pathname === "/auth/callback")
        return handleCallback(request, env);
      if (url.pathname === "/auth/logout") return handleLogout(request);

      // DNS API routes (session required)
      if (url.pathname === "/api/dns") {
        const session = await getSession(request, env);
        if (!session)
          return Response.json({ error: "Unauthorized" }, { status: 401 });
        if (request.method === "GET") return handleGetDNS(request, env);
        if (request.method === "POST") return handleSetDNS(request, env);
        return new Response("Method Not Allowed", { status: 405 });
      }

      // Main page (session required, redirect to login if missing)
      if (url.pathname === "/") {
        const session = await getSession(request, env);
        if (!session) return handleLogin(request, env);
        return renderMain(env, session);
      }

      return new Response("Not Found", { status: 404 });
    } catch (err) {
      console.error(err);
      return new Response("Internal Server Error: " + err.message, {
        status: 500,
      });
    }
  },
};
