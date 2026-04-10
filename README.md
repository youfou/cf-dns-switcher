# CF DNS Switcher

A Cloudflare Worker that lets you instantly switch a domain's DNS record between preconfigured target nodes — directly from your browser, protected by Google OAuth.

![DNS Switcher screenshot](screenshot.jpg)

## Features

- **One-click switching** between named target nodes (A, AAAA, or CNAME — auto-detected)
- **Custom target** input for arbitrary IPs or hostnames
- **Google OAuth** login restricted to a single trusted email address
- **No database** — sessions use signed HttpOnly cookies (HMAC-SHA256 JWT)
- **Zero dependencies** — a single `index.js` using only Workers runtime APIs
- Built-in `/help` page with full setup instructions (no login required)

## Quick Start

### 1. Clone & configure

```bash
git clone https://github.com/youfou/cf-dns-switcher.git
cd cf-dns-switcher
```

Edit `wrangler.toml` to set your domain, email, and nodes:

```toml
[vars]
DOMAIN       = "sub.example.com"
GOOGLE_EMAIL = "you@gmail.com"

NODE_NAME_1 = "Home Server"
NODE_HOST_1 = "1.2.3.4"

NODE_NAME_2 = "VPS Tokyo"
NODE_HOST_2 = "5.6.7.8"
```

### 2. Set secrets

These three values are sensitive and must never be stored in files:

```bash
wrangler secret put GOOGLE_CLIENT_ID
wrangler secret put GOOGLE_CLIENT_SECRET
wrangler secret put CF_API_TOKEN
```

See the [Google OAuth Setup](#google-oauth-setup) and [Cloudflare API Token](#cloudflare-api-token) sections below for how to obtain each value.

### 3. Deploy

```bash
wrangler deploy
```

After deploying, Wrangler prints your Worker URL (e.g. `https://cf-dns-switcher.<your-account>.workers.dev`). Go back to Google Cloud Console and add `https://<your-worker-url>/auth/callback` as an authorized redirect URI — see step 4 of [Google OAuth Setup](#google-oauth-setup).

## Environment Variables

| Variable | Required | Set via | Description |
|---|---|---|---|
| `DOMAIN` | ✅ | `wrangler.toml` | Domain whose DNS record is managed |
| `GOOGLE_EMAIL` | ✅ | `wrangler.toml` | Google account email allowed to log in |
| `GOOGLE_CLIENT_ID` | ✅ | `wrangler secret put` | Google OAuth 2.0 Client ID |
| `GOOGLE_CLIENT_SECRET` | ✅ | `wrangler secret put` | Google OAuth 2.0 Client Secret |
| `CF_API_TOKEN` | ✅ | `wrangler secret put` | Cloudflare API token with *Edit zone DNS* permission |
| `NODE_NAME_n` | Optional | `wrangler.toml` | Display name for node *n* (n = 1, 2, …) |
| `NODE_HOST_n` | Optional | `wrangler.toml` | IP address or hostname for node *n* |

Nodes are read from `NODE_NAME_1` / `NODE_HOST_1` upward, stopping at the first missing `NODE_NAME_n`. Only pairs where both name and host are defined are shown.

## DNS Type Detection

The worker inspects the target value and picks the record type automatically:

| Target value | Record type |
|---|---|
| `1.2.3.4` (IPv4) | `A` |
| `2001:db8::1` (IPv6) | `AAAA` |
| `cdn.example.com` (hostname) | `CNAME` |

If an existing record's type needs to change, the old record is deleted and a new one is created.

## Google OAuth Setup

This worker uses Google OAuth to restrict access to a single trusted account. You need to create OAuth credentials in Google Cloud Console.

1. Open [Google Cloud Console](https://console.cloud.google.com/) → create or select a project.
2. Go to [APIs & Services → OAuth consent screen](https://console.cloud.google.com/apis/credentials/consent) → set user type to *External* and fill in the required fields. Under **Test users**, add the Google account email you intend to use. (While the app is in Testing mode, only explicitly added test users can sign in — this is fine for a personal tool.)
3. Go to [APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials) → **Create Credentials** → **OAuth 2.0 Client ID** → application type: *Web application*.
4. Under **Authorized redirect URIs**, add your Worker's callback URL. You'll get the exact URL after running `wrangler deploy`; it looks like:
   ```
   https://cf-dns-switcher.<your-account>.workers.dev/auth/callback
   ```
   If you haven't deployed yet, you can save a placeholder and come back to update it after step 3 of Quick Start.
5. Click **Create**. Copy the **Client ID** and **Client Secret**, then set them as secrets:
   ```bash
   wrangler secret put GOOGLE_CLIENT_ID
   wrangler secret put GOOGLE_CLIENT_SECRET
   ```

## Cloudflare API Token

1. Open [Dashboard → My Profile → API Tokens](https://dash.cloudflare.com/profile/api-tokens).
2. Click **Create Token** → use the *Edit zone DNS* template.
3. Under **Zone Resources**, restrict to the specific zone that contains your domain.
4. Click **Continue to summary** → **Create Token**. Copy the token — it is shown only once.
5. Set it as a secret:
   ```bash
   wrangler secret put CF_API_TOKEN
   ```

## Project Structure

```
cf-dns-switcher/
├── index.js        # Entire Worker — routing, auth, DNS logic, UI
└── wrangler.toml   # Deployment config and non-sensitive variables
```

## License

MIT