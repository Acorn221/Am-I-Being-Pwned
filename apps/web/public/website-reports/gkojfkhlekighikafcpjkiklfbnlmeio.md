# Security Analysis: Hola VPN - Your Website Unblocker

| Field | Value |
|-------|-------|
| Extension ID | `gkojfkhlekighikafcpjkiklfbnlmeio` |
| Version | 1.249.511 |
| Manifest Version | 3 |
| Users | ~5,000,000 |
| Risk | **MEDIUM** |
| Date | 2026-02-09 |

## Summary

VPN extension with disabled P2P exit node infrastructure (nopeer build), MITM capability (user-prompted), extensive telemetry via perr.hola.org, and obfuscated fallback CDN domains. No broad URL exfiltration.

## Vulnerabilities

### VULN-01: Dormant P2P Exit Node Infrastructure [MEDIUM]

**Files:** `bg.bg.bundle.js:35247`, `bg.conf.bundle.js:68-74`

```javascript
proxy_peer = m[2] == 22223 || m[2] == 22226

// Port configuration
"ports": {
    "direct": 22222,
    "peer": 22223,
    "hola": 22224,
    "trial": 22225,
    "trial_peer": 22226
}
```

**Analysis:** The extension contains full peer routing logic — port allocation, domain-based peer targeting (Netflix, Hulu, etc.), and strategy routing decisions. However, the current build is flagged `nopeer_v3` in source maps, indicating P2P is disabled. The code could theoretically be re-enabled server-side.

**Verdict:** MEDIUM — P2P infrastructure is present but inactive in this build.

---

### VULN-02: User-Prompted MITM Capability [MEDIUM]

**Files:** `mitm.bundle.js:237`, `530.bundle.js:554-623`

```javascript
const Mitm = () => {
    perr("mitm_show");
    // User can approve unblocking
    perr("mitm_manual_approved");
    yield api.mitm_set_unblock(root_url, tab_id);
    // Or ignore
    perr("mitm_manual_ignore");
    yield api.mitm_set_ignore(root_url, tab_id);
}
```

**Analysis:** MITM files exist (`mitm.bundle.js`, `mitm.html`) for intercepting SSL/TLS connections on certain sites. The implementation shows a user-facing dialog requiring manual approval before unblocking — this is not silent interception.

**Verdict:** MEDIUM — MITM capability exists but requires user consent per-site.

---

### VULN-03: Extensive Telemetry with Selective URL Reporting [MEDIUM]

**Files:** `bg.bg.bundle.js:31564-31586`, `971.bundle.js:15995`

```javascript
// Google captcha detection — sends full URL to perr.hola.org
const google_captcha_send_perr = _url => {
    if (!google_host(url.hostname)) return;
    perr(id, { url: _url }, { ... })
}

// VPN popup operations — sends root_url + popup URL
perr("be_tpopup_open", { root_url, url });
```

**Analysis:** Telemetry system (`perr.hola.org`) logs every extension event. Most events are metadata-only (install, update, errors), but specific events include URLs: Google captcha pages (full URL), payment pages (full URL), and VPN domain operations (root domain). No broad browsing history collection — no `chrome.history` API, no XHR/fetch hooking, no passive URL harvesting.

**Verdict:** MEDIUM — Telemetry is extensive but URL collection is narrowly scoped.

---

### VULN-04: Persistent UUID Tracking [LOW]

**Files:** `bg.bg.bundle.js:281-339`

```javascript
function ensure_uuid() {
    const uuid = get(ret, "local.uuid") ||
                 ret.localStorage ||
                 ret.cookie ||
                 get(ret, "ccgi.value");
}
```

**Analysis:** Users are assigned a persistent UUID stored redundantly across chrome.storage, localStorage, cookies, and server-side. This allows cross-session identification. Standard for VPN services but more aggressive than typical implementations.

**Verdict:** LOW — Persistent tracking is invasive but expected for account-based VPN services.

---

## Flags

| Category | Evidence |
|----------|----------|
| affiliate_fraud | `bg.bg.bundle.js:186`: Affiliate ID (`aff_id`) tracking in install telemetry, parent company (Bright Data) operates residential proxy network |
| data_exfiltration | `bg.bg.bundle.js:31564`: Google captcha URLs and VPN operation domains sent to `perr.hola.org` |
| dynamic_eval | `971.bundle.js:4779`: `new Function("", '"use strict";return (' + v.__Function__ + ");")()` — constructs functions from stored data |
| dynamic_function | `971.bundle.js:4501`: `var func = new Function(["flags", "conv"], f)` — dynamic function construction |

## Endpoints

| Domain | Purpose | Data Sent |
|--------|---------|-----------|
| client.hola.org | Main API (auth, config, status) | UUID, version, device info, country |
| perr.hola.org | Telemetry/error reporting | Event logs, selective URLs (captcha/payment pages) |
| hola.org | Website/account | Cookies (aff_id, install_src, be_usage) |
| h-vpn.org | VPN infrastructure | Proxy routing |
| holavpn.com | VPN infrastructure | Proxy routing |
| zspeed-cdn.com | CDN fallback | Agent server connections |
| c6gj-static.net | CDN fallback (obfuscated) | Agent server connections |
| su89-cdn.net | CDN fallback (obfuscated) | Agent server connections |
| x-cdn-static.com | CDN fallback (obfuscated) | Agent server connections |
| kbz0pwvxmv.com | CDN fallback (obfuscated) | Agent server connections |
| yg5sjx5kzy.com | CDN fallback (obfuscated) | Agent server connections |

## Data Flow

User installs extension → UUID assigned (stored in storage/cookies/server) → install telemetry sent to `perr.hola.org` with affiliate ID and device metadata. During VPN usage, proxy connections route through numbered `zagent*.hola.org` servers with obfuscated domain fallbacks. Telemetry events fire on VPN state changes, errors, and specific page types (Google captcha, payment pages) — these include the relevant URL. All other browsing activity is not reported back to Hola's servers.

## Overall Risk: MEDIUM

Hola VPN is a functional VPN with heavier-than-typical telemetry and dormant P2P infrastructure. The P2P exit node code is present but disabled in this `nopeer_v3` build. MITM capability exists but requires user approval. URL reporting is limited to specific contexts (captcha detection, payment pages, VPN operations) — there is no broad browsing surveillance. The obfuscated fallback CDN domains are concerning for transparency but serve a functional purpose (resilience against blocking). The connection to Bright Data's residential proxy business is a reputational concern but not evidenced as active in this build.
