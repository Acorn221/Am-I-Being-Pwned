# Security Analysis: StreamTube Proxy
**Extension ID:** epkcfhiniijndongcpclcfogmbpphfga
**Version:** 3.1
**Users:** ~70,000
**Risk Level: MEDIUM**

## Executive Summary

StreamTube Proxy is a YouTube unblocking extension primarily targeting Russian-speaking users. It routes YouTube traffic (and optionally a large list of ~265,000 blocked Russian domains) through third-party proxy servers. The extension uses Chrome's PAC (Proxy Auto-Config) mechanism via `chrome.proxy.settings.set()` to selectively proxy YouTube-related domains through hardcoded proxy IPs embedded in the extension code.

The extension contains a dormant but fully functional C2-style mechanism (`loadThirdServer`) that fetches remote configuration from a GitHub-hosted JSON file (`https://raw.githubusercontent.com/vpn-naruzhu/public/main/uboost-extension`), resolves a dynamic API base URL (`uubb.website`), collects the user's device ID (a generated UUID) and real IP address (via `api.ipify.org`), then POSTs these to the remote server to receive proxy host:port instructions. This code path is currently dead (defined but never called), suggesting it was either disabled in this version or is being staged for future activation. The remote config endpoint is live and returns valid JSON with `apiBaseUrl: "uubb.website"`.

The content scripts inject advertising for "GEMERA VPN" (a Telegram-based VPN service) directly into YouTube watch pages and Google search results. This ad injection is hardcoded, not dynamic, and promotes `t.me/gemera_vpn_bot`. The extension also proxies `www.google.com` traffic through the proxy servers on servers 2, 3, and 4, meaning Google Search traffic passes through untrusted third-party infrastructure where it could be intercepted.

## Flag Verdicts

| Triage Flag | Pattern | Verdict | Notes |
|---|---|---|---|
| `eval` (79 hits) | Dynamic code execution | **FALSE POSITIVE** | All 79 occurrences are domain names containing "eval" in the ~265K domain blocklist (e.g., "eval.kz", "evalu8.org") |
| `fetch()` (3 hits) | Network requests | **TRUE POSITIVE (dormant)** | Remote config fetch from GitHub, IP lookup via ipify.org, and POST to dynamic API endpoint -- all in dormant `loadThirdServer` function |
| `fingerprint` (1 hit) | Browser fingerprinting | **FALSE POSITIVE** | Domain name "webfingerprint.digital" in blocklist |
| `webgl` (2 hits) | Canvas fingerprinting | **FALSE POSITIVE** | Domain names in blocklist (e.g., "bounty-webglory.shop") |
| `innerHTML` | DOM injection | **TRUE POSITIVE** | Content script injects GEMERA VPN ad banner into YouTube watch pages via `insertAdjacentHTML` |
| `history.pushState` monkey-patch | Navigation interception | **TRUE POSITIVE** | `content.js` patches `history.pushState` and `history.replaceState` to detect YouTube `/watch` page navigations and display an overlay |

## Detailed Findings

### 1. Ad Injection on YouTube Pages (TRUE POSITIVE -- LOW severity)

**File:** `deobfuscated/content_scripts/content.js` (lines 1-19)

The content script runs on `*://*.google.com/*` and `*://*.youtube.com/*` and injects a promotional banner for "GEMERA VPN" into YouTube watch pages:

```javascript
let e = document.querySelector("ytd-watch-metadata");
// ...
e.insertAdjacentHTML("afterbegin", `
    <div class="premium premium--animated premium--gradient ${n?"premium--dark":""}">
        <div class="premium__container">
            <div class="premium__header">
                <div class="premium__message">
                    <span class="premium__highlight">GEMERA VPN</span>
                </div>
                <div class="premium__actions">
                    <a class="premium__button" target="_blank" href="https://t.me/gemera_vpn_bot?start=ytboost">
                        Получить
                    </a>
                </div>
            </div>
            ...
        </div>
    </div>
`);
```

This injects an advertising banner for a Telegram VPN bot (`@gemera_vpn_bot`) at the top of YouTube video metadata on every watch page. The banner promotes a 3-day trial, 35+ locations, and unlimited devices.

### 2. YouTube Navigation Interception Overlay (TRUE POSITIVE -- LOW severity)

**File:** `deobfuscated/content.js` (lines 1-30)

This script monkey-patches `history.pushState` and `history.replaceState` to intercept YouTube SPA navigations and displays a fullscreen overlay saying "Wait, your YouTube is being accelerated..." (in Russian) for 5 seconds:

```javascript
e.pushState = function(n) {
    "function" == typeof e.onpushstate && e.onpushstate({ state: n });
    var a = t.apply(e, arguments);
    return onUrlChange(), a
};
// ...
function showOverlay() {
    // Creates #custom-overlay with message "Подождите, ваш Ютуб ускоряется..."
    // Auto-removes after 5 seconds
}
```

Note: This file (`content.js` at root) is NOT in the manifest's content_scripts -- only `content_scripts/content.js` is declared. This root-level `content.js` appears to be an unused/orphaned file.

### 3. Google Search Traffic Proxied Through Untrusted Servers (TRUE POSITIVE -- MEDIUM severity)

**File:** `deobfuscated/background.js` -- serverConfigs (servers 2, 3, 4)

Servers 2, 3, and 4 include `www.google.com` in the list of domains routed through the proxy:

```
dnsDomainIs(host, "www.google.com") || shExpMatch(host, "*." + "www.google.com")
```

This means all Google Search traffic (including search queries, which may contain sensitive information) passes through third-party proxy servers controlled by the extension operators. The proxy IPs are:
- Server 2: `193.233.228.23:9661`
- Server 3: `185.103.200.141:63897`
- Server 4: `72.56.59.61:63132`

Server 1 does NOT proxy Google -- only YouTube and `play.google.com`.

### 4. Dormant C2 / Remote Proxy Configuration (TRUE POSITIVE -- MEDIUM severity, currently dormant)

**File:** `deobfuscated/background.js` -- `loadThirdServer` function

A complete but never-called function fetches configuration from GitHub, collects device fingerprint data, and retrieves proxy instructions from a remote API:

```javascript
const loadThirdServer = () => {
    // Generates UUID device_id
    // Fetches config from GitHub: https://raw.githubusercontent.com/vpn-naruzhu/public/main/uboost-extension
    // Extracts apiBaseUrl (currently "uubb.website")
    // Gets user's real IP from https://api.ipify.org?format=json
    // POSTs to https://${apiBaseUrl}/api/v1/get-proxy with:
    //   { device_id: "uuid", device_ip: "user's real IP" }
    // Receives { host, port } and sets proxy accordingly
};
```

The remote config at the GitHub URL is live and returns:
```json
{
    "apiBaseUrl": "uubb.website",
    "currentVersion": "6.2.1",
    "requiredVersion": "6.2.1",
    "supportedBrowsers": ["chrome", "edge-chromium", "yandexbrowser"],
    "proxyUpdatePeriod": 50,
    "proxyUpdatePeriodPremium": 50
}
```

This represents a fully functional remote code/config loading mechanism that:
- Sends the user's real IP address to a third-party server
- Generates and stores a persistent device identifier (UUID)
- Allows the server operator to dynamically control which proxy the user connects through
- Could be activated in a future update without any code changes to the extension (just by wiring `loadThirdServer` into the call chain)

### 5. Massive Russian Domain Blocklist Routing (INFORMATIONAL)

**File:** `deobfuscated/background.js` -- server4 config

Server 4 ("Server 4 (additional)" in the UI) contains approximately 265,000 blocked domain names organized by domain level (levels 1-34). When a visited domain matches the blocklist, traffic is routed through `PROXY 72.56.59.61:63132`. This appears to be a Russia-specific censorship circumvention list, routing blocked websites through the proxy.

This is the reason `background.js` is 9.2MB -- the domain blocklist accounts for nearly all of the file size.

### 6. User IP Collection (TRUE POSITIVE -- LOW severity, currently dormant)

**File:** `deobfuscated/background.js` -- inside `loadThirdServer`

```javascript
fetch("https://api.ipify.org?format=json").then((r => r.json())).then((r => {
    o(r.ip)
}))
```

The user's real public IP is fetched and then sent to the operator's server along with a device UUID. This is currently dormant.

### 7. Uninstall Tracking URL

**File:** `deobfuscated/background.js`

```javascript
const UNINSTALL_URL = "https://gemera-vpn.com/?ref_code=ytboost";
chrome.runtime.setUninstallURL(UNINSTALL_URL);
```

On uninstall, users are redirected to gemera-vpn.com with a referral code. This is a common (low-risk) marketing practice.

### 8. Install Welcome Page

**File:** `deobfuscated/background.js`

```javascript
chrome.runtime.onInstalled.addListener((function(r) {
    "install" === r.reason && chrome.tabs.create({
        url: "https://swaponline.notion.site/YouTube-Booster-11c91437ef0a801e8ec2caacc33f64fe"
    })
}));
```

Opens a Notion page on first install. Low risk.

## Network Map

### Hardcoded Proxy Servers
| Server Config | Proxy IP:Port | Routes |
|---|---|---|
| server1 | `92.255.105.69:57331` | YouTube, googlevideo, ytimg, ggpht |
| server1 | `45.12.142.143:64322` | play.google.com only |
| server2 | `193.233.228.23:9661` | YouTube + Google + streaming services (7tv, BetterTTV, FrankerFaceZ, Discord CDN) |
| server3 | `185.103.200.141:63897` | YouTube + Google + streaming services |
| server4 | `185.103.200.141:63897` | YouTube + streaming services |
| server4 | `72.56.59.61:63132` | ~265K blocked Russian domains + Gemini |

### External Endpoints
| URL | Purpose | Status |
|---|---|---|
| `https://raw.githubusercontent.com/vpn-naruzhu/public/main/uboost-extension` | Remote config (C2) | **Dormant** -- defined but never called |
| `https://api.ipify.org?format=json` | Real IP collection | **Dormant** -- inside dormant function |
| `https://${apiBaseUrl}/api/v1/get-proxy` (currently `uubb.website`) | Dynamic proxy assignment | **Dormant** -- inside dormant function |
| `https://gemera-vpn.com/?ref_code=ytboost` | Uninstall redirect | **Active** |
| `https://swaponline.notion.site/YouTube-Booster-11c91437ef0a801e8ec2caacc33f64fe` | Install welcome page | **Active** |
| `https://t.me/gemera_vpn_bot?start=ytboost` | GEMERA VPN Telegram bot (ad link) | **Active** (injected into YouTube pages) |
| `https://t.me/youtube_vpn_support` | Support contact (in popup) | **Active** |
| `https://forms.gle/t779oNyQqQtb6eMs8` | Feedback form (in popup) | **Active** |
| `https://chromewebstore.google.com/detail/epkcfhiniijndongcpclcfogmbpphfga/reviews` | CWS review page (in popup) | **Active** |

### Associated Domains
| Domain | Relationship |
|---|---|
| `uubb.website` | Dynamic API base URL from remote config |
| `uboost.space` | Proxied domain (in YouTube services list) |
| `uboost.tube` | Proxied domain (in YouTube services list) |
| `gemera-vpn.com` | Marketing/uninstall redirect |
| `vpn-naruzhu` (GitHub user) | Hosts remote config file |

## Permissions Analysis

| Permission | Declared | Used | Assessment |
|---|---|---|---|
| `proxy` | Yes | Yes | Core functionality -- sets PAC script proxy configs |
| `storage` | Yes | Yes | Stores connection state, server selection, device ID |
| `host_permissions: https://www.youtube.com/*` | Yes | Yes | Content script injection on YouTube |

The permissions are minimal and appropriate for the stated functionality. No over-privileged permissions (no `tabs`, `management`, `cookies`, `webRequest`, etc.).

## What the Extension Does NOT Do

- **No extension enumeration or killing** -- No `chrome.management` API usage whatsoever
- **No credential harvesting** -- No form monitoring, no keylogging, no `keydown`/`keypress` listeners
- **No cookie theft** -- No `chrome.cookies` or `document.cookie` access
- **No XHR/fetch monkey-patching** -- The `history.pushState` patch is for SPA navigation detection only, not for intercepting network requests
- **No dynamic code execution** -- No `eval()`, `new Function()`, `importScripts()` with remote code
- **No browser fingerprinting** -- No canvas, WebGL, AudioContext, or navigator property collection
- **No search result manipulation** -- Google Search results are not modified, only proxied
- **No tab/browsing history access** -- Only queries active tab to check if it's YouTube for reload
- **No remote code loading** -- The dormant C2 function only retrieves proxy host:port, not executable code
- **No encrypted/obfuscated communication** -- All endpoints use plain HTTPS with JSON payloads

## Final Verdict

**Risk Level: MEDIUM**

StreamTube Proxy is a YouTube unblocking proxy extension with legitimate core functionality but several concerning behaviors:

1. **Ad injection** into YouTube pages promoting a separate Telegram VPN service (GEMERA VPN) -- this is undisclosed monetization injected into user-facing web pages.

2. **Google Search traffic routing** through third-party proxy servers on 3 of 4 server configs -- this creates a man-in-the-middle position where the proxy operator can potentially observe search queries and results.

3. **Dormant C2 infrastructure** with a live remote config endpoint that could be activated in a future update to dynamically control proxy routing and collect user device IDs + real IP addresses. The GitHub-hosted config file at `vpn-naruzhu/public` is actively maintained and returns current data.

4. **All proxy servers are unidentified third-party infrastructure** -- users have no visibility into who operates `92.255.105.69`, `193.233.228.23`, `185.103.200.141`, or `72.56.59.61`, or what logging/interception they perform.

The extension is not outright malicious in its current form -- it does not steal credentials, enumerate extensions, or execute remote code. However, the combination of Google Search traffic interception, ad injection, and a staged C2 mechanism that could be trivially activated represents meaningful risk to the ~70,000 users. The primarily Russian-language UI and Russia-focused domain blocklist suggest this targets users in Russia seeking to bypass internet censorship, a demographic particularly vulnerable to proxy-based surveillance.
