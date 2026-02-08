# Vulnerability Report: Safehouse VPN & Security

## Extension Metadata

| Field | Value |
|-------|-------|
| **Extension ID** | ppbmlefhgoananjpjenjhoihhaohnmol |
| **Name** | Safehouse VPN & Security |
| **Internal Name** | Bodyguard |
| **Version** | 3.3.0 |
| **Author** | Safehouse Tech |
| **User Count** | ~3,000 |
| **Build Framework** | Plasmo + Parcel (React) |
| **Analysis Date** | 2026-02-08 |

---

## Executive Summary

**OVERALL RISK: LOW**

Safehouse VPN & Security is a **legitimate commercial VPN and security extension** developed by Safehouse Tech, an Indian cybersecurity startup. The extension provides VPN proxy services, ad/tracker blocking via declarativeNetRequest, tab performance optimization, site permission auditing, data breach monitoring, and privacy controls (Safe Browsing, Do Not Track).

The codebase is built with the Plasmo framework and bundled with Parcel. It is **not obfuscated** and follows standard React development patterns. All backend communication is directed exclusively to `api.safehousetech.com` with standard Mixpanel analytics for product telemetry.

Despite broad permissions (`<all_urls>`, proxy, webRequest, privacy, contentSettings, system.cpu/memory), **all capabilities map directly to documented, user-facing features**. No evidence of malicious behavior was found:
- No credential harvesting
- No cookie theft
- No keylogging
- No data exfiltration
- No DOM injection
- No extension enumeration/killing
- No obfuscation or dynamic code loading

One minor implementation bug was identified (proxy disconnection listener removal) that could cause temporary navigation blocking, but this is not a security vulnerability.

---

## Vulnerability Details

### No Critical, High, or Medium Vulnerabilities Identified

After comprehensive analysis of all scripts (background, content, popup, options), manifest permissions, API calls, and network communication patterns, **no exploitable vulnerabilities or malicious behaviors were found**.

---

## False Positive Analysis

The extension likely triggers multiple automated security flags due to its broad permissions and API usage. All flags are **false positives**:

| Category | Detection Pattern | Verdict | Explanation |
|----------|------------------|---------|-------------|
| **Broad Permissions** | `<all_urls>` host permissions + content scripts on all URLs | FALSE POSITIVE | Required for VPN proxy (intercept all traffic) and ad-blocking (content script scans for third-party trackers). Standard for VPN/ad-blocker extensions. |
| **Cookie Harvesting** | No detection - extension does NOT access cookies | N/A | No `chrome.cookies` API calls, no `document.cookie` references. |
| **Document Write** | React innerHTML in UI components | FALSE POSITIVE | Standard React DOM manipulation (`dangerouslySetInnerHTML` for SVG rendering). No injection into web pages. |
| **Dynamic Eval** | setTimeout/setInterval in UI libraries | FALSE POSITIVE | From bundled date-fns, React, and Mixpanel SDK. No `eval()` or `new Function()` with dynamic content. |
| **Dynamic Function** | React synthetic events | FALSE POSITIVE | Part of React's event system in popup/options UI. |
| **Dynamic Import** | Parcel module loader | FALSE POSITIVE | Standard Parcel bundler runtime. No dynamic remote code loading. |
| **Fetch Hooking** | No detection - extension does NOT hook fetch | N/A | No monkey-patching of `window.fetch` or `XMLHttpRequest`. Uses standard fetch for backend API calls. |
| **Keylogging** | Keyboard event listeners in options page | FALSE POSITIVE | Keyboard events are from React synthetic event system and Mixpanel OTP paste handling. Content script has NO keyboard listeners. |
| **Privacy APIs** | `chrome.privacy.*` and `chrome.contentSettings.*` | FALSE POSITIVE | Used for user-facing features: Safe Browsing toggle, Do Not Track toggle, Permission Control dashboard. |
| **System APIs** | `chrome.system.cpu.getInfo()`, `chrome.system.memory.getInfo()` | FALSE POSITIVE | Powers "Performance Plus" feature showing CPU/memory optimization stats. Data stored locally, NOT sent to server. |
| **WebRequest Blocking** | `chrome.webRequest.onAuthRequired` and `onBeforeRequest` with blocking | FALSE POSITIVE | `onAuthRequired`: Provides proxy credentials. `onBeforeRequest`: Temporarily blocks navigation for 1 second during proxy disconnection to prevent unproxied traffic. |
| **DeclarativeNetRequest** | Dynamic rule manipulation | FALSE POSITIVE | Implements ad-blocking ("Active Defence") with user-configurable domain block/whitelist. |
| **Tab Management** | `chrome.tabs.discard()` | FALSE POSITIVE | Core to "Performance Plus" tab hibernation feature (discards inactive tabs after configurable timeout). |

---

## API Endpoints

All backend communication is directed to a single domain: `api.safehousetech.com`

### Authentication & User Management
- `POST /api/v1/auth/web/login/sendOtp` - Send OTP for login
- `POST /api/v1/auth/web/login/validateOtp` - Validate OTP and authenticate
- `GET /api/v1/auth/token/refresh` - Refresh expired auth token
- `POST /api/v1/auth/sendOTP` - Send OTP (for cyber insurance)
- `POST /api/v1/auth/validateOTP` - Validate OTP
- `POST /api/v1/auth/logout` - User logout
- `POST /api/v1/user/update` - Update user profile

### VPN Proxy
- `GET /api/v1/proxy/region` - Fetch available proxy server regions
- `POST /api/v1/proxy/fetchServer` - Get assigned proxy server details (IP, port, credentials)
- `GET /api/v1/proxy/disconnect` - Release proxy server
- `GET /api/v1/proxy/updateLastUsed` - Keep proxy session alive (prevents auto-disconnect)

### Licensing & Subscription
- `GET /api/v1/license` - Fetch user licenses
- `POST /api/v1/license/select/{hash}` - Select license
- `POST /api/v1/license/validate` - Validate license
- `POST /api/v1/license/attach/{hash}` - Attach license to account
- `GET /api/v1/plan/details` - Subscription plan details
- `GET /api/v1/plan/isRecurring` - Check if plan auto-renews
- `POST /api/v1/plan/cancel` - Cancel subscription

### Additional Features
- `GET /api/v1/breach?email=` - Data breach monitoring check
- `POST /api/v1/insurance/acknowledge` - Acknowledge cyber insurance (HDFC ERGO, India-specific)
- `GET /api/v1/insurance/policy` - Fetch insurance policy details

### Third-Party Analytics
- `api-js.mixpanel.com` - Mixpanel product analytics (feature usage tracking)
- `cdn.mxpnl.com` - Mixpanel CDN (SDK resources)

**Authentication:** Bearer token + refresh token pattern. Tokens stored in `chrome.storage.local`. Standard 401 retry-with-refresh flow.

---

## Data Flow Summary

### Inbound Data (from backend to extension)
- **Proxy server credentials** (IP, port, username, password) - ephemeral, not persisted
- **Auth tokens** (JWT) - stored in chrome.storage.local
- **Proxy regions** - displayed in UI for user selection
- **User profile** (email, name, license status) - stored locally
- **Breach scan results** - displayed in dashboard
- **License/subscription details** - displayed in dashboard
- **Cyber insurance policy** (India-specific) - displayed in dashboard

### Outbound Data (from extension to backend)
- **Authentication requests** (email, OTP code)
- **Proxy session management** (region selection, keep-alive pings)
- **User profile updates** (email, name changes)
- **License management** (activation, validation)
- **Breach monitoring queries** (email address for breach check)
- **Subscription operations** (plan selection, cancellation)

### Outbound Analytics (to Mixpanel)
- **Product events** (VPN connect/disconnect with region, feature activation/deactivation, login success, purchase initiation)
- **User identification** (email, name for Mixpanel people profiles)
- **NO browsing data** - Mixpanel does NOT receive URLs visited, page content, or user behavior on websites

### Local Data Storage (chrome.storage.local)
- Auth token, refresh token
- User email, name
- VPN connection status, selected region, inactivity timeout
- Active Defence stats (blocked URL counts, whitelisted domains, blocked domain rules)
- Performance Plus stats (tab discard counts, CPU/memory measurements, whitelisted domains)
- Permission Control audit results (cached per-site permissions)
- Data breach scan results
- Web protection feature toggles (Active Defence, Performance Plus, Link Protection, Do Not Track)

### Data NOT Collected
- Browsing history (URLs visited)
- Page content or DOM structure
- Form data or credentials
- Cookies
- Keyboard input or clipboard content
- Social media data
- Search queries
- File system access

---

## Code Behavior Analysis

### Manifest Permissions Justification

| Permission | Purpose | Evidence |
|------------|---------|----------|
| `proxy` | VPN proxy configuration via PAC script | `background.d5306455.js:5353` - `chrome.proxy.settings.set()` |
| `tabs` | Tab management for Performance Plus, blocked site navigation | `background.d5306455.js:1223-1238`, `5887-5897` |
| `unlimitedStorage`, `storage` | Local stats, settings, auth tokens | Throughout codebase - `chrome.storage.local` |
| `privacy` | Safe Browsing and Do Not Track toggles | `background.d5306455.js:1244-1252` |
| `contentSettings` | Permission Control dashboard (camera/mic/location audit) | `options.33a2637a.js:75055-75081` |
| `declarativeNetRequest*` | Ad/tracker blocking, tracking parameter stripping | `background.d5306455.js:1138-1209`, `5857-5976` |
| `contextMenus` | Right-click menu integration (block site, whitelist domain, discard tab) | `background.d5306455.js:5849-5866` |
| `system.cpu`, `system.memory` | Hardware monitoring for Performance Plus optimization stats | `background.d5306455.js:5559-5604` |
| `webRequest`, `webRequestAuthProvider` | Proxy authentication and disconnect protection | `background.d5306455.js:5291-5306`, `5395-5426` |
| `<all_urls>` (host) | Required for proxy to intercept all traffic, ad-blocker to scan all pages | Manifest requirement for VPN/ad-blocker |
| `<all_urls>` (content scripts) | Content script scans third-party scripts for ad/tracker detection | `content.2b4bf174.js:183-211` |

### Background Script Key Functions

**Proxy Management** (`background.d5306455.js:5270-5431`):
- `generatePACScript()` (line 5307) - Creates PAC script with `PROXY` or `HTTPS` mode, bypasses `api.safehousetech.com`
- `enableProxy()` (line 5350) - Sets proxy via `chrome.proxy.settings.set()`
- `disableProxy()` (line 5381) - Resets proxy to direct, clears credentials
- `authHandler()` (line 5291) - Provides proxy credentials via `onAuthRequired`
- Auto-disconnect after 12 minutes of inactivity (configurable, line 216-217)

**Ad Blocking** (`background.d5306455.js:327-351`):
- Content script sends detected third-party script URLs
- Background counts blocked URLs, stores stats locally
- Dynamic rules created for user-blocked domains via `chrome.declarativeNetRequest.updateDynamicRules()`
- Static rulesets (adv.json, adv-filter-list.json, susp.json) contain thousands of ad/tracker domains

**Tab Optimization** (`background.d5306455.js:5436-5604`):
- Attaches discard timers to inactive tabs after 10 min (default)
- Checks: not pinned, not audible, not discarded, not active, not whitelisted
- Static whitelist: teams.microsoft.com, meet.google.com, zoom.us, youtube.com
- Measures CPU/memory before/after discard for optimization stats
- All measurements stored locally, NOT sent to server

**Privacy Controls** (`background.d5306455.js:1244-1252`):
- `updateSafeBrowsing(enabled)` - Toggles `chrome.privacy.services.safeBrowsingEnabled`
- `updateDoNotTrack(enabled)` - Toggles `chrome.privacy.websites.doNotTrackEnabled`
- Both are user-facing dashboard toggles

### Content Script Behavior

**File:** `content.2b4bf174.js` (362 lines)

**Purpose:** Passive scanner for third-party scripts (ad/tracker detection)

**Behavior:**
1. On page load, collects all `<script>` tags
2. Filters out same-domain scripts and known safe libraries (bootstrap, jsdelivr, jquery, cloudfront, recaptcha)
3. Remaining third-party script URLs sent to background as "blocked URLs" for stats
4. If no third-party scripts found, defaults to counting Google Analytics URL (artificially inflates count)
5. Sends `PERFORMANCE_PLUS` message on window load (triggers tab discard timer)
6. Sends `UPDATE_CONTEXT_MENU` message on mousedown (refreshes right-click menu state)

**What it does NOT do:**
- No DOM modification
- No script blocking (blocking is done via declarativeNetRequest in background)
- No keylogging
- No form scraping
- No XHR/fetch interception
- No cookie access
- No password detection
- No ad/content injection

### UI Components (Popup & Options)

**Popup:** React UI for VPN toggle, region selection, Active Defence stats
**Options:** Full dashboard with charts (CPU/memory graphs, blocked URL stats, permission audit, breach monitoring, cyber insurance)

Both include Mixpanel SDK for product analytics:
- Token: `3d8273733bc3aba779e5defd83dace03` (public client token)
- Tracked events: VPN connect/disconnect, feature toggles, login, license events
- Session recording: DISABLED (`record_sessions_percent: 0`)
- Data sent: Feature usage only, NO browsing behavior

---

## Security Strengths

1. **No obfuscation** - Standard Parcel bundle, fully readable code
2. **Strict CSP** - `script-src 'self'; object-src 'self';` prevents remote code execution
3. **Single backend domain** - All API calls go to `api.safehousetech.com`, no suspicious third-party endpoints
4. **No chrome.cookies access** - Extension does not touch cookies
5. **No extension enumeration** - No `chrome.management` API usage
6. **No credential harvesting** - No form scraping, password detection, or keylogging
7. **Content script isolation** - Content script only reads script tags, does not modify DOM
8. **Local-only system monitoring** - CPU/memory stats stored locally, not sent to server
9. **User-controlled features** - All invasive permissions (privacy, contentSettings) map to user-facing dashboard controls
10. **Standard auth flow** - Bearer token + refresh token with 401 retry, tokens in storage.local

---

## Identified Issues

### Issue 1: Proxy Disconnection Listener Removal Bug (Non-Security)

**Severity:** Low (Implementation Bug)
**File:** `background.d5306455.js:5395-5410`
**Verdict:** NOT EXPLOITABLE

**Description:**
When the proxy disconnects unexpectedly, the extension attempts to block all main_frame navigation for 1 second to prevent unproxied traffic leakage. However, the listener removal uses an anonymous function reference that does not match the originally registered listener:

```javascript
chrome.webRequest.onBeforeRequest.addListener(() => ({
    cancel: true
}), { urls: ["<all_urls>"], types: ["main_frame"] }, ["blocking"]);

setTimeout(() => {
    chrome.webRequest.onBeforeRequest.removeListener(() => {}); // Bug: new function reference
}, 1000);
```

**Impact:**
The blocking listener is never removed, which could cause all navigation to be permanently blocked until the service worker restarts or the user reloads the extension.

**Mitigation:**
Service worker lifecycle in Manifest V3 causes periodic restarts, which would clear the stuck listener. Users can also disable/re-enable the extension. This is a quality-of-service bug, not a security vulnerability.

**Recommendation:**
Define the listener as a named function and pass the same reference to `removeListener()`.

---

### Issue 2: Artificial Ad Block Count Inflation (Non-Security)

**Severity:** Low (Marketing Misrepresentation)
**File:** `content.2b4bf174.js:201-202`
**Verdict:** NOT MALICIOUS

**Description:**
If the content script detects no third-party scripts on a page, it defaults to counting `www.google-analytics.com/analytics.js` as a "blocked URL":

```javascript
if (blockedUrls.size === 0 && !currentUrl.includes(LocalHosts.LOCAL_HOST) && !currentUrl.includes(LocalHosts.LOCAL_127))
    blockedUrls.add(GA_URL);
```

**Impact:**
The "Active Defence" blocked count is artificially inflated for marketing purposes. This does not represent actual blocking (blocking is done via declarativeNetRequest rulesets, not the content script).

**Recommendation:**
Remove the fallback GA URL addition or clearly document it as an estimated count rather than actual blocked requests.

---

## Overall Risk Assessment

| Risk Category | Level | Justification |
|--------------|-------|---------------|
| **Data Exfiltration** | CLEAN | No evidence of sensitive data collection or transmission beyond standard auth/analytics |
| **Credential Theft** | CLEAN | No form scraping, password detection, or credential harvesting |
| **Malicious Code** | CLEAN | No obfuscation, no dynamic code loading, no suspicious patterns |
| **Privacy Invasion** | LOW | Broad permissions justified by features; Mixpanel analytics limited to product events |
| **User Harm** | CLEAN | One non-security bug (listener removal) could cause temporary navigation blocking |
| **Extension Conflicts** | CLEAN | No extension enumeration or killing behavior |

**FINAL RISK: LOW**

This is a legitimate commercial VPN and security extension. All triage flags are false positives. The only issues identified are a minor implementation bug and marketing count inflation, neither of which pose security risks to users.

---

## Conclusion

Safehouse VPN & Security (ppbmlefhgoananjpjenjhoihhaohnmol) is a **legitimate, commercially-developed browser extension** providing VPN, ad-blocking, tab optimization, and privacy auditing features. The extension was built using the Plasmo framework with standard React patterns and is not obfuscated.

Despite broad permissions that typically indicate high risk, **every permission maps directly to documented, user-facing functionality**. Comprehensive analysis of background scripts, content scripts, and UI components revealed:

- **No malicious behavior**
- **No data exfiltration**
- **No credential harvesting**
- **No keylogging**
- **No cookie theft**
- **No DOM injection**
- **No extension enumeration/killing**

All backend communication goes exclusively to `api.safehousetech.com`. Product analytics via Mixpanel track only feature usage events, not browsing behavior. System monitoring (CPU/memory) is stored locally and never transmitted.

The extension provides genuine value to users through VPN proxy, comprehensive ad/tracker blocking (4.7MB domain blocklist), URL tracking parameter stripping, tab memory optimization, site permission auditing, data breach monitoring, and privacy control toggles.

**Recommendation:** This extension is safe for continued use. The identified bugs (proxy listener removal, ad count inflation) should be reported to the developer but do not pose security threats to users.
