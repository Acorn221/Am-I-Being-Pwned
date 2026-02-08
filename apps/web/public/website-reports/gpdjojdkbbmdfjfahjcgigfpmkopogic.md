# Save to Pinterest (gpdjojdkbbmdfjfahjcgigfpmkopogic) - Vulnerability Report

## Extension Overview
| Field | Value |
|-------|-------|
| Name | Save to Pinterest |
| ID | gpdjojdkbbmdfjfahjcgigfpmkopogic |
| Version | 6.12.0 |
| Manifest | V3 |
| Users | ~6M |
| Publisher | Pinterest (official) |
| Triage | SUSPECT (1 T1, 0 T2, 2 V1, 1 V2) |

## Permissions
- `contextMenus` -- right-click "Save image" menu
- `cookies` -- reads `.pinterest.com` cookies
- `storage` -- local extension state
- `activeTab` -- access to current tab on click
- `declarativeNetRequest` -- modifies request headers and redirect rules
- `host_permissions`: `*://*/*`, `<all_urls>` -- full host access

## Architecture
| Component | File | Size |
|-----------|------|------|
| Service Worker | `backgroundScript.js` | 78KB |
| Content Script | `contentScript.js` | 146KB (runs on all `*://*/*`) |
| Sidebar/Popup UI | `bundle.js` (loaded in injected iframe via `index.html`) | 1.4MB |
| DNR Rules | `assets/rules.json` | Static User-Agent header for API calls |

---

## Flag Analysis

### FLAG 1: cookie_access (T1) -- TRUE POSITIVE (Low Severity)

**Location:** `backgroundScript.js` lines 1197-1204 (function `Ze`)

```javascript
function Ze() {
    const e = yield T.cookies.getAll({
        domain: me  // ".pinterest.com"
    }), s = e.find(a => a.name === "_auth"), r = s?.value,
       t = e.find(a => a.name === "_pinterest_sess"), o = t?.value;
    return { authCookieValue: r, sessionCookieValue: o }
}
```

**Analysis:**
- The extension reads cookies exclusively from `.pinterest.com` domain.
- It reads exactly two cookies: `_auth` (boolean auth flag) and `_pinterest_sess` (session cookie).
- The session cookie value is SHA-512 hashed before being used as an anti-forgery token (`X-Request-Forgery-Token` header).
- Cookie access is scoped to Pinterest's own domain only. No third-party cookie reading.

**Content script cookie access:** In `contentScript.js` line 1266, the function `dt` reads `document.cookie` but only on the Pinterest OAuth page (`help.pinterest.com/en/save-extension/oauth-access-token`) to extract `access_token` and `state` for the OAuth flow. This is gated by the `na()` check.

**Verdict:** TRUE POSITIVE for the flag, but the behavior is legitimate. The extension only reads Pinterest's own first-party cookies to authenticate API requests. The session cookie is hashed before use.

---

### FLAG 2: postmessage_no_origin (V1) -- TWO INSTANCES, MIXED VERDICT

#### Instance 1: Content Script -> Iframe postMessage (contentScript.js line 1256)

```javascript
lt = ({ element: e, action: t, payload: n }) => {
    e.postMessage({
        target: Ae,  // "pinterest-save-extension"
        action: t,
        payload: n
    }, "*")
};
```

**Analysis:**
- Sends messages from the content script to the extension's own injected iframe (`index.html`).
- Uses `"*"` as the target origin instead of the extension's own origin.
- The iframe is created by the extension itself (line 3593-3594: `l.src = $.runtime.getURL("/index.html")`).
- The data sent includes: board info, image URLs, page URLs, descriptions, and funnel IDs.

**Risk Assessment:** LOW. While `"*"` is used, the iframe is created by the extension itself and loaded from the extension's own resources (chrome-extension:// URL). A malicious page cannot inject content into this iframe due to same-origin policy on the extension origin. However, using `"*"` is still a defense-in-depth violation.

#### Instance 2: Background Script postMessage (backgroundScript.js line 1916)

```javascript
Ir = ({ element: e, action: s, payload: r }) => {
    e.postMessage({
        target: PINTEREST_SAVE_EXTENSION_ID,
        action: s,
        payload: r
    }, "*")
};
```

**Analysis:** Same pattern as Instance 1 but in the background script context. This function appears to be dead code in the background service worker (service workers don't have DOM elements to postMessage to).

#### Instance 3: Grid overlay postMessage (contentScript.js line 1825)

```javascript
r.contentWindow?.postMessage(JSON.stringify(t.data), r.src)
```

**Analysis:** This posts to an iframe loaded from `https://assets.pinterest.com/ext/grid.html`. The target origin IS set to `r.src` (the iframe's actual URL), which is correct. However, the message listener on line 1825 does NOT check origin:

```javascript
e.addEventListener("message", d => {
    window.clearTimeout(m), d.data === "x" && c()
})
```

**Risk:** VERY LOW. The listener only responds to `d.data === "x"` which simply closes/removes the grid overlay. An attacker could trigger the overlay to close, but cannot inject data.

#### Instance 4: Bundle.js receiver (bundle.js line 35186)

```javascript
const i = l => {
    const { target: d, action: u, payload: f } = l.data || {};
    if (d === Ht) {  // checks target === "pinterest-save-extension"
```

**Analysis:** The bundle.js message listener does NOT check `event.origin`. It only checks that `data.target === "pinterest-save-extension"`. A malicious page that knows this constant string could craft a postMessage to the extension's iframe. However:
- The iframe runs within the extension's own origin (`chrome-extension://...`).
- The iframe is injected by the content script as a child of the page's DOM.
- A page script CAN send postMessages to this iframe since it's in the same DOM tree.
- The payload could include spoofed board IDs, image URLs, etc.

**Exploitability:** LOW-MEDIUM. An attacker could potentially:
1. Send `MOUNT_SIDEBAR_APP` with spoofed `thumb` array containing attacker-controlled image URLs.
2. Send `MOUNT_SAVEPICKER_APP` with spoofed board data.
However, actual pin creation requires authenticated API calls to Pinterest, which go through the background script. The attacker cannot forge the user's Pinterest session.

**Verdict:** TRUE POSITIVE. The `"*"` target origin and missing origin check on the receiver side represent a defense-in-depth weakness. Practical exploitability is low because the critical operations (pin creation, auth) are mediated through the background script's authenticated API layer.

---

### FLAG 3: dynamic_window_open (V2) -- TRUE POSITIVE (Low Severity)

**Location:** `bundle.js` line 8515

```javascript
Je = ({ url: n, name: a }) => {
    ...
    return window.open(n, a, b)
};
```

**Usage contexts:**
- Line 32435: Opens user's Pinterest profile page
- Line 34241: Opens a Pinterest pin page after creation
- Line 34493: Opens Pinterest logout URL
- Line 34616: Opens Pinterest OAuth login URL

**Analysis:** All `window.open` calls are to `pinterest.com` domains with hardcoded URL patterns. The `url` parameter is constructed from known Pinterest API endpoints and user data. No user-supplied or externally-controlled URLs flow into `window.open`.

**Verdict:** TRUE POSITIVE for the flag, but FALSE POSITIVE for actual vulnerability. All opened URLs are Pinterest-controlled.

---

## Privacy Analysis

### Data Collection

#### 1. Page URL Collection
The extension collects the current page URL in several contexts:
- **When the user actively pins:** URL is sent to Pinterest's API as `source_url` (truncated to 2048 chars).
- **In telemetry events:** `url: document.URL` is included in click/view log events sent to `trk.pinterest.com`.
- **Canonical URL extraction:** Reads `<link rel="canonical">` from the page.

**Passive collection:** The content script does NOT send URLs to Pinterest when the user is not interacting with it. URL data is only collected when:
- The user clicks the toolbar button
- The user hovers over the save button and the save picker opens
- The user right-clicks to save an image

#### 2. Image Scraping
When activated, the content script scrapes:
- All `<img>` tags on the page
- CSS background images
- YouTube/Instagram embed iframes
- OpenGraph meta images
- Structured data (ld+json) for GTIN product codes
- Image dimensions, alt text, data-pin attributes

This scraping only occurs when the user initiates a save action. It is NOT passive.

#### 3. Conversion Tracking (beuid parameter) -- PRIVACY CONCERN

**Location:** `backgroundScript.js` lines 2179-2212 (function `ms`)

```javascript
ms = () => {
    const { user: { id: e, country: s,
        ads_customize_from_conversion: r,
        personalize_from_offsite_browsing: t
    } } = S();
    e && r && t && s && !ce.includes(s) ?
        T.declarativeNetRequest.updateSessionRules({
            addRules: [{
                id: 1002,
                action: {
                    type: "redirect",
                    redirect: {
                        transform: {
                            queryTransform: {
                                addOrReplaceParams: [{
                                    key: "beuid",
                                    value: e  // Pinterest user ID
                                }]
                            }
                        }
                    }
                },
                condition: {
                    urlFilter: "*://ct.pinterest.com/*"
                }
            }]
        }) : T.declarativeNetRequest.updateSessionRules({
            removeRuleIds: [1002]
        })
};
```

**This function runs on EVERY tab activation and window focus change** (line 2297):
```javascript
T.tabs.onActivated.addListener(ms)
T.windows.onFocusChanged.addListener(ms)
```

**What it does:**
- When the user has opted into both `ads_customize_from_conversion` AND `personalize_from_offsite_browsing` in their Pinterest account settings, AND the user is NOT in an EU/EEA country (checked against `ce` list of country codes), the extension adds a declarativeNetRequest rule that appends the user's Pinterest ID (`beuid` parameter) to ALL requests to `ct.pinterest.com`.
- `ct.pinterest.com` is Pinterest's conversion tracking pixel domain. Websites that have Pinterest conversion tags embedded will trigger requests to this domain.
- This means when a user visits a website with a Pinterest conversion pixel, their Pinterest user ID is appended to the tracking request, allowing Pinterest to correlate the user's browsing on third-party sites with their Pinterest account.

**Privacy implications:**
- This is a form of cross-site tracking. Even though it respects the user's Pinterest account preferences, the behavior occurs silently and is not clearly disclosed in the extension's description.
- EU/EEA users are excluded (GDPR compliance), but non-EU users are tracked by default if their Pinterest settings allow it.
- The rule is dynamically updated on every tab switch, so it is always active.
- The `beuid` parameter links the user's identity across all websites that have Pinterest tracking pixels.

#### 4. Telemetry / Event Logging

Events are batched and sent to `trk.pinterest.com/v3/callback/event/` via POST. Events include:
- Extension install/update events
- Pin creation attempts (success/failure)
- UI interactions (button clicks, view events)
- Page URLs where actions were taken
- Browser type and extension version
- User ID or anonymous `unauthId`

The logging system batches up to 20 events before flushing, with a 60-second timeout.

#### 5. No Third-Party Analytics
The extension does NOT include any third-party analytics SDKs (no Google Analytics, Facebook Pixel, Hotjar, etc.). All telemetry goes exclusively to Pinterest's own infrastructure.

### Domains Contacted
- `api.pinterest.com` -- API requests (pin creation, boards, user data)
- `trk.pinterest.com` -- Event logging / telemetry
- `ct.pinterest.com` -- Conversion tracking (via declarativeNetRequest rule, not direct requests)
- `www.pinterest.com` -- Uninstall URL, OAuth flow
- `assets.pinterest.com` -- Grid overlay iframe (legacy path)

---

## Security Assessment

### Vulnerability Summary

| ID | Finding | Severity | Type |
|----|---------|----------|------|
| V-01 | postMessage without origin check in bundle.js receiver | LOW-MED | Defense-in-depth weakness |
| V-02 | postMessage with `"*"` target origin to iframe | LOW | Defense-in-depth weakness |
| V-03 | Grid overlay message listener has no origin check | VERY LOW | Defense-in-depth weakness |
| V-04 | Cross-site user tracking via `beuid` parameter | MEDIUM | Privacy concern |

### V-01: postMessage Receiver Without Origin Check (bundle.js)

The sidebar/popup UI running in `index.html` (within a `chrome-extension://` iframe) listens for `message` events without verifying the sender's origin:

```javascript
const i = l => {
    const { target: d, action: u, payload: f } = l.data || {};
    if (d === Ht) {  // only checks target string
        switch (u) {
            case Y.MOUNT_SAVEPICKER_APP: { ... }
            case Y.MOUNT_SIDEBAR_APP: { ... }
        }
    }
};
window.addEventListener("message", i);
```

A malicious page could send:
```javascript
document.querySelector('iframe[src*="chrome-extension"]')
    .contentWindow.postMessage({
        target: "pinterest-save-extension",
        action: 1, // MOUNT_SIDEBAR_APP
        payload: { /* spoofed data */ }
    }, "*");
```

**Mitigation:** The iframe's origin is `chrome-extension://gpdjojdkbbmdfjfahjcgigfpmkopogic`, and web pages cannot access its contentWindow due to cross-origin restrictions. However, a page could still use `postMessage` to the iframe since it's embedded in the page's DOM. The practical impact is limited because:
1. The spoofed data would only affect the UI display.
2. Actual API calls go through `chrome.runtime.sendMessage` to the background script.
3. Authentication state cannot be manipulated this way.

### V-04: Cross-Site Conversion Tracking

The `beuid` tracking is the most significant privacy finding. It:
- Runs on every tab activation (not just when the user pins something)
- Appends the user's Pinterest ID to third-party conversion tracking pixels
- Enables Pinterest to build a browsing profile across all websites with their tracking pixel
- Is gated by Pinterest account settings but users may not understand the implications
- Excludes EU users (GDPR compliance) but not users in other privacy-conscious jurisdictions

---

## Banned Domain / No-Pin System

The extension maintains two lists for restricting functionality:
1. **Disallowed domains** (`M` variable, contentScript.js line 942): Blocks pinning from email services (Gmail, Yahoo Mail, Outlook, etc.), Google Docs, financial sites (Chase), and Google accounts pages.
2. **Hashed banned domains** (`P` variable, contentScript.js line 943): 24 SHA-1 hashed domain patterns that prevent pinning. These domains are obfuscated, presumably for legal/policy reasons.
3. **Password stripping** (line 3105-3114): URLs are sanitized to remove query parameters matching `/password/gi` before being processed.

---

## Overall Risk Assessment

**Risk Rating: LOW**

This is a legitimate first-party extension from Pinterest with no malicious behavior. Key findings:

1. **Cookie access is appropriate** -- only reads Pinterest's own authentication cookies.
2. **No passive browsing surveillance** -- data collection only occurs during user-initiated pin actions.
3. **postMessage handling has minor defense-in-depth gaps** -- no practical exploit path due to extension origin isolation.
4. **The `beuid` conversion tracking is the primary privacy concern** -- enables cross-site user tracking via Pinterest's conversion pixel network, though it respects user account preferences and GDPR.
5. **No third-party analytics or tracking SDKs** are present.
6. **All network communication goes to Pinterest-owned domains**.
7. **The extension does NOT enumerate or disable other extensions** (unlike many VPN/privacy extensions we've analyzed).

### Recommendations
- The postMessage handlers should verify `event.origin` against the extension's own origin for defense-in-depth.
- The `beuid` conversion tracking behavior should be more prominently disclosed to users.
- The `"*"` target origin in `postMessage` calls should be replaced with the specific extension origin.
