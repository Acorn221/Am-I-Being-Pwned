# Zoom Chrome Extension (kgjfgplpablkjnlkjmjdecgdpfankdle) - Vulnerability Report

**Extension:** Zoom Chrome Extension
**Version:** 1.9.10
**Users:** ~8 million
**MV3:** Yes
**Triage Classification:** SUSPECT (2 T1, 0 T2, 6 V1, 7 V2)
**Overall Risk Assessment:** LOW-MEDIUM (well-defended extension with some residual attack surface)

---

## 1. Extension Architecture

### Manifest Permissions
- `storage`, `unlimitedStorage`
- Host permissions: `https://www.google.com/calendar/*`, `https://calendar.google.com/calendar/*`, `https://*.zoom.us/*`, `https://*.zoom.com/*`
- CSP allows scripts from `*.google.com` and `*.zoom.us` -- notably permissive but scoped to first-party domains.

### Components
| Component | File(s) | Runs On |
|-----------|---------|---------|
| Service Worker | `bg-loader.js` -> `lib.bundle.js`, `utils.bundle.js`, `background.bundle.js` | Background |
| Content Script (main) | `lib.bundle.js`, `utils.bundle.js`, `content.bundle.js` | Google Calendar (all_frames) |
| Content Script (login) | `logintransit.bundle.js` | `*.zoom.us/zm/extension_login/*`, `*.zoom.com/zm/extension_login/*` |
| Content Script (install check) | `extinstallcheck.bundle.js` | `*.zoom.us/myhome*`, `*.zoom.com/myhome*` |
| Injected Script | `injectobserver.bundle.js` | Google Calendar (page context, web_accessible_resources) |
| Popup | `popup.html` + `popup.bundle.js` | Extension popup |
| Options | `options.html` + `options.bundle.js` | Extension options page |

### Key Libraries
- **jQuery** (in `lib.bundle.js`) - used extensively for DOM manipulation
- **DOMPurify** (in `lib.bundle.js`) - used for HTML sanitization via `safeHTML()` wrapper

---

## 2. Triage Flag Analysis

### T1 Flags

#### T1-1: `script_injection` -- TRUE POSITIVE (Benign by Design)
**Location:** `content.bundle.js` line 63-68
```javascript
i.loadObserver = function() {
    let t = document.createElement("script");
    t.src = chrome.runtime.getURL("js/injectobserver.bundle.js");
    t.onload = function() { this.remove() };
    (document.head || document.documentElement).appendChild(t);
}
```
**Analysis:** The content script injects `injectobserver.bundle.js` into the Google Calendar page context. This is a standard pattern for extensions that need to intercept page-level APIs (in this case, XHR). The injected script is a static extension resource, not dynamically constructed. The script is listed in `web_accessible_resources`.

**Purpose:** The injected observer hooks `XMLHttpRequest.open` and `XMLHttpRequest.send` on Google Calendar to intercept calendar sync requests (`sync.sync`, `event`, `deleteevent`). It reads calendar event data from Google's internal API responses to detect when Zoom meetings are created, edited, or deleted, then relays this info via `window.postMessage` back to the content script.

**Risk:** LOW. The injected script is a static, bundled resource. However, because it is listed in `web_accessible_resources` with `matches: ["<all_urls>"]`, any page can load this script (see Finding V-1 below).

#### T1-2: `innerhtml_dynamic` -- MIXED (Some True Positive, Mostly Mitigated)

Multiple instances of `innerHTML` assignment exist in `content.bundle.js`. The key ones:

**a) Description node manipulation (lines 611, 621, 635, 1247, 1982):**
```javascript
o[0].innerHTML = n;
o[0].dispatchEvent(new Event("paste"));
```
These write to Google Calendar's event description field. The content comes from a mix of extension-generated HTML (separators, Zoom links) and existing Google Calendar DOM content. The data flow is: read from Calendar DOM -> add Zoom meeting info -> write back. This operates within the same-origin Google Calendar page. Data is escaped via `f()` (which is `escapeHtml`/`textContent` encoding).

**Risk:** LOW. Data flows within the same origin and is largely extension-controlled.

**b) Phone number linkification (line 3523):**
```javascript
e = e.replace(n[t], '<a href="tel:' + n[t] + '">' + n[t] + "</a>");
t(this).html(e);
```
Reads existing Google Calendar event description HTML, finds phone number patterns (`\+[0-9][0-9 ]+[0-9]`), wraps them in `<a href="tel:...">` tags, and writes back via jQuery `.html()`. The phone number regex is strict (digits and spaces only), so injection through this path is not feasible.

**Risk:** NEGLIGIBLE.

### V1 Flags

#### V1-1: `postmessage_no_origin` -- FALSE POSITIVE (All Listeners Check Origin)

There are **three** `window.addEventListener("message", ...)` handlers in the content script. Every single one validates the origin:

**Handler 1 (line 14):** Main calendar event relay
```javascript
"https://calendar.google.com" === n.origin && (...)
```
Strict origin check. Only processes messages from Google Calendar's own origin.

**Handler 2 (line 1378-1380):** Whiteboard iframe communication
```javascript
"zmCalMessage" === t.data?.type && t.origin === dt && (...)
```
Checks origin against `dt`, which is set via `Zt()` -> `Yt()` -> `safeHTML(t, [])` (DOMPurify-sanitized). The `dt` variable is populated from the Zoom whiteboard URL base, so it resolves to the user's Zoom domain (e.g., `https://zoom.us`).

**Handler 3 (line 1698-1699):** Workspace iframe communication
```javascript
t.origin === ne.webDomain && (...)
```
Checks origin against `ne.webDomain`, which comes from the background script's workspace data (ultimately from Zoom's API response -- a Zoom domain).

**Verdict:** All three postMessage listeners properly validate origin. This is a FALSE POSITIVE for the "no origin check" flag.

#### V1-2 through V1-6: `dynamic_tab_url` (5 instances) -- TRUE POSITIVE (Low Risk)

**Instance 1: `openUrl` handler (background.bundle.js line 312-316)**
```javascript
if ("openUrl" == e.type) {
    let t = e.url;
    return t && chrome.tabs.create({ url: t }), {}
}
```
This accepts a URL from `chrome.runtime.onMessage` (internal extension messaging only) and opens it in a new tab with NO URL validation. However, `chrome.runtime.onMessage` can only be triggered by the extension's own content scripts and popup/options pages, not by web pages. The content scripts only run on Google Calendar and Zoom domains.

**Attack surface:** A compromised Google Calendar page or Zoom page could send `{type: "openUrl", url: "javascript:..."}` via `chrome.runtime.sendMessage()`. However, in MV3, `chrome.tabs.create` does NOT support `javascript:` URLs. An attacker could at most open an arbitrary `https://` URL. This is also reachable via the long-running port connection's `viewTemplateDetail` handler, which constructs URLs from `templateId` -- but the URL is constructed with a hardcoded base URL from `getUserBaseUrl()` (a Zoom domain).

**Risk:** LOW. The URL is gated behind internal messaging. No URL validation, but the attack surface is limited to Zoom/Calendar pages injecting arbitrary navigation.

**Instance 2: `getAdminTemplateDetailUrl` (background.bundle.js line 600-606)**
```javascript
let t = await o.A.getAdminTemplateDetailUrl(e);
chrome.tabs.create({ url: t })
```
The URL is constructed as: `getUserBaseUrl() + "meeting#/template/list?templateId=${e}"`. The `templateId` comes from the content script port message. The base URL is always a Zoom domain. The `templateId` is interpolated into a fragment identifier, limiting injection potential.

**Risk:** LOW.

**Instances 3-5: Popup/Options navigation**
Various `chrome.tabs.create` calls using `getUserBaseUrl()` + hardcoded paths (e.g., `"profile"`, `"launch/clips"`, `"signin?from=extension"`). All base URLs come from stored Zoom configuration data.

**Risk:** NEGLIGIBLE.

#### V1-7: `dynamic_window_open` -- TRUE POSITIVE (Low Risk)

Six `window.open()` calls in `content.bundle.js`:

**Most notable (line 2866, 3513):**
```javascript
let n = t.$lastClickedBtn.attr("data-url");
n && window.open(n, "_blank")
```
The `data-url` attribute is set by the extension itself (line 2880):
```javascript
vn("#zoom-video-sec #zoom_join_meeting_button").attr("data-url", t)
```
where `t` comes from `addParamsToUrl(o.url, {jst: e})` -- the `o.url` is a Zoom meeting join URL from the extension's own API response. The URL is processed through `encodeURI()` as a fallback.

**Other instances (lines 4048, 4629, 5875):**
```javascript
window.open(t(this).attr("href"))
```
These open `href` attributes from links the extension itself has created in Google Calendar's DOM (e.g., Zoom meeting links, open source page links). All are within the Google Calendar content script context.

**Line 6147:**
```javascript
n && window.open(n)
```
Opens a Zoom profile settings URL constructed from `getUserBaseUrl()`.

**Risk:** LOW. All URLs are extension-controlled or derived from Zoom API responses.

### V2 Flags

#### V2-1: `jquery_html_dynamic` -- MIXED (Mostly Mitigated, One Concern)

The extension uses jQuery `.html()` extensively. Key patterns:

**a) DOMPurify-sanitized content:** Most dynamic content flows through `safeHTML()` which wraps DOMPurify. Examples:
- `showToast()` uses `c.safeHTML(e, ["b", "br", "p"])` before `.html()`
- Tooltip content uses `et()` -> `X.safeHTML(t)` or `nt()` -> `X.safeHTML(t, [])`
- The `$()` function in options.bundle.js is `r.safeHTML(e, [])` (strip all tags)

**b) Workspace conflict tips (content.bundle.js line 1721-1724):**
```javascript
let e = t.selfCheckMessageList || [];
if (e.length) {
    let t = e.join("<br>");
    n.addClass("show").attr("info", t),
    n[0].zoomTooltip && n[0].zoomTooltip.updatePopupContent(t)
}
```
The `selfCheckMessageList` comes from a `postMessage` from Zoom's workspace iframe. While the `postMessage` handler at line 1698 does check `t.origin === ne.webDomain`, this specific data path flows from the iframe's `zrWorkspaceRoomCheckResult` message type through to tooltip content. The `updatePopupContent` function calls `et(t)` or `nt(t)` depending on `isText`, both of which go through `safeHTML()` (DOMPurify). However, line 1724 passes the raw joined string directly, which is then stored as an `info` attribute and later rendered via the tooltip system which DOES sanitize.

BUT: The `attr("info", t)` call at line 1724 stores unsanitized data in a DOM attribute. When the tooltip is later created from this attribute (line 1887), it reads `t.attr("info")` and passes it to the tooltip constructor, where `content: t.attr("info")` flows to `et(t.content)` -> `safeHTML()`. So it IS sanitized before DOM insertion.

**c) Options page PAC toll numbers (options.bundle.js line 122):**
```javascript
s.each(o.toll_numbers, function(e, t) {
    i.append("<label>" + $(t) + "</label>")
})
```
The `$()` function here is `r.safeHTML(e, [])` -- full DOMPurify sanitization with no allowed tags. Server-controlled data but sanitized.

**Risk:** LOW. DOMPurify is consistently applied.

---

## 3. Identified Vulnerabilities

### V-1: Web-Accessible Injected Observer Script (Informational/Low)

**File:** `manifest.json` -> `web_accessible_resources`
```json
"web_accessible_resources": [{
    "resources": ["images/loading_24.gif", ..., "js/injectobserver.bundle.js"],
    "matches": ["<all_urls>"]
}]
```

The `injectobserver.bundle.js` is accessible to ALL URLs. This script:
1. Hooks `window.XMLHttpRequest` with a monkey-patched version
2. Intercepts `open()` and `send()` calls
3. Parses Google Calendar API responses
4. Posts results via `window.postMessage` to `https://calendar.google.com`

**Impact:** Any webpage could load `chrome-extension://kgjfgplpablkjnlkjmjdecgdpfankdle/js/injectobserver.bundle.js` as a `<script>` tag. On that page, the script would:
- Overwrite `XMLHttpRequest` with a wrapper that logs/inspects requests
- Look for DOM elements like `#zoom-quick2adv-number`, `#zoom-whiteboard-record`
- Post messages to `https://calendar.google.com`

In practice, the impact is **negligible** because:
- The script only parses Google Calendar-specific API formats (`sync.sync`, `event`, `deleteevent`)
- It posts messages to a hardcoded `https://calendar.google.com` origin, which a malicious page cannot receive
- The XHR interception only reads, never modifies data (except for injecting Zoom meeting descriptions, which requires specific DOM elements to exist)

However, the XHR monkey-patching could theoretically cause side effects on the page that loads it. The `matches: ["<all_urls>"]` should be narrowed to `calendar.google.com`.

**Severity:** LOW (Informational)
**CVSS:** 2.0
**Recommendation:** Restrict `web_accessible_resources` matches to `["https://calendar.google.com/*"]`.

### V-2: Login Transit DOM-Read Without Sanitization

**File:** `logintransit.bundle.js`
```javascript
let e = "", o = document.querySelector("#zm_web_domain") || document.querySelector("#zm_domain_url");
o && (e = o.value || "");
chrome.runtime.sendMessage({type: "passZoomExtLoginSession", info: {url: e}});
```

**File:** `background.bundle.js` (line 197-204)
```javascript
if ("passZoomExtLoginSession" == e.type) {
    let a = t?.tab?.id;
    try {
        await o.A._ssologin(e.info.url), u(a), ...
```

**File:** `utils.bundle.js` (line 3098-3100)
```javascript
_ssologin: async function(e) {
    var t = e + "/" + d.loginUrl;
    return e || (t = await r.A.getUserBaseUrl() + d.loginUrl), await d._login(t)
}
```

The `logintransit.bundle.js` content script runs on `https://*.zoom.us/zm/extension_login/*` and `https://*.zoom.com/zm/extension_login/*`. It reads a DOM element's value (`#zm_web_domain` or `#zm_domain_url`) and sends it to the background script as a URL that is then used to construct an API endpoint for SSO login.

**Attack Scenario:** If an attacker can control the `#zm_web_domain` input value on a Zoom login transit page (e.g., via DOM manipulation on a compromised Zoom subdomain, or by crafting a page at a matching URL pattern), they could inject an arbitrary URL. The `_ssologin` function constructs: `attacker_url + "/" + loginUrl` and makes a POST request to it with `{ext_version, snstype, accesstoken}`.

**Mitigating factors:**
- The content script only runs on `*.zoom.us` and `*.zoom.com` domains (not arbitrary pages)
- An attacker would need to control content on a Zoom subdomain
- The POST body contains an empty `accesstoken` field (the login is cookie-based)
- MV3's service worker does not have access to cookies directly

**Severity:** LOW
**CVSS:** 2.5
**Recommendation:** Validate the URL read from the DOM against an allowlist of Zoom domains before sending to the background script.

### V-3: `openUrl` Message Handler -- Unrestricted URL Navigation

**File:** `background.bundle.js` (line 312-316)
```javascript
if ("openUrl" == e.type) {
    let t = e.url;
    return t && chrome.tabs.create({ url: t }), {}
}
```

Any content script or internal extension page can send `{type: "openUrl", url: "..."}` to the background, which opens it unconditionally. While this is restricted to internal extension messaging (only content scripts on calendar.google.com and *.zoom.us/*.zoom.com can call it), there is no URL validation.

**Attack Scenario:** If XSS is achieved on Google Calendar or a Zoom page (the domains where content scripts run), the attacker could call:
```javascript
chrome.runtime.sendMessage({type: "openUrl", url: "https://evil.com/phishing"})
```
This would open the phishing page in a new tab with no user interaction beyond whatever triggered the XSS.

**Mitigating factors:**
- Requires pre-existing XSS on Google Calendar or Zoom -- both high-security targets
- MV3's `chrome.tabs.create` rejects `javascript:` and `data:` URLs
- The tab opens with no special permissions

**Severity:** LOW
**CVSS:** 3.0
**Recommendation:** Validate URLs against a Zoom/Google domain allowlist before opening.

### V-4: Extension Install Check Leaks Version to Zoom Pages

**File:** `extinstallcheck.bundle.js`
```javascript
let e = document.createElement("div");
e.id = "zoom-extension-installed-dom-mark";
e.style.display = "none";
e.setAttribute("version", chrome.runtime.getManifest().version);
document.body.appendChild(e);
```

On any `*.zoom.us/myhome*` or `*.zoom.com/myhome*` page, the extension creates a hidden DOM element that exposes the exact extension version. This enables version fingerprinting.

**Impact:** A Zoom page (or any script running on it) can detect the extension's presence and exact version, enabling targeted attacks against known vulnerabilities in specific versions.

**Severity:** INFORMATIONAL
**CVSS:** 1.5

### V-5: onMessageExternal Exposes Version to Any Extension

**File:** `background.bundle.js` (line 691-695)
```javascript
chrome.runtime.onMessageExternal.addListener(function(e, t, a) {
    return e && e.message && "version" == e.message && a({
        version: 1
    }), !0
});
```

Any other Chrome extension can send a message to this extension and receive a version response. This enables cross-extension fingerprinting.

**Mitigating factors:**
- The response is a hardcoded `{version: 1}` (not the actual manifest version)
- No sender validation, but no sensitive data is returned
- Returns `true` (keeps the message channel open) even for unrecognized messages, but this only affects the response callback lifecycle

**Severity:** INFORMATIONAL
**CVSS:** 1.0

### V-6: XHR Monkey-Patching in Page Context (Injected Observer)

**File:** `injectobserver.bundle.js` (lines 1-525)

The injected observer completely replaces `window.XMLHttpRequest` with a wrapper that:
1. Intercepts every `open()` call, storing the URL path in `this._path`
2. Intercepts every `send()` call, reading and potentially modifying the request body
3. Hooks `readystatechange` to parse responses from specific API endpoints

The `send()` hook modifies outgoing request bodies in certain conditions:
```javascript
// Lines 464-519: Modifies sync.sync and event request bodies
n.send = function(e) {
    if ("sync.sync" === this._path && ...) {
        // Reads #zoom-quick-desc and #zoom-quick-location DOM elements
        // Injects their content into the Google Calendar sync request body
    }
    // ...
}
```

**Impact:** This is the mechanism by which the extension adds Zoom meeting details (description, location) to Google Calendar events. The modification is intentional and scoped. However, the complete XHR replacement in the page context means:
- All XHR requests on Google Calendar are routed through extension code
- If the extension has a bug in its response parsing, it could corrupt data
- The response handler uses `JSON.parse` on response data without try/catch in some branches (though most are wrapped)

**Severity:** LOW (by design, but increases attack surface)

---

## 4. Data Handling Assessment

### Meeting Data
- **Meeting credentials** (passwords, tokens): Stored in `chrome.storage.local`. Passwords are handled via DOMPurify-sanitized input fields. The `remoteCheckPassword` function sends passwords to Zoom's server for validation -- they are not stored in plaintext long-term (only the PMI saved password is cached).
- **Meeting IDs and join URLs**: Extracted from Google Calendar events and Zoom API responses. These are written into Calendar event descriptions via innerHTML but are extension-controlled strings.
- **User email**: Stored in Zoom's config data in `chrome.storage.local`. Displayed in the popup via `.text()` (not `.html()`), so no XSS risk there.

### Authentication Tokens
- **ZAK token** (`_zm_zak`): Primary authentication token stored in `chrome.storage.local`. Used in API requests as a header/body parameter. Properly scoped to Zoom API calls only.
- **SSO session**: Handled via the login transit content script. Session cookies are used implicitly via fetch/XHR to Zoom domains.

### Sensitive Operations
- Meeting scheduling, editing, deletion -- all require valid ZAK token
- Whiteboard access and workspace management -- token-gated
- No recording data, chat data, or participant PII is handled by this extension. It is purely a scheduling extension that reads/writes Google Calendar events.

---

## 5. External Communication Assessment

### Can a Malicious Page Communicate with the Extension?

**Direct messaging:** NO. `chrome.runtime.sendMessage()` from web pages requires `externally_connectable` to be declared in the manifest, which it is NOT. The `onMessageExternal` handler only responds to other extensions, not web pages.

**postMessage:** PARTIALLY. A malicious page could `window.postMessage()` to a Google Calendar tab where the extension's content script is running. However, all three `postMessage` listeners validate the origin (`https://calendar.google.com`, Zoom whiteboard domain, or Zoom workspace domain). A malicious page in a different origin cannot pass these checks.

**Injected script communication:** The `injectobserver.bundle.js` runs in the page context of Google Calendar. It reads DOM elements and XHR data. A malicious script on Google Calendar could plant DOM elements with crafted data (e.g., `#zoom-quick2adv-number`, `#zoom-quick-desc`) that would be picked up by the observer. However, achieving script execution on Google Calendar is extremely difficult.

**Content script on Zoom pages:** The `logintransit.bundle.js` reads DOM values on `*.zoom.us/zm/extension_login/*`. A compromised Zoom subdomain could provide malicious values.

### Can the Extension Be Used as a Pivot?

The extension has limited value as a pivot point:
- No `<all_urls>` content script injection
- No `webRequest` / `declarativeNetRequest` permissions
- No `tabs` permission (cannot enumerate tabs/URLs)
- No `cookies` permission
- Scoped to Google Calendar and Zoom domains only

---

## 6. Summary of Findings

| ID | Finding | Severity | True/False Positive |
|----|---------|----------|-------------------|
| T1-1 | Script injection (injectobserver.bundle.js) | By design | TRUE POSITIVE (benign) |
| T1-2 | innerHTML with dynamic content | Mitigated | TRUE POSITIVE (low risk) |
| V1-1 | postMessage without origin check | N/A | FALSE POSITIVE (all check origin) |
| V1-2-6 | Dynamic tab URLs (5 instances) | Low | TRUE POSITIVE (internal only) |
| V1-7 | Dynamic window.open | Low | TRUE POSITIVE (extension-controlled) |
| V2-1 | jQuery .html() with dynamic content | Mitigated | TRUE POSITIVE (DOMPurify used) |
| V-1 | web_accessible_resources too broad | Low | NEW FINDING |
| V-2 | Login transit reads DOM without URL validation | Low | NEW FINDING |
| V-3 | openUrl handler has no URL allowlist | Low | NEW FINDING |
| V-4 | Version fingerprinting via DOM marker | Informational | NEW FINDING |
| V-5 | onMessageExternal version disclosure | Informational | NEW FINDING |
| V-6 | Full XHR monkey-patch in page context | Low (by design) | NEW FINDING |

---

## 7. Conclusion

The Zoom Chrome Extension is a **well-engineered, security-conscious extension** with no evidence of malicious behavior. Key positive security practices:

1. **DOMPurify integration**: All user-facing dynamic HTML content is sanitized through DOMPurify (`safeHTML()` wrapper). This is consistently applied across content scripts, options, and popup.
2. **postMessage origin validation**: All three `window.addEventListener("message", ...)` handlers properly check `event.origin` before processing data.
3. **Minimal permissions**: MV3, no `<all_urls>`, no `tabs`, no `cookies`, no `webRequest`. Host permissions are strictly scoped to Google Calendar and Zoom.
4. **Token-gated operations**: All sensitive API operations check `hasZoomRqToken()` before proceeding.
5. **No data exfiltration**: No telemetry to third parties, no analytics beyond Zoom's own logging endpoint.

The identified vulnerabilities are all **low severity** and would require pre-existing compromise of Google Calendar or Zoom domains to exploit. The most actionable recommendations are:

1. Restrict `web_accessible_resources` to Google Calendar URLs only
2. Add URL validation in the `openUrl` message handler
3. Validate the DOM-read URL in `logintransit.bundle.js` against Zoom domain patterns

**This extension is NOT malware. It is a legitimate, well-defended Zoom scheduling tool.**
