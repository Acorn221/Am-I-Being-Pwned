# Free Download Manager (FDM) Browser Extension - Vulnerability Report

**Extension ID:** ahmpjcflkgiildlgicmcieglgoilbfdp
**Version:** 3.2.4
**Manifest Version:** 3
**Users:** ~3,000,000
**Author:** FreeDownloadManager.ORG
**Homepage:** https://www.freedownloadmanager.org

---

## Executive Summary

Free Download Manager's browser extension is a download interception tool that routes browser downloads to the FDM desktop application via native messaging. The code is **not malicious** -- it contains no obfuscation, no telemetry, no analytics, no affiliate injection, and no data exfiltration. However, the extension carries **significant vulnerability surface** due to its architecture: it intercepts ALL web traffic via webRequest on `<all_urls>`, communicates with an unsandboxed native application, and allows remote self-uninstallation. Given FDM's documented 2023 supply chain compromise (their Linux package was trojaned for 3+ years), the native messaging bridge represents an especially critical attack vector.

**Overall Risk: MEDIUM-HIGH (Vulnerability surface, not malicious intent)**

---

## Triage Flag Analysis

### V1: CSP unsafe-eval + unsafe-inline (Sandbox Policy)
**Verdict: TRUE POSITIVE -- but MITIGATED by scope**

The manifest declares:
```json
"content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self';",
    "sandbox": "sandbox allow-scripts allow-forms allow-popups allow-modals; script-src 'self' 'unsafe-inline' 'unsafe-eval'; child-src 'self';"
}
```

**Analysis:**
- The `extension_pages` CSP is properly locked down: `script-src 'self'; object-src 'self'` -- no unsafe-eval, no unsafe-inline.
- The `unsafe-eval` and `unsafe-inline` appear ONLY in the `sandbox` policy.
- **However, there are NO sandbox pages in the extension.** The only two HTML files are `settings.html` and `install.html`, both loaded as normal extension pages (popup and window respectively), not sandboxed iframes.
- The sandbox CSP is a dead declaration -- vestigial configuration that has no effect.

**Risk:** LOW. The sandbox CSP is unused. The actual extension pages CSP is secure. This flag is effectively a **false positive in practice** since no sandbox pages exist to exploit it.

### V1: CSP unsafe-inline (Same as above)
**Verdict: TRUE POSITIVE -- but MITIGATED (same reasoning)**

See above. The `unsafe-inline` is only in the sandbox CSP, which applies to zero pages.

### V2: webRequest on `<all_urls>`
**Verdict: TRUE POSITIVE -- Significant attack surface**

The extension registers **multiple** webRequest listeners on `<all_urls>`:

1. **DownloadsInterceptManager** (download interception):
   - `onBeforeSendHeaders` -- reads request headers, can modify Referer header
   - `onBeforeRequest` -- reads request URLs, POST bodies, document URLs
   - `onSendHeaders` -- captures request headers including cookies
   - `onHeadersReceived` -- reads response headers (content-type, content-disposition, content-length)

2. **NetworkRequestsMonitor** (video sniffing for native app):
   - `onSendHeaders` -- captures ALL request headers from all tab requests
   - `onResponseStarted` -- captures ALL response headers from all tab requests

3. **FdmSchemeHandler**:
   - `onBeforeRequest` -- scans ALL URLs for `fdmguid=6d36f5b5519148d69647a983ebd677fc` magic parameter

**What traffic is intercepted:**
- The download interceptor monitors ALL requests but only acts on those matching download criteria (content-disposition, application/* content-type, file extensions).
- The NetworkRequestsMonitor captures ALL HTTP request/response headers from tab-originated requests and **forwards them to the native application** via the native messaging port.
- This means every HTTP request's full headers (including cookies, authorization tokens, etc.) are sent to the FDM desktop application.

**Risk:** HIGH. Even though the data only goes to the local native application, a compromised FDM installation (see supply chain context) would have access to all HTTP headers from all browsing.

---

## Detailed Architecture Analysis

### Component Map

| Component | File | Role |
|-----------|------|------|
| Service Worker | `dist/js/service_worker.js` | Bundled background (all modules concatenated) |
| Content Script 1 | `src/js/webextension.js` | Browser API polyfill (benign, 35 lines) |
| Content Script 2 | `src/js/fdmschemecatch.js` | Catches `fdm:` scheme links (benign, 8 lines) |
| Content Script 3 | `src/js/youtubeutils.js` | YouTube channel/playlist URL detection (benign) |
| Content Script 4 | `src/js/contextmenuhlpr.js` | Selection monitoring for context menus |
| Popup | `src/html/settings.html` | Settings popup (skip list, pause) |
| Install Page | `src/html/install.html` | First-run prompt to install FDM desktop app |

### Permissions Analysis

| Permission | Used For | Concern Level |
|------------|----------|---------------|
| `cookies` | Reads cookies for download URLs to pass to FDM app | MEDIUM -- cookies for ANY URL sent to native app |
| `webRequest` | Download interception + network monitoring | HIGH -- sees all traffic |
| `declarativeNetRequest` | Dynamic blocking rules (mostly commented out) | LOW |
| `downloads` | Intercept and cancel browser downloads, redirect to FDM | LOW -- core functionality |
| `nativeMessaging` | Communication with FDM desktop application | HIGH -- bridge to unsandboxed code |
| `contextMenus` | "Download with FDM" context menus | LOW |
| `activeTab` | Script injection for "Download All" functionality | LOW |
| `storage` | Settings persistence | LOW |
| `history` | Checks recent history during install to detect CWS origin | LOW |
| `tabs` | Tab URL tracking for video detection | MEDIUM |
| `notifications` | Download failure notifications | LOW |
| `alarms` | Timer management | LOW |
| `scripting` | Inject scripts to collect all links on page ("Download All") | LOW -- user-initiated only |
| `host_permissions: <all_urls>` | Required for webRequest on all URLs | HIGH |

---

## Vulnerability Details

### VULN-01: Native Messaging Bridge -- Full HTTP Header Exfiltration to Local App (HIGH)

**File:** `src/js/netwrkmon.js` (NetworkRequestsMonitor) + `src/js/fdmnetwrkmon.js`

The `NetworkRequestsMonitor` captures ALL HTTP request/response headers from every tab-originated request and forwards them to the FDM native application:

```javascript
// netwrkmon.js lines 9-12
browser.webRequest.onSendHeaders.addListener(
    this.onSendHeaders.bind(this),
    { urls: ["<all_urls>"] },
    ["requestHeaders"]);
```

```javascript
// fdmnetwrkmon.js lines 45-60
FdmNetworkRequestsMonitor.prototype.onGotHeaders = function (
    requestId, url, requestMethod, requestHeaders,
    responseStatusLine, responseHeaders)
{
    var task = new FdmBhNetworkRequestResponseNotification;
    var rqh = requestMethod + " " + PathFromUrl(url) + " HTTP/1.1\r\n";
    rqh += HttpHeadersToString(requestHeaders) + "\r\n";
    var rsh = responseStatusLine + "\r\n" +
        HttpHeadersToString(responseHeaders) + "\r\n";
    task.setInfo(requestId, url, rqh, rsh);
    this.nhManager.postMessage(task);  // Sent to native app
}
```

**Impact:** Every HTTP request/response header pair (including Cookie, Authorization, Set-Cookie headers) is serialized and sent to the FDM desktop application. If the desktop application is compromised (as happened in 2023), this is a full browsing session exfiltration channel.

### VULN-02: Cookie Extraction for Any URL (MEDIUM)

**File:** `src/js/cookiemgr.js`

```javascript
CookieManager.prototype.getCookiesForUrls = function(urls, callback)
{
    for (var i = 0; i < urls.length; ++i)
    {
        browser.cookies.getAll(
            { 'url': urls[i], 'partitionKey': {} },
            function (resultIndex, cookies) {
                var cookiesString = cookies.map(function (cookie) {
                    return cookie.name + "=" + cookie.value + ";";
                }).join(' ');
                // ...
            });
    }
}
```

Cookies for download URLs are extracted and sent to the native application alongside the download request. This is necessary for authenticated downloads but means cookie values transit through the native messaging channel.

### VULN-03: Remote Self-Uninstall via externally_connectable (MEDIUM)

**File:** `src/js/main.js`

```javascript
browser.runtime.onMessageExternal.addListener(function (request, sender, sendResponse)
{
    if (sender.url.toLowerCase().indexOf("https://files2.freedownloadmanager.org") == -1)
        return;
    if (request == "uninstall")
    {
        browser.management.uninstallSelf();
    }
});
```

Combined with `externally_connectable` in manifest:
```json
"externally_connectable": {
    "matches": ["*://*.freedownloadmanager.org/*"]
}
```

**Impact:** Any page on `*.freedownloadmanager.org` can send messages to the extension. A page on `files2.freedownloadmanager.org` can trigger self-uninstallation. If freedownloadmanager.org is compromised (which has precedent), an attacker could silently remove the extension from all 3M users.

**Note:** The origin check uses `indexOf`, which means `https://files2.freedownloadmanager.org.evil.com` would NOT bypass it (the `.` prevents subdomain spoofing), but any XSS on `files2.freedownloadmanager.org` would suffice.

### VULN-04: Magic GUID URL Interception (LOW-MEDIUM)

**File:** `src/js/fdmscheme.js`

```javascript
FdmSchemeHandler.prototype.onBeforeRequest = function (details)
{
    if (details.url.indexOf("fdmguid=6d36f5b5519148d69647a983ebd677fc") != -1)
    {
        this.sendUrlToFdm(details.url);
        return { redirectUrl: "javascript:" };
    }
};
```

Any URL containing the hardcoded GUID parameter `fdmguid=6d36f5b5519148d69647a983ebd677fc` is intercepted and sent to the native FDM application. This is a known trigger mechanism for FDM website integration. The GUID acts as a shared secret, but it is hardcoded and publicly visible. Any website that includes this parameter can trigger a download in FDM.

### VULN-05: innerHTML with i18n Messages (LOW)

**File:** `src/js/i18n-helper.js`

```javascript
if (message.includes('<')) {
    element.innerHTML = message;
}
```

Localization messages containing `<` are injected via `innerHTML`. The messages come from `_locales/*/messages.json`, which are extension-bundled files. The `settings_update_message` message contains an `<a>` tag linking to freedownloadmanager.org. This is safe as long as the localization files are not tampered with, but in a supply chain attack scenario, a modified `messages.json` could inject arbitrary HTML/script into the settings popup (which has the secure CSP, so scripts would be blocked -- but HTML/CSS injection is still possible).

### VULN-06: POST Data Capture (MEDIUM)

**File:** `src/js/dldsinterceptmgr.js`

```javascript
if (details.method == "POST")
{
    requestDetails.postData = "&";
    if (undefined != details.requestBody && undefined != details.requestBody.formData)
    {
        for (var field in details.requestBody.formData)
        {
            requestDetails.postData += field + "=" +
                    encodeURIComponent(details.requestBody.formData[field][i]) + "&";
        }
    }
}
```

POST form data is captured for download interception. When a download is triggered via POST, the form data is serialized and sent to the native application. This could include sensitive form fields if the POST triggers a file download.

---

## Supply Chain Analysis

### 2023 FDM Supply Chain Compromise Context

In 2023, the FDM Linux download page (freedownloadmanager.org) was compromised to serve a trojaned Debian package that installed a Bash stealer and reverse shell. The compromise persisted for over 3 years (2020-2023). This is directly relevant because:

1. **The extension communicates with the FDM desktop application** -- if the desktop app is trojaned, it receives all data the extension sends (full HTTP headers, cookies, download URLs, POST data).

2. **The extension checks freedownloadmanager.org for installation** -- the install page links to `https://freedownloadmanager.org/download.htm?from=gh`.

3. **The extension's externally_connectable trusts *.freedownloadmanager.org** -- a compromised website could control the extension.

### No Evidence of Extension Compromise

After thorough static analysis:
- **No obfuscated code** -- all source is readable and well-commented
- **No eval(), Function(), atob(), or dynamic code execution** in any JS file
- **No external fetch/XHR calls** -- the extension makes zero HTTP requests to any server
- **No analytics, telemetry, or beacon endpoints**
- **No affiliate injection or URL modification**
- **No encoded/encrypted payloads**
- **No suspicious domains** -- only references are to freedownloadmanager.org, youtube.com, and google.com
- **No data exfiltration** beyond the native messaging channel to the local FDM app
- **Code structure is clean** -- clear function names, consistent patterns, no minified/packed sections

The extension itself is NOT compromised. The risk is in the architecture.

---

## Risk Summary

| ID | Finding | Severity | Type |
|----|---------|----------|------|
| VULN-01 | All HTTP headers forwarded to native app | HIGH | Architecture vulnerability |
| VULN-02 | Cookie extraction for download URLs | MEDIUM | Architecture vulnerability |
| VULN-03 | Remote self-uninstall from FDM domains | MEDIUM | Trust boundary issue |
| VULN-04 | Hardcoded magic GUID for URL interception | LOW-MEDIUM | Weak authentication |
| VULN-05 | innerHTML with i18n messages | LOW | Potential injection vector |
| VULN-06 | POST form data capture | MEDIUM | Data exposure to native app |
| CSP-01 | sandbox CSP with unsafe-eval/inline | LOW | Unused/vestigial config |

---

## Triage Flag Summary

| Flag | Description | Verdict | Notes |
|------|-------------|---------|-------|
| V1 | csp_unsafe_eval | TRUE POSITIVE (mitigated) | Only in unused sandbox CSP; extension pages CSP is secure |
| V1 | csp_unsafe_inline | TRUE POSITIVE (mitigated) | Same as above -- sandbox CSP applies to zero pages |
| V2 | webrequest_all_urls | TRUE POSITIVE | Multiple listeners on all URLs; full header forwarding to native app |

---

## Key Conclusions

1. **Not malicious.** The extension contains no malware, no data theft, no affiliate fraud, and no obfuscated payloads. It is a legitimate download manager integration.

2. **Significant attack surface through native messaging.** The combination of `<all_urls>` webRequest monitoring + native messaging creates a pipeline where ALL HTTP traffic metadata flows to an unsandboxed desktop application. The security of 3M users' browsing data depends entirely on the integrity of the FDM desktop application.

3. **Supply chain risk is the primary concern.** Given FDM's documented 2023 supply chain compromise on their Linux packages, the same attack vector could be used against the desktop app that receives data from this extension. A trojaned FDM desktop app would gain access to:
   - Every URL visited in the browser
   - All HTTP request/response headers (including cookies and auth tokens)
   - POST form data from download requests
   - The ability to silently intercept and redirect downloads

4. **The CSP flags are effectively false positives.** The unsafe-eval/unsafe-inline apply only to a sandbox CSP that governs zero pages.

5. **No indicators of current compromise** in the extension code itself.
