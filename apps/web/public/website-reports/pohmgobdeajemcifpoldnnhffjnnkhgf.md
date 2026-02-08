# WeVideo Screen & Webcam Recorder - Security Analysis Report

**Extension ID:** `pohmgobdeajemcifpoldnnhffjnnkhgf`
**Version:** 3.8.0 (build c57ba38)
**Users:** ~1,000,000
**Manifest Version:** 3
**Framework:** WXT (Web Extension Toolkit) + React 17.0.2 + Vite
**Analysis Date:** 2026-02-06

---

## Executive Summary

WeVideo Screen & Webcam Recorder is a **legitimate screen/webcam recording extension** built by WeVideo, Inc. The extension is well-structured, uses recognized libraries, and its behavior aligns with its stated purpose. The triage classification of SUSPECT is largely driven by false positives from bundled third-party libraries (Sentry, CryptoJS, Axios, protobuf.js, ONNX Runtime, FFmpeg WASM).

**No malware, data theft, ad injection, or covert tracking was identified.**

However, several security findings of LOW-to-MEDIUM severity were identified, primarily around hardcoded credentials, overly broad permissions, a permissive sandbox CSP, and a storage injection vector in the external message handler.

**Overall Risk Rating: LOW (CLEAN with caveats)**

---

## Permissions Analysis

### Declared Permissions
| Permission | Justification | Verdict |
|---|---|---|
| `storage` | Stores user session state, preferences, recording configs | Legitimate |
| `unlimitedStorage` | Stores large video recording blobs (screen recordings) | Legitimate |
| `notifications` | Notifies user when uploads complete | Legitimate |
| `tabs` | Manages recording tabs, webcam tab, script page tab | Legitimate |
| `offscreen` | Creates offscreen document for screen capture + video processing | Legitimate |
| `scripting` | Injects content script into active tab for recording toolbar overlay | Legitimate |

### Host Permissions
| Permission | Justification | Verdict |
|---|---|---|
| `<all_urls>` | Needed for content script injection (recording toolbar on any page) + `scripting.executeScript` for toolbar re-injection | Overly broad but functionally justified |

### Optional Permissions
| Permission | Justification | Verdict |
|---|---|---|
| `activeTab` | Alternative to `<all_urls>` for targeted injection | Legitimate |

### Externally Connectable
```json
"externally_connectable": {
  "matches": ["https://*.wevideo.com/*"]
}
```
Only `*.wevideo.com` can send external messages to the extension. This is appropriately scoped to the vendor's domain.

### Content Security Policy
```json
"extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';",
"sandbox": "sandbox allow-scripts allow-forms allow-popups allow-modals; script-src 'self' 'wasm-unsafe-eval' 'unsafe-inline' 'unsafe-eval'; child-src 'self';"
```

**Finding:** The sandbox CSP includes `'unsafe-inline'` and `'unsafe-eval'`, which is more permissive than necessary. However, no sandbox pages were found in the extension (confirmed by `has_sandbox: false` in wasm_analysis.json). The sandbox CSP declaration without any actual sandboxed pages represents dead configuration rather than an active vulnerability.

### Web Accessible Resources
```json
"web_accessible_resources": [{
  "resources": ["res/fonts/Lato-Regular.woff2", "res/fonts/Lato-Bold.woff2",
                "webcam.html", "offscreen.html", "ort-wasm-simd-threaded.wasm"],
  "matches": ["<all_urls>"]
}]
```

**Finding (LOW):** `webcam.html` and `offscreen.html` are exposed to all URLs. While these pages load internal modules and don't accept external input beyond URL parameters (webcam ID), exposing them to `<all_urls>` means any website can probe for the extension's presence by attempting to load these resources. This is a minor **extension fingerprinting** vector.

---

## Detailed Findings

### FINDING 1: External Message Handler Storage Injection (MEDIUM)

**File:** `/deobfuscated/background.js`, line 111
**Severity:** MEDIUM (requires compromised wevideo.com)

```javascript
const oe = (e, t, n) => {
    e.action === "auth" && t.url === `${T()}/api/4/rce/tokens` ? (n(!0), chrome.storage.local.set(e, () => {
      chrome.tabs.create({
        url: "main.html#/welcome"
      }, () => {
        h = !0
      }), t && t.tab && t.tab.id && chrome.tabs.remove(t.tab.id)
    }))
    // ...
};
chrome.runtime.onMessageExternal.addListener(oe);
```

**Issue:** When the message has `action === "auth"` and originates from a tab at `wevideo.com/api/4/rce/tokens`, the **entire message object `e`** is stored directly into `chrome.storage.local`. There is no filtering of which keys from the message are stored. An attacker who achieves XSS on `*.wevideo.com` could inject arbitrary key-value pairs into the extension's local storage alongside the expected `key` and `secret` fields.

**Impact:** An XSS on wevideo.com could potentially:
- Overwrite extension state/preferences
- Inject a malicious `environment` value to redirect API calls (though the environment logic only supports "eu" or defaults to "www")
- Corrupt the `globalState` causing DoS

**Mitigating factor:** Requires the sender tab's URL to exactly match the `/api/4/rce/tokens` path on wevideo.com, which limits the attack surface.

---

### FINDING 2: Hardcoded Sentry DSN (LOW / Informational)

**File:** `/deobfuscated/chunks/script-B14bJQSc.js`, line 12024

```javascript
o_ = "https://a900bae3f05e1e46c3cde10a92da64ba@o4507140171497472.ingest.de.sentry.io/4507140183097424"
```

**Issue:** The Sentry DSN is hardcoded in the extension source. While Sentry DSNs are designed to be "public" (used client-side), an exposed DSN allows an attacker to send fake error reports to WeVideo's Sentry project, potentially polluting their error tracking or consuming their Sentry quota.

**Impact:** LOW. Standard practice for client-side error reporting. Sentry recommends rate limiting and source filtering to mitigate abuse.

---

### FINDING 3: Hardcoded WeVideo API Key (LOW / Informational)

**File:** `/deobfuscated/chunks/script-B14bJQSc.js`, line 12024

```javascript
a_ = "feae7814-39e5-4fe8-ab00-1871130c201f"
// Used as:
headers: {
    "Content-Type": "application/json",
    "wev-api-key": a_
}
```

**Issue:** A WeVideo API key is hardcoded and used for error logging to `wevideo.com/api/5/logs/event`. This key could be extracted and used to send fake log events to WeVideo's logging endpoint.

**Impact:** LOW. The key appears to be a non-sensitive logging API key, not an authentication credential.

---

### FINDING 4: Hardcoded Google OAuth Client ID (Informational)

**File:** `/deobfuscated/chunks/offscreen-pDz1FGa_.js`, line 76

```javascript
authUrl: `https://accounts.google.com/o/oauth2/auth/oauthchooseaccount?client_id=752950701654.apps.googleusercontent.com&redirect_uri=https%3A%2F%2F${_t}%2Fapi%2F4%2Frce%2Fdrive&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive.file%20profile%20email&...`
```

**Issue:** Google OAuth client ID `752950701654.apps.googleusercontent.com` is hardcoded. This is standard for OAuth flows and the client ID is inherently public. The scope is limited to `drive.file` (only files created by the app) and `profile email`.

**Impact:** Informational. Standard OAuth practice.

---

### FINDING 5: Extension Fingerprinting via Web Accessible Resources (LOW)

**Manifest:**
```json
"web_accessible_resources": [{
  "resources": ["webcam.html", "offscreen.html", "ort-wasm-simd-threaded.wasm", ...],
  "matches": ["<all_urls>"]
}]
```

**Issue:** Any website can detect whether this extension is installed by attempting to load `chrome-extension://pohmgobdeajemcifpoldnnhffjnnkhgf/webcam.html`. This enables browser fingerprinting (identifying users who have this extension installed).

**Impact:** LOW. Extension fingerprinting is a known limitation of `web_accessible_resources`. Could be mitigated by restricting `matches` to `*.wevideo.com`.

---

### FINDING 6: Permissive Sandbox CSP (Informational)

**Manifest:**
```json
"sandbox": "sandbox allow-scripts allow-forms allow-popups allow-modals; script-src 'self' 'wasm-unsafe-eval' 'unsafe-inline' 'unsafe-eval'; child-src 'self';"
```

**Issue:** The sandbox CSP allows `unsafe-inline` and `unsafe-eval`. However, no sandbox pages exist in this extension -- the CSP declaration appears to be unused boilerplate.

**Impact:** Informational. No active risk since no sandboxed pages exist.

---

## WASM Analysis

### ffmpeg-core.wasm (32 MB)
- **Library:** FFmpeg compiled to WASM via Emscripten
- **Loader:** `js/ffmpeg-core.js` (standard Emscripten glue) and `js/worker.js` (standard @ffmpeg/ffmpeg 0.12.6 worker)
- **Purpose:** Video encoding/transcoding of screen recordings
- **Risk:** NONE. Standard open-source FFmpeg WASM build. The "interesting strings" about HTTP, proxy, cookies are FFmpeg's built-in HTTP protocol handler (for streaming inputs) -- not used for data exfiltration.
- **SHA256:** `2390efa7fb66e7e42dbae15427571a5ffc96b829480904c30f471f0a78967f61`

### ort-wasm-simd-threaded.wasm (11 MB)
- **Library:** ONNX Runtime Web (Microsoft)
- **Loader:** `chunks/Segmenter-rs-5KwM3.js`
- **Purpose:** AI-powered background segmentation for webcam (virtual background/blur effects). Uses the `mp_selfie_segm_landscape_opset11.onnx` model for person segmentation.
- **Risk:** NONE. Standard Microsoft ONNX Runtime WASM build for ML inference.
- **SHA256:** `207d02be4591c156b0a98f024f3d58005b5b04c92274d759fb390338c63559ea`

---

## Triage Flag Verdicts

### T1 Flags (Critical Indicators)
| # | Flag | Verdict | Explanation |
|---|------|---------|-------------|
| T1-1 | XHR/fetch hooking | **FALSE POSITIVE** | Sentry SDK instrumentation for breadcrumb tracking (error reporting). Standard Sentry behavior: wraps `XMLHttpRequest.prototype.open/send` and `fetch` to capture HTTP request metadata for error context. Does NOT intercept or modify user data. |
| T1-2 | Dynamic code loading | **FALSE POSITIVE** | protobuf.js `inquire` module uses `eval("quire".replace(/^/,"re"))` to dynamically construct `require`. This is a well-known pattern in the protobuf.js library (used by ONNX Runtime for ML model parsing). Does NOT execute arbitrary code. |

### T2 Flags (Moderate Indicators)
| # | Flag | Verdict | Explanation |
|---|------|---------|-------------|
| T2-1 | WASM binaries | **FALSE POSITIVE** | FFmpeg (video encoding) + ONNX Runtime (AI segmentation). Both are standard open-source libraries with legitimate purposes for a screen recorder. |
| T2-2 | CryptoJS usage | **FALSE POSITIVE** | HMAC-SHA256 for API request signing (AWS Signature V4 for S3 uploads). Standard authentication pattern -- not used for obfuscation. |
| T2-3 | `<all_urls>` permission | **FALSE POSITIVE (partial)** | Needed for content script injection (recording toolbar overlay). Could be narrowed with `activeTab` but the extension already declares it as optional. Functionally justified. |
| T2-4 | Cookie access | **FALSE POSITIVE** | Axios HTTP library standard cookie handling utilities. Not used to steal cookies. |
| T2-5 | Keyboard event listeners | **FALSE POSITIVE** | React 17 synthetic event system (in CircularProgress-DJje5DFy.js) + Sentry breadcrumb capture (click/keypress for error context). Standard UI framework behavior, not keylogging. |

### T3 Flags (Low Indicators)
| # | Flag | Verdict | Explanation |
|---|------|---------|-------------|
| T3-1 | External API communication | **FALSE POSITIVE** | All API calls go to `*.wevideo.com` (or `eu.wevideo.com`), Google Drive API, OneDrive API. These are the expected backends for a screen recording tool that uploads to cloud storage. |

### V Flags (Vulnerability Indicators)
| # | Flag | Verdict | Explanation |
|---|------|---------|-------------|
| V1-1 | `externally_connectable` | **TRUE POSITIVE (LOW)** | wevideo.com can send messages to the extension. The `onMessageExternal` handler has a storage injection vulnerability (see Finding 1). |
| V1-2 | `scripting` permission | **FALSE POSITIVE** | Used only for re-injecting the content script toolbar. No evidence of arbitrary script injection. |
| V1-3 | Hardcoded secrets | **TRUE POSITIVE (LOW)** | Sentry DSN, WeVideo API key, Google OAuth client ID exposed in source (see Findings 2-4). |
| V1-4 | `host_permissions: <all_urls>` | **FALSE POSITIVE (partial)** | Overly broad but functionally justified for a screen recording overlay. |
| V1-5 | Web accessible resources | **TRUE POSITIVE (LOW)** | Extension fingerprinting possible via exposed webcam.html/offscreen.html (see Finding 5). |
| V1-6 | `wasm-unsafe-eval` CSP | **FALSE POSITIVE** | Required for WASM execution. Standard in MV3 for extensions using WebAssembly. |
| V2-1 | `unsafe-eval` in sandbox CSP | **TRUE POSITIVE (Informational)** | Overly permissive but no sandbox pages exist (see Finding 6). |
| V2-2 through V2-5 | Various | **FALSE POSITIVE** | Library patterns (React, Axios, Sentry, protobuf.js). |
| V3-1 | `unlimitedStorage` | **FALSE POSITIVE** | Justified for storing large video recordings locally before upload. |

---

## Data Flow Summary

1. **Recording Flow:** User initiates recording -> offscreen document captures screen via `getDisplayMedia` + webcam via `getUserMedia` -> MediaRecorder creates WebM blobs -> stored in extension storage -> uploaded to WeVideo S3 (with AWS SigV4 signing) or Google Drive or OneDrive
2. **Authentication Flow:** User signs in via wevideo.com -> auth tokens (`key`, `secret`) sent to extension via `onMessageExternal` -> stored in `chrome.storage.local` -> used for HMAC-SHA256 signed API requests
3. **Analytics:** Events sent to `wevideo.com/api/4/analytics/instrumentation` (Mixpanel proxy) and `wevideo.com/api/4/analytics/hubspotevent/` -- standard product analytics, server-side proxied
4. **Error Reporting:** Sentry SDK + custom WeVideo error logging to `wevideo.com/api/5/logs/event`
5. **Content Script:** Injects a recording toolbar overlay (`<wvr-tools>` custom element) into the active tab -- UI only, does not read page content

---

## Network Destinations

| Domain | Purpose | Risk |
|---|---|---|
| `www.wevideo.com` / `eu.wevideo.com` | Primary API (auth, upload, analytics, error logs) | Expected |
| `*.sentry.io` (o4507140171497472.ingest.de.sentry.io) | Error reporting | Expected |
| `accounts.google.com` | Google Drive OAuth | Expected |
| `www.googleapis.com` | Google Drive file upload/management | Expected |
| `login.microsoftonline.com` | OneDrive OAuth | Expected |
| `graph.microsoft.com` | OneDrive file upload | Expected |
| S3 buckets (dynamic, from upload tickets) | Video file storage | Expected |

No suspicious, unexpected, or third-party tracking domains were identified.

---

## Conclusion

**WeVideo Screen & Webcam Recorder is CLEAN.** The extension performs its stated function (screen/webcam recording with cloud upload) without any malicious behavior. All triage flags are attributable to standard third-party libraries (Sentry, React, CryptoJS, Axios, FFmpeg WASM, ONNX Runtime, protobuf.js).

The most notable finding is the **storage injection vulnerability in the `onMessageExternal` handler** (Finding 1), which could allow a compromised wevideo.com page to write arbitrary keys to the extension's storage. This is a real but low-likelihood vulnerability that requires XSS on the vendor's own domain.

**Recommended reclassification: SUSPECT -> CLEAN (with LOW-severity vulnerability notes)**
