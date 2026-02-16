# Vulnerability Report: Captcha Solver: Auto captcha solving service

## Metadata
- **Extension ID**: pgojnojmmhpofjgdmaebadhbocahppod
- **Extension Name**: Captcha Solver: Auto captcha solving service
- **Version**: 1.17.0
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Captcha Solver: Auto captcha solving service" is a legitimate browser extension designed to automatically solve various types of CAPTCHAs (reCAPTCHA, hCaptcha, Cloudflare Turnstile, AWS CAPTCHA) using the Capsolver API service. The extension operates by injecting content scripts across all websites, hooking XHR and fetch APIs to intercept CAPTCHA responses, and forwarding them to the Capsolver backend service for automated solving.

While the extension's core functionality is legitimate and matches its stated purpose, it implements message passing without proper origin validation across multiple content scripts, creating a medium-severity security concern that could allow malicious websites to potentially abuse the extension's communication channels. The extension also collects basic usage analytics via Google Analytics for telemetry purposes.

## Vulnerability Details

### 1. MEDIUM: PostMessage Listeners Without Origin Validation

**Severity**: MEDIUM
**Files**: recaptcha-recognition.js:364, my-content-script.js:371, image-to-text.js:364, hcaptcha-recognition.js:364, funcaptcha-recognition.js:364, cloudflare-content.js:364, aws-recognition.js:364, aW5qZWN0X2hhc2g-t.js:2, aW5qZWN0X2hhc2g-s.js:2
**CWE**: CWE-346 (Origin Validation Error)

**Description**: Multiple content scripts register `window.addEventListener("message")` handlers without validating the origin of incoming messages. While most handlers check for `n.data.from === t` or specific message types, they do not verify `event.origin` before processing messages, allowing any website to potentially send crafted messages to these handlers.

**Evidence**:
```javascript
// recaptcha-recognition.js:364
window.addEventListener("message", n => {
  if (n.source === window && n.data.from !== void 0 && n.data.from === t) {
    let o = n.data[0],
      r = e.getEvents();
    for (let i in r) i === o.event && r[i](o.payload)
  }
}, !1)
```

```javascript
// cloudflare-content.js:545
window.addEventListener("message", async function(e) {
  var n, r;
  if (((n = e == null ? void 0 : e.data) == null ? void 0 : n.type) !== "registerTurnstile" || !((r = e.data) != null && r.sitekey)) return;
  // ... processes message without origin check
```

**Verdict**: While the handlers check message structure and type, the lack of origin validation is a security weakness. However, the impact is limited since the extension primarily processes CAPTCHA-related messages and the communication is mostly internal (between injected scripts and content scripts). The handlers use `n.source === window` checks which somewhat mitigates cross-frame attacks, but malicious same-origin scripts could still send crafted messages.

## False Positives Analysis

### XHR/Fetch Hooking
The extension hooks `XMLHttpRequest` and `fetch` APIs in the page context (aW5qZWN0X2hhc2g-r.js), intercepting responses from specific reCAPTCHA endpoints (`/recaptcha/api2/reload`, `/recaptcha/api2/userverify`, etc.). This is **legitimate and expected** for a CAPTCHA solver - it needs to intercept CAPTCHA challenge/response flows to automate solving. The hooks only listen to specific reCAPTCHA-related URLs and forward data via postMessage to content scripts.

```javascript
// aW5qZWN0X2hhc2g-r.js
const recaptchaListeningList = [
  '/recaptcha/api2/reload',
  '/recaptcha/api2/userverify',
  '/recaptcha/enterprise/reload',
  '/recaptcha/enterprise/userverify'
];

XHR.send = function (postData) {
  const _url = this._url;
  this.addEventListener('load', function () {
    const isInList = recaptchaListeningList.some(url => _url.indexOf(url) !== -1);
    if (isInList) {
      window.postMessage({ type: 'xhr', data: this.response, url: _url }, '*');
    }
  });
  return send.apply(this, arguments);
};
```

### Google Analytics Telemetry
The extension sends usage analytics to Google Analytics (measurement_id: G-MJTX6G6YHX, api_secret: 5f5uGZ8yS9er8l9xMXdDBA). This is **disclosed in the extension's normal operation** for tracking extension usage, CAPTCHA solve events, and user engagement. The data collected appears limited to:
- Client ID (generated UUID stored locally)
- Session ID (timestamp-based, expires after 30 minutes)
- Event names and basic engagement metrics
- No sensitive user data or browsing history is collected

### Obfuscated Code Structure
The webpack-bundled code appears deobfuscated (variable names like `Se`, `Pe`, `_e` are typical webpack artifacts). The directory name `aW5qZWN0X2hhc2g` is base64-encoded ("inject_hash"), which is a simple obfuscation technique but not indicative of malicious intent - it's likely used to prevent simple text-based detection or scanning.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.google-analytics.com | Usage analytics | Client ID, session ID, event names, engagement time | Low - Standard telemetry |
| api.capsolver.com | CAPTCHA solving API | CAPTCHA challenges, sitekeys, proxy config (if enabled) | Low - Core functionality |
| challenges.cloudflare.com | Cloudflare Turnstile | Sitekey, website URL, action, cData | Low - CAPTCHA solving target |
| chrome.runtime.getURL() | Local extension resources | Config files, injected scripts | None - Internal |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This extension is a legitimate CAPTCHA solving service that operates transparently within its stated purpose. The XHR/fetch hooking and postMessage communication are necessary for intercepting and solving CAPTCHAs across different websites. While the postMessage handlers lack strict origin validation (MEDIUM severity finding), the actual risk is limited because:

1. The handlers primarily process internal messages between extension components
2. Message structure validation provides some protection against misuse
3. The extension does not collect sensitive user data beyond usage analytics
4. All network communication is to documented endpoints (Google Analytics, Capsolver API)
5. The extension requires user configuration (API key) to function, providing user awareness

The primary security concern is the postMessage origin validation issue, which should be addressed by the developer by adding `event.origin` checks to all message handlers. However, this does not represent an immediate high-risk threat to users given the extension's limited scope and the defensive checks already in place.

Users should be aware that:
- The extension has broad access (`<all_urls>`) necessary for CAPTCHA solving on any website
- Usage analytics are collected via Google Analytics
- An API key from Capsolver is required for the service to function
- The extension modifies page behavior by hooking fetch/XHR globally
