# Vulnerability Report: Speed Reading / Reedy Reader

**Extension ID:** `ihbdojmggkmjbhfflnchljfkgdhokffj`
**Version:** 3.1.2
**Manifest Version:** 3
**Assessment Date:** 2026-02-06

## Summary

Analysis of the "Speed Reading" (Reedy Reader) extension identified **2 verified vulnerabilities** and **1 informational finding**. The extension is a legitimate speed-reading tool built with Preact/WXT framework. Most triage flags were false positives attributable to framework internals (Preact `dangerouslySetInnerHTML`, WXT content script lifecycle messaging, styled-components/Emotion CSS-in-JS). Two real issues exist: a postMessage origin validation gap in the WXT content script lifecycle mechanism, and hardcoded third-party API keys.

---

## Vulnerability 1: postMessage Without Origin Validation (WXT Content Script Lifecycle)

**Severity:** LOW
**CVSS 3.1:** 3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N)

**Files:**
- `content-scripts/content.js` lines 5977-5992
- `background.js` lines 2441-2457
- `chunks/L-C5cz0lUo.js` lines 2199-2214

**Description:**

The WXT framework's `ContentScriptContext` class uses `window.postMessage()` with target origin `"*"` to coordinate content script lifecycle (preventing duplicate scripts after extension updates). When a new content script starts, it broadcasts a message via `stopOldScripts()`:

```javascript
// content-scripts/content.js:5977-5981
stopOldScripts() {
    window.postMessage({
        type: Qf.SCRIPT_STARTED_MESSAGE_TYPE,  // "wxt:content-script-started"
        contentScriptName: this.contentScriptName
    }, "*")
}
```

The corresponding listener in `listenForNewerScripts()` (line 5983-5992) checks only `e.data.type` and `e.data.contentScriptName` but does NOT validate `e.origin` or `e.source`:

```javascript
// content-scripts/content.js:5983-5992
listenForNewerScripts(r) {
    let n = !0,
      e = e => {
        var t;
        if ((null == (t = e.data) ? void 0 : t.type) === Qf.SCRIPT_STARTED_MESSAGE_TYPE &&
            (null == (t = e.data) ? void 0 : t.contentScriptName) === this.contentScriptName) {
          let e = n;
          n = !1, e && null != r && r.ignoreFirstEvent || this.notifyInvalidated()
        }
      };
    addEventListener("message", e), this.onInvalidated(() => removeEventListener("message", e))
}
```

Any page script (or iframe) can craft a message matching the expected shape to force the content script to self-invalidate via `notifyInvalidated()`, which calls `this.abort("Content script context invalidated")`.

**PoC Exploit Scenario:**

A malicious webpage can disable the Reedy Reader content script by injecting:

```javascript
window.postMessage({
    type: "wxt:content-script-started",
    contentScriptName: "content-scripts/content.js"
}, "*");
```

This causes the content script's AbortController to fire, invalidating all event listeners and preventing the extension from functioning on that page. The content script name value is predictable since it's derived from the file path.

**Impact:**

- Denial of service of the extension on any webpage that includes the above script
- The content script runs in an ISOLATED world, so this cannot escalate to data theft
- Limited to availability impact -- the extension stops working on the affected page
- This is a known WXT framework pattern (not specific to this extension)

---

## Vulnerability 2: Hardcoded Third-Party API Keys

**Severity:** LOW
**CVSS 3.1:** 2.4 (AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N)

**Files:**
- `background.js` line 5265 (Amplitude API key)
- `background.js` line 5320 (Logflare API key)
- `background.js` line 5322 (Logflare source ID)
- `background.js` line 3965 (Sentry DSN)

**Description:**

Three third-party analytics/monitoring service credentials are hardcoded in the service worker:

1. **Amplitude Analytics API Key** (line 5265):
   ```javascript
   api_key: "fbcc95b6cf85d6b7e1bd0587923e95da",
   // Used with: https://api2.amplitude.com/2/httpapi
   ```

2. **Logflare API Key + Source ID** (lines 5320-5322):
   ```javascript
   "X-API-KEY": "NH0k1fNZEBAm"
   // Used with: https://api.logflare.app/logs?source=3d028592-9ec7-4c0f-a3d1-4008557bf9c0
   ```

3. **Sentry DSN** (line 3965):
   ```javascript
   dsn: "https://0eebb44f08bfa4a180ff321ab569cf5c@o4507910860767232.ingest.us.sentry.io/4507910866665472"
   ```

**PoC Exploit Scenario:**

An attacker who extracts these keys can:

- **Amplitude:** Submit fake analytics events, polluting the developer's usage data and potentially skewing business decisions. The Amplitude HTTP API v2 key is write-only by design, so reading existing data is not possible.
- **Logflare:** Inject fake log entries, potentially causing log pollution or storage cost exhaustion.
- **Sentry:** Submit fake error reports, flooding the developer's error dashboard and potentially exhausting their Sentry quota.

Example Amplitude data injection:
```javascript
fetch("https://api2.amplitude.com/2/httpapi", {
    method: "POST",
    body: JSON.stringify({
        api_key: "fbcc95b6cf85d6b7e1bd0587923e95da",
        events: [{ event_type: "fake_event", device_id: "attacker" }]
    })
});
```

**Impact:**

- Analytics data pollution for the extension developer
- Potential quota/billing exhaustion on Logflare and Sentry
- No user data is at risk -- these are write-only analytics keys
- Sentry DSN exposure is a known accepted practice for client-side error monitoring
- This is standard practice for browser extensions and client-side apps (keys are inherently extractable)

---

## False Positive Analysis

The following triage flags were investigated and determined to be false positives:

### FP1: CSP `unsafe-inline` (style-src)

**File:** `manifest.json`
**CSP:** `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`

The `unsafe-inline` directive applies **only to `style-src`**, not `script-src`. This allows inline CSS styles, which is required by the Emotion/styled-components CSS-in-JS library used in the extension's UI (visible at `content-scripts/content.js:7861` where `style` elements are dynamically created). This is a standard and necessary pattern for CSS-in-JS frameworks and does NOT enable script injection.

The `script-src` defaults to `'self'` (via `default-src 'self'`), which is secure.

### FP2: innerHTML with Dynamic Content (Preact Framework)

**Files:** `content-scripts/content.js` lines 464-471, `chunks/L-C5cz0lUo.js` lines 530-531

These are **Preact's virtual DOM diffing internals** handling `dangerouslySetInnerHTML`. The framework checks `u.__html === h.__html` before updating innerHTML -- this is standard Preact behavior, not a vulnerability.

The extension's own usage of `dangerouslySetInnerHTML` at lines 12832-12890 renders:
- `contextBeforeHtml` / `contextAfterHtml` -- derived from page text tokens, processed through an escaping pipeline
- `wordHtml` -- individual words escaped via `Er()` (line 7213: `e.replace(/</g, "&lt;").replace(/>/g, "&gt;")`) before HTML construction at line 13292

At line 13294, sequel tokens joined via `s.join("")` are inserted into the HTML string without explicit escaping. However, these tokens are derived from the extension's own tokenizer processing page text content. While this is a defense-in-depth concern, the tokens are word-level fragments from the extension's parser (not raw user input), and the content script runs in an ISOLATED world, so any theoretical injection would only affect the extension's own shadow DOM overlay, not the host page.

The `_r` helper function (line 7190) sets innerHTML from static translation strings like `CS_info` (hardcoded HTML at line 6831), which is safe.

### FP3: Readability.js innerHTML

**File:** `content-scripts/content.js` lines 5254, 5368, 5449

This is Mozilla's **Readability.js** library (article extraction), which operates on a cloned DOM document. The innerHTML assignments are part of its internal article content extraction algorithm (resetting body content during retry loops). This operates on DOM nodes within the page's own document tree, not injecting untrusted external data.

---

## Telemetry Summary

The extension sends the following telemetry (not a vulnerability, but noted for completeness):

| Service | Data Sent | Endpoint |
|---------|-----------|----------|
| Amplitude | Page views, UI interactions, device info (UA, OS, language) | `api2.amplitude.com/2/httpapi` |
| Logflare | Error logs with device context | `api.logflare.app/logs` |
| Sentry | JavaScript errors, stack traces | `o4507910860767232.ingest.us.sentry.io` |

All telemetry endpoints are declared in the CSP `connect-src` directive, which is transparent.

---

## Overall Assessment

**Risk Level: LOW**

This extension is a **legitimate speed-reading tool** with no malicious behavior. The two findings are low-severity issues common to nearly all browser extensions:

1. The postMessage origin gap is a WXT framework pattern affecting only extension availability (not confidentiality or integrity)
2. The hardcoded API keys are write-only analytics credentials, standard for client-side applications

No data exfiltration, no privilege escalation, no remote code execution vectors were identified.
