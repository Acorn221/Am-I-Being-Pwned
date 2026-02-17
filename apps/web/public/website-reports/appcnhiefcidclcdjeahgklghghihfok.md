# Vulnerability Report: Google Meet Attendance List

## Metadata
- **Extension ID**: appcnhiefcidclcdjeahgklghghihfok
- **Extension Name**: Google Meet Attendance List
- **Version**: 5.2.1
- **Users**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Google Meet Attendance List is a legitimate productivity extension that tracks and saves attendance lists from Google Meet calls. The extension operates by intercepting Google Meet API responses to collect participant data, which is then synced to the developer's backend (meetlist.io) for cloud storage and multi-device access.

While the extension serves its stated purpose, it contains several medium-severity security issues related to message handling and code injection patterns. The primary concerns are: (1) multiple postMessage event listeners without origin validation, (2) fetch/XHR hooking in the MAIN world context, and (3) externally_connectable configuration allowing the developer's website to communicate with the extension. These issues create potential attack surface but do not constitute active malicious behavior.

## Vulnerability Details

### 1. MEDIUM: postMessage Handlers Without Origin Validation

**Severity**: MEDIUM
**Files**: updates.js:2894, options.js:11123, content-scripts/sync.isolated.js:888
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The extension registers multiple `window.addEventListener("message")` handlers without validating the message origin in some cases. While two handlers (updates.js and options.js) do check `event.origin === config["MEETLIST_BASE_WEB_URL"]`, they only verify the origin matches `https://meetlist.io` but process untrusted data directly.

**Evidence**:
```javascript
// updates.js:2887
function sendPremiumEvent(event) {
  if (event.isTrusted && event.origin === config["MEETLIST_BASE_WEB_URL"]) {
    premiumPrice = event.data;  // Directly uses event.data without validation
    google_analytics["a" /* default */].fireEvent('premium_upsell_view', {
      price: premiumPrice
    });
  }
}
window.addEventListener('message', sendPremiumEvent);
```

The sync.isolated.js content script also has a message listener at line 888 (detected by static analyzer).

**Verdict**:
While origin checking is present for some handlers, the extension trusts all data from meetlist.io without further validation. If the meetlist.io domain were compromised or served malicious content via XSS, attackers could send arbitrary messages to the extension. The impact is limited to triggering analytics events with attacker-controlled data and potential state manipulation.

### 2. MEDIUM: Fetch and XHR Hooking in MAIN World Context

**Severity**: MEDIUM
**Files**: content-scripts/meet-shims.main.js:1041-1083, 1097-1128
**CWE**: CWE-94 (Code Injection)

**Description**:
The extension injects a content script that runs in the MAIN world context (world: "MAIN") and overrides native `window.fetch` and `XMLHttpRequest.prototype.open` to intercept Google Meet API calls. This pattern is commonly associated with data exfiltration malware.

**Evidence**:
```javascript
// Fetch hooking (meet-shims.main.js:1042)
var __originalFetch = window.fetch;
window.fetch = function (url) {
  var resp = __originalFetch.apply(this, arguments);
  var wrapperFn = async function(response) {
    if (response.ok) {
      responseClone = response.clone();
      base64String = await responseClone.text();
      Object(helpers["d" /* sendExtMessage */])('meetings.decode_sync', {
        b64: base64String
      });
      return response;
    }
  };
  if (url && url.indexOf('SyncMeetingSpaceCollections') > -1) {
    resp.then(wrapperFn);
  }
  return resp;
};

// XHR hooking (meet-shims.main.js:1099)
var xhrOpenDesc = Object.getOwnPropertyDescriptor(XMLHttpRequest.prototype, 'open');
var origXhrOpen = xhrOpenDesc.value;
var xhrOpenProxy = new Proxy(origXhrOpen, {
  apply: function apply(target, thisArg, argumentsList) {
    var regex = /\/calendar\/v[^\/]+\/calendars\/([^\/]+)\/events/;
    var match = regex.exec(url);
    if (match && match[1]) {
      var calendarId = decodeURIComponent(match[1]);
      thisArg.addEventListener('load', function () {
        var eventDetails = JSON.parse(this.responseText);
        Object(helpers["d" /* sendExtMessage */])('meetings.event_details', {
          eventDetails: eventDetails,
          calendarId: calendarId
        });
      });
    }
    return Reflect.apply(target, thisArg, argumentsList);
  }
});
```

**Verdict**:
The hooking is **legitimate for the extension's stated purpose** of capturing attendance data from Google Meet's internal API responses. The extension specifically targets:
- `SyncMeetingSpaceCollections` API endpoint (participant list sync)
- Google Calendar API responses (meeting metadata)

The intercepted data is sent via CustomEvent (`gmal-message`) to the isolated content script, which forwards it to the background script for processing and storage. This is the expected behavior for an attendance tracking tool. However, this pattern is risky because any bug or compromise could lead to broader data exposure beyond meeting attendance.

### 3. MEDIUM: externally_connectable Configuration

**Severity**: MEDIUM
**Files**: manifest.json:19-23
**CWE**: CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)

**Description**:
The manifest declares `externally_connectable` with `*://*.meetlist.io/*`, allowing any page on the developer's domain to send messages to the extension via `chrome.runtime.sendMessage`.

**Evidence**:
```json
"externally_connectable": {
  "matches": [
    "*://*.meetlist.io/*"
  ]
}
```

**Verdict**:
This is necessary for the extension's cloud sync feature, where users access their meeting history via the meetlist.io web interface. The website needs to communicate with the extension to retrieve locally stored data. However, if meetlist.io experiences XSS or subdomain takeover, attackers could abuse this channel to invoke extension APIs. The risk is mitigated by the fact that the background script validates message types and only exposes specific API endpoints.

### 4. LOW: CSP with 'wasm-unsafe-eval'

**Severity**: LOW
**Files**: manifest.json:64-66
**CWE**: CWE-1188 (Insecure Default Initialization of Resource)

**Description**:
The Content Security Policy includes `'wasm-unsafe-eval'` in the extension pages CSP.

**Evidence**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'; script-src-elem 'self'"
}
```

**Verdict**:
The static analyzer flagged this as `unsafe-eval`, but `wasm-unsafe-eval` only allows WebAssembly compilation and is significantly less dangerous than `unsafe-eval`. No WASM files were detected in the codebase, suggesting this may be a precautionary measure or left over from a build tool default. Impact is minimal.

## False Positives Analysis

1. **"Obfuscated" flag from static analyzer**: The extension uses Webpack bundling, which produces minified/transformed code. This is standard build tooling, not intentional obfuscation to hide malicious behavior.

2. **Fetch/XHR hooking as "malware"**: While this pattern is commonly used by data exfiltration malware, in this case it's the core functionality of a meeting attendance tracker. The extension's purpose is explicitly to capture participant lists from Google Meet API responses.

3. **Data sent to external domain**: The extension sends attendance data to `api.meetlist.io` and `insights.meetlist.io`, which is disclosed in the extension description ("Backup meetings in cloud", "Access history from multiple devices"). Users are informed this is a cloud sync feature.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.meetlist.io/v1/* | Cloud sync for attendance data | Meeting codes, participant names, timestamps, calendar metadata | LOW - Disclosed feature |
| insights.meetlist.io/heartbeat | Telemetry/analytics | Device ID, premium status, language, meeting count, meeting names | LOW - Standard analytics |
| meetlist.io/embed/premium | Premium subscription iframe | None (embedded iframe for payment) | LOW - Standard e-commerce |

All endpoints use HTTPS and are scoped to the developer's infrastructure.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
This extension provides legitimate attendance tracking functionality for Google Meet and operates transparently within its stated purpose. However, it exhibits several medium-risk patterns:

1. **postMessage handlers** without sufficient validation create potential for cross-origin attacks if meetlist.io is compromised
2. **Fetch/XHR hooking** in MAIN world gives the extension deep access to Google Meet's internal APIs - necessary for functionality but risky if misused
3. **externally_connectable** creates an attack surface via the developer's website

The extension does NOT exhibit:
- Credential theft
- Hidden data exfiltration beyond stated purpose
- Malicious code execution
- Undisclosed tracking

The risk is elevated above LOW due to the architectural decisions (MAIN world injection, message handling patterns) that increase attack surface. However, there is no evidence of malicious intent. Users should be aware that the extension:
- Captures full participant lists from meetings
- Syncs meeting data to the developer's cloud servers
- Grants meetlist.io the ability to communicate with the extension

**Recommendation**: The extension is safe for users who trust the developer and understand that meeting attendance data is stored on external servers. Developers should improve origin validation on message handlers and consider additional input sanitization.
