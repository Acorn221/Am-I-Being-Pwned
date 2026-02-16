# Vulnerability Report: Moesif Origin/CORS Changer & API Logger

## Metadata
- **Extension ID**: digfbfaphojjndkpccljibejjbppifbc
- **Extension Name**: Moesif Origin/CORS Changer & API Logger
- **Version**: 1.0.6
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Moesif Origin/CORS Changer & API Logger is a developer tool designed to bypass CORS restrictions and capture HTTP API traffic for debugging purposes. The extension modifies request/response headers using declarativeNetRequest rules and injects a monitoring script that captures XMLHttpRequest calls. When logging is enabled and configured with a Moesif Application ID, all API traffic is transmitted to api.moesif.net for analytics.

While the extension serves a legitimate development use case, it presents medium-risk privacy concerns: (1) a postMessage event listener in the content script lacks origin validation, potentially allowing malicious sites to send arbitrary data to Moesif, and (2) the extension intercepts and exfiltrates all HTTP request/response data from websites to a third-party service, though this requires explicit user opt-in via configuration. The extension is appropriate for controlled development environments but poses risks if used carelessly on production sites with sensitive data.

## Vulnerability Details

### 1. MEDIUM: PostMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: contentScript.bundle.js:226-238
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The content script registers a `window.addEventListener("message")` handler that processes messages from any source without validating the message origin. This handler receives data payloads intended for Moesif and forwards them to api.moesif.net via XMLHttpRequest.

**Evidence**:
```javascript
window.addEventListener("message", (function(e) {
  e.source === window && e.data && (n.debug("message received from page script: " + e.data.type),
  e.data.type && e.data.type.indexOf("send_to_moesif") >= 0 && function(e, t, o) {
    try {
      n.debug("about to send data to moesif " + e);
      var r = new XMLHttpRequest;
      r.open("POST", e),
      r.setRequestHeader("Content-Type", "application/json"),
      r.setRequestHeader("X-Moesif-Application-Id", o),
      r.setRequestHeader("X-Moesif-SDK", "cors-extension/1.0.6"),
      // ... sends JSON.stringify(t)
    }
  }(e.data.url, e.data.data, e.data.moesifApplicationId))
}))
```

The check `e.source === window` only validates that the message comes from the same window context, not from a trusted origin. The ext-analyzer correctly flagged: `[HIGH] window.addEventListener("message") without origin check`.

**Verdict**: While the message type check (`send_to_moesif`) provides minimal filtering, a malicious script on any site could craft messages to abuse this endpoint. The impact is somewhat mitigated because the attacker needs to know or guess the Moesif Application ID to send valid requests, but the lack of origin validation still represents a security weakness.

### 2. MEDIUM: API Request/Response Data Exfiltration to Third-Party

**Severity**: MEDIUM
**Files**: moesif.min.js (XHR/Fetch hooking), contentScript.bundle.js:197-202 (injection)
**CWE**: CWE-200 (Exposure of Sensitive Information)
**Description**: When API logging is enabled, the extension injects moesif.min.js into every webpage. This script hooks `XMLHttpRequest.prototype` to intercept all HTTP requests/responses made by the page, including headers, request bodies, response bodies, and timing information. The captured data is then transmitted to api.moesif.net.

**Evidence** (moesif.min.js):
```javascript
function _(e, t, r) {
  ge.log("processResponse for" + e._url);
  var n = (new Date).toISOString();
  if (r) {
    var o = e._url ? e._url.toLowerCase() : e._url;
    if (o && 0 > o.indexOf("moesif.com") && 0 > o.indexOf("apirequest.io")) {
      // ... extracts request data
      o = {
        uri: o,
        verb: e._method,
        time: e._startTime,
        headers: e._requestHeaders
      },
      // ... parses request body
      // ... extracts response headers, status, body
      r({
        request: o,
        response: n
      })
    }
  }
}
```

The hook is installed globally on all XMLHttpRequest objects:
```javascript
var r = XMLHttpRequest.prototype,
// ... intercepts .open(), .send(), onreadystatechange
```

**Verdict**: This behavior is **disclosed** in the extension description: "Log/capture XmlHttpRequest API calls for debugging and analytics." Users must explicitly enable logging and provide a Moesif Application ID for data transmission to occur. However, once enabled, ALL HTTP traffic on ALL websites is captured and sent to a third-party commercial service. This includes potentially sensitive data like authentication tokens, personal information, or proprietary API responses. While legitimate for debugging, the risk is elevated because:
- Users may forget the extension is running and visit production or sensitive sites
- The breadth of data capture is extensive (full request/response bodies)
- Data is sent to an external commercial entity

### 3. LOW: Overly Permissive CORS Override

**Severity**: LOW
**Files**: background.bundle.js:188-234 (declarativeNetRequest rules)
**CWE**: CWE-942 (Permissive Cross-domain Policy)
**Description**: The extension's primary function is to modify CORS headers to bypass same-origin policy restrictions. When enabled, it sets `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Headers: *` for all XMLHttpRequest resources (excluding api.moesif.net).

**Evidence**:
```javascript
{
  id: 2,
  priority: 1,
  action: {
    type: "modifyHeaders",
    responseHeaders: [{
      header: "Access-Control-Allow-Origin",
      operation: "set",
      value: "*"
    }, {
      header: "Access-Control-Allow-Headers",
      operation: "set",
      value: "*"
    }, {
      header: "Access-Control-Allow-Methods",
      operation: "set",
      value: "GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH"
    }]
  }
}
```

**Verdict**: This is the **intended functionality** of a CORS development tool and is clearly described in the extension name and description. While disabling CORS protections weakens browser security, this is an expected trade-off for development/testing scenarios. Users explicitly install this extension to achieve this behavior. Not flagged as a higher severity because it aligns with the extension's stated purpose.

## False Positives Analysis

1. **Obfuscation Flag**: The ext-analyzer marked the code as "obfuscated." This is webpack bundling with minified variable names, not intentional obfuscation to hide malicious intent. The deobfuscated code is readable standard JavaScript.

2. **XHR Hooking**: While the extension hooks `XMLHttpRequest.prototype`, this is not covert malware behavior—it's the core advertised functionality of an API logging tool. The extension's name and description explicitly state "Log/capture XmlHttpRequest API calls."

3. **Remote Config**: The extension communicates with api.moesif.net, but there's no evidence of remote configuration or remote code execution. The endpoint is used purely for data logging.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.moesif.net | API analytics/logging service | Full HTTP request/response data (URL, method, headers, body, timing) when logging is enabled | MEDIUM - Requires user opt-in (Application ID), but captures comprehensive traffic data including potentially sensitive information |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This extension is a legitimate developer tool with a transparent purpose—bypassing CORS restrictions and logging API calls for debugging. The risk classification of MEDIUM (rather than LOW/CLEAN) is based on two factors:

1. **PostMessage Security Weakness**: The lack of origin validation on the postMessage listener is a code-level vulnerability that violates secure messaging best practices, even though practical exploitation is somewhat limited.

2. **Scope of Data Exfiltration**: When API logging is enabled, the extension transmits comprehensive HTTP traffic data to a third-party commercial service. While this requires explicit user configuration (providing a Moesif Application ID), the potential for inadvertent exposure of sensitive data is significant. Users may enable logging for development but forget to disable it when browsing sensitive sites or production environments.

**Recommendations for Users**:
- Only use this extension in isolated development environments
- Disable logging (and ideally the entire extension) when not actively debugging
- Never use this extension while authenticated to production services or handling sensitive data
- Review Moesif's privacy policy regarding logged data retention and usage

**Recommendations for Developer**:
- Add origin validation to the postMessage listener (check `event.origin` against trusted domains)
- Implement visual indicators (e.g., prominent badge, page overlays) when logging is active to prevent users from forgetting it's enabled
- Consider adding domain whitelisting/blacklisting to prevent logging on sensitive sites
- Add clear warnings in the extension UI about data privacy implications
