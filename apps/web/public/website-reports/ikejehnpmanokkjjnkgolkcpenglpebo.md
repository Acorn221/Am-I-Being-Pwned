# Vulnerability Report: ブラウザ切替機能２ for Google Workspace™ ＜サテライトオフィス＞

## Metadata
- **Extension ID**: ikejehnpmanokkjjnkgolkcpenglpebo
- **Extension Name**: ブラウザ切替機能２ for Google Workspace™ ＜サテライトオフィス＞
- **Version**: 1.2.0
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15
- **Homepage**: http://www.sateraito.jp/

## Executive Summary

This is a Japanese enterprise tool ("Browser Switching Function 2 for Google Workspace by Satellite Office") designed to automatically open certain URLs in Internet Explorer or other browsers via a native messaging host. The extension monitors navigation events on Google services (Gmail, Calendar) and specific whitelisted domains, then communicates with a native Windows application to launch external browsers when configured URL patterns are detected.

While the extension serves a legitimate enterprise purpose (legacy browser compatibility for internal systems), it exhibits privacy concerns around remote configuration fetching and user data collection. The extension extracts the user's email address from the Gmail DOM, sends it to a remote server (`sateraito-apps-browser.appspot.com`) along with their Google Workspace domain, and downloads URL pattern configurations without clear user consent or disclosure. This behavior, combined with tabs permission and webNavigation monitoring, creates a privacy risk for users who may not understand the data sharing implications.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Remote Configuration and User Email Exfiltration

**Severity**: MEDIUM
**Files**: bsw_c.js, bsw_b.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The content script (`bsw_c.js`) extracts the user's email address from the Gmail interface by querying multiple DOM selectors. It then sends both the email address and Google Workspace domain to a remote server without explicit user notification or consent.

**Evidence**:
```javascript
// bsw_c.js lines 54-108
var n = a.textContent.trim(); // email address extracted
var u = n.split("@");
var r = u[1] || ""; // domain extracted
var h = {
  domain: r,
  email: n
};
// This data is sent via chrome.runtime.sendMessage
```

```javascript
// bsw_b.js lines 1325-1328
function b() {
  var k = "https://sateraito-apps-browser.appspot.com/j/" + a.domain + "?v=2&rk=" + (new Date).getTime();
  a.email && (k += "&oauth2email=" + encodeURIComponent(a.email));
  return k
}
```

The extension fetches configuration data from `sateraito-apps-browser.appspot.com/j/{domain}?oauth2email={email}` and stores it locally. This configuration includes URL patterns that trigger browser switching behavior.

**Verdict**: While this is likely designed for legitimate enterprise IT management, sending user email addresses to external servers without prominent disclosure in the UI is a privacy concern. The extension description only mentions "opening URLs in Internet Explorer" and doesn't clearly disclose data collection.

### 2. MEDIUM: Browser Activity Monitoring and Tab URL Access

**Severity**: MEDIUM
**Files**: bsw_b.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The extension monitors all navigation events via `chrome.webNavigation.onBeforeNavigate` and accesses tab URLs to determine if they match configured patterns for browser switching.

**Evidence**:
```javascript
// bsw_b.js lines 1442-1449
chrome.webNavigation.onBeforeNavigate.addListener(function(a) {
  return r(function(b) {
    if (1 == b.a) return W("▼▼ BeforeNavigate(): start."), l(b, Y(), 2);
    !0 === va ? (W("BeforeNavigate : " + a.tabId + " / " + a.url), Ya(a)) :
      W("BeforeNavigate : gboolConnectCheckDone === false");
    return l(b, X.m(), 0)
  })
});
```

```javascript
// bsw_b.js lines 881-926 - Ya function checks URLs against patterns
function Ya(a) {
  // Examines a.url and determines if it should be opened in IE/Edge/etc
  var d = Xa(a.url);
  e = d.b
  // If match found, passes URL to native host
}
```

The extension has visibility into all URLs the user navigates to on configured domains (Gmail, Google Calendar, and `sateraito-apps-browser.appspot.com`), plus it queries all open tabs on startup.

**Verdict**: While tab access is necessary for the extension's core functionality, the combination of URL monitoring + remote config + email collection creates a broader privacy footprint than a simple browser switcher would require.

### 3. LOW: Native Messaging Communication

**Severity**: LOW
**Files**: bsw_b.js
**CWE**: CWE-927 (Use of Implicit Intent for Sensitive Communication)

**Description**:
The extension communicates with a native Windows application (`jp.sateraito.browserswitcher`) via Chrome's native messaging API. URLs are passed to the native host for opening in external browsers.

**Evidence**:
```javascript
// bsw_b.js lines 1222-1291
u.h = chrome.runtime.connectNative("jp.sateraito.browserswitcher");
// ...
u.H = function(a, b) {
  u.h && (b || (b = ""), a = {
    command: "ExecIE",
    window_open_param: b,
    url: a
  }, W("postMessage:" + JSON.stringify(a)), u.h.postMessage(a))
};
```

**Verdict**: Native messaging is a documented Chrome API and is necessary for this extension's functionality. However, users must install a separate Windows MSI package, which could potentially introduce additional security risks if the MSI is compromised. The extension shows error messages if the MSI is not installed or is an outdated version (< 2.2.0).

## False Positives Analysis

The static analyzer flagged several data flows that, while technically accurate, are expected for this type of enterprise tool:

1. **chrome.tabs.query → fetch**: This is the extension fetching configuration from the server based on the user's domain. Not inherently malicious, but privacy-concerning without disclosure.

2. **chrome.storage.local.get → fetch**: The extension retrieves stored configuration and may refresh it from the server. This is normal behavior for a remotely-managed enterprise tool.

3. **Message data → fetch**: The options.js page requests status information from the background script. This is legitimate internal communication.

The extension does not appear to contain hidden malicious code, stealer functionality, or command-and-control infrastructure. It appears to be a genuine enterprise IT tool.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://sateraito-apps-browser.appspot.com/j/{domain}` | Configuration download | User email, Google Workspace domain, timestamp | Medium - User PII sent without prominent disclosure |
| `https://sateraito-apps-browser.appspot.com/static/domselectoremail.json` | DOM selector updates | None (GET request) | Low - Just downloads selector patterns |
| `https://sateraito-apps-browser.appspot.com/static/redirect*.html` | Redirect pages | None | Low - Static redirect pages shown when tabs are closed after browser switch |

All endpoints use HTTPS and are hosted on Google App Engine under the `sateraito-apps-browser` application.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This extension serves a legitimate enterprise use case (browser switching for legacy internal applications), but implements it in a way that raises privacy concerns:

**Concerns:**
- Collects and transmits user email addresses to a remote server without clear disclosure in the extension description or UI
- Monitors browsing activity on Google services (Gmail, Calendar)
- Downloads configuration from remote server controlled by vendor
- Accesses all open tabs on startup
- No explicit privacy policy linked in the manifest

**Mitigating Factors:**
- Appears to be a genuine enterprise tool from a Japanese software vendor (Satellite Office)
- Limited scope: only operates on Google domains and specific configured URLs
- Uses native messaging, requiring separate MSI installation (provides some user awareness)
- No evidence of credential theft, ad injection, or other overtly malicious behavior
- Configuration data is validated with MD5 hash to prevent tampering

**Recommendation**: This extension is appropriate for enterprise deployment where IT administrators understand and approve the data collection, but may be concerning for individual users who install it without understanding that their email and domain information will be sent to the vendor's server. The extension description should more clearly disclose data collection practices.
