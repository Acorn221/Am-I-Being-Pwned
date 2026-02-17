# Vulnerability Report: Scrible Extension

## Metadata
- **Extension ID**: lijhjhlnfifgoabbihoobnfapogkcjgk
- **Extension Name**: Scrible Extension
- **Version**: 2.0.7
- **Users**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Scrible Extension is a legitimate web annotation and research tool that communicates with www.scrible.com to provide annotation, bookmarking, and research features. The extension contains multiple instances of postMessage handlers that accept messages without proper origin validation, creating potential attack vectors for cross-site scripting and unauthorized command injection. While the extension appears to be benign in its intended functionality and only communicates with its own service at scrible.com, the lack of origin checks on message handlers represents a significant security vulnerability that could be exploited by malicious web pages.

## Vulnerability Details

### 1. MEDIUM: Unvalidated postMessage Handlers

**Severity**: MEDIUM
**Files**: content-scripts/general-web-content-script.js, content-scripts/sign-in-connector.js, pdf-loader-iframe.js, page-capture-helper-iframe.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension registers multiple window.addEventListener("message") handlers across four different files without properly validating the origin of incoming messages. This allows any web page to send arbitrary messages to these handlers and potentially trigger unintended functionality.

**Evidence**:

1. **general-web-content-script.js (line 1711)**:
```javascript
window.addEventListener("message", function (message) {
  let payloadData = message.data;
  try {
    if (typeof payloadData === 'string') payloadData = JSON.parse(payloadData)
  } catch (e) {
    return;
  }
  if(!payloadData) return;

  if (payloadData.skribel__method === "loadPdfData") {
    transferPdf(payloadData.pdfUrl, payloadData.requestId);
  } else if (payloadData.skribel__method === 'redirectToSavedPage') {
    if(payloadData.url && payloadData.url.indexOf("https://@@TARGET_HOST@@/") === 0) {
      window.location.href = payloadData.url;
    }
  }
  // ... additional handlers
});
```

2. **sign-in-connector.js (line 1339)**:
```javascript
window.addEventListener("message", async function (message) {
  var payloadData = message.data;
  try {
    if (typeof payloadData === 'string') payloadData = JSON.parse(payloadData)
  } catch (e) {
    return;
  }
  if (payloadData.skribel__method === "newAppTokenRequest") {
    // Handles authentication token requests
  }
});
```

3. **page-capture-helper-iframe.js (line 1515)**:
```javascript
window.addEventListener("message", async function (message) {
  var payloadData = message.data;
  // ...
  let originUrl = new URL(message.origin);
  //TODO: should probably do some sort of authentication this message is from the content script

  if (payloadData.skribel__method === "downloadFile") {
    await downloadFile(payloadData.url, payloadData.response_message);
  } else if (payloadData.skribel__method === "initiatePageCapture") {
    initiatePageCapture(payloadData.url, payloadData.title, payloadData.rawHtml);
  }
});
```

4. **pdf-loader-iframe.js (line 1469)**: Similar pattern without origin validation.

**Verdict**: While these handlers check for specific method names (e.g., `skribel__method`), they do not validate `message.origin`. The page-capture-helper-iframe.js file even contains a TODO comment acknowledging this security gap. A malicious webpage could craft messages matching the expected format to trigger these handlers. However, the actual exploitability is reduced by some internal validation (e.g., the redirectToSavedPage checks for specific URL patterns).

## False Positives Analysis

1. **Not obfuscated**: The static analyzer flagged this extension as "obfuscated," but the code is actually well-formatted JavaScript using the webextension-polyfill library and standard bundling practices. The code is readable and appears to be minified but not intentionally obfuscated.

2. **Legitimate authentication flow**: The extension's token management system (APP_TOKEN, AUTH_TOKEN) is part of a standard OAuth-style authentication flow with scrible.com and is not malicious credential harvesting.

3. **Error reporting**: The reportException function sends error details to scrible.com for debugging purposes. This is disclosed in the extension's privacy policy and is standard practice for production applications.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://www.scrible.com/api/authentication/app_token_request_exchange | Initial app token request | Installation UID, version | Low - Authentication |
| https://www.scrible.com/api/authentication/app_auth_token_request | Request auth token | App token | Low - Authentication |
| https://www.scrible.com/api/authentication/renew_app_token | Token renewal | App token, version, install UID | Low - Authentication |
| https://www.scrible.com/api/account/information | Check sign-in status | Auth token | Low - Session validation |
| https://www.scrible.com/api/account/sign_out | Sign out | Auth token | Low - Session termination |
| https://www.scrible.com/api/entry/lookup/{md5} | Lookup saved annotations | URL MD5 hash, auth token | Low - Core functionality |
| https://www.scrible.com/beta/ajax/extension_error_report | Error reporting | Error details, current URL, stack trace | Low - Telemetry |
| https://www.scrible.com/beta/ajax/get_extension_uid | Get extension UID | Browser vendor, version | Low - Installation tracking |

All endpoints are HTTPS and communicate exclusively with www.scrible.com, which is the legitimate service domain for this extension.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: The Scrible Extension is a legitimate productivity tool with a real user base of 400,000 users. It does not engage in hidden data exfiltration, credential theft, or other malicious behavior. However, it contains a significant architectural vulnerability in the form of unvalidated postMessage handlers across multiple components. These handlers could potentially be exploited by malicious websites to trigger unintended actions, though the actual impact is limited by internal validation logic.

The extension appropriately:
- Uses HTTPS for all communications
- Restricts host permissions to scrible.com and necessary <all_urls> for its annotation functionality
- Implements proper CSP (though connect-src is set to *)
- Does not access sensitive APIs like cookies, webRequest, or downloads beyond its stated purpose
- Clearly discloses its data collection practices

The primary concern is the architectural flaw in message handling, which represents a real security risk that should be addressed by the developer. This vulnerability prevents a "LOW" or "CLEAN" rating, but the lack of actual malicious intent or behavior prevents escalation to "HIGH" or "CRITICAL."

**Recommendation**: The developers should implement proper origin validation in all postMessage event listeners, checking that `message.origin` matches expected extension or scrible.com origins before processing any message data.
