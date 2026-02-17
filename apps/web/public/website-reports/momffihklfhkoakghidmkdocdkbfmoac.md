# Vulnerability Report: Контур.Расширение

## Metadata
- **Extension ID**: momffihklfhkoakghidmkdocdkbfmoac
- **Extension Name**: Контур.Расширение (Kontur.Extension)
- **Version**: 3.2.12
- **Users**: ~3,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Контур.Расширение is a Russian enterprise extension developed for Kontur services, designed to provide cryptographic operations and diagnostics functionality through native messaging. The extension serves as a bridge between web pages and native host applications ("kd.nc" for diagnostics and "kontur.plugin" for cryptographic operations).

The extension has a MEDIUM risk level due to a message injection vulnerability in the content script. While the extension implements domain restrictions for actual native messaging operations (limiting to kontur.ru and testkontur.ru domains), the initial postMessage listener accepts messages from any origin without validation. This could allow malicious web pages to trigger connection attempts or potentially interfere with legitimate communication flows.

## Vulnerability Details

### 1. MEDIUM: postMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: content.js (line 190)
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The content script registers a message event listener on line 190 without validating the origin of incoming messages. While there is a basic check that `event.source == window` (line 166), this only prevents messages from different windows, not messages from malicious scripts running in the same page context.

**Evidence**:
```javascript
// content.js:164-190
function handleMessage(event) {
    var data = event.data;
    if (!data || (event.source != window)) {
        return;
    }

    var request = data.request;
    if (!request) {
        return;
    }

    var type = data.type,
        isNewType = (type === KONTUR_DIAG_REQUEST) || (type === KONTUR_PLUGIN_REQUEST),
        toDiag = (type === KONTUR_DIAG_REQUEST) || (type === DIAG_REQUEST_TYPE),
        toPlugin = (type === KONTUR_PLUGIN_REQUEST) || (type === PLUGIN_REQUEST_TYPE),
        origin = event.origin;

    if (toDiag) {
        request.origin = origin;
        sendDiag(request, isNewType, origin, data.sessionId);
    } else if (toPlugin && request.sessionId) {
        request.hostUri = origin;
        sendPlugin(request, isNewType, origin, request.sessionId);
    }
}

window.addEventListener("message", handleMessage, false);
```

The handler accepts messages with specific type values (`KONTUR_DIAG_REQUEST`, `KONTUR_PLUGIN_REQUEST`, etc.) from any origin. While the actual domain validation happens later in the background script (line 279 in background.js checks `isDiagDomains(request.origin)`), the content script still processes these messages and initiates chrome.runtime.connect() calls.

**Verdict**:
This is a defense-in-depth issue. A malicious script on any webpage could send postMessages to trigger connection attempts. While the background script implements domain whitelisting that should prevent actual access to the native messaging hosts, the lack of origin validation at the entry point creates unnecessary attack surface. An attacker could:
1. Attempt to enumerate extension presence
2. Trigger error messages that reveal extension behavior
3. Potentially interfere with legitimate message flows through race conditions

**Mitigation**: The content script should validate that messages originate only from Kontur domains before processing, rather than relying solely on backend validation.

## False Positives Analysis

### Management API Usage (NOT MALICIOUS)
The extension uses `chrome.management` API to:
- Check for and manage old versions of Kontur extensions (background.js:24-44)
- Enable/disable conflicting extensions (background.js:91-96)
- Subscribe to extension lifecycle events (background.js:66-72)

This is legitimate functionality for an enterprise extension that needs to manage its own ecosystem and prevent conflicts with legacy versions. The extension IDs being checked are all Kontur-owned extensions.

### Native Messaging (LEGITIMATE USE)
The extension connects to two native messaging hosts:
- `kd.nc` - for diagnostics functionality
- `kontur.plugin` - for cryptographic operations (likely digital signatures)

This is the intended purpose of the extension as described in its localized description: "Расширение для сервиса Диагностики и выполнения криптографических операций в сервисах Контура" (Extension for Diagnostics service and performing cryptographic operations in Kontur services).

### Extension Uninstall (STANDARD BEHAVIOR)
The background script closes browser tabs showing the extension's web store page after installation/update (background.js:469-494). This is standard cleanup behavior, not malicious.

### Content Script Reloading (STANDARD PRACTICE)
On installation, the extension reloads its content scripts in all open tabs (background.js:439-467). This is standard practice to ensure the extension works immediately without requiring tab reloads.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | No external network communication detected | N/A | N/A |

The extension communicates only through:
1. Native messaging to local host applications (`kd.nc` and `kontur.plugin`)
2. Internal chrome.runtime messaging between content and background scripts
3. PostMessage between webpage and content script (same-window only)

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

The extension is a legitimate enterprise tool for Russian accounting and business management services (Kontur/SKB Kontur). It serves 3 million users and provides necessary cryptographic and diagnostics functionality through native messaging.

The MEDIUM risk rating is based solely on the postMessage handler vulnerability (CWE-346). While the backend implements proper domain restrictions (limiting access to kontur.ru, testkontur.ru, and localhost.testkontur.ru domains), the lack of origin validation at the content script level violates defense-in-depth principles and creates unnecessary attack surface.

**Positive Security Factors**:
- Domain whitelisting implemented in background script (isDiagDomains function)
- HTTPS-only enforcement (except for localhost.testkontur.ru)
- No external network communication
- Legitimate enterprise use case
- Proper session management and cleanup
- MV3 implementation with service worker

**Risk Factors**:
- Missing origin validation in postMessage handler
- Very broad permissions (<all_urls>, management, scripting)
- Large user base (3M) means wider impact if exploited
- Low rating (2.8/5) suggests user friction or concerns

**Recommendation**: The extension should add origin validation to the content script's message handler to match the domain whitelist used in the background script. This would prevent malicious scripts from triggering any extension behavior, even error responses.
