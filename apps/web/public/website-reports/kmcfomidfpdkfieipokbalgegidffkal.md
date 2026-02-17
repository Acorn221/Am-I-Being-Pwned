# Vulnerability Report: Enpass Password Manager

## Metadata
- **Extension ID**: kmcfomidfpdkfieipokbalgegidffkal
- **Extension Name**: Enpass Password Manager
- **Version**: 6.11.10
- **Users**: Unknown (popular password manager)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Enpass Password Manager is a legitimate browser extension that provides password autofill functionality by communicating with the Enpass desktop application via native messaging. The extension intercepts WebAuthn/passkey API calls to allow Enpass to manage passkeys alongside passwords. While static analysis flagged a postMessage handler without explicit origin validation, examination reveals this is mitigated by an HTTPS-only check that prevents most practical attacks. The extension uses broad permissions appropriate for a password manager, including host access to all URLs and native messaging to communicate with the desktop app.

The extension's architecture relies on the desktop application as the source of truth for credential storage, with the browser extension acting as a bridge. No external telemetry or data exfiltration to third-party servers was detected beyond a Google Forms uninstall survey URL.

## Vulnerability Details

### 1. MEDIUM: Incomplete Origin Validation on postMessage Handlers

**Severity**: MEDIUM
**Files**: injected/scripts/webauthnInterceptor.js
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The extension intercepts the browser's native `navigator.credentials.create()` and `navigator.credentials.get()` APIs to allow Enpass to handle passkey creation and authentication. These interceptors use `window.addEventListener("message")` to receive responses from the content script after user interaction. The static analyzer flagged two instances where postMessage handlers lack explicit origin checks:

```javascript
window.addEventListener('message', l)
```

Within the handler `l`, validation occurs but relies on comparing `window.origin` with the payload origin:

```javascript
const p = d?.origin,
      g = p && p === window.origin;
if (d?.uuid && l === d?.uuid && 'passkey_authentication_intercepted_response' === a && g) {
```

**Evidence**:
Lines 41-67 and 99-117 in `webauthnInterceptor.js` show the pattern where messages are filtered by:
1. UUID matching (prevents replay attacks from different calls)
2. Command type matching
3. Origin matching (`p === window.origin`)

However, the critical mitigation is an HTTPS-only check at line 151-156:

```javascript
function a(e) {
  try {
    return 'https:' === new URL(e).protocol
  } catch {
    return !1
  }
}
```

This function `a()` is called at lines 44 and 97 to validate that `window.origin` uses HTTPS before processing passkey operations. If the page is not HTTPS, the interceptor calls the browser's native method instead.

**Verdict**:
While the postMessage handlers don't validate `event.origin` directly, the HTTPS-only enforcement significantly reduces attack surface. An attacker would need to compromise an HTTPS page the user is visiting to inject malicious postMessage events, rather than using a simple MITM attack on HTTP. This is a defense-in-depth weakness rather than a directly exploitable vulnerability. The UUID matching also prevents trivial message injection.

**Risk**: MEDIUM (incomplete defense-in-depth, but practical exploitation requires compromising HTTPS context)

## False Positives Analysis

### Native Messaging Usage
The extension requires `nativeMessaging` permission to communicate with the Enpass desktop application. This is the expected architecture for a password manager that stores credentials locally rather than in the cloud. The extension does not directly store sensitive data - it acts as a UI bridge to the native app.

### Broad Host Permissions
Host permissions for `http://*/*` and `https://*/*` are required for a password manager to function across all websites where users need to autofill credentials. This is standard practice for legitimate password managers.

### WebAuthn API Interception
The interception of `CredentialsContainer.prototype.create` and `CredentialsContainer.prototype.get` is intentional functionality to allow Enpass to manage passkeys. The extension modifies the prototype to insert itself in the authentication flow, which appears malicious in static analysis but is legitimate for a credential manager.

### Cryptographic Libraries
The extension bundles SJCL (Stanford JavaScript Crypto Library), SRP (Secure Remote Password), and other crypto primitives. These are used for secure communication with the desktop app, not for malicious purposes.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.enpass.io | Homepage/documentation link | None detected | None |
| docs.google.com/forms (uninstall survey) | User feedback collection on uninstall | Potentially browser/extension info | Low - standard practice |

No data exfiltration endpoints detected. No analytics or telemetry frameworks identified.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
Enpass Password Manager is a well-known commercial password manager with a legitimate business model. The extension follows expected patterns for password manager extensions:

1. Native messaging for communication with desktop app
2. Content script injection on all pages for autofill
3. WebAuthn API interception for passkey management
4. Local storage usage for settings/cache

The single identified vulnerability (incomplete postMessage origin validation) is mitigated by HTTPS-only enforcement and UUID matching. While this represents incomplete defense-in-depth, it does not constitute a high-severity security issue. The extension does not exhibit data exfiltration, hidden network communication, or other malicious behaviors.

**Recommendations for Users**:
Continue using as intended. The extension is safe for managing passwords when used with the official Enpass desktop application.

**Recommendations for Developers**:
Add explicit `event.origin` validation in postMessage handlers to strengthen defense-in-depth:

```javascript
window.addEventListener('message', (event) => {
  if (event.origin !== window.origin) return;
  // ... existing handler logic
});
```
