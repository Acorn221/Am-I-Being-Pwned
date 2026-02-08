# NordPass Password Manager Security Analysis

## Metadata
- **Extension Name**: NordPass® Password Manager & Digital Vault
- **Extension ID**: eiaeiblijfjekdanodkjadfinkhbfgcd
- **Version**: 7.3.13
- **Users**: ~6,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

NordPass is a legitimate password manager extension from NordSecurity (makers of NordVPN). The extension implements comprehensive password management functionality including autofill, passkey support, form field classification using TensorFlow.js models, and secure vault integration. After thorough analysis of the codebase (~16.9MB of JavaScript), **no malicious behavior, critical vulnerabilities, or suspicious patterns were identified**.

The extension uses appropriate permissions for its functionality, implements proper CSP policies, communicates only with legitimate NordPass infrastructure, and follows security best practices for a password manager. All data handling appears purpose-appropriate for password management.

**Risk Level: CLEAN**

## Vulnerability Analysis

### No Critical or High Severity Issues Found

After comprehensive analysis, no vulnerabilities or malicious patterns were detected.

## Legitimate Functionality Observations

### 1. Passkey Implementation (passkeys.js)
**Severity**: INFORMATIONAL
**Files**: `js/passkeys.js`
**Description**: The extension implements WebAuthn passkey support by proxying browser's `CredentialsContainer.prototype.create()` and `CredentialsContainer.prototype.get()` methods. This allows NordPass to handle passkey creation/authentication requests.

**Code Pattern**:
```javascript
CredentialsContainer.prototype.create = new Proxy(CredentialsContainer.prototype.create, {
  apply(e, t, r) {
    // Intercepts passkey creation requests
    // Sends to NordPass via postMessage
    window.postMessage({type: "PASSKEY/CREDENTIALS_CREATE", ...}, {targetOrigin: window.origin})
  }
})
```

**Verdict**: **LEGITIMATE** - This is expected behavior for a password manager supporting passkeys. The extension provides users an option to use NordPass for passkey storage instead of the browser's built-in credential manager.

---

### 2. Form Classification with TensorFlow.js
**Severity**: INFORMATIONAL
**Files**: `js/classifier.js`, `FieldClassifier/*.json`, `FormClassifier/model.json`
**Description**: Uses TensorFlow.js machine learning models to classify web forms and input fields for intelligent autofill (login forms, credit cards, registration, password reset, etc.).

**Verdict**: **LEGITIMATE** - Modern password managers use ML to accurately detect form types. Models are stored locally in the extension.

---

### 3. HTML Popover Detection (nordpass-script.js)
**Severity**: INFORMATIONAL
**Files**: `js/nordpass-script.js`
**Description**: Monitors HTML Popover API usage by proxying `togglePopover()` and `showPopover()` methods to detect when page shows popovers.

**Code**:
```javascript
HTMLElement.prototype.togglePopover = new Proxy(HTMLElement.prototype.togglePopover, {
  apply(o, e, t) {
    const p = o.apply(e, t);
    return p && window.postMessage({type: "NORDPASS/HTML_POPOVER_SHOWN"}, {targetOrigin: window.origin}), p;
  }
})
```

**Verdict**: **LEGITIMATE** - Allows NordPass UI to properly position/hide its overlay when page uses native popovers.

---

### 4. Extension Detection for Web Panel
**Severity**: INFORMATIONAL
**Files**: `js/ecp-extension-detection.js`
**Description**: Simple message listener that responds to web panel queries asking if extension is installed.

**Code**:
```javascript
window.addEventListener("message", s => {
  i.source && i.origin === window.origin && i.data?.type === "NORDPASS/IS_INSTALLED" &&
    i.data.source === "ECP" && i.source.postMessage({type: "NORDPASS/IS_INSTALLED"}, i.origin)
})
```

**Verdict**: **LEGITIMATE** - Standard extension detection for web-based admin panels (ECP = Enterprise Control Panel).

---

### 5. Redirect Handler for Web App
**Severity**: INFORMATIONAL
**Files**: `js/redirectContent.js`, manifest `content_scripts[1]`
**Description**: Content script running on `nordpass.com/app/*` and `rockycliff.net/app/*` (staging domain).

**Verdict**: **LEGITIMATE** - Handles redirects to extension popup when users navigate to web app URLs.

---

### 6. Sentry Error Reporting
**Severity**: INFORMATIONAL
**Files**: `js/initExtensionSentry.chunk.js`
**Configuration**: DSN points to `debug.nordpass.com/11`
**Sample Rate**: 10% (0.1)

**Code**:
```javascript
const r = new Oo({
  dsn: "https://864218d973b4ad03b12770aea7f6499a@debug.nordpass.com/11",
  environment: "production",
  sampleRate: 0.1,
  release: "7.3.13"
})
```

**Verdict**: **LEGITIMATE** - Standard Sentry SDK integration for crash reporting. Sends to NordPass's own Sentry instance, not third-party.

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| Proxy usage | `passkeys.js`, `nordpass-script.js` | Legitimate interception for passkey support and UI coordination |
| TensorFlow.js references | `classifier.js` | ML-based form field classification (legitimate feature) |
| postMessage calls | Multiple content scripts | Secure communication between isolated content script contexts |
| chrome.storage, chrome.tabs | `background.js` (via polyfill) | Standard extension APIs for password manager functionality |
| WebSocket connections | CSP policy allows `wss://*.nordpass.com:8884/`, `wss://*.nordpass.com:8885/mqtt` | Real-time sync for password vault (MQTT protocol) |

## Permissions Analysis

### Declared Permissions
```json
"permissions": [
  "idle",           // Detect user idle state for auto-lock
  "alarms",         // Scheduled tasks (session timeouts)
  "storage",        // Store encrypted vault data locally
  "tabs",           // Access tab info for autofill context
  "privacy",        // Privacy settings integration
  "contextMenus",   // Right-click menu for autofill
  "offscreen"       // Offscreen documents (MV3 requirement)
]
```

**Verdict**: All permissions are appropriate for a password manager.

### Host Permissions
```json
"host_permissions": [
  "https://api-toggle.nordpass.com/*",
  "https://api-toggle.stag.us.nordpass.com/*",
  "https://lastpass.com/*"
]
```

**Analysis**:
- `api-toggle.nordpass.com` - Feature flag/config endpoint (not found in active code paths)
- `lastpass.com` - Listed in CSP but **not used in code**. Likely for future LastPass import feature.

### Optional Permissions
```json
"optional_permissions": ["clipboardRead", "clipboardWrite"]
```

**Verdict**: User must grant clipboard access separately. Appropriate for password copy/paste.

## API Endpoints

| Domain | Purpose | Active Usage |
|--------|---------|--------------|
| `*.nordpass.com` | Main API/vault sync | Yes (via CSP) |
| `*.npass.app` | CDN/assets | Yes (via CSP) |
| `*.nordbusinessaccount.com` | Business account management | Yes (via CSP) |
| `nl-cs-production-cloud-storage.s3.amazonaws.com` | Cloud storage (file attachments) | Yes (via CSP) |
| `wss://*.nordpass.com:8884/`, `wss://*.nordpass.com:8885/mqtt` | Real-time vault sync (MQTT) | Yes (via CSP) |
| `login.microsoftonline.com`, `graph.microsoft.com` | Microsoft SSO integration | Yes (via CSP) |
| `lastpass.com` | Listed in permissions/CSP | Not found in code |
| `debug.nordpass.com` | Sentry error reporting | Yes (error tracking) |

**Note**: No undeclared endpoints found. All communication goes to legitimate NordPass/NordSecurity infrastructure.

## Content Security Policy

```
connect-src 'self' data: https://*.nordpass.com https://*.npass.app
  https://*.nordbusinessaccount.com https://nl-cs-production-cloud-storage.s3.amazonaws.com/
  https://lastpass.com/ https://login.microsoftonline.com/
  wss://*.nordpass.com:8884/ wss://*.nordpass.com:8885/mqtt
```

**Analysis**: Strict CSP with allowlist of legitimate services. Includes `'wasm-unsafe-eval'` for TensorFlow.js ML models (standard requirement).

## Data Flow Summary

1. **Form Detection**: Content scripts (`content.js`) use TensorFlow.js models to classify login/payment forms
2. **User Interaction**: User clicks NordPass icon overlay on input fields
3. **Credential Retrieval**: Background service worker fetches credentials from local storage (encrypted vault)
4. **Autofill**: Content script injects credentials into detected form fields
5. **Sync**: WebSocket (MQTT) connection to `*.nordpass.com:8885/mqtt` for real-time vault synchronization
6. **Passkeys**: Native WebAuthn API interception allows storing passkeys in NordPass vault
7. **Session Management**: Uses `idle` permission to auto-lock after inactivity

**Privacy Note**: Extension implements strict CSP, excludes itself from own domains (nordpass.com, nordaccount.com), and all data handling aligns with password manager functionality.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

### Justification

NordPass is a **legitimate, well-implemented password manager** from a reputable security company (NordSecurity). The extension:

✅ **No malicious patterns detected**
✅ Uses appropriate permissions for password management
✅ Communicates only with verified NordPass infrastructure
✅ Implements proper Content Security Policy
✅ Uses local machine learning for form classification (no data exfiltration)
✅ Follows security best practices (CSP, permission scoping, manifest v3)
✅ Transparent error reporting (Sentry to own domain)
✅ No third-party analytics, tracking SDKs, or ad injection
✅ No extension enumeration, proxy infrastructure, or obfuscation
✅ Open about functionality (passkey interception clearly disclosed in behavior)

### Invasive But Legitimate Functionality

While the extension requires extensive permissions (`tabs`, `storage`, `privacy`, content scripts on all pages) and intercepts sensitive browser APIs (WebAuthn), this is **expected and necessary** for a password manager to function. The extension:

- **Does not collect data beyond its stated purpose** (password management)
- **Does not phone home with browsing activity** (only syncs encrypted vault data)
- **Does not inject ads or track users**
- **Properly excludes itself from sensitive domains** (own account pages)

### Conclusion

NordPass Password Manager is a **CLEAN** extension that serves its intended purpose without malicious behavior or exploitable vulnerabilities. The codebase (~16.9MB) consists primarily of legitimate password management logic, TensorFlow.js for ML-based form detection, and standard extension infrastructure. All "invasive" behaviors (API interception, broad permissions) are transparently part of password manager functionality and align with user expectations.

**Recommendation**: Safe for continued use. No security concerns identified.
