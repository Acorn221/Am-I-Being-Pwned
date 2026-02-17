# Security Analysis: Sticky Password manager & safe

| Field | Value |
|-------|-------|
| Extension ID | `bnfdmghkeppfadphbnkjcicejfepnbfe` |
| Version | 8.9.4.1339 |
| Manifest Version | 3 |
| Users | ~90,000 |
| Risk | **LOW** |
| Date | 2026-02-09 |

## Summary

Legitimate password manager with minor postMessage origin validation gaps in cross-origin frame communication; no malicious behavior detected.

## Vulnerabilities

### VULN-01: postMessage with wildcard origin in cross-origin frame communication [Low]

**Files:** `spContent.js:1731`, `spContent.js:1760`, `spContent.js:1940`, `spContent.js:2017`, `spContent.js:2228`, `spAutofillCore.js:6608`, `spAutofillCore.js:6766`

```javascript
// spContent.js:1731 - sending to cross-origin child frame
frameWindow.postMessage(frameMessage, '*');

// spContent.js:1940 - sending configuration back to window
AWindow.postMessage(resultMessage, '*');

// spAutofillCore.js:6608
AWindow.postMessage(message, '*');

// spAutofillCore.js:6766
window.top.postMessage(message, '*');
```

**Analysis:** The extension uses `postMessage` with `'*'` as the target origin in several places when communicating between cross-origin frames (parent-child iframe communication for autofill). This is a common pattern for password managers that need to communicate across cross-origin iframes for form filling. The messages sent contain internal autofill data (screen position coordinates, DOMXml fragments, password manager configuration). The `wndOnMessage` handler in spContent.js:1893 does validate incoming messages using an `AccessID` check (`message.AccessID != spWindowMessageAccessID`), which provides a weak form of authentication. However, this AccessID is generated per-session and shared across frames, reducing the risk. The newer `spWindowTransport` class (used for WebAuthn and cross-origin visibility queries) uses `MessageChannel` ports instead of broadcast, and validates sender IDs, which is more secure. The wildcard usage is limited to the legacy cross-origin frame autofill communication path. No sensitive credential data (passwords, usernames) is sent via these wildcard postMessages -- only structural form information and UI coordinates.

**Verdict:** Low -- Cross-origin postMessage with wildcard origin is used for internal frame communication only; messages are filtered by AccessID and contain only structural autofill metadata, not credentials.

---

### VULN-02: Web Accessible Resources with `<all_urls>` match [Low]

**Files:** `manifest.json:17-23`

```json
"web_accessible_resources": [
   {
      "matches": ["<all_urls>"],
      "resources": ["spFormElementPrototypeEx.js","spWebAuthnPageScript.js"],
      "extension_ids": []
   }
]
```

**Analysis:** Two JavaScript files are exposed as web accessible resources to all URLs. `spFormElementPrototypeEx.js` hooks `HTMLFormElement.prototype.submit` to dispatch a custom `sp_submit` event (used to detect form submissions for autofill). `spWebAuthnPageScript.js` intercepts `navigator.credentials.create` and `navigator.credentials.get` to provide passkey/WebAuthn support through the password manager. Both scripts self-remove from the DOM after 1500ms. These WARs could theoretically be used for extension fingerprinting (any page can try to load these resources to detect if Sticky Password is installed). However, the scripts themselves contain no sensitive data and their behavior is limited to their intended autofill/WebAuthn purposes.

**Verdict:** Low -- Standard password manager pattern; WAR fingerprinting risk is minimal for a well-known commercial product.

---

## Flags

| Category | Evidence |
|----------|----------|
| postmessage_no_origin | `spContent.js:1731,1760,1940,2017,2228`: Cross-origin frame autofill communication uses `postMessage(msg, '*')` |
| war_js_html_all_urls | `manifest.json`: `spFormElementPrototypeEx.js` and `spWebAuthnPageScript.js` exposed to `<all_urls>` |

## False Positives

| Pattern | Reason |
|---------|--------|
| `HTMLFormElement.prototype.submit` hook in `spFormElementPrototypeEx.js` | Standard password manager technique to detect form submissions for credential saving |
| `navigator.credentials.create/get` override in `spWebAuthnPageScript.js` | Standard passkey/WebAuthn integration for password manager functionality |
| `chrome.management.uninstallSelf` in `spUninstall.js` | Only used to self-uninstall when triggered by the desktop app; does not enumerate or control other extensions |
| `chrome.privacy.services` usage in `spPrivacyServices.js` | Disables Chrome's built-in password saving to avoid conflicts; standard behavior for password managers |
| `innerHTML` usage in `spUninstall.js`, `spProtocolIncompatible.js` | Only sets content from `chrome.i18n.getMessage()` (trusted localization strings), not user input |
| `window.addEventListener('message', ...)` in `spContent.js` | Validates messages with `AccessID` check; processes only known action types |
| `WebSocket` to `ws://127.0.0.1` in `spTransport.js` | Local-only WebSocket connection to the Sticky Password desktop application (native host communication) |
| `forge.min.js` postMessage with `'*'` | Internal forge.js library async scheduling, not extension communication |

## Endpoints

| Domain | Purpose | Data Sent |
|--------|---------|-----------|
| `ws://127.0.0.1:{port}` | WebSocket transport to local Sticky Password desktop app | Autofill protocol messages (DOMXml, form data, credentials via encrypted channel) |
| `https://www.stickypassword.com` | Post-install landing page and applink redirect | UI language, host existence flag |

## Data Flow

The extension operates as a bridge between web pages and the locally-installed Sticky Password desktop application. The data flow is:

1. **Content scripts** (`spContent.js`) run on all HTTP/HTTPS pages, monitoring form focus events and collecting DOM structure (form elements, input types, positions) into an XML representation.

2. **Background script** (`spBackground.js`) connects to the native Sticky Password desktop application via `chrome.runtime.connectNative('com.sticky_password')` (Native Messaging Host). It also supports a WebSocket fallback to `ws://127.0.0.1:{port}`.

3. **Transport Protocol** (`spTransportProtocol.js`) handles authentication between the extension and desktop app using a key exchange protocol (ELSv3/EAv2) with encrypted communications via forge.js (RSA/AES).

4. **Autofill flow**: Content script collects form structure -> sends to background -> background forwards to desktop app via encrypted transport -> desktop app returns credentials -> background sends autofill commands back to content script -> content script fills form fields.

5. **WebAuthn/Passkey flow**: Page script intercepts `navigator.credentials` calls -> sends to content script via MessageChannel ports -> content script forwards to background -> background sends to desktop app -> response flows back to page.

6. **Privacy management**: On install, the extension disables Chrome's built-in password manager, address autofill, and credit card autofill via `chrome.privacy.services` API.

7. **No remote server communication**: The extension does NOT communicate with any remote servers for data processing. All credential storage and management happens locally through the desktop application. The only external URL accessed is `stickypassword.com` for the post-install landing page.

## Overall Risk: LOW

This is a legitimate, well-structured password manager extension from Lamantine Software (established 2001). The code is clean, well-commented, and follows standard password manager patterns. Key observations:

- **No malicious behavior**: No data exfiltration, no remote config, no ad injection, no tracking SDKs, no extension enumeration.
- **Local-only architecture**: All sensitive operations occur through the locally-installed desktop application via Native Messaging or local WebSocket. No credentials ever leave the local machine through the extension.
- **Encrypted transport**: The communication protocol between extension and desktop app uses key exchange and encryption (RSA/AES via forge.js).
- **Minimal permissions**: Only `privacy`, `tabs`, `storage`, `notifications`, and `nativeMessaging` -- all justified for a password manager.
- **No host permissions**: Content scripts use `http://*/*` and `https://*/*` matches (standard for autofill), but there are no host permissions in the manifest.
- **Strong CSP**: `script-src 'self'; object-src 'self'` -- no unsafe-inline or unsafe-eval.
- The two low-severity findings (wildcard postMessage in cross-origin frames and WAR fingerprinting) are standard patterns for password managers and do not pose meaningful security risks.
