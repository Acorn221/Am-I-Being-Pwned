# Security Analysis: Bitdefender SecurePass

| Field | Value |
|-------|-------|
| Extension ID | `gcmahhkjkpigcpfpmdjnbiakmbdegfeh` |
| Version | 1.5.0 |
| Manifest Version | 3 |
| Users | ~100,000 |
| Risk | **CLEAN** |
| Date | 2026-02-09 |

## Summary

Legitimate Bitdefender password manager (Psono-based) with broad permissions appropriate for its autofill functionality; telemetry to nimbus.bitdefender.net includes page URLs and form metadata for debugging but no credential exfiltration.

## Vulnerabilities

### VULN-01: Web Accessible Resources Exposed to All Origins [LOW]

**Files:** `manifest.json:75-92`

```json
"web_accessible_resources": [
    {
      "resources": [
        "data/fonts/*.woff2",
        "data/css/contentscript.css",
        "data/img/psono-encrypt.png",
        "data/img/psono-decrypt.png",
        "data/notification-bar.html",
        "data/cc-autofill-notification.html",
        "data/cc-autofill-disabled-notification.html",
        "data/login-rules/*",
        "data/unlock-with-pin.html"
      ],
      "matches": [
        "*://*/*"
      ]
    }
  ]
```

**Analysis:** The extension exposes several HTML pages, CSS, fonts, images, and login rule JSON files as web-accessible resources to all origins. This allows any website to detect the presence of this extension via resource probing (e.g., fetching `chrome-extension://<id>/data/notification-bar.html`). The exposed resources are UI components (notification bars, PIN unlock) and static assets -- they do not contain sensitive data or executable logic that could be exploited. The login-rules files contain CSS selectors for form detection, which is non-sensitive metadata.

**Verdict:** LOW -- Extension fingerprinting is possible, but the exposed resources contain no sensitive data and pose no direct exploitation risk.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `eval("require('crypto')")` | `background-chrome.js:3030`, `background-chrome.js:52106` | Standard Node.js crypto library shimming in bundled code (tweetnacl/sjcl pattern). Conditional on Node.js environment, never executes in browser context. |
| `new Function("return this")()` | `background-chrome.js:53416` | Standard webpack/library pattern for obtaining global `this` reference. Not dynamic code execution. |
| `new Function("appliers", "row", ...)` | `bundle.min.js:124387` | MUI DataGrid filter compilation. Standard library code for data grid filtering. |
| `innerHTML` in dropdown menus | `worker-content-script.js:471`, `worker-content-script-elster.js:68` | Content is sanitized through `innerText -> innerHTML` encoding (function `L()` at line 172). Dropdown content is generated from vault entries, not from untrusted external input. |
| `innerHTML` in jQuery | `lib/jquery.min.js` (multiple) | Standard jQuery library internals. |
| `innerHTML` in DOMPurify | `background-chrome.js:7401-7537` | DOMPurify sanitization library. This is a security tool, not a vulnerability. |
| `chrome.management.uninstallSelf()` | `background-chrome.js:1213` | Only uninstalls the extension itself (user-triggered account deletion flow). Does NOT enumerate or disable other extensions. |
| `chrome.privacy.services.passwordSavingEnabled` | `background-chrome.js:894,1172` | Standard password manager behavior: checks if it can disable the browser's built-in password manager to avoid conflicts. |
| `keydown`/`keyup`/`keypress` listeners | `worker-content-script.js:203,577,849` | Form submit detection (Enter key on Google login), input event simulation for autofill, and keyboard shortcut (Ctrl+Shift+L). Not keylogging. |
| `window.open` | `background-chrome.js:1060` | Opens extension UI in new window. Standard behavior. |
| `postMessage` usage | `background-chrome.js` (multiple) | BroadcastChannel and Web Worker communication for internal extension messaging. No cross-origin postMessage without origin validation. |

## Flags

| Category | Evidence |
|----------|----------|
| war_js_html_all_urls | `manifest.json`: HTML pages (notification-bar.html, cc-autofill-notification.html, unlock-with-pin.html) and login-rules/* exposed to all origins via web_accessible_resources |

## Endpoints

| Domain | Purpose | Data Sent |
|--------|---------|-----------|
| securepass-api.bitdefender.com | Primary password vault API | Encrypted vault data, authentication tokens, device fingerprint |
| nimbus.bitdefender.net | Bitdefender telemetry/analytics (Karma) | Feature usage events, autofill debugging data (URLs, page titles, form HTML, input field metadata), device fingerprint, extension version |
| login.bitdefender.com | Bitdefender SSO authentication | OAuth/SSO credentials flow |
| securepass-auth.bitdefender.com | Loki authentication service | Authentication tokens |
| securepass.bitdefender.com | Web app companion | N/A (link target) |
| securepass-overflow-proxy.bitdefender.com | Overflow proxy for large payloads | Encrypted data chunks |
| securepass-cache.bitdefender.com | CDN for cached resources | N/A (read-only) |
| keyserver.ubuntu.com | PGP key server for GPG features | PGP public key lookups |
| www.psono.pw | Psono project verification | N/A (config default URL) |

## Data Flow

Bitdefender SecurePass is a password manager built on the open-source Psono platform, customized and branded by Bitdefender. All credential data follows an end-to-end encryption model:

1. **Credential capture**: Content scripts detect login forms on all pages using CSS selectors (fetched from cached login-rules or fallback defaults). When a user submits a login form, the username and password values are captured from the DOM and sent via `chrome.runtime.sendMessage` to the background service worker.

2. **Vault storage**: Credentials are encrypted client-side using tweetnacl/sjcl cryptographic libraries before being sent to `securepass-api.bitdefender.com`. The encryption key is derived from the user's master password, which never leaves the client.

3. **Autofill**: When visiting a page with a matching saved credential, the extension fills form fields using React-style value setter injection and dispatches synthetic DOM events to trigger framework change handlers.

4. **Telemetry**: The extension sends product analytics to `nimbus.bitdefender.net/karma/input` via JSON-RPC. This includes:
   - Feature usage events (password import, master password setup, etc.)
   - Autofill debugging data when autofill issues occur, which can include: full URL, domain, page title, form HTML (truncated to 2KB), input field metadata (type, name, id, placeholder, autocomplete attributes), and device fingerprint.
   - **No credentials or vault contents are included in telemetry.**

5. **Authentication**: Users authenticate via Bitdefender SSO (`login.bitdefender.com`) or direct Psono-style authentication. OAuth flows use `chrome.identity` or a custom window-based auth flow.

6. **Security scanning**: The extension can check saved passwords against breach databases (HaveIBeenPwned integration) -- password hashes are sent, not plaintext passwords. Before sending, username and password fields are explicitly deleted from the summary data.

## Overall Risk: CLEAN

Bitdefender SecurePass is a legitimate, well-structured password manager from a major security vendor. While it requests broad permissions (`http://*/*`, `https://*/*`, `tabs`, `webRequest`, `privacy`, `clipboardWrite`), these are all standard and necessary for a password manager that needs to:

- Detect and autofill login forms on any website (host permissions, content scripts on `*://*/*`)
- Disable the browser's built-in password manager to avoid conflicts (`privacy`)
- Copy passwords to clipboard (`clipboardWrite`)
- Handle HTTP authentication prompts (`webRequest`, `webRequestAuthProvider`)
- Track active tabs for autofill context (`tabs`)

The telemetry to Nimbus includes page URLs and form metadata for debugging autofill issues, which is a common practice for password managers to improve their form detection. Critically, no credentials, vault contents, or sensitive user data are included in telemetry payloads. The code explicitly deletes password and username fields before sending breach scan summaries.

The extension does not exhibit any malicious patterns: no extension enumeration (only `uninstallSelf`), no remote code loading, no XHR/fetch hooking, no ad injection, no affiliate fraud, no keylogging, and no data exfiltration. The eval() and new Function() occurrences are standard library patterns that do not execute in browser context or are standard framework internals (webpack, MUI DataGrid).
