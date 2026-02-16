# Security Analysis: Password Manager Pro

| Field | Value |
|-------|-------|
| Extension ID | `hfdkpbblioghdghhkdppipefbchgpohn` |
| Version | 3.0.1.0 |
| Manifest Version | 3 |
| Users | ~90,000 |
| Risk | **LOW** |
| Date | 2026-02-09 |

## Summary

Legitimate ManageEngine Password Manager Pro enterprise extension with broad permissions justified by its password management and autofill functionality; minor XSS risk from innerHTML usage with server-sourced formParams in auto-logon.

## Vulnerabilities

### VULN-01: innerHTML Injection via Server-Sourced formParams [MEDIUM]

**Files:** `js/cs/dom_utils.js:11`, `js/cs/initialize_cs.out.js:14`

```javascript
static createFromAndSubmit(resourceUrl, formParams) {
    var form = document.createElement('form');
    form.name = "PMP_InvokeUrl";
    form.id = "PMP_InvokeUrlForm";
    form.action = resourceUrl;
    form.method = "POST";

    document.body.appendChild(form);
    form.innerHTML = formParams;
    // ...
    document.getElementById('PMP_InvokeUrlForm').submit();
}
```

**Analysis:** The `createFromAndSubmit` method injects `formParams` directly into a form element via `innerHTML`. The `formParams` value originates from login details stored in the background script (`autoLoginData`), which are populated from the popup when a user initiates auto-logon. While this data comes from the user's own PMP server (not arbitrary web content), a compromised or malicious PMP server could inject arbitrary HTML/JavaScript into the page context via this path. The `resourceUrl` used as the form action is also server-sourced. This is mitigated by the fact that this only executes when the user is authenticated to their own enterprise PMP server and the URL matches the configured resource.

**Verdict:** MEDIUM -- Server-sourced data injected via innerHTML into content script context; exploitable only if the user's PMP server is compromised.

---

### VULN-02: Cookie Access for Session Management [LOW]

**Files:** `js/popup.js:1134`, `js/popup.js:5061`, `js/popup.js:7720`

```javascript
chrome.cookies.get({"url": server, "name": "pmpcc"}, function(cookie) {
    hiddenField.setAttribute("value", cookie.value);
});

chrome.cookies.get({ url: server, name: "JSESSIONIDSSO" }, function(cookie) {
    callback(!!(cookie && cookie.value));
});
```

**Analysis:** The extension reads specific cookies (`pmpcc`, `JSESSIONIDSSO`) from the user-configured PMP server URL. These are used for SSO detection and session management with the PMP server. The cookie access is scoped to the PMP server domain only, not arbitrary sites. This is expected behavior for a password manager that integrates with its own backend server.

**Verdict:** LOW -- Cookie access is narrowly scoped to the PMP server domain for legitimate session management.

---

### VULN-03: Web Accessible Resources with All URLs Match [LOW]

**Files:** `manifest.json:57-71`

```json
"web_accessible_resources": [
    {
        "resources": [
            "images/pmp_16x16.png",
            "css/autofill.css",
            "images/loading.gif",
            "html/save_password.html",
            "html/autofill.html*"
        ],
        "matches": [
            "https://*/*",
            "http://*/*"
        ],
        "use_dynamic_url": true
    }
]
```

**Analysis:** The extension exposes several resources (images, CSS, HTML pages) as web-accessible to all HTTP/HTTPS origins. This could theoretically allow any website to fingerprint the extension's presence by probing these resource URLs. However, the `use_dynamic_url: true` flag mitigates this by generating random URLs that change per session, making fingerprinting significantly harder. The exposed resources are limited to UI assets (icons, autofill CSS, save password UI), not executable scripts.

**Verdict:** LOW -- Web accessible resources exposed to all URLs, but `use_dynamic_url` significantly mitigates fingerprinting risk.

---

## Flags

| Category | Evidence |
|----------|----------|
| xss | `js/cs/dom_utils.js:11`: Server-sourced `formParams` injected via `form.innerHTML` in content script |
| cookie_harvesting | `js/popup.js:1134,5061,7720`: Reads `pmpcc` and `JSESSIONIDSSO` cookies from PMP server domain |
| war_js_html_all_urls | `manifest.json`: Web accessible resources (images, CSS, HTML) matched to `http://*/*` and `https://*/*` |

## Endpoints

| Domain | Purpose | Data Sent |
|--------|---------|-----------|
| `https://{user-configured-server}/api/json/auth` | Authentication (login) | Username, password, domain, auth mode |
| `https://{user-configured-server}/api/json/firstauth` | First-factor authentication | Username, password, captcha |
| `https://{user-configured-server}/api/json/request` | API operations (password retrieval, resource listing, search, audit, logout) | Auth token, session ID, operation-specific data |
| `https://{user-configured-server}/restapi/json/v1/` | REST API (passwords, personal accounts, resources, TOTP, session recording, server status) | Auth token, session ID, resource IDs, account details |

## Data Flow

This extension is ManageEngine Password Manager Pro (PMP), an enterprise privileged access management (PAM) product. The data flow is entirely between the browser extension and the user's own self-hosted PMP server:

1. **Configuration**: User configures their PMP server hostname via the popup UI. The server name is stored in `chrome.storage.local`.

2. **Authentication**: User logs in through the popup with username/password (optionally with 2FA). The server returns an auth token and session ID, stored in `chrome.storage.session`.

3. **Autofill**: When a web page loads, the content script (`initialize_cs.out.js`) sends the current URL to the background script. The background script queries the PMP server for matching resources/accounts. If credentials are found, they are autofilled into detected login forms.

4. **Password Save**: When the user submits a login form on a website, the extension detects the username/password and offers to save them to the PMP server.

5. **Session Recording** (PAM360 only, disabled in PMP builds): The extension supports web session recording for privileged access auditing, using `getDisplayMedia` to capture screen content and uploading video chunks to the PMP server.

6. **No third-party endpoints**: All API calls go exclusively to the user-configured PMP server (`https://{serverName}/...`). There are no hardcoded external domains, no analytics SDKs, no telemetry endpoints, and no data exfiltration.

7. **Credential handling**: Passwords retrieved from the server are passed through `chrome.runtime.sendMessage` to the content script for autofill. They are never stored persistently; only the auth token and session ID persist in `chrome.storage.session` (cleared on logout/timeout).

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| innerHTML usage in popup | `js/popup.js` (lines 4504, 6700) | SVG timer circle injection using hardcoded static SVG strings, no user data |
| innerHTML in alertBox | `js/cs/autofill.js:312`, `js/cs/initialize_cs.out.js:1531` | Static HTML template for session recording consent dialog using i18n strings and extension-internal image URLs |
| innerHTML in popup list clearing | `js/popup/DomainAccountLoginUI.js`, `js/popup/ResourceAutologonController.js` | Setting `innerHTML = ""` to clear list contents |
| jQuery innerHTML usage | `js/jquery-3.1.0.min.js` | Standard jQuery 3.1.0 library, not extension-specific code |
| browsingData.remove (cookies) | `js/bg/web_session_recording.js:429-441` | Used exclusively for cleaning up browsing data after privileged session recording ends; scoped to specific recording URLs |
| Clipboard access | `js/bg/offscreen.js:83-115` | Clipboard copy/paste used for password clipboard management with configurable auto-clear timeout |

## Overall Risk: LOW

Password Manager Pro is a legitimate enterprise password management product by ManageEngine (Zoho Corporation). The extension's broad permissions (`cookies`, `tabs`, `clipboardRead/Write`, all-URLs host permissions) are fully justified by its core password management, autofill, and privileged session recording functionality.

Key observations:
- **No malicious behavior detected**: All network calls go to the user-configured PMP server. There are no hardcoded external domains, no analytics/tracking SDKs, no data exfiltration to third parties.
- **No obfuscation**: Code is clean, well-structured ES6 modules with clear class hierarchy. No minification beyond jQuery.
- **No dynamic code execution**: No `eval()`, no `new Function()`, no dynamic script injection. The only `innerHTML` usage of concern is the `formParams` injection which requires server compromise to exploit.
- **Session recording is disabled for PMP**: The `BuildChecks.webSessionRecordingCheck()` returns `false` for PMP builds (only enabled for PAM360 with build >= 7400), so the screen recording functionality is inert in this extension.
- **Proper security practices**: Auth tokens stored in session storage (not local), auto-logout via alarms, clipboard auto-clear, iframe token validation.

The single medium-severity finding (innerHTML with server-sourced data) is a defense-in-depth concern rather than an actively exploitable vulnerability, as it requires the user's own PMP server to be compromised. The low rating reflects that while the extension has wide permissions, its behavior is entirely consistent with its stated purpose.
