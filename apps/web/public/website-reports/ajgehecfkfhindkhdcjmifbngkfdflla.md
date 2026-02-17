# Security Analysis: Yoti Password Manager

| Field | Value |
|-------|-------|
| Extension ID | `ajgehecfkfhindkhdcjmifbngkfdflla` |
| Version | 1.12.9 |
| Manifest Version | 3 |
| Users | ~5,000 |
| Risk | **LOW** |
| Date | 2026-02-09 |

## Summary

Legitimate password manager with broad permissions expected for its functionality; minor concerns around WAR HTML exposure and webRequest body interception, but no malicious behavior detected.

## Vulnerabilities

### VULN-01: Web Accessible Resources expose HTML templates to all origins [Low]

**Files:** `manifest.json:71-84`

```json
"web_accessible_resources": [
    {
      "resources": [
        "templates/*.html",
        "popup/*.html",
        ...
      ],
      "matches": ["*://*/*"]
    }
]
```

**Analysis:** The extension exposes `templates/*.html` and `popup/*.html` to all origins via `matches: ["*://*/*"]`. This allows any website to detect the extension's presence by probing for these resources. The HTML files themselves contain static UI templates (save-secret, success-bar, warning-bar, popup) and do not include sensitive data. However, the exposure enables extension fingerprinting by any page.

**Verdict:** Low -- WAR HTML accessible to all origins enables fingerprinting but does not expose credentials or executable code.

---

### VULN-02: Cookie access scoped to yoti.com only [Low]

**Files:** `background.js:5961-5977`

```javascript
this.browserEngine.cookies.set(function(e) {
    return {
        name: "YPM",
        url: "https://www.yoti.com",
        secure: !0,
        value: `${e}`,
        expirationDate: (new Date).getTime() / 1e3 + 31536e3
    }
}(e))
// ...
this.browserEngine.cookies.get({
    name: "YPM",
    url: "https://www.yoti.com"
}).then(...)
```

**Analysis:** The extension requests the `cookies` permission (which grants access to all cookies on all domains given the `http://*/*` and `https://*/*` host permissions). However, the actual cookie usage is limited to setting and reading a single cookie named "YPM" on `https://www.yoti.com` to track tutorial completion state. There is no evidence of reading or exfiltrating cookies from other domains. The broad permission scope is typical for MV3 password managers but the actual usage is narrow.

**Verdict:** Low -- The cookies permission is overly broad relative to actual usage (yoti.com only), but no harvesting or exfiltration occurs.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `new Function("return this")()` | `popup/config.js:6`, `background.js:4240`, `content_script.js:11754` | Webpack globalThis polyfill -- standard bundler pattern to detect global scope |
| `innerHTML` assignments | `content_script.js:7283`, `popup/app.js:12672` | React/Preact `dangerouslySetInnerHTML` reconciliation -- framework-internal, not user-controlled |
| `innerHTML` in `tutorial.js:73` | `popup/tutorial.js:73` | Sets hardcoded status title/body from extension's own constant strings, not external input |
| `innerHTML` in `vendor.min.js` | `libs/vendor.min.js` (multiple) | jQuery DOM manipulation internals -- standard library code |
| `innerHTML` in `lottie.min.js` | `popup/lottie.min.js` (multiple) | Lottie animation library internals |
| `eval()` in lottie.min.js | `popup/lottie.min.js:4743` | Lottie expression evaluator for After Effects expressions -- standard lottie feature |
| `XMLHttpRequest` usage | `background.js:3140-3182`, `content_script.js:12447-12496` | Fetch polyfill (whatwg-fetch) -- standard polyfill for older environments |
| `webRequest.onBeforeRequest` with `requestBody` | `background.js:6225-6262` | Password capture on form POST -- core password manager functionality to detect when credentials are submitted |
| `postMessage` usage | `background.js:3304,3915`, `content_script.js:16471+` | SockJS transport (background) and chrome.runtime.Port messaging (content script) -- standard extension IPC |

## Flags

| Category | Evidence |
|----------|----------|
| war_js_html_all_urls | `manifest.json`: `templates/*.html` and `popup/*.html` accessible to all origins via `matches: ["*://*/*"]` |
| cookie_harvesting | `background.js:5961-5977`: Uses `cookies` permission (broad scope) but only accesses a single "YPM" cookie on yoti.com |

## Endpoints

| Domain | Purpose | Data Sent |
|--------|---------|-----------|
| securechannel.yoti.com:443 | Channel service for QR-code-based device pairing and session creation | Public key, session metadata (browser name/version/OS) |
| secureccloud.yoti.com:443 | Content cloud for encrypted credential storage (insert, retrieve, delete, lock/unlock) | Encrypted credentials, encryption key IDs, cloud ID, requester public key |
| code.yoti.com | QR code prefix for device linking; also used to fetch site logos | QR session data, site domain for logo lookup |
| www.yoti.com | Cookie domain for tutorial state; marketing/info link | Single "YPM" cookie (tutorial completed boolean) |
| support.yoti.com | Help/support link | None (opens in browser) |

## Data Flow

User credentials flow as follows:

1. **Form detection**: The content script (`content_script.js`) scans all pages for login/registration/password-reset forms by identifying username and password input fields. It monitors for DOM mutations to detect dynamically loaded forms.

2. **Credential capture**: When the user submits a form, the background script's `webRequest.onBeforeRequest` listener intercepts the POST request body to extract the username and password values. These are stored in memory as `capturedSecrets` keyed by site URL.

3. **Save prompt**: The content script displays a Yoti-branded notification bar asking the user to save the detected credentials.

4. **Encrypted storage**: If the user confirms, credentials are encrypted client-side using the user's key pair (RSA + hybrid encryption via `crypto.subtle`), then transmitted to `secureccloud.yoti.com` via the content cloud API. The server stores only encrypted blobs; it cannot read the plaintext.

5. **Autofill**: On subsequent visits, the content script requests matching credentials from the background script, which retrieves and decrypts them from the content cloud. Credentials are filled into the detected form fields.

6. **Session management**: The extension uses SockJS/Vert.x EventBus for real-time WebSocket communication with `securechannel.yoti.com` for device pairing and session management. Sessions time out after 15 minutes (configurable). Locking wipes in-memory secrets.

7. **Cookie usage**: A single cookie ("YPM") is set on `yoti.com` to track whether the user has completed the onboarding tutorial.

All credential data is encrypted before leaving the extension. The extension does not transmit plaintext passwords to any server. The key pair is stored in `chrome.storage.local`.

## Overall Risk: LOW

Yoti Password Manager is a legitimate password management extension built by Yoti, a known digital identity company. Its permissions (tabs, storage, webRequest, cookies, and all-URLs host permissions) are standard and necessary for a password manager that needs to detect login forms, intercept form submissions, autofill credentials, and manage sessions.

The extension communicates exclusively with Yoti's own infrastructure (`securechannel.yoti.com`, `secureccloud.yoti.com`, `code.yoti.com`). All credential storage uses client-side encryption with RSA key pairs and hybrid encryption, meaning the server only handles encrypted blobs.

The two low-severity findings are:
1. HTML templates exposed as web-accessible resources to all origins, enabling extension fingerprinting.
2. The `cookies` permission grants broader access than the single yoti.com cookie actually used.

There is no evidence of data exfiltration, remote code execution, ad injection, extension enumeration, or any other malicious behavior. The webRequest body interception is core to password capture functionality. The `new Function` and `eval` instances are from standard bundler polyfills and the Lottie animation library, respectively.
