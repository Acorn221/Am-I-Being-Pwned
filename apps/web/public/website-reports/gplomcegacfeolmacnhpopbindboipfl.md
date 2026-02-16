# Security Analysis: Team Password Manager

| Field | Value |
|-------|-------|
| Extension ID | `gplomcegacfeolmacnhpopbindboipfl` |
| Version | 5.22.23 |
| Manifest Version | 3 |
| Users | ~10,000 |
| Risk | **MEDIUM** |
| Date | 2026-02-09 |

## Summary

Password manager extension stores API credentials (including plaintext password) in chrome.storage.sync with weak SJCL encryption keyed on guessable material; content script runs on all URLs with all_frames:true, injecting password data into page DOM.

## Vulnerabilities

### VULN-01: Plaintext API Password Stored in chrome.storage.sync [MEDIUM]

**Files:** `js/background.js:121`, `js/background.js:349-361`

```javascript
// On API connection, the plaintext password is stored directly in sync storage:
let c = {
  tpmConnected: !0,
  tpmConnectionType: "api",
  tpmUrl: t,
  tpmUrlShow: e.url,
  tpmUsername: e.username,
  tpmPassword: e.password,       // <-- plaintext password in sync storage
  tpmPasswordToSave: n,           // <-- SJCL-encrypted version (optional)
  tpmSavePassword: e.save_password,
  ...
};
chrome.storage.sync.set(c, function() { ... });

// Every API call reads the plaintext password and uses it for Basic Auth:
"api" == t.tpmConnectionType && (a.Authorization = "Basic " + btoa(t.tpmUsername + ":" + t.tpmPassword))
```

**Analysis:** When using "API" connection mode, the user's TPM password is stored in plaintext in `chrome.storage.sync` under the key `tpmPassword`. This value syncs across all Chrome profiles signed into the same Google account. Every API call retrieves this plaintext password and uses it for HTTP Basic Authentication. While the optional "save password" feature uses SJCL encryption, the actual working password (`tpmPassword`) is always stored unencrypted during an active session. The SJCL encryption key is constructed from `url + username` which is guessable. Any extension with access to `chrome.storage.sync` or any compromise of the Chrome sync infrastructure would expose the password.

**Verdict:** MEDIUM -- Plaintext credential storage in synced storage is a design concern for a password manager, though it is somewhat inherent to browser-extension-based password managers that need to make authenticated API calls.

---

### VULN-02: Content Script Injects Passwords Into Page DOM on All URLs [MEDIUM]

**Files:** `js/contentscript.js:141-164`, `manifest.json:15-22`

```json
// manifest.json - content script runs everywhere, in all frames
"content_scripts": [
    {
        "matches": ["<all_urls>"],
        "js": ["js/jquery-3.5.1.min.js", "js/contentscript.js", "js/psl.js",
               "js/jquery.sendkeys.js", "js/bililiteRange.js"],
        "run_at" : "document_end",
        "all_frames": true
    }
]
```

```javascript
// contentscript.js - password data is injected directly into input fields
function usePassword(e, t) {
  (loginFields = tpmGetLoginFields()) && (
    selectorOpened && ($("#tpmLoginSelectorIframeId").hide(), selectorOpened = !1),
    fieldsHourglass(),
    chrome.runtime.sendMessage({
      id: "TPM_GET_PASSWORD_ID",
      pwdId: e,
      pwdReason: t
    }, function(e) {
      fieldsIcons(),
      e && (e.username ? enterField(loginFields[0], e.username) :
            e.email && enterField(loginFields[0], e.email),
            enterField(loginFields[1], e.password))  // password written to DOM
    })
  )
}

function enterField(e, t) {
  e.value = t,
  e.dispatchEvent(new Event("input", { bubbles: !0 })),
  e.dispatchEvent(new Event("change", { bubbles: !0 }))
}
```

**Analysis:** The content script runs on every URL in every frame (`all_frames: true`). When a user selects a password to fill, the plaintext username and password are written directly into input field values on the page. The `input` and `change` events are dispatched and bubble up, meaning any JavaScript on the page (including malicious scripts in iframes or XSS payloads) can observe these events and capture the credential values. While this is standard behavior for password manager extensions, `all_frames: true` combined with `<all_urls>` increases the attack surface -- a malicious iframe could potentially intercept filled credentials.

**Verdict:** MEDIUM -- Standard password-fill behavior but the all_frames + all_urls combination exposes credentials to potentially untrusted iframes.

---

### VULN-03: Web Accessible Resources Expose JS to All Origins [LOW]

**Files:** `manifest.json:35-43`

```json
"web_accessible_resources": [
    {
        "resources": [
            "img/*",
            "js/login_selector/*"
        ],
        "matches": ["<all_urls>"]
    }
]
```

**Analysis:** The login selector JavaScript files and all images are accessible to every website. This allows any website to detect the presence of this extension by probing for these resources (extension fingerprinting). The `js/login_selector/*` files include `login_selector.js` which contains the password listing UI logic. While the JS files themselves do not contain secrets, their accessibility enables extension enumeration by any web page.

**Verdict:** LOW -- Extension fingerprinting is possible; no direct data leakage from the exposed resources themselves.

---

### VULN-04: Weak SJCL Encryption Key Derivation for Saved Password [LOW]

**Files:** `js/background.js:110-111`, `js/background.js:78-79`

```javascript
// Encrypting the password for "save password" feature:
var s = e.url + e.username;
n = sjcl.encrypt(s, e.password)

// Decrypting:
var t = e.tpmUrlShow + e.tpmUsername;
o = sjcl.decrypt(t, e.tpmPasswordToSave)
```

**Analysis:** When the user opts to save their password, it is encrypted using SJCL with a key derived by concatenating the TPM server URL and the username. Both of these values are also stored in `chrome.storage.sync` alongside the encrypted password, meaning the decryption key is stored right next to the ciphertext. An attacker who gains access to the sync storage has everything needed to decrypt the saved password.

**Verdict:** LOW -- The encryption provides no meaningful protection since the key material is co-located with the ciphertext, but this is a convenience feature and the plaintext password is already stored separately during active sessions anyway.

---

## Flags

| Category | Evidence |
|----------|----------|
| war_js_html_all_urls | `manifest.json`: `js/login_selector/*` and `img/*` are web-accessible to `<all_urls>`, enabling extension fingerprinting |

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| innerHTML usage | `popup.js`, `login_selector.js`, `login_error.js` | All innerHTML assignments either use `escapeHtml()` sanitization or parse through `DOMParser` before appending, or only insert i18n messages from `chrome.i18n.getMessage()` which are trusted |
| postMessage in jstree.js | `tree/jstree.js:1898` | Standard jstree library using Web Workers with postMessage for tree operations; not cross-origin messaging |
| jQuery innerHTML in localizeHtmlPage | `popup.js:386`, `login_selector.js:221`, `saver.js:15`, `login_error.js:20` | Replaces `__MSG_*__` tags with `chrome.i18n.getMessage()` results -- trusted extension-internal i18n strings only |

## Endpoints

| Domain | Purpose | Data Sent |
|--------|---------|-----------|
| User-configured TPM server (e.g. `tpm.mycompany.com`) | Core functionality: API connection, password search, retrieval, and storage | API credentials (Basic Auth), password search queries, new password entries |
| teampasswordmanager.com | Help documentation links only (in popup.html) | None (user clicks external link) |
| clients2.google.com | Chrome Web Store auto-update URL (in manifest.json) | Standard CRX update checks |

## Data Flow

1. **Connection phase:** User enters their TPM server URL, username, and password in the popup. The extension stores these in `chrome.storage.sync` (password in plaintext for API mode, optionally SJCL-encrypted for the "remember password" feature). For auto-connect mode, the content script reads a hidden `#CETPMURL` element from the TPM server page and connects automatically without storing a password.

2. **Browsing phase:** On every page load, the content script (`contentscript.js`) runs in all frames. It checks if the extension is connected, then scans the page for login forms (username + password field pairs). When found, it adds lock icons to the fields and attaches click handlers.

3. **Password retrieval:** When the user clicks a login field, an iframe-based login selector opens showing matching passwords from the TPM server. The background script fetches password data from the configured TPM API endpoint using Basic Authentication, passing the stored credentials.

4. **Password fill:** The selected password's username and password values are sent from the background script to the content script, which writes them directly into the detected form fields and dispatches `input`/`change` events.

5. **Password save:** On form submission, if the "offer to save" option is enabled, the extension captures the URL, username, and password from the form and opens a saver popup window. The user can then save the credentials back to the TPM server.

6. **Data scope:** All communication is exclusively between the extension and the user's self-hosted TPM server. No data is sent to any third-party service, analytics endpoint, or the extension developer.

## Overall Risk: MEDIUM

This is a legitimate password manager extension for the "Team Password Manager" self-hosted product. It serves a clear purpose and all network communication is directed solely at the user's own TPM server instance -- there is no telemetry, analytics, or third-party data exfiltration.

The MEDIUM rating is based on two factors: (1) the plaintext storage of API credentials in `chrome.storage.sync`, which syncs across Chrome profiles and is accessible to the Chrome sync infrastructure, and (2) the broad content script injection surface (`<all_urls>` with `all_frames: true`) that fills passwords into page DOM where they could theoretically be intercepted by malicious page scripts or iframes.

These are common design patterns in browser-based password managers and do not indicate malicious intent. The extension properly uses `escapeHtml()` for output sanitization, uses DOMParser for HTML construction, and limits its functionality strictly to password management. The code is straightforward, not obfuscated, and contains no signs of data exfiltration, ad injection, extension enumeration, or any other malicious behavior.
