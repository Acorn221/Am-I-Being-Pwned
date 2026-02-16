# Security Analysis: GateKeeper Password Manager

| Field | Value |
|-------|-------|
| Extension ID | `hpabmnfgopbnljhfamjcpmcfaehclgci` |
| Version | 2.2.8 |
| Manifest Version | 3 |
| Users | ~10,000 |
| Risk | **LOW** |
| Date | 2026-02-09 |

## Summary

Legitimate enterprise password manager using native messaging and local API; fetches remote config from gkchain.com without integrity verification, and bundles a vm polyfill with eval, but no malicious behavior detected.

## Vulnerabilities

### VULN-01: Remote Configuration Without Integrity Verification [LOW]

**Files:** `js/background.bundle.js:36533`

```javascript
}).get("https://dl.gkchain.com/software/enterprise/passwordManagerRules.json").then((e => {
    t.data = e.data, t.succeeded = !0, r = e.data
})).catch((e => {
    e.response ? t.errorMessage = e.response.statusText : t.errorMessage = "settingsService::getPwdMgrRules error"
}));
```

**Analysis:** On initialization, the background script fetches a JSON configuration file from `https://dl.gkchain.com/software/enterprise/passwordManagerRules.json`. The fetched data is stored as `pwdMgrRules` and returned to requesters via `GET_PWD_MGR_RULES` message. There is no signature verification or integrity check on the fetched data. However, the data appears to be used purely for password policy rules (e.g., minimum length, complexity requirements), not for code execution. The risk is that if `dl.gkchain.com` were compromised, an attacker could push modified rules, but the impact is limited to password policy enforcement -- not code execution or data exfiltration.

**Verdict:** LOW -- Remote config fetch without integrity verification, but limited to password policy rules with no code execution path.

---

### VULN-02: Bundled VM Polyfill Contains eval() [LOW]

**Files:** `js/background.bundle.js:32251`, `js/contentScript.bundle.js:42950`, `js/popup.bundle.js:49267`

```javascript
Script.prototype.runInThisContext = function() {
    return eval(this.code)
};
```

**Analysis:** This is a `browserify`/`vm-browserify` polyfill that provides a browser-compatible implementation of Node.js's `vm` module. The `eval(this.code)` call is part of `Script.prototype.runInThisContext()`. This is a standard library polyfill bundled by webpack, not custom extension code. No code paths in the extension's own logic construct `Script` objects with user-controlled or remotely-fetched code. The polyfill also includes `new Function("return this")()` for global context detection, which is standard behavior.

**Verdict:** LOW -- Bundled vm polyfill with eval is a standard library artifact, not used with dynamic/remote code in this extension.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `new Function("return this")()` | `background.bundle.js:4272`, `popup.bundle.js:8625`, etc. | Standard global `this` detection polyfill |
| `innerHTML` assignments | Multiple React DOM files | React's internal SVG namespace handling and DOM manipulation -- standard React framework code |
| `keydown`/`keyup`/`keypress` dispatching | `contentScript.bundle.js:45323-45341` | Part of password autofill simulation -- dispatches synthetic keyboard events to trigger form validation after filling fields |
| `document.cookie` access | `background.bundle.js:33401-33404` | Axios HTTP library cookie handling -- standard cookie jar implementation for HTTP requests |
| `postMessage` usage | Multiple files | React scheduler's `MessageChannel` polyfill and internal message passing -- standard React framework code |
| `XMLHttpRequest` | `background.bundle.js:33152` | Axios HTTP adapter -- standard HTTP library, not XHR hooking |

## Flags

| Category | Evidence |
|----------|----------|
| remote_config | `js/background.bundle.js:36533`: Fetches password manager rules from `https://dl.gkchain.com/software/enterprise/passwordManagerRules.json` on every init without integrity verification |

## Endpoints

| Domain | Purpose | Data Sent |
|--------|---------|-----------|
| `https://dl.gkchain.com` | Remote configuration (password manager rules JSON) | None (GET request only) |
| `http://localhost:12190` | Local GateKeeper desktop app API (HTTP) | Credentials CRUD operations, user session data, PIN verification |
| `https://localhost:12199` | Local GateKeeper desktop app API (HTTPS) | Same as above, encrypted |
| `com.untetheredlabs.nativemessaging` | Native messaging host (GateKeeper desktop app) | Credential operations, session data, user info |
| `https://www.google.com/s2/favicons` | Favicon service for website icons | Domain URLs for credential display |

## Data Flow

GateKeeper Password Manager operates as a bridge between the Chrome browser and the GateKeeper desktop application (by Untethered Labs, Inc.). The data flow is:

1. **User Authentication:** The extension communicates with a local GateKeeper desktop application via two channels: (a) Chrome native messaging (`com.untetheredlabs.nativemessaging`) and (b) local HTTP/HTTPS APIs on `localhost:12190`/`localhost:12199`. Authentication is proximity-based through the desktop app.

2. **Credential Storage:** All passwords, credit cards, addresses, and secure notes are stored and encrypted by the GateKeeper desktop application -- NOT in the browser extension itself. The extension requests credentials from the desktop app and fills them into web forms.

3. **Content Script Form Detection:** The content script (`contentScript.bundle.js`) scans pages for login forms by identifying `input` fields of type text/email/tel/password. It collects field metadata (id, name, type, placeholder, autocomplete attributes) and sends it to the background script to match against stored credentials. When a match is found, it autofills the fields and dispatches synthetic keyboard/input/change events to trigger form validation.

4. **Remote Configuration:** On startup, the background script fetches password policy rules from `https://dl.gkchain.com/software/enterprise/passwordManagerRules.json`. This is a one-time GET request used for enterprise password strength requirements.

5. **No External Data Exfiltration:** Credentials are only sent to the local desktop application (localhost). No user data, browsing history, or credentials are sent to any remote server. The only external network request is the rules JSON fetch from gkchain.com.

## Overall Risk: LOW

GateKeeper Password Manager is a legitimate enterprise password management extension that serves as a browser companion to the GateKeeper desktop application by Untethered Labs, Inc. It uses broad permissions (`http://*/*`, `https://*/*`, `nativeMessaging`, `webNavigation`, `tabs`, `scripting`) which are justified for its core functionality of detecting login forms on all websites and autofilling credentials.

The extension communicates exclusively with localhost APIs and a native messaging host for credential operations. The only external endpoint is `dl.gkchain.com` for fetching password policy rules. There is no evidence of data exfiltration, ad injection, extension enumeration, keylogging, or any other malicious behavior.

The two low-severity findings are: (1) fetching remote configuration without integrity verification, which has limited impact since the data is used only for password policy rules, and (2) a bundled `vm-browserify` polyfill containing `eval()` which is a standard webpack artifact not used with dynamic code. The broad host permissions and content script injection on all pages are expected for a password manager that needs to detect and fill login forms across all websites.
