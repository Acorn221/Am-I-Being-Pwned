# Vulnerability Report: Clever Extension

## Metadata
- **Extension Name:** Clever
- **Extension ID:** nopfnnpnopgmcnkjchnlpomggcdjfepo
- **Version:** 1.18.4
- **Manifest Version:** 3
- **User Count:** ~15,000,000
- **Author:** Clever (clever.com)
- **Description:** Allows students and staff to access apps in Clever Portal.

## Executive Summary

Clever is a legitimate single sign-on (SSO) extension used extensively in K-12 education. It enables students and staff to log into third-party educational applications via the Clever Portal without manually entering credentials. The extension uses a custom scripting engine ("SquidScript") to automate login flows on third-party sites by filling in credential forms and clicking buttons.

The extension has broad permissions (`*://*/*` host permissions, `cookies`, `tabs`, `scripting`, `activeTab`) and injects a content script on every page. However, these permissions are justified by its core functionality: automating SSO logins across arbitrary third-party educational apps. All network communication is exclusively to Clever's own domains (`clever.com`, `lockbox.clever.com`, `client-events.clever.com`). No evidence of data exfiltration, tracking SDKs, proxy infrastructure, or malicious behavior was found.

## Vulnerability Details

### MEDIUM-1: Broad Content Script Injection on All Pages
- **Severity:** MEDIUM
- **File:** `js/document_start.js` (runs at `document_start` on `*://*/*`)
- **Code:**
  ```json
  "content_scripts": [{
    "matches": ["*://*/*"],
    "js": ["js/document_start.js"],
    "run_at": "document_start"
  }]
  ```
- **Analysis:** The content script runs on every single page. On page load, it sends a `get_action` message to the background script to check if the current URL matches a pending SSO login flow. If no tab state exists for the current tab, the content script does nothing. This is architecturally necessary because Clever cannot predict which domains third-party educational apps use.
- **Verdict:** Expected behavior for SSO functionality. The content script is essentially a no-op unless the background script has an active login flow for the current tab.

### MEDIUM-2: SquidScript Engine Executes Server-Defined Instructions
- **Severity:** MEDIUM
- **Files:** `js/document_start.js` (lines 2680-2762, 2942-3265)
- **Code:**
  ```javascript
  const e = yield a.getActionForURL(document.location.href);
  switch (e.type) {
    case "run_squidscript":
      // Executes script instructions from Clever's lockbox API
      o.execute({ script: s, variables: r, ... });
  }
  ```
- **Analysis:** The SquidScript engine executes login automation instructions fetched from `lockbox.clever.com`. These instructions are limited to a fixed set of safe DOM operations: `set` (fill input fields), `click`, `waitFor`, `navigate`, `delay`, `exists`, `textContentMatch`, `setSelectOption`, `mouseover`, `setCookie`, `clearCookiesByDomain`. There is no `eval()`, `Function()`, or arbitrary code execution. The instruction set is a custom DSL (domain-specific language) parsed by a Jison-based parser, not arbitrary JavaScript.
- **Verdict:** Controlled server-driven automation with a limited, safe command set. No arbitrary code execution capability. This is Clever's documented "Saved Passwords" feature for automating logins.

### LOW-3: Credential Handling via Lockbox API
- **Severity:** LOW
- **File:** `js/background.js` (lines 21644-21716)
- **Code:**
  ```javascript
  getCredentialsAndUserForToken(e) {
    // Fetches credentials from lockbox.clever.com
    yield this.fetch(`${this.lockboxURL}/api/credentials`, {
      method: "GET", token: e
    });
  }
  postCredentialsForToken(e, t, n, a) {
    yield this.fetch(`${this.lockboxURL}/api/credentials`, {
      method: "POST",
      body: { username: t, password: n, customFields: a },
      token: e
    });
  }
  ```
- **Analysis:** Credentials (username/password) are stored and retrieved from Clever's Lockbox service (`lockbox.clever.com`). All requests use Bearer token authentication. Credentials flow: Lockbox API -> background script -> content script (as SquidScript variables) -> DOM input fields on login pages. This is the core SSO password-filling functionality.
- **Verdict:** Expected behavior for a credential manager/SSO tool. Credentials are transmitted over HTTPS with authentication tokens.

### LOW-4: Cookie Clearing Capability
- **Severity:** LOW
- **File:** `js/background.js` (lines 22051-22106)
- **Code:**
  ```javascript
  case "clear_cookies":
    chrome.cookies.getAll({ domain: e.domain }, (e) => {
      for (const t of e) chrome.cookies.remove({ ... });
    });
  case "logout_apps":
    // Clears cookies for redirect URIs (from Clever Portal)
    chrome.cookies.getAll({ domain: e }, function (e) {
      for (const t of e) chrome.cookies.remove({ ... });
    });
  ```
- **Analysis:** The extension can clear cookies for arbitrary domains. This is used for: (1) the SquidScript `clearCookiesByDomain` command during login flows (e.g., clearing stale sessions), and (2) the `logout_apps` external message handler (triggered by clever.com via `externally_connectable`) to log users out of apps. The `logout_apps` handler explicitly excludes `clever.com` cookies from deletion.
- **Verdict:** Expected behavior for SSO logout functionality.

### INFO-5: Externally Connectable from clever.com
- **Severity:** INFO
- **File:** `manifest.json` (line 82-86), `js/background.js` (lines 22075-22109)
- **Code:**
  ```json
  "externally_connectable": {
    "matches": ["*://localhost/*", "https://clever.com/*"]
  }
  ```
- **Analysis:** The Clever Portal website can send messages to the extension via `chrome.runtime.onMessageExternal`. Supported commands: `update_app_redirects` (store redirect URIs), `open_app_url` (open a tab), `logout_apps` (clear cookies for app domains). This is tightly scoped to Clever's own domain.
- **Verdict:** Standard pattern for web-to-extension communication. Properly restricted to clever.com.

### INFO-6: Web-Accessible Resources
- **Severity:** INFO
- **File:** `manifest.json` (lines 69-80)
- **Code:**
  ```json
  "web_accessible_resources": [{
    "resources": ["js/credential_form.html", "js/click_injector.js"],
    "matches": ["http://*/*", "https://*/*"]
  }]
  ```
- **Analysis:** `credential_form.html` is loaded as an iframe for the credential update UI when login fails. `click_injector.js` is injected as a page-level script to fire click events via CustomEvent (bypasses content script isolation for click simulation). Both are exposed to all origins but contain no sensitive data or APIs.
- **Verdict:** Architecturally needed for the login automation flow. Minimal attack surface.

## False Positive Table

| Pattern | Location | Reason |
|---|---|---|
| `keydown`/`keypress`/`keyup` events | `document_start.js:2985-2987` | SquidScript simulates keyboard events to trigger React/Angular change handlers during form-fill |
| `document.cookie` assignment | `document_start.js:3181` | SquidScript `setCookie` command for login automation |
| `querySelector`/`querySelectorAll` | `document_start.js` (many) | SquidScript DOM operations for form-filling and button-clicking |
| `innerHTML` | Not found | N/A |
| React keyboard event handlers | `credential_form.js:33094-34642` | React internal event system (bundled React library) |
| `postMessage` | `credential_form.js:25344-25349` | Internal async scheduling (core-js/scheduler polyfill) |
| TypeScript compiler | `document_start.js:3280-157266` | Bundled TypeScript compiler for SquidScript executor generation |

## API Endpoints Table

| Endpoint | Method | Purpose | Auth |
|---|---|---|---|
| `https://lockbox.clever.com/api/applications/{id}` | GET | Fetch app configuration and login instructions | Bearer token |
| `https://lockbox.clever.com/api/credentials` | GET | Retrieve stored user credentials for SSO | Bearer token |
| `https://lockbox.clever.com/api/credentials` | POST | Save/update user credentials | Bearer token |
| `https://lockbox.clever.com/redirect/{appId}` | - | OAuth redirect endpoint for token exchange | OAuth flow |
| `https://clever.com/oauth/authorize` | - | OAuth authorization endpoint | OAuth flow |
| `https://client-events.clever.com/v2/events` | POST | Telemetry: login success/failure events | Credentials: include |

## Data Flow Summary

1. **User clicks app in Clever Portal** -> Portal sends OAuth redirect -> extension intercepts token URL -> background script extracts app ID and access token
2. **Background fetches app config** from `lockbox.clever.com/api/applications/{id}` -> gets login instructions (SquidScript), login URL, and supported domains
3. **Background fetches credentials** from `lockbox.clever.com/api/credentials` using bearer token -> stores in tab state
4. **Background navigates tab** to the app's login URL
5. **Content script on login page** sends `get_action` message -> background returns SquidScript instructions and credentials
6. **SquidScript engine executes** -> fills username/password fields, clicks submit button, handles multi-step flows
7. **On completion**, background script logs success/failure event to `client-events.clever.com`
8. **On credential failure**, extension displays credential update form (iframe) for user to enter new credentials

All data flows are exclusively to/from `*.clever.com` domains. No third-party analytics, tracking, or data exfiltration observed.

## Overall Risk: **CLEAN**

**Rationale:** Clever is a well-known educational technology platform used by over 100,000 schools. The extension's broad permissions (`*://*/*`, cookies, tabs, scripting) are justified by its SSO functionality, which must operate across arbitrary third-party educational app domains. All network communication is restricted to Clever's own infrastructure. The SquidScript engine uses a limited, safe DSL rather than arbitrary code execution. The credential handling follows standard OAuth + bearer token patterns. The telemetry is limited to login success/failure metrics sent to Clever's own event service. No evidence of malicious behavior, data exfiltration, tracking SDKs, proxy infrastructure, ad injection, or obfuscation.
