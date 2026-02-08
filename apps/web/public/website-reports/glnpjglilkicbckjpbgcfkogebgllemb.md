# Vulnerability Report: Okta Browser Plugin

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Okta Browser Plugin |
| Extension ID | glnpjglilkicbckjpbgcfkogebgllemb |
| Version | 6.45.0 |
| Manifest Version | 3 |
| Users | ~4,000,000 |
| Publisher | Okta, Inc. |
| Analysis Date | 2026-02-08 |

## Executive Summary

The Okta Browser Plugin is a legitimate enterprise SSO (Single Sign-On) browser extension published by Okta, a major identity and access management provider. The extension requires broad permissions (`<all_urls>`, cookies, tabs, webRequest, scripting, storage, webNavigation, declarativeNetRequestWithHostAccess) which are extensive but consistent with its purpose of providing SSO across all web applications for enterprise users.

The extension manages authentication flows (PKCE OAuth, session cookies), auto-fills credentials, monitors authentication state, handles basic auth, and integrates with Okta Personal (password vault). All network communication is directed to Okta's own infrastructure domains (*.okta.com, *.oktapreview.com, *.trexcloud.com, etc.) and Pendo for analytics (with user consent gating). No evidence of malicious behavior, data exfiltration, residential proxy infrastructure, extension enumeration, or suspicious third-party SDK injection was found.

## Vulnerability Details

### INFO-01: Broad Host Permissions
- **Severity:** INFO
- **Files:** `manifest.json`
- **Code:** `"host_permissions": ["https://*/", "http://*/"]`
- **Verdict:** Expected for an enterprise SSO plugin. Required to inject content scripts on any site where users may need to authenticate and to intercept authentication flows (basic auth, SAML redirects).

### INFO-02: Pendo Analytics Tracking
- **Severity:** INFO
- **Files:** `shared/common/event-tracker.js`, `shared/common/fn/fn-api.js`
- **Code:** `PendoEventTrackUrl: "https://app.pendo.io/data/track"`
- **Verdict:** Standard product analytics via Pendo. Properly gated behind `pluginPendoTrackingEnabled` org setting AND `cookieConsentGiven` flag. Firefox users have additional opt-out consent (`interactiveDataConsent`). Tracks UI interaction events (button clicks, feature usage) -- no browsing data or PII exfiltration. OktaPersonal org events are filtered to exclude app names/URLs.

### INFO-03: Cookie Access for Session Management
- **Severity:** INFO
- **Files:** `js/webextension-cookies.js`, `shared/common/fn/fn-cookie-manager.js`
- **Code:** Reads `sid`, `DT`, `idx` cookies from Okta domains
- **Verdict:** Reads only Okta session cookies (`sid`, `DT`, `idx`) needed to establish authenticated sessions. No cross-domain cookie harvesting.

### INFO-04: Content Script Injection on All Pages
- **Severity:** INFO
- **Files:** `shared/preload-content.js`, `js/webextension-executeScript-v3.js`
- **Code:** Content script scans for password/username fields; injected on DOM content loaded
- **Verdict:** The preload content script runs a chain of checks before injecting the full content script: verifies the page is an Okta page OR has monitored sites configured OR has password/username fields. Injection is purposeful for SSO functionality. No DOM exfiltration.

### INFO-05: Basic Auth Credential Injection
- **Severity:** INFO
- **Files:** `js/webextension-basic-auth.js`
- **Code:** `chrome.webRequest.onAuthRequired` listener on `<all_urls>`
- **Verdict:** Provides HTTP basic authentication credentials from the Okta vault when sites request them. Credentials are fetched from Okta's own API (`/api/plugin/2/...`) and only applied when a matching auth site is configured. Rate-limited to prevent repeated attempts (2-second throttle).

### INFO-06: declarativeNetRequest Header Modification
- **Severity:** INFO
- **Files:** `js/webextension-request-headers-v3.js`, `shared/bg/start-background-script.js`
- **Code:** Adds `X-Okta-User-Agent-Extended` and `X-Okta-User-Agent-Account-Data` headers; modifies Origin/Referer for OAuth token refresh
- **Verdict:** Header injection is limited to Okta domain requests for user agent identification and OAuth CORS handling. Origin/Referer modification is specifically for PKCE token refresh flows to Okta's own authorization servers. No arbitrary header injection to third-party sites.

### INFO-07: Password Save Suppression via Privacy API
- **Severity:** INFO
- **Files:** `js/webextension-suppress-pwd-save.js`
- **Code:** Uses `chrome.privacy.services.passwordSavingEnabled` to temporarily disable browser password saving during SSO flows
- **Verdict:** Optional permission (`privacy`). Temporarily disables Chrome's built-in password manager during SSO sign-in flows to prevent credential capture conflicts. Properly restores settings after completion.

### INFO-08: WebCrypto Usage
- **Severity:** INFO
- **Files:** `shared/common/core/crypto-manager.js`
- **Code:** AES-GCM encryption/decryption, PKCE challenge generation, RSA signature verification
- **Verdict:** Standard WebCrypto API usage for PKCE OAuth flows, vault encryption/decryption (Okta Personal), and ID token signature verification. No custom/weak crypto implementations.

## False Positive Table

| Pattern | Location | Reason for FP |
|---------|----------|---------------|
| `innerHTML` | `shared/shared.js` (content script UI), popover/newtab exports | React/UI framework rendering for Okta's own popup UI. Bundled UI components, not dynamic injection. |
| `String.fromCharCode` | `shared/common/constants.js` | Constructs the storage key `OKTA_ACCOUNT_WHITE_LIST` -- a constant string, not obfuscation. |
| `chrome.management.getSelf` | `js/webextension-onboarding.js` | Only calls `getSelf()` (not `getAll()`) to check if extension was user-installed vs enterprise-deployed. No extension enumeration. |
| `<all_urls>` webRequest listener | `js/webextension-request-headers-v3.js` | Empty no-op listener (`_.noop`) registered to ensure `extraHeaders` access for Okta domain-specific declarativeNetRequest rules. |
| `getAll()` on cookie stores | `js/webextension-cookies.js` | Used only to find the correct cookie store for the current tab (Firefox/Safari container support). |

## API Endpoints Table

| Endpoint Pattern | Purpose | Auth |
|-----------------|---------|------|
| `{okta_domain}/api/plugin/2/sites*` | Fetch monitored SSO sites | Session cookie |
| `{okta_domain}/api/plugin/2/settings` | Plugin settings & feature flags | Session cookie |
| `{okta_domain}/api/plugin/2/log` | Extension debug logging to Okta | Bearer token |
| `{okta_domain}/api/internal/enduser/home` | User's app dashboard | Session cookie |
| `{okta_domain}/enduser/api/v1/home` | User's app dashboard (v1) | Session cookie |
| `{okta_domain}/api/internal/enduser/vault` | Okta Personal password vault | Bearer token |
| `{okta_domain}/okta-personal/api/v2/core/*` | Okta Personal core service | Bearer token |
| `{okta_domain}/oauth2/v1/authorize` | OIDC authorization | PKCE |
| `{okta_domain}/.well-known/openid-configuration` | OIDC discovery | None |
| `https://app.pendo.io/data/track` | Pendo analytics (consent-gated) | Integration key |
| `https://login.okta.com` | Onboarding org discovery | None |

## Data Flow Summary

1. **Authentication Flow:** Extension reads Okta session cookies (`sid`, `DT`, `idx`) from Okta domains to maintain authenticated state. Uses PKCE OAuth to obtain access tokens. All auth data stays within the Okta ecosystem.

2. **Content Script Flow:** Preload script checks if page is an Okta page, has custom domain mapping, or has login forms. If conditions are met, full content script is injected for SSO/autofill functionality. Communication with background via `chrome.runtime.connect()` ports.

3. **Credential Flow:** Password vault data is encrypted client-side (AES-GCM) and stored in Okta Personal's servers. Basic auth credentials are fetched on-demand from Okta's API only when matching auth sites trigger `onAuthRequired`.

4. **Analytics Flow:** UI interaction events sent to Pendo, gated by `pluginPendoTrackingEnabled` org setting + user cookie consent. Personal org events strip sensitive fields (app names, URLs). Firefox requires explicit interactive consent.

5. **Header Modification:** `X-Okta-User-Agent-Extended` header added to Okta domain requests for version identification. Origin/Referer headers modified only for PKCE token refresh requests to Okta authorization servers.

## Overall Risk Assessment

**CLEAN**

The Okta Browser Plugin is a legitimate enterprise SSO extension from Okta, Inc. While it requires very broad permissions (all URLs, cookies, scripting, webRequest), every capability is used in service of its core purpose: providing single sign-on, password management, and authentication monitoring across web applications for enterprise users. All network communication is directed at Okta's own infrastructure. Analytics tracking (Pendo) is properly consent-gated. No evidence of malicious behavior, data exfiltration, proxy infrastructure, extension enumeration, third-party SDK injection, or obfuscation was found. The codebase is well-structured, readable, and consistent with an enterprise security product.
