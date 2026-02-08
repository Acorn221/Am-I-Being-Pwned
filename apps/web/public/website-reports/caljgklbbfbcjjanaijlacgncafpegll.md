# Vulnerability Report: Avira Password Manager

## Metadata
- **Extension Name:** Avira Password Manager
- **Extension ID:** caljgklbbfbcjjanaijlacgncafpegll
- **Version:** 2.21.0.5015
- **Author:** Avira Operations GmbH & Co. KG
- **Users:** ~8,000,000
- **Manifest Version:** 3
- **Analysis Date:** 2026-02-08

## Executive Summary

Avira Password Manager is a legitimate password management extension from Avira (a well-known German cybersecurity company, subsidiary of NortonLifeLock/Gen Digital). The extension requests broad permissions (`<all_urls>`, `webRequest`, `tabs`, `cookies`, `scripting`, `storage`, `webNavigation`, `idle`, `alarms`, `contextMenus`) which are justified by its password manager functionality: autofilling credentials on all websites, detecting login forms, managing cookies for session awareness, and injecting UI overlays.

The extension communicates exclusively with Avira-owned infrastructure (passwords.avira.com, api.my.avira.com, extensions.avira.com, ncs-ds.avira.com, rs.avira.com, spoc.avira.com) and standard cloud services (AWS for encrypted vault sync via AppSync/GraphQL and S3, Firebase for push notifications). Third-party services include Mixpanel (product analytics), Sentry (error reporting), Google Analytics (usage metrics), and HaveIBeenPwned (password breach checking).

No malicious behavior, data exfiltration, residential proxy infrastructure, market intelligence SDKs, ad injection, extension enumeration/killing, XHR/fetch hooking, or remote code execution was identified. The codebase is a standard bundled/minified JavaScript application built with well-known libraries (jQuery, Backbone/Marionette, Lodash, Redux, React components, AWS SDK, Firebase SDK).

## Vulnerability Details

### LOW-1: Web Accessible Resources Exposed to All Origins
- **Severity:** LOW
- **File:** `manifest.json` (lines 17-30)
- **Code:** `"matches": ["<all_urls>"]` for `panel.html`, `html/*.html`, and icon resources
- **Details:** The extension exposes its panel HTML pages and icon images to all web origins. While this is common for password manager UI overlays that need to render on any page, it could theoretically allow any website to probe for the extension's presence via resource timing attacks or direct iframe embedding.
- **Verdict:** Low risk. This is standard practice for password managers that inject inline UI elements. The exposed resources are UI shells (panel.html, dashboard.html, inlineForm.html, inlineTooltip.html, notifications.html) that require extension context to function and contain no sensitive data.

### LOW-2: Mixpanel Analytics with Installation Tracking
- **Severity:** LOW
- **File:** `js/background/background_worker.js`
- **Code:** `this._mixpanel.init(N.mixpanelToken)`, `this._mixpanel.identify(i)`, `this._mixpanel.track(e,t,r)`
- **Details:** The extension initializes Mixpanel with a product token and tracks user events including login state, registration status, vault lock status, and user actions. It generates installation-specific IDs and distinct IDs for analytics. Data sent includes: IsLoggedIn, isRegistered, isUnlocked, isUnregisteredMode, migrationStatus, browser type, source/subSource attribution.
- **Verdict:** Standard product analytics for a commercial password manager. No credentials, passwords, or visited URLs are sent to Mixpanel. Only product interaction events and state flags.

### LOW-3: Google Analytics Collection
- **Severity:** LOW
- **File:** `js/background/background_worker.js`
- **Code:** References to `https://www.google-analytics.com/collect`
- **Verdict:** Standard usage metrics collection. Expected for a commercial product.

### INFO-1: eval() Usage in JSON Parsing Fallback
- **Severity:** INFO
- **File:** `js/background/background_worker.js`
- **Code:** `eval("("+text+"...")`
- **Details:** A single eval() call exists as a JSON parsing fallback, likely from an older JSON polyfill (json2.js pattern). The CSP (`script-src 'self'`) would block this in extension pages regardless.
- **Verdict:** False positive. Standard JSON parsing polyfill pattern, blocked by CSP.

### INFO-2: new Function() Calls
- **Severity:** INFO
- **File:** `js/background/background_worker.js`
- **Code:** `new Function("return this")`, `new Function("return "+e)`, `new Function("args","return this."+e.name+"(args...")`
- **Details:** These are standard patterns from bundled libraries: global `this` detection (common in UMD wrappers), and method invocation helpers. The CSP (`script-src 'self'`) blocks dynamic code execution in extension pages.
- **Verdict:** False positive. Standard library patterns, mitigated by CSP.

### INFO-3: chrome.privacy.services Access
- **Severity:** INFO
- **File:** `js/background/background_worker.js`
- **Code:** `chrome.privacy.services.passwordSavingEnabled.set({value:e})`
- **Details:** The extension disables Chrome's built-in password saving to prevent conflicts with its own password manager. This is accessed through the optional `privacy` permission.
- **Verdict:** Expected behavior for a password manager to avoid duplicate save prompts.

### INFO-4: chrome.history API Wrappers
- **Severity:** INFO
- **File:** `js/background/background_worker.js`
- **Code:** Wrapper functions for `chrome.history.onVisited`, `chrome.history.deleteUrl`, `chrome.history.addUrl`, `chrome.history.search`, `chrome.history.deleteAll`
- **Details:** The extension adapter includes wrappers for history APIs. The `history` permission is NOT declared in the manifest, so these would fail at runtime. These are likely part of a shared extension adapter library that supports multiple Avira products.
- **Verdict:** No concern. The `history` permission is not granted; these are dead code from a shared library.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `eval("("+text+"...")` | background_worker.js | JSON2 polyfill pattern, blocked by CSP |
| `new Function("return this")` | background_worker.js | UMD global detection pattern |
| `new Function("return "+e)` | background_worker.js | Library helper pattern |
| `innerHTML` usage | content.js, dashboard/index.js | jQuery DOM manipulation for UI rendering (password form overlays) |
| `postMessage` | content.js, panel.js | Internal iframe communication between extension UI components |
| `fromCharCode` / `btoa` / `atob` | Multiple files | Crypto operations, base64 encoding for vault data, Firebase messaging token handling |
| Sentry SDK hooks | background_worker.js | Standard error monitoring (Sentry SDK wraps XHR/fetch for breadcrumbs) |
| Firebase public keys | background_worker.js | FCM push notification VAPID key |
| `chrome.management.get` | background_worker.js | Getting own extension details, not enumerating others |

## API Endpoints Table

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `https://api.my.avira.com` | Avira account authentication/API | None - 1st party |
| `https://passwords.avira.com` | Password Manager web app | None - 1st party |
| `https://extensions.avira.com` | Extension config/updates | None - 1st party |
| `https://extensions.avira.com/pwm/uninstall` | Uninstall survey redirect | None - 1st party |
| `https://ncs-ds.avira.com/api/datastore/v2` | NCS data store API | None - 1st party |
| `https://rs.avira.com/api/1` | Avira reporting service | None - 1st party |
| `https://spoc.avira.com` | SPOC service (single point of contact) | None - 1st party |
| `https://spocnotify.avira.com` | Push notifications service | None - 1st party |
| `https://rv22n44kt5dpxeytw7c3bqmtla.appsync-api.eu-central-1.amazonaws.com/graphql` | AWS AppSync - vault sync (production) | None - encrypted vault |
| `https://5w2zr57dczhtnkauhyvfbcipxm.appsync-api.eu-west-1.amazonaws.com/graphql` | AWS AppSync - vault sync (secondary) | None - encrypted vault |
| `https://tamh9wgwol.execute-api.eu-central-1.amazonaws.com/production` | AWS API Gateway (production) | None - 1st party infra |
| `https://vvw4btjrqe.execute-api.eu-central-1.amazonaws.com/production` | AWS API Gateway (production) | None - 1st party infra |
| `https://17opm4zg7e.execute-api.eu-west-1.amazonaws.com/test` | AWS API Gateway (test - likely dead code) | None |
| `https://s3.eu-central-1.amazonaws.com/avira-pwm-favicons` | S3 favicon storage | None - static assets |
| `https://s3.eu-central-1.amazonaws.com/avira-pwm-static/` | S3 static assets | None - static assets |
| `https://avira-pwm-extensions.s3.eu-central-1.amazonaws.com/inContext-negative-list.json` | Negative list for in-context suggestions | None - config file |
| `https://avira-password-manager.firebaseio.com` | Firebase Realtime DB | None - Firebase infra |
| `https://ncs-spoc.firebaseio.com` | Firebase Realtime DB (NCS SPOC) | None - Firebase infra |
| `https://fcmregistrations.googleapis.com/v1` | Firebase Cloud Messaging registration | None - FCM |
| `https://firebaseinstallations.googleapis.com/v1` | Firebase installations API | None - Firebase |
| `https://securetoken.google.com/` | Firebase Auth token refresh | None - Firebase |
| `https://api.mixpanel.com` | Mixpanel analytics | Low - product analytics |
| `https://www.google-analytics.com/collect` | Google Analytics | Low - usage analytics |
| `https://5d9ce744e23342eb868dc6fa501ef61e@sentry.avira.net/50` | Sentry error reporting (self-hosted) | None - error monitoring |
| `https://api.pwnedpasswords.com` | HaveIBeenPwned k-Anonymity API | None - password breach check |
| `https://haveibeenpwned.com/api/v3` | HaveIBeenPwned API | None - password breach check |
| `https://www.research.net/r/6DTRT75` | SurveyMonkey survey | None - user feedback |
| `https://campaigns.avira.com/*/pwm-isec-33` | Avira upsell campaign pages | None - 1st party marketing |

## Data Flow Summary

1. **Form Detection & Autofill:** Content script (`content-inject.js`) signals background to inject full content scripts. Content scripts detect login/signup forms on web pages, present autofill UI overlays (inlineForm, inlineTooltip), and fill credentials from the encrypted local vault.

2. **Vault Sync:** Encrypted vault data is synchronized via AWS AppSync (GraphQL) endpoints. The extension uses AWS Cognito for authentication and client-side encryption (AES, RSA, PBKDF2) before any data leaves the device. 190 crypto-related references confirm heavy use of client-side encryption.

3. **Authentication:** User authentication flows through `api.my.avira.com` (Avira account) and AWS Cognito identity pools. Firebase is used for push notifications.

4. **Analytics:** Product usage events (not credentials or URLs) are sent to Mixpanel and Google Analytics. Error/crash data goes to a self-hosted Sentry instance at `sentry.avira.net`.

5. **Password Breach Check:** Password hashes (k-Anonymity model - only first 5 chars of SHA-1 hash) are checked against HaveIBeenPwned API.

6. **External Communication:** The `externally_connectable` manifest entry only allows `https://passwords.avira.com/*` and specific Avira extension IDs to communicate with the extension, used for an onboarding flow.

7. **Cookie Access:** The extension accesses cookies only through its own cookie management functions (get/set/remove) for session-related purposes, not for harvesting or exfiltration.

## Overall Risk Assessment

**CLEAN**

Avira Password Manager is a legitimate commercial password management product from a well-established cybersecurity company. While it requires extensive permissions (`<all_urls>`, cookies, webRequest, tabs, scripting, storage), these are all justified by its core functionality as a password manager that must:
- Detect and interact with login forms on all websites
- Autofill credentials into form fields
- Monitor page navigation to trigger autofill
- Manage extension-related cookies for session handling
- Use the scripting API to inject content scripts dynamically

All network communication is directed to Avira-owned infrastructure or well-known, legitimate third-party services (AWS, Firebase, Mixpanel, Sentry, HaveIBeenPwned). No evidence of data exfiltration, malicious behavior, proxy infrastructure, market intelligence SDKs, ad/coupon injection, remote code execution, or obfuscated payload delivery was found.
