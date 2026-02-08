# Vulnerability Report: LastPass: Free Password Manager

## Metadata
| Field | Value |
|---|---|
| **Extension Name** | LastPass: Free Password Manager |
| **Extension ID** | hdokiejnpimakedhajhdlcegeplioahd |
| **Version** | 4.151.1 |
| **Manifest Version** | 3 |
| **User Count** | ~9,000,000 |
| **Author** | LastPass |

## Executive Summary

LastPass is a well-known password manager extension with approximately 9 million users. The extension requests broad permissions (all URLs, scripting, tabs, webRequest, webNavigation, storage, notifications, contextMenus, alarms, offscreen) and injects content scripts into all HTTP/HTTPS pages. While these permissions are extensive, they are consistent with the expected functionality of a password manager that needs to detect login forms, autofill credentials, and manage passkeys across all websites.

The extension communicates exclusively with LastPass infrastructure (lastpass.com, lastpass.eu, accounts.lastpass.com, pollserver.lastpass.com), standard identity providers for federated login (Microsoft, Google, Okta, PingOne, OneLogin), and legitimate third-party services (Datadog for error monitoring, Segment for product analytics, HaveIBeenPwned API for breach detection, Google Drive API for backup).

No malicious behavior, data exfiltration, residential proxy infrastructure, extension enumeration, ad/coupon injection, market intelligence SDKs, or AI scraping was found. The code is minified (webpack bundled) but not obfuscated.

## Vulnerability Details

### 1. MEDIUM - `executeScript` with Dynamic Code String
| Field | Value |
|---|---|
| **Severity** | MEDIUM |
| **File** | `background-redux-new.js` |
| **Code** | `executeScript:(e,a)=>new Promise((r=>{chrome.tabs.executeScript(parseInt(e,10),{code:a},...` |
| **Verdict** | Potential for code injection if `a` parameter is attacker-controlled. However, this is a legacy MV2-style API wrapper. The extension primarily uses `executeScriptFile` with static file references (`web-client-content-script.js`, `first-password-loggedin-detector.js`, `credentials-library.js`). The `code` variant appears to be a utility function, and no evidence of it being called with untrusted input was found. Low practical risk. |

### 2. LOW - `first-password-loggedin-detector.js` Reads Cookies from Major Sites
| Field | Value |
|---|---|
| **Severity** | LOW |
| **File** | `first-password-loggedin-detector.js` |
| **Code** | `document.cookie.split("; ").find((n=>n.startsWith(e+"=")))` for Google (SID), Amazon (x-main), LinkedIn, Facebook, Outlook |
| **Verdict** | Web-accessible resource injected into MAIN world that reads cookies from major sites to detect if the user is logged in. This is used for the "first password" onboarding flow. Cookie values (SID, x-main) are read but only used for boolean logged-in detection -- the values are NOT sent anywhere. The result (`isLoggedIn: true/false`) is communicated via `window.postMessage`. This is a privacy-conscious implementation. |

### 3. LOW - `credentials-library.js` Overrides `navigator.credentials.create/get`
| Field | Value |
|---|---|
| **Severity** | LOW |
| **File** | `credentials-library.js` |
| **Code** | `navigator.credentials.create = t => new Promise(...)` / `navigator.credentials.get = async t => new Promise(...)` |
| **Verdict** | Overrides the Web Credentials API (navigator.credentials) in MAIN world to intercept WebAuthn/Passkey operations. This is required for LastPass passkey management functionality. The original methods are preserved as `window.__nativeCredentialsCreate` and `window.__nativeCredentialsGet` and are used as fallbacks. Data is communicated only via `postMessage` to the extension. Expected password manager behavior. |

### 4. LOW - Broad `onBeforeRequest` Listener
| Field | Value |
|---|---|
| **Severity** | LOW |
| **File** | `background-redux-new.js` |
| **Code** | `i.webRequest.onBeforeRequest.addListener(r,{urls:["<all_urls>"]},["requestBody"])` |
| **Verdict** | Monitors all web requests with request body access. Used specifically for detecting federated login flows (OIDC redirect from accounts.lastpass.com) to intercept OAuth/SAML authentication responses. The listener filters for specific LastPass/Microsoft/Okta URLs. This is expected for federated SSO login support. The listener is dynamically added/removed around federated login operations. |

### 5. INFO - Segment Analytics Integration
| Field | Value |
|---|---|
| **Severity** | INFO |
| **File** | `background-redux-new.js` |
| **Code** | `this.host=o(a.host||"https://api.segment.io"),this.path=o(a.path||"/v1/batch")` |
| **Verdict** | Sends product analytics events to Segment (api.segment.io). Events tracked include user actions like "User Logged Out", "Save Prompt Viewed", "Logged in to Site", etc. Respects user tracking preferences (`isTrackingEnabled` localStorage flag, `encryptedVaultDataSource.repromptSettings.improve`). Standard product analytics -- no passwords, vault data, or browsing history is sent. |

### 6. INFO - Datadog RUM Integration
| Field | Value |
|---|---|
| **Severity** | INFO |
| **File** | `background-redux-new.js` |
| **Code** | `Mc.init({clientToken:n,env:"prod",version:r.version,site:"datadoghq.com",service:r.dataDogService,useSecureSessionCookie:!0,forwardErrorsToLogs:!1,...` |
| **Verdict** | Standard Datadog Real User Monitoring for error tracking and performance monitoring. Uses secure session cookies. Error forwarding is disabled. Endpoints: `browser-intake-datadoghq.com`, `datad0g-browser-agent.com`, `datadoghq-browser-agent.com`, CloudFront CDN. Standard practice for enterprise software. |

### 7. INFO - Pendo Integration
| Field | Value |
|---|---|
| **Severity** | INFO |
| **File** | `extension-pendo.html`, `static/js/951.extensionPendo.js` |
| **Code** | Pendo loaded in a dedicated extension page (`extension-pendo.html`) |
| **Verdict** | Pendo is used for in-app notifications and user guidance. Runs in an isolated extension page (web-accessible resource), not injected into web pages. Respects the `isTrackingEnabled` preference. Standard product experience tool. |

### 8. INFO - Master Password Reuse Detection
| Field | Value |
|---|---|
| **Severity** | INFO |
| **File** | `background-redux-new.js` |
| **Code** | `checkMasterPasswordReuse:(e,a)=>t($.CHECK_FOR_MASTER_PASSWORD_REUSE,{pageDomain:e,value:a})` |
| **Verdict** | Monitors form submissions to detect if the user enters their master password on a non-LastPass website. Compares the entered value locally against a hash -- the password is NOT sent to any server. If detected, shows a warning: "Risk detected! You entered your master password on [site]." This is a legitimate security feature to prevent credential reuse. |

## False Positive Table

| Pattern | Location | Reason |
|---|---|---|
| `eval()` / `new Function()` | `background-redux-new.js`, `web-client-content-script.js` | Webpack module system boilerplate and OIDC client library JOSE/JWT parsing. Standard bundler output. |
| `document.cookie` access | `web-client-content-script.js` | Datadog RUM SDK cookie management (`_dd_s` session cookie). Standard APM library behavior. |
| `innerHTML` assignments (3) | `web-client-content-script.js` | React DOM rendering internals. Known FP. |
| `XMLHttpRequest.prototype` | `background-redux-new.js` | Axios HTTP client library. Known FP (Axios auth headers). |
| `.interceptors.request/response` | `background-redux-new.js` | Axios interceptors for authentication token injection and error handling. Standard Axios usage pattern. |
| `keydown`/`keyup` events | Multiple files | React/Chakra UI keyboard navigation, focus trapping (Floating UI). Known FP. |
| `postMessage` usage (20 files) | Multiple files | Extension internal communication between content scripts, background, and extension pages. Standard MV3 messaging pattern. |
| `onBeforeSendHeaders` | `web-client-content-script.js` | Filters extension origin request headers. Used to strip unnecessary headers from extension-internal requests. |
| `importScripts` | `background-redux-new.js` | Webpack chunk loading for service worker. Standard bundler pattern for MV3 service workers. |
| `feature_flag` / `featureFlag` | `background-redux-new.js` | LaunchDarkly-style feature flag checks for gradual rollout of new features. Server-side feature toggles controlling UI features, not remote code execution. |
| `cloudfront.net` domains | Background + content script | Datadog RUM SDK CDN delivery (`d3uc069fcn7uxw.cloudfront.net`, `d20xtzwzcl0ceb.cloudfront.net`). Present in CSP allowlist and in public suffix list data. |

## API Endpoints Table

| Endpoint | Purpose | Data Sent |
|---|---|---|
| `https://lastpass.com/*` | Main vault, web client | Encrypted vault operations |
| `https://lastpass.eu/*` | EU data residency | Same as above (EU region) |
| `https://accounts.lastpass.com/*` | Account management, SSO | Authentication, OIDC flows |
| `https://pollserver.lastpass.com/poll_server.php` | Vault sync polling | Session info, version, sync status |
| `https://api.pwnedpasswords.com/range/` | Breach detection (k-anonymity) | First 5 chars of SHA-1 hash prefix |
| `https://api.segment.io/v1/batch` | Product analytics | User events (non-PII, respects opt-out) |
| `https://browser-intake-datadoghq.com` | Error monitoring | Performance metrics, error logs |
| `https://login.microsoftonline.com/*` | Microsoft SSO | OIDC authentication flow |
| `https://*.okta.com/*`, `*.oktapreview.com/*` | Okta SSO | OIDC authentication flow |
| `https://*.pingone.com/*` (+ regional) | PingOne SSO | OIDC authentication flow |
| `https://accounts.google.com/*` | Google SSO + Drive backup | OIDC auth, Drive API for vault backup |
| `https://content.googleapis.com/drive/v3/*` | Google Drive vault backup | Encrypted vault backup data |
| `https://*.onelogin.com/*` | OneLogin SSO | OIDC authentication flow |
| `wss://*.lastpass.com`, `wss://*.lastpass.eu` | WebSocket sync (CSP only) | Real-time vault sync |

## Data Flow Summary

1. **Credential Detection**: Content script (`web-client-content-script.js`) injected into all pages detects login forms via DOM observation. Form field data is communicated to the background service worker via `chrome.runtime.sendMessage`.

2. **Autofill**: Background script matches detected forms against encrypted vault data (decrypted client-side using PBKDF2/AES derived from master password). Credentials are sent back to the content script for injection into form fields.

3. **Passkey Management**: `credentials-library.js` (MAIN world) intercepts `navigator.credentials.create/get` to enable LastPass-managed passkeys. Communicates with the extension via `postMessage` to the content script, which relays to the background.

4. **Vault Sync**: Background script polls `pollserver.lastpass.com` for changes and syncs encrypted vault data. All vault data remains encrypted in transit and at rest.

5. **Federated Login**: `onBeforeRequest` listener monitors OIDC redirect flows during SSO authentication with Microsoft, Google, Okta, PingOne, and OneLogin.

6. **Login Detection**: `first-password-loggedin-detector.js` (MAIN world, web-accessible) checks if user is logged into major sites (Google, Amazon, LinkedIn, Facebook, Outlook) by reading cookies. Only returns boolean `isLoggedIn` -- no cookie values are exfiltrated.

7. **Master Password Protection**: Monitors form submissions to warn users if they type their master password on non-LastPass sites. Comparison is done locally.

8. **Analytics**: Segment (product analytics) and Datadog (error monitoring) collect non-PII operational data. Both respect user opt-out preferences.

9. **Chrome Privacy API**: Uses `chrome.privacy.services.passwordSavingEnabled` to disable Chrome's built-in password saving (to avoid conflicts). Optional permission.

## Overall Risk Assessment

**CLEAN**

LastPass is a legitimate, well-known password manager from a major security company (owned by GoTo/LogMeIn). While the extension requires extensive permissions (all URLs, webRequest with requestBody, scripting, tabs), every permission is justified by core password manager functionality:

- **All URLs**: Required to detect and fill login forms on any website
- **webRequest + requestBody**: Required for federated SSO login interception
- **scripting**: Required for dynamic content script injection
- **tabs/webNavigation**: Required for form detection and autofill coordination
- **storage/unlimitedStorage**: Required for encrypted vault cache
- **offscreen**: Required for clipboard operations and localStorage in MV3

No evidence of:
- Data exfiltration or unauthorized data collection
- Residential proxy infrastructure
- Extension enumeration or competitor killing
- Ad/coupon injection or affiliate fraud
- Market intelligence SDK injection (no Sensor Tower, Pathmatics, SimilarWeb)
- AI conversation scraping
- Remote code execution or code download
- Intentional obfuscation (standard webpack minification only)

The analytics integrations (Segment, Datadog, Pendo) are industry-standard, properly configured, and respect user opt-out settings. All network communication is with known LastPass infrastructure or well-documented third-party services listed in the CSP.
