# Security Analysis: ESET Password Manager

| Field | Value |
|-------|-------|
| Extension ID | `khhapgacijodhjokkcjmleaempmchlem` |
| Version | 3.8.0 |
| Manifest Version | 3 |
| Users | ~60,000 |
| Risk | **CLEAN** |
| Date | 2026-02-09 |

## Summary

Legitimate ESET password manager with broad but justified permissions for autofill, cookie-based SSO, and breach monitoring; all traffic goes to ESET-controlled infrastructure.

## Vulnerabilities

### VULN-01: Web-Accessible HTML Resources Exposed to All Sites [LOW]

**Files:** `manifest.json:57-70`

```json
"web_accessible_resources": [
    {
      "matches": [
        "http://*/*",
        "https://*/*"
      ],
      "resources": [
        "src/images/icons/blank.png",
        "src/content_scripts/popup.html",
        "src/content_scripts/notification.html",
        "src/images/icons/icon-32.png",
        "src/images/icons/icon-32-i.png",
        "src/images/icons/iconForce-32.png"
      ]
    }
]
```

**Analysis:** The extension exposes `popup.html` and `notification.html` as web-accessible resources to all HTTP/HTTPS origins. Any website can attempt to load these resources to fingerprint whether the extension is installed. The HTML files themselves are simple React containers with no sensitive data. The risk is limited to extension detection/fingerprinting.

**Verdict:** LOW -- Extension fingerprinting is possible but the exposed resources contain no sensitive logic or data.

---

### VULN-02: Remote Configuration Fetched from CDN [LOW]

**Files:** `src/background/background.js:20804`, `src/sp-core/core.js:42701`

```javascript
CONFIG_URL: "https://cdn-static.pwm.eset.systems/settings/config-eset.json",
```

```javascript
// core.js - RemoteConfig service
url: this._servicesConfigProvider.getApiUrls().CONFIG_URL,
```

**Analysis:** The extension periodically fetches a remote configuration JSON from ESET's CDN (`cdn-static.pwm.eset.systems`). The default config (hardcoded as fallback) controls feature flags like `tfaEnabled`, `sentryEnabled`, `freeAccountLimit`, `trialDaysLimit`, and sync intervals. This is a standard feature management pattern. The config does not contain executable code, extension disable/enable commands, or any mechanism to alter extension behavior beyond predefined feature toggles. The domain is ESET-controlled infrastructure.

**Verdict:** LOW -- Standard remote feature configuration from first-party CDN with no code execution or kill-switch capability.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `Function("return this")()` | content-script.js:216,6258; popup.js:3979,29420; notification.js:4046,30568; services.js:23309,27152,31257; background.js:19961,31445; core.js:23216,65257; ui-vendors.js:10649,86913 | Webpack/bundler global `this` polyfill |
| `new Function("F,a", ...)` | services.js:23007 | core-js polyfill for `Reflect.construct` |
| `new Function(...)` in core.js:24787 | core.js:24787 | jQuery `parseJSON` fallback (never reached in modern browsers with native JSON) |
| `Function("return function*() {}")` | core.js:11270 | Generator function feature detection |
| `Function("binder", ...)` | core.js:10284 | `function-bind` polyfill |
| `new Function(...)` for File polyfill | ui-vendors.js:83281 | jsPDF File constructor polyfill |
| XHR prototype patching | background.js:1028-1059 | Sentry SDK breadcrumb instrumentation (`__sentry_xhr_v3__`) |
| `postMessage(e, "*")` | background.js:6540; ui-vendors.js:31769 | Sentry rrweb session replay cross-origin iframe communication (origin validated at line 6196: `t.origin !== t.data.origin`) |
| `postMessage(e + "", "*")` | services.js:24020 | core-js `setImmediate` polyfill using message channel |
| `addEventListener("message", ...)` | background.js:10621 | Sentry report dialog close handler |
| keydown/keypress listeners | popup.js, notification.js (React), background.js:906 | React synthetic event system and Sentry breadcrumb click/keypress tracking |
| `document.cookie` access | services.js:17946-18082 | mParticle SDK cookie management for analytics session tracking |
| `chrome.cookies.getAll` | background.js:27241,27312; services.js:289,2742 | Reading specific named cookies from `eset.com` and `saferpass.com` for SSO/premium detection |
| innerHTML usage | popup.js, notification.js, background.js | React DOM rendering (dangerouslySetInnerHTML), Preact virtual DOM |
| mParticle SDK | services.js:16035-19949 | Analytics SDK bundled but `mParticleKey` is `void 0` (disabled) |

## Flags

| Category | Evidence |
|----------|----------|
| war_js_html_all_urls | `manifest.json`: popup.html and notification.html exposed as web-accessible resources to all HTTP/HTTPS origins |
| remote_config | `src/sp-core/core.js`: Fetches config-eset.json from cdn-static.pwm.eset.systems for feature flags (sync intervals, premium limits, sentry toggle) |

## Endpoints

| Domain | Purpose | Data Sent |
|--------|---------|-----------|
| api.pwm.eset.systems | Primary API (user, auth, sync, sharing, migration, feedback, monitoring, SSO, key rotation, icons, verification, analytics, organization) | Encrypted vault data, auth tokens, user metadata |
| sync.pwm.eset.systems | Password vault synchronization | Encrypted vault documents |
| notify.pwm.eset.systems (WSS + HTTPS) | Real-time push notifications via WebSocket | Session tokens |
| cdn-static.pwm.eset.systems | CDN for static assets and remote config | None (read-only) |
| troubleshoot.pwm.eset.systems | Sentry error reporting DSN | Error/crash reports, session replays |
| api.pwnedpasswords.com | Have I Been Pwned password check (k-anonymity) | First 5 chars of password SHA-1 hash (k-anonymity model) |
| haveibeenpwned.com | Breach monitoring reference | None (informational link) |
| maps.googleapis.com | Static map images for device location display | Latitude/longitude from IP geolocation |
| home.eset.com | SSO cookie exchange, redirect URLs | SSO session cookies |
| go.eset.eu | Product URLs (goodbye, welcome, knowledge base) | None (redirect URLs) |
| help.eset.com | Help documentation | None (informational) |
| jssdks.mparticle.com | mParticle analytics SDK endpoints (currently disabled, key is undefined) | None when disabled |
| identity.mparticle.com | mParticle identity resolution (currently disabled) | None when disabled |

## Data Flow

The ESET Password Manager operates as a client-side encrypted vault. User credentials and sensitive data (passwords, credit cards, identities, notes) are encrypted locally using libsodium (loaded as WASM) before being synced to ESET's servers at `api.pwm.eset.systems` and `sync.pwm.eset.systems`.

The content script (`content-script.js`) runs on all pages to detect login/registration forms using extensive regex-based field classification. When forms are detected, it communicates with the background service worker via `chrome.runtime.sendMessage` through the `forge` messaging bridge. The extension injects iframe-based popups (`popup.html`, `notification.html`) for autofill UI.

Authentication flows use ESET's "doorman" service for CSA (Client Security Authentication) registration and Actify for additional verification. SSO integration reads cookies from `eset.com` and `saferpass.com` (SaferPass was the original product name before ESET acquisition) to detect premium status and pre-registration info.

The `browsingData` permission is used for a "clear browsing data" feature within the password manager UI. The `bookmarks` permission enables bookmark import. The `cookies` permission is used exclusively for reading/removing specific named cookies on ESET/SaferPass domains for SSO flows -- not for broad cookie harvesting.

Error monitoring is handled by Sentry SDK (DSN points to ESET-controlled `troubleshoot.pwm.eset.systems`), which includes rrweb session replay for debugging. The mParticle analytics SDK is bundled but the API key is set to `undefined`, meaning it is currently inactive.

A Google Maps Static API key (`AIzaSyBkMFzpyiUPV5hO6y7kpccwOmIjSdP0Zd4`) is embedded for displaying device location maps in the "Secure Me" feature, which helps users locate devices where their vault is active.

## Overall Risk: CLEAN

This is a legitimate password manager produced by ESET, a well-known cybersecurity company (originally developed as SaferPass and acquired by ESET). The extension requires broad permissions (`<all_urls>`, cookies, tabs, browsingData, bookmarks, clipboardWrite, unlimitedStorage) that are all justified by its password management functionality: autofill requires page access, SSO requires cookie access, vault management requires storage, and the browsing data clearing feature requires the browsingData permission.

All network communication is directed to ESET-controlled infrastructure (`*.pwm.eset.systems`, `*.eset.com`, `*.eset.eu`) with the exception of standard third-party services (Have I Been Pwned for breach checking, Google Maps for device location). The remote configuration mechanism fetches feature flags from a first-party CDN without code execution capability. No evidence of data exfiltration, ad injection, affiliate fraud, keylogging, extension enumeration, or any other malicious behavior was found. The bundled mParticle analytics SDK is disabled (key is undefined). The two low-severity findings (WAR fingerprinting and remote config) are standard patterns in legitimate extensions of this type.
