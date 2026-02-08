# Vulnerability Report: LINE

## Metadata
- **Extension Name:** LINE
- **Extension ID:** ophjlpahpchlmihnnnihgmmeilfjmjjc
- **Version:** 3.7.1
- **Users:** ~4,000,000
- **Manifest Version:** 3
- **Publisher:** LINE Corporation (LY Corporation)

## Executive Summary

LINE is the official Chrome extension for the LINE messaging platform, one of the largest messaging services in Asia. The extension operates as a standalone popup-based messaging client (not injecting into web pages). It uses a panel window to display a React-based chat interface, connecting to official LINE backend servers for messaging, media, stickers, and related features.

The extension requests broad permissions (`host_permissions: *://*/*`, `cookies`, `downloads`) but these are justified by its function as a full messaging client that needs to fetch media (stickers, profile images, shared content) from various CDN subdomains and uses cookies for authentication session management. No content scripts are declared. The extension does not inject into any web pages.

No malicious behavior, data exfiltration beyond expected messaging telemetry, or exploitable vulnerabilities were identified.

## Vulnerability Details

### LOW-1: Broad Host Permissions
- **Severity:** LOW
- **Files:** `manifest.json`
- **Code:** `"host_permissions": ["*://*/*"]`
- **Analysis:** The extension requests access to all URLs via host_permissions. This is used for the service worker fetch handler (cache.js) which intercepts sticker image requests to `stickershop` hostnames, and for the main app to fetch media from LINE CDN servers (profile.line-scdn.net, obs.line-scdn.net, shop.line-scdn.net, stickershop.line-scdn.net, emojipack.landpress.line.me). While a narrower permission scope targeting `*.line-scdn.net`, `*.line-apps.com`, `*.line.me` would be preferable, this is a common pattern for large messaging apps that need to load user-shared content from diverse URLs.
- **Verdict:** Informational. Overly broad but not exploited maliciously.

### LOW-2: First-Party Analytics (LINE UTS)
- **Severity:** LOW
- **Files:** `static/js/main.js`
- **Code:** `endpoint:"https://uts-front.line-apps.com"` and `fetch("".concat(d,"/event-web"),{method:"POST",body:JSON.stringify(u),mode:"no-cors",keepalive:!0})`
- **Analysis:** The extension uses LINE's own User Tracking System (UTS) loaded from `static.line-scdn.net/uts/edge/`. It sends usage telemetry to `uts-front.line-apps.com/event-web`. The telemetry includes session IDs, screen IDs, and user interaction events. MID (user identifiers) are explicitly redacted from URLs before sending: `beforeSend:e=>(gd.test(e.url)&&(e.url=e.url.replace(new RegExp(gd,"g"),"[MID]"))`. This is standard first-party analytics for a messaging app.
- **Verdict:** Expected behavior for LINE's own telemetry. MID redaction is a positive privacy practice.

### LOW-3: Sentry Error Reporting
- **Severity:** LOW
- **Files:** `static/js/main.js`, `static/js/popup.js`
- **Code:** `dsn:"https://56dc42acf92b4b6e9a064e629eae78d8@sentry-uit.line-apps.com/12",release:"line-chrome@3.7.1",environment:"REAL",sampleRate:.5,tracesSampleRate:.2`
- **Analysis:** The extension sends error reports and performance traces to LINE's self-hosted Sentry instance at `sentry-uit.line-apps.com`. Sample rate is 50% for errors and 20% for traces. This is a standard practice for production applications.
- **Verdict:** Expected behavior. Self-hosted Sentry on LINE's own infrastructure.

### INFO-1: Cookie Usage for Authentication
- **Severity:** INFORMATIONAL
- **Files:** `static/js/main.js`, `manifest.json`
- **Code:** `chrome.cookies.remove({url:II().getServerBaseUrl("chrome_gw"),name:"lct"})`
- **Analysis:** The `cookies` permission is used solely for managing the LINE Chrome Gateway authentication cookie (`lct`) on `line-chrome-gw.line-apps.com`. This cookie is removed during logout. No evidence of reading or exfiltrating cookies from other domains.
- **Verdict:** Expected authentication cookie management.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML =` | `static/js/main.js` | React SVG rendering, DOM template operations, Lit Web Components - standard framework patterns |
| `new Function()` | `static/js/main.js` | globalThis polyfill pattern: `new Function("return this")()` - standard webpack/babel output |
| `postMessage` | `static/js/main.js` | Web Worker communication for image transcoding, LTSM sandbox, Forge.js PRNG, and service worker cache clearing. All internal extension communication. |
| `eval()`-like | N/A | No eval() calls found |
| `keypress` collector | `static/js/main.js` | Forge.js entropy collection for cryptographic PRNG (`s.collectInt(e.charCode,8)`) - standard crypto library behavior for E2EE |
| `document.cookie` | `static/js/main.js` | Axios cookie handling utility (standard HTTP client library) |
| Sentry fingerprint/user | `static/js/main.js`, `static/js/popup.js` | Sentry SDK scope management, not browser fingerprinting |
| WebSocket | `static/js/main.js` | LINE messaging transport for real-time message delivery |
| AES encrypt/decrypt | `static/js/main.js` | Node-forge crypto library for E2EE (End-to-End Encryption) in LINE messaging |

## API Endpoints Table

| Endpoint | Purpose |
|----------|---------|
| `line-chrome-gw.line-apps.com` | Main Chrome Gateway API (messaging, auth, operations) |
| `legy-jp.line-apps.com` | LINE Edge Gateway (messaging protocol, Thrift RPC) |
| `legy-backup.line-apps.com` | Backup edge gateway |
| `obs.line-apps.com` | Object storage (media upload/download) |
| `obs.line-scdn.net` | Object storage CDN |
| `profile.line-scdn.net` | Profile image CDN |
| `stickershop.line-scdn.net` | Sticker CDN |
| `shop.line-scdn.net` | LINE Store CDN |
| `emojipack.landpress.line.me` | Emoji CDN |
| `static.line-scdn.net` | Static assets (UTS analytics SDK) |
| `uts-front.line-apps.com` | Usage telemetry |
| `sentry-uit.line-apps.com` | Error reporting (Sentry) |
| `cix.line-apps.com` | Connection info exchange |
| `store.line.me` | Sticker/emoji store (opened in browser) |
| `linevoom.line.me` | LINE VOOM (social feed, opened in browser) |
| `help.line.me` | Help pages (opened in browser) |
| `terms.line.me` | Terms of service (opened in browser) |
| `contact-cc.line.me` | Contact/support (opened in browser) |
| `line.me/R/nv/settings/account` | Account settings QR (opened in browser) |

## Data Flow Summary

1. **Authentication:** User scans QR code from mobile LINE app. Extension communicates via Thrift RPC to `line-chrome-gw.line-apps.com` for session creation, PIN verification, and certificate validation. Auth token stored via `chrome.storage.local` and session cookie `lct`.

2. **Messaging:** Real-time messages received via SSE (Server-Sent Events) from `line-chrome-gw.line-apps.com/api/operation/receive`. Messages sent via Thrift RPC POST requests to the same gateway. End-to-end encryption supported via Node-forge (AES).

3. **Media:** Sticker/emoji PNG images fetched from CDN and cached via Service Worker (`cache.js`). Profile images, shared media, and OBS (Object Binary Storage) content fetched from respective CDN endpoints.

4. **Telemetry:** Usage events sent to LINE's own UTS analytics (`uts-front.line-apps.com`). User MIDs are redacted before sending. Error reporting sent to self-hosted Sentry (`sentry-uit.line-apps.com`) at 50% sample rate.

5. **UI:** Extension opens as a panel window (`chrome.windows.create`) displaying a React SPA. No content scripts injected into web pages. External links (sticker store, help, terms) opened in the default browser via `window.open`.

6. **Storage:** Uses `chrome.storage.local` for window state and settings. Uses IndexedDB for local message/conversation data.

## Overall Risk: **CLEAN**

This is a legitimate messaging client from LINE Corporation (LY Corporation). While it requests broad permissions (`*://*/*`, `cookies`), these are justified by its function as a full-featured messaging application that needs to access multiple CDN domains for media content and manage authentication cookies. All network communication is directed exclusively to official LINE infrastructure (`*.line-apps.com`, `*.line-scdn.net`, `*.line.me`). No content scripts are injected into web pages. No evidence of data exfiltration, malicious behavior, extension enumeration, proxy infrastructure, market intelligence SDKs, or remote kill switches. The extension includes standard first-party analytics with MID redaction and self-hosted error reporting -- both expected for a production messaging application serving millions of users.
