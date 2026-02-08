# Vulnerability Report: Take Webpage Screenshots Entirely - FireShot

## Metadata
- **Extension Name:** Take Webpage Screenshots Entirely - FireShot
- **Extension ID:** mcbpblocgmgfnpjjppndjkmgjaogfceg
- **Version:** 2.1.4.7
- **Manifest Version:** 3
- **User Count:** ~3,000,000
- **Author:** Evgeny Vokilsus (contacts@getfireshot.com)
- **Analysis Date:** 2026-02-08

## Executive Summary

FireShot is a well-established webpage screenshot tool with ~3M users. The extension captures full-page, visible area, or selection screenshots and supports saving to various formats including PDF (via WASM encoder), with optional native helper for advanced features. It also integrates with Gmail via InboxSDK for email attachment functionality.

The extension uses a reasonable set of permissions for its purpose. All network communication is directed to first-party domains (getfireshot.com, ssl.getfireshot.com, screenshot-program.com, auth.getfireshot.com) for legitimate purposes: licensing/activation, crash reporting, error monitoring (Sentry), and update checks. No evidence of data exfiltration, malicious behavior, market intelligence SDKs, proxy infrastructure, or dynamic code execution was found.

**Overall Risk: CLEAN**

## Permissions Analysis

| Permission | Justification | Risk |
|---|---|---|
| `storage` | Stores user preferences and licensing data | LOW |
| `alarms` | Scheduled update checks | LOW |
| `scripting` | Injects content scripts for screenshot capture | LOW |
| `activeTab` | Captures the currently active tab | LOW |
| `nativeMessaging` | Communicates with desktop helper for PDF/save features | LOW |
| `contextMenus` | Right-click menu for capture options | LOW |

### Optional Permissions
| Permission | Justification | Risk |
|---|---|---|
| `tabs` | Access tab info for batch capture/capture list features | LOW |
| `downloads` | Save screenshots to disk | LOW |
| `<all_urls>` (optional host) | Required for capturing any page; optional, user-granted | LOW |
| `https://mail.google.com/*` (optional host) | Gmail integration via InboxSDK | LOW |

### CSP
```
script-src 'self' 'wasm-unsafe-eval'; object-src 'self';
```
The `wasm-unsafe-eval` is required for the PDF encoder WASM module. No `unsafe-eval` or remote script loading.

## Vulnerability Details

### No Vulnerabilities Found

No significant security vulnerabilities were identified. The extension:

1. **No eval/Function constructor usage** - No dynamic code execution patterns detected
2. **No remote code loading** - All scripts are bundled locally
3. **No cookie/credential harvesting** - No access to document.cookie or auth tokens
4. **No browsing history collection** - No chrome.history usage
5. **No extension enumeration** - No chrome.management API usage
6. **No XHR/fetch hooking** - Sentry SDK hooks are standard error monitoring (known FP)
7. **No keylogging** - Keyboard listener patterns are from Sentry SDK (known FP) and the selection area tool (Escape key handler)
8. **No data exfiltration** - All outbound traffic goes to first-party domains for legitimate purposes

## False Positive Table

| Pattern | Location | Explanation |
|---|---|---|
| `addEventListener("keypress")` | fsServiceWorker.js (Sentry SDK) | Sentry breadcrumb capture for error context - standard SDK behavior |
| `createElement("script")` | fsServiceWorker.js (Sentry SDK) | Sentry `showReportDialog` function - standard SDK feature |
| `XMLHttpRequest` prototype wrapping | fsServiceWorker.js (Sentry SDK) | Sentry XHR instrumentation for breadcrumbs - standard SDK behavior |
| `De(s, "addEventListener")` | fsServiceWorker.js (Sentry SDK) | Sentry event target wrapping for error boundaries - standard SDK behavior |
| `innerHTML` / `insertAdjacentHTML` | fsAutomationBanner.js | Creates batch mode progress banner UI - static HTML template only |
| InboxSDK injection | fsServiceWorker.js | Well-known Gmail integration library, used for email attachment feature |

## API Endpoints Table

| Endpoint | Purpose | Data Sent |
|---|---|---|
| `https://auth.getfireshot.com/activate/...` | License activation | License key, hardware ID, extension version |
| `https://auth.getfireshot.com/deactivate/...` | License deactivation | Session ID, GUID |
| `https://auth.getfireshot.com/experiment/v2/...` | A/B testing for features | Anonymous experiment ID, mode (no-cors) |
| `https://ssl.getfireshot.com/images/api/utm.gif` | Install/update analytics | Day counter (anonymous) |
| `https://ssl.getfireshot.com/images/api/chromefeatures.gif` | Feature usage tracking | Anonymous feature flags |
| `https://ssl.getfireshot.com/sentry-filter-*.csv` | Error filter config | Extension version |
| `https://screenshot-program.com/fireshot/crash_report.php` | Crash reports | Error stack, user comment (user-initiated) |
| `https://o4507590541901824.ingest.us.sentry.io/...` | Error monitoring (Sentry) | Error data, extension version, UUID |
| `https://getfireshot.com/installed*.php` | Install tracking | Extension version |
| `https://getfireshot.com/updated*.php` | Update tracking | Extension version |

## Data Flow Summary

1. **Screenshot Capture:** Content scripts (fsContent.js, fsFrames.js) are injected into the active tab to measure page dimensions, scroll, and capture visible portions. Screenshots are taken via chrome.tabs.captureVisibleTab (implied by Manifest V3 `activeTab`). Data stays local.

2. **PDF Generation:** Screenshot data is processed by fsWorker.js + fsEncoder.wasm locally in a Web Worker. No image data is sent to any server.

3. **Licensing:** The extension communicates with `auth.getfireshot.com` for Pro license validation, sending UA string, timestamp, hardware ID, and extension version via the `X-FS-DATA` header. This is standard commercial software licensing.

4. **Error Reporting:** Sentry SDK sends error/crash data to sentry.io. Users can opt out. The extension also maintains a server-side error filter to reduce noise.

5. **Native Messaging:** Communicates with a local desktop helper application (`com.getfireshot.api`) for advanced save formats. Data stays on the local machine.

6. **Gmail Integration:** Uses InboxSDK (well-known library) to add screenshot attachment functionality to Gmail when the user grants the optional `mail.google.com` permission.

## Overall Risk Assessment

**CLEAN**

FireShot is a legitimate, well-established screenshot tool. While it requires several permissions and makes network requests, all functionality directly serves its stated purpose. The permissions are appropriately scoped (using `activeTab` instead of broad host permissions by default, with `<all_urls>` as optional). Network traffic is limited to first-party domains for licensing, analytics, and error reporting. The Sentry integration includes user opt-out capability. No evidence of malicious behavior, data harvesting, or privacy violations was found.
