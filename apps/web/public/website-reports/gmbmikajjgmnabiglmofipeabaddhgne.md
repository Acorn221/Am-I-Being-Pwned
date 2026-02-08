# Vulnerability Report: Save to Google Drive

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Save to Google Drive |
| Extension ID | gmbmikajjgmnabiglmofipeabaddhgne |
| Version | 3.0.9 |
| Manifest Version | 3 |
| User Count | ~8,000,000 |
| Author | drive-web-fe-eng@google.com (Google) |
| Analysis Date | 2026-02-08 |

## Executive Summary

Save to Google Drive is an **official Google extension** that allows users to save web content (pages, images, audio, video) directly to Google Drive. The extension is built using Google's Closure Library and compiled JavaScript. It uses Manifest V3 with a service worker architecture.

The extension requests broad permissions (`<all_urls>`, `tabs`, `webRequest`, `pageCapture`, `scripting`) which are necessary for its core functionality of capturing and saving content from any page. All network communication is exclusively directed to official Google APIs (`googleapis.com`). The codebase uses Google's safevalues library for secure DOM manipulation and trusted types enforcement.

**No malicious behavior, vulnerabilities, or suspicious patterns were identified.** The extension performs exactly its intended function with no extraneous data collection, no third-party communications, and no dynamic code loading beyond standard Closure Library patterns.

## Vulnerability Details

### INFO-01: Broad Host Permissions
| Field | Value |
|-------|-------|
| Severity | INFO |
| File | manifest.json |
| Verdict | FALSE POSITIVE - Required for functionality |

The extension requests `<all_urls>` host permission. This is required because the extension needs to:
- Capture page content from any website via `pageCapture`
- Monitor content types via `webRequest.onResponseStarted` for all main frame URLs
- Inject content scripts to capture page HTML, expand CSS, and handle scrolling for full-page screenshots

This is a necessary and expected permission for a "save any page to Drive" extension.

### INFO-02: OAuth2 Scopes
| Field | Value |
|-------|-------|
| Severity | INFO |
| File | manifest.json |
| Verdict | EXPECTED |

The extension uses OAuth2 with scopes:
- `https://www.googleapis.com/auth/drive.file` - Write files to Drive (core functionality)
- `https://www.googleapis.com/auth/userinfo.email` - Get user email for account display

These are minimal and appropriate scopes for the extension's purpose.

### INFO-03: Closure Library eval/Function Patterns
| Field | Value |
|-------|-------|
| Severity | INFO |
| File | js/rpc.js.compiled (lines 55-57), js/backgroundpagebootstrap.js (Closure Library) |
| Verdict | FALSE POSITIVE - Closure Library standard patterns |

```javascript
// rpc.js.compiled - Gadgets RPC JSON parsing fallback
j=(new Function("return ("+k+"\n)"))()
// Closure Library config parsing
return eval("("+text+")")
```

These are standard Google Closure Library patterns for gadgets RPC configuration parsing (part of the Google API client library) and `goog.loadModuleFromSource_` which is only used in debug/development mode (`!COMPILED` path). In the compiled production build (`COMPILED=true`), these code paths are dead code.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `new Function()` | rpc.js.compiled:55-57 | Google Closure Library gadgets RPC JSON config parsing |
| `eval()` | rpc.js.compiled:386 | Gadgets JSON fallback parser, only used when native JSON unavailable |
| `goog.globalEval()` | All scripts | Closure Library standard, only active in debug mode |
| `goog.loadModuleFromSource_` | All scripts | Closure Library standard, dead code in production (COMPILED=true) |
| `document.write()` | Closure Library | Debug loader, dead code in production (COMPILED=true) |
| `innerHTML` / DOM manipulation | safevalues library | Google's safevalues library provides type-safe DOM manipulation |
| `postMessage` | rpc.js.compiled | Standard gadgets.rpc cross-frame communication for Google Picker |
| `XMLHttpRequest` | Closure Library | `goog.loadFileSync_` - debug-only file sync loader |
| `<all_urls>` webRequest | backgroundpagebootstrap.js | Content-Type detection for main_frame responses |
| `chrome.identity.getAuthToken` | backgroundpagebootstrap.js | Standard OAuth2 token management |

## API Endpoints Table

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `https://www.googleapis.com/drive/v2/files` | GET/PUT/POST | Google Drive file operations (upload, rename, trash) |
| `https://www.googleapis.com/upload/drive/v2/files` | POST | Resumable file uploads to Google Drive |
| `https://www.googleapis.com/userinfo/v2/me` | GET | Retrieve authenticated user email |
| `https://www.googleapis.com/drive/v2/about` | GET | Drive account info |
| `https://clients2.google.com/service/update2/crx` | GET | Chrome extension auto-update (standard) |

## Data Flow Summary

1. **User triggers save**: User clicks the browser action button or uses context menu (right-click > Save to Google Drive).
2. **Authentication**: Extension calls `chrome.identity.getAuthToken()` for Google OAuth2 token.
3. **Content capture**: Depending on the action:
   - **Page capture**: Uses `chrome.pageCapture` API to create MHTML.
   - **Image/scrolling capture**: Injects content scripts (`contentscriptscroll.js`, `contentscriptexpand.js`, `contentscriptraw.js`) to capture page content.
   - **URL save**: Downloads the resource directly.
   - **Element position**: Uses `elementposition.js` to detect clickable elements for selection capture.
4. **Upload**: Uses resumable upload to `googleapis.com/upload/drive/v2/files` with proper auth headers.
5. **Display results**: Opens upload dialog (`upload.html`) showing progress and result.
6. **Print-to-Drive**: Registers as a virtual printer via `chrome.printerProvider` for print-to-Drive functionality.

All data flows are strictly between the browser, the extension, and official Google APIs. No data is sent to any third-party service.

## Overall Risk Assessment

| Risk Level | CLEAN |
|------------|-------|

**Justification**: This is an official Google extension authored by `drive-web-fe-eng@google.com`. The codebase is built with Google's Closure Library and follows Google's internal security practices (safevalues library, Trusted Types). All network communication goes exclusively to official Google API endpoints. The broad permissions (`<all_urls>`, `tabs`, `webRequest`, `pageCapture`, `scripting`) are all necessary for the extension's core functionality of capturing and saving web content to Google Drive. There is no evidence of any malicious behavior, data exfiltration, third-party SDK injection, extension enumeration, residential proxy infrastructure, remote configuration, or any other suspicious activity. The `new Function()` and `eval()` patterns found are standard Closure Library/Gadgets RPC patterns that are either dead code in production builds or only used for safe JSON config parsing.
