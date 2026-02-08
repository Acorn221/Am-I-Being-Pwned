# Vulnerability Report: IDM Integration Module

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | IDM Integration Module |
| Extension ID | ngpampappnmepgilojfohadhhmbhlaek |
| Version | 6.42.59 |
| Author | Tonec FZE |
| Users | ~20,000,000 |
| Manifest Version | 3 |
| Homepage | http://www.internetdownloadmanager.com/ |

## Executive Summary

IDM Integration Module is the official browser extension for Internet Download Manager (IDM), a well-known Windows desktop download manager. The extension intercepts browser download requests and routes them to the native IDM desktop application via WebSocket (localhost:1001) and native messaging (`com.tonec.idm`). It monitors all web requests, detects media content (video/audio) on pages, and provides context menu integration for downloading.

The extension requests extensive permissions (`<all_urls>`, `webRequest`, `cookies`, `tabs`, `downloads`, `management`, `proxy`, `nativeMessaging`, `scripting`, `declarativeNetRequest`) which are **all justified** by its core download management functionality. There are no signs of data exfiltration, malicious behavior, ad injection, or any activity outside the scope of its intended purpose.

## Vulnerability Details

### V-001: Broad Permission Scope
| Field | Value |
|-------|-------|
| Severity | LOW (Informational) |
| Files | `manifest.json` |
| Verdict | **Justified for functionality** |

The extension requests `<all_urls>` host permissions and numerous API permissions. However, every permission maps directly to IDM's core function:
- `webRequest` + `<all_urls>`: Intercept download requests across all sites
- `cookies`: Pass authentication cookies to IDM so downloads resume correctly
- `downloads` + `downloads.shelf` + `downloads.ui`: Intercept and redirect downloads to IDM
- `nativeMessaging`: Communicate with the IDM desktop application
- `proxy`: Read proxy settings to pass to IDM for download routing
- `management`: Check for Epic Privacy Browser extension (ID: `clhiejnehegdfknplplojohghjaklbae`) for compatibility
- `tabs` + `webNavigation` + `scripting`: Detect media on pages and manage download UI
- `declarativeNetRequest`: Handle IDM registration URL redirects
- `storage`: Store client ID and extension state
- `contextMenus`: "Download with IDM" context menu

### V-002: Local WebSocket Communication
| Field | Value |
|-------|-------|
| Severity | LOW (Informational) |
| Files | `background.js` (line ~98) |
| Code | `Fa=["127.0.0.1:1001","0.1.0.1:1001"]` |
| Verdict | **Expected behavior** |

The extension communicates with the IDM desktop app via WebSocket on `127.0.0.1:1001` (and fallback `0.1.0.1:1001`). It also uses native messaging (`com.tonec.idm`) as a fallback channel. This is the standard architecture for browser-to-desktop-app communication and all data stays local.

### V-003: XHR/Fetch Request Interception (document.js)
| Field | Value |
|-------|-------|
| Severity | LOW (Informational) |
| Files | `document.js` |
| Verdict | **Expected behavior - download detection** |

The `document.js` script (injected as a web-accessible resource) hooks `XMLHttpRequest.open`, `XMLHttpRequest.send`, `fetch`, `Response.text()`, and `Response.arrayBuffer()` to detect downloadable content from XHR/fetch responses. The intercepted data (URLs and response content hashes) is sent back to the content script via `window.postMessage` with message codes `1229212977`-`1229212983`. This is a standard technique for download managers to capture streaming media URLs that aren't visible to the `webRequest` API.

### V-004: ROT13 Obfuscation of YouTube Selectors
| Field | Value |
|-------|-------|
| Severity | LOW (Informational) |
| Files | `content.js` |
| Verdict | **Anti-detection measure, not malicious** |

The content script uses ROT13 encoding for YouTube-specific DOM selectors and config property names (e.g., `ytcfg.set`, `EXPERIMENT_FLAGS`, `PLAYER_JS_URL`, `VISITOR_DATA`, `ytmusic-player`). This is likely to avoid automated detection/blocking by YouTube's anti-download measures, not to hide malicious behavior.

### V-005: Keyboard Modifier Key Tracking
| Field | Value |
|-------|-------|
| Severity | LOW (Informational) |
| Files | `content.js` |
| Code | `const da={16:!0,17:!0,18:!0,45:!0,46:!0}` (Shift, Ctrl, Alt, Insert, Delete) |
| Verdict | **Expected behavior - hotkey support** |

The content script listens for keydown/keyup events but ONLY for modifier keys (keyCodes 16=Shift, 17=Ctrl, 18=Alt, 45=Insert, 46=Delete). This is used for IDM's keyboard shortcut functionality (e.g., hold Alt+click to force download). No text input or password keylogging occurs.

### V-006: Console Method Override (debug.js)
| Field | Value |
|-------|-------|
| Severity | LOW (Informational) |
| Files | `debug.js` |
| Verdict | **Anti-fingerprinting measure** |

The `debug.js` script overrides `console.log`, `console.dir`, and `console.table` to suppress logging of function objects and objects with non-enumerable getter properties. This prevents sites from detecting/fingerprinting the extension's injected hooks. It respects Cloudflare challenge pages (`_cf_chl_opt`).

### V-007: Cookie Access for IDM Homepage
| Field | Value |
|-------|-------|
| Severity | LOW (Informational) |
| Files | `background.js` (line ~107-108) |
| Verdict | **Expected behavior - client ID persistence** |

The extension reads/writes a single cookie (`idmwebext_cid`) on `internetdownloadmanager.com` to maintain a client ID that syncs between the extension and the IDM website. This is standard license/client identification behavior.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| XHR/fetch hooking | `document.js` | Download detection for streaming media, not data theft |
| ROT13 obfuscation | `content.js` | YouTube anti-blocking, not hiding malicious code |
| Keyboard event listeners | `content.js` | Modifier keys only (Shift/Ctrl/Alt/Ins/Del) for hotkeys |
| `console.log` override | `debug.js` | Anti-fingerprinting, not hiding malicious activity |
| `management.get()` call | `background.js` | Checks for Epic Privacy Browser extension for compatibility |
| `<all_urls>` permission | `manifest.json` | Required for download interception on all sites |
| Mouse event tracking | `content.js` | Tracking click coordinates for download button overlay positioning |
| `proxy` permission | `background.js` | Reads proxy settings to pass to IDM for download routing |

## API Endpoints Table

| Endpoint | Purpose | Direction |
|----------|---------|-----------|
| `ws://127.0.0.1:1001/` | WebSocket to local IDM app | Local only |
| `ws://0.1.0.1:1001/` | Fallback WebSocket to local IDM app | Local only |
| `com.tonec.idm` (native messaging) | Native messaging to IDM app | Local only |
| `http://www.internetdownloadmanager.com/` | Homepage URL (cookie domain) | Read cookie only |
| `internetdownloadmanager.com`, `tonec.com` | externally_connectable origins | Inbound messages only |

## Data Flow Summary

1. **Content Script** (`content.js`): Injected on all pages. Detects video/audio elements, monitors DOM changes, tracks modifier key state for hotkeys, reports media element positions/URLs to background script via `runtime.connect()`.

2. **Document Script** (`document.js`): Injected as web-accessible resource. Hooks XHR/fetch to capture streaming media URLs. Communicates with content script via `window.postMessage` (same-origin only, codes `1229212977-1229212983`).

3. **Background Script** (`background.js`):
   - Listens to all `webRequest` events to detect downloadable content
   - Reads cookies for download URLs to pass authentication to IDM
   - Communicates with local IDM desktop app via WebSocket (`127.0.0.1:1001`) or native messaging (`com.tonec.idm`)
   - Manages context menus ("Download with IDM")
   - Redirects browser downloads to IDM
   - Reads proxy settings to pass to IDM

4. **No external network calls**: All communication is either to the local IDM app (WebSocket/native messaging) or reading browser state (cookies, proxy). No data is sent to remote servers.

## Overall Risk: **CLEAN**

This is a legitimate download manager integration extension from Tonec FZE (the company behind Internet Download Manager). Despite its extensive permissions and deep browser integration (XHR/fetch hooking, webRequest monitoring, cookie access), all functionality directly supports its stated purpose of intercepting and routing downloads to the IDM desktop application. There is:

- **No data exfiltration** to remote servers
- **No ad/coupon injection**
- **No tracking/analytics SDKs**
- **No remote code execution or dynamic code loading**
- **No residential proxy infrastructure**
- **No extension enumeration/killing** (the `management.get` call checks for a single known extension for compatibility)
- All communication stays local (localhost WebSocket + native messaging)
