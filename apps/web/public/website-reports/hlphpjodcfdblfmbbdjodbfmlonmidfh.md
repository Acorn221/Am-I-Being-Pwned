# Vulnerability Report: Content Server Browser Web Extension

## Metadata
| Field | Value |
|-------|-------|
| **Extension Name** | Content Server Browser Web Extension |
| **Extension ID** | hlphpjodcfdblfmbbdjodbfmlonmidfh |
| **Version** | 3.0.0.0 |
| **Author** | OpenText |
| **Manifest Version** | 3 |
| **User Count** | ~3,000,000 |
| **Analysis Date** | 2026-02-08 |

## Executive Summary

This is a legitimate enterprise extension by OpenText (formerly Open Text Corporation) that provides a bridge between the OpenText Content Server web interface and native desktop applications (Office Editor, WebDAV). The extension uses Chrome's `nativeMessaging` API to communicate with a locally installed native messaging host (`com.opentext.desktop.webext.messaging`). It reads page data from OpenText Content Server pages, forwards it to the native app for document editing operations (e.g., opening Office documents for editing), and returns results back to the web page.

The extension requests broad permissions (`*://*/` host permissions, `cookies`, `tabs`, `all_frames: true` content scripts on all URLs) which are invasive. However, the content scripts are designed to activate only on pages containing specific OpenText Content Server DOM elements or URL patterns (`func=Edit.Edit`, `func=webdav.webdavedit`). The extension does not make any external network requests, does not inject ads, does not scrape data, and does not contain obfuscated code. All communication flows are local: web page -> content script -> background script -> native messaging host -> and back.

**No malicious behavior detected. The broad permissions are typical of enterprise browser extensions that need to operate on internally-hosted Content Server instances at arbitrary URLs.**

## Vulnerability Details

### LOW-1: Broad Host Permissions with All-Frames Content Script Injection
- **Severity**: LOW
- **Files**: `manifest.json`
- **Code**:
  ```json
  "content_scripts": [{
      "js": ["chrome_only.js", "content.js", "content_v3.js"],
      "all_frames": true,
      "matches": ["http://*/*", "https://*/*"]
  }],
  "host_permissions": ["*://*/"]
  ```
- **Verdict**: The extension injects content scripts into every HTTP/HTTPS page in all frames. While this is a large attack surface, the content scripts perform no action unless they detect specific OpenText Content Server DOM elements (`WebExtension$Channel-{guid}`, `oedata`, `webdavdata`) or URL patterns. This is a common pattern for enterprise extensions that must work on customer-hosted instances at unpredictable URLs. **Not malicious, but increases attack surface.**

### LOW-2: Cookie Access on All Domains
- **Severity**: LOW
- **Files**: `manifest.json`, `background_v3.js` (line 73-74)
- **Code**:
  ```javascript
  // acquireCookies() - only called when extension is actively processing a request
  g_browser.cookies.getAll(details, cookieCallback);
  ```
- **Verdict**: The extension reads session cookies for the current tab's URL and forwards them to the native messaging host. This is used for authentication passthrough (so the native Office Editor app can authenticate to Content Server). Cookies are only acquired when the background script is actively processing an edit request initiated by a Content Server page. Cookie data is only sent to the local native messaging host, never to any remote server. **Legitimate enterprise SSO functionality.**

### INFO-1: innerHTML Usage in Logging
- **Severity**: INFO
- **Files**: `content.js` (line 111, 127)
- **Code**:
  ```javascript
  fLogNode.innerHTML += s + NL;
  // and
  var _rawdata = _data ? _data.innerHTML : null;
  ```
- **Verdict**: The `innerHTML` assignment in `logToBrowserPage()` is only used for debug logging to the web page, gated behind a `?logtowebpage=` URL parameter. The `innerHTML` read on line 723 is used to read WebDAV data from a DOM element. Neither presents a real XSS risk in this context since the content is from the same-origin Content Server page. **Non-issue.**

## False Positive Table

| Pattern | Location | Reason for FP |
|---------|----------|---------------|
| `cookies.getAll()` | `background_v3.js:73` | Reads session cookies only for current active tab URL, forwards only to local native messaging host for SSO auth. Not exfiltration. |
| `innerHTML` read/write | `content.js:111,723` | Debug logging to page element (gated behind URL param) and reading data from same-origin DOM element. Not XSS. |
| `all_frames: true` | `manifest.json:17` | Enterprise extension pattern - must detect Content Server iframes on customer-hosted deployments. |
| `Proxy` object | `background_v3.js:811` | Used solely for debug mode toggle (Reflect.set on `debugMode.log`). Not MobX-style hooking. |
| `CustomEvent` dispatch | `content_v3.js:54` | Standard communication pattern between content script and injected page script (WebExtV3.js). Not data exfiltration. |
| `navigator.userAgent` | `content.js:641`, `content_v3.js:117` | Sent to background script as part of request metadata. Standard browser identification. |

## API Endpoints Table

| Endpoint/Target | Type | Purpose |
|----------------|------|---------|
| `com.opentext.desktop.webext.messaging` | Native Messaging Host | Primary native messaging app for document operations |
| `com.opentext.officeeditor.actionhandler` | Native Messaging Host (Legacy) | Legacy Office Editor native messaging fallback |
| `com.opentext.webdav.actionhandler` | Native Messaging Host (Legacy) | Legacy WebDAV native messaging fallback |
| `clients2.google.com/service/update2/crx` | CWS Auto-update | Standard Chrome Web Store update endpoint |

**No external HTTP/HTTPS endpoints contacted.** All communication is via Chrome's native messaging API to locally installed host applications.

## Data Flow Summary

```
1. User navigates to OpenText Content Server page
2. Content scripts (content.js, content_v3.js) inject into page
3. Scripts check for specific DOM elements or URL patterns:
   - V2 path: DOM element "WebExtension$Channel-{guid}" or URL contains "func=Edit.Edit" / "func=webdav.webdavedit"
   - V3 path: CustomEvent "OpenText_WebExtV3_ContentJS_Event" from page's WebExtV3.js
4. If active, content script reads request data (application name, method, parameters) from DOM
5. Content script sends "execute" message to background script via chrome.runtime.sendMessage
6. Background script optionally acquires session cookies for the current tab URL
7. Background script sends request data + cookies to native messaging host via chrome.runtime.sendNativeMessage
8. Native host processes request (e.g., opens document in Office for editing)
9. Native host returns result to background script
10. Background script forwards result to content script via chrome.tabs.sendMessage
11. Content script updates DOM element and dispatches event for the web page to consume
```

**Data collected**: Request domain, user agent string, session cookies (for current URL only), document edit parameters from Content Server page.
**Data destination**: Local native messaging host only. No remote servers contacted.

## Overall Risk Assessment

**CLEAN**

This is a legitimate enterprise extension by OpenText for integrating Content Server (document management system) with native desktop applications. Despite its broad permissions (`*://*/` host access, cookies, all-frames injection), the extension:

1. Makes zero external network requests - all communication is via native messaging to locally installed apps
2. Only activates on pages containing specific OpenText Content Server elements/URLs
3. Cookie access is limited to passing session tokens to the local native host for SSO
4. Contains no obfuscation, no dynamic code execution (`eval`, `new Function`), no remote config endpoints
5. Has clean, well-commented code with obvious enterprise development patterns
6. The native messaging hosts are registered locally and require separate installation

The broad permissions are a necessary consequence of enterprise deployment where Content Server instances are hosted at arbitrary internal URLs.
