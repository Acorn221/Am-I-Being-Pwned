# Security Analysis Report: DjVu.js Viewer

## Extension Metadata
- **Extension ID**: bpnedgjmphmmdgecmklcopblfcbhpefm
- **Name**: DjVu.js Viewer
- **Version**: 0.10.1.0
- **Publisher**: RussCoder
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Homepage**: https://github.com/RussCoder/djvujs

## Executive Summary

**Risk Level: CLEAN**

DjVu.js Viewer is a legitimate open-source Chrome extension for viewing DjVu document files. The extension is based on the djvujs library (https://github.com/RussCoder/djvujs) and provides functionality to open .djvu/.djv files from local disk or web links. The code analysis reveals no security vulnerabilities, malicious behavior, or privacy concerns. The extension uses WebAssembly for efficient DjVu document rendering, which is a legitimate use case for this file format.

The ext-analyzer flagged 2 exfiltration flows involving `document.querySelectorAll/getElementById → fetch`, but these are false positives from the Vite/React modulepreload polyfill, a standard build artifact with no security implications.

## Vulnerability Details

### No Vulnerabilities Identified

After thorough analysis of the deobfuscated source code, no security vulnerabilities were discovered. The extension implements its core functionality in a secure manner:

1. **No Data Exfiltration**: The extension does not collect, track, or transmit user data to external servers.
2. **No Dangerous Code Execution**: While the extension uses `chrome.scripting.executeScript`, it only injects its own bundled scripts (`dist/djvu.js` and `dist/djvu_viewer.js`) for rendering DjVu documents within web pages.
3. **No PostMessage Vulnerabilities**: The extension does not use `postMessage` or message event listeners.
4. **No Remote Code Loading**: All JavaScript is bundled within the extension package.
5. **No Credential Harvesting**: No evidence of keylogging, form interception, or credential theft.

### Code Analysis

#### Background Script (background.js)
The background script implements:
- Context menu integration for opening .djvu files
- URL interception using `declarativeNetRequest` to redirect .djvu URLs to the viewer
- Message handling for script injection (legitimate use for in-page rendering)
- Support for both file:// and http(s):// URLs

```javascript
function listenForMessages() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (sender.tab && message === 'include_scripts') {
            Promise.all([
                executeScript('dist/djvu.js', sender),
                executeScript('dist/djvu_viewer.js', sender),
            ]).then(() => {
                sendResponse();
            })
            return true;
        }
        // ... other message handling
    });
}
```

This is a standard pattern for content script injection when needed (for rendering `<object>` and `<embed>` tags in-page).

#### Content Script (content.js)
The content script searches for DjVu `<object>` and `<embed>` tags on web pages and replaces them with the DjVu.js viewer. This is the intended functionality for viewing embedded DjVu documents.

```javascript
const objects = document.querySelectorAll(
    'object[classid="clsid:0e8d0700-75df-11d3-8b4a-0008c7450c4a"]'
    + ', object[type="image/x.djvu"]'
);
```

#### Viewer Components
- **viewer.html**: Simple HTML page that loads the DjVu.js library and React-based viewer UI
- **dist/djvu.js**: Core DjVu rendering library with WebAssembly support (544KB)
- **dist/djvu_viewer.js**: React-based UI components (527KB, includes React, Redux, styled-components)

The viewer uses XMLHttpRequest to fetch DjVu documents from URLs:

```javascript
function loadFileViaXHR(url, responseType = 'arraybuffer') {
    return new Promise((resolve, reject) => {
        var xhr = new XMLHttpRequest();
        xhr.open("GET", url);
        xhr.responseType = responseType;
        xhr.onload = (e) => resolve(xhr);
        xhr.onerror = (e) => reject(xhr);
        xhr.send();
    });
}
```

This is legitimate functionality - the extension needs to fetch .djvu files to display them.

### False Positive Analysis

The ext-analyzer flagged the following as exfiltration flows:

```
[HIGH] document.querySelectorAll → fetch    dist/djvu_viewer.js
[HIGH] document.getElementById → fetch    dist/djvu_viewer.js
```

**Analysis**: These flows are from the Vite modulepreload polyfill at lines 10-33 of djvu_viewer.js:

```javascript
(function() {
  const t = document.createElement("link").relList;
  if (t && t.supports && t.supports("modulepreload")) return;
  for (const o of document.querySelectorAll('link[rel="modulepreload"]')) r(o);
  new MutationObserver(o => {
    for (const i of o)
      if (i.type === "childList")
        for (const a of i.addedNodes)
          a.tagName === "LINK" && a.rel === "modulepreload" && r(a)
  }).observe(document, { childList: !0, subtree: !0 });

  function r(o) {
    if (o.ep) return;
    o.ep = !0;
    const i = n(o);
    fetch(o.href, i)  // This is the flagged line
  }
})();
```

This code is a browser polyfill that preloads ES modules for performance. The `fetch()` calls only load resources from the extension's own `href` attributes (same-origin), not external domains. This is standard Vite build output and poses no security risk.

## Network Endpoints

The extension references the following external domains (in link text only, not for data transmission):

1. **github.com/RussCoder/djvujs** - GitHub repository link (in UI)
2. **djvu.js.org** - Project website link (in UI)

No network requests are made to external domains except when users explicitly load .djvu files from remote URLs (which is the core functionality of a document viewer).

## Permissions Analysis

### Requested Permissions

1. **storage** - Used to save user preferences (interceptHttpRequests, analyzeHeaders options)
2. **declarativeNetRequest** - Used to redirect .djvu URLs to the viewer page
3. **scripting** - Used to inject DjVu viewer scripts into pages with `<object>`/`<embed>` tags
4. **contextMenus** - Adds "Open with DjVu.js Viewer" context menu for .djvu links
5. **<all_urls>** (host permissions) - Required to detect and intercept .djvu files on any website

### Permission Justification

All permissions are necessary for the extension's core functionality:
- Intercepting .djvu URLs requires `declarativeNetRequest` + `<all_urls>`
- Rendering embedded DjVu documents requires `scripting` to inject the viewer into pages
- Context menu integration requires `contextMenus`
- Saving settings requires `storage`

No excessive or suspicious permission requests.

### Content Security Policy

```json
"content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self';"
}
```

Strong CSP - only allows scripts from the extension package itself, preventing remote code injection.

## Web Accessible Resources

```json
"web_accessible_resources": [
    {
        "resources": ["viewer.html"],
        "matches": ["<all_urls>"]
    }
]
```

Only `viewer.html` is exposed as a web-accessible resource, which is necessary for the extension to open the viewer in a new tab or redirect to it. This does not pose a security risk.

## WASM Usage

The extension uses WebAssembly for DjVu document decoding and rendering. This is flagged by the analyzer but is a legitimate performance optimization for the computationally intensive task of rendering DjVu documents. The WASM code is bundled within `dist/djvu.js` and does not execute arbitrary code from external sources.

## Code Quality & Obfuscation

The code is minified (standard for production builds) but not intentionally obfuscated. The variable names are shortened by the build process (Vite/Rollup), but the code structure is standard for a React application. The extension is open-source, and the unminified source is available on GitHub.

## Final Verdict

**Risk Level: CLEAN**

DjVu.js Viewer is a safe, legitimate extension with no security vulnerabilities. It serves a specific purpose (viewing DjVu documents) and implements that functionality without any malicious behavior, data collection, or privacy violations. The extension follows Chrome extension best practices, uses a strong CSP, and requests only the permissions necessary for its functionality.

The ext-analyzer findings are false positives from standard build tooling (Vite modulepreload polyfill). Users can safely install this extension for viewing DjVu document files.

### Recommendations

- None. The extension is safe to use as-is.

### Tags

No security-related tags apply to this extension.

---

**Analyzed by**: Claude Sonnet 4.5
**Analysis Date**: 2026-02-15
**Confidence Level**: High
