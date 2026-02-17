# Vulnerability Report: Save Image As PNG

## Metadata
- **Extension ID**: nkokmeaibnajheohncaamjggkanfbphi
- **Extension Name**: Save Image As PNG
- **Version**: 1.0.3
- **Users**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Save Image As PNG" is a legitimate utility extension developed by Rob Wu that adds a context menu option to convert and download images as PNG format. The extension uses standard Chrome APIs to fetch images, convert them to PNG using canvas rendering, and trigger downloads. The code is well-documented and implements proper error handling.

The extension has one minor security concern: the service worker's postMessage event listener (background.js:319) does not validate the origin before processing messages. However, the practical risk is minimal because the extension only communicates with its own offscreen document and uses message ID validation to prevent message confusion.

## Vulnerability Details

### 1. LOW: PostMessage Handler Without Origin Validation

**Severity**: LOW
**Files**: background.js (line 319)
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The service worker registers a message event listener that does not explicitly validate the origin of incoming messages before processing them:

```javascript
const responsePromise = new Promise(resolve => {
    function listener(event) {
        if (event.origin === origin && event.data.messageId === messageId) {
            resolve(event.data.response);
            self.removeEventListener('message', listener);
        }
    }
    self.addEventListener('message', listener);
});
```

While the code checks `event.origin === origin`, the `origin` variable is not defined in the visible scope within the listener function, which could lead to it being undefined or referring to the global origin.

**Evidence**:
- Line 314 in background.js references `event.origin === origin` but `origin` appears to be undefined
- The ext-analyzer flagged this as: `[HIGH] window.addEventListener("message") without origin check    background.js:319`

**Verdict**:
This is a LOW severity issue rather than HIGH because:
1. The extension only creates and communicates with its own offscreen document (offscreen.html)
2. The offscreen document is loaded from the extension's own package, not from external sources
3. The message protocol uses randomly generated UUIDs (`crypto.randomUUID()`) as message IDs, preventing message confusion
4. The offscreen document's service worker message handler (`navigator.serviceWorker.onmessage`) only processes specific message types ('alert' and 'decodeBlobAsPNG')
5. There are no web-accessible resources or externally_connectable configurations that would allow external origins to send messages

The vulnerability would require an attacker to somehow inject malicious code into the offscreen document context, which is not exposed to external web pages.

## False Positives Analysis

1. **Host Permissions `<all_urls>`**: While broad, this is necessary for the extension's core functionality - it needs to inject content scripts to access images from any website the user is browsing. The extension only injects scripts when the user explicitly clicks the context menu item (using `activeTab` permission pattern).

2. **Dynamic Code Execution via executeScript**: The extension uses `chrome.scripting.executeScript()` to run image conversion code in the page context. This is legitimate and necessary to:
   - Access images in the page's DOM to avoid re-downloading
   - Respect the page's cookie/authentication context for protected images
   - Handle cross-origin images properly using canvas operations
   - The injected functions are inline and static, not constructed from user input

3. **Offscreen Document Usage**: The extension creates an offscreen document for two purposes:
   - Displaying error alerts (since service workers don't support `alert()`)
   - Decoding SVG images that can't be processed via `createImageBitmap()`
   - Both are legitimate uses of the offscreen API

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | This extension makes no external network requests | N/A | None |

The extension only fetches images from the same domains the user is already browsing (using `fetch(srcUrl, { credentials: 'include' })`), and all processing happens locally in the browser. No data is sent to external servers.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This is a well-implemented, single-purpose utility extension with transparent functionality. The code is authored by Rob Wu, a known Chrome extension developer and contributor to browser security research. The extension:

1. **Operates transparently**: Does exactly what it claims - converts images to PNG format
2. **No data collection**: Makes no network requests to external servers
3. **Proper permissions**: Uses `activeTab` to minimize access until user action
4. **Clean code**: Well-documented, properly structured, with error handling
5. **No obfuscation**: Code is readable and straightforward

The single identified vulnerability (postMessage without proper origin validation) has minimal practical risk due to:
- Limited attack surface (only talks to its own offscreen document)
- Message ID validation prevents message confusion
- No external communication channels
- The `origin` check is present, just potentially incorrectly scoped

**Recommendation**: The extension is safe for users. The developer should fix the origin validation to properly define the expected origin before the event listener registration, but this does not pose an immediate security risk to users.
