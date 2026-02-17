# Vulnerability Report: Selectext: Copy Text From Videos

## Metadata
- **Extension ID**: gkkdmjjodidppndkbkhhknakbeflbomf
- **Extension Name**: Selectext: Copy Text From Videos
- **Version**: 3.1.19
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Selectext is a video OCR extension that allows users to copy text directly from videos on YouTube and other websites. The extension provides legitimate OCR functionality through an external API at `api.selectext.app`. While the extension's core purpose is legitimate, it contains a significant security vulnerability: widespread use of postMessage listeners without origin validation across multiple content scripts. This creates an attack surface where malicious websites could trigger unintended extension functionality. The extension also sends video screenshots (base64-encoded data URIs) and usage telemetry to external servers with cookies, though this appears disclosed in the extension's purpose.

The extension does not appear to contain malicious functionality, but the lack of origin checking on cross-frame messaging represents a medium-severity vulnerability that could be exploited by malicious websites.

## Vulnerability Details

### 1. MEDIUM: Unsafe postMessage Handlers Without Origin Validation

**Severity**: MEDIUM
**Files**: content.js (lines 427, 859, 2362, 2365, 2724), shortcut.js (lines 89, 233), screenshot.js (lines 108, 211), iframeListener.js (line 4)
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The extension implements multiple `window.addEventListener("message")` handlers across various content scripts that do not validate the `event.origin` before processing messages. These handlers control critical functionality including:
- Screenshot capture and clipboard operations
- OCR triggering and video frame extraction
- Iframe dimension calculations
- Cross-frame communication for embedded videos

**Evidence**:

From `iframeListener.js` (lines 4-32):
```javascript
window.addEventListener("message", function (event) {
    if (event.data !== undefined && event.data.type !== undefined) {
        if (event.data.iframeSrc !== undefined) {
            const iframeSrc = event.data.iframeSrc;
            let iframe = $(`iframe[src*='${iframeSrc}']`).get(0);
            // ... processes messages without origin check
            if (event.data.type === "COPY_DATA_URI_TO_CLIPBOARD") {
                copyDataUriToClipboardHandler(iframe, event.data.dataUri);
            }
        }
    }
});
```

From `shortcut.js` (lines 89-99):
```javascript
window.addEventListener("message", iframeMaxVideoSizeListener);
// ... later posts to any origin
iframe.contentWindow.postMessage({
    type: "MAX_SCREEN_AREA_VIDEO_REQUEST",
    windowWidth: window.innerWidth,
    windowHeight: window.innerHeight,
    offsetX: iframeBoundingRect.left,
    offsetY: iframeBoundingRect.top,
    index: index
}, "*")  // Posts to wildcard origin
```

From `content.js` (line 427):
```javascript
window.addEventListener("message", onIframeDimensionsResponse);
// No origin validation in handler
```

**Verdict**: While the extension is designed to work across iframe boundaries for legitimate functionality (handling videos in iframes), the lack of origin validation means a malicious website could:
1. Trigger screenshot capture operations
2. Inject crafted data URIs into clipboard operations
3. Manipulate iframe dimension calculations
4. Potentially trigger OCR operations on attacker-controlled content

This is a classic postMessage vulnerability pattern. The extension should validate `event.origin` against a whitelist or at minimum check that messages originate from expected contexts.

### 2. LOW: Data Transmission to Third-Party API

**Severity**: LOW
**Files**: background.js (lines 250-260, 269-281)
**CWE**: CWE-359 (Exposure of Private Information)

**Description**: The extension sends video screenshots (as base64-encoded data URIs) and usage telemetry to `api.selectext.app` with credentials included.

**Evidence**:

From `background.js` (lines 269-281):
```javascript
async function performOCR(dataURI, url) {
  const response = await fetch(DETECT_TEXT_URL, {
    method: 'POST',
    body: JSON.stringify({ dataURI: dataURI, url: url }),
    mode: 'cors',
    cache: 'no-cache',
    headers: {
      'Content-Type': 'application/json',
    },
    credentials: 'include',  // Sends cookies
  })
  return response;
}
```

From `background.js` (lines 250-260):
```javascript
function logSelection(currentSelectionInfo) {
  fetch(LOG_SELECTION_URL, {
    method: 'POST',
    body: JSON.stringify(currentSelectionInfo),
    mode: 'cors',
    cache: 'no-cache',
    headers: {
      'Content-Type': 'application/json'
    },
    credentials: 'include',
  }).catch((e) => {})
}
```

**Verdict**: This data collection appears consistent with the extension's stated purpose (OCR functionality requires sending video frames to a backend service). The extension sends:
- Video screenshot data (necessary for OCR)
- Current page URL (sent with OCR requests)
- Usage telemetry (`currentSelectionInfo`)

While this involves data transmission, it appears disclosed as part of the extension's core functionality. Users installing an OCR extension would reasonably expect video frames to be sent to a processing service. Rated LOW rather than CLEAN due to the inclusion of page URLs and cookies with requests, which could enable user tracking.

## False Positives Analysis

1. **Content Script Injection on `<all_urls>`**: The extension requires broad permissions because it needs to overlay OCR UI on videos across all websites. This is legitimate for its stated purpose.

2. **Dynamic Script Injection**: The `background.js` uses `browser.scripting.executeScript()` to inject content scripts on installation (lines 32-40). This is a legitimate pattern for ensuring the extension works on already-open tabs after installation.

3. **Third-Party Libraries**: Uses jQuery, lodash, and other common libraries. These are standard dependencies, not obfuscated malicious code.

4. **browsingData Permission**: Used to clear website cache for `selectext.app` domain only (line 138 in background.js), likely for session management purposes.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://api.selectext.app/detect-text` | OCR processing | Video screenshot (base64), page URL | Medium - Sends browsing context |
| `https://api.selectext.app/log-selection` | Usage analytics | Selection metadata | Low - Telemetry data |
| `https://api.selectext.app/is-screenshot-unlocked` | Feature check | Cookies only | Low - Feature flag query |
| `https://selectext.app/signin` | User authentication | N/A (redirect) | Low - Standard auth flow |
| `https://selectext.app/portal/*` | User portal pages | N/A (redirect) | Low - UI navigation |
| `https://docs.google.com/forms/...` | Uninstall survey | N/A (redirect) | Low - Feedback collection |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: The extension provides legitimate OCR functionality and does not appear to contain malicious code. However, it has a significant architectural flaw: multiple postMessage event listeners across content scripts lack origin validation. This creates an exploitable attack surface where malicious websites could:

1. Trigger screenshot capture functionality
2. Manipulate clipboard operations with crafted data
3. Interfere with iframe communication mechanisms
4. Potentially exfiltrate data through these mechanisms

While no active exploitation was observed and the extension's data collection aligns with its stated purpose, the postMessage vulnerability represents a clear security issue that should be remediated. The risk is elevated from LOW to MEDIUM due to:
- The number of unsafe message handlers (10+ instances)
- The sensitivity of operations they control (clipboard, screenshots)
- The large user base (200,000 users)
- The `<all_urls>` permission scope, meaning the vulnerability is exploitable from any website

**Recommended Remediation**: All postMessage event listeners should validate `event.origin` before processing messages. For internal extension communication, use `browser.runtime.sendMessage()` instead of window.postMessage() where possible. For iframe communication, implement an origin whitelist.
