# Vulnerability Assessment Report
## OCR Editor - Text from Image

### Extension Metadata
- **Extension ID**: ihnfmldlpdipgnliolhfffenpcmjgnif
- **Extension Name**: OCR Editor - Text from Image
- **Version**: 3.2.4
- **User Count**: ~40,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

---

## Executive Summary

OCR Editor is a Chrome extension that extracts text from images using OCR (Optical Character Recognition). The extension allows users to either capture screenshots from web pages or upload images directly. The captured images are sent to a backend service (`backend.ocreditor.com`) for OCR processing, and results are displayed to the user.

**Overall Risk Assessment: MEDIUM**

The extension has a concerning privacy posture due to sending all image data to an external server without clear encryption or user consent mechanisms. While it serves its intended purpose and shows no signs of malicious behavior, the broad permissions combined with unlimited external data transmission present moderate privacy and security risks.

---

## Vulnerability Details

### 1. MEDIUM - Unrestricted External Data Transmission
**Severity**: MEDIUM
**Files**: `background.js` (lines 21-38), `options.js` (lines 461-474)
**Category**: Privacy / Data Exfiltration Risk

**Description**:
The extension sends all captured/uploaded images to an external server (`https://backend.ocreditor.com/api/image/text`) without apparent encryption beyond HTTPS. The extension has `<all_urls>` host permissions, allowing it to capture screenshots from any website the user visits.

**Code Evidence**:
```javascript
// background.js:21-29
await fetch("https://backend.ocreditor.com/api/image/text", {
  method: "POST",
  body: JSON.stringify({
    img: t,
    userId: n  // Persistent user ID
  }),
  headers: {
    "Content-type": "application/json; charset=UTF-8"
  }
})
```

**Risk**:
- All images (including potentially sensitive screenshots) are transmitted to third-party servers
- No evidence of end-to-end encryption
- Persistent user tracking via `randomId` stored in local storage
- Images could contain passwords, PII, financial information, confidential documents, etc.

**Verdict**: The extension's core functionality requires sending images externally for OCR processing, which is disclosed in the description. However, the lack of transparency about data retention, the persistent user ID tracking, and the broad `<all_urls>` permission create a concerning privacy surface.

---

### 2. LOW-MEDIUM - Persistent User Tracking
**Severity**: LOW-MEDIUM
**Files**: `background.js` (lines 157-176)
**Category**: Privacy / User Tracking

**Description**:
The extension generates and stores a persistent random user ID that is sent with every OCR request.

**Code Evidence**:
```javascript
// background.js:157-163
const o = () => {
  let e = Math.floor(Date.now() / 1e3),
    t = "",
    o = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let e = 0; e < 10; e++) t += o.charAt(Math.floor(Math.random() * o.length));
  return e + t
};

// background.js:168-169
chrome.storage.local.set({
  randomId: n
})
```

**Risk**:
- Enables cross-session user tracking
- No user consent mechanism for tracking
- Persistent identifier survives across extension updates
- Could be used to build usage profiles

**Verdict**: While common for analytics, the lack of opt-out mechanisms and transparency about tracking makes this a privacy concern.

---

### 3. LOW - Broad Host Permissions
**Severity**: LOW
**Files**: `manifest.json` (lines 29-32)
**Category**: Excessive Permissions

**Description**:
The extension requests `<all_urls>` host permissions and the `scripting` permission, allowing it to inject content scripts into any web page.

**Manifest Evidence**:
```json
"host_permissions": [
  "<all_urls>",
  "*://*/options.html"
],
"permissions": [
  "tabs",
  "storage",
  "scripting",
  "activeTab",
  "unlimitedStorage"
]
```

**Risk**:
- Extension can access content on all websites
- Content script injection capability on all sites
- Potential for future abuse if extension is compromised or sold

**Verdict**: The permissions are technically necessary for screenshot capture functionality but create a significant attack surface if the extension is compromised.

---

### 4. INFO - Third-Party URL Redirects
**Severity**: INFO
**Files**: `background.js` (lines 167, 177)
**Category**: User Experience

**Description**:
The extension uses bit.ly shortlinks for install/uninstall pages, which obscure the actual destination and could be changed remotely.

**Code Evidence**:
```javascript
chrome.tabs.create({
  url: "https://bit.ly/ocrin"  // Install page
})
chrome.runtime.setUninstallURL("https://bit.ly/ocrui")  // Uninstall survey
```

**Risk**:
- Bit.ly links can be modified without updating the extension
- Potential for phishing if links are hijacked
- Lack of transparency about destination

**Verdict**: Minor security concern; best practice would be direct URLs.

---

### 5. INFO - Translation Service Integration
**Severity**: INFO
**Files**: `options.js` (lines 611-621)
**Category**: Additional Data Transmission

**Description**:
The extension sends OCR results to a backend translation service when users select a language.

**Code Evidence**:
```javascript
fetch("https://backend.ocreditor.com/getData", {
  method: "POST",
  body: JSON.stringify({
    data: M,  // OCR text
    language: n.target.value
  }),
  headers: {
    "Content-Type": "application/json"
  }
})
```

**Risk**:
- Additional data transmission to external server
- OCR text (potentially sensitive) sent for translation

**Verdict**: Legitimate feature but adds to overall data transmission surface.

---

## False Positive Analysis

| Pattern | Location | Verdict | Reason |
|---------|----------|---------|--------|
| `querySelector` usage | contentScript.js, 662.js, 288.js, options.js | FALSE POSITIVE | Standard DOM manipulation for React and UI functionality |
| `Function("return this")()` | popup.js:372, options.js:745 | FALSE POSITIVE | Standard webpack global detection pattern |
| `String.fromCharCode` | 662.js (multiple) | FALSE POSITIVE | React keyboard event handling - standard library code |
| `window.atob` detection | contentScript.js:151, 662.js:6208 | FALSE POSITIVE | Browser feature detection for IE compatibility |
| XMLHttpRequest | 288.js | FALSE POSITIVE | Axios HTTP library - legitimate HTTP client |
| `btoa` authentication | 288.js:8956 | FALSE POSITIVE | Standard HTTP Basic Auth encoding in Axios |
| `document.cookie` access | 288.js:9472, 9475 | FALSE POSITIVE | Cookie utilities in Axios for XSRF protection |
| `addEventListener` patterns | contentScript.js (multiple) | FALSE POSITIVE | Standard event handling for screenshot capture UI |
| React SVG innerHTML | 662.js:573 | FALSE POSITIVE | Known React pattern for SVG rendering |

---

## API Endpoints Analysis

| Endpoint | Method | Purpose | Data Sent | Risk Level |
|----------|--------|---------|-----------|------------|
| `https://backend.ocreditor.com/api/image/text` | POST | OCR Processing | Base64 image data, userId | MEDIUM |
| `https://backend.ocreditor.com/getData` | POST | Translation | OCR text, language code | LOW |
| `https://ocreditor.com/results?id={id}` | GET | Results Display | Result ID (via URL) | LOW |
| `https://bit.ly/ocrin` | GET | Install redirect | None | INFO |
| `https://bit.ly/ocrui` | GET | Uninstall survey | None | INFO |

---

## Data Flow Summary

### User Interaction Flow:
1. **Screenshot Mode**: User clicks "Detect Now" → content script enables screenshot selection → captures visible tab → sends to background script
2. **Upload Mode**: User drags/uploads image → read as base64 data URL → sends to background script

### Data Processing Flow:
1. Background script receives base64 image data
2. Extracts base64 payload (removes data URL prefix)
3. Retrieves persistent `randomId` from local storage
4. POSTs to `backend.ocreditor.com/api/image/text` with image + userId
5. Receives result ID from server
6. Opens results page: `ocreditor.com/results?id={resultId}`
7. Options page fetches OCR results and displays to user
8. User can optionally translate text (sends OCR output to translation endpoint)

### Sensitive Data Handling:
- **Image Data**: All screenshots/uploads sent to external server
- **User Tracking**: Persistent unique ID sent with every request
- **OCR Results**: Text extracted from images stored on external server
- **Local Storage**: Stores randomId, image data, OCR results temporarily

---

## Security Recommendations

1. **Implement Client-Side OCR**: Consider using WebAssembly-based OCR (like Tesseract.js) to process images locally and eliminate external data transmission
2. **Add Privacy Controls**: Provide user opt-in/opt-out for tracking and clear privacy policy
3. **Reduce Permissions**: Consider using `activeTab` only instead of `<all_urls>` to limit scope
4. **Add Encryption**: Implement end-to-end encryption for image transmission if server processing is required
5. **Replace URL Shorteners**: Use direct URLs instead of bit.ly links
6. **Data Retention Policy**: Document and disclose how long images/OCR results are stored
7. **Add Content Security Policy**: Manifest has no CSP - consider adding restrictions

---

## Overall Risk Assessment

**Risk Level: MEDIUM**

### Justification:
The OCR Editor extension serves its stated purpose of extracting text from images without engaging in clearly malicious behavior. However, several factors elevate it to MEDIUM risk:

1. **Privacy Concerns**: All user images (potentially containing sensitive information) are transmitted to external servers with persistent user tracking
2. **Broad Permissions**: `<all_urls>` access combined with screenshot capabilities creates significant data access
3. **Lack of Transparency**: No clear privacy policy or user consent mechanisms for data transmission and tracking
4. **Third-Party Dependencies**: Reliance on external services creates supply chain risks

### Mitigating Factors:
- No evidence of data selling, malware, or malicious intent
- HTTPS used for all communications
- Functionality matches stated purpose
- No content script injection for data harvesting
- No evidence of credential theft or keylogging
- Uses standard libraries (React, Axios, Material-UI) without tampering

### Recommendation:
The extension is **functionally legitimate** but has **concerning privacy practices**. Users who handle sensitive information should be aware that all screenshots/images are sent to external servers. The extension would benefit from client-side OCR processing to eliminate privacy concerns entirely.

For enterprise/security-conscious environments, this extension should be **blocked or used with caution** due to the risk of inadvertently capturing and transmitting sensitive information (credentials, PII, financial data, confidential documents).
