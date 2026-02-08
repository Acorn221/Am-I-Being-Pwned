# Security Analysis Report: QR Code Generator

## Extension Metadata
- **Extension Name**: QR Code Generator
- **Extension ID**: hoeiookpkijlnjdafhaclpdbfflelmci
- **User Count**: ~40,000 users
- **Version**: 1.0.5
- **Manifest Version**: 3

## Executive Summary

The QR Code Generator extension provides QR code scanning and generation functionality. After comprehensive security analysis, this extension demonstrates **EXCESSIVE AND UNNECESSARY permissions** that represent a significant security risk. While the core QR functionality appears benign, the extension requests broad host permissions (`<all_urls>`) with content script injection across all websites, which is far beyond what's required for a QR code generator. This permission model creates unnecessary attack surface and privacy risks.

**Overall Risk Level: HIGH**

The extension exhibits a dangerous permission model that violates the principle of least privilege, requests access to all websites without justification, and injects content scripts globally—creating substantial privacy and security concerns for users.

## Vulnerability Details

### 1. EXCESSIVE HOST PERMISSIONS - HIGH SEVERITY

**Finding**: The extension requests unrestricted access to all URLs with redundant permission declarations.

**Evidence** (`manifest.json` lines 20-23):
```json
"host_permissions": [
    "*://*/*",
    "<all_urls>"
]
```

**Verdict**: **MALICIOUS DESIGN PATTERN**

**Explanation**:
- A QR code generator should operate entirely within its popup UI and does NOT require access to any websites
- The extension requests both `*://*/*` AND `<all_urls>` (redundant, indicating poor security awareness)
- This gives the extension permission to read/modify content on EVERY website the user visits
- The feature set (scan QR codes, generate QR codes) can be fully implemented without host permissions
- This is a classic red flag seen in malicious extensions that later introduce ad injection, data harvesting, or other abusive behaviors

**Impact**:
- Extension can read all data on every website (passwords, banking info, personal data)
- Extension can modify content on any page
- Extension can intercept and manipulate network requests
- Creates massive privacy violation risk

### 2. GLOBAL CONTENT SCRIPT INJECTION - HIGH SEVERITY

**Finding**: The extension injects content scripts on ALL websites at document_start with all_frames enabled.

**Evidence** (`manifest.json` lines 27-38):
```json
"content_scripts": [
    {
      "matches": [
        "<all_urls>"
      ],
      "js": [
        "/static/content.js"
      ],
      "run_at": "document_start",
      "all_frames": true
    }
]
```

**Verdict**: **MALICIOUS DESIGN PATTERN**

**Explanation**:
- Content script runs on EVERY website immediately at document_start (before page loads)
- Executes in ALL frames (including iframes), maximizing attack surface
- The 1,424-line content.js contains the entire QR scanning/generation UI that should only appear in a popup
- No legitimate reason for a QR generator to inject code into every webpage
- `document_start` timing allows interception of page construction and early DOM manipulation
- The only remotely justifiable use case (scanning QR codes from images via context menu) could be implemented with activeTab permission instead

**Impact**:
- Extension code runs on banking sites, email, social media, etc.
- Can capture user interactions, keystrokes, form data
- Executes before page security controls initialize
- Performance degradation across all browsing

### 3. UNSAFE innerHTML USAGE - MEDIUM SEVERITY

**Finding**: The extension uses innerHTML with user-controlled/dynamic content, creating XSS risks.

**Evidence** (`static/content.js` line 1401):
```javascript
t.id = "rb-qrsg-overlay-container", t.innerHTML = T, document.body.appendChild(t)
```

Where `T` is a large HTML template string (lines 95-222) that includes:
```javascript
let T = `
<div class="rb-qrsg-backdrop rb-qrsg-hidden" id="rb-qrsg-overlay">
    <div class="rb-qrsg-overlay">
        <a href="#1" class="rb-qrsg-cancel-btn"><img src="${L("/assets/image/exit.png")}"...
```

**Verdict**: **MODERATE RISK**

**Explanation**:
- While the template string `T` appears to use chrome.runtime.getURL() (the `L()` function) for asset paths
- The extension also processes user input (QR text, scanned data) and displays it
- Line 1292: `f(".rb-qrsg-scanned-data").textContent = s` - Uses textContent (safe)
- Line 1117: `a.innerHTML = o.join("")` - Builds QR table HTML dynamically
- The innerHTML usage for template injection is relatively safe, but represents code smell
- Risk increases if future updates add dynamic user content to these HTML strings

**Impact**:
- Potential for XSS if user-controlled data enters HTML construction
- Current implementation appears to sanitize by using textContent for user data
- Future modifications could introduce vulnerabilities

### 4. CONTEXT MENU IMAGE URL MANIPULATION - LOW SEVERITY

**Finding**: The extension creates new tabs with manipulated image URLs when scanning QR codes from context menu.

**Evidence** (`static/bg.js` lines 39-43):
```javascript
(e => {
  let t = new URL(e?.srcUrl);
  t.searchParams.set("rb_qrsg_scan_image_url", "1"), chrome.tabs.create({
    url: t.toString()
  })
})(a)
```

**Verdict**: **QUESTIONABLE DESIGN**

**Explanation**:
- When user right-clicks an image and selects "Scan QR code", the extension creates a new tab with the image URL plus a query parameter
- This relies on the website serving the image correctly with query parameters
- Could fail on sites with strict URL validation
- Opens user to potential URL manipulation issues
- More secure approach: Use chrome.tabs.captureVisibleTab or fetch image via content script

**Impact**:
- May not work reliably across all websites
- Could expose user to unexpected page loads
- Minimal security risk, primarily a design flaw

### 5. WEB CAMERA ACCESS WITHOUT CLEAR PERMISSION - MEDIUM SEVERITY

**Finding**: Extension accesses webcam through webpage permissions, not declared manifest permissions.

**Evidence** (`static/content.js` lines 1300-1307):
```javascript
checkAndScanWithWebCam = () => {
  navigator.mediaDevices.getUserMedia({
    audio: !1,
    video: !0
  }).then(t => {
    this.scanWithWebCam()
  }).catch(t => {
    "NotAllowedError" == t.name && k("Please allow or turn on your web camera")
  })
}
```

**Verdict**: **MODERATE CONCERN**

**Explanation**:
- Extension requests camera access via webpage API, not Chrome permission system
- Because content script runs on all pages, it could potentially request camera access on any website
- No manifest declaration of camera usage
- Users won't see camera permission in extension permissions list
- Camera access should be requested only in extension context (popup), not via content scripts on websites

**Impact**:
- Privacy concern - users may not realize extension can access camera
- Could be invoked on any webpage where content script runs
- Bypasses Chrome's extension permission transparency

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `postMessage` usage | scanner/worker.js, content.js | Legitimate Web Worker communication for QR scanning algorithm |
| SVG `createElementNS` | content.js line 1076 | Standard QR code rendering using SVG |
| Event listeners | content.js multiple | Normal DOM event handling for UI interactions |
| `chrome.runtime.getURL()` | content.js via `L()` function | Proper extension resource loading |
| QR library code | content.js lines 470-1223 | Standard QR encoding/decoding algorithms (obfuscated library code) |

## API Endpoints / External Connections

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `chrome.google.com/webstore` | Link to extension reviews | Safe - standard Chrome Web Store link |
| None | No external API calls detected | N/A |

**Note**: The extension makes NO external network requests. All QR scanning/generation happens client-side. However, this could change in future updates given the broad permissions.

## Data Flow Summary

### Data Collection
- **QR Code Content**: User-provided text or scanned QR data remains local
- **Images**: User-uploaded images processed locally in browser
- **Camera Feed**: Accessed for QR scanning, processed locally
- **Page Content**: Content script has access to all page content on all sites

### Data Storage
- No evidence of localStorage, sessionStorage, or indexedDB usage
- No evidence of data persistence
- Scanned/generated QR codes appear to be ephemeral

### Data Transmission
- **None detected in current version**
- However, broad permissions would allow future updates to exfiltrate:
  - Browsing history (via content script injection on all sites)
  - User interactions and form data
  - Scanned QR code content
  - Any webpage content

## Key Findings Summary

1. **Unnecessary Permissions**: Requests `<all_urls>` host permissions with zero justification
2. **Global Content Script**: Injects JavaScript into every website at document_start
3. **Privacy Violation Potential**: Can read/modify all webpage content
4. **Hidden Camera Access**: Requests webcam via page context, not manifest
5. **No Current Malicious Behavior**: Despite excessive permissions, no evidence of active data harvesting

## Overall Risk Assessment: HIGH

### Risk Breakdown
- **Permission Abuse**: HIGH - Requests far more access than needed
- **Privacy Risk**: HIGH - Can monitor all browsing activity
- **Active Malware**: NONE DETECTED - No current malicious behavior
- **Future Risk**: HIGH - Permissions enable trivial malware addition in updates

### Justification

While this extension currently appears to only provide QR functionality, it exhibits **textbook malicious permission patterns**:

1. **Excessive permissions with no justification** - QR generation/scanning can be done entirely in popup with activeTab permission
2. **Global content script injection** - Injecting 1,400+ lines of UI code into every website is absurd
3. **All-sites access** - Can read passwords, banking info, emails, etc. across entire browsing session
4. **Principle of least privilege violation** - Requests maximum permissions for minimal functionality

This matches the pattern of:
- **Legitimate-looking extensions** with clean current behavior but excessive permissions
- **Future attack vector** - Developer (or if account compromised) can push malicious update to 40,000 users
- **Common extension abuse** - Start legitimate, build user base, then monetize via ad injection/data harvesting

### Similar Clean Extensions with Proper Permissions
A properly designed QR extension would:
- Use `activeTab` permission only (granted when user clicks extension)
- No host_permissions required
- No content scripts on websites
- All UI in popup.html
- Camera access requested in popup context with proper manifest permission

## Recommendation

**HIGH RISK** - This extension should be flagged for:
1. **Immediate user warning** about excessive permissions
2. **Permission reduction requirement** - Developer should refactor to use activeTab only
3. **Removal from store** if permissions not justified and reduced
4. **User advisory** to uninstall and use alternative QR extensions with proper permissions

The extension is NOT currently malicious but creates **unacceptable privacy and security risk** through its permission model. Users should be warned that installing this extension grants it access to read and modify ALL their web browsing activity.
