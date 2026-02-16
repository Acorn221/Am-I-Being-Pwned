# Vulnerability Report: DICOM viewer extension

## Metadata
- **Extension ID**: ljijfflodcoklbdnhbjhladgnbnjcena
- **Extension Name**: DICOM viewer extension
- **Version**: 1.2.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

DICOM viewer extension is a legitimate browser extension designed to facilitate window and tab management for medical imaging (DICOM) viewer applications. The extension acts as a bridge between web-based DICOM viewers and a native desktop application through Chrome's native messaging API. It provides window manipulation features including positioning, focusing, closing, and fullscreen control.

The extension requests broad permissions including `tabs`, `scripting`, `system.memory`, `nativeMessaging`, and host permissions for all URLs (`http://*/*`, `https://*/*`). However, the code review reveals these permissions are used appropriately for the stated functionality. The content script only activates on pages that specifically request it via a `dw-ext="true"` attribute on the document body, limiting its scope. The extension does not collect user data, make external network requests, or exhibit malicious behavior. The primary risk is the broad attack surface if the extension or the native host application were compromised.

## Vulnerability Details

### 1. LOW: Broad Permission Scope with Native Messaging

**Severity**: LOW
**Files**: background.js, contentscript.js, manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests host permissions for all HTTP/HTTPS URLs and uses native messaging to communicate with a desktop application. While the content script only activates on pages with `dw-ext="true"` attribute, the broad permissions create a larger attack surface if the extension or native application were compromised.

**Evidence**:
```javascript
// manifest.json
"host_permissions": [
  "http://*/*",
  "https://*/*"
],
"permissions": [
  "tabs",
  "activeTab",
  "scripting",
  "system.memory",
  "nativeMessaging"
]

// contentscript.js - Activation gate
if (document && document.body && document.body.getAttribute("dw-ext")==="true" && !document.body.hasAttribute("dw-ext-ver")) {
  document.body.setAttribute("dw-ext-ver","6");
  // ... extension logic
}
```

**Verdict**: This is appropriate for the extension's legitimate functionality. The content script self-limits activation to pages that explicitly request it. The native messaging is used for file transfer between the web viewer and desktop application, which is the core purpose of this extension. The broad permissions are necessary to support DICOM viewers hosted on any domain.

## False Positives Analysis

Several patterns that could appear suspicious in other contexts are legitimate for this medical imaging extension:

1. **Window/Tab Manipulation**: The extensive window management code (close, focus, fullscreen, position, reload) is the core functionality for arranging multiple DICOM viewer windows.

2. **Native Messaging**: Communication with `dicom.printer.native.messaging` native host is necessary for file transfer between web and desktop components.

3. **All URLs Content Script**: Required to support DICOM viewers hosted on any hospital/clinic domain.

4. **System Memory Access**: Used to report available memory to the DICOM application, likely for managing large medical image files.

5. **Message Passing without Origin Validation**: The content script checks `request.url.startsWith(window.location.origin)` before processing messages, providing appropriate origin validation.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native Host: `dicom.printer.native.messaging` | File transfer to/from desktop application | DICOM image data, window commands | LOW - Local only |

No external network endpoints are contacted by this extension. All communication is either internal (between extension components) or to the local native messaging host.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: This is a legitimate enterprise/medical extension with no malicious intent or privacy violations. The code is clean, well-structured, and implements its stated functionality without overreach. The MEDIUM rating reflects the potential impact if the extension or native application were compromised, given the broad permissions and privileged operations (window manipulation, native messaging, access to all URLs). However, the extension implements appropriate safeguards including content script activation gating and origin checks. For healthcare organizations using DICOM systems, this extension presents acceptable risk when deployed through managed enterprise channels.
