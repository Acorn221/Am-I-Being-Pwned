# Vulnerability Report: Pixie Reader

## Metadata
- **Extension ID**: oihhpemnlfdlkdhbiajjjkbbojdojchj
- **Extension Name**: Pixie Reader: Text-to-Speech, TTS, PDF, Web Highlight & OpenDyslexic
- **Version**: 3.1.0
- **Users**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Pixie Reader is a legitimate accessibility extension that provides text-to-speech, dyslexia-friendly fonts, PDF reading, and web highlighting features. The extension uses Firebase for authentication and Google OAuth2 for user login. Static analysis flagged one postMessage listener without origin validation in the EPUB reader component, which could theoretically be exploited for cross-site scripting if malicious content is loaded. However, the extension's overall functionality is consistent with its stated purpose, and there is no evidence of data exfiltration, hidden tracking, or malicious behavior.

The static analyzer's "exfiltration flow" finding appears to be a false positive related to tab querying for legitimate muting functionality in the sidebar UI. The extension properly scopes its permissions and communicates only with its own Firebase backend for user authentication and premium feature management.

## Vulnerability Details

### 1. LOW: Postmessage Listener Without Origin Validation

**Severity**: LOW
**Files**: epub-reader.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The EPUB reader component registers a window message event listener without validating the origin of incoming messages. This pattern can allow malicious iframes or pages to send arbitrary messages to the extension page.

**Evidence**:
```javascript
window.addEventListener("message", e => {
  e.data.m
}, !1)
```

**Verdict**: This is a minor security weakness. While it's technically possible for a malicious page to send messages to the EPUB reader iframe, the message handler appears incomplete or minimal (only accessing `e.data.m` without further processing). The impact is limited because:
1. The EPUB reader runs in an isolated extension page context, not on arbitrary websites
2. The handler doesn't appear to process the message data in a dangerous way
3. Users must explicitly open EPUB files through the extension interface

**Recommendation**: Add origin validation to reject messages from untrusted sources:
```javascript
window.addEventListener("message", e => {
  if (e.origin !== chrome.runtime.getURL("").slice(0, -1)) return;
  e.data.m
}, !1)
```

## False Positives Analysis

### Static Analyzer Exfiltration Flow (False Positive)

The ext-analyzer tool flagged:
```
[HIGH] chrome.tabs.query → fetch(${s})    serviceWorker.js
```

**Analysis**: After reviewing the deobfuscated code, this appears to be a false positive. The `chrome.tabs.query` calls in the codebase are used for legitimate UI functionality:

1. **Mute all tabs feature** (sidebar.js, onboard.js): Queries all tabs to mute/unmute them when the user toggles the "mute sounds" accessibility feature
2. **Get active tab** (sidebar.js, onboard.js): Retrieves the current active tab to apply accessibility settings to the correct page

The tab query results are NOT sent to external servers. The serviceWorker.js file is heavily webpack-bundled with Firebase libraries, and the analyzer appears to have connected two unrelated code paths through the bundled code.

### WASM Files (Expected)

The extension contains two WASM files for PDF rendering:
1. **openjpeg.wasm** (250KB) - JPEG2000 image decoder for PDF images
2. **qcms_bg.wasm** (94KB) - Rust-based color management system

These are legitimate components of the PDF.js library used for client-side PDF rendering. No malicious functionality detected in WASM analysis.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| accsio.firebaseapp.com | Firebase authentication finish signup redirect | OAuth tokens | Low - Standard Firebase auth flow |
| identitytoolkit.googleapis.com | Google Identity Toolkit (Firebase Auth backend) | Email, auth tokens | Low - Standard Google auth |
| googleapis.com | Google OAuth2 user info | OAuth scopes for profile/email | Low - Disclosed OAuth scopes |
| accsio.ai | Company website for terms/privacy/uninstall | None (display only) | Low - Static content |

**OAuth2 Configuration**:
- Client ID: 721371878427-gi0tars331kvuh34runiku1ghalh3f9f.apps.googleusercontent.com
- Scopes: userinfo.profile, userinfo.email
- Purpose: User account management for premium features

All network communication is with disclosed, legitimate services. No hidden tracking or data collection endpoints detected.

## Privacy Analysis

**Data Collection**: The extension collects:
- User Google profile/email (if user chooses to login via OAuth)
- User accessibility preferences (stored locally in chrome.storage.local)
- Web highlights (stored locally in IndexedDB, not synced to server)

**Storage Mechanisms**:
- chrome.storage.local - User preferences and settings
- IndexedDB ("pixie-reader" database) - Web page highlights with metadata

**Disclosure**: The extension requires users to accept privacy policy at accsio.ai/privacy before using premium features. OAuth scopes are properly declared in manifest.

## Content Scripts Analysis

**Injection Scope**: `<all_urls>` with `all_frames: true`

**Functionality**: The content script provides:
- Text-to-speech reading functionality
- Visual overlays for reading ruler/highlighter
- Dyslexia-friendly font injection
- CSS modifications for contrast/saturation
- Web highlighting persistence

**Justification**: The broad content script scope is necessary for an accessibility tool that must work on any webpage the user visits. The functionality matches the extension's stated purpose.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

Pixie Reader is a legitimate accessibility extension with one minor security issue (postMessage without origin check) that has limited practical impact. The extension:

1. **Follows best practices**: Uses MV3, properly scoped permissions, standard Firebase auth
2. **No malicious behavior**: No hidden data exfiltration, tracking, or credential harvesting
3. **Transparent functionality**: All features match the stated accessibility purpose
4. **Appropriate permissions**: Content script on `<all_urls>` is justified for accessibility features
5. **Local-first storage**: User highlights stored in IndexedDB, not sent to servers
6. **Disclosed data collection**: OAuth scopes and privacy policy properly presented

The static analyzer's high-severity exfiltration finding is a false positive caused by webpack bundling connecting unrelated code paths. The actual tab query operations are for legitimate UI functionality (muting tabs, getting active tab for settings).

**Recommendation**: The postMessage listener should add origin validation, but this does not warrant a higher risk rating given the isolated execution context and minimal impact.
