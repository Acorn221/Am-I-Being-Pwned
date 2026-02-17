# Vulnerability Report: Chessvision.ai Chess Position Scanner

## Metadata
- **Extension ID**: johejpedmdkeiffkdaodgoipdjodhlld
- **Extension Name**: Chessvision.ai Chess Position Scanner
- **Version**: 3.8.1
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Chessvision.ai Chess Position Scanner is a legitimate chess analysis tool that scans chess positions from websites, books, and videos and sends them to the developer's API server (app.chessvision.ai) for analysis. The extension implements Firebase authentication and integrates with the Chessvision.ai web application.

While the extension sends user data to external servers and has a postMessage listener without strict origin validation, the data exfiltration is disclosed and legitimate for the extension's core functionality. The postMessage vulnerability is limited to third-party cookie detection messages and does not expose sensitive user data.

## Vulnerability Details

### 1. LOW: PostMessage Listener Without Origin Validation

**Severity**: LOW
**Files**: contentScript.bundle.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension implements a window message event listener (`handleCookiesMessage`) that processes messages without strict origin validation.

**Evidence**:
```javascript
// Line 29156
window.addEventListener("message", this.handleCookiesMessage, !1)

// Line 28544-28550
n.handleCookiesMessage = function(e) {
  "MM:3PCunsupported" === e.data ? n.setState({
    thirdPartyCookiesEnabled: !1,
    thirdPartyCookiesDialogOpen: !0
  }) : "MM:3PCsupported" === e.data && n.setState({
    thirdPartyCookiesEnabled: !0
  })
}
```

**Verdict**: The vulnerability is limited to third-party cookie detection messages with specific string values ("MM:3PCunsupported" and "MM:3PCsupported"). The handler only sets UI state flags and does not execute code or exfiltrate sensitive data. This is a minor security concern but does not pose a significant risk.

## False Positives Analysis

**Firebase and Google API Usage**: The extension uses Firebase Authentication and Google Cloud APIs, which are legitimate authentication mechanisms. The API keys visible in the code (AIzaSyAzopUSXAsZI9QwT4dSvl8PdUlf31Vd2gI) are standard Firebase client-side API keys that are intended to be public.

**Webpack Bundling**: The code is webpack-bundled (not truly obfuscated). The ext-analyzer flagged it as "obfuscated" but this is standard webpack minification for production builds.

**Legitimate Data Exfiltration**: The extension sends chess position data (FEN notation), user authentication state, and settings to app.chessvision.ai. This is the core functionality of a chess analysis extension and is disclosed in the extension's description.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| app.chessvision.ai | Chess position analysis | FEN notation, auth tokens, user settings | Low - Disclosed functionality |
| chessvision-video-search.appspot.com | Video search functionality | Chess position queries | Low - Disclosed functionality |
| firebase/google APIs | User authentication | Auth credentials, user ID | Low - Standard OAuth flow |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This is a legitimate chess analysis extension that functions as advertised. The data collection (chess positions, user authentication state) is directly related to the extension's stated purpose and is disclosed. The postMessage listener vulnerability is minor and limited in scope. The extension uses standard security practices including Firebase authentication and HTTPS for all communications. The "obfuscated" flag from ext-analyzer is a false positive (webpack bundling). No evidence of undisclosed tracking, credential theft, or malicious behavior was found.
