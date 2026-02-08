# Screenpresso Chrome Extension Security Analysis

## Extension Metadata
- **Extension Name**: Screenpresso
- **Extension ID**: agffhkejbocomabiogfdjnbfcnpdljie
- **Version**: 2022.09.09
- **User Count**: ~20,000 users
- **Manifest Version**: 3
- **Developer**: Learnpulse
- **Homepage**: https://www.screenpresso.com/

## Executive Summary

Screenpresso is a legitimate screenshot capture Chrome extension that integrates with the Windows desktop application "Screenpresso.exe" via native messaging. The extension captures full-page screenshots by auto-scrolling, stitching together multiple viewport captures, and either sending the result to the native application or saving locally in PNG/JPG/PDF format.

**Overall Risk Assessment: CLEAN**

The extension demonstrates clean, well-structured code with legitimate functionality matching its stated purpose. No malicious behavior, data exfiltration, obfuscation, or security vulnerabilities were identified. The extension uses appropriate permissions for its screenshot functionality and implements native messaging to communicate with a companion desktop application.

## Vulnerability Analysis

### No Critical or High Severity Issues Found

After comprehensive analysis of the codebase, no critical or high severity vulnerabilities were identified.

### Medium Severity Issues

None identified.

### Low Severity Issues

#### 1. Commented-Out Google Analytics Code
- **Severity**: LOW (Informational)
- **File**: `www.screenpresso.com/engine/service-worker.js` (lines 135-151)
- **Description**: The extension contains commented-out Google Analytics tracking code with tracking ID `UA-6234018-23`. This code is explicitly disabled with a comment noting "Will not work in V3" (Manifest V3).
- **Code**:
```javascript
/* Will not work in V3
  (function (i, s, o, g, r, a, m) {
    i["GoogleAnalyticsObject"] = r;
    ...
  })(window, document, "script", "https://www.google-analytics.com/analytics.js", "ga");
  ga("create", "UA-6234018-23", "auto");
  ga("set", "checkProtocolTask", function () {});
*/
```
- **Verdict**: **Not a vulnerability**. The code is commented out and not executed. Developers left it in as legacy code from a previous manifest version.

#### 2. Native Messaging to Local Application
- **Severity**: LOW (Design Pattern)
- **File**: `www.screenpresso.com/engine/service-worker.js` (lines 276-289)
- **Description**: The extension uses `chrome.runtime.sendNativeMessage()` to communicate with "com.screenpresso.api" native host.
- **Code**:
```javascript
BROWSER.runtime.sendNativeMessage(
  "com.screenpresso.api",
  request,
  function (response) {
    if (chrome.runtime.lastError) {
      BROWSER.DEBUG = chrome.runtime.lastError.message;
    } else {
      // Success
    }
    sendResponse(response);
  }
);
```
- **Verdict**: **Legitimate functionality**. This is the intended design pattern for browser-to-desktop integration. The extension sends screenshot data to the Windows desktop application for editing. If the native application is not installed, the extension falls back to saving locally (PNG/JPG/PDF) or clipboard.

#### 3. Dynamic Script Injection (jsPDF Library)
- **Severity**: LOW (Controlled)
- **File**: `www.screenpresso.com/engine/service-worker.js` (lines 209-220)
- **Description**: The extension lazily loads the jsPDF library when PDF export is selected.
- **Code**:
```javascript
BROWSER.scripting.executeScript(
  {
    target: {tabId: tabId},
    files: [jsPDF],
  },
  function (result) {
    if (!BROWSER.runtime.lastError) {
    }
  }
);
```
- **Verdict**: **Safe**. The script being injected is a bundled library (`www.screenpresso.com/libs/jspdf.min.js` v1.5.3), not dynamically fetched from an external source. This is a performance optimization (lazy loading).

## Manifest Analysis

### Permissions
```json
"permissions": ["activeTab", "nativeMessaging", "scripting", "storage"]
```

**Analysis**:
- **activeTab**: Used to capture screenshots of the current tab - appropriate for screenshot functionality
- **nativeMessaging**: Used to communicate with Screenpresso.exe desktop application - legitimate use case
- **scripting**: Used to inject content scripts and jsPDF library - necessary for functionality
- **storage**: Stores user preferences (format, clipboard, debug) - minimal data, appropriate use

**Verdict**: All permissions are justified and used appropriately for the extension's core functionality.

### Content Security Policy
```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```

**Verdict**: Strong CSP that only allows scripts from the extension package itself. No external scripts or unsafe-eval.

### Host Permissions
The extension declares content scripts that run on `http://*/*` and `https://*/*` at `document_idle`. This is necessary to capture screenshots on any webpage the user visits.

**Verdict**: Broad host access is required for the screenshot functionality but the extension only activates when the user clicks the toolbar button.

## Code Analysis

### Background Service Worker
**File**: `www.screenpresso.com/engine/service-worker.js`

**Functionality**:
- Listens for toolbar button clicks
- Checks page zoom level and normalizes to 1.0 before capture
- Captures visible tab screenshots using `chrome.tabs.captureVisibleTab()`
- Sends native messages to Screenpresso.exe desktop app
- Lazily loads jsPDF library when needed
- Manages toolbar icon state (enabled/disabled, color changes)

**Security Analysis**: No suspicious behavior. All Chrome API usage is appropriate and safe.

### Content Script
**File**: `www.screenpresso.com/engine/content_scripts.js`

**Functionality**:
- Orchestrates full-page screenshot capture by:
  1. Auto-scrolling through the page
  2. Capturing viewport screenshots at each scroll position
  3. Stitching screenshots together on a canvas
  4. Handling fixed/sticky positioned elements
- Sends screenshot data to native app or saves locally
- Supports PNG, JPG, and PDF export formats
- Clipboard integration for copying screenshots

**Security Analysis**:
- No DOM manipulation beyond temporary overlay during capture
- No keylogging, form interception, or sensitive data access
- No network requests to external servers
- Screenshot data only sent to local native application or saved locally
- Clean implementation with proper cleanup

### Browser Abstraction Layer
**File**: `www.screenpresso.com/engine/browser.js`

**Functionality**:
- Provides cross-browser compatibility (Chrome/Firefox)
- Wrapper functions for storage, messaging, and debugging
- No dynamic code execution

**Security Analysis**: Clean abstraction layer with no security concerns.

## Data Flow Analysis

### Screenshot Capture Flow
1. User clicks toolbar icon
2. Extension checks zoom level, normalizes if needed
3. Content script activates on current tab
4. Auto-scroll and capture loop:
   - Scroll to position
   - Request `captureVisibleTab` from background
   - Background captures viewport and returns data URL
   - Content script stores image data
   - Repeat until full page captured
5. Stitch screenshots together on canvas
6. Export options:
   - **Primary**: Send to Screenpresso.exe via native messaging
   - **Fallback 1**: Copy to clipboard (if enabled)
   - **Fallback 2**: Save as PNG/JPG/PDF file

### Data Storage
- **chrome.storage.sync**: Stores user preferences
  - `format`: Image format (0=PNG, 1=JPG, 2=PDF)
  - `clipboard`: Boolean for clipboard mode
  - `debug`: Boolean for debug logging
- No sensitive user data collected or stored

### Network Activity
- **None**: The extension makes zero network requests
- All screenshot data stays local (native app or file system)
- No analytics or telemetry (GA code is commented out)

## False Positive Analysis

| Pattern | Location | Verdict |
|---------|----------|---------|
| `sendNativeMessage` | service-worker.js:276 | Legitimate - documented integration with desktop app |
| `executeScript` | service-worker.js:210 | Legitimate - lazy loading bundled jsPDF library |
| Commented GA code | service-worker.js:135-151 | Not executed - legacy code from Manifest V2 |
| Global event prevention | content_scripts.js:62-64 | Legitimate - disables scrolling during screenshot capture |
| DOM injection (aside) | content_scripts.js:53-65 | Legitimate - temporary overlay shows capture progress |

## API Endpoint Analysis

**No external API endpoints identified.**

The extension does not communicate with any remote servers. All operations are local:
- Native messaging to `com.screenpresso.api` (local Windows application)
- Local file downloads
- Clipboard API (browser-native)

## Attack Surface Assessment

### Potential Attack Vectors

1. **Malicious Native Host**: If a malicious application registers as "com.screenpresso.api", it could receive screenshot data. However, this requires:
   - Administrative/installation privileges on the user's machine
   - Native messaging host manifest registration
   - User already trusts Screenpresso desktop app

   **Mitigation**: This is inherent to native messaging design and not an extension vulnerability.

2. **Screenshot Content Exposure**: Screenshots may contain sensitive information (passwords, PII, etc.). However:
   - User explicitly triggers captures
   - Data only sent to trusted local app or saved locally
   - No cloud upload or third-party transmission

   **Mitigation**: This is the intended functionality and documented behavior.

3. **Script Injection on All Sites**: Content scripts run on all HTTP/HTTPS sites at `document_idle`, but:
   - Scripts remain dormant until user clicks toolbar
   - No automatic data collection
   - No modification of page content (except temporary overlay during capture)

   **Mitigation**: Behavior is appropriate for screenshot functionality.

## Code Quality Assessment

**Positive Indicators**:
- Clean, well-structured code with meaningful variable names
- Comprehensive comments explaining functionality
- Proper error handling with `chrome.runtime.lastError` checks
- No obfuscation (beyond minified jsPDF library)
- No dead code or unused functions
- Proper cleanup and resource management
- Manifest V3 compliant

**Minor Issues**:
- Commented-out code should be removed in production
- Some variable shadowing (e.g., `local` declared twice in service-worker.js:54,56)

## Compliance & Privacy

- **No data collection**: Extension does not collect user data, browsing history, or analytics
- **No third-party services**: All functionality is local
- **No tracking**: Google Analytics code is disabled
- **Transparent**: Functionality matches description in manifest and Chrome Web Store

## Recommendations

1. **Remove commented-out code**: Clean up the disabled Google Analytics code (lines 135-151 in service-worker.js)
2. **Consider permission reduction**: If possible, replace broad content script injection with `activeTab` dynamic injection to reduce attack surface
3. **Add integrity checks**: Consider validating the native messaging host identity
4. **Code cleanup**: Fix minor variable shadowing issue

## Overall Risk Assessment

**Risk Level: CLEAN**

Screenpresso is a legitimate, well-implemented screenshot extension with no security vulnerabilities or malicious behavior. The extension:

- ✅ Serves its stated purpose (screenshot capture and desktop app integration)
- ✅ Uses appropriate permissions with proper justification
- ✅ Contains no obfuscation or hidden functionality
- ✅ Makes no external network requests
- ✅ Collects no user data or analytics
- ✅ Implements proper security practices (CSP, error handling)
- ✅ Follows Chrome extension best practices
- ✅ Manifest V3 compliant

The extension is safe for use and poses no security risk to users who have the legitimate Screenpresso desktop application installed. Users without the desktop app can still use local save/clipboard functionality safely.

## Conclusion

After comprehensive analysis of the Screenpresso Chrome extension, no security vulnerabilities, malicious behavior, or privacy concerns were identified. The extension is a clean, legitimate tool that integrates with a Windows desktop application for screenshot capture and editing. All code is transparent, well-structured, and appropriately scoped for its functionality.

**Final Verdict: CLEAN - Safe for use**
