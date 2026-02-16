# Vulnerability Report: Online speech recognition

## Metadata
- **Extension ID**: pehlbpmpoabkgenppepoaihkacolpdcf
- **Extension Name**: Online speech recognition (Speechpad / Voice Notebook)
- **Version**: 10.0
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension provides voice-to-text functionality using Chrome's Web Speech API with native messaging integration for OS-level text insertion. The extension allows users to dictate text into web forms and system applications via a native messaging host (`ru.speechpad.host`). The extension is associated with two legitimate websites (speechpad.ru and voicenotebook.com) that provide online speech recognition services.

The extension uses legitimate features for its stated purpose. The native messaging component enables text insertion into system-level applications beyond the browser, which is the core functionality. The code is relatively clean with only minor security considerations related to the use of legacy DOM manipulation methods.

## Vulnerability Details

### 1. LOW: Use of document.execCommand() for clipboard operations

**Severity**: LOW
**Files**: offscreen.js
**CWE**: CWE-676 (Use of Potentially Dangerous Function)
**Description**: The extension uses the deprecated `document.execCommand('copy')` method for clipboard operations in the offscreen document. While this is a legitimate use case (the comments indicate that `navigator.clipboard` API requires window focus which offscreen documents cannot have), it represents use of a deprecated API.

**Evidence**:
```javascript
// offscreen.js:69
document.execCommand('copy');
```

**Verdict**: This is a legitimate workaround for MV3 clipboard limitations in offscreen documents as of January 2023. The implementation follows Google's official sample code (Apache 2.0 licensed header present). This is not a security vulnerability but a technical debt issue. The user-provided data flows through proper message validation before being copied.

### 2. MINOR: postMessage without strict origin validation

**Severity**: LOW
**Files**: myscript.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The content script uses `window.postMessage` with wildcard origin (`"*"`) for page-to-extension communication.

**Evidence**:
```javascript
// myscript.js:44
window.postMessage({ type: "FROM_SCRIPT", text: "all ok"}, "*");
```

**Verdict**: While the postMessage uses a wildcard, the listener in myscript.js properly validates the message source (`event.source != window`) and checks for specific message types. The data flow is: page → content script → background → native host. This is standard practice for content script injection patterns. The wildcard is used for same-window communication only, not cross-origin.

## False Positives Analysis

### Native Messaging to "ru.speechpad.host"
The static analyzer flagged data flows from DOM elements to `chrome.runtime.sendNativeMessage` as potential exfiltration. However, this is the core legitimate functionality:
- The extension's purpose is to send speech-recognized text to a native application
- The native messaging host name `ru.speechpad.host` must be installed separately by the user
- Native messaging requires explicit user installation of the host application and generates Chrome permission prompts
- The text being sent is user-dictated speech, not harvested sensitive data

### Web Speech API Usage
The extension uses `webkitSpeechRecognition()` which is Chrome's implementation of the Web Speech API. This is a standard browser API for voice recognition and does not represent malicious behavior.

### Script Injection (injscript.js)
The extension injects a script to enable voice input on active text fields. This is expected behavior for a voice-to-text tool and properly checks that the target is an editable element (textarea, input[type=text], contentEditable).

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| speechpad.ru | Official website for Russian/Ukrainian users | User settings (language preference, recording mode) via URL parameters | Low - Legitimate first-party service |
| voicenotebook.com | Official website for English users | User settings (language preference, recording mode) via URL parameters | Low - Legitimate first-party service |
| ru.speechpad.host (native) | Native messaging host for OS-level text insertion | Dictated text, formatting commands, undo operations | Low - Requires user installation, legitimate functionality |

### Endpoint Details:
- **speechpad.ru / voicenotebook.com**: These are opened in new tabs based on user locale. Only preference data is sent via URL query parameters (autostart, language code, buffer/native speech flags). No sensitive data exfiltration occurs.
- **Native messaging host**: Sends recognized speech text and control commands (checking, undo) to the locally-installed native application. This is the core functionality enabling text insertion into system applications.

## Content Script Analysis

The extension includes one content script (`myscript.js`) that only runs on the extension's own domains:
- `http(s)://speechpad.ru/*`
- `http(s)://voicenotebook.com/*`

This content script acts as a bridge between the web application and the extension, enabling communication for features like clipboard operations and native messaging integration. It does NOT run on `<all_urls>` and cannot access arbitrary user browsing data.

## Permissions Analysis

All requested permissions are justified:
- **scripting**: Inject voice recognition script into active text fields on user command
- **storage**: Save user preferences (language, spacing options)
- **tabs**: Query and message tabs running speechpad.ru/voicenotebook.com
- **clipboardWrite**: Copy recognized text to clipboard
- **offscreen**: MV3 requirement for clipboard API access
- **contextMenus**: Add right-click menu option to start voice input
- **nativeMessaging**: Core functionality for OS-level text insertion
- **activeTab**: Inject script only into user-activated tab

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This is a legitimate voice-to-text extension with appropriate permissions for its stated functionality. The native messaging component is properly disclosed and requires explicit user installation. While the static analyzer flagged data flows from DOM to native messaging as potential exfiltration, this is the intended and documented behavior of a voice dictation tool.

The only minor concern is the use of deprecated `document.execCommand()`, which is a technical debt issue rather than a security vulnerability and follows Google's recommended pattern for MV3 offscreen documents.

The extension does not:
- Collect browsing history or sensitive user data
- Inject scripts on arbitrary websites (content scripts limited to own domains)
- Make unauthorized network requests
- Contain obfuscated malicious code
- Perform credential theft or session hijacking

The obfuscation flag from the analyzer appears to be related to minified/bundled code patterns rather than intentional code hiding.
