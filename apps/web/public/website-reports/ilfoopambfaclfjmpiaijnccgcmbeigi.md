# Vulnerability Report: FormApps Extension

## Metadata
- **Extension ID**: ilfoopambfaclfjmpiaijnccgcmbeigi
- **Extension Name**: FormApps Extension
- **Version**: 2.13.0.35
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

FormApps Extension is a legitimate browser extension developed by Software602 a.s. for working with their electronic forms system. The extension serves as a bridge between web pages and a native desktop application, using Chrome's native messaging API to facilitate communication. The extension only activates on pages containing specific form elements (identified by `wf_fillerform` DOM element) and acts as a message relay between the web page and the local FormApps desktop application.

Analysis of the codebase reveals no security vulnerabilities, privacy concerns, or malicious behavior. The extension uses appropriate origin checks for postMessage communication, employs native messaging exclusively for localhost communication, and does not collect, transmit, or exfiltrate any user data to remote servers.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

### 1. Broad Host Permissions
The extension requests `https://*/*` host permissions, which appears overly broad. However, this is justified for this extension type:
- The content script only injects visible DOM elements on pages with existing FormApps form elements (`wf_fillerform`)
- The extension does not actively scrape or collect data from arbitrary pages
- Broad permissions allow the extension to work on any domain where FormApps forms may be hosted

### 2. postMessage Usage
The extension uses `window.postMessage()` to communicate between content script and page context:
- **Origin checking is properly implemented**: `if (event.source !== window || event.origin !== window.location.origin) return;` (formapps.js:42-43)
- Messages are only accepted from the same window and origin
- This is secure and follows best practices

### 3. Native Messaging
The extension uses native messaging to communicate with a local desktop application:
- This is the intended purpose of the extension
- Native messaging only connects to localhost applications registered in the OS
- No remote communication occurs through native messaging
- The HOST_PATH prefix `cz.software602.chrome.` ensures only approved native hosts are contacted

### 4. executeScript on Install/Update
The background script injects the content script into existing tabs on install/update (background.js:421-431):
- This ensures the extension works on already-open tabs without requiring reload
- Only injects on `https://` URLs, skipping Chrome internal pages
- This is a user-friendly feature, not a security concern

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | No external endpoints | N/A | None |

The extension does not communicate with any external API endpoints. All communication is:
1. Between web page and content script (same-origin postMessage)
2. Between content script and background script (internal Chrome messaging)
3. Between background script and native application (localhost-only native messaging)

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

This extension is a legitimate enterprise tool with a clear, non-malicious purpose. Key security observations:

1. **No data exfiltration**: The extension does not transmit any user data to remote servers
2. **Proper origin validation**: postMessage listeners correctly validate event source and origin
3. **Appropriate permissions**: While host permissions are broad, they are justified for the extension's legitimate use case
4. **No dynamic code execution**: No use of eval(), Function constructor, or similar dangerous patterns
5. **Native messaging security**: Uses Chrome's secure native messaging API with proper host prefixes
6. **Professional development**: Code includes proper copyright notices, version tracking, and error handling
7. **Static analysis clean**: ext-analyzer reported no suspicious findings

The extension appears to be professionally developed by Software602 a.s., a legitimate software company, for legitimate business purposes (electronic form processing). There are no indicators of malicious intent or security vulnerabilities.
