# Vulnerability Report: Antidote

## Metadata
- **Extension ID**: cchfigjcpjmclmmphipdkeocklpnjecm
- **Extension Name**: Antidote
- **Version**: 1000.2.85
- **Users**: ~300,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Antidote is a French grammar and writing assistant tool developed by Druide informatique inc. The extension communicates with a native desktop application (Antidote) installed on the user's computer to provide advanced proofreading, grammar checking, dictionary, and style guide features. The extension acts as a bridge between web text editors (including Google Docs, WordPress, and various web applications) and the desktop Antidote application.

While the extension has several attack surface issues related to unvalidated postMessage handlers, these are necessary for its legitimate functionality as a text editor integration tool. The extension communicates exclusively with localhost (127.0.0.1) via WebSocket and native messaging to connect with the locally-installed Antidote desktop application. No external data exfiltration or privacy violations were identified.

## Vulnerability Details

### 1. MEDIUM: Multiple postMessage Handlers Without Origin Validation

**Severity**: MEDIUM
**Files**: antidoteGrav.js, antidoteAPIJSConnect.js, antidote.js, AgentTexteurGrav.js
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
**Description**: The extension implements multiple `window.addEventListener("message")` handlers across various components without validating the origin of incoming messages. This creates potential for cross-site scripting attacks if a malicious website sends crafted messages to the extension's content scripts.

**Evidence**:
```javascript
// antidoteGrav.js:9
window.addEventListener("message", gestionnaireMessageDsPage, false);

// antidoteAPIJSConnect.js:8
window.addEventListener("message", gestionnaireMessageDsPageAntidoteAPI_JSConnect, false);

// antidote.js:1308, 1424, 1460
window.addEventListener("message", gestionnaireMessageAntidoteAPIJSConnect, false);
window.addEventListener("message", gestionnaireMessageGrav, false);
window.addEventListener("message", gestionnaireMessageDuCorrecteurAW, false);
```

However, the handlers do implement type filtering:
```javascript
function gestionnaireMessageDsPage(event) {
    if (event.data.type != "TypeContentScript")
        return;
    // ... process message
}
```

**Verdict**: While there is no origin check, the extension uses type-based message filtering to distinguish between different communication channels. The messages primarily coordinate text editing operations between different components of the extension (page scripts, content scripts, and background). The risk is mitigated by the fact that the extension only processes specific message types and does not execute arbitrary code or send sensitive data externally based on these messages.

### 2. LOW: Externally Connectable Configuration

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-923 (Improper Restriction of Communication Channel to Intended Endpoints)
**Description**: The manifest declares `externally_connectable` for Google Docs domains, allowing external websites to send messages to the extension.

**Evidence**:
```json
"externally_connectable": {
  "matches": [
    "https://docs.google.com/*",
    "https://drive.google.com/*",
    "https://*.googleusercontent.com/*"
  ]
}
```

**Verdict**: This configuration is intentional and necessary for the extension's Google Docs integration functionality. The extension needs to communicate with Google Docs pages to provide proofreading services within the Google Docs editor. This is a documented and expected behavior for text editor integration tools.

## False Positives Analysis

### Obfuscation Flag
The static analyzer flagged the code as "obfuscated." However, this appears to be standard JavaScript minification/compilation rather than malicious obfuscation. The code uses French variable names and constants (e.g., `gestionnaireMessageDsPage`, `monAppNative`, `etablisConnexionWebSocket`) which is consistent with the developer being a French-Canadian company (Druide informatique inc.). The deobfuscated code is readable and follows standard patterns for browser extension development.

### Native Messaging
The extension uses `chrome.runtime.connectNative()` to connect to a native application named per `cstNomAgentAntidote`. This is legitimate behavior for an extension that requires integration with a desktop application. The native messaging is used exclusively to communicate with the locally-installed Antidote grammar checker application.

### WebSocket to Localhost
The extension establishes WebSocket connections to `ws://127.0.0.1:[port]` (line 2128 in background.js). This is a legitimate local communication channel with the desktop Antidote application and does not represent a security risk, as it only connects to localhost.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| ws://127.0.0.1:[dynamic port] | Local WebSocket connection to Antidote desktop app | Text content for proofreading, UI messages, configuration | LOW - localhost only |
| https://script.google.com/macros/s/AKfycbz2aniNVwfTMGdlpkh2QlMPSpeUZSPCUHdPdgBdhQ_R98wp1pKg/exec | Google Apps Script for Google Docs integration | OAuth tokens, document access requests | LOW - legitimate Google API |
| https://www.googleapis.com/oauth2/v3/tokeninfo | Google OAuth token validation | OAuth access tokens | LOW - standard OAuth flow |
| https://accounts.google.com/o/oauth2/auth | Google OAuth authorization | OAuth parameters | LOW - standard OAuth flow |
| https://antidote.app/ | Antidote Web service | Links/redirects only | LOW - first-party service |
| https://www.druide.com/ | Druide informatique (developer website) | None - informational links only | CLEAN |
| https://www.antidote.info/ | Antidote info/support | None - informational links only | CLEAN |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

Antidote is a legitimate grammar and writing assistance tool that requires deep integration with web text editors and a native desktop application. The security concerns identified are primarily architectural decisions necessary for the extension's functionality:

1. **postMessage handlers without origin validation**: While this is technically a vulnerability, the handlers use type-based filtering and do not expose sensitive operations or data exfiltration paths. The messages are used for coordinating text editing operations within the extension's own components.

2. **Broad host permissions** (`http://*/*`, `https://*/*`): Required for the extension to work on any webpage where users might want to use the grammar checker, which is the core value proposition.

3. **Native messaging**: Legitimate use case for communicating with the desktop Antidote application.

4. **WebSocket to localhost**: Standard pattern for browser-to-desktop-app communication.

The extension does not exhibit malicious behavior such as:
- Data exfiltration to unauthorized third parties
- Credential theft
- Ad injection
- Cookie harvesting
- Hidden network requests to external servers (except legitimate Google OAuth)
- Code execution from remote sources

The extension is published by Druide informatique inc., a well-established Canadian software company that has been developing the Antidote grammar checker since 1996. The extension has 300,000 users and serves as the official browser integration for their desktop software.

The low risk rating reflects that while there are some attack surface concerns from a strict security perspective, they are necessary for the extension's legitimate functionality and do not represent actual privacy or security threats to users in the context of how the extension operates.
