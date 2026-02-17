# Vulnerability Report: Antidote

## Metadata
- **Extension ID**: lbojggafdepnclikhiapkpinbfdhbdoi
- **Extension Name**: Antidote
- **Version**: 901.1033.27
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Antidote is a legitimate grammar and spelling checker extension developed by Druide informatique inc. The extension provides French and English language correction tools integrated into web browsers. It communicates with a locally-installed native application via WebSocket connections to localhost (ws://127.0.0.1) and native messaging.

The extension has been flagged for postMessage handlers without origin validation, which represents a low-severity security issue. However, the extension does not engage in undisclosed data collection, remote code execution, or credential theft. All communication is either local (to the native Antidote app) or to Google Apps Script endpoints for Google Docs integration support. The extension's purpose as a writing assistant tool is transparent and matches its stated functionality.

## Vulnerability Details

### 1. LOW: postMessage Handlers Without Origin Validation

**Severity**: LOW
**Files**: antidoteGrav.js, antidoteAPIJSConnect.js, antidote.js
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The extension injects multiple scripts into web pages that listen for postMessage events without validating the origin of the sender. This allows any script on the page to send messages to these handlers.

**Evidence**:

```javascript
// antidoteGrav.js:5
function InitGravDsPage() {
  window.addEventListener("message", gestionnaireMessageDsPage, false)
};

function gestionnaireMessageDsPage(event) {
  if (event.data.type != "TypeContentScript") return;
  // Checks type but not origin
  var _d9 = event.data.message;
  // ... processes messages
}

// antidoteAPIJSConnect.js:8
window.addEventListener("message", gestionnaireMessageDsPageAntidoteAPI_JSConnect, false);

function gestionnaireMessageDsPageAntidoteAPI_JSConnect(event){
  if (event.data.type != "TypeContentScriptAntidoteAPIJSConnect")
    return;
  return;
};
```

The handlers check for a specific message type but do not validate `event.origin`, allowing any script on the page to potentially interact with these handlers.

**Verdict**:
This is a low-severity issue because:
1. The messages processed appear to be control/coordination messages for the extension's own functionality
2. No sensitive user data is transmitted through these channels
3. The handlers primarily coordinate between page context and content script for text editing operations
4. The extension does not execute arbitrary code or make security decisions based on these messages

The vulnerability could allow a malicious script on the same page to interfere with Antidote's functionality, but does not enable data theft or privilege escalation.

## False Positives Analysis

**Native Messaging and WebSocket to Localhost**: The extension uses native messaging and establishes WebSocket connections to `ws://127.0.0.1` on a dynamically provided port. This is the expected behavior for an extension that integrates with a locally-installed desktop application (Antidote grammar checker). This is NOT data exfiltration - it's legitimate local IPC (inter-process communication).

**Management Permission for Extension Detection**: The extension uses the `management` permission to detect and uninstall older versions of itself, which is standard behavior for extension updates and migrations:

```javascript
// background.js:1223-1243
function gestionnaireExterne(_d7, sender) {
  if (_d7.message == "je vous demande de me laisser votre place.") {
    if (sender.id == "antidote_uni10_firefox@druide.com") {
      fureteur.management.uninstallSelf()
    }
  }
}
```

This is legitimate version management, not malicious extension enumeration for attack purposes.

**Google Apps Script Endpoints**: The extension references Google Apps Script URLs for Google Docs integration. This is expected functionality for a writing tool that needs to work with Google Docs:

```javascript
// cstAntidote.js:109-110
const scriptsAntidoteGoogleDocs2015 = 'https://script.google.com/macros/s/AKfycbyhHr9-k74ojrhyxw7U6FfgSMi5mjgzji_0rhsq8mSmM0_dKlo/exec';
const scriptsAntidoteGoogleDocs2017 = 'https://script.google.com/macros/s/AKfycbz2aniNVwfTMGdlpkh2QlMPSpeUZSPCUHdPdgBdhQ_R98wp1pKg/exec';
```

These are used to enable the extension to interact with Google Docs' editing environment, which requires special scripting support.

**Broad Host Permissions**: The extension requests `http://*/*` and `https://*/*` permissions, which is appropriate for a writing assistant that needs to work on any web page where users might be typing.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| ws://127.0.0.1:{port} | Local WebSocket to native Antidote app | Text content for grammar checking, selection ranges, document metadata | Low - localhost only, expected functionality |
| https://script.google.com/macros/s/AKfycbyhHr9-k74ojrhyxw7U6FfgSMi5mjgzji_0rhsq8mSmM0_dKlo/exec | Google Apps Script for Google Docs 2015 support | Unknown - likely coordination data for Google Docs integration | Low - legitimate Google Apps Script endpoint |
| https://script.google.com/macros/s/AKfycbz2aniNVwfTMGdlpkh2QlMPSpeUZSPCUHdPdgBdhQ_R98wp1pKg/exec | Google Apps Script for Google Docs 2017 support | Unknown - likely coordination data for Google Docs integration | Low - legitimate Google Apps Script endpoint |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
Antidote is a legitimate, commercially-developed writing assistance tool from Druide informatique inc. The extension exhibits expected behavior for its category:

1. **Local Communication Only**: All substantive data (text being checked) goes to localhost WebSocket connections to the native application, not remote servers
2. **No Data Exfiltration**: No evidence of sending user data to third-party servers beyond what's needed for Google Docs integration
3. **Transparent Functionality**: The extension's behavior matches its stated purpose as a grammar and spelling checker
4. **Professional Development**: Code includes copyright notices, proper error handling, and multi-language support
5. **Single Vulnerability**: Only one low-severity issue (postMessage without origin check) which does not enable serious attacks

The postMessage vulnerability should be fixed by adding origin validation, but it does not represent a significant security risk to users in the current implementation. The extension is safe for use.
