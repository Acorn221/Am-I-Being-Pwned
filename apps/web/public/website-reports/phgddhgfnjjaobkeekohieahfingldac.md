# Vulnerability Report: M*Modal Fluency Direct Web Connector

## Metadata
- **Extension ID**: phgddhgfnjjaobkeekohieahfingldac
- **Extension Name**: M*Modal Fluency Direct Web Connector
- **Version**: 5.12.5.75
- **Users**: ~900,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

M*Modal Fluency Direct Web Connector is a legitimate medical dictation extension that enables healthcare professionals to use voice-to-text dictation within web-based Electronic Health Record (EHR) systems. The extension communicates with a local native application (FDWebConnect.exe) through both native messaging and WebSocket connections to localhost. While the extension requests broad permissions including `<all_urls>` and `scripting`, these are justified for its medical documentation workflow integration across various EHR platforms.

The extension has one minor security concern: custom event listeners that handle postMessage-style communication without origin validation. However, given the extension's legitimate purpose and the fact that it only communicates with localhost, the overall risk is assessed as LOW.

## Vulnerability Details

### 1. LOW: PostMessage Event Handlers Without Origin Validation

**Severity**: LOW
**Files**: fd-web-connector.js, content-script.js
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The extension uses custom DOM events (CustomEvent) for communication between the injected web-accessible script and the content script. While these are not standard postMessage calls, they follow a similar pattern where messages are dispatched and listened to without explicit origin validation.

**Evidence**:

```javascript
// fd-web-connector.js - Event dispatch without origin check
document.addEventListener('fdWebExtension.fdConnect', fdWebExtension.fdConnectEventHandler);
document.addEventListener('fdWebExtension.fdDisconnect', fdWebExtension.fdDisconnectEventHandler);
document.addEventListener('fdWebExtension.PushTabUpdate', fdWebExtension.fdPushTabUpdate);
document.addEventListener('fdWebExtension.receiveNativeMsg', fdWebExtension.receiveNativeMsg);

// content-script.js - Listeners on custom events
document.addEventListener('fdWebExtension.saveToStorage', e => {
  var key = e.detail.key;
  var value = e.detail.value;
  chrome.storage.local.set({ [key]: value });
});

document.addEventListener('fdWebExtension.sendNativeMsg', e => {
  var msg = e.detail.msg;
  chrome.runtime.sendMessage({ message: "sendNativeMsg", nativeMsg: msg });
});
```

**Verdict**: This is a LOW severity issue because:
1. The events are custom DOM events, not cross-origin postMessage
2. The extension only communicates with localhost (127.0.0.1)
3. The native messaging connection requires explicit user installation of the companion application
4. The events are namespaced (`fdWebExtension.*`) reducing collision risk
5. The extension is designed for medical environments where the host system is typically controlled

While origin validation would be best practice, the attack surface is limited by the localhost-only communication model and the requirement for local application installation.

## False Positives Analysis

### Broad Permissions (<all_urls>)
The extension requests `<all_urls>` host permissions, which appears overly broad. However, this is justified because:
- Medical dictation must work across any EHR web application (Epic, Cerner, Athena, etc.)
- Healthcare facilities use diverse vendor platforms with different domains
- The extension only activates when the native application is installed and running
- All actual functionality is mediated through the localhost WebSocket/native messaging connection

### WebSocket to Localhost
The extension opens WebSocket connections to `ws://127.0.0.1` and `wss://127.0.0.1`. This is **not** data exfiltration:
- The connections are explicitly to localhost only
- This enables communication with the locally-installed dictation software
- The fallback to `ws://` (unencrypted) only occurs in "embedded connection mode" for legacy integrations
- Standard operation uses `wss://` (encrypted WebSocket)

### Dynamic Function Execution
The code includes `fdExecuteFunction` and `fdExecuteKnownFunction` which might appear to execute arbitrary code. However:
- The MV3 version explicitly blocks arbitrary script execution: `"fdExecuteFunction cannot process arbitrary script in manifest v3"`
- Only a whitelist of known functions can be executed (MSpeechAPI controls, Athena.Refresh, etc.)
- These are specific integrations with known EHR platforms and medical dictation APIs

### Content Script Injection on All URLs
The background script dynamically injects content scripts on all tabs. This is legitimate because:
- Required for the extension to work on newly navigated EHR pages
- Only injects when the user has explicitly installed both the extension and native application
- Standard practice for browser automation tools in enterprise environments

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| ws://127.0.0.1:2020 | Local WebSocket connection to FDWebConnect.exe | Dictation commands, text insertion, focus events, log messages | LOW - localhost only, requires native app |
| wss://127.0.0.1:2020 | Secure WebSocket to FDWebConnect.exe (default) | Same as above | LOW - localhost only, encrypted |
| chrome.runtime.connectNative | Native messaging to com.mmodal.fluency_direct_web_connector | Tab messages, connection state | LOW - requires explicit native host installation |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
M*Modal Fluency Direct Web Connector is a legitimate medical productivity tool used by approximately 900,000 healthcare professionals. The extension's architecture is appropriate for its use case:

1. **Legitimate Use Case**: Medical voice dictation integration with EHRs
2. **Localhost Communication**: All network activity is to 127.0.0.1, not external servers
3. **User Consent**: Requires explicit installation of both extension and native application
4. **Enterprise Context**: Deployed in controlled healthcare environments
5. **Minor Security Concern**: Custom event handlers could benefit from additional validation, but the attack surface is minimal

The single LOW severity vulnerability (lack of origin validation on custom events) is mitigated by the extension's architecture and deployment context. There is no evidence of data exfiltration, credential theft, or malicious behavior.

**Recommendation**: This extension is safe for use in its intended medical/healthcare environment. Organizations deploying it should ensure the native application (FDWebConnect.exe) is obtained from official M*Modal sources and kept up to date.
