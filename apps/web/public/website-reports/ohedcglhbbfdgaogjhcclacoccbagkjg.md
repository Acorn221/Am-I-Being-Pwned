# Vulnerability Report: Адаптер Рутокен Плагин

## Metadata
- **Extension ID**: ohedcglhbbfdgaogjhcclacoccbagkjg
- **Extension Name**: Адаптер Рутокен Плагин
- **Version**: 1.1.0.0
- **Users**: ~2,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension serves as a browser adapter for Rutoken Plugin, a Russian cryptographic hardware token system. It bridges web pages to a native messaging host (`ru.rutoken.firewyrmhost`) to enable cryptographic operations via NPAPI-style plugin emulation using the FireWyrm framework. While the extension's core functionality is legitimate for its stated purpose, it contains a medium-severity security vulnerability: a postMessage event listener without origin validation in webpage.js. The extension has extensive permissions (`<all_urls>`, nativeMessaging, scripting) necessary for its functionality, but the missing origin check could allow malicious websites to trigger unintended behavior.

The extension appears to be a legitimate enterprise/government tool for working with Rutoken cryptographic tokens, commonly used in Russia for digital signatures and authentication. The large user base (2 million) and legitimate functionality suggest this is not malware, but the security issue should be addressed.

## Vulnerability Details

### 1. MEDIUM: postMessage Event Listener Without Origin Validation

**Severity**: MEDIUM
**Files**: webpage.js:1413, content.js:9
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The extension implements a message passing system between web pages, content scripts, and the native messaging host. In webpage.js line 1413, there is a `window.addEventListener("message")` handler that does not properly validate the origin of incoming messages before processing them. While the code does check that `event.source == window` (same-window check) and validates the message structure (`event.data.rutoken`), it does not validate the origin of the message.

**Evidence**:

```javascript
// webpage.js:1413
window.addEventListener("message", onMessage, false);

function onMessage(event) {
    // We only accept messages from ourselves
    if (event.source != window || typeof event.data === "undefined") { return; }

    if (typeof event.data.rutoken === "undefined") { return; }

    if (event.data.rutoken.source == "content" && typeof event.data.rutoken.event !== "undefined") {
        if (event.data.rutoken.event == "created") {
            while (connectList.length) {
                var cur = connectList.pop();
                connectWyrmhole(cur.extId, cur.dfd, event.data.rutoken);
            }
        } else {
            if (!qEvents[event.data.rutoken.port]) {
                qEvents[event.data.rutoken.port] = [];
            }
            qEvents[event.data.rutoken.port].push(event);
        }
    }
    // ... continues processing without origin check
}
```

Additionally, in webpage.js:1465, another message listener exists:

```javascript
window.addEventListener("message", function (event) {
    if (event.source != window || typeof event.data === "undefined" || typeof event.data.rutoken === "undefined") {
        return;
    }

    var data = event.data.rutoken;
    if (typeof data.promiseId === "undefined") {
        return;
    }

    var promise = promises[data.promiseId];
    if (typeof promise === "undefined") {
        return;
    } else {
        delete promises[data.promiseId];
    }

    if (typeof data.source === "undefined" || data.source !== "extension") {
        promise.reject("Wrong message from extension: " + data);
    } else {
        promise.resolve(data.result);
    }
});
```

**Verdict**:
While the impact is somewhat mitigated by the same-window check (`event.source == window`) and the requirement for specific message structure with extension ID validation, a malicious script running on the same page could potentially craft messages that trigger the wyrmhole communication system. The extension ID check provides some protection, but this is still a violation of security best practices. An attacker with XSS on a page where this extension is active could potentially interact with the native messaging host in unintended ways.

The proper fix would be to validate `event.origin` against a whitelist of allowed origins, or at minimum check that messages come from the expected source.

## False Positives Analysis

**Broad Permissions (`<all_urls>`, `nativeMessaging`, `scripting`)**: These are legitimate and necessary for the extension's purpose. It needs to inject scripts into all pages to provide the Rutoken plugin API, communicate with the native host for cryptographic operations, and dynamically register content scripts for MV3 compatibility.

**Complex Code Structure**: The FireWyrmJS framework and Wyrmhole communication system appear complex but are legitimate components for emulating NPAPI-style plugin behavior in modern browsers. This is not obfuscation but rather a sophisticated bridge architecture.

**Global Object Injection**: The extension injects global objects (`window[extensionId]` and `window[objectId]`) into web pages. This is the intended functionality to provide a plugin-like API to websites that expect the Rutoken plugin interface.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | This extension does not make external HTTP/HTTPS requests | N/A | CLEAN |

**Note**: The extension only communicates with a local native messaging host (`ru.rutoken.firewyrmhost`), not external web servers. All cryptographic operations are handled locally.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This is a legitimate enterprise tool for cryptographic hardware token integration, serving 2 million users. The core functionality is not malicious and serves a valid business purpose (digital signatures, authentication via Rutoken hardware). However, it contains a medium-severity security vulnerability:

1. **postMessage without origin validation** - While partially mitigated by same-window checks and message structure validation, this violates security best practices and could be exploited by malicious scripts on the same page to interact with the native messaging bridge.

2. **Extensive permissions are justified** - The `<all_urls>` and `nativeMessaging` permissions are necessary for the extension's legitimate function as a browser-to-hardware bridge.

3. **No data exfiltration** - The extension does not send data to external servers, only to a local native application.

4. **No malicious behavior** - No evidence of credential theft, tracking, ad injection, or other malicious activity.

The MEDIUM risk rating reflects the security vulnerability that should be fixed, but acknowledges this is a legitimate tool, not malware. Organizations using Rutoken should continue to use this extension but should be aware of the postMessage security issue. The vendor should implement proper origin validation in a future update.
