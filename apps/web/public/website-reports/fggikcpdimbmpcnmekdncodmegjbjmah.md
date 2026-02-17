# Vulnerability Report: Fast Signature

## Metadata
- **Extension ID**: fggikcpdimbmpcnmekdncodmegjbjmah
- **Extension Name**: Fast Signature
- **Version**: 2.5.2
- **Users**: ~80,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Fast Signature is a legitimate electronic signature extension developed by Docapost Fast. The extension facilitates digital document signing by acting as a bridge between web pages on specific Docapost domains and a native host application installed on the user's computer. The extension's scope is strictly limited to authorized Docapost domains (dfast.fr and efast.fr subdomains) and uses native messaging to communicate with local signing software. No remote data collection, exfiltration, or network communication occurs beyond the stated functionality.

The extension follows a standard architecture for native messaging extensions, with a background service worker managing the connection to the native host and a content script injecting communication handlers into authorized web pages. All code is clean, well-structured, and contains no obfuscation or malicious patterns.

## Vulnerability Details

### 1. LOW: Tab Query Without Strict Filtering

**Severity**: LOW
**Files**: background.js
**CWE**: CWE-285 (Improper Authorization)
**Description**: The extension uses `browser.tabs.query({ url: "*://*/parapheur/*" })` to find relevant tabs for message delivery. This pattern matches any protocol and any domain containing "/parapheur/" in the path, which is broader than the content script's match patterns and could theoretically match unintended domains.

**Evidence**:
```javascript
// Line 110 in background.js
browser.tabs.query({ url: "*://*/parapheur/*" }, function (tabs) {
    var i;
    for (i = 0; i < tabs.length; i++) {
        let tabID = tabs[i].id;
        console.log("using tab: " + tabID);
        console.log("sending MESSAGE");
        browser.tabs.sendMessage(tabID, {
            action: 'RECEIVED_NATIVE_MESSAGE',
            type: messageObj.Type,
            data: messageObj.Message,
        });
    }
});
```

**Verdict**: This is a minor technical issue with limited real-world impact. The content script is only injected on the explicitly listed Docapost domains in manifest.json, so even if the background script attempts to send messages to other tabs, those tabs won't have the content script to receive them. The risk of message leakage to unintended origins is negligible. This represents defensive coding weakness rather than an exploitable vulnerability.

## False Positives Analysis

The extension exhibits several patterns that might appear suspicious in isolation but are entirely legitimate for its purpose:

- **Native Messaging**: The use of `nativeMessaging` permission and `connectNative()` is the core functionality - this extension is designed to bridge web content with local signing hardware/software.
- **Tab Queries**: The background script queries tabs to relay messages, which is standard for extensions coordinating between web pages and native applications.
- **Custom Events**: The content script uses `CustomEvent` and `dispatchEvent` to communicate with the web page, which is the standard pattern for content script to page communication.
- **Tab Permission**: Required to identify which tab initiated a signature request and route responses correctly.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| N/A | No network endpoints | N/A | None |

The extension makes no network requests. All communication occurs through:
1. Content script ↔ Background script (via `chrome.runtime.sendMessage`)
2. Background script ↔ Native host application (via `chrome.runtime.connectNative`)

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This is a legitimate enterprise electronic signature extension with a well-defined and limited scope. The extension:

1. **Operates only on authorized domains**: Content scripts are restricted to six specific Docapost/Efast domains
2. **No data exfiltration**: Makes no network requests; all data flows to a local native application
3. **Transparent functionality**: The code clearly implements the stated purpose (electronic signature) with no hidden behaviors
4. **Clean code**: No obfuscation, no dynamic code execution, no eval usage
5. **Appropriate permissions**: Only requests `nativeMessaging` and `tabs`, both necessary for its functionality
6. **Manifest V3**: Uses modern extension architecture

The single identified issue (overly broad tab query pattern) has negligible practical impact due to content script scope restrictions. The extension poses minimal security or privacy risk to users and appears to be a professionally developed enterprise tool for document signing workflows within the Docapost ecosystem.
