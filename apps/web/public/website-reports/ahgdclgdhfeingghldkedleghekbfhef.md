# Vulnerability Report: Symantec Authentication Client Extension

## Metadata
- **Extension ID**: ahgdclgdhfeingghldkedleghekbfhef
- **Extension Name**: Symantec Authentication Client Extension
- **Version**: 100.5.0.109
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

The Symantec Authentication Client Extension is an enterprise authentication tool designed to bridge web pages with a native Symantec PKI client application via the Chrome nativeMessaging API. The extension creates a communication channel between web content and the native authentication client to facilitate certificate-based authentication workflows.

While the extension serves a legitimate enterprise security purpose, it exhibits a medium-severity security concern: it accepts postMessage events from any origin without validation, combined with broad <all_urls> permissions. This creates a potential attack surface where malicious websites could attempt to abuse the messaging bridge to interact with the native PKI client in unintended ways.

## Vulnerability Details

### 1. MEDIUM: PostMessage Communication Without Origin Validation

**Severity**: MEDIUM
**Files**: content/pkiClientExtension.js, background/pkiClientExtension.js, background/messenger.js
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The extension implements a messaging bridge that listens for postMessage events from web pages and forwards them to a native messaging host (Symantec PKI Client). The content script injects a bridge object into all pages (via <all_urls>) that accepts messages from the DOM without validating the origin of the sender.

**Evidence**:
- The extension uses `<all_urls>` permission in content_scripts, injecting bridge code into every webpage
- Detection script (`content/detection.js`) injects a DOM element to signal extension presence: `a.id="__symantecPKIClientDetector"; a.innerHTML="__PRESENT"`
- The bridge accepts JSON-RPC 2.0 formatted messages via the DOM event system
- Content script (`content/bridge.js`) establishes a port connection to the background page and relays messages
- Background page (`background/messenger.js`) processes messages and forwards them to the native messaging host
- Native messaging connection uses host ID: `com.symantec.pkiclient.nativemessaging.launcher` or flavor-specific variants

The message flow is: Web Page (postMessage) -> Content Script -> Background Page -> Native Host

While the native host likely has its own authentication/authorization checks, the lack of origin validation at the extension level means any webpage can attempt to send messages to the PKI client. The extension accepts messages with methods including: `findExtensions`, `startup`, `bootstrap`, `brokerChannelInit`, `clientMessages`, `setTrustedURL`, `enterClientMode`, `leaveClientMode`, `shutdown`.

**Verdict**: This is a design pattern common in enterprise bridge extensions where the native application is expected to perform security checks. However, the lack of origin whitelisting at the extension level increases attack surface. A malicious website could probe the messaging interface, potentially discovering information about installed authentication clients or attempting to trigger unintended behaviors. The risk is partially mitigated by the fact that the native messaging host must be installed separately and likely implements its own access controls.

## False Positives Analysis

**Native Messaging for Enterprise Tools**: The extension's use of nativeMessaging and <all_urls> is appropriate for its stated purpose as an enterprise authentication bridge. These permissions are necessary for the extension to facilitate communication between web-based authentication portals and the local PKI client software.

**No Data Exfiltration**: Despite having <all_urls> access, the extension does not collect or exfiltrate user data. It serves purely as a message relay between DOM events and the native application.

**Script Injection on Startup**: The `attach.js` script programmatically injects content scripts into existing tabs on startup. While this could appear suspicious, it's a legitimate technique to ensure the bridge is available in tabs that were already open when the extension was installed or updated.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | N/A | N/A | N/A |

The extension does not communicate with any external web servers. All communication is local (DOM <-> Content Script <-> Background <-> Native Host).

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: This is a legitimate enterprise security tool developed by Symantec (now part of Broadcom) for PKI-based authentication. The extension correctly implements a bridge pattern for native messaging, which is the appropriate Chrome API for this use case.

The MEDIUM risk rating is assigned due to the lack of origin validation in the postMessage interface, combined with the broad injection scope (<all_urls>). While this is a common pattern for enterprise bridge extensions where the native application performs authorization, it does create an expanded attack surface. Any webpage could theoretically attempt to interact with the PKI client through this bridge.

For enterprise deployments where this extension is required for authentication infrastructure, this risk is acceptable and expected. The native Symantec PKI Client application is responsible for enforcing authentication and authorization policies, not the browser extension.

**Recommendations for users**:
- This extension should only be installed in enterprise environments where Symantec/Broadcom authentication infrastructure is in use
- The native PKI client application must be properly configured with appropriate security policies
- Regular users without enterprise PKI requirements should not install this extension

**Not flagged as HIGH or CRITICAL because**: The extension serves its stated purpose without deception, does not exfiltrate data, and relies on the native application for security enforcement, which is standard for enterprise bridge extensions.
