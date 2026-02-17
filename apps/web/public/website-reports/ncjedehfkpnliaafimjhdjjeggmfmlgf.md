# Vulnerability Report: Copilot sidebar for Chrome

## Metadata
- **Extension ID**: ncjedehfkpnliaafimjhdjjeggmfmlgf
- **Extension Name**: Copilot sidebar for Chrome
- **Version**: 2.0.0
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension ports Microsoft Edge's Copilot sidebar to Chrome by spoofing the Edge browser user-agent and stripping security headers (CSP and X-Frame-Options) from Bing and Copilot domains. While the extension's stated purpose is legitimate (making Copilot available in Chrome), it introduces security concerns through its postMessage implementation that lacks origin validation, and its aggressive modification of security headers that could expose users to clickjacking and other attacks if the embedded content were compromised.

The extension reads page content from all websites via content scripts and sends it to the Copilot iframe for AI processing. This behavior is expected for an AI assistant, but the lack of proper origin checking on postMessage handlers creates an attack surface where malicious iframes could trigger unauthorized page data extraction.

## Vulnerability Details

### 1. MEDIUM: postMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: sidepanel/sidepanel.js
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)

**Description**: The extension's sidepanel listens for postMessage events without validating the sender's origin. While the iframe is loaded from `copilot.microsoft.com`, the message listener accepts messages from any origin (`*`).

**Evidence**:
```javascript
// sidepanel/sidepanel.js:60
window.addEventListener("message", postMessageListner, false);

// sidepanel/sidepanel.js:35-46
async function postMessageListner(event) {
  console.debug("onMessage", event.origin, JSON.stringify(event.data));
  const eventName = event.data.eventName;
  if (eventName === "Discover.Chat.Interact.Req") {
    sendEventToIframe("Discover.Chat.Interact.Rep", { status: true });
  } else if (eventName === "Discover.Chat.Consent.Req") {
    sendEventToIframe("Discover.Chat.Consent.Rep", { text: "Accepted" });
  } else if (eventName === "Discover.Chat.Page.GetData") {
    const tab = await getActiveTab();
    const response = await chrome.tabs.sendMessage(tab.id, { action: "getPageData" });
    sendEventToIframe("Discover.Chat.Page", { text: response.text });
  }
  // ... more handlers
}
```

The handler logs `event.origin` but never validates it. Any iframe or window with access to the sidepanel window could send these messages. The `Discover.Chat.Page.GetData` event triggers extraction of the current tab's text content and sends it to the iframe.

**Verdict**: This is a security vulnerability. If the iframe from `copilot.microsoft.com` were somehow replaced or if additional iframes were injected into the sidepanel, they could trigger page data extraction without proper authorization. The extension should validate `event.origin === 'https://copilot.microsoft.com'` before processing messages.

### 2. MEDIUM: Security Header Stripping

**Severity**: MEDIUM
**Files**: background.js, rules/bing.json
**CWE**: CWE-693 (Protection Mechanism Failure)

**Description**: The extension uses declarativeNetRequest to strip Content-Security-Policy and X-Frame-Options headers from Bing and Copilot domains to allow embedding in the sidepanel.

**Evidence**:
```javascript
// background.js:14-47
chrome.declarativeNetRequest.updateDynamicRules({
  removeRuleIds: [1],
  addRules: [
    {
      id: 1,
      priority: 1,
      action: {
        type: "modifyHeaders",
        requestHeaders: [
          {
            header: "user-agent",
            operation: "set",
            value: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 Edg/110.0.1587.41",
          },
          {
            header: "sec-ch-ua",
            operation: "set",
            value: '"Microsoft Edge";v="111", "Not(A:Brand";v="8", "Chromium";v="111"',
          },
        ],
        responseHeaders: [
          { header: "x-frame-options", operation: "remove" },
          { header: "content-security-policy", operation: "remove" },
        ],
      },
      condition: {
        urlFilter: "bing",
        isUrlFilterCaseSensitive: false,
        resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest", "websocket"],
      },
    },
  ],
});

// rules/bing.json
{
  "action": {
    "type": "modifyHeaders",
    "responseHeaders": [
      {
        "header": "content-security-policy",
        "operation": "remove"
      }
    ]
  },
  "condition": {
    "requestDomains": ["copilot.microsoft.com"],
    "resourceTypes": ["sub_frame"]
  }
}
```

**Verdict**: While necessary for the extension's functionality (Microsoft's services explicitly prevent framing), this creates a security concern. By removing CSP and X-Frame-Options, the extension disables protection against clickjacking and content injection attacks. If Microsoft's services were compromised or if a network attacker could intercept these requests, users would have reduced security protections. Additionally, the user-agent spoofing could be considered deceptive, though it's necessary for the service to function.

## False Positives Analysis

The following patterns were identified but are NOT vulnerabilities:

1. **User-Agent Spoofing**: The extension spoofs an Edge browser user-agent to access Microsoft Copilot. While this could be considered protocol deception, it's necessary for the extension's stated purpose since Microsoft only officially supports Copilot in Edge. This is disclosed in the extension description.

2. **Broad Host Permissions (<all_urls>)**: Required for the content script to extract page text from any website the user wants to discuss with Copilot. This is expected behavior for an AI assistant extension.

3. **Page Content Extraction**: The content script reads `document.body.innerText` and PDF text when requested. This is the core feature of the extension - allowing users to discuss page content with Copilot.

4. **Redirecting to External Site on Install**: Opens `https://bing-sidebar.com/setup` on installation, likely for setup instructions. Standard practice for onboarding.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| copilot.microsoft.com | Microsoft Copilot AI service (embedded in sidepanel) | Active tab title, URL, and page text content when user requests analysis | LOW - Disclosed functionality, user-initiated |
| *.bing.com | Bing search integration for Copilot | Browser headers, search queries | LOW - Part of Copilot service |
| bing-sidebar.com/setup | Setup/onboarding page | None (redirect only) | LOW - Informational only |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

The extension provides legitimate functionality (porting Edge's Copilot to Chrome) but introduces two security concerns:

1. The postMessage handler lacks origin validation, creating an attack surface where malicious code could potentially trigger page data extraction if it gained access to the sidepanel context.

2. The aggressive stripping of security headers (CSP, X-Frame-Options) reduces defense-in-depth protections. While necessary for the extension to function, this creates risk if Microsoft's services were compromised or if network-level attacks occurred.

The extension is not malicious and serves its stated purpose, but the security implementation could be improved by:
- Adding strict origin validation to postMessage handlers
- Documenting the security implications of header stripping
- Potentially limiting the scope of header modifications to only what's strictly necessary

For users who want Copilot functionality in Chrome and trust Microsoft's services, this extension provides value. However, security-conscious users should be aware that it weakens some browser security protections to enable cross-browser functionality that Microsoft doesn't officially support.
