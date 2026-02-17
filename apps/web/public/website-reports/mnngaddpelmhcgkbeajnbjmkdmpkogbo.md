# Vulnerability Report: Scan Translator

## Metadata
- **Extension ID**: mnngaddpelmhcgkbeajnbjmkdmpkogbo
- **Extension Name**: Scan Translator
- **Version**: 2.0.25
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Scan Translator is a browser extension designed to translate manga, scans, and images using AI-powered translation. The extension captures screenshots or images from web pages and sends them to a third-party API (dolphin-app-ys43m.ondigitalocean.app) for translation processing. While the extension's core functionality is legitimate and disclosed (translating images), it does collect and transmit potentially sensitive data including screenshot images, website URLs, and user authentication tokens to an external server. The extension uses postMessage for internal communication without explicit origin validation in the initial event listener setup, though this is partially mitigated by the webext-bridge library's MessageChannel-based architecture.

The extension operates on a freemium model with credit limits and authentication requirements. Users are required to sign up for an account to use the translation features beyond the free tier.

## Vulnerability Details

### 1. MEDIUM: Screenshot and Browsing Context Exfiltration

**Severity**: MEDIUM
**Files**: dist/background/index.mjs (lines 2284-2320)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension sends base64-encoded screenshots along with website URLs to a third-party API endpoint at `https://dolphin-app-ys43m.ondigitalocean.app/api`. While this is the core functionality of a translation extension, users may not fully understand that their screenshots and browsing context are being transmitted to an external server.

**Evidence**:
```javascript
// Background script - lines 2281-2298
const Te = "https://dolphin-app-ys43m.ondigitalocean.app/api";

async function Ke(e, r, t) {
  try {
    const n = new Headers({
      "Content-Type": "application/json"
    });
    t && n.append("Authorization", `Bearer ${t}`);
    const i = await fetch(`${Te}/screenshot`, {
      method: "POST",
      headers: n,
      body: JSON.stringify({
        screenshotBase64: e.dataUrl,
        targetLang: r,
        className: e.className
      })
    });
    return i.ok || void 0, await i.json()
  } catch {}
}

async function Xe(e, r, t, n, i, l) {
  try {
    const o = new Headers({
      "Content-Type": "application/json"
    });
    l && o.append("Authorization", `Bearer ${l}`);
    const g = await fetch(`${Te}/translate`, {
      method: "POST",
      headers: o,
      body: JSON.stringify({
        websiteUrl: e,
        imageBase64: r,
        targetLang: i,
        imageUrl: t
      }),
      signal: n
    });
```

**Verdict**: This is expected behavior for a translation extension, but the data transmission includes:
- Screenshot images (base64-encoded)
- Website URLs (browsing context)
- User authentication tokens (Bearer tokens)
- Image URLs from visited pages

The extension's description states it translates "raw manga, scans or images," which implies this functionality. However, the extension has access to `<all_urls>` and could potentially capture screenshots from any website, including those containing sensitive information (banking, healthcare, personal communications, etc.). While the user initiates the translation action, they may not realize the full extent of data being transmitted.

### 2. MEDIUM: postMessage Event Listener Without Origin Validation

**Severity**: MEDIUM
**Files**: dist/contentScripts/index.global.js (line 4077)
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The content script sets up a window.addEventListener("message") handler without immediately validating the origin of incoming messages. While the webext-bridge library implements a MessageChannel-based architecture that provides some isolation, the initial postMessage listener accepts messages from any origin ("*").

**Evidence**:
```javascript
// Content script - lines 4066-4077
const r = () => {
  const o = new MessageChannel;
  o.port1.onmessage = i => {
    if (i.data === "port-accepted") return window.removeEventListener("message", n), s(o.port1);
    t == null || t(i)
  }, window.postMessage({
    cmd: "webext-port-offer",
    scope: A,
    context: e
  }, "*", [o.port2])  // Posts message with "*" origin
};
window.addEventListener("message", n), e === "window" ? setTimeout(r, 0) : r()
```

The listener function `n` is defined earlier:
```javascript
// Line 4064
if (i === "webext-port-offer" && l === A && g !== e) return window.removeEventListener("message", n), u[0].onmessage = t, u[0].postMessage("port-accepted"), s(u[0])
```

**Verdict**: This pattern is part of the webext-bridge library's architecture for establishing MessageChannel-based communication between different extension contexts. The library validates messages based on command type (`webext-port-offer`), scope, and context matching before accepting them. Once the MessageChannel is established, subsequent communication happens through the dedicated port rather than global postMessage.

However, this still represents a potential attack surface where:
1. A malicious page could potentially interfere with the port handshake process
2. The initial message handler accepts messages from any origin before filtering
3. There's no explicit `event.origin` check against an allowlist

The risk is partially mitigated by:
- The library's command-based protocol (`webext-port-offer`)
- Context and scope matching requirements
- MessageChannel isolation after handshake
- The listener is removed after the port is established

## False Positives Analysis

### ext-analyzer Obfuscation Flag
The static analyzer flagged this extension as "obfuscated," but the code appears to be standard webpack-bundled Vue.js application code. The minified variable names and bundler patterns are typical of modern JavaScript build processes, not intentional obfuscation for malicious purposes.

### Image Data Transmission
While the extension sends image data and URLs to an external server, this is the explicitly stated purpose of the extension ("translate raw manga, scans or images"). This is disclosed functionality, not covert data exfiltration.

### Authentication Tokens
The extension stores and transmits Bearer tokens for authentication. This is standard practice for authenticated API services and part of the legitimate freemium business model (free tier with credit limits, paid pro tier).

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| dolphin-app-ys43m.ondigitalocean.app/api/screenshot | Screenshot translation | screenshotBase64, targetLang, className, Bearer token | Medium - Screenshots may contain sensitive content from any website |
| dolphin-app-ys43m.ondigitalocean.app/api/translate | Image translation | websiteUrl, imageBase64, imageUrl, targetLang, Bearer token | Medium - Includes browsing context (URLs) and image content |
| scan-translator.com | Official website | N/A (referenced in error messages) | Low - Legitimate business website |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Scan Translator is a legitimate translation extension that performs its stated function of translating images and manga. However, it earns a MEDIUM risk rating for the following reasons:

1. **Broad Data Access**: The extension has `<all_urls>` permission and can capture screenshots from any website, including those with sensitive content (banking, healthcare, personal communications). While users initiate the translation action, they may not realize screenshots could be taken from sensitive pages.

2. **Third-Party Data Transmission**: All screenshot data, website URLs, and authentication tokens are sent to a third-party DigitalOcean-hosted API. Users have no visibility into:
   - How long this data is retained
   - Whether it's used for purposes beyond translation (e.g., ML training)
   - What security measures protect the data in transit and at rest
   - Whether the data is shared with other parties

3. **Browsing Context Exposure**: The extension transmits website URLs along with image content, providing the API server with information about which sites users visit and when they use the translation feature.

4. **postMessage Attack Surface**: While mitigated by the webext-bridge library's architecture, the initial postMessage handler without explicit origin validation represents a potential attack surface on malicious pages.

**Mitigating Factors**:
- The extension's functionality is disclosed (image translation)
- Users explicitly trigger translation actions (not automatic/background collection)
- The extension uses HTTPS for API communication
- Authentication is required (accountability)
- Error messages reference a legitimate business website
- No evidence of credential theft, session hijacking, or other high-severity attacks

**Recommendations for Users**:
- Be cautious about translating screenshots from sensitive websites (banking, healthcare, etc.)
- Understand that screenshot data and URLs are sent to a third-party server
- Review the extension's privacy policy before use
- Consider using the extension only on manga/comic websites as intended
- Disable "Auto Translate" features if concerned about automatic data transmission
