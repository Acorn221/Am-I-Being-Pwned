# Vulnerability Report: Omnibug

## Metadata
- **Extension ID**: bknpehncffejahipecakbfkomebjmokl
- **Extension Name**: Omnibug
- **Version**: 2.1.0
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Omnibug is a legitimate browser extension designed for developers and marketers to debug and analyze outgoing requests from digital marketing tools (Google Analytics, Adobe Analytics, Facebook Pixel, etc.). The extension uses DevTools integration to intercept and decode marketing tag requests for debugging purposes. After thorough analysis of the codebase and runtime behavior, no security or privacy concerns were identified. The extension only processes network requests when DevTools is explicitly opened by the user, and all data remains local to the browser - nothing is exfiltrated to external servers.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

### webRequest API with `<all_urls>`
The extension requests `webRequest` permission with `<all_urls>` host permissions. This appears highly privileged but is legitimate for the extension's stated purpose:
- **Purpose**: To intercept and analyze marketing tool requests (Google Analytics, Adobe Analytics, Facebook Pixel, etc.)
- **Gating mechanism**: The `validProviderRequest()` function ensures requests are only processed when:
  1. DevTools is open for that specific tab (via `tabHasOmnibugOpen()`)
  2. The URL matches known marketing provider patterns (via `providerPattern.test()`)
  3. The request is not an OPTIONS request
- **Data handling**: Captured request data is sent to the DevTools panel via `postMessage()` - it never leaves the browser
- **Verdict**: NOT data exfiltration - this is the core functionality of a developer debugging tool

### Network Request Interception
The service worker registers listeners for:
- `chrome.webRequest.onBeforeRequest` - captures request details and POST data
- `chrome.webRequest.onHeadersReceived` - detects HTTP 4xx/5xx errors
- `chrome.webRequest.onErrorOccurred` - detects blocked/cancelled requests

All of these are gated by the `validProviderRequest()` check, which ensures the extension only processes requests when the developer has explicitly opened Omnibug in DevTools. The captured data is formatted and displayed in the DevTools panel for debugging purposes.

**Verdict**: Legitimate developer tool behavior - not surveillance or data collection.

### Provider Pattern Matching
The extension includes a large `providers.js` file (313KB deobfuscated) containing parsers for 60+ marketing platforms. This is necessary to decode proprietary parameter formats used by various marketing tools. The patterns are used to identify and parse relevant requests.

**Verdict**: Expected behavior for a marketing tag debugger.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| omnibug.io | Homepage/documentation link (manifest homepage_url) | None | None |

No other external endpoints are contacted by this extension. All network request data is processed locally and displayed in the DevTools panel.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
Omnibug is a well-designed developer tool that operates transparently and only when explicitly activated by the user opening DevTools. The extension's use of privileged permissions (webRequest, <all_urls>) is justified by its stated purpose and is properly gated behind user intent checks. No data exfiltration, credential theft, or malicious behavior was identified. The extension is verified on the Chrome Web Store with 200,000 users and has been actively maintained since 2011 (open source on GitHub: MisterPhilip/omnibug). This is a legitimate tool used by web developers and digital marketing professionals for debugging marketing tag implementations.

**Key security controls observed**:
1. Request processing only occurs when DevTools is open (`tabHasOmnibugOpen()`)
2. Only marketing tool requests matching known patterns are captured
3. All data remains local to the browser (sent via `postMessage` to DevTools panel)
4. No dynamic code execution (eval, Function, executeScript)
5. No external network requests from the extension itself
6. Open source codebase available for public audit
