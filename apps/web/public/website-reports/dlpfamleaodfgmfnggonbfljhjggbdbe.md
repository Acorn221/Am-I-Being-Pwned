# Vulnerability Report: K7 Webprotection

## Metadata
- **Extension ID**: dlpfamleaodfgmfnggonbfljhjggbdbe
- **Extension Name**: K7 Webprotection
- **Version**: 5.4
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

K7 Webprotection is a legitimate browser extension developed by K7Computing, a reputable antivirus software company. The extension provides safe browsing indicators on search engine results (Google, Bing, Yahoo) by annotating links with safety ratings. It communicates exclusively with locally-installed K7 antivirus software via the native messaging API (localhost:7080), which then performs malware scanning and reputation checks. The extension does not exfiltrate data to external servers, does not use eval or dynamic code execution, and follows security best practices. No security or privacy concerns were identified.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

Several patterns might appear suspicious on initial review but are legitimate for this extension's intended purpose:

1. **Broad Host Permissions (`http://*/*`, `https://*/*`)**: Required to inject content scripts on search engine results pages (Google, Bing, Yahoo) to annotate links with safety indicators.

2. **Native Messaging**: The extension uses `chrome.runtime.sendNativeMessage` to communicate with the K7 antivirus software installed on the user's computer. This is a standard integration pattern for antivirus extensions and does not pose a security risk. All communication is local (127.0.0.1:7080) and does not leave the user's machine.

3. **Dynamic Script Injection**: The extension injects scripts (`k7srdom.js`, `k7constant.js`, `k7srdom_load.js`) into search result pages. This is necessary to add safety rating icons next to search results and is scoped to only Google, Bing, and Yahoo domains via regex patterns.

4. **Sizzle Selector Library**: The extension includes Sizzle.js (a CSS selector engine, originally from jQuery) to locate search result links across different search engine layouts. This is not obfuscation but a standard library for DOM manipulation.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://127.0.0.1:7080/k7sr/isenabled.htm | Check if site rating feature is enabled in K7 antivirus | Empty payload | None - localhost only |
| https://127.0.0.1:7080/k7sr/siterate/sitelookup.htm | Get safety ratings for URLs | JSON array of URLs from search results | None - localhost only |

**Note**: All endpoints are localhost (127.0.0.1) and communicate with the locally-installed K7 antivirus software via the native messaging host `com.k7computing.k7webprotection`. No external data transmission occurs.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This is a legitimate antivirus extension with no security or privacy concerns. The extension serves its stated purpose of protecting users from malicious websites by:
- Displaying safety indicators on search engine results
- Communicating only with locally-installed K7 antivirus software
- Not collecting or exfiltrating user data
- Not using dangerous APIs like eval or dynamic code execution
- Being developed by a reputable antivirus company (K7Computing)

The broad permissions are necessary and appropriate for the extension's functionality. The static analysis found no suspicious flows, and code review confirms no data exfiltration, credential harvesting, or malicious behavior. The extension follows MV3 best practices with a service worker background script and declarative scripting API.
