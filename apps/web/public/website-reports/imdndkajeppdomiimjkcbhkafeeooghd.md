# Vulnerability Report: Browsing Protection by WithSecure

## Metadata
- **Extension ID**: imdndkajeppdomiimjkcbhkafeeooghd
- **Extension Name**: Browsing Protection by WithSecure
- **Version**: 5.0.74
- **Users**: ~2,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Browsing Protection by WithSecure is a legitimate enterprise security extension developed by WithSecure (formerly F-Secure Corporation) with 2 million users. The extension acts as a browser companion to WithSecure's desktop security products, providing real-time URL reputation checking, malicious website blocking, safe search enforcement, and shopping website safety ratings.

All data processing occurs through native messaging communication with the locally-installed WithSecure security application. The extension does not independently transmit data to external servers. URL checks and security verdicts are handled by the native host application, which communicates with WithSecure's Security Cloud. This architecture is appropriate for enterprise security software.

## Vulnerability Details

### No vulnerabilities identified

After comprehensive analysis of the extension's codebase, no security or privacy vulnerabilities were found. The extension operates as designed for its stated purpose as an enterprise security tool.

## False Positives Analysis

### Native Messaging Architecture
The extension uses native messaging to communicate with a local WithSecure security application (`app.withsecure_chrome_https`). This is the expected architecture for enterprise security software and not a security concern.

**Evidence**:
- Native host identifier: `app.withsecure_chrome_https`
- WebSocket fallback for ChromeOS: `ws://100.115.92.2:2804` (localhost-only, link-local address)
- All URL reputation checks are routed through the native host

**Verdict**: Legitimate enterprise security architecture.

### Broad Permissions
The extension requests `webRequest`, `webNavigation`, `tabs`, and `<all_urls>` host permissions. While these are powerful permissions, they are necessary and appropriate for a browsing protection extension that must:
- Monitor navigation to check URLs against threat databases
- Block access to malicious websites
- Inject security ratings into search engine results
- Enforce safe search settings

**Verdict**: Permissions are justified by the extension's stated security functionality.

### User Consent Flow
The extension requires explicit user consent before activation, displaying a detailed privacy notice that explains data collection:
> "The addresses of websites you visit are transferred to the WithSecure security products to check its rating and category."

If the user declines consent, the extension uninstalls itself via `chrome.management.uninstallSelf()`.

**Verdict**: Transparent data collection disclosure with proper consent mechanism.

### Message Passing Flows
The static analyzer flagged message data flows to `fetch` and `*.src`. Analysis confirms these are benign:
1. `fetch` is used only for HEAD requests to check if local resources exist (`checkResourceExists()`)
2. `*.src` assignments are for setting icon images in UI elements (search result ratings, shopping safety indicators)

**Verdict**: No data exfiltration; flagged flows are legitimate UI operations.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native messaging host (localhost) | URL reputation checking, settings synchronization, threat verdicts | URLs being visited, tab information, extension version, browser info | None - local IPC with installed security software |
| WebSocket `ws://100.115.92.2:2804` | ChromeOS-only fallback for native messaging | Same as native messaging | None - link-local address, localhost equivalent |

## Functionality Overview

### Core Features
1. **URL Reputation Checking**: Sends visited URLs to native host for safety verdict; blocks harmful/suspicious sites
2. **Search Result Ratings**: Injects safety icons next to search results on Google, Bing, Yahoo, DuckDuckGo
3. **Safe Search Enforcement**: Adds strict mode parameters to search engine queries when enabled
4. **Shopping Website Safety**: Displays trustworthiness ratings for e-commerce sites
5. **Banking Protection Mode**: Restricts browsing during banking sessions to prevent malware interference
6. **Content Filtering**: Supports parental controls and category-based blocking (configurable via native host)
7. **Ad Blocking**: Optional ad blocking based on configurable domain lists

### Data Flow
1. User navigates to URL
2. Extension captures navigation event via `webNavigation.onCompleted` / `webRequest.onBeforeRequest`
3. Extension sends URL to native host via `NativeHost.postMessage()`
4. Native host queries WithSecure Security Cloud (external to extension)
5. Native host returns verdict (safe/harmful/suspicious/blocked)
6. Extension blocks page or allows navigation based on verdict
7. For blocked pages, displays customized block page with reasoning

### Settings Management
All settings (safe search, ad blocking, trusted shopping, search results) are controlled by the native host and synchronized to the extension. Users cannot modify settings within the extension; configuration is managed through the WithSecure desktop application.

## Code Quality Observations

- Well-structured code with clear separation of concerns
- Extensive copyright notices and licensing information from F-Secure/WithSecure
- Proper error handling and fallback mechanisms (e.g., WebSocket for ChromeOS where native messaging may not be available)
- Multi-browser compatibility (Chrome, Edge, Firefox, Safari)
- Internationalization support (39 locales)
- Professional development practices evident throughout

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: Browsing Protection by WithSecure is a legitimate enterprise security extension that operates as intended. It serves as a browser companion to WithSecure's desktop security products, providing real-time protection against malicious websites. The extension does not exhibit any malicious behavior, undisclosed data collection, or security vulnerabilities. All permissions are justified and necessary for the stated functionality. The architecture appropriately delegates security intelligence and data processing to the locally-installed native application, which is the expected pattern for enterprise security software.

The extension is published by a reputable security company (WithSecure, formerly F-Secure), has 2 million users, and operates transparently with proper consent mechanisms. It is safe for use in environments where WithSecure security products are deployed.
