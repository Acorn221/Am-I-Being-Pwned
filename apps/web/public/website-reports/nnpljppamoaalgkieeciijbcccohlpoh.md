# Vulnerability Report: Link Redirect Trace

## Metadata
- **Extension ID**: nnpljppamoaalgkieeciijbcccohlpoh
- **Extension Name**: Link Redirect Trace
- **Version**: 1.1.5.27
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Link Redirect Trace is a legitimate SEO and web development tool designed to analyze redirect chains, HTTP headers, robots.txt files, and provide backlink analysis metrics. The extension monitors web navigation events to trace redirect paths (301, 302, meta refreshes, client-side redirects) and displays this information to the user.

After thorough analysis of the deobfuscated source code, **no security or privacy vulnerabilities were identified**. The extension's behavior is consistent with its stated purpose, and all network requests are legitimate and necessary for the advertised functionality.

## Vulnerability Details

No vulnerabilities identified.

## False Positives Analysis

### 1. Extensive Permissions (Not a Vulnerability)
**Permissions**: `<all_urls>`, `webRequest`, `webNavigation`, `tabs`, `activeTab`, `storage`

**Analysis**: These permissions are necessary and appropriate for a redirect tracer:
- `<all_urls>` + `webRequest` - Required to observe HTTP response headers and redirect status codes
- `webNavigation` - Required to track navigation events and identify client-side redirects
- `tabs` - Required to access tab information and update UI
- `storage` - Used to persist user settings (cookies display, robots.txt cache time, etc.)

**Verdict**: Legitimate use case. The extension cannot function without these permissions.

### 2. Content Script on All Sites (Not a Vulnerability)
**File**: `/js/cs-page.js`
**Matches**: `http://*/*`, `https://*/*`
**Run At**: `document_start`

**Analysis**: The content script has minimal functionality:
- Reads meta refresh redirects from the DOM
- Reads rel=canonical links
- Reads meta robots tags
- Detects user clicks to distinguish user-initiated vs automatic redirects
- Checks `performance.getEntriesByType('navigation')` for HTTP/2 detection

**Data Flow**: All collected data is sent to the background script via `chrome.runtime.sendMessage` for analysis and display. No data is sent externally.

**Verdict**: Necessary for detecting client-side redirect mechanisms that aren't visible through webRequest API alone.

### 3. External API Calls (Not a Vulnerability)
The extension makes requests to three external services:

#### a) LinkResearchTools API
- **Endpoint**: `https://plugin.linkresearchtools.com/v3.000/power_trust/api/api.php`
- **Purpose**: Provides SEO metrics (Power*Trust scores, backlink counts) for analyzed URLs
- **API Key**: Hardcoded (`6a8c1ddc779a8d760d7f4b209a89fc3361d`) - this is a shared plugin key, not user credentials
- **Data Sent**: URLs being analyzed by the user
- **User Initiated**: Yes - only when user clicks to view SEO metrics in popup

**Verdict**: Legitimate feature clearly described in extension description ("backlink power, and trust!"). User initiates these requests explicitly.

#### b) IP Geolocation API
- **Endpoint**: `http://ip-api.com/json/{ip}`
- **Purpose**: Provides geographic location data for IP addresses encountered in redirect chains
- **Data Sent**: IP addresses from server responses
- **Privacy**: Uses public, free IP geolocation service

**Verdict**: Standard functionality for network analysis tools. No sensitive data transmitted.

#### c) LinkResearchTools Marketing URLs
- **Domains**: `https://lrt.li/*`
- **Purpose**: Affiliate/tracking links for install/uninstall/welcome pages, help links, rating prompts
- **Examples**: `rtsuccesschrome`, `rtuninstallchrome`, `rthelpfirefox`
- **Privacy**: Standard marketing tracking, no user data collection beyond install events

**Verdict**: Standard extension lifecycle tracking. User is only redirected to these pages on install/uninstall events or when clicking help/rating links.

### 4. Analytics Implementation (Not Active)
**File**: `/js/ChromePlatformAnalytics.js`

**Analysis**: The code references Google's chrome-platform-analytics library, but inspection of `/js/App.js` shows it's stubbed out:

```javascript
var ChromePlatformAnalytics = {
  init: function(){},
  sendAppView: function(){},
  sendEvent: function(){},
  toggle: function(){}
};
```

**Verdict**: Analytics functionality is present in code but not actively implemented. No actual telemetry is sent.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| plugin.linkresearchtools.com | SEO metrics (Power*Trust, backlinks) | URLs user is analyzing | **NONE** - User-initiated, matches stated purpose |
| ip-api.com | IP geolocation lookup | IP addresses from HTTP responses | **NONE** - Public IPs only, no user data |
| lrt.li | Marketing/tracking links | Install/uninstall events | **NONE** - Standard lifecycle tracking |

## Code Quality Observations

**Positive Indicators**:
1. Clean, well-structured code with clear module separation
2. Proper use of Chrome Extension APIs (MV3 compliant)
3. Caching mechanisms to reduce redundant API calls
4. Error handling in network requests
5. Settings stored locally with `chrome.storage.local`
6. Uses standard libraries (jQuery 3.6.1, Mustache 2.2.1)

**No Malicious Patterns**:
- No credential harvesting
- No cookie exfiltration
- No history scraping
- No hidden network requests
- No eval() or dynamic code execution
- No postMessage handlers without origin checks
- No attempts to access other extensions

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
Link Redirect Trace is a legitimate, professionally developed SEO tool that performs exactly as advertised. The extension:

1. **Matches Stated Purpose**: All functionality directly relates to analyzing redirect chains, HTTP headers, and SEO metrics
2. **Appropriate Permissions**: Extensive permissions are justified and necessary for redirect tracing functionality
3. **Transparent Network Activity**: All external requests serve clear purposes aligned with the tool's description
4. **No Privacy Violations**: Does not collect, store, or transmit user browsing data beyond what's necessary for the immediate analysis task
5. **User Control**: SEO metric lookups are user-initiated, not automatic
6. **No Security Flaws**: No vulnerable code patterns, proper error handling, secure API usage

The extension is safe for use by SEO professionals, web developers, and site administrators who need to analyze redirect chains and HTTP headers.

**Recommendation**: Approve for continued use.
