# Vulnerability Report: MozBar

## Metadata
- **Extension ID**: eakacpaijcpapndcfffdgphdiccmpknp
- **Extension Name**: MozBar
- **Version**: 4.1.1
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

MozBar is a legitimate SEO toolbar extension developed by Moz (formerly SEOMoz), a well-established SEO software company. The extension provides domain authority metrics, page analysis features, and SERP (Search Engine Results Page) overlay data to help users analyze website SEO performance.

After thorough analysis of the deobfuscated source code and webpack source maps, this extension demonstrates standard practices for a legitimate SEO tool. All network communications are directed to official Moz API endpoints, the extension requires user authentication via Moz credentials, and data collection is consistent with the stated functionality. No evidence of hidden data exfiltration, malicious code injection, or unauthorized tracking was found.

## Vulnerability Details

No vulnerabilities were identified. This section documents the review findings.

## False Positives Analysis

### Webpack Bundling Flagged as Obfuscation
The ext-analyzer tool flagged the extension as "obfuscated" due to webpack bundling. However, analysis of the source maps reveals this is standard React application bundling:
- Complete source maps available for all JavaScript files
- Source maps contain readable TypeScript source code
- Uses standard dependencies (axios, React, jQuery, uuid)
- Webpack configuration is standard for modern web applications

This is NOT malicious obfuscation - it's production build optimization.

### Broad Permissions Are Functionality-Required
The extension requests:
- `<all_urls>` host permissions: Required to inject SEO metrics toolbar on any webpage the user visits
- `cookies`: Used to retrieve Moz authentication token from moz.com cookies
- `webRequest`: Used to monitor page load timing and HTTP status codes for SEO analysis
- `tabs`: Required to update toolbar data when users switch tabs
- `storage`: Stores user configuration and cached API responses

All permissions align with the extension's stated SEO analysis functionality.

### Cookie Access Is Legitimate Authentication
The background script reads cookies from `moz.com` specifically to retrieve the user's authentication token:
```typescript
cookiesApi.get({ "url": meta.cookie_web, "name": meta.cookie_name }, function (cookie) {
  if (cookie?.value) {
    const token = cookie?.value
    const data = { session: token }
    ls.storage().local.set(data)
  }
})
```
This is a standard authentication pattern for browser extensions that integrate with web services requiring login.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.moz.com/jsonrpc | Production API for SEO metrics | URLs being analyzed, user auth token | LOW - Legitimate service API |
| development.api.moz.com | Development API endpoint | Same as production | LOW - Development environment |
| analytics.moz.com | Link explorer and page grader features | Target URLs and keywords | LOW - Analytics features |
| moz.com | Authentication, pricing, help pages | User authentication data | LOW - Official Moz website |

All endpoints are owned by Moz and serve documented API features.

## Code Review Findings

### Background Script (background/index.ts)
- Monitors page load timing using Performance API
- Tracks HTTP status codes and redirects for SEO analysis
- Manages user authentication token from Moz cookies
- Handles message passing between content scripts and popup
- Caches SERP analysis results to reduce API calls

### Content Script (content/index.tsx)
- Injects SEO toolbar into web pages
- Displays domain authority metrics on page
- Overlays metrics on search engine results pages
- Implements keyword highlighting feature
- Calculates page load performance metrics

### API Service (api/api_v2.ts)
- Communicates with `api.moz.com/jsonrpc` API
- Validates URLs using standard regex before analysis
- Caches API responses with configurable lifetime
- Implements error handling for API failures
- All API calls require user authentication token

### Data Collection
The extension collects:
1. URLs of pages the user visits (sent to Moz API for analysis)
2. Page load timing metrics (stored locally, sent to API)
3. User's Moz authentication token (from cookies)
4. SERP keyword queries (when user requests keyword analysis)

All data collection is necessary for the extension's SEO analysis functionality and is sent only to Moz's official API endpoints.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
MozBar is a legitimate, professionally-developed SEO toolbar by an established company in the SEO industry. The extension's behavior fully aligns with its stated purpose of providing SEO metrics and page analysis. All network communications go to official Moz API endpoints, user data is handled transparently for authentication, and there is no evidence of hidden tracking, data exfiltration to third parties, or malicious functionality. The broad permissions requested are all justified by the extension's core features. The webpack bundling flagged as "obfuscation" is standard production build optimization, with full source maps available for audit.
