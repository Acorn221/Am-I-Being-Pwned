# Vulnerability Report: Real-Debrid extension

## Metadata
- **Extension ID**: oefkkgfcahbeccgckjgbnfclcmnjgidg
- **Extension Name**: Real-Debrid extension
- **Version**: 1.6.2
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

The Real-Debrid extension is a legitimate browser extension that integrates with the Real-Debrid premium download service. It scans web pages for downloadable links from supported file hosting services, sends them to the Real-Debrid API for unrestricted downloading, and provides a popup interface for managing detected links.

After thorough analysis of the extension's code, static analysis results, and functionality, no security or privacy concerns were identified. The extension operates transparently within its stated purpose, uses proper OAuth 2.0 authentication, and only communicates with legitimate Real-Debrid domains. All permissions are justified for its intended functionality.

## Vulnerability Details

No vulnerabilities identified.

## False Positives Analysis

### `<all_urls>` Permission
The extension requests `<all_urls>` host permission, which may appear overly broad. However, this is justified because:
- The extension's core functionality is to scan any web page for downloadable links from supported file hosters
- Users can enable/disable automatic link discovery via the "auto debrid" setting
- When automatic discovery is disabled, the extension only scans the current page URL, not the full page content
- The extension does not exfiltrate browsing data - it only extracts download links matching Real-Debrid's supported hoster regex patterns

### Content Script Injection
The extension injects `parser.js` into all web pages when tabs are activated or updated. This is legitimate behavior because:
- The content script (`parser.js`) only extracts page HTML to search for download links
- It respects the user's "autoDebrid" setting - only scanning full page content when enabled
- All extracted links are sent to the background worker for validation against Real-Debrid's regex patterns
- No sensitive data (passwords, form inputs, cookies) is accessed by the content script

### Redirect Chain Tracking
The extension uses `webRequest.onBeforeRedirect` to track redirect chains. This is a legitimate feature because:
- Many file hosters use URL shorteners that redirect to the actual download page
- The redirect tracking captures the final URL to detect supported links
- Redirect chains are only stored per-tab and cleared when the tab navigates to a new page
- No redirect data is sent to external servers beyond the Real-Debrid API for link validation

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| app.real-debrid.com/oauth/v2/device/code | OAuth device authorization | client_id (hardcoded default) | NONE - Standard OAuth flow |
| app.real-debrid.com/oauth/v2/device/credentials | Poll for OAuth credentials | client_id, device_code | NONE - Standard OAuth flow |
| app.real-debrid.com/oauth/v2/token | Token refresh/exchange | client_id, client_secret, refresh_token | NONE - Standard OAuth flow, credentials stored locally |
| app.real-debrid.com/rest/1.0/user | Fetch user account info | Authorization: Bearer token | NONE - Legitimate API call |
| app.real-debrid.com/rest/1.0/hosts/regex | Fetch supported hoster patterns | Authorization: Bearer token | NONE - Legitimate API call |
| app.real-debrid.com/rest/1.0/hosts/regexFolder | Fetch folder link patterns | Authorization: Bearer token | NONE - Legitimate API call |
| app.real-debrid.com/rest/1.0/unrestrict/check | Check if link is supported | Authorization: Bearer token, link URL | NONE - Expected functionality |
| app.real-debrid.com/rest/1.0/unrestrict/link | Unrestrict download link | Authorization: Bearer token, link URL | NONE - Core functionality |
| app.real-debrid.com/rest/1.0/unrestrict/folder | Extract folder links | Authorization: Bearer token, link URL | NONE - Core functionality |
| real-debrid.com/authorize | OAuth authorization page | device_id, client_id | NONE - User-initiated OAuth flow |
| real-debrid.com/streaming-{id} | Open streaming page | None (tab navigation) | NONE - User-initiated action |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

This extension is a legitimate tool for Real-Debrid premium service users. It performs exactly as described - scanning web pages for downloadable links and managing them through the Real-Debrid API. The extension:

1. **Uses proper authentication**: Implements OAuth 2.0 device flow for user authorization
2. **Respects user privacy**: Does not collect or transmit browsing history, personal data, or any information beyond download links
3. **Transparent operation**: All network requests go to legitimate Real-Debrid domains
4. **Appropriate permissions**: All requested permissions are justified for the stated functionality
5. **User control**: Provides settings to control automatic link discovery behavior
6. **No malicious patterns**: No obfuscation, no eval/Function calls, no suspicious code execution
7. **Clean static analysis**: ext-analyzer found no suspicious data flows

The extension poses no security or privacy risk to users who are legitimate Real-Debrid customers.
