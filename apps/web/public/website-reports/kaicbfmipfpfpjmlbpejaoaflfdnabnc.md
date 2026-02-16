# Vulnerability Report: Chrometana - Redirect Bing Somewhere Better

## Metadata
- **Extension ID**: kaicbfmipfpfpjmlbpejaoaflfdnabnc
- **Extension Name**: Chrometana - Redirect Bing Somewhere Better
- **Version**: 2.0.1
- **Users**: ~70,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Chrometana is a legitimate utility extension that redirects Bing searches (including those initiated by Windows Cortana) to alternative search engines chosen by the user. The extension intercepts Bing search requests via the webRequest API and redirects them to Google, DuckDuckGo, Yahoo, or a custom search engine URL. The code is clean, well-structured, and contains no malicious functionality, obfuscation, or privacy violations. All operations are local to the browser with no data exfiltration or external communication beyond the user's chosen search engine redirects.

The extension's functionality is exactly as advertised: it provides a straightforward search redirection service for Windows users who want to use search engines other than Bing when using Cortana or Windows search features.

## Vulnerability Details

No security or privacy vulnerabilities were identified in this extension.

## False Positives Analysis

**webRequest/webRequestBlocking Permissions**: While these are powerful permissions that could theoretically be abused for network interception, in this case they are used solely for their intended purpose - redirecting Bing search URLs to alternative search engines. The interception is limited to `*://*.bing.com/search*` URLs only, and the redirection logic is straightforward and non-malicious.

**Custom Search Engine Feature**: Users can specify a custom search engine URL. While this could theoretically be used to redirect searches to a malicious domain, this is a user-controlled feature that enhances functionality. The extension validates that custom URLs start with "http" and the user must explicitly enable this feature.

**Options Page Auto-Open on Install**: The extension opens its options page upon installation (`chrome.tabs.create` in onInstalled listener). This is standard practice for configuration-requiring extensions and not suspicious.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| google.com | Search redirect target (optional) | User's search query from Bing | None - user-initiated |
| duckduckgo.com | Search redirect target (optional) | User's search query from Bing | None - user-initiated |
| yahoo.com | Search redirect target (optional) | User's search query from Bing | None - user-initiated |
| Custom URL | User-configured redirect (optional) | User's search query from Bing | None - user-controlled |

All endpoints are search engines that receive only the search query extracted from the Bing URL. No additional user data, tracking identifiers, or browser information is transmitted. The data flow is: Bing URL → parse query → redirect to chosen search engine.

## Code Analysis

### bootstrap.js (Background Script)
- Implements webRequest listener on `*://*.bing.com/search*` URLs
- Extracts search query from Bing URL using regex: `/\?q\=([0-9a-zA-Z-._~:\/?#[\]@!$'()*+,;=%]*)($|(\&))/`
- Checks source parameter (`form=WNSGPH` or `form=WNSBOX` for Cortana searches)
- Redirects to user-selected search engine with query preserved
- Supports "open website" feature for direct navigation (e.g., "go to example.com")
- All settings stored in chrome.storage.sync (user preferences only)
- Clean, readable code with no obfuscation

### redirect.js (Content Script)
- Fallback mechanism that runs on Bing search pages
- Sends message to background script to get redirect URL
- Simple 12-line script with no data collection

### options.js (Options Page)
- UI logic for managing user preferences
- Validates custom search URLs (must start with "http")
- All data storage is local via chrome.storage.sync
- No external communications

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: Chrometana is a well-designed, legitimate utility extension with a clear and useful purpose. The code is transparent, contains no malicious patterns, performs no unauthorized data collection, and operates exactly as described. The extension only intercepts Bing searches to redirect them to user-selected alternatives, which is the core advertised functionality. All user preferences are stored locally, and there are no network communications except for the intended search engine redirects initiated by the user. The ~70,000 user base and clean implementation indicate this is a trustworthy tool for Windows users who want to use alternative search engines with Cortana.
