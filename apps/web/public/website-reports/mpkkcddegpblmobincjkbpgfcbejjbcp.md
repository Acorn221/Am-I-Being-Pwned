# Vulnerability Report: FACEIT FORECAST

## Metadata
- **Extension ID**: mpkkcddegpblmobincjkbpgfcbejjbcp
- **Extension Name**: FACEIT FORECAST
- **Version**: 1.7.8
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

FACEIT FORECAST is a browser extension designed to provide detailed statistics and match forecasts for players on the FACEIT competitive gaming platform. The extension operates exclusively on faceit.com and uses legitimate OAuth-style authentication with the extension's own backend services.

After thorough analysis of the codebase, including static analysis of data flows and manual code review, this extension demonstrates no malicious behavior or security vulnerabilities. All network requests are appropriately scoped to the extension's legitimate functionality of fetching gaming statistics, configuration data, and user authentication.

## Vulnerability Details

No vulnerabilities were identified during this analysis.

## False Positives Analysis

### Static Analyzer Exfiltration Flows
The ext-analyzer tool flagged 4 "exfiltration" flows involving DOM queries (document.getElementById, document.querySelectorAll) reaching fetch() calls to external domains. These are false positives for the following reasons:

1. **GitHub Configuration Fetching** (`raw.githubusercontent.com`):
   - Lines 103-104 in forecast.js: Fetches API key from the extension's public GitHub repository
   - This is configuration data retrieval, not data exfiltration
   - No sensitive user data is sent in these requests

2. **Extension API Calls** (`api.fforecast.net`):
   - Lines 40, 221 in popup.js and forecast.js: Registration and online count endpoints
   - These send device IDs (randomly generated identifiers) for extension analytics
   - No browsing data, credentials, or PII is transmitted

3. **DOM Query Sources**:
   - The flagged DOM queries (getElementById, querySelectorAll) are reading FACEIT webpage elements to extract match/player data
   - This data is specific to FACEIT matches and is NOT sensitive browsing history
   - Data flow: FACEIT DOM → Extension → fforecast.net API (for match statistics processing)
   - This is the core, legitimate functionality of the extension

### Obfuscation Flag
The static analyzer flagged the code as "obfuscated." This appears to be a false positive:
- The code uses webpack bundling with variable name minification (common in production builds)
- Variable names like `e`, `t`, `n`, `s` are typical webpack output, not deliberate obfuscation
- Code structure and logic are clear and readable after deobfuscation
- No string encoding, control flow flattening, or other obfuscation techniques detected

### Cookie Usage
The extension sets cookies on `.faceit.com` domain (lines 196-200 in forecast.js):
- Used for caching API keys and session data within the FACEIT domain
- Scoped to `.faceit.com` only (not cross-domain tracking)
- Standard practice for web-integrated extensions

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| auth.fforecast.net | OAuth-style authentication | Device ID, OAuth state parameter | None - standard auth flow |
| api.fforecast.net | Extension analytics, online user count | Device ID (random UUID), extension version | None - legitimate telemetry |
| cdn.fforecast.net | Configuration data (maps config) | None (GET request) | None - static config retrieval |
| raw.githubusercontent.com | API key and patch notes | None (GET request) | None - public repository content |

All endpoints are owned by the extension developer (TerraMiner/Faceit-Forecast) and serve legitimate purposes for the extension's functionality.

## Permissions Analysis

The extension requests minimal permissions:
- **storage**: Used for caching player statistics, user preferences, and authentication tokens
- **Content script on faceit.com**: Appropriate scope for a FACEIT-specific extension
- No dangerous permissions requested (tabs, webRequest, cookies API, etc.)

## Authentication Flow Review

The extension implements a secure OAuth-like flow:
1. Generates random state parameter (line 355 in popup.js)
2. Opens authentication tab to auth.fforecast.net
3. Backend worker polls verification endpoint (line 56 in worker.js)
4. Stores authentication token in chrome.storage.sync
5. Token expires after 7 days (line 69 in worker.js: 6048e5 ms = 7 days)

No credentials are handled directly by the extension. All authentication is delegated to the backend service.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This extension exhibits no security vulnerabilities or privacy concerns. All flagged issues from static analysis are false positives resulting from legitimate functionality. The extension:
- Operates only on its target domain (faceit.com)
- Uses minimal permissions appropriate for its stated purpose
- Implements secure authentication patterns
- Sends no sensitive user data to third parties
- Has transparent, non-obfuscated code
- Serves the legitimate purpose described in its metadata

The extension is a well-built utility tool for FACEIT gamers and poses no threat to user privacy or security.
