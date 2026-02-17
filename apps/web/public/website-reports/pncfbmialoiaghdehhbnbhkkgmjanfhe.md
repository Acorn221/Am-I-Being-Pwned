# Vulnerability Report: uBlacklist

## Metadata
- **Extension ID**: pncfbmialoiaghdehhbnbhkkgmjanfhe
- **Extension Name**: uBlacklist
- **Version**: 9.4.0
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

uBlacklist is a legitimate browser extension that allows users to block specific sites from appearing in Google and other search engine results. The extension provides cloud synchronization features via Google Drive, Dropbox, WebDAV, and browser sync storage. After thorough analysis of the codebase, including static analysis via ext-analyzer and manual code review, no security vulnerabilities or privacy concerns were identified.

The extension implements proper OAuth 2.0 flows for Google Drive and Dropbox integration, with appropriate token refresh mechanisms and secure storage practices. The data flows flagged by ext-analyzer are legitimate and expected for this type of extension - they relate to user configuration settings and subscription management features. The extension operates transparently within its stated functionality and does not engage in any undisclosed data collection, exfiltration, or malicious behavior.

## Vulnerability Details

No vulnerabilities identified.

## False Positives Analysis

### ext-analyzer EXFILTRATION Flag
The static analyzer flagged one exfiltration flow: `document.getElementById → fetch` in `scripts/options.js`. This is a false positive. The flow relates to the extension's subscription feature, where users can subscribe to publicly available blocklists hosted at URLs they specify. The fetch operations retrieve ruleset files from user-configured URLs for the purpose of updating blocklists - this is core functionality clearly described in the extension's purpose.

### Obfuscated Flag
The extension was flagged as "obfuscated" by ext-analyzer. This is webpack-bundled production code, not intentional obfuscation. The codebase includes standard libraries like dayjs, React, and Preact. The code is minified for performance but maintains readable structure with clear function names and logical organization.

### Cloud Sync OAuth Flows
The extension implements OAuth 2.0 authentication for Google Drive and Dropbox:

**Google Drive OAuth:**
- Client ID: `304167046827-45h8no7j0s38akv999nivvb7i17ckqeh.apps.googleusercontent.com`
- Scope: `https://www.googleapis.com/auth/drive.appdata` (app-specific hidden folder only)
- Uses standard authorization code flow with refresh tokens
- Alternative flow option for browsers with identity API restrictions

**Dropbox OAuth:**
- App Key: `kgkleqa3m2hxwqu`
- Creates files in `/Apps/uBlacklist/` folder only
- Uses offline access tokens for background sync

These OAuth implementations follow best practices: they request minimal scopes, use secure authorization code flow, properly handle token refresh, and store credentials in browser storage.

### Content Script Scope
The extension injects content scripts on Google search result pages across all international domains (google.com, google.co.uk, google.de, etc.) to provide the core blocking functionality. This is necessary for the extension to identify and hide/block search results matching user-defined rules. The content script only interacts with Google search result DOM elements and does not access or transmit page content.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://accounts.google.com/o/oauth2/v2/auth | Google OAuth authorization | OAuth parameters (client ID, scope, redirect URI) | None - standard OAuth |
| https://oauth2.googleapis.com/token | Google OAuth token exchange/refresh | Authorization codes, refresh tokens | None - standard OAuth |
| https://www.googleapis.com/drive/v3/* | Google Drive API | Blocklist sync data to appdata folder | None - user-initiated sync |
| https://www.dropbox.com/oauth2/authorize | Dropbox OAuth authorization | OAuth parameters | None - standard OAuth |
| https://api.dropboxapi.com/oauth2/token | Dropbox OAuth token exchange/refresh | Authorization codes, refresh tokens | None - standard OAuth |
| https://content.dropboxapi.com/2/files/* | Dropbox file operations | Blocklist sync data | None - user-initiated sync |

All external endpoints are legitimate OAuth providers and cloud storage APIs. Data transmitted is limited to:
1. OAuth credentials (standard protocol)
2. User-created blocklist rules (encrypted in transit via HTTPS)
3. Extension settings and configuration

No user browsing data, search queries, or personally identifiable information is transmitted to any external server.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

uBlacklist is a well-designed, legitimate browser extension with no security or privacy concerns. The extension:

1. **Transparent functionality**: All behaviors align with its stated purpose of blocking search results
2. **Proper OAuth implementation**: Cloud sync features use standard, secure authentication flows with minimal scope requests
3. **No data exfiltration**: Does not collect, store, or transmit user browsing data, search queries, or personal information
4. **Appropriate permissions**: All requested permissions are necessary for core functionality (activeTab for content scripts, identity for OAuth, storage for user preferences, scripting for result manipulation)
5. **Open source**: The extension is open source (referenced GitHub repository: https://github.com/ublacklist/builtin) which allows community review
6. **User control**: All cloud sync features are opt-in, and users maintain full control over their blocklist data

The extension follows browser extension best practices, implements MV3 properly, and provides a valuable privacy-enhancing service by allowing users to curate their search results without introducing new privacy or security risks.
