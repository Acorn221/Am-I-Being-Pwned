# Vulnerability Report: Indie Wiki Buddy

## Metadata
- **Extension Name**: Indie Wiki Buddy
- **Extension ID**: fkagelmloambgokoeokbpihmgpkbgbfm
- **Version**: 3.14.0
- **User Count**: ~100,000
- **Analysis Date**: 2026-02-07
- **Manifest Version**: 3

## Executive Summary

Indie Wiki Buddy is a legitimate, open-source browser extension designed to redirect users from corporate wiki farms (Fandom, Fextralife, Neoseeker) to independent community-run wikis. The extension also filters search engine results to promote independent wikis and integrates with BreezeWiki (an ad-free Fandom frontend).

**Overall Risk: CLEAN**

The extension shows no evidence of malicious behavior. All functionality is transparent and user-serving:
- Redirects users from corporate wikis to independent alternatives based on user preferences
- Filters search results on major search engines (Google, Bing, DuckDuckGo, etc.)
- Fetches BreezeWiki mirror list from legitimate API endpoint
- All network requests are to documented, legitimate services
- Code is well-structured, open-source, and matches the stated functionality

## Vulnerability Analysis

### 1. Remote Code Execution / Dynamic Code
**Severity**: NONE
**Status**: CLEAN

- **Finding**: No `eval()`, `Function()`, or dynamic script injection detected
- **Evidence**: Uses standard `atob()` only for legitimate base64 decoding of compressed storage data (gzip-compressed JSON settings)
- **Verdict**: CLEAN - No dynamic code execution vulnerabilities

### 2. Network Requests / External APIs
**Severity**: LOW (Informational)
**Status**: CLEAN

**API Endpoints Identified**:
- `https://bw.getindie.wiki/instances.json` - Fetches list of BreezeWiki mirror instances
- `https://getindie.wiki/changelog/?updated=true` - Opens changelog on update (user-configurable)

**Analysis**:
- All fetch requests are to legitimate, documented services
- BreezeWiki instance list is used to provide ad-free Fandom alternatives
- No sensitive data is transmitted
- No third-party analytics or tracking
- **Verdict**: CLEAN - All network requests are transparent and user-serving

### 3. Data Collection / Privacy
**Severity**: NONE
**Status**: CLEAN

**Storage Analysis**:
- Uses `chrome.storage.sync` and `chrome.storage.local` for user preferences
- Stores user settings (redirect preferences, wiki toggles, statistics)
- Statistics tracked: redirect count, alert count, search filter count, BreezeWiki usage count
- **No cookies, no localStorage for tracking, no external data transmission**
- All data is stored locally or in browser sync storage for user convenience
- **Verdict**: CLEAN - Privacy-respecting storage usage

### 4. Permissions Analysis
**Severity**: LOW (Justified)
**Status**: CLEAN

**Declared Permissions**:
- `storage` - Stores user preferences and settings
- `webRequest` - Monitors navigation to Fandom/Fextralife/Neoseeker to trigger redirects
- `notifications` - Shows notifications when redirects occur
- `scripting` - Injects content scripts for banners and search filtering

**Host Permissions**:
- Fandom.com, Fextralife.com, Neoseeker.com (target wikis)
- BreezeWiki mirrors (alternative frontend)
- Major search engines (Google, Bing, DuckDuckGo, Brave, Ecosia, etc.)

**Optional Host Permissions**:
- `https://*/*` - Requested only when user enables custom search engines

**Analysis**:
- All permissions are justified and necessary for stated functionality
- `webRequest` is used only to detect navigation to target sites (lines 44-75 in background.js)
- No permission abuse detected
- **Verdict**: CLEAN - Appropriate permission usage

### 5. Content Script Behavior
**Severity**: NONE
**Status**: CLEAN

**Content Scripts**:
1. **search-filtering.js** (945 lines): Filters search results, reorders indie wiki results
2. **content-banners.js** (315 lines): Displays redirect banners on Fandom/Fextralife/Neoseeker
3. **content-breezewiki.js** (16 lines): Hides promotional banners on BreezeWiki, appends query params
4. **common-functions.js** (421 lines): Shared utilities for URL matching and redirects

**Analysis**:
- DOM manipulation is limited to inserting banners and modifying search results
- No form hijacking, no keylogging, no credential harvesting
- No clipboard access, no screenshot capture
- MutationObserver usage is legitimate (watches for dynamically loaded search results)
- **Verdict**: CLEAN - All DOM manipulation serves stated functionality

### 6. Background Script Behavior
**Severity**: NONE
**Status**: CLEAN

**background.js Analysis** (264 lines):
- Listens for `webRequest` events on Fandom/Fextralife/Neoseeker URLs
- Performs automatic redirects based on user settings
- Fetches BreezeWiki instance list when needed
- Manages extension state (power on/off, icon updates)
- **No external analytics, no C2 communication, no data exfiltration**
- **Verdict**: CLEAN - Transparent background processing

### 7. Extension Enumeration / Fingerprinting
**Severity**: NONE
**Status**: CLEAN

- No extension enumeration detected
- No browser fingerprinting beyond standard extension APIs
- **Verdict**: CLEAN

### 8. Ad Injection / Monetization
**Severity**: NONE
**Status**: CLEAN

- No ad injection code detected
- No affiliate links or coupon injection
- No monetization mechanisms
- Open-source project with transparent goals
- **Verdict**: CLEAN

### 9. Obfuscation / Code Quality
**Severity**: NONE
**Status**: CLEAN

- Code is well-formatted and readable
- No obfuscation detected
- Proper JSDoc comments and type annotations
- Matches open-source repository (GitHub: KevinPayravi/indie-wiki-buddy)
- **Verdict**: CLEAN

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `atob()` | common-functions.js:7, content-search-filtering.js:21 | Legitimate base64 decoding for gzip-compressed JSON storage (compression reduces storage quota usage) |
| `String.fromCharCode()` | common-functions.js:75 | Part of gzip compression stream handling for storage optimization |
| `MutationObserver` | content-search-filtering.js:31, content-banners.js:293 | Watches for dynamically loaded search results and page readiness (standard practice for SPAs) |
| `fetch()` | background.js:178, content-banners.js:25 | Fetches BreezeWiki instance list from official API |

## API Endpoints

| Endpoint | Purpose | Data Sent | Data Received |
|----------|---------|-----------|---------------|
| https://bw.getindie.wiki/instances.json | Fetch BreezeWiki mirrors | None | JSON array of mirror instances with version requirements |
| https://getindie.wiki/changelog/?updated=true | Changelog page | None | HTML page (user-initiated) |

## Data Flow Summary

1. **User Navigation**: User visits Fandom/Fextralife/Neoseeker wiki
2. **Background Script**: `webRequest` listener detects navigation
3. **Wiki Matching**: Checks local JSON database for independent wiki alternative
4. **User Preference Check**: Reads `chrome.storage.sync` for wiki-specific settings
5. **Action**: Based on setting (redirect/alert/disabled):
   - **Redirect**: Immediately redirects to independent wiki
   - **Alert**: Injects banner with link to independent wiki
   - **Disabled**: No action
6. **Statistics**: Increments local counters (redirect count, etc.)

**Search Engine Flow**:
1. User performs search on supported engine
2. Content script loads local wiki database
3. Scans search results for Fandom/Fextralife/Neoseeker links
4. Matches against wiki database
5. Based on setting:
   - **Replace**: Shows indie wiki result above commercial result
   - **Hide**: Hides commercial result with toggle to reveal
   - **Disabled**: No filtering

**No external data transmission occurs during normal operation except for BreezeWiki instance list fetching.**

## Security Strengths

1. **Open Source**: Code is publicly auditable on GitHub
2. **Minimal Permissions**: Only requests necessary permissions
3. **No External Dependencies**: No third-party SDKs or analytics
4. **Local Processing**: All wiki matching done locally with bundled JSON database
5. **User Control**: All features can be disabled per-wiki or globally
6. **Privacy-Focused**: No user data collection or transmission
7. **CSP Compliant**: Manifest does not weaken Content Security Policy

## Recommendations

**For Users**:
- Extension is safe to use and privacy-respecting
- Review redirect settings in extension options if desired
- No security concerns identified

**For Developers**:
- Consider implementing Subresource Integrity (SRI) for future external resource loading
- Current implementation is excellent from security perspective

## Overall Risk Assessment

**Risk Level: CLEAN**

Indie Wiki Buddy is a legitimate, well-coded browser extension that performs exactly as advertised. It redirects users from corporate wiki farms to independent wikis based on a curated database, with full user control and transparency. No malicious behavior, privacy violations, or security vulnerabilities were identified.

The extension represents a positive use case for browser extensions: enhancing user experience and promoting decentralization without compromising security or privacy.

## Technical Details

- **Total Code Size**: ~2,352 lines of JavaScript
- **External Requests**: 1 legitimate API endpoint (BreezeWiki mirrors)
- **Data Storage**: Local preferences only (gzip-compressed JSON)
- **Wiki Database**: Bundled JSON files (22 language variants, 400KB+ total)
- **Supported Languages**: 22 (EN, DE, FR, ES, IT, JA, etc.)
- **Search Engines Supported**: 13+ (Google, Bing, DuckDuckGo, Brave, etc.)

## Conclusion

This extension is **CLEAN** and safe for users. It is a well-intentioned, privacy-respecting tool that enhances browsing by promoting independent wikis. No security risks identified.
