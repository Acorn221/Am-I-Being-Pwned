# Vulnerability Report: HeadingsMap

## Metadata
- **Extension ID**: flbjommegcjonpdmenkdiocclhjacmbi
- **Extension Name**: HeadingsMap
- **Version**: 4.10.6
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

HeadingsMap is a legitimate accessibility tool designed to show, browse, and audit the headings structure of web pages for accessibility and SEO purposes. The extension analyzes HTML headings (H1-H6), landmarks, and HTML5 outline structure, displaying them in a collapsible tree view within a side panel.

Static analysis and manual code review reveal no security or privacy concerns. The extension operates entirely client-side, processes page content locally, stores only user preferences in chrome.storage.local, and does not exfiltrate any user data or browsing information to external servers. The XMLHttpRequest usage found in the code is limited to loading local extension resources (CSS files and HTML content) using chrome.runtime.getURL(), not external endpoints.

## Vulnerability Details

No vulnerabilities identified.

## False Positives Analysis

### XMLHttpRequest Usage (NOT A VULNERABILITY)
**Files**: content_scripts/headingsmap.js (lines 370, 381)

The static analyzer may flag XMLHttpRequest usage, but examination reveals these are benign:

1. **Function `Ee` (line 369-375)**: Loads local HTML files from the extension's `html/` directory for displaying help, release notes, and privacy policy dialogs within the extension UI.

2. **Function `tt` (line 377-387)**: Loads local CSS files from the extension's `css/` directory to style the headings panel.

Both functions use `chrome.runtime.getURL()` (stored in variable `me` at line 21) to construct paths to local extension resources, not external URLs. The only external URL in the entire codebase is a hardcoded LinkedIn profile link (https://www.linkedin.com/in/jorgerumoroso/) at line 4210, which is simply a contact link in the help menu - clicking it opens a new tab, no data is transmitted programmatically.

### innerHTML Usage (NOT A VULNERABILITY)
**File**: content_scripts/headingsmap.js (line 300)

The extension uses `innerHTML` in function `ze()` to parse email addresses into clickable mailto links for the help dialog. The input is a hardcoded string containing "headingsmap@gmail.com", not user-controlled content, so there's no XSS risk.

### Broad Permissions (LEGITIMATE USE)
**Permissions**: `<all_urls>`, `activeTab`, `storage`, `webNavigation`

These permissions are necessary and appropriately used for the extension's stated purpose:
- `<all_urls>` + `activeTab`: Required to inject the content script that analyzes heading structure on any web page
- `storage`: Stores user preferences (panel position, theme, display settings)
- `webNavigation`: Used to enumerate all frames on a page via `chrome.webNavigation.getAllFrames()` so the extension can analyze headings in iframes

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | N/A | N/A | None |

The extension makes no network requests to external servers. All operations are performed locally.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

HeadingsMap is a well-designed accessibility tool with no security or privacy issues. The extension:

1. **No data exfiltration**: Performs all analysis locally, sends no data to external servers
2. **Minimal data collection**: Only stores user preferences locally
3. **Appropriate permissions**: All requested permissions align with the extension's functionality
4. **No dynamic code execution**: No use of eval(), Function(), or unsafe practices
5. **Secure implementation**: Proper use of Chrome extension APIs, no postMessage vulnerabilities
6. **Transparent purpose**: Functionality matches description - helps developers and accessibility auditors analyze page structure
7. **Active development**: MV3 compliant, maintained by identifiable developer (Jorge Rumoroso)

This extension is safe for users and serves a legitimate accessibility/development purpose.
