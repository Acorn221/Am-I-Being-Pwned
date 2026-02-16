# Vulnerability Report: Web Cache Viewer

## Metadata
- **Extension ID**: pbkloffickinnlnmefmjmjbacohecpbd
- **Extension Name**: Web Cache Viewer
- **Version**: 2.0
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Web Cache Viewer is a legitimate utility extension that provides users with quick access to web archive services, specifically the Wayback Machine and Archive.today. The extension allows users to view cached or archived versions of web pages through context menu entries and a browser action popup.

After thorough analysis of the codebase, including static analysis and manual code review, no security vulnerabilities or privacy concerns were identified. The extension operates transparently, uses minimal permissions appropriate for its functionality, makes no undisclosed network requests, and does not collect or transmit user data. All external URLs opened by the extension are well-known archive services or legitimate support/information pages.

## Vulnerability Details

No vulnerabilities were identified during the analysis.

## False Positives Analysis

### Storage API Usage
The extension uses `chrome.storage` and `localStorage` APIs exclusively for storing user preferences (theme selection: dark/light mode). This is standard practice for maintaining UI state and does not involve any sensitive data collection.

### External URLs
The extension opens several external URLs, but all are legitimate and expected:
- **web.archive.org** - Wayback Machine archive service (core functionality)
- **archive.today** (and mirrors: archive.is, archive.ph, archive.fo) - Archive.today service (core functionality)
- **searchengineland.com** - Educational article about Google Cache removal (informational context menu item)
- **ko-fi.com/matbram** - Developer support page (optional donation link)

None of these URLs receive user data or browsing information from the extension.

### Content Scripts on Archive Domains
The extension injects content scripts on archive service domains (`web.archive.org`, `archive.today`, etc.) to:
1. Detect if a cached version was successfully found
2. Display a countdown modal if no cache exists
3. Prevent recursive archiving (user attempting to archive an already-archived URL)

This is legitimate functionality that enhances user experience and prevents misuse.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| web.archive.org | View cached web pages via Wayback Machine | Current page URL only | None - user-initiated, expected functionality |
| archive.today | Create/view snapshots via Archive.today | Current page URL only | None - user-initiated, expected functionality |
| searchengineland.com | Educational content about Google Cache | None | None - static informational page |
| ko-fi.com/matbram | Developer support/donation page | None | None - static donation page |

## Code Quality & Security Observations

### Positive Security Practices
1. **Manifest V3 compliance** - Uses modern service worker architecture
2. **Minimal permissions** - Only requests necessary permissions (activeTab, contextMenus, storage, scripting, tabs)
3. **No host permissions** - Does not request broad host access
4. **No eval usage** - No dynamic code execution detected
5. **Clean codebase** - Well-commented, readable code with no obfuscation
6. **User control** - All archive lookups are user-initiated (context menu or popup clicks)
7. **Error handling** - Proper try-catch blocks throughout the codebase

### Permission Justification
- **activeTab**: Required to get the URL of the current page for archiving
- **contextMenus**: Creates context menu entries for archive services
- **storage**: Stores user theme preference (dark/light mode)
- **scripting**: Injects content scripts to detect archive success/failure
- **tabs**: Opens new tabs for archive services and manages tab state

All permissions are justified and appropriately scoped.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: This extension is a straightforward utility tool with no security vulnerabilities or privacy concerns. It performs exactly as advertised - providing quick access to web archive services. The extension does not collect user data, does not make undisclosed network requests, uses minimal and appropriate permissions, and implements no tracking or data exfiltration mechanisms. The codebase is clean, well-structured, and contains no malicious functionality. This is a legitimate, user-beneficial extension that poses no risk to users.
