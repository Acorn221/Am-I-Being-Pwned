# Vulnerability Report: Competitive Companion

## Metadata
- **Extension ID**: cjnmckjndlpiamhfimnnjmnckgghkjbl
- **Extension Name**: Competitive Companion
- **Version**: 2.63.0
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Competitive Companion is a legitimate open-source browser extension designed for competitive programmers. It parses competitive programming problems from various online judge platforms (Codeforces, AtCoder, LeetCode, etc.) and sends them to local development tools like CP Editor, CPH, or competitive programming IDEs running on localhost.

The extension operates exactly as advertised in its description and GitHub repository. It uses minimal permissions appropriate for its functionality, only requests localhost communication to send parsed problem data to local tools, and includes optional host permissions for specific competitive programming APIs. The static analyzer flagged a fetch to www.w3.org, but this is part of the bundled PDF.js library for SVG namespace declarations, not data exfiltration.

## Vulnerability Details

No security or privacy vulnerabilities identified.

## False Positives Analysis

### Static Analyzer Findings

The ext-analyzer flagged one "EXFILTRATION" flow:
- `document.getElementById → fetch(www.w3.org)` in js/content.js

**Analysis**: This is a false positive. The reference to `www.w3.org` appears in the bundled PDF.js library (pdfjs-dist@4.2.67) as part of SVG namespace declarations (`xmlns="http://www.w3.org/2000/svg"`). These are hardcoded strings used for SVG rendering in PDF documents, not actual network requests. The extension includes PDF.js to handle PDF problem statements from some competitive programming platforms.

**Evidence**:
```javascript
// Line 8853 in content.js - SVG namespace constant
let n3 = "http://www.w3.org/2000/svg";

// Line 12989 - SVG data URI for canvas compatibility testing
e4.src = 'data:image/svg+xml;charset=UTF-8,<svg viewBox="0 0 1 1" width="1" height="1" xmlns="http://www.w3.org/2000/svg">...';
```

These are standard SVG namespace declarations, not network exfiltration.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| http://localhost:1327, 4243, 4244, 6174, 10042, 10043, 10045, 27121 | Communication with local competitive programming tools (CP Editor, CPH, etc.) | Parsed problem metadata (problem name, time limit, test cases, etc.) | None - localhost only |
| https://codejam.googleapis.com/dashboard/get_file/* | Optional: Download Google Code Jam problem files | None (download only) | None - legitimate API for Google competitions |
| https://api.tlx.toki.id/v2/* | Optional: Access TLX/TOKI competitive programming platform | None (API requests with user credentials) | None - legitimate competitive programming platform |
| https://resources.beecrowd.com/* | Optional: Access Beecrowd (formerly URI Online Judge) resources | None (download problem resources) | None - legitimate online judge platform |

All endpoints are either localhost (for tool integration) or legitimate competitive programming platform APIs that require explicit user permission via Chrome's optional_host_permissions.

## Background Script Analysis

The background script (background.js) implements:
1. **Context menu creation**: Allows users to select specific parsers from right-click menu
2. **Content script injection**: Injects parser logic when user clicks extension icon
3. **Message handling**: Relays parsed problem data from content scripts to localhost tools
4. **Permission management**: Requests required permissions based on the current website

**Key security features**:
- Validates localhost permission before sending data
- Uses AbortController with 500ms timeout for all localhost requests (configurable)
- Never exposes data externally - only sends to localhost or approved APIs
- Handles errors gracefully without exposing sensitive information

## Content Script Analysis

The content script (content.js, 2.2MB bundled) includes:
1. **150+ competitive programming platform parsers** for sites like Codeforces, AtCoder, LeetCode, HackerRank, etc.
2. **PDF.js library** (pdfjs-dist@4.2.67) for parsing PDF problem statements
3. **Problem parsing logic**: Extracts problem metadata, test cases, time/memory limits
4. **Nanobar library**: Provides progress bar UI when downloading test cases

The code is webpack-bundled but not obfuscated. The extension is open source (https://github.com/jmerle/competitive-companion) and code matches the published repository.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
- **No privacy concerns**: Does not collect, store, or transmit user data beyond localhost communication
- **Minimal permissions**: Only requests activeTab, contextMenus, storage, scripting - all justified by functionality
- **Localhost-only data flow**: Parsed problem data only sent to localhost development tools
- **Optional API access**: External API permissions are optional and only for legitimate competitive programming platforms
- **Open source**: Code is publicly auditable on GitHub (https://github.com/jmerle/competitive-companion)
- **Appropriate for purpose**: All functionality directly supports the stated goal of parsing competitive programming problems

This extension is a legitimate, well-designed tool for competitive programmers with no security or privacy issues.
