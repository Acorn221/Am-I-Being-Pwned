# Vulnerability Report: Download with Ant Download Manager

## Metadata
- **Extension ID**: dalgiebmfcjackkbjfbfmlnflbdfbekj
- **Extension Name**: Download with Ant Download Manager
- **Version**: 0.5.0
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension is a legitimate browser integration for Ant Download Manager (AntDM), a desktop download manager application. The extension uses Chrome's nativeMessaging API to communicate exclusively with the locally-installed AntDM software via the native messaging host "com.dlhelper.ch". All captured download requests, cookies, and tab information are sent only to the local native application, not to any remote servers. The extension's purpose is to intercept downloads from the browser and route them to the native download manager for handling.

Static analysis with ext-analyzer found no suspicious findings. All network-related code paths lead to the native messaging interface, which is the expected and documented behavior for this type of download manager integration extension.

## Vulnerability Details

No security or privacy vulnerabilities were identified.

## False Positives Analysis

The following patterns might appear suspicious but are legitimate for a download manager extension:

1. **Extensive permissions**: The extension requests `cookies`, `downloads`, `tabs`, `webRequest`, `webNavigation`, `nativeMessaging`, `management`, and broad host permissions (`http://*/*`, `https://*/*`). These are all necessary for its core functionality:
   - `cookies` and `webRequest` are needed to capture authentication cookies for downloads
   - `downloads` is required to intercept and manage download operations
   - `tabs` and `webNavigation` are used to capture referrer URLs and page context
   - `nativeMessaging` is the core communication channel with the desktop application
   - `management` is used to check extension version/status
   - Broad host permissions are needed to capture downloads from any website

2. **Cookie harvesting**: The extension actively captures cookies for download URLs using `chrome.cookies.getAll()`. This is necessary functionality because many downloads require authentication cookies to succeed, and the native download manager needs these cookies to properly download protected files.

3. **Tab enumeration and tracking**: The extension tracks tab states, URLs, and titles in the `VBOX_g_Tabs` object and monitors tab creation/removal events. This is standard behavior for video/media capture functionality, where the extension needs to associate download requests with their source pages and maintain context about what's being downloaded.

4. **webRequest monitoring**: The extension monitors all HTTP responses via `chrome.webRequest.onHeadersReceived` to identify downloadable files based on Content-Disposition headers, MIME types, and file extensions. This is the expected mechanism for a download manager to intercept downloads before the browser handles them.

5. **Content script injection**: The extension dynamically injects content scripts using `chrome.scripting.executeScript()` to create video capture buttons on supported video streaming sites. This is a documented feature for capturing streaming media.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| com.dlhelper.ch (Native Messaging) | Communication with local AntDM software | Download URLs, cookies, referrers, user-agent, tab context, file metadata | NONE (local IPC only) |

**Note**: This is not a network endpoint but a native messaging host. All data flows are local to the user's machine between the browser extension and the installed desktop application.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

This is a legitimate download manager extension that functions exactly as documented. The extension's entire purpose is to integrate the browser with the Ant Download Manager desktop application installed on the user's system. All "data collection" serves the specific purpose of passing download context to the native application, which is the core functionality users install this extension to enable.

Key factors supporting the CLEAN rating:

1. **Zero remote data exfiltration**: All data flows go exclusively to the local native messaging host (com.dlhelper.ch), not to any remote servers
2. **No obfuscation**: The code is cleanly formatted and uses clear variable names
3. **Transparent purpose**: The extension description, permissions, and code all align with the stated purpose of download management
4. **Appropriate privilege use**: All requested permissions are justified by documented features
5. **Static analysis clean**: ext-analyzer found no suspicious code execution patterns, data exfiltration flows, or security issues
6. **MV3 compliance**: Uses modern Manifest V3 with service worker architecture
7. **Established software**: Ant Download Manager is a known desktop application, not a novel or suspicious program

The extension requires significant permissions because download management fundamentally requires intercepting network requests, capturing authentication state, and coordinating between the browser and a native application. Users who install this extension explicitly want this behavior to route their downloads through their preferred download manager.
