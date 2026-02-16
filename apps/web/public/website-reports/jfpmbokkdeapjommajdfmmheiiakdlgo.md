# Vulnerability Report: Download with JDownloader

## Metadata
- **Extension ID**: jfpmbokkdeapjommajdfmmheiiakdlgo
- **Extension Name**: Download with JDownloader
- **Version**: 0.3.7
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Download with JDownloader" is a browser extension that integrates with the JDownloader2 desktop application to intercept and redirect browser downloads to the external download manager. The extension communicates with a local JDownloader instance running on http://127.0.0.1:9666/ and uses native messaging to launch the JDownloader application when needed.

The extension is functionally legitimate and operates as advertised. It intercepts downloads through the chrome.downloads API, extracts links from web pages, and sends them to the local JDownloader instance. The extension optionally collects cookies (with explicit user permission) to support authenticated downloads. No external data exfiltration or malicious behavior was identified.

## Vulnerability Details

No security vulnerabilities were identified in this extension.

## False Positives Analysis

Several patterns in the code could appear suspicious but are legitimate for this extension type:

1. **Native Messaging with Node.js Modules**: The extension uses `chrome.runtime.sendNativeMessage` with a script that imports Node.js modules like `child_process`, `fs`, `path`, and `crypto` (worker.js:242-246). This is legitimate functionality to launch the JDownloader desktop application from the browser.

2. **Cookie Access**: The extension requests optional `cookies` permission and reads cookies via `chrome.cookies.getAll()` (worker.js:150-152). This is a standard feature for download managers to support authenticated downloads - cookies are sent to the local JDownloader instance so it can download files from sites requiring authentication.

3. **Link Extraction and Script Injection**: The extension injects scripts to extract all links, images, and video sources from web pages (worker.js:509-515). This is expected behavior for a download manager that offers "download all links" functionality.

4. **XMLHttpRequest for Type Detection**: The grab interface uses XHR to detect content types by fetching headers (data/grab/index.js:46-57). This is legitimate functionality to categorize downloadable content.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| http://127.0.0.1:9666/flash/ | Check if JDownloader is running | None (GET request) | None - localhost only |
| http://127.0.0.1:9666/{engine} | Send download jobs to JDownloader | URL, referrer, cookies, filename, package name | None - localhost only |

All network communication is strictly to localhost (127.0.0.1:9666), which is the default JDownloader API endpoint. No external servers are contacted by this extension.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This extension is a legitimate browser integration for JDownloader2, a popular open-source download manager. The extension operates entirely as documented and does not exhibit any malicious behavior.

Key security considerations:
- All network communication is to localhost only (127.0.0.1:9666)
- Native messaging is used appropriately to launch a local desktop application
- Cookie access requires explicit user permission and cookies are only sent to the local JDownloader instance
- The extension properly uses Manifest V3 APIs
- No code obfuscation, eval usage, or dynamic code execution
- No external data collection or tracking
- Source code is clean and well-structured

The extension's permissions are appropriate for its functionality. The optional `*://*/*` host permission is only used for link extraction features when explicitly triggered by the user via context menus.
