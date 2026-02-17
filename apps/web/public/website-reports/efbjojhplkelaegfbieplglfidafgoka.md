# Vulnerability Report: VT4Browsers + Google TI

## Metadata
- **Extension ID**: efbjojhplkelaegfbieplglfidafgoka
- **Extension Name**: VT4Browsers + Google TI
- **Version**: 5.0.0
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

VT4Browsers + Google TI is the official browser extension from VirusTotal (now Google Threat Intelligence). This extension provides security scanning functionality for URLs, files, and indicators of compromise (IOCs) directly within the browser. The extension allows users to scan links and downloads through VirusTotal's API, highlight IOCs on web pages, and access threat intelligence data.

After thorough code review and static analysis, this extension has been determined to be **CLEAN**. All network communication is directed exclusively to VirusTotal's legitimate infrastructure, and the extension's functionality aligns precisely with its stated purpose as an official security tool. The permissions requested are appropriate and necessary for the extension's security scanning features.

## Vulnerability Details

No security vulnerabilities were identified in this extension.

## False Positives Analysis

### High-Privilege Permissions
- **`<all_urls>` host permission**: Required for content scripts to scan and analyze web pages for IOCs (IP addresses, domains, URLs, file hashes)
- **`webRequest` permission**: Used to collect passive DNS data and monitor downloads for automatic file scanning
- **`downloads` permission**: Enables automatic scanning of downloaded files before they execute
- **`tabs` permission**: Required to inject security UI elements and communicate scan results

All permissions are justified and necessary for a security extension that scans web content and file downloads.

### Content Script Injection
The extension injects content scripts on `<all_urls>` to:
- Detect and highlight indicators of compromise (IOCs) on web pages
- Add VirusTotal widget overlays for threat intelligence
- Scan selected text/hashes via context menu
- Monitor and optionally scan file downloads

This is standard behavior for security browser extensions and is not malicious.

### Network Activity
All network requests are directed to:
- `https://www.virustotal.com/*` - Official VirusTotal/GTI API endpoints
  - `/ui/files` - File scanning
  - `/ui/urls` - URL scanning
  - `/api/v3/widget` - Threat intelligence widget
  - `/api/v3/gtiwidget` - Google Threat Intelligence widget
  - `/core/v2/backend/resolutions/ingest` - Passive DNS data submission

The extension includes an API key header (`X-VT-Anti-Abuse-Header`) that is generated client-side using a timestamp and random number, encoded with base64. This is not obfuscation but rather an anti-abuse mechanism.

### Code Patterns
- **jQuery and Bootstrap**: Libraries used for UI manipulation in content scripts
- **Dynamic content creation**: Used to inject VirusTotal UI overlays and threat indicators on pages
- **Message passing**: Standard Chrome extension message passing between background and content scripts
- **File reading**: Used to scan downloaded files via FileReader API before sending to VirusTotal

All code patterns are consistent with legitimate security extension functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.virustotal.com/ui/files | File scanning | File contents (user-initiated or with consent) | Low - User controlled |
| www.virustotal.com/ui/urls | URL scanning | URLs (user-selected or download URLs) | Low - User controlled |
| www.virustotal.com/api/v3/widget | IOC lookup | IP addresses, domains, URLs, hashes from pages | Low - Opt-in feature |
| www.virustotal.com/api/v3/gtiwidget | GTI threat data | IOCs for threat intelligence | Low - Opt-in feature |
| www.virustotal.com/core/v2/backend/resolutions/ingest | Passive DNS | Hostname-IP pairs from browsing | Low - Opt-in, privacy-conscious |

All endpoints belong to VirusTotal's legitimate infrastructure. Data submission is either user-initiated or opt-in through extension settings.

## Privacy Features

The extension includes multiple privacy safeguards:

1. **File Filtering**: Excludes document file types (PDF, DOC, XLS, etc.) from automatic scanning by default
2. **Download Prompts**: Can be configured to ask before scanning each file
3. **Passive DNS Opt-in**: DNS resolution data collection is a separate opt-in setting
4. **Private IP Filtering**: Excludes private IP ranges from passive DNS collection
5. **File Size Limits**: Limits file scanning to 100MB to prevent accidental large uploads
6. **File Header Validation**: Checks magic bytes to avoid scanning sensitive document types

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

This is the official VirusTotal/Google Threat Intelligence browser extension, published by a reputable security company. The extension's functionality is transparent and matches its description:

1. **Legitimate Publisher**: VirusTotal is a well-known Google-owned security service
2. **Transparent Functionality**: All features are documented and user-controlled
3. **No Hidden Behavior**: Code review reveals no undisclosed data collection or exfiltration
4. **Privacy-Conscious**: Includes multiple privacy safeguards and opt-in controls
5. **Security Benefits**: Provides genuine value by scanning suspicious URLs and files
6. **Appropriate Permissions**: All permissions are justified and necessary for stated functionality
7. **No Malicious Code**: Static analysis and code review found no suspicious patterns

The extension operates exactly as advertised - it is a legitimate security tool for scanning web content and files using VirusTotal's API. Users should be aware that IOC highlighting and passive DNS features will send browsing data to VirusTotal, but these are opt-in features with clear privacy implications documented in the extension settings.
