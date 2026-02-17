# Vulnerability Report: G DATA WebProtection

## Metadata
- **Extension ID**: iokapgenfjiafbmphhhcgmgkobiiomcp
- **Extension Name**: G DATA WebProtection
- **Version**: 1.14.0
- **Users**: ~500,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

G DATA WebProtection is a legitimate browser companion extension developed by G DATA CyberDefense AG, a well-established German antivirus company. The extension works in conjunction with G DATA's desktop security software to provide real-time web protection against malicious websites, phishing, and malware downloads.

The extension requires native messaging permissions to communicate with the locally installed G DATA security software (via "de.gdata.nativewebprotection" native host). It intercepts web requests and downloads, sends URLs and file hashes to G DATA's cloud services for reputation checking, and blocks access to known malicious sites by redirecting users to warning pages. All sensitive operations are performed through the local G DATA application, and the extension operates as expected for a legitimate security product.

## Vulnerability Details

No security vulnerabilities were identified. This is a clean, legitimate security extension.

## False Positives Analysis

### Native Messaging Communication
The extension uses `chrome.runtime.connectNative("de.gdata.nativewebprotection")` to establish communication with G DATA's desktop software. This is standard behavior for security products that bridge browser and desktop components. The native messaging is used to:
- Notify the desktop application of blocked URLs
- Report file downloads for scanning
- Receive configuration settings from the desktop software
- Report malware detections via MII (Malware Information Initiative)

### Data Collection to G DATA Servers
The extension sends URLs and file metadata to G DATA's cloud services:
- **URL Cloud**: `dlarray-bp-*.gdatasecurity.de/url/v3` - Checks URL reputation
- **File Cloud**: `dlarray-bp-*.gdatasecurity.de` - Checks file hashes (MD5)
- **MII Reporting**: `url-mii-comchan.gdatasoftware.com` and `file-mii-comchan.gdatasoftware.com`

This is expected behavior for cloud-based malware protection. The extension sends:
- Full URLs being accessed (for reputation checks)
- File URLs, MD5 checksums, and file sizes (for download scanning)
- Client version, browser version, and product information
- IP addresses and HTTP headers (for context)

This data collection is disclosed in G DATA's privacy policy and is essential for real-time threat protection.

### Broad Permissions
The extension requests:
- `webRequest` - To intercept and block malicious web requests
- `<all_urls>` host permissions - To protect on all websites
- `downloads` - To scan downloaded files
- `tabs` - To redirect to block pages
- `nativeMessaging` - To communicate with desktop software

These permissions are appropriate and necessary for a web security product.

### Webpack Bundling
The static analyzer flagged the code as "obfuscated" due to webpack bundling. This is standard modern JavaScript build tooling, not malicious obfuscation. The deobfuscated code is well-structured with clear copyright headers, TypeScript origins, and professional coding practices.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| dlarray-bp-{region}-secsrv*.gdatasecurity.de | URL reputation check | Full URLs, client version, browser version | Low - Expected for security product |
| dlarray-bp-{region}-fileblsrv*.gdatasecurity.de | File reputation check | File URL, MD5 hash, file size, CCID | Low - Expected for download scanning |
| url-mii-comchan.gdatasoftware.com/report/mii/url/ | Malware Information Initiative URL reporting | Blocked URLs, verdict details | Low - Threat intelligence sharing |
| file-mii-comchan.gdatasoftware.com/report/mii/file/ | Malware Information Initiative file reporting | File detections | Low - Threat intelligence sharing |

All endpoints use HTTPS encryption and are owned by G DATA CyberDefense AG.

## Code Quality Assessment

The extension demonstrates professional development practices:
- Well-structured TypeScript source code (compiled via webpack)
- Proper error handling with try-catch blocks
- Timeout mechanisms to prevent hanging requests
- Cache implementation to reduce server queries
- Retry logic with exponential backoff
- Comprehensive internationalization (15 languages)
- Clear copyright notices and licensing information
- Defensive programming with input validation

## Architecture Overview

1. **Background Service Worker** (`background.js`):
   - Establishes native messaging connection to G DATA desktop app
   - Monitors web requests via webRequest API
   - Queries URL/file cloud for reputation checks
   - Redirects to block pages for malicious content
   - Reports detections to desktop application

2. **Block Pages** (`html/blocked_site.html`, `html/goto_fragfinn.html`):
   - Displayed when malicious sites are blocked
   - Shows reason for blocking (malware, phishing, PUP, blacklist)
   - Provides option to return to previous page
   - Requires desktop app configuration to whitelist

3. **Native Messaging Integration**:
   - Bidirectional communication with desktop software
   - Extension receives settings and configuration
   - Extension sends blocking events and detections
   - Desktop app provides CCID (customer ID) for cloud queries

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

G DATA WebProtection is a legitimate, professionally developed security extension from an established antivirus vendor. All behaviors that might appear suspicious in isolation (URL collection, native messaging, broad permissions, data exfiltration) are appropriate and expected for a web protection product.

The extension's purpose is explicitly to collect browsing data for security analysis, which is clearly disclosed. It operates as a companion to G DATA's desktop security software and cannot function independently. The code quality is high, showing professional development practices and no indicators of malicious intent.

Users who install this extension are customers of G DATA's antivirus software and expect this level of web protection. The extension delivers its advertised functionality without any hidden or undisclosed behaviors.

**Recommendation**: No action required. This is a clean, legitimate security product.
