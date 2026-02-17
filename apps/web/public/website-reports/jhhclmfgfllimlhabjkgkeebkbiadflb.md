# Vulnerability Report: EPUBReader

## Metadata
- **Extension ID**: jhhclmfgfllimlhabjkgkeebkbiadflb
- **Extension Name**: EPUBReader
- **Version**: 2.1.1
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

EPUBReader is a legitimate browser extension designed to read EPUB files directly in the browser. The extension intercepts .epub file downloads and displays them in a custom reader interface. While the extension requests `<all_urls>` host permissions, code analysis reveals no evidence of malicious behavior, data exfiltration, or unauthorized data collection. The extension primarily uses XMLHttpRequest to download EPUB files from their original locations and processes them locally using a zip library.

The extension only contacts its own domain (epubread.com) for two legitimate purposes: displaying a welcome page on first install and setting an uninstall feedback URL. The overly broad `<all_urls>` permission appears to be necessary for the extension's core functionality (intercepting EPUB file downloads from any website), though it could be considered slightly excessive for the stated purpose. No third-party analytics, tracking, or advertising code was detected.

## Vulnerability Details

### 1. LOW: Overly Broad Host Permissions

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**:
The extension requests `<all_urls>` host permissions, which grants access to all websites. While this appears necessary for the extension's declarativeNetRequest rule that intercepts .epub file downloads from any domain, it represents a broader permission set than strictly required for the core EPUB reading functionality.

**Evidence**:
```json
"host_permissions": [
  "<all_urls>"
]
```

The declarativeNetRequest rule uses this to redirect EPUB files:
```json
{
  "id": 1,
  "priority": 1,
  "action": {
    "type": "redirect",
    "redirect": {
      "regexSubstitution": "chrome-extension://jhhclmfgfllimlhabjkgkeebkbiadflb/reader.html?filename=\\0"
    }
  },
  "condition": {
    "regexFilter": "^(http|https|file)://.*/.*\\.epub.*",
    "resourceTypes": ["main_frame", "sub_frame"]
  }
}
```

**Verdict**:
This is a legitimate use of broad permissions for the extension's stated functionality. The extension needs to intercept EPUB file navigations from any website to provide its reader service. No evidence of permission abuse was found. The extension does not inject content scripts, does not read page data, and does not interact with web pages beyond the EPUB file redirection.

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated," but this is a false positive. The code is not obfuscated - it uses standard webpack bundling with a zip/inflate library for EPUB file processing. The compression/decompression code in `js/zip/` is legitimate functionality for reading EPUB files (which are essentially ZIP archives).

XMLHttpRequest usage is legitimate - it's used exclusively to download EPUB files from their original URLs when the user clicks on an EPUB link. The downloaded content is processed locally and not sent to external servers.

The `onMessageExternal` listener in background.js is for an external API that allows other extensions to control the EPUB reader (page forward/backward, get document info). This is a documented feature, not a security vulnerability.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| epubread.com/welcome_new.php | First-install welcome page | User language preference (from browser) | CLEAN |
| www.epubread.com/goodbye.php | Uninstall feedback URL | None (Chrome API only) | CLEAN |
| www.epubread.com/faq.php | Help documentation link | None (user-initiated navigation) | CLEAN |

## Network Behavior

All XMLHttpRequest calls in the extension are for downloading EPUB files from their original source URLs (wherever the user clicked the EPUB link). The extension does not:
- Send user data to remote servers
- Make unauthorized network requests
- Track user behavior
- Include analytics or advertising code
- Exfiltrate browsing history or personal information

The only extension-initiated network contacts are:
1. Opening the welcome page on first install (with optional language parameter)
2. Setting an uninstall URL for optional user feedback

Both are transparent, user-initiated actions.

## Permissions Analysis

- **declarativeNetRequest**: Used to intercept EPUB file navigations and redirect to the reader
- **downloads**: Used to save EPUB files to disk when requested by the user
- **storage**: Used to store user preferences (reading style, font size, bookmarks)
- **<all_urls>**: Required for EPUB interception across all domains

All permissions are used for their stated purposes with no evidence of abuse.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
EPUBReader is a legitimate utility extension that performs its stated function (reading EPUB files in the browser) without security or privacy violations. While the `<all_urls>` permission is broad, it appears necessary for the core functionality and is not abused. The extension does not collect or exfiltrate user data, does not inject malicious code, does not track users, and only contacts its own domain for legitimate purposes (welcome page and uninstall feedback).

The single LOW-severity finding relates to the broad host permissions, which could be considered excessive but are functionally justified. There are no medium, high, or critical vulnerabilities. The extension is safe for use by its 1 million users.
