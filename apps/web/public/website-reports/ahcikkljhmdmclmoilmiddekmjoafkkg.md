# Vulnerability Report: x-zombie-killer

## Metadata
- **Extension ID**: ahcikkljhmdmclmoilmiddekmjoafkkg
- **Extension Name**: x-zombie-killer
- **Version**: 2.2.1
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

x-zombie-killer is a Twitter/X content filtering extension designed to hide unwanted posts ("zombies") based on various criteria including language, duplicate content, and spam patterns. The extension implements a premium license verification system that contacts api.itokoba.com to validate user licenses.

The static analyzer flagged three exfiltration flows related to license verification and configuration sync. While data is sent to external servers, this is limited to license keys and user configuration preferences, which appears to be disclosed functionality for the premium feature set. The extension does not collect browsing history, Twitter credentials, or other sensitive user data beyond what is necessary for its stated filtering functionality.

## Vulnerability Details

### 1. LOW: Premium License Verification with Remote Server

**Severity**: LOW
**Files**: background.js, options.js
**CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)
**Description**: The extension sends user license keys to api.itokoba.com via HTTPS POST requests for validation. Three API endpoints are used:
- `/check-license/index.php` - Validates license keys
- `/verify-license/index.php` - Initial license activation
- `/unlink-license/index.php` - License deactivation

**Evidence**:
```javascript
// background.js - Periodic license check (daily)
var n = await fetch("https://api.itokoba.com/check-license/index.php", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    license_key: e
  })
});
```

```javascript
// options.js - User-initiated verification
var d = await fetch("https://api.itokoba.com/verify-license/index.php", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    license_key: e
  })
});
```

**Verdict**: This is expected behavior for a freemium extension model. The license key transmission occurs over HTTPS and is limited to authentication purposes. Users explicitly enter license keys to unlock premium features, so this data flow is disclosed. The daily background check (via chrome.alarms every 1440 minutes) ensures licenses remain valid but could be considered mildly privacy-invasive if not disclosed in the privacy policy.

## False Positives Analysis

The static analyzer flagged the following as potential exfiltration:

1. **chrome.storage.sync.get → fetch(api.itokoba.com)** - This retrieves the stored license key and sends it for validation. This is the core functionality of the license system and not malicious.

2. **document.getElementById → fetch(api.itokoba.com)** - This reads the license key input field when users click "verify license" in the options page. This is user-initiated and expected.

3. **message data → fetch(api.itokoba.com)** - The content script can trigger the options page via chrome.runtime.sendMessage with action "openOptionsPage", but this does not send any data to external servers. This is a false positive for the attack surface analysis.

The extension's content script (content.js) operates entirely locally on Twitter/X pages. It filters tweets based on:
- Hardcoded spam word lists (Arabic, Hindi, Japanese spam patterns)
- User-configured muted words (premium feature)
- Duplicate content detection (Jaccard similarity)
- Character set filtering
- Verified account filtering (premium)
- Whitelist functionality (premium)

All filtering logic executes client-side with no data sent to external servers.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.itokoba.com/check-license/index.php | Daily license validation | License key (user-provided) | Low - Expected functionality |
| api.itokoba.com/verify-license/index.php | Initial license activation | License key (user-provided) | Low - User-initiated |
| api.itokoba.com/unlink-license/index.php | License deactivation | License key (user-provided) | Low - User-initiated |

All communications use HTTPS POST with JSON payloads. No browsing history, Twitter content, or personal identifiers (beyond license keys) are transmitted.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

The extension's core functionality (filtering Twitter/X content) operates entirely locally without external data transmission. The remote server communication is limited to premium license validation, which is expected behavior for freemium software.

The daily background license check could be considered slightly intrusive if not properly disclosed, as it creates periodic network connections. However, this is a standard anti-piracy measure and only transmits the license key - no user activity or Twitter content is collected.

The extension does not exhibit:
- Credential theft
- Session hijacking
- Undisclosed data collection
- Browsing history exfiltration
- Code injection vulnerabilities
- XSS or CSP bypasses
- Malicious content manipulation

The codebase is straightforward with no obfuscation (minification only), uses standard Chrome extension APIs appropriately, and implements reasonable content filtering logic. The premium features (whitelist, custom muted words, verified account filtering) require remote license validation, but this appears to be the stated business model.

**Recommendation**: Users should review the extension's privacy policy to confirm that license verification practices are disclosed. The extension is safe for its stated purpose of filtering unwanted Twitter/X content.
