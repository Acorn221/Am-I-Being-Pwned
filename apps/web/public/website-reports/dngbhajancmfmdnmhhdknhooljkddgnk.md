# Vulnerability Report: Save Emails as PDF by cloudHQ

## Metadata
- **Extension Name**: Save Emails as PDF by cloudHQ
- **Extension ID**: dngbhajancmfmdnmhhdknhooljkddgnk
- **Version**: 1.1.2.22
- **Users**: ~100,000
- **Vendor**: cloudHQ (https://www.cloudhq.net)
- **Analysis Date**: 2026-02-07

## Executive Summary

Save Emails as PDF is a legitimate Gmail productivity extension by cloudHQ that enables users to export and save Gmail emails as PDF documents. The extension demonstrates **standard business practices** for a SaaS product with minimal security concerns. While it collects user email addresses and communicates with cloudHQ servers for authentication and PDF conversion services, these behaviors are **appropriate and expected** for the advertised functionality.

**Overall Risk: LOW**

The extension uses InboxSDK (a Gmail-focused development framework by Streak), communicates exclusively with cloudhq.net domains, and implements proper permission scoping. No evidence of malware, data exfiltration beyond service requirements, residential proxy infrastructure, ad injection, or obfuscation was found.

## Vulnerability Details

### 1. Server Communication & Authentication
**Severity**: LOW
**Files**: `background.js` (lines 24691-25034), `content.js`
**Verdict**: CLEAN - Expected Behavior

The extension communicates with `https://www.cloudhq.net/` for legitimate service functionality:

```javascript
// background.js:24691
var g_server_url = "https://www.cloudhq.net/";
var g_extension_what = "save_to_pdf";

// Login check endpoint
url: cgo.g_server_url + login_check_controller +
     "/chrome_extension_login_or_signup_dialog",
data: {
  email_or_login: cgo.g_email_or_login,
  switch_login: "1",
  gmail_timezone_offset: cgo.g_gmail_timezone_offset,
  gmail_timezone: cgo.g_gmail_timezone,
  cloudHQ_extension_version: cgo.g_cloudHQ_extension_version,
  what: cgo.g_cloudHQ_feature_name
}
```

**Analysis**: The extension collects user email addresses and timezone information to provide personalized service and authenticate users with cloudHQ's backend. This is standard for SaaS products requiring user accounts.

### 2. Email Message ID Access
**Severity**: LOW
**Files**: `background.js` (lines 22458-22472)
**Verdict**: CLEAN - Required for Core Functionality

```javascript
// background.js:22458
message_view.getMessageIDAsync().then(function (message_id) {
  if (message_id) {
    request_data['message_id'] = message_id;
    c_cmn.fn_ajax({
      url: cgo.g_server_url + 'main_gmail_save_eml/chrome_extension_save_eml_to_gmail',
      dataType: "json",
      data: request_data,
      type: 'POST',
      // ...
    });
  }
});
```

**Analysis**: The extension sends Gmail message IDs to cloudHQ servers for PDF conversion. This is **necessary and expected** for the core "save email as PDF" functionality. The extension requires server-side processing to convert emails to PDF format.

### 3. Manifest Permissions Analysis
**Severity**: LOW
**Files**: `manifest.json`
**Verdict**: CLEAN - Appropriately Scoped

```json
{
  "permissions": [
    "scripting",
    "storage",
    "background"
  ],
  "host_permissions": [
    "https://mail.google.com/",
    "https://www.cloudhq.net/"
  ]
}
```

**Analysis**: Permissions are minimal and appropriate:
- `scripting`: Required to inject UI into Gmail
- `storage`: Required to store user preferences and authentication state
- `background`: Required for service worker functionality
- Host permissions limited to Gmail and cloudHQ only

**No broad permissions** like `webRequest`, `cookies`, `tabs` (beyond standard access), or `<all_urls>`.

### 4. Content Script Injection
**Severity**: LOW
**Files**: `content.js` (116,809 lines), `pageWorld.js` (20,655 lines)
**Verdict**: CLEAN - InboxSDK Framework

The extension uses InboxSDK, a legitimate Gmail development framework:

```javascript
// pageWorld.js:1-19
/*!
 * InboxSDK
 * https://www.inboxsdk.com/
 *
 * The use of InboxSDK is governed by the Terms of Services located at
 * https://www.inboxsdk.com/terms
 *
 * Want to hack on Gmail? Join us at: www.streak.com/careers?source=sdk
 */
```

**Analysis**: InboxSDK is a well-known framework by Streak for building Gmail extensions. The large file sizes (116K+ lines) are expected as they include the entire framework bundled with the extension. This is **not obfuscation**, but standard webpack bundling.

### 5. Local Storage Usage
**Severity**: LOW
**Files**: `content.js` (lines 27016-35419)
**Verdict**: CLEAN - UI State Persistence

```javascript
// content.js:27036
data = JSON.parse(window.localStorage.getItem('inboxsdk__sidebar_expansion_settings') || 'null');

// content.js:27403
return JSON.parse(window.localStorage.getItem('inboxsdk__sidebar_ordering') || 'null');
```

**Analysis**: LocalStorage is used exclusively for InboxSDK UI state (sidebar expansion, ordering preferences). No sensitive data harvesting detected.

### 6. Background Proxy for AJAX
**Severity**: LOW
**Files**: `background.js` (lines 24697-24729)
**Verdict**: CLEAN - CORS Workaround

```javascript
// background.js:24697
chrome.runtime.onMessage.addListener(
  function(input_request, sender, sendResponse) {
    if (input_request.what == 'PROXY_AJAX') {
      var out_request = input_request.payload;
      // Security check
      if (!out_request['url'] || !out_request['url'].startsWith(g_server_url)) {
        sendResponse({ what: 'error', payload: 'Invalid request' });
        return;
      }
      bg_cmn.ajaxRequest(out_request);
    }
  }
);
```

**Analysis**: The background script proxies AJAX requests from content scripts to cloudHQ servers. This is a standard pattern to work around CORS restrictions. **Important**: The code includes security validation to ensure only requests to `g_server_url` (cloudhq.net) are permitted.

### 7. Chrome Extension Installation Tracking
**Severity**: LOW
**Files**: `background.js` (lines 24990-25032)
**Verdict**: CLEAN - Standard Onboarding

```javascript
// background.js:25016
chrome.runtime.onInstalled.addListener(function(details) {
  if ((details.reason === 'install') || (details.reason === 'update')) {
    fn_storage_permission_check();
    if ((details.reason === 'install')) {
      bg_cmn.refreshBrowser('gmail', true, {
        install_or_update: details.reason
      });
    }
  }
});

// background.js:25034
chrome.runtime.setUninstallURL("https://www.cloudhq.net/uninstall_chrome_extension?product_what=" + g_extension_what);
```

**Analysis**: Standard installation tracking and uninstall survey. The extension refreshes Gmail tabs on install/update to activate features and sets an uninstall URL for user feedback collection.

## False Positive Analysis

| Pattern | Location | Explanation |
|---------|----------|-------------|
| Large JS files (116K lines) | content.js, background.js | Webpack-bundled InboxSDK framework + jQuery + dependencies. Not obfuscation. |
| `eval`, `Function()` patterns | background.js:2528-6319 | jQuery internal functions (`isFunction`, `markFunction`). Standard library code. |
| `localStorage` access | content.js:27016+ | InboxSDK UI state persistence only. No sensitive data. |
| Server communication | All files | Legitimate cloudHQ service calls for authentication and PDF conversion. |
| Email address collection | background.js:23326 | Required for SaaS account authentication. |
| Message ID transmission | background.js:22469 | Required for PDF conversion service. |

## API Endpoints & Data Flow

### Endpoints Contacted

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://www.cloudhq.net/[controller]/chrome_extension_login_or_signup_dialog` | User authentication | email_or_login, timezone, extension_version, feature_name |
| `https://www.cloudhq.net/main_gmail_save_eml/chrome_extension_save_eml_to_gmail` | PDF conversion | message_id, user-specific request_data |
| `https://www.cloudhq.net/dashboard/apps/save_to_pdf` | User dashboard access | email_or_login, registration_code, provider_mode |
| `https://www.cloudhq.net/chrome_extensions_menu_updates` | Extension menu updates | email_or_login |
| `https://www.cloudhq.net/uninstall_chrome_extension` | Uninstall feedback | product_what |

### Data Flow Summary

1. **User Authentication Flow**:
   - Extension detects Gmail email address via InboxSDK
   - Sends email + timezone to cloudHQ for login check
   - Receives authentication status, user_id, is_paid flag
   - Stores authentication state in chrome.storage.sync

2. **PDF Conversion Flow**:
   - User clicks "Save as PDF" button in Gmail
   - Extension retrieves Gmail message ID via InboxSDK
   - Posts message_id to cloudHQ backend
   - Server processes email and returns PDF/status
   - Extension displays success message to user

3. **Data Retention**:
   - Local: Install timestamp, UI preferences, authentication state
   - Remote: User email, message IDs for processing, timezone

## Overall Risk Assessment

**OVERALL RISK: LOW**

### Risk Factors:
- ✅ **No malware indicators**: No cryptocurrency miners, keyloggers, or credential theft
- ✅ **No residential proxy infrastructure**: No P2P networking or traffic routing
- ✅ **No ad/coupon injection**: No DOM manipulation for advertising
- ✅ **No market intelligence SDKs**: No Sensor Tower, Pathmatics, or similar trackers
- ✅ **No browser fingerprinting**: No excessive telemetry beyond service requirements
- ✅ **No obfuscation**: Code is readable, uses standard frameworks
- ✅ **Appropriate permissions**: Minimal, scoped to Gmail and cloudHQ domains only
- ⚠️ **User data collection**: Collects email addresses and message IDs (required for service)
- ⚠️ **Third-party dependency**: Uses InboxSDK (Streak framework)

### Security Strengths:
1. **URL validation** in AJAX proxy prevents arbitrary server requests
2. **Host permissions** limited to mail.google.com and cloudhq.net
3. **No sensitive permission requests** (no cookies, webRequest, debugger, etc.)
4. **Externally connectable** limited to cloudhq.net domains only
5. **Standard SaaS architecture** with transparent server communication

### Recommendations for Users:
- **Safe to use** for intended PDF export functionality
- Understand that email metadata (message IDs, sender email) is transmitted to cloudHQ servers
- cloudHQ is an established SaaS company (not a fly-by-night operation)
- Review cloudHQ's privacy policy for data retention/usage details

### Recommendations for Developers:
- Consider implementing client-side PDF generation to reduce data transmission
- Add transparency notifications about which data is sent to servers
- Implement certificate pinning for cloudHQ API calls
- Publish security audit results and data handling practices

## Conclusion

Save Emails as PDF by cloudHQ is a **legitimate, low-risk extension** that performs its advertised functionality without engaging in malicious behavior. The extension follows standard practices for a server-backed SaaS product, with appropriate permission scoping and transparent server communication limited to cloudHQ's own infrastructure.

The data collection (email addresses, message IDs) is **necessary and proportional** to the service offered. Users should be comfortable using this extension if they trust cloudHQ as a service provider and understand that their email metadata will be processed server-side for PDF conversion.

**No critical or high-severity vulnerabilities identified.**
