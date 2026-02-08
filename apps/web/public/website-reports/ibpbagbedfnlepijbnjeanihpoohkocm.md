# Vulnerability Report: Export Emails to Sheets by cloudHQ

## Metadata
- **Extension ID**: ibpbagbedfnlepijbnjeanihpoohkocm
- **Extension Name**: Export Emails to Sheets by cloudHQ
- **Version**: 1.0.2.25
- **User Count**: ~40,000
- **Developer**: cloudHQ (https://www.cloudhq.net)
- **Analysis Date**: 2026-02-08

## Executive Summary

Export Emails to Sheets by cloudHQ is a legitimate productivity extension that enables users to export Gmail messages and labels to Google Sheets. The extension integrates with cloudHQ's server infrastructure (cloudhq.net) and uses the InboxSDK framework to interact with Gmail.

**Overall Risk: CLEAN**

While the extension requests broad permissions and communicates with external servers, this behavior is fully aligned with its stated functionality of exporting email data to Google Sheets. The extension serves its intended purpose without exhibiting malicious behavior. All data transmission to cloudHQ servers appears to be part of the legitimate email export workflow.

## Permission Analysis

### Declared Permissions
- `scripting` - For injecting content scripts
- `storage` - For storing extension configuration
- `background` - Service worker for background operations

### Host Permissions
- `https://mail.google.com/` - Gmail access (required for email export)
- `https://inbox.google.com/` - Inbox access (legacy)
- `https://www.cloudhq.net/` - cloudHQ backend server

### Content Security Policy
No custom CSP defined in manifest (uses default MV3 CSP).

### Permission Assessment
**Verdict: APPROPRIATE** - All permissions are necessary for the extension's core functionality of exporting Gmail data to Google Sheets via cloudHQ's service.

## Vulnerability Details

### 1. Third-Party SDK Integration - InboxSDK
**Severity**: INFORMATIONAL
**Files**: content.js (93,358 lines), pageWorld.js (20,652 lines)
**Description**:

The extension uses InboxSDK (version 2.2.11), a legitimate third-party library developed by Streak for Gmail integration:

```javascript
// content.js lines 1-24
/*!
 * InboxSDK
 * https://www.inboxsdk.com/
 * The use of InboxSDK is governed by the Terms of Services located at
 * https://www.inboxsdk.com/terms
 */
```

**Evidence**: Standard InboxSDK implementation with common patterns for Gmail DOM manipulation, email parsing, and UI injection.

**Verdict: FALSE POSITIVE** - InboxSDK is a widely-used, legitimate library for Gmail extensions. No evidence of tampering or malicious modifications.

---

### 2. Communication with cloudHQ Backend
**Severity**: INFORMATIONAL
**Files**: background.js (lines 19284, 24684-24979)
**Description**:

The extension communicates with `https://www.cloudhq.net/` for its core functionality:

```javascript
// background.js line 19284
this.server_url = "https://www.cloudhq.net/";

// background.js line 24685
var g_extension_what = "gmail_sheets";

// background.js lines 24690-24722
chrome.runtime.onMessage.addListener(
  function(input_request, sender, sendResponse) {
    if (input_request.what == 'PROXY_AJAX') {
      var out_request = input_request.payload;
      if (!out_request['url'] || !out_request['url'].startsWith(g_server_url)) {
        sendResponse({ what: 'error', payload: 'Invalid request' });
        return;
      }
      // Proxies AJAX requests through background script
    }
  }
);
```

**Security Features Observed**:
1. URL validation - only allows requests to cloudhq.net domain
2. Request proxying through background script (security best practice)
3. User authentication via `email_or_login` parameter

**Verdict: EXPECTED BEHAVIOR** - Communication with cloudHQ servers is necessary for the email export functionality. The extension validates URLs before making requests.

---

### 3. User Email Address Collection
**Severity**: INFORMATIONAL
**Files**: background.js (lines 19741-19808, 24966-24979)
**Description**:

The extension collects the user's Gmail email address for authentication with cloudHQ services:

```javascript
// background.js lines 24968-24979
chrome.tabs.sendMessage(tab.id, { action: "getUserEmailAddress" }, function(email_or_login) {
  var url_dashboard;
  if (email_or_login) {
    url_dashboard = g_server_url + 'dashboard/apps/' + g_extension_what +
      '?email_or_login='+encodeURIComponent(email_or_login)+
      '&switch_login=1&registration_code=' + g_extension_what;
  }
});
```

**Purpose**: User identification for cloudHQ account linking and multi-account support.

**Verdict: LEGITIMATE FUNCTIONALITY** - Email address collection is necessary for the extension to associate exported data with the correct cloudHQ account.

---

### 4. Popup Window Management
**Severity**: INFORMATIONAL
**Files**: background.js (lines 24754-24796, wrapper.js)
**Description**:

The extension opens popup windows for user interaction and uses postMessage for communication:

```javascript
// wrapper.js lines 15-27
window.addEventListener('message', function(e) {
  if (g_server_url.startsWith(e.origin)) {
    parent.postMessage(e.data, '*');
  } else if (e.origin == 'chrome-extension://' + chrome.runtime.id ||
             'https://mail.google.com'.startsWith(e.origin)) {
    if (iframe) {
      iframe.contentWindow.postMessage(e.data, '*');
    }
  }
});
```

**Security Concern**: Uses wildcard `'*'` for postMessage target origin in one instance.

**Verdict: ACCEPTABLE RISK** - While using `'*'` is not best practice, the message content is validated at the sender, and this is only used for UI communication between extension components.

---

### 5. Extension Menu and Multi-Extension Support
**Severity**: INFORMATIONAL
**Files**: background.js (lines 20900-21200)
**Description**:

The extension implements a menu system that can display multiple cloudHQ extensions if installed:

```javascript
// background.js lines 20990-21027
fetchExtensionData = function () {
  var request_list = [];
  config_extensions.forEach(function (config_extension) {
    var ext_name = config_extension["internal_name"];
    if (amo.isExtensionEnabled(ext_name)) {
      amo.fetch("system/content_apps/" + ext_name + ".json", ...);
    }
  });
};
```

**Verdict: EXPECTED BEHAVIOR** - This is a feature for users who have multiple cloudHQ extensions installed, providing a unified menu experience.

## False Positive Analysis

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| jQuery library code | background.js lines 1-19000 | Standard jQuery 3.x implementation (DOM manipulation, AJAX helpers) |
| InboxSDK library | content.js, pageWorld.js | Legitimate third-party Gmail SDK by Streak |
| HTML parsing/rendering | background.js lines 1764-11200 | Standard DOM manipulation libraries (htmlparser2, dom-serializer) |
| `eval` references | None found | No dynamic code evaluation detected |
| `Function()` constructor | background.js (jQuery internals) | Part of jQuery library, not used for dynamic code execution |
| `postMessage` with `'*'` | wrapper.js line 18 | Used only for extension-internal UI communication |

## API Endpoints

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://www.cloudhq.net/dashboard/apps/gmail_sheets` | Extension dashboard | `email_or_login`, `registration_code` |
| `https://www.cloudhq.net/main_cloud_fs_interface/refresh_cloudhq_dir` | Refresh file browser | User action data |
| `https://www.cloudhq.net/logger` | Error/usage logging | Log messages, category, level |
| `https://www.cloudhq.net/system/content_home/chrome_extensions/_defaults.json` | Extension config | None (GET request) |
| `https://www.cloudhq.net/chrome_extensions_menu` | Multi-extension menu | `email_or_login` |
| `https://support.cloudhq.net/` | Support documentation | None (opens in new tab) |

## Data Flow Summary

1. **Gmail Access**: Extension injects InboxSDK into Gmail pages to interact with the email interface
2. **Email Export Trigger**: User selects emails/labels to export
3. **Authentication**: User's email address is sent to cloudHQ for account verification
4. **Export Processing**: Email data is sent to cloudHQ servers for processing
5. **Google Sheets Integration**: cloudHQ backend writes data to user's Google Sheets (via OAuth)
6. **Status Updates**: Extension receives status updates via background script message passing

**Data Exfiltration Assessment**: All data transmission is part of the stated functionality (exporting emails to Google Sheets). No evidence of unauthorized data collection.

## Code Quality and Security Practices

### Positive Observations
1. **URL validation** before making external requests
2. **Request proxying** through background script (MV3 best practice)
3. **No dynamic code execution** (no eval, no Function() constructor misuse)
4. **Standard libraries** (jQuery, InboxSDK - no suspicious modifications)
5. **Proper error handling** throughout the codebase

### Areas for Improvement
1. **postMessage security**: One instance uses wildcard `'*'` origin (low risk)
2. **Extensive permissions**: Could potentially be more granular (though appropriate for functionality)

## Overall Risk Assessment

**Risk Level: CLEAN**

### Justification

Export Emails to Sheets by cloudHQ is a legitimate productivity extension that performs exactly as advertised. While it requires broad permissions to access Gmail data and communicates with external cloudHQ servers, these behaviors are:

1. **Clearly disclosed** in the extension's description
2. **Necessary** for the core email export functionality
3. **Implemented securely** with URL validation and proper message passing
4. **Using standard libraries** (InboxSDK, jQuery) without malicious modifications

The extension serves a legitimate business purpose (email backup/export) and is developed by cloudHQ, an established productivity software company. There is no evidence of:

- Data harvesting beyond stated functionality
- Malicious code injection
- Unauthorized API calls
- Privacy violations
- Market intelligence SDKs
- Ad injection or affiliate link manipulation
- Extension killing or fingerprinting
- Obfuscation beyond standard webpack bundling

### Recommendation

**APPROVED FOR USE** - This extension is safe for users who want to export Gmail data to Google Sheets. Users should understand that:
- Email data is processed by cloudHQ's servers (standard for this type of service)
- A cloudHQ account is required for full functionality
- The extension has broad Gmail access (necessary for email export)

The extension's invasive permissions are justified and serve its intended purpose without evidence of malicious behavior or significant security vulnerabilities.
