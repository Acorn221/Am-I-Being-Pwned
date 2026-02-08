# Vulnerability Report: Save Emails to Drive by cloudHQ

## Extension Metadata
- **Extension Name**: Save Emails to Drive by cloudHQ
- **Extension ID**: glgaegbgegomicnedooifcbnmppmofkf
- **Version**: 1.0.2.18
- **User Count**: ~40,000
- **Developer**: cloudHQ (https://www.cloudhq.net)
- **Manifest Version**: 3

## Executive Summary

Save Emails to Drive is a legitimate Gmail extension developed by cloudHQ that enables users to save Gmail emails to Google Drive in multiple formats (PDF, HTML, EML, TXT). The extension integrates with Gmail using the InboxSDK framework and communicates with cloudHQ's backend infrastructure to facilitate email-to-drive synchronization.

**Overall Risk Assessment**: **CLEAN**

While the extension requires extensive permissions and processes sensitive email data through external servers, this is necessary for its core functionality. The extension demonstrates appropriate security controls including URL validation, proper manifest permissions scoping, and standard OAuth flows. No malicious behavior, hidden functionality, or exploitable vulnerabilities were identified.

## Technical Analysis

### Manifest Permissions & CSP

**Declared Permissions**:
- `scripting` - For injecting InboxSDK page world script
- `storage` - For storing user preferences and install timestamp
- `background` - Service worker execution

**Host Permissions**:
- `https://mail.google.com/` - Gmail integration (legitimate)
- `https://inbox.google.com/` - Legacy Inbox support
- `https://www.cloudhq.net/` - Backend API communication

**Content Security Policy**: None explicitly declared (relies on MV3 defaults)

**Externally Connectable**: `*://*.cloudhq.net/*` - Allows cloudHQ domains to communicate with extension

**Assessment**: Permissions are appropriately scoped for the extension's stated functionality. All host permissions align with legitimate use cases.

### Background Script Analysis

**File**: `background.js` (25,038 lines, webpack bundled)

**Key Components**:
1. **InboxSDK Injection Handler** (Lines 19237-19269)
   - Responds to `inboxsdk__injectPageWorld` messages
   - Injects `pageWorld.js` into Gmail using MV3 `chrome.scripting.executeScript`
   - Properly validates sender context with `documentId`/`frameId`

2. **AJAX Proxy Handler** (Lines 24695-24733)
   ```javascript
   chrome.runtime.onMessage.addListener(function(input_request, sender, sendResponse) {
     if (input_request.what == 'PROXY_AJAX') {
       var out_request = input_request.payload;
       if (!out_request['url'] || !out_request['url'].startsWith(g_server_url)) {
         sendResponse({ what: 'error', payload: 'Invalid request' });
         return;
       }
   ```
   - **Security Control**: Validates all requests must target `g_server_url` (https://www.cloudhq.net/)
   - Prevents SSRF by rejecting requests to arbitrary domains
   - Acts as controlled proxy for content script XHR

3. **Port-based Communication** (Lines 24735-24893)
   - Manages popup window lifecycle for save dialogs
   - Handles message passing between Gmail tab and popup windows
   - Implements cleanup on disconnect

4. **Extension Icon Click Handler** (Lines 24956-24989)
   - Opens cloudHQ dashboard with user context
   - Retrieves user email via `getUserEmailAddress` message to content script
   - Constructs URL: `https://www.cloudhq.net/dashboard/apps/save_to_googledrive?email_or_login=...`

5. **Install/Update Lifecycle** (Lines 24991-25013)
   - Refreshes Gmail tabs on install
   - Stores install timestamp in chrome.storage.sync
   - Sets uninstall URL: `https://www.cloudhq.net/uninstall_chrome_extension?product_what=save_to_googledrive`

**Global Variables**:
- `g_server_url = "https://www.cloudhq.net/"`
- `g_extension_what = "save_to_googledrive"`

**Verdict**: No malicious behavior. URL validation prevents request hijacking. Standard extension lifecycle management.

### Content Script Analysis

**File**: `content.js` (90,455 lines, webpack bundled with InboxSDK)

**Key Components**:

1. **InboxSDK Integration** (~46,000 lines)
   - Official InboxSDK library (https://www.inboxsdk.com/)
   - Provides Gmail UI manipulation framework
   - Handles compose views, message views, thread views
   - Includes OAuth token management for InboxSDK events API

2. **CloudHQ File Browser** (Lines 80850-81260)
   - Implements Google Drive file picker UI
   - API Endpoints:
     - `POST /main_cloud_fs_interface/cloudhq_dir` - List Drive folders/files
     - `POST /main_cloud_fs_interface/refresh_cloudhq_dir` - Refresh directory
     - `POST /main_cloud_fs_interface/cloudhq_init` - Initialize connection
   - Data sent: folder metadata, user preferences, file selection

3. **Email Save Functionality** (Lines 84350-84450)
   ```javascript
   message_view.getMessageIDAsync().then(function (message_id) {
     request_data['message_id'] = message_id;
     c_cmn.fn_ajax({
       url: cgo.g_server_url + 'main_gmail_save_eml/chrome_extension_save_eml_to_gmail',
       dataType: "json",
       data: request_data,
       type: 'POST',
   ```
   - Retrieves Gmail message ID using InboxSDK methods
   - Sends message ID (not full email content) to cloudHQ backend
   - Backend presumably fetches email via Gmail API using user's OAuth token
   - Response indicates success and provides label name

4. **Authentication & User Management** (Lines 23316-23420 in background.js, called from content)
   - Endpoint: `POST /main_pre_user/check` - Verify user login status
   - Endpoint: `POST /chrome_extension_login_or_signup_dialog` - Show login UI
   - Sends: email address, account switcher list, chrome extension name
   - Standard OAuth-based authentication flow

5. **AJAX Proxy Pattern**
   ```javascript
   function fn_ajax(params) {
     chrome.runtime.sendMessage({ what: 'PROXY_AJAX', payload: params }, function (r) {
   ```
   - All network requests proxied through background script
   - Background validates URLs before execution
   - Prevents direct content script network access

**Data Access**:
- Gmail message IDs (via InboxSDK `getMessageIDAsync()`)
- Thread IDs
- User email address
- Gmail UI state (conversation view, timezone, language)
- **Does NOT directly access email body content in extension code**

**Verdict**: Appropriate data access for stated functionality. Email content access delegated to backend (user must authorize cloudHQ OAuth). No exfiltration of sensitive data beyond message IDs.

### Page World Script Analysis

**File**: `pageWorld.js` (20,655 lines)

**Purpose**: InboxSDK framework injected into Gmail's main page context to access Gmail's internal APIs

**Key Functionality**:
- Provides DOM manipulation in Gmail's context
- Accesses Gmail's internal data structures
- Communicates with content script via `window.postMessage`
- Standard InboxSDK implementation (used by many legitimate Gmail extensions)

**Verdict**: Standard InboxSDK page world injection. No custom malicious code detected.

## API Endpoints Summary

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `/main_cloud_fs_interface/cloudhq_dir` | POST | List Drive folders | folder metadata, file_flag |
| `/main_cloud_fs_interface/refresh_cloudhq_dir` | POST | Refresh Drive folder | folder metadata |
| `/main_cloud_fs_interface/cloudhq_init` | POST | Initialize Drive connection | service selection flags |
| `/main_gmail_save_eml/chrome_extension_save_eml_to_gmail` | POST | Save email to Drive | message_id |
| `/main_pre_user/check` | POST | Check user auth status | email, account list |
| `/chrome_extension_login_or_signup_dialog` | GET | Get login UI | login context |
| `/dashboard/apps/save_to_googledrive` | GET | Extension dashboard | email_or_login, registration_code |
| `/uninstall_chrome_extension` | GET | Uninstall feedback | product_what |

**Base URL**: `https://www.cloudhq.net/`

**Validation**: All requests validated in background script to ensure they target cloudHQ domain only.

## Security Concerns & Mitigations

### 1. Email Data Processing Through External Servers
**Concern**: Email message IDs sent to cloudHQ backend
**Severity**: Medium (by design)
**Mitigation**: This is the core functionality - users explicitly authorize cloudHQ to access their Gmail via OAuth. Extension sends message IDs (not full content) which backend retrieves via Gmail API.
**Verdict**: NOT a vulnerability - legitimate architectural pattern for cloud-based email tools

### 2. InboxSDK Framework
**Concern**: Third-party SDK with broad Gmail access
**Severity**: Low
**Mitigation**: InboxSDK is an industry-standard framework used by major Gmail extensions (Streak, Boomerang, etc.). Open source and well-audited.
**Verdict**: Acceptable use of established framework

### 3. User Email Address Collection
**Concern**: Extension retrieves and sends user email address to backend
**Severity**: Low
**Mitigation**: Required for multi-account support and user identification. Standard practice for account-based extensions.
**Verdict**: Necessary for functionality

### 4. Extensive Permissions
**Concern**: Access to all Gmail data via host_permissions
**Severity**: Low
**Mitigation**: Permissions scoped to specific domains (mail.google.com, cloudhq.net). Required for Gmail integration and backend communication.
**Verdict**: Appropriately scoped

## Vulnerability Assessment

### No Vulnerabilities Identified

After comprehensive analysis, **no security vulnerabilities or malicious behavior were found**:

✅ **No dynamic code execution** (eval, Function constructor)
✅ **No credential harvesting** beyond standard OAuth flow
✅ **No keylogging or input monitoring**
✅ **No ad/coupon injection**
✅ **No extension enumeration or killing**
✅ **No XHR/fetch hooking** (proxying is controlled, not hooking)
✅ **No residential proxy infrastructure**
✅ **No market intelligence SDKs** (Sensor Tower, Pathmatics, etc.)
✅ **No AI conversation scraping**
✅ **No obfuscation** (webpack bundling is standard, code is readable)
✅ **No kill switches or remote config abuse**
✅ **Proper SSRF protection** via URL validation in background script

## False Positives

| Pattern | Context | Reason for False Positive |
|---------|---------|---------------------------|
| `innerHTML` usage (101 instances) | InboxSDK framework, jQuery | Standard DOM manipulation for UI rendering |
| `XMLHttpRequest` usage | InboxSDK CORB workaround, jQuery | Legitimate network requests, proxied through validated background |
| `postMessage` calls | InboxSDK page-content communication | Standard cross-context messaging pattern |
| `cookie` references (56 instances) | jQuery library internals | Library cookie utilities, not active harvesting |
| OAuth token handling | InboxSDK events API | InboxSDK's own analytics, not extension malware |
| `password` input type | jQuery form handling | Library support for form inputs, not credential theft |

## Data Flow Summary

```
User clicks "Save to Drive" in Gmail
    ↓
Content script calls InboxSDK getMessageIDAsync()
    ↓
Content script sends message ID to background via chrome.runtime.sendMessage
    ↓
Background validates URL and proxies AJAX to https://www.cloudhq.net/main_gmail_save_eml/...
    ↓
CloudHQ backend receives message ID
    ↓
Backend fetches full email via Gmail API (using user's pre-authorized OAuth token)
    ↓
Backend saves email to user's Google Drive
    ↓
Response sent back to content script
    ↓
UI notification displayed to user
```

**Key Security Properties**:
- Extension never handles full email content directly
- All sensitive operations delegated to backend with user OAuth authorization
- AJAX proxy prevents SSRF and enforces domain whitelist
- No local storage of email data

## Overall Risk Assessment

**Risk Level**: **CLEAN**

**Justification**:
This is a legitimate, well-architected Gmail extension that performs its stated function (saving emails to Google Drive) without security vulnerabilities or hidden malicious behavior. While it requires extensive permissions and processes sensitive email data, this is:

1. **Necessary for functionality**: Cannot save emails without accessing Gmail and communicating with backend
2. **Transparent to users**: Clearly described in extension description and permissions
3. **User-authorized**: Requires explicit OAuth consent for Gmail/Drive access
4. **Properly implemented**: Includes SSRF protection, URL validation, appropriate permission scoping
5. **Industry-standard architecture**: Uses established patterns (InboxSDK, OAuth, message proxying)

The extension demonstrates responsible security practices including input validation, permission minimization, and separation of concerns between content scripts and background service worker.

**Recommendation**: CLEAN - Safe for users who understand and accept cloudHQ's data processing model (emails processed through external servers).

---

**Report Generated**: 2025-02-08
**Analysis Depth**: Comprehensive (manifest, background script, content script, page world, API endpoints, data flows)
**Code Coverage**: 136,148 lines analyzed across 3 JavaScript files
