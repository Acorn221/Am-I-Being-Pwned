# Vulnerability Analysis Report: Hippo Video Extension

## Extension Metadata
- **Extension Name**: Hippo Video: Video and Screen Recorder
- **Extension ID**: cijidiollmnkegoghpfobabpecdkeiah
- **User Count**: ~80,000
- **Manifest Version**: 3
- **Version**: 4.0.43

## Executive Summary

Hippo Video is a legitimate screen recording and video sharing extension with extensive permissions and integrations. The analysis identified **MEDIUM** risk concerns primarily around LinkedIn cookie harvesting, broad host permissions, and extensive AWS telemetry logging. No critical vulnerabilities or malicious code patterns were detected, but the extension's extensive data access and logging capabilities warrant scrutiny.

**Overall Risk Level**: MEDIUM

## Vulnerability Details

### 1. LinkedIn Cookie Harvesting (MEDIUM Severity)

**File**: `background.bundle.js` (lines 10816-10873)

**Description**: The extension harvests LinkedIn session cookies (`li_at`, `JSESSIONID`) and user profile data when triggered by a `get_linkedin_profile_details` message.

**Code Evidence**:
```javascript
chrome.cookies.getAll({
  url: "https://www.linkedin.com/"
}, (function(e) {
  // Extracts JSESSIONID and li_at cookies
  "JSESSIONID" === e[s].name && (r = i),
  "li_at" === e[s].name && (o = i)

  // Makes authenticated API call to LinkedIn
  var c = new Request("https://www.linkedin.com/voyager/api/me", {
    method: "GET",
    headers: a,
    mode: "cors",
    credentials: "include"
  });
```

**Verdict**: CONCERNING - While this appears to be a legitimate integration feature for LinkedIn video personalization, it requires user opt-in via `optional_permissions: ["cookies"]` and `optional_host_permissions: ["https://www.linkedin.com/"]`. The extension harvests sensitive authentication tokens that could be used for session hijacking if exfiltrated. The manifest shows this is optional, requiring user consent before activation.

---

### 2. Broad Host Permissions (MEDIUM Severity)

**File**: `manifest.json`

**Description**: Extension requests `<all_urls>` in `host_permissions`, granting access to all websites.

**Code Evidence**:
```json
"host_permissions":["<all_urls>"]
```

**Verdict**: CONCERNING - While necessary for a screen recorder that needs to inject UI on any page, this permission grants the extension ability to read/modify all web content. The content script injection uses this for legitimate recorder functionality (toolbar, webcam overlay, etc.) but represents a significant attack surface if compromised.

---

### 3. Extensive AWS Telemetry Logging (MEDIUM Severity)

**File**: `background.bundle.js` (lines 10280-10520)

**Description**: Extension implements comprehensive logging infrastructure using AWS Kinesis Firehose to send telemetry data including user actions, errors, browser info, and URLs.

**Code Evidence**:
```javascript
class fu {
  constructor({ module, integrationType, assetId, logUID, tokenType, token, email }) {
    this.logger = new Yc({ token, tokenType, email });
    this.firehoseClient = new Gc(config);
  }

  _logData(e, t, n) {
    n[REQUEST_PATH] = location ? location.href : "Unable to locate request path";
    n[REQUEST_BROWSER] = navigator.userAgent;
    n[USER_ID] = this._getUserId();
    this._pushLogRecord(n);
  }

  async _pushLogRecord(e, t) {
    await this._getFederateTokenAndUpdateConfig();
    const r = new Ds(n); // PutRecordCommand
    await this.firehoseClient.send(r);
  }
}
```

**Verdict**: ACCEPTABLE - This is standard application logging/analytics. The extension uses AWS Cognito for federated credentials and sends logs to Kinesis Firehose stream. Data includes URLs visited, user IDs, browser info, and error traces. While extensive, this is typical for SaaS video platforms that need analytics. No evidence of PII exfiltration beyond standard product telemetry.

---

### 4. Chrome Extension Management API Usage (LOW Severity)

**File**: `background.bundle.js` (lines 10950-10958)

**Description**: Extension monitors its own enable/disable state.

**Code Evidence**:
```javascript
chrome.management.onDisabled.addListener((function(e) {
  chrome.runtime.id == e.id && function() {
    a("hippo_auth"); // Clears auth on disable
  }()
}))
```

**Verdict**: ACCEPTABLE - Only monitors its own extension state to clear authentication when disabled. No enumeration of other extensions detected.

---

### 5. Dynamic Integration Configuration (LOW Severity)

**File**: `background.bundle.js` (lines 11004-11156)

**Description**: Extension fetches dynamic integration configurations from remote servers for third-party CRM/sales platforms.

**Code Evidence**:
```javascript
chrome.storage.local.get(["dynamicIntegUrls"], (function(e) {
  chrome.storage.local.get(["dynamicIntegConfigurations"], (function(n) {
    // Loads configurations for Salesforce, HubSpot, Pipedrive, etc.
  }))
}))
```

**Verdict**: ACCEPTABLE - Legitimate feature allowing the extension to integrate with 20+ platforms (Salesforce, HubSpot, Gmail, Slack, etc.) without requiring extension updates. Configurations stored locally after download. No evidence of remote code execution.

---

## False Positive Analysis

| Pattern | File | Verdict |
|---------|------|---------|
| `innerHTML` usage | contentScript.bundle.js | React DOM manipulation - standard framework pattern |
| `dangerouslySetInnerHTML` | contentScript.bundle.js | React prop - controlled usage in framework |
| `eval` patterns | None detected | No dynamic code execution found |
| AWS SDK imports | background.bundle.js | Legitimate AWS SDK for Cognito/Firehose logging |
| `chrome.cookies` | background.bundle.js | Optional permission for LinkedIn integration only |
| `chrome.management` | background.bundle.js | Self-monitoring only, no competitor enumeration |

## API Endpoints Summary

All endpoints point to legitimate Hippo Video infrastructure:

| Domain | Purpose | Evidence |
|--------|---------|----------|
| `hippovideo.io` | Primary backend | Video upload, auth, user management |
| `hippowiz.com` | Legacy domain | Dynamic configurations |
| `das.io` | Unknown subdomain | Listed in `externally_connectable` |
| `hippovideo.us` | Regional endpoint | Listed in manifest |
| `hippovideo.ai` | AI features | Listed in manifest |
| `hippovideo.online` | Alt domain | Listed in manifest |

**Key API Calls**:
- `/api/user/token_valid.json` - Authentication validation
- `/api/user/get_federated_aws_token` - AWS Cognito credentials
- `/video/guest/*` - Guest/unauthenticated video operations
- `/video/delivery/user_info` - User profile data
- `/google_api/drive/configure` - Google Drive integration
- `/google_api/gmail/configure` - Gmail integration

## Data Flow Summary

1. **Authentication Flow**:
   - User authenticates via Google OAuth2 (`client_id: 975749760800-...`)
   - Extension stores `hippo_auth` token in `chrome.storage.local`
   - Token used for API requests to `hippovideo.io`

2. **Recording Flow**:
   - Uses `tabCapture` permission for screen recording
   - Optional webcam access via `camera` permission (user-prompted)
   - Uploads video to `hippovideo.io/video` endpoints
   - Stores recording metadata in AWS S3 (inferred from AWS SDK usage)

3. **Telemetry Flow**:
   - Extension logs user actions, errors, performance metrics
   - Fetches AWS Cognito federated token from backend
   - Pushes logs to AWS Kinesis Firehose stream
   - Data includes: URLs, browser UA, user ID, timestamps, event types

4. **LinkedIn Integration** (Optional):
   - Requires explicit user permission for `cookies` and LinkedIn host
   - Harvests `li_at` session cookie when user enables LinkedIn features
   - Fetches user profile from LinkedIn Voyager API
   - Likely used for video personalization/signature features

## Permission Analysis

**Manifest Permissions**:
- `tabCapture` - Screen recording (necessary)
- `tabs` - Tab management for recording UI (necessary)
- `activeTab` - Current tab access (necessary)
- `storage` - Settings/auth storage (necessary)
- `scripting` - Content script injection (necessary)
- `identity` - Google OAuth (necessary)
- `management` - Self-monitoring only (acceptable)

**Optional Permissions** (require user consent):
- `cookies` - LinkedIn integration only
- `https://www.linkedin.com/` - LinkedIn integration only

**Host Permissions**:
- `<all_urls>` - Broad but necessary for screen recorder that injects UI on any page

## Security Recommendations

1. **LinkedIn Cookie Access**: While currently optional, implement additional safeguards:
   - Clear session cookies after use
   - Implement token rotation
   - Add explicit user notification when accessing LinkedIn cookies

2. **Telemetry Scope**: Consider:
   - Anonymizing URLs before logging
   - Providing opt-out mechanism for telemetry
   - Documenting what data is logged in privacy policy

3. **CSP Implementation**: Manifest v3 extension lacks explicit Content Security Policy - recommend adding:
   ```json
   "content_security_policy": {
     "extension_pages": "script-src 'self'; object-src 'self'"
   }
   ```

4. **Permission Justification**: Document in-product why `<all_urls>` is required to reduce user suspicion.

## Overall Risk Assessment

**Risk Level**: MEDIUM

**Rationale**:
- Legitimate video recording extension with expected permissions
- LinkedIn cookie harvesting is concerning but mitigated by optional permissions
- No evidence of malicious behavior, code obfuscation, or data exfiltration beyond standard telemetry
- Extensive logging could expose user browsing patterns but appears to be product analytics
- No extension enumeration, proxy infrastructure, or ad injection detected
- No AI conversation scraping or market intelligence SDK integration

**Threats**:
- If Hippo Video servers compromised, attacker could access LinkedIn sessions for opted-in users
- AWS telemetry logs contain browsing history (URL paths)
- Broad host permissions create large attack surface if extension compromised

**Mitigations**:
- LinkedIn integration requires explicit user opt-in
- Standard AWS security model (Cognito federated credentials)
- No dynamic code execution or remote configuration of executable code
- Content scripts are bundled (not loaded from CDN)

## Conclusion

Hippo Video is a legitimate commercial video recording extension with standard SaaS telemetry practices. The LinkedIn cookie harvesting feature is the primary concern but is appropriately gated behind optional permissions. Recommend monitoring for changes to cookie access patterns or expansion of LinkedIn data harvesting in future versions.
