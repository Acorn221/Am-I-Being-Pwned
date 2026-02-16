# Vulnerability Report: OrbitNote

## Metadata
- **Extension ID**: feepmdlmhplaojabeoecaobfmibooaid
- **Extension Name**: OrbitNote
- **Version**: 7.0.4
- **Users**: ~7,000,000
- **Developer**: Texthelp
- **Homepage**: https://orbit.texthelp.com
- **Manifest Version**: 3

## Executive Summary

OrbitNote is a legitimate educational PDF annotation and reading extension developed by Texthelp. The extension facilitates opening PDFs in the OrbitNote web application and provides integrations with Google Classroom, Schoology, and Brightspace/D2L learning management systems. After comprehensive security analysis, the extension demonstrates **legitimate educational functionality with appropriate permissions for its intended purpose**. While it has broad permissions and makes network requests, all functionality aligns with its stated purpose of PDF document management and educational platform integration.

**Risk Level: CLEAN**

The extension is invasive by necessity (requiring broad host permissions for PDF interception and LMS integrations) but serves its intended purpose without malicious behavior. Data handling is limited to Google Drive OAuth integration and educational platform functionality.

## Vulnerability Analysis

### 1. Permissions Analysis - LOW CONCERN
**Severity**: Informational
**File**: `manifest.json`
**Lines**: 24-40

**Finding**:
The extension requests extensive permissions:
- `webRequest` - For intercepting PDF downloads
- `scripting`, `tabs`, `webNavigation` - For content injection
- `gcm` - For Google Cloud Messaging (feature flags/updates)
- `identity`, `identity.email` - For Google OAuth
- `host_permissions`: `https://*/*`, `http://*/*` - Broad access

**Code**:
```json
"permissions": [
    "webRequest", "scripting", "tabs", "gcm", "idle", "alarms",
    "webNavigation", "storage", "identity", "identity.email"
],
"host_permissions": [
    "https://www.google-analytics.com/",
    "https://*/*",
    "http://*/*"
]
```

**Analysis**:
These permissions are necessary for the extension's core functionality:
- PDF interception requires `webRequest` to detect PDF content-type headers
- LMS integrations (Classroom, Schoology, Brightspace) require `scripting` and broad host permissions
- Google Drive integration requires `identity` for OAuth

**Verdict**: **FALSE POSITIVE** - Permissions align with stated functionality. Extension intercepts PDF downloads to redirect to OrbitNote web app and integrates with educational platforms.

---

### 2. Google Cloud Messaging (GCM) - LOW CONCERN
**Severity**: Informational
**File**: `background/Messaging/GCMMessaging.js`
**Lines**: 12-505

**Finding**:
Extension implements GCM-based messaging system to receive feature flags and configuration updates from `messaging.texthelp.com`.

**Code**:
```javascript
this._messagingUrl = 'https://messaging.texthelp.com/';
this._senderId = [database];

chrome.gcm.register(this._senderId, (registrationId) => {
    // Register with service
    this._registerIdWithService(registrationId, topic, callback);
});

chrome.gcm.onMessage.addListener((message) => {
    var response = JSON.parse(message.data.message);
    if (response.message.application !== 'rw4gc') return;
    // Process disabled features
    var lastMessage = this._parseMessageDoc(response);
});
```

**Analysis**:
- GCM is used for "datadesk" feature flag system
- Messages contain `disabled-features` arrays to control extension behavior
- Only accepts messages where `application === 'rw4gc'`
- Sets expiration alarms for timed feature flags
- No evidence of remote code execution or malicious commands

**Verdict**: **FALSE POSITIVE** - Standard enterprise feature flag system for managing extension behavior across deployments. Common pattern for educational software with managed deployments.

---

### 3. PDF Interception and Redirection - LOW CONCERN
**Severity**: Informational
**File**: `background/pdfHandler.js`
**Lines**: 20-100

**Finding**:
Extension intercepts PDF downloads using `webRequest.onHeadersReceived` and can redirect to OrbitNote web application.

**Code**:
```javascript
var VIEWER_URL = 'https://orbit.texthelp.com';

function getViewerURL(pdf_url) {
    return VIEWER_URL + '?file=' + encodeURIComponent(pdf_url);
}

chrome.webRequest.onHeadersReceived.addListener(
    function (details) {
        if (isPdfFile(details)) {
            IsOptionPdfAutoRedirect().then(autoRedirect => {
                if (autoRedirect) {
                    return {redirectUrl: getViewerURL(details.url)};
                }
            });
        }
    }
);
```

**Analysis**:
- Only intercepts GET requests for PDF files (checks `content-type: application/pdf`)
- User-controlled setting `defaultOpenWebPagePDF` controls auto-redirect (default: false)
- Redirects to legitimate Texthelp domain
- No modification of PDF content
- No interception of non-PDF traffic

**Verdict**: **FALSE POSITIVE** - Core functionality for opening PDFs in OrbitNote. User has control via settings.

---

### 4. Content Script Injection - LOW CONCERN
**Severity**: Informational
**Files**: `content-scripts/schoology/contentScript.js`, `content-scripts/classroom/contentScript.js`, `content-scripts/brightspace/texthelpbrightspace.js`

**Finding**:
Extension injections content scripts into learning management system (LMS) pages to add "Open with OrbitNote" buttons.

**Code Example** (Schoology):
```javascript
var textHelpButton = document.createElement('div');
textHelpButton.innerHTML = `
    <div class="app-logo-container">
        <img class="app-logo" src="chrome-extension://feepmdlmhplaojabeoecaobfmibooaid/Chrome/Icons/orbitnote-icon-32x32.png">
    </div>
    <div class="app-title">OrbitNote</div>
`;
textHelpButton.addEventListener("click", function (t) {
    // Opens assignment in OrbitNote
});
```

**Analysis**:
- Content scripts only inject UI elements (buttons, icons)
- Google Classroom integration: Adds "Open with OrbitNote" option for PDFs
- Schoology integration: Adds submission/assignment handling
- Brightspace/D2L integration: Adds file opening functionality
- No credential harvesting or form manipulation
- Limited to educational platform domains

**Verdict**: **FALSE POSITIVE** - Expected LMS integration features for educational workflow.

---

### 5. Google Drive OAuth Integration - LOW CONCERN
**Severity**: Informational
**File**: `manifest.json`, `schoologyOpen/bundle.js`
**Lines**: OAuth scopes 162-167

**Finding**:
Extension requests Google Drive OAuth scopes for file access.

**Code**:
```json
"oauth2": {
    "client_id": "243341882805-fav9vbuf7c132v7lkvav10h32o5gds7q.apps.googleusercontent.com",
    "scopes": [
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/drive.file",
        "https://www.googleapis.com/auth/drive.readonly"
    ]
}
```

**Bundle.js Drive API Calls**:
```javascript
xhr.open("POST", "https://www.googleapis.com/upload/drive/v2/files?uploadType=multipart", true);
xhr.open("GET", "https://www.googleapis.com/drive/v3/files/?" + driveQuery.build(), true);
```

**Analysis**:
- `drive.file` scope - Access to files created/opened by the app (not all files)
- `drive.readonly` - Read-only access to Drive files
- Used for Schoology assignment workflow (downloading PDFs, uploading completed work)
- Google Classroom integration fetches PDF files via Drive API
- Standard OAuth flow, no token theft observed

**Verdict**: **FALSE POSITIVE** - Necessary for Google Classroom integration where assignments are stored in Drive.

---

### 6. Shadow DOM Injection - LOW CONCERN
**Severity**: Informational
**File**: `content-scripts/global/contentScript.js`
**Lines**: 37-85

**Finding**:
Extension attempts to access closed shadow roots using `chrome.dom.openOrClosedShadowRoot` API.

**Code**:
```javascript
function checkForClosedShadowRoot() {
    const shadowRoot = chrome.dom.openOrClosedShadowRoot(document.body);
    const iframe = shadowRoot.querySelector("iframe");

    const isValidPDFViewer = shadowRoot.mode === "closed" &&
                            iframe &&
                            iframe.getAttribute("type") === "application/pdf";

    if (isValidPDFViewer) {
        return { detected: true, pdfUrl: window.location.href, method: "shadow-root" };
    }
}
```

**Analysis**:
- Used to detect Chrome's built-in PDF viewer (which uses closed shadow DOM)
- Only purpose is to inject "Open with OrbitNote" button
- Does not modify PDF content or exfiltrate data
- Gracefully handles API unavailability

**Verdict**: **FALSE POSITIVE** - Legitimate use case for detecting PDF viewer to add functionality button.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| Axios library | `content-scripts/schoology/js/axios.js` | Minified v0.19.0 library for HTTP requests in Schoology integration |
| `innerHTML` usage | Multiple content scripts | Limited to injecting static UI buttons/tooltips, no user input |
| `postMessage` | Content scripts | Only for communication between extension contexts and OrbitNote web app |
| Broad host permissions | `manifest.json` | Required for PDF interception on any domain and LMS integrations |
| `chrome.tabs.query({})` | `background/index.js` | Used to broadcast feature flag updates to all tabs |
| `addEventListener('message')` | Content scripts | Only listens for messages from OrbitNote domain (origin validation) |

## API Endpoints Table

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `messaging.texthelp.com/getlastmessage/v1` | Fetch feature flags | User topic ID | LOW - Config only |
| `messaging.texthelp.com/registertoken/v1` | Register GCM token | GCM registration ID, topic | LOW - Push notification setup |
| `orbit.texthelp.com` | PDF viewer webapp | PDF URL (parameter) | LOW - Core functionality |
| `www.googleapis.com/drive/*` | Drive API | OAuth token, file IDs | LOW - Standard Drive integration |
| `www.google-analytics.com` | Analytics (declared) | Unknown | LOW - Standard analytics |

## Data Flow Summary

1. **PDF Interception Flow**:
   - `webRequest` detects PDF → Injects button OR redirects to `orbit.texthelp.com?file=[url]`
   - User sees "Open with OrbitNote" button
   - Click redirects to OrbitNote web app with PDF URL as parameter

2. **LMS Integration Flow**:
   - Content script detects Classroom/Schoology/Brightspace page
   - Injects UI elements (buttons, icons)
   - User clicks → Extension uses Drive API (Classroom) or native LMS API to fetch file
   - Opens file in OrbitNote web app

3. **Feature Flag Flow**:
   - Background script registers with GCM (sender ID: 224182583415)
   - Receives messages from `messaging.texthelp.com`
   - Parses `disabled-features` array
   - Broadcasts to all tabs via `chrome.tabs.sendMessage`

4. **Data Sent to Remote Servers**:
   - **messaging.texthelp.com**: User topic ID (likely hashed email), GCM token
   - **orbit.texthelp.com**: PDF URLs (as query parameters)
   - **googleapis.com**: OAuth tokens, Drive file IDs (standard Drive API)

**No sensitive data harvesting observed.** Extension does not:
- Intercept form submissions
- Access passwords or cookies
- Capture keystrokes
- Exfiltrate browsing history
- Inject ads or tracking pixels

## Security Recommendations

1. **Analytics Transparency**: The extension declares `google-analytics.com` in host_permissions but no analytics initialization code was found in deobfuscated files. Clarify if analytics is used or remove permission.

2. **CSP Enhancement**: Current CSP allows `script-src 'self'` which is secure. Consider adding `connect-src` restrictions to whitelist only Texthelp and Google domains.

3. **GCM Feature Flags**: The feature flag system allows remote disabling of features. While no dangerous commands were found, document what features can be controlled remotely for transparency.

4. **OAuth Scope Minimization**: Consider if `drive.readonly` scope is necessary alongside `drive.file` (which already provides access to files opened by the app).

## Overall Risk Assessment

**Risk Level: CLEAN**

**Justification**:
OrbitNote is a legitimate educational tool by Texthelp (established edtech company). All invasive permissions serve documented purposes:
- Broad host permissions enable PDF interception across all sites (core feature)
- LMS integrations require scripting access to Classroom/Schoology/Brightspace
- Google Drive access is standard for Classroom integrations
- GCM messaging is a standard enterprise feature flag system

The extension does not exhibit malicious behavior patterns:
- ❌ No ad injection
- ❌ No credential harvesting
- ❌ No keystroke logging
- ❌ No residential proxy functionality
- ❌ No extension enumeration/killing
- ❌ No XHR/fetch hooking for MITM
- ❌ No cookie exfiltration
- ❌ No obfuscated/packed code (beyond Webpack bundling)
- ❌ No remote code execution vectors

**This extension is CLEAN for its intended educational use case.** The invasive permissions are justified by the need to intercept PDFs across all websites and integrate with multiple learning management systems. Data handling is limited to necessary OAuth flows and configuration management.

Users should be aware that the extension:
1. Can redirect PDF downloads to OrbitNote (optional, disabled by default)
2. Integrates with their Google Drive (for Classroom assignments)
3. Receives feature configuration from Texthelp servers
4. Has visibility into PDF URLs accessed (inherent to functionality)
