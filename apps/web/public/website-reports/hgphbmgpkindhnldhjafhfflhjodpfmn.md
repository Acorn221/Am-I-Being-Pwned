# Security Analysis Report: Powtoon Capture - Screen and Webcam Recorder

## Extension Metadata
- **Extension ID**: hgphbmgpkindhnldhjafhfflhjodpfmn
- **Extension Name**: Powtoon Capture - Screen and Webcam Recorder
- **Version**: 3.0.7
- **User Count**: ~60,000
- **Manifest Version**: 3
- **Developer**: apps@powtoon.com

## Executive Summary

Powtoon Capture is a legitimate screen and webcam recording extension for Chrome developed by Powtoon Ltd. The extension has been analyzed for potential security vulnerabilities and malicious behavior. While the extension has broad permissions as expected for screen recording functionality, no evidence of malicious activity, data exfiltration beyond normal operation, or intentional security vulnerabilities was found.

**Overall Risk Assessment: LOW**

The extension operates as advertised - a screen/webcam recording tool that uploads recordings to Powtoon's servers. All network communication is limited to legitimate Powtoon domains for authentication, video upload, and analytics.

## Manifest Analysis

### Permissions Requested
```json
{
  "permissions": [
    "notifications",      // Display recording status notifications
    "cookies",           // Manage Powtoon authentication cookies
    "offscreen",         // For video processing
    "storage",           // Store user preferences and session data
    "scripting",         // Inject content scripts for UI overlay
    "system.display"     // Get display information for recording
  ],
  "host_permissions": [
    "<all_urls>",        // Required to record any website
    "https://*.powtoon.com/*"  // Access Powtoon services
  ]
}
```

### Permission Analysis
- **<all_urls>**: High privilege but necessary for screen recording functionality - extension needs to inject recording UI overlays on any site
- **cookies**: Used only for Powtoon authentication (csrftoken, sessionid)
- **scripting**: Required to inject camera/recording UI overlays
- All permissions align with stated functionality

### Content Security Policy
```json
"extension_pages": "script-src 'self'; style-src 'self' 'unsafe-inline' https://*.typekit.net; object-src 'self'"
```
- **Assessment**: Good security posture
- Only allows scripts from extension itself
- Unsafe inline styles permitted (common for React apps, low risk)
- Allows Adobe Typekit fonts (legitimate typography service)

### Externally Connectable
```json
{
  "ids": ["*"],
  "matches": [
    "*://localhost/*",
    "*://*.powtoon.com/*"
  ]
}
```
- **Concern**: `"ids": ["*"]` allows any extension to connect
- **Mitigation**: Only localhost and powtoon.com domains can make web connections
- **Risk**: Low - primarily for development and Powtoon web integration

## Code Analysis

### Background Script (background.bundle.js - 19,441 lines)

#### API Endpoints
All network traffic is directed to legitimate Powtoon domains:
```javascript
API_ENDPOINT: "https://www.powtoon.com"
API_ENDPOINT_BI_EVE: "https://trek.powtoon.com/event.gif"  // Analytics endpoint

Endpoints used:
- /api/v2/user/me/permissions
- /api/v2/capture/settings
- /api/v2/org/settings
- /api/v2/user/me/profile
- /api/v2/domain-info (for enterprise subdomain validation)
```

#### Chrome API Usage
```javascript
// Standard extension operations
- chrome.runtime.* (messaging, getURL, getManifest)
- chrome.storage.local.* (store settings, session data, CSRF token)
- chrome.cookies.* (manage Powtoon auth cookies for www.powtoon.com)
- chrome.tabs.* (query, create tabs)
- chrome.action.* (set icon, handle clicks)
- chrome.scripting.executeScript (inject content scripts for recording UI)
- chrome.notifications.create (show recording status)
- chrome.offscreen.createDocument (video processing)
```

#### Authentication & Session Management
The extension uses standard web authentication:
1. Checks login status via `GET /api/v2/user/me/profile`
2. Reads cookies: `csrftoken`, `sessionid`, `last_activity_timestamp`
3. Includes `x-csrftoken` header in API requests (CSRF protection)
4. Opens Powtoon login page if user not authenticated

**Security Note**: Cookie access is limited to `*.powtoon.com` domain only.

#### Analytics Implementation
```javascript
// Business Intelligence tracking
function sendBIEvent(eventData) {
  fetch("https://trek.powtoon.com/event.gif?...", {
    method: "GET",
    mode: "no-cors"
  });
}
```
Events tracked:
- Extension installation (action: "install", value: 70017)
- Recording start (action: "start_presenting", value: 70022)
- Recording stop (action: "stop_presenting", value: 70023)

**Assessment**: Standard product analytics, no PII beyond user actions.

### Content Script (contentScript.bundle.js - 40,673 lines)

#### Technology Stack
- React 18 (UI framework)
- Redux (state management)
- Sentry SDK (error monitoring - sends to legitimate Sentry.io)
- Immer (immutable state)

#### DOM Manipulation
Limited DOM operations found:
- 9 instances of `innerHTML` usage (all within React's safe rendering context)
- React's built-in XSS protection via JSX sanitization
- Shadow DOM used for recording UI overlay (isolation from host page)

#### Communication
```javascript
// Only communicates with background script
chrome.runtime.sendMessage({
  action: "OPEN_WINDOW_WITH_URL",
  data: windowConfig
});
```

No evidence of:
- Direct DOM scraping beyond what's needed for recording
- Form field monitoring
- Keylogging
- Third-party script injection

### Camera/Offscreen Scripts
- camera.bundle.js (10,087 lines): Handles webcam capture
- offscreen.bundle.js (18,592 lines): Video processing worker
- Standard MediaStream API usage for recording

## Security Findings

### ✅ No Critical Vulnerabilities Found

### ✅ No High-Risk Issues Found

### ⚠️ Medium Risk: Broad Host Permissions
**Finding**: Extension requests `<all_urls>` permission

**Context**: This is functionally required for screen recording - the extension must be able to:
1. Inject recording UI overlay on any website
2. Capture screen content from any page user is viewing

**Verdict**: NOT EXPLOITED - Permission usage aligns with stated functionality

**Evidence**:
- Content script only injects recording controls UI
- No evidence of data harvesting from host pages
- Shadow DOM isolation prevents conflicts with host page

### ⚠️ Medium Risk: Cookie Access
**Finding**: Extension can access cookies

**Scope**: Limited to `*.powtoon.com` cookies only

**Usage**: Only reads/writes Powtoon authentication cookies:
```javascript
chrome.cookies.get({
  url: "https://www.powtoon.com",
  name: "csrftoken"
})
chrome.cookies.get({
  url: "https://www.powtoon.com",
  name: "sessionid"
})
```

**Verdict**: CLEAN - No cookie theft, only manages own authentication

### ℹ️ Low Risk: Externally Connectable to All Extensions
**Finding**: `"ids": ["*"]` in externally_connectable

**Impact**: Other extensions can message this extension

**Mitigation**: Only localhost and powtoon.com domains can establish connections

**Verdict**: LOW RISK - Primarily for development workflow

### ℹ️ Low Risk: Third-Party Error Monitoring
**Finding**: Sentry SDK integrated for crash reporting

**Data Sent**: Error stack traces, browser version, extension version

**Domain**: Legitimate Sentry.io error monitoring service

**Verdict**: ACCEPTABLE - Standard development practice, no PII leaked

## Data Flow Analysis

### Data Collection
1. **User Settings**: Recording preferences, camera/mic selections (stored locally)
2. **Session Data**: Authentication tokens, user profile info
3. **Analytics Events**: Installation, recording start/stop timestamps
4. **Recordings**: Video files uploaded to Powtoon servers

### Data Transmission
All network requests go to legitimate Powtoon infrastructure:
- `www.powtoon.com` - Main API, authentication, user profile
- `ec.powtoon.com` - Enterprise customer domain
- `trek.powtoon.com` - Analytics endpoint
- `*.sentry.io` - Error monitoring (Sentry SDK)
- `*.typekit.net` - Adobe Fonts CDN

### Data Storage
```javascript
chrome.storage.local stores:
- User preferences (recording settings, quality)
- Session metadata (last activity, user status)
- Enterprise subdomain (if applicable)
- Extension ID
- CSRF token for API security
```

No evidence of:
- Browsing history collection
- Form data harvesting
- Sensitive data exfiltration
- Unauthorized data transmission

## API Endpoints Summary

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| /api/v2/user/me/profile | GET | Check login status | None (cookies only) |
| /api/v2/user/me/permissions | GET | Get user capabilities | CSRF token |
| /api/v2/capture/settings | GET | Get recording settings | CSRF token |
| /api/v2/org/settings | GET | Enterprise settings | CSRF token |
| /api/v2/domain-info | GET | Validate enterprise domain | Subdomain parameter |
| trek.powtoon.com/event.gif | GET | Analytics tracking | Event type, timestamp, metadata |

All endpoints use HTTPS. No unencrypted data transmission.

## False Positives Ignored

The following patterns were detected but determined to be false positives:

| Pattern | Context | Verdict |
|---------|---------|---------|
| React SVG `innerHTML` | React's built-in rendering | Safe - JSX sanitization |
| Sentry SDK hooks | Official Sentry error monitoring | Legitimate - no PII leak |
| Dynamic function creation | Regenerator runtime for async/await | Standard Babel polyfill |
| Axios auth headers | CSRF token for API security | Security feature, not vulnerability |
| MobX Proxy objects | State management library | Standard pattern |

## Privacy Assessment

### Data Minimization: ✅ PASS
- Only collects data necessary for recording functionality
- No excessive telemetry beyond basic usage analytics

### User Consent: ✅ PASS
- Recording requires explicit user action (click extension icon)
- Camera/microphone access requires browser permission prompts

### Data Security: ✅ PASS
- HTTPS for all API communication
- CSRF protection on API endpoints
- Secure cookie handling (HttpOnly, Secure flags respected)

### Third-Party Sharing: ✅ PASS
- No data shared with third parties except:
  - Sentry.io (error monitoring - anonymized)
  - Adobe Typekit (font loading - no user data)

## Compliance Notes

### Chrome Web Store Policies: ✅ COMPLIANT
- Permissions match stated functionality
- No deceptive behavior
- Privacy policy linked (assumed at powtoon.com)

### GDPR Considerations:
- User recordings stored on Powtoon servers (user has account/consent)
- No unauthorized personal data collection
- Analytics can be disabled (enterprise settings available)

## Recommendations

### For Users:
1. ✅ Extension is safe to use for intended purpose
2. ⚠️ Be aware recordings are uploaded to Powtoon's cloud
3. ⚠️ Requires Powtoon account and login
4. ℹ️ Review Powtoon's privacy policy for data retention policies

### For Developers:
1. ✅ Well-architected React application
2. ✅ Good security practices (CSP, CSRF protection)
3. 💡 Consider narrowing `externally_connectable.ids` from `["*"]` to specific extension IDs
4. 💡 Document why `<all_urls>` permission is required in store listing

## Conclusion

**Powtoon Capture is a CLEAN extension with LOW security risk.**

The extension performs its advertised function of screen and webcam recording without any detected malicious behavior. All permissions are justified by the functionality, and network communication is limited to legitimate Powtoon infrastructure. The code quality is high, using modern React patterns and security best practices.

No evidence found of:
- ❌ Malware or malicious code
- ❌ Data exfiltration beyond legitimate operation
- ❌ Cryptocurrency mining
- ❌ Ad injection
- ❌ Cookie theft
- ❌ Credential harvesting
- ❌ Extension fingerprinting/enumeration
- ❌ Proxy infrastructure
- ❌ Kill switches or remote code execution
- ❌ Obfuscation beyond standard webpack bundling

The extension operates transparently as a Powtoon product integration, requiring user authentication and uploading recordings to Powtoon's service - all expected behavior for this type of tool.

## Overall Risk Rating: **LOW** ✅

The extension is safe for general use. Users should be comfortable with Powtoon having access to their recordings, which is inherent to the cloud-based service model.
