# Vulnerability Report: Vmaker - Free Screen Recorder

## Extension Metadata
- **Extension ID**: bjibimlhliikdlklncdgkpdmgkpieplj
- **Extension Name**: Vmaker - Free Screen Recorder
- **Version**: 5.2.0
- **User Count**: ~70,000 users
- **Manifest Version**: 3
- **Homepage**: https://app.vmaker.com/dashboard/

## Executive Summary

Vmaker is a legitimate screen recording extension for Chrome that provides video messaging and screen recording functionality with integrations for Gmail, Google Meet, Jira, GitHub, GitLab, HubSpot, and Intercom. The extension has **CRITICAL security concerns** due to overly broad permissions and an insecure externally_connectable configuration that creates significant attack surface.

**Overall Risk Assessment: CRITICAL**

The extension's `externally_connectable: {"matches": ["<all_urls>"]}` configuration allows any website to communicate with the extension, creating a massive security vulnerability that could be exploited for privilege escalation attacks.

## Vulnerability Details

### CRITICAL: Universal External Connectivity (CVE-Quality)

**Severity**: CRITICAL
**File**: `manifest.json` (lines 148-150)
**Code**:
```json
"externally_connectable": {
  "matches": ["<all_urls>"]
}
```

**Verdict**: VULNERABILITY - This is a critical security misconfiguration.

**Impact**:
- Any malicious website can send messages to this extension using `chrome.runtime.sendMessage()`
- Extension responds to `OPEN_VMAKER_PLUGIN` message from ANY external source (background.js:1584-1588)
- Attackers can invoke screen recording functionality from malicious sites
- No origin validation or authentication required
- Breaks Same-Origin Policy protections

**Attack Scenario**:
1. User visits attacker-controlled website
2. Attacker's JavaScript calls: `chrome.runtime.sendMessage("bjibimlhliikdlklncdgkpdmgkpieplj", {message: "OPEN_VMAKER_PLUGIN"})`
3. Extension launches recording interface without user consent
4. Attacker can potentially trigger privileged operations

**Recommendation**: Restrict `externally_connectable` to only trust vmaker.com domains:
```json
"externally_connectable": {
  "matches": ["https://*.vmaker.com/*", "https://app.vmaker.com/*"]
}
```

### HIGH: Excessive Permissions

**Severity**: HIGH
**File**: `manifest.json` (lines 119-130)
**Code**:
```json
"permissions": [
  "tabCapture",
  "activeTab",
  "tabs",
  "scripting",
  "storage",
  "desktopCapture",
  "notifications",
  "unlimitedStorage",
  "idle"
],
"host_permissions": ["<all_urls>"]
```

**Verdict**: HIGH RISK - Permissions exceed minimum necessary for core functionality.

**Issues**:
- `host_permissions: ["<all_urls>"]` grants network access to all websites
- `tabs` permission enables full tab enumeration and metadata access
- `scripting` + `<all_urls>` allows arbitrary code injection
- Combined with `externally_connectable` creates privilege escalation risk

**Data Access**: Extension can access all web page content through content scripts injected on `<all_urls>`.

### HIGH: Content Script Injection on All URLs

**Severity**: HIGH
**File**: `manifest.json` (lines 58-63, 74-76)
**Code**:
```json
{
  "matches": ["<all_urls>"],
  "css": ["/css/root.css"],
  "js": ["/static/js/content.js"]
},
{
  "js": ["/static/js/getWindow.js"],
  "matches": ["<all_urls>"]
}
```

**Verdict**: MODERATE CONCERN - Standard for screen recording but increases attack surface.

**Impact**:
- Content scripts run on every website user visits
- 7.5MB content.js injected into all pages (performance impact)
- getWindow.js attempts to store window object in chrome.storage (line 1426-1437)
- Combined with externally_connectable, malicious sites could trigger unintended behavior

**Observation**: getWindow.js stores window object reference but includes poor error handling with user-visible alerts.

### MEDIUM: WebSocket Communication to Third-Party Server

**Severity**: MEDIUM
**File**: `app/background.js` (lines 117-208)
**Code**:
```javascript
socketURL: a = "https://ping.vmaker.com"
// ...
SOCKET = io(e || a, {
  transports: ["websocket", "polling"],
  reconnection: !0,
  reconnectionAttempts: 3,
  pingTimeout: 3e4,
  pingInterval: 25e3
})
```

**Verdict**: ACCEPTABLE - Legitimate upload infrastructure but lacks security hardening.

**Observations**:
- Socket.io connection to ping.vmaker.com for video blob uploads
- Handles BlobReceivedResponse, BlobMergedResponse events
- Falls back to S3 storage on server errors (lines 64-67, 154-156)
- No evidence of sensitive data exfiltration
- Connection limited to authenticated upload sessions

**Recommendation**: Implement certificate pinning and rate limiting.

### MEDIUM: OAuth/Authentication Flow

**Severity**: MEDIUM
**File**: `app/background.js` (lines 363-413)
**Code**:
```javascript
const doApiCall = (e, a, t, o = !1, n = !1) => {
  // ...
  const { access_token: d } = s
  // ...
  u = { ...u, authorization: d }
  fetch(e, {
    method: "POST",
    headers: u,
    body: g
  })
}
```

**Verdict**: ACCEPTABLE - Standard token-based authentication.

**Observations**:
- Uses bearer token authentication via `authorization` header
- Access tokens stored in chrome.storage.local under `VMAKER_REDUX_DATA`
- Social auth responses handled via background messages (lines 36-41)
- No evidence of token theft or leakage

**Recommendation**: Implement token rotation and expiration checking.

### LOW: Sentry Error Tracking

**Severity**: LOW
**File**: `app/libs/sentry.min.js`, `app/background.js` (lines 932-946)
**Code**:
```javascript
Sentry.init({
  dsn: e,
  integrations: [new Sentry.Integrations.BrowserTracing],
  tracesSampleRate: 1,
  environment: "DEVELOPMENT" === a ? "development" : "production"
})
```

**Verdict**: ACCEPTABLE - Standard error monitoring practice.

**Observations**:
- Sentry SDK v6.2.1 for error tracking
- DSN loaded from `backgroundState.sentryURL`
- Only activates in PRODUCTION environment
- Standard integration, no security concerns

## False Positives

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| InboxSDK usage | inboxsdk-v3.js | Official Streak/InboxSDK library for Gmail integration - legitimate use |
| AWS SDK | app/libs/s3.js | Official AWS SDK v2.9.0 for S3 uploads - standard video upload infrastructure |
| Socket.io | app/libs/socket-io.min.js | Standard WebSocket library for real-time upload progress - legitimate |
| Sentry SDK | app/libs/sentry.min.js | Official error tracking SDK - standard dev practice |
| RecordRTC | app/libs/RecordRTC.min.js | Popular open-source screen recording library |
| `new Function()` | static/js/getWindow.js | Used in Promise polyfill (line 101) - standard polyfill code |

## API Endpoints Analysis

| Endpoint | Purpose | Security | Verdict |
|----------|---------|----------|---------|
| https://ping.vmaker.com | WebSocket upload server | Authenticated via access_token | SAFE |
| (Dynamic authUrl) | OAuth authentication | Token-based | SAFE |
| (Dynamic playerURL) | Video player page | Public video links | SAFE |
| (Dynamic dashboardURL) | User dashboard | Authenticated | SAFE |

**Note**: Most API endpoints are dynamically configured via `SET_REQUEST_URLS` message from content scripts, not hardcoded.

## Data Flow Summary

### Data Collection
- **User Information**: userid, email, name, access_token (stored in chrome.storage.local)
- **Recording Metadata**: videoId, recordId, recording time, resolution settings
- **Upload Data**: Video blobs, thumbnails sent to ping.vmaker.com or AWS S3
- **Telemetry**: Extension logs sent to Sentry for error tracking (production only)

### Data Storage
- **chrome.storage.local**: User authentication state, Redux state, upload progress
- **IndexedDB**: Video blobs during upload via db.js wrapper
- **No sensitive data harvesting detected**

### External Communication
- **ping.vmaker.com**: Real-time video upload via WebSocket
- **AWS S3**: Fallback video storage (credentials obtained via getAWSAccessURL)
- **vmaker.com domains**: Authentication, player, dashboard APIs
- **Sentry.io**: Error telemetry (production environment)

## Integration Points Analysis

### Gmail Integration (InboxSDK)
- **File**: inboxsdk-v3.js, static/js/gmail-content.js
- **Behavior**: Adds video insertion button to Gmail compose interface
- **Risk**: LOW - Uses official InboxSDK, standard Gmail integration

### Third-Party Platform Integrations
- **Jira/Atlassian**: Button injection for video attachments
- **GitHub/GitLab**: PR/issue comment video insertion
- **Google Meet**: In-meeting recording widget
- **HubSpot/Intercom**: Contact/conversation video embedding
- **Risk**: LOW - All integrations use content scripts for UI injection only

## Overall Risk Assessment

**RISK LEVEL: CRITICAL**

### Primary Concerns:
1. **CRITICAL**: `externally_connectable: ["<all_urls>"]` allows any website to interact with extension
2. **HIGH**: Excessive permissions create large attack surface
3. **HIGH**: Universal content script injection increases exposure

### Mitigating Factors:
- No evidence of data theft or malicious behavior in current implementation
- Legitimate business use case (screen recording SaaS)
- Code appears to be production build from reputable company
- Standard third-party libraries (AWS SDK, Sentry, InboxSDK)

### Exploitation Difficulty:
- **Easy** for external websites to trigger extension functionality
- **Moderate** to escalate to privilege abuse (requires chaining with other vulnerabilities)

## Recommendations

### Immediate Actions (Critical)
1. **Remove `externally_connectable: ["<all_urls>"]`** or restrict to `https://*.vmaker.com/*`
2. Remove external message listener or add strict origin validation
3. Consider removing `tabs` permission if not essential

### Security Hardening
1. Implement Content Security Policy for injected frames
2. Add rate limiting to WebSocket uploads
3. Implement certificate pinning for API endpoints
4. Rotate and expire access tokens more aggressively
5. Minimize content script scope where possible

### Code Quality
1. Remove user-facing alerts in getWindow.js error handling
2. Optimize 7.5MB content.js bundle size
3. Add request signing/validation for external messages

## Conclusion

Vmaker is a **legitimate but poorly secured** screen recording extension. The core functionality appears benign, but the **critical security misconfiguration in `externally_connectable`** creates an unacceptable security risk. Any website can interact with this extension, potentially triggering screen recording or other privileged operations without proper user consent.

**This extension should not be considered safe for sensitive environments until the externally_connectable configuration is fixed.**

---

**Report Generated**: 2026-02-07
**Analysis Method**: Static code analysis of deobfuscated extension source
**Analyst**: Automated Security Scanner
