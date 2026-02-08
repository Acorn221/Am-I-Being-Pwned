# Security Analysis Report: Sortd for Gmail

## Extension Metadata
- **Name**: Sortd for Gmail
- **Extension ID**: aohlfneeliakfcefeffppfplagbccbni
- **Version**: 2.4.462.14791
- **Users**: ~40,000
- **Manifest Version**: 3

## Executive Summary

Sortd for Gmail is a legitimate productivity extension that transforms Gmail into a visual task management system. The extension requires extensive permissions to integrate deeply with Gmail, authenticate users with its backend service, and track email engagement. After comprehensive analysis, **no malicious behavior or critical vulnerabilities were identified**. The extension serves its stated purpose and follows standard patterns for authenticated SaaS extensions.

**Overall Risk Assessment: CLEAN**

The extension is invasive by design due to its core functionality (task management overlay on Gmail), but demonstrates no evidence of malicious intent, data exfiltration beyond intended features, or exploitable vulnerabilities.

## Detailed Analysis

### 1. Manifest Permissions & CSP

**Permissions Requested:**
- `storage` - Local data persistence (user settings, tokens)
- `scripting` - Content script injection for Gmail integration
- `declarativeNetRequestWithHostAccess` - Email read receipt tracking (blocks images)

**Host Permissions:**
- `https://app.sortd.com/*` - Backend API communication
- `https://mail.google.com/*` - Gmail integration

**Optional Permissions:**
- `notifications` - Browser notifications for reminders
- `*://*.googleusercontent.com/*` - Email image proxy (for read receipts)
- `*://*.sortd.com/*` - Additional API endpoints

**Content Security Policy:**
```javascript
"script-src 'self'; object-src 'self'"
```
**Verdict**: ✅ **SECURE** - Proper CSP prevents inline scripts and eval. No unsafe-eval or unsafe-inline directives.

### 2. Authentication & Token Management

**Authentication Flow:**
- OAuth 2.0 integration with Google via `web.sortd.com/auth/login`
- Stores refresh tokens (`jrt`) and access tokens (`jat`) in chrome.storage.local
- Token refresh mechanism using `/su/{{authTokenId}}/refreshToken` endpoint
- Tokens scoped per email address using pattern: `sortd/{email}/token`

**Code Evidence (background.js:343-360):**
```javascript
async function a(e) {
  if (!e) return;
  if (o[e] || await c(e), !o[e] || !o[e].jrt || !o[e].authTokenId) return;
  const r = await fetch(s.chrome.host.mail3.refreshTokenUrl.replace("{{authTokenId}}", o[e].authTokenId), {
    method: "GET",
    credentials: "include",
    mode: "cors",
    headers: {
      "Content-Type": "application/json;charset=UTF-8",
      "X-Requested-With": "XMLHttpRequest",
      "X-Access-Token": o[e].jrt
    }
  });
  // Token refresh and storage
}
```

**Verdict**: ✅ **SECURE** - Standard OAuth token refresh pattern with proper credential management. Tokens stored in chrome.storage (encrypted by browser). No hardcoded credentials or plaintext token exposure.

### 3. Network Communications

**Primary API Endpoints (web.sortd.com):**
- `/auth/login` - User authentication
- `/srv/log/logMessage` - Error reporting
- `/srv/tracker/track` - Analytics events
- `/srv/popupnotification/retrieve` - Notification polling
- `/su/{authTokenId}/refreshToken` - Token refresh

**HTTP Implementation:**
- Uses native `fetch()` API with proper error handling
- All requests to `https://web.sortd.com` (HTTPS only)
- Credentials sent via `X-Access-Token` header (not URL parameters)
- No XMLHttpRequest hooking or fetch interception detected

**Verdict**: ✅ **LEGITIMATE** - Standard SaaS backend communication. All traffic to declared first-party domain. No third-party data sharing beyond analytics.

### 4. Content Script Injection & DOM Manipulation

**Injection Targets:**
- `https://mail.google.com/*` (primary interface)
- Excluded: background tabs, HTML view (`/mail/u/*/h/*`)

**Scripts Loaded:**
```javascript
"js": [
  "lib/webcomponents-ce.js",
  "lib/jquery.min.js",
  "lib/kefir.min.js",
  "lib/pickadate/picker.js",
  "lib/pickadate/picker.date.js",
  "load.js"
]
```

**Functionality:**
- Injects visual task management overlay into Gmail
- Monitors Gmail DOM for email threads, compose windows, send events
- Adds custom UI elements (boards, panels, reminders)
- Uses InboxSDK integration patterns (visible in pageWorld.js)

**Verdict**: ✅ **EXPECTED** - Extensive DOM manipulation is inherent to the product. No evidence of keylogging, clipboard access, or password field monitoring.

### 5. Analytics & Tracking

**Tracking Services:**
- Google Tag Manager (AW-966631203)
- Facebook Pixel (827452130790680)
- First-party tracking at `/srv/tracker/track`

**Events Tracked:**
```javascript
TRACKER: {
  EVENTS: {
    LOGIN_ATTEMPT: "Access - Login Attempt",
    LOGIN_FAILURE: "Access - Login Failure",
    INSTALLED_EXTENSION: {
      event: "Access - Installed Extension",
      trackOnce: true
    },
    OPENED_EMAIL_TRACKING_STREAM: {
      event: "Email - Opened Email Tracking Stream",
      trackOnce: false
    }
  }
}
```

**Email Read Receipts:**
- Uses declarativeNetRequest to block tracking pixel loads for user's own emails
- Injects hidden tracking images in sent emails: `<img src="READ_RECEIPT_URL">`
- Blocks images matching: `https://ci[0-9].googleusercontent.com/meips/[...]=s0-d-e1-ft#https://web.sortd.com/srv/rr/...`

**Verdict**: ⚠️ **PRIVACY CONCERN (DISCLOSED)** - Email tracking is an explicit feature. Extension injects read receipt pixels and tracks opens. This is disclosed in permissions and settings. Not malicious, but users should be aware.

### 6. Data Access & Storage

**Data Collected:**
- User email address (from Gmail)
- Email thread metadata (subjects, participants, dates)
- Task/board organization data
- User activity tracking (Gmail interactions)

**Storage Locations:**
- `chrome.storage.local` - User settings, tokens, board data
- `sessionStorage` - Temporary email session data
- Backend database (web.sortd.com) - Synced task/board state

**Data Transmission:**
- Email metadata sent to Sortd backend for task management
- Analytics events to GTM/Facebook
- Error logs to `/srv/log/logMessage`

**Verdict**: ⚠️ **INVASIVE BUT DISCLOSED** - Extension reads and transmits email metadata to function. This is necessary for task management features but gives Sortd significant visibility into user's Gmail. Required by the permission model.

### 7. Security Concerns Analysis

**❌ Extension Enumeration/Killing**: NOT DETECTED
**❌ XHR/Fetch Hooking**: NOT DETECTED
**❌ Residential Proxy Infrastructure**: NOT DETECTED
**❌ Remote Kill Switch**: NOT DETECTED (standard version updates only)
**❌ Market Intelligence SDKs**: NOT DETECTED (no Sensor Tower, Pathmatics, etc.)
**❌ AI Conversation Scraping**: NOT DETECTED
**❌ Ad/Coupon Injection**: NOT DETECTED
**❌ Code Obfuscation**: Webpack bundling only (standard build process)
**❌ Dynamic Code Execution**: No `eval()`, `Function()`, or `execScript` usage
**❌ Cookie Harvesting**: NOT DETECTED
**❌ Keylogging**: NOT DETECTED

### 8. False Positive Analysis

| Pattern | Location | Verdict |
|---------|----------|---------|
| `postMessage` usage | frameWrapper.js, background.js | ✅ Legitimate iframe communication between extension components |
| Token storage | background.js | ✅ Standard OAuth token management in chrome.storage |
| DOM manipulation | main.js (2.4MB) | ✅ Required for Gmail UI overlay |
| Fetch calls | background.js | ✅ Backend API communication only |
| Error reporting | background.js:523 | ✅ Standard error logging to `/srv/log/logMessage` |
| Image blocking rules | background.js:1068-1098 | ✅ Read receipt blocking feature (user privacy) |

### 9. API Endpoints Summary

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `/auth/login` | GET | OAuth flow | Redirect parameters |
| `/srv/isAuthenticated` | GET | Session check | Email, authTokenId |
| `/su/{id}/refreshToken` | GET | Token refresh | authTokenId, refresh token |
| `/srv/log/logMessage` | POST | Error logging | Error details, stack traces |
| `/srv/tracker/track` | POST | Analytics | Event name, user email, properties |
| `/srv/tracker/setuserproperty` | POST | User metadata | Email, properties |
| `/srv/popupnotification/retrieve` | GET | Notifications | User ID |
| `/srv/rr/*` | GET | Read receipts | Email tracking pixel |

All endpoints use HTTPS and authenticate with `X-Access-Token` header.

### 10. Data Flow Summary

```
Gmail DOM → Content Scripts (main.js) → postMessage →
Background Service Worker → HTTPS → web.sortd.com API →
Backend Database (task/board storage)

Analytics: Extension Events → GTM/Facebook → Third-party analytics
```

**User Data Journey:**
1. Extension reads Gmail thread data via DOM
2. User organizes emails into boards/tasks
3. Task metadata synced to Sortd backend
4. Read receipts tracked via image pixel injection
5. Usage analytics sent to GTM/Facebook

## Overall Risk Assessment

**Risk Level: CLEAN**

**Rationale:**
Sortd for Gmail is a legitimate productivity tool that requires extensive Gmail access to function. While the extension is highly invasive (reads email metadata, injects tracking pixels, transmits data to backend), all behaviors align with its advertised functionality as a task management system for Gmail teams.

**Key Points:**
- ✅ No malicious code patterns detected
- ✅ No data exfiltration beyond intended features
- ✅ Proper authentication and token management
- ✅ Standard SaaS architecture (client + backend API)
- ✅ Transparent permission requests matching functionality
- ⚠️ Email read receipts are a privacy-sensitive feature (disclosed)
- ⚠️ Email metadata sent to third-party service (required for product)

**Recommendation:**
Extension is SAFE for users who understand and accept:
1. Sortd will have access to email metadata
2. Email tracking pixels will be injected in sent messages
3. Usage analytics shared with Google/Facebook
4. Task/board data stored on Sortd servers

This is a legitimate freemium SaaS product, not malware.

---

**Report Generated**: 2026-02-08
**Analysis Method**: Static code analysis, manifest review, network pattern analysis
**Code Location**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/aohlfneeliakfcefeffppfplagbccbni/`
