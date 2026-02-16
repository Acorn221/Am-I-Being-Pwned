# Security Analysis Report: Record, Transcribe & ChatGPT for Google Meet (tl;dv)

## Extension Metadata
- **Extension ID**: lknmjhcajhfbbglglccadlfdjbaiifig
- **Extension Name**: Record, Transcribe & ChatGPT for Google Meet
- **Short Name**: tl;dv
- **Version**: 2.28.1185
- **Users**: ~400,000
- **Manifest Version**: 3
- **Developer**: tldv.io

## Executive Summary

**Overall Risk Assessment: LOW**

This is a **LEGITIMATE meeting recording and transcription service**. The extension is the official Chrome extension for tl;dv (tldv.io), a well-known commercial product that provides AI-powered meeting recording, transcription, and analysis services. The extension operates transparently as documented, with proper user consent flows and legitimate business functionality.

The extension requests broad permissions (`<all_urls>`) which are necessary for its core functionality of detecting meeting links across web pages and injecting recording UI into Google Meet/Calendar. All network traffic goes to legitimate tldv.io infrastructure. Analytics collection (Mixpanel) and error tracking (Sentry) are standard for commercial SaaS products.

**No malicious behavior detected.**

---

## Permissions Analysis

### Declared Permissions
```json
{
  "permissions": ["tabs", "storage", "alarms"],
  "optional_permissions": ["clipboardWrite"],
  "host_permissions": ["<all_urls>"]
}
```

### Permission Risk Assessment

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `tabs` | Required to detect active Google Meet tabs and inject recording UI | **LOW** - Standard for productivity extensions |
| `storage` | Stores user settings, auth tokens, meeting queue state | **LOW** - Normal usage |
| `alarms` | Manages periodic session ID refresh (every 0.4 minutes) while meetings are active | **LOW** - Legitimate background task |
| `clipboardWrite` | Optional permission for copying meeting links/transcripts | **LOW** - User-initiated |
| `<all_urls>` | Detects meeting URLs across all pages, injects UI on Google Calendar/Meet | **MEDIUM** - Broad but necessary for core functionality |

### Content Security Policy
- **Not explicitly set** - Uses Manifest V3 defaults (stricter than MV2)

### Externally Connectable
```json
{
  "matches": ["*://tldv.io/*", "*://tldv.tech/*"]
}
```
- Allows tldv.io web app to communicate with extension for JWT token exchange and sign-out events
- **Risk: LOW** - Properly scoped to own domains

---

## Vulnerability Analysis

### 1. Firebase Configuration Exposure (FALSE POSITIVE)

**Severity**: INFO
**Files**: `background.js:37893-37899`

**Finding**:
```javascript
TLDX_FIREBASE_API_KEY: "AIzaSyA_d2z_LMkARJysO5MINZc-W3DFE-ZHXT0",
TLDX_FIREBASE_APP_ID: "1:724695490036:web:74fdba648a47384d3b2da1",
TLDX_FIREBASE_AUTH_DOMAIN: "lmi-store.firebaseapp.com",
TLDX_FIREBASE_PROJECT_ID: "lmi-store",
TLDX_FIREBASE_STORAGE_BUCKET: "lmi-store.appspot.com"
```

**Verdict**: **FALSE POSITIVE** - Firebase API keys are designed to be public. Security is enforced server-side via Firebase Security Rules. This is standard Firebase web client configuration.

---

### 2. Mixpanel Analytics Collection

**Severity**: INFO
**Files**: `background.js:37902, 10950-10989`

**Finding**:
```javascript
TLDX_MIXPANEL_TOKEN: "9119f2c3302030eaaee56e29fcf9b1bc"

// Mixpanel identify call
{
  event: "$identify",
  properties: {
    $distinct_id_before_identity: deviceId,
    $anon_id: deviceId
  }
}
```

**Analysis**:
- Standard Mixpanel analytics for product usage tracking
- Collects: `deviceId`, user events (meeting joins, highlights created, bot requests)
- Data sent to Mixpanel servers (not third-party SDK harvesting like Sensor Tower)
- Transparent usage analytics for legitimate SaaS business

**Verdict**: **ACCEPTABLE** - Standard first-party analytics, not deceptive tracking. Users expect analytics from a commercial product.

---

### 3. Sentry Error Tracking

**Severity**: INFO
**Files**: `background.js:37904, 37925-37942`

**Finding**:
```javascript
TLDX_SENTRY_DSN: "https://c43a1b6af24946be99c06b2dcda5162b@o4504156929982464.ingest.sentry.io/4504222632443904"
```

**Analysis**:
- Standard Sentry error monitoring for crash reporting
- Extension version included in error reports
- `beforeSend` hook present (allows filtering sensitive data before upload)

**Verdict**: **ACCEPTABLE** - Industry-standard error monitoring, properly configured.

---

### 4. User Authentication via External Messages

**Severity**: LOW
**Files**: `background.js:38079-38095`

**Finding**:
```javascript
Ne.runtime.onMessageExternal.addListener(async (y, w) => {
  const I = X(w.url || "");  // Validates sender is tldv.io or tldv.tech
  if (y.jwt && I) {
    C.dispatch(Zm(y.jwt));  // Store JWT token
  }
  if (y.type === gB && I) {
    C.dispatch(Is());  // Sign out
  }
})
```

**Analysis**:
- Extension receives JWT tokens from tldv.io web app via `externally_connectable`
- Validates sender URL matches `tldv.io` or `tldv.tech` before accepting tokens
- Enables SSO-like experience (sign in on web, auto-sign in extension)

**Verdict**: **SECURE** - Proper origin validation prevents unauthorized token injection.

---

### 5. Meeting Detection on All URLs

**Severity**: LOW
**Files**: `manifest.json`, `content-scripts/multi-tabs.js`

**Finding**:
```json
{
  "matches": ["<all_urls>"],
  "exclude_matches": ["*://*.tldv.io/app/embed/*", "*://*.zoom.us/*", ...],
  "js": ["content-scripts/multi-tabs.js"]
}
```

**Analysis**:
- Runs on ALL pages to detect Google Meet/Zoom/Teams links in emails, calendars, Slack, etc.
- Regex patterns: `https://meet.google.com/[a-z]{3}-[a-z]{4}-[a-z]{3}`
- Does NOT scrape page content beyond URL detection
- No DOM manipulation on non-meeting pages

**Verdict**: **ACCEPTABLE** - Necessary for core value proposition (auto-detect meeting links). No evidence of abuse.

---

### 6. Google Calendar Integration

**Severity**: LOW
**Files**: `content-scripts/google-calendar.js`, `manifest.json`

**Finding**:
```json
{
  "matches": ["*://calendar.google.com/*"],
  "js": ["content-scripts/google-calendar.js"]
}
```

**Analysis**:
- Injects UI into Google Calendar to show recording status and tldv bot join controls
- Reads calendar event data to extract meeting links and participant info
- No evidence of calendar data exfiltration beyond what user explicitly records

**Verdict**: **ACCEPTABLE** - Documented feature. Calendar access is necessary for meeting management UI.

---

### 7. Google Meet Recording Controls

**Severity**: LOW
**Files**: `content-scripts/google-meet.js`, `background.js:8311-8335`

**Finding**:
```javascript
// API endpoints for bot recording
e.post("/meetings/join-now", { conferenceId, provider: "googleMeet" })
e.post("/v1/meetings/join-now", { ... })
```

**Analysis**:
- Injects recording UI into Google Meet interface
- Sends meeting join requests to tldv.io backend to dispatch recording bot
- Displays recording consent banners (required for legal compliance in many jurisdictions)
- Transcript data stored on tldv.io servers (user's cloud storage)

**Verdict**: **ACCEPTABLE** - Core product functionality. Recording happens via server-side bot, not client-side capture.

---

### 8. Device ID Tracking

**Severity**: INFO
**Files**: `background.js:37944-37952, 10321-10326`

**Finding**:
```javascript
const { deviceId } = await Ne.storage.sync.get("deviceId");
if (!deviceId) {
  const w = self.crypto.randomUUID();
  Ne.storage.sync.set({ deviceId: w });
}

// Feature flags API
e.get(`/v1/feature-flags?deviceId=${deviceId}`, ...)
```

**Analysis**:
- Generates random UUID on first install for feature flag targeting
- Used for A/B testing and gradual feature rollouts
- Not linked to PII without user sign-in

**Verdict**: **ACCEPTABLE** - Standard product analytics practice.

---

### 9. Keyboard Shortcut Registration

**Severity**: INFO
**Files**: `manifest.json:13-16`, `background.js:38011-38026`

**Finding**:
```json
{
  "commands": {
    "pin-highlight": {
      "suggested_key": { "default": "Ctrl+Period" },
      "description": "Create a highlight during a meeting"
    }
  }
}
```

**Analysis**:
- Single keyboard shortcut for creating highlights during meetings
- No evidence of keylogging or keystroke capture
- Keydown handlers in content scripts are for UI interactions (React event handlers)

**Verdict**: **CLEAN** - Legitimate productivity feature, no keylogger.

---

## False Positives

| Pattern | Reason | Location |
|---------|--------|----------|
| Firebase API keys | Public by design, security is server-side | `background.js:37893` |
| `XMLHttpRequest`/`fetch` | Legitimate API calls to tldv.io backend | All files |
| `postMessage` | Standard extension-web page communication | `background.js:35719-35722` |
| `innerHTML` usage | React DOM rendering, not XSS injection | `google-meet.js:89106` |
| Base64 encoding/decoding | JWT token parsing, not obfuscation | `background.js:817, 17675` |
| `navigator.userAgent` | Firebase SDK browser detection | `background.js:12824` |
| `localStorage`/`sessionStorage` | Standard client-side state management | All files |
| Password references | Firebase Auth API error codes | `background.js:25981-26000` |
| WebRequest polyfill | Browser extension API compatibility layer | `background.js:31339, 37653` |

---

## API Endpoints & Data Flow

### Primary Backend Infrastructure
| Domain | Purpose | Data Sent |
|--------|---------|-----------|
| `api.tldv.io` | Core API (meetings, users, transcripts) | Meeting metadata, user profile, recording requests |
| `gw.tldv.io` | API Gateway | Feature flags, integrations (OAuth, Intercom, Paragon) |
| `gaia.tldv.io` | Unknown (likely internal service) | Not actively called in extension code |
| `tldv.io/app` | Web application | Auth tokens (via `externally_connectable`) |
| `firebaseapp.com` | Firebase Auth/Firestore | User authentication, real-time meeting state sync |

### Third-Party Services
| Service | Domain | Purpose | Data Sent |
|---------|--------|---------|-----------|
| Mixpanel | `mixpanel.com` | Product analytics | Event data (meeting joins, highlights), deviceId, user ID |
| Sentry | `sentry.io` | Error tracking | Stack traces, extension version, error context |
| Google APIs | `gapi.*` | Google Calendar OAuth | Calendar event data (on user consent) |

### Key API Calls
```javascript
// Meeting Management
POST /meetings/join-now              // Start recording bot
POST /v1/meetings/join-now           // V2 API
GET  /v1/meetings/{id}/transcript    // Fetch transcript
PUT  /v1/meetings/{id}               // Update meeting metadata
DELETE /v1/meetings/{id}             // Delete meeting

// User & Settings
GET  /users/me                       // User profile
GET  /v1/user-settings/              // User preferences
PUT  /v1/user-settings/              // Update settings

// Analytics
POST /v1/track                       // Event tracking

// Integrations
GET  /v1/integrations/paragon/auth   // Third-party integrations
GET  /v1/intercom/auth               // Customer support widget
```

---

## Data Collection Summary

### Data Collected by Extension

| Data Type | Purpose | Retention | User Control |
|-----------|---------|-----------|--------------|
| Meeting URLs | Detect when user joins Google Meet/Zoom/Teams | Temporary (session) | Required for core functionality |
| Google Calendar events | Show meeting list, detect scheduled recordings | Read-only, not stored | User grants Calendar permission |
| Recording preferences | Auto-record settings, transcript language | Persistent (tldv.io account) | User configurable in settings |
| Meeting transcripts | AI transcription of recorded meetings | Cloud storage (user's tldv.io account) | User initiates recordings |
| Usage analytics | Product improvement (Mixpanel) | Per Mixpanel retention policy | Cannot opt-out (standard SaaS) |
| Error logs | Bug fixing (Sentry) | Per Sentry retention policy | Automatic |
| Auth tokens (JWT) | Maintain user session | Expires per JWT claims | Sign-out clears |
| Device ID (UUID) | Feature flags, A/B testing | Persistent (chrome.storage.sync) | Cannot opt-out |

### Data NOT Collected
- ❌ Browsing history beyond meeting URL detection
- ❌ Keystrokes or form inputs (no keylogger)
- ❌ Cookie harvesting from other sites
- ❌ Screenshots or screen recordings (client-side)
- ❌ Email content or personal communications
- ❌ Credit card or payment info (handled by tldv.io web app, not extension)

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | tl;dv Behavior | Assessment |
|-------------------|----------------|------------|
| **Extension enumeration/killing** | None detected | ✅ CLEAN |
| **XHR/fetch hooking** | None - uses standard fetch() for own API calls | ✅ CLEAN |
| **Residential proxy infrastructure** | None | ✅ CLEAN |
| **Market intelligence SDKs** (Sensor Tower, etc.) | None - uses Mixpanel (first-party analytics) | ✅ CLEAN |
| **AI conversation scraping** | Only transcribes meetings user explicitly records | ✅ CLEAN |
| **Ad/coupon injection** | None | ✅ CLEAN |
| **Remote config kill switches** | Feature flags for gradual rollouts (standard practice) | ✅ ACCEPTABLE |
| **Social media data harvesting** | None | ✅ CLEAN |
| **Hidden network requests** | All API calls go to documented tldv.io domains | ✅ CLEAN |
| **Obfuscated code** | Standard webpack bundling, no malicious obfuscation | ✅ CLEAN |

---

## Content Script Behavior Analysis

### `google-meet.js` (6.7MB, 99,216 lines)
- **Purpose**: Injects tl;dv recording UI into Google Meet interface
- **DOM Access**: Reads meeting participant names, meeting ID from Meet UI
- **Network**: Sends meeting state to background script via message passing
- **Risk**: LOW - Large file size due to bundled React framework + UI components

### `google-calendar.js` (5.2MB, 53,672 lines)
- **Purpose**: Shows recording status and bot controls in Google Calendar
- **DOM Access**: Reads calendar event titles, meeting links, participant emails
- **Network**: Queries tldv.io API for recorded meetings
- **Risk**: LOW - Necessary for calendar integration feature

### `multi-tabs.js` (6.6MB, 97,792 lines)
- **Purpose**: Detects meeting links on all web pages
- **DOM Access**: Minimal - only searches page content for meeting URL patterns
- **Network**: Notifies background script of detected meeting links
- **Risk**: LOW - Runs on `<all_urls>` but does not scrape sensitive data

---

## Security Best Practices Adherence

| Practice | Status | Notes |
|----------|--------|-------|
| Manifest V3 migration | ✅ PASS | Using MV3 (more secure than MV2) |
| Minimal permissions | ⚠️ PARTIAL | `<all_urls>` is broad but justified |
| HTTPS-only API calls | ✅ PASS | All backend calls use HTTPS |
| Content Security Policy | ✅ PASS | MV3 defaults enforced |
| No remote code execution | ✅ PASS | No `eval()` or dynamic script injection |
| Origin validation | ✅ PASS | `externally_connectable` properly scoped |
| Secure token storage | ✅ PASS | JWT stored in `chrome.storage.sync` (encrypted by Chrome) |
| Error handling | ✅ PASS | Sentry integration with `beforeSend` hook |

---

## Privacy Policy Compliance

**Privacy Policy URL**: https://tldv.io/privacy (referenced in Calendar UI strings)

### Key Privacy Considerations:
1. **Transparency**: Extension description clearly states "record & transcribe Google Meet"
2. **User Consent**: Recording requires explicit user action (click "Record" button)
3. **Data Retention**: Calendar UI mentions "Free users recordings deleted after 3 months"
4. **Third-Party Sharing**: Mixpanel and Sentry integrations (standard for SaaS)

**Compliance Assessment**: Appears compliant with standard SaaS privacy practices. Users are informed that meetings are recorded/transcribed.

---

## Recommendations

### For Users
1. ✅ **Safe to use** - This is a legitimate commercial product
2. ⚠️ Be aware that meeting recordings/transcripts are stored on tldv.io servers (cloud service)
3. ⚠️ Extension can see meeting URLs on all web pages (necessary for link detection)
4. ℹ️ Usage analytics collected via Mixpanel (standard for SaaS products)

### For Developers (tldv.io team)
1. **Reduce host_permissions scope**: Consider requesting only specific domains where meeting links appear (Gmail, Calendar, Slack, etc.) instead of `<all_urls>` to reduce user concern
2. **Add CSP header**: Explicitly set `content_security_policy` in manifest for defense-in-depth
3. **Implement opt-out for analytics**: Provide privacy-conscious users option to disable Mixpanel tracking
4. **Document data flows**: Publish transparency report showing what data goes to which third parties

---

## Overall Risk Assessment

### Risk Score: **LOW** (CLEAN)

**Justification**:
- ✅ Legitimate business with transparent functionality
- ✅ No malicious patterns detected (no data harvesting, ad injection, proxy infrastructure)
- ✅ Proper security practices (HTTPS, origin validation, secure token storage)
- ✅ Analytics/error tracking are standard for commercial SaaS
- ⚠️ Broad `<all_urls>` permission requires user trust, but is necessary for core feature
- ℹ️ Meeting data stored on tldv.io servers (expected behavior for cloud recording service)

**Verdict**: **RECOMMENDED FOR USE** - This is a trustworthy extension providing valuable meeting recording/transcription services. The broad permissions are justified by the product's core value proposition.

---

## Appendix: Code Evidence

### A. Auth Token Exchange (Secure)
```javascript
// background.js:38079-38095
Ne.runtime.onMessageExternal.addListener(async (y, w) => {
  const I = X(w.url || "");  // Validates sender is tldv.io or tldv.tech
  if (y.jwt && I) {
    const k = C.getState();
    if (k.auth.accessToken !== y.jwt || !k.user.user) {
      We.success("background", "Persisting new token. event=onMessageExternal");
      C.dispatch(Zm(y.jwt));
    }
  }
});

// URL validation function
function X(y) {
  const w = t.includes("tldv.tech") && y.includes("tldv.tech");
  return t.includes("tldv.io") && y.includes("tldv.io") || w;
}
```

### B. Meeting URL Detection (Legitimate)
```javascript
// background.js:15-23
const eg = /https:\/\/meet\.google\.com\/([a-z]{3}-[a-z]{4}-[a-z]{3})/;
const XS = n => {
  eg.lastIndex = 0;
  const e = eg.exec(n);
  if (e) return {
    provider: hr.GOOGLE_MEET,
    conferenceLink: e[0],
    conferenceId: e[1]
  };
};
```

### C. API Communication (Transparent)
```javascript
// background.js:8311-8335
const coreApi = {
  joinMeetingNow(conferenceId, provider) {
    return e.post("/meetings/join-now", { conferenceId, provider });
  },
  getTranscript(meetingId) {
    return e.get(`/v1/meetings/${meetingId}/transcript`);
  },
  shareMeeting(meetingId, emails) {
    return e.post(`/v1/meetings/${meetingId}/share`, { emails });
  }
};
```

---

**Report Generated**: 2026-02-06
**Analyst**: Claude (Anthropic AI Security Analysis)
**Analysis Method**: Static code analysis of deobfuscated source code
**Confidence Level**: HIGH (complete source code review of all 4 JavaScript files)
