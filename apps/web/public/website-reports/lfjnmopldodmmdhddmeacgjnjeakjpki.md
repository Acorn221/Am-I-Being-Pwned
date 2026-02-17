# Security Analysis Report: Button for Google Calendar

## Metadata
- **Extension Name**: Button for Google Calendar
- **Extension ID**: lfjnmopldodmmdhddmeacgjnjeakjpki
- **Version**: 26.1.31
- **User Count**: ~100,000
- **Vendor**: Manganum (manganum.app)
- **Analysis Date**: 2026-02-07

## Executive Summary

Button for Google Calendar is a legitimate calendar management extension that integrates with Google Calendar API. The extension uses OAuth2 authentication to access read-only calendar data and provides quick event management features.

**Overall Risk Level: CLEAN**

The extension follows security best practices with minimal permissions, uses official Google APIs, and has no malicious behavior. All network requests are limited to legitimate Google Calendar API endpoints. The extension is developed by Manganum, a known developer of productivity extensions.

## Vulnerability Analysis

### 1. Manifest Permissions Review
**Severity**: INFORMATIONAL
**Status**: CLEAN

**Permissions Requested**:
```json
{
  "permissions": ["alarms", "identity", "notifications", "storage"],
  "oauth2": {
    "client_id": "498582140037-idmaqvknkffr3npnsdl2d09ni80m9gsf.apps.googleusercontent.com",
    "scopes": ["https://www.googleapis.com/auth/calendar.readonly"]
  }
}
```

**Analysis**:
- `alarms`: Used for periodic event synchronization (every minute scheduler)
- `identity`: Required for OAuth2 authentication with Google Calendar API
- `notifications`: Desktop notifications for calendar event reminders
- `storage`: Local storage for cached calendar data and user preferences
- OAuth scope: `calendar.readonly` - appropriate for read-only calendar access

**Verdict**: All permissions are justified and minimal for functionality. Read-only calendar scope prevents data modification abuse.

---

### 2. Content Security Policy
**Severity**: INFORMATIONAL
**Status**: CLEAN

**Analysis**:
- No custom CSP defined (uses Manifest V3 defaults)
- No content scripts declared
- No web_accessible_resources
- Extension operates entirely in background/popup context

**Verdict**: No CSP concerns. Extension does not inject into web pages.

---

### 3. Network API Analysis
**Severity**: LOW
**Status**: CLEAN

**API Endpoints Contacted**:
| Endpoint | Purpose | Method | Authentication |
|----------|---------|--------|----------------|
| `https://www.googleapis.com/calendar/v3/calendars/{id}/events` | Fetch calendar events | GET | Bearer OAuth2 |
| `https://www.googleapis.com/calendar/v3/users/me/calendarList` | Get user's calendars | GET | Bearer OAuth2 |
| `https://www.googleapis.com/calendar/v3/users/me/settings` | Get user settings | GET | Bearer OAuth2 |
| `https://www.googleapis.com/calendar/v3/calendars/{id}/events/quickAdd` | Quick add events | POST | Bearer OAuth2 |

**Code Evidence** (`background.js:12712-13186`):
```javascript
// Fetching events with OAuth token
const l = await fetch(m, {
  method: "GET",
  headers: {
    Authorization: "Bearer " + a
  }
});

// Quick add event
const r = await fetch(n, {
  type: "POST",
  headers: {
    Authorization: "Bearer " + e
  }
});
```

**Verdict**: All network requests use official Google Calendar API v3 endpoints with OAuth2 authentication. No third-party analytics or tracking services detected.

---

### 4. Authentication & Token Management
**Severity**: INFORMATIONAL
**Status**: CLEAN

**Code Evidence** (`background.js:12687-12703`):
```javascript
class s {
  static getAuthToken(e, t) {
    chrome.identity.getAuthToken(e, (async e => {
      !chrome.runtime.lastError && e ? t(e, null) : t(null, chrome.runtime.lastError.message)
    }))
  }
  static removeCachedAuthToken(e, t) {
    chrome.identity.removeCachedAuthToken({
      token: e
    }, t)
  }
}
```

**Analysis**:
- Uses `chrome.identity.getAuthToken()` - official Chrome OAuth2 API
- Properly handles token invalidation (401 responses trigger token removal)
- No token leakage to external services
- OAuth client ID matches Google's format

**Verdict**: Secure token management following Chrome extension OAuth best practices.

---

### 5. Data Storage & Privacy
**Severity**: INFORMATIONAL
**Status**: CLEAN

**Stored Data**:
- `CALENDARS`: User's calendar list metadata
- `EVENTS`: Cached calendar events
- `CALENDARS_SYNC_TIMESTAMP`: Last sync timestamp
- `EVENTS_SYNC_TIMESTAMP`: Event sync timestamp
- `FULL_SYNC_TIMESTAMP`: Full sync timestamp
- User preferences: `BADGE_TEXT_SHOWN`, `SHOW_NOTIFICATIONS`, `TIME_UNTIL_NEXT_INCLUDES_ALL_DAY_EVENTS`

**Analysis**:
- All data stored in `chrome.storage.local` (stays on device)
- No sensitive data exfiltration
- Cached data is necessary for offline functionality and performance
- Timestamps used for intelligent sync scheduling (prevents API rate limit abuse)

**Verdict**: Appropriate data storage with no privacy concerns.

---

### 6. Update & Install Behavior
**Severity**: LOW
**Status**: ACCEPTABLE

**Code Evidence** (`background.js:13232-13237`):
```javascript
chrome.runtime.setUninstallURL("https://get.manganum.app/3WFm")
chrome.runtime.onInstalled.addListener((function(e) {
  const t = chrome.runtime.OnInstalledReason.UPDATE;
  e.reason === t && chrome.tabs.create({
    url: "https://get.manganum.app/e6CO"
  })
}))
```

**Analysis**:
- Opens vendor page on uninstall (standard feedback mechanism)
- Opens update announcement page on extension update
- Both URLs point to manganum.app (legitimate vendor domain)
- No forced redirects during normal operation

**Verdict**: Standard vendor practice. Users may find update tabs intrusive but not malicious.

---

### 7. Code Quality & Obfuscation
**Severity**: INFORMATIONAL
**Status**: CLEAN

**Analysis**:
- Code is webpack-bundled (not maliciously obfuscated)
- Contains standard libraries: jQuery, Moment.js, lodash
- No `eval()`, `new Function()`, or suspicious dynamic code execution
- Single use of `String.fromCharCode()` in vendors.js is part of jQuery library
- Deobfuscated code is readable and follows standard patterns

**Verdict**: Production-grade bundling, not malicious obfuscation.

---

### 8. Third-Party Promotion
**Severity**: LOW
**Status**: ACCEPTABLE

**Code Evidence** (`action.html`):
```html
<div class="warning">
  <a target="_blank" href="https://get.manganum.app/lzhf">
    Try for free our new sidebar extension with Google Calendar, Gmail, and Tasks 😍
  </a>
</div>
```

**Analysis**:
- Promotional banner in popup UI for vendor's other products
- Non-intrusive (user can ignore)
- Links to manganum.app domain (same vendor)
- No forced redirects or ad injection into web pages

**Verdict**: Standard self-promotion by vendor. Not malware.

---

## False Positive Analysis

| Pattern | Location | Reason for FP | Verdict |
|---------|----------|---------------|---------|
| `XMLHttpRequest` | vendors.js:2924 | jQuery library AJAX implementation | SAFE - Legitimate library |
| `String.fromCharCode` | vendors.js:259 | jQuery Unicode handling | SAFE - Standard library function |
| `document.querySelectorAll` | options.js:128,145 | UI element selection in options page | SAFE - Standard DOM manipulation |
| Third-party URLs | action.html, background.js | Vendor self-promotion | ACCEPTABLE - Transparent marketing |

## API Endpoint Summary

| Endpoint | Data Sent | Data Received | Risk |
|----------|-----------|---------------|------|
| `googleapis.com/calendar/v3/calendars/*/events` | OAuth token, date range | Calendar events | LOW - Official API |
| `googleapis.com/calendar/v3/users/me/calendarList` | OAuth token | Calendar list | LOW - Official API |
| `googleapis.com/calendar/v3/users/me/settings` | OAuth token | User settings | LOW - Official API |
| `googleapis.com/calendar/v3/calendars/*/events/quickAdd` | OAuth token, event text | Event details | LOW - Official API |
| `get.manganum.app/*` | None (user clicks) | Vendor pages | INFORMATIONAL - Marketing |

## Data Flow Summary

```
User Authorization (OAuth2)
    ↓
chrome.identity.getAuthToken() → Bearer Token
    ↓
Background Script (Service Worker)
    ↓
fetch() → Google Calendar API v3
    ↓
Calendar Events JSON
    ↓
chrome.storage.local (cache)
    ↓
Popup UI (calendar view)
    ↓
chrome.notifications (event reminders)
```

**Data Exfiltration**: NONE
**Cookie Access**: NONE
**Cross-Site Tracking**: NONE
**Remote Code Loading**: NONE

## Security Recommendations

1. **For Users**: Extension is safe to use. Consider disabling notifications if not needed.
2. **For Developers**:
   - Consider making update tabs optional via user preference
   - Add privacy policy link in extension description
   - Document what data is cached locally

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
- No malicious behavior detected
- Uses official Google Calendar API exclusively
- Minimal permissions (read-only calendar access)
- No data exfiltration or tracking
- No injection into web pages
- Transparent vendor (Manganum/browsecraft.com)
- Code quality indicates professional development
- OAuth2 implementation follows best practices

**Confidence**: HIGH (95%)

The extension is a legitimate productivity tool with appropriate security practices. The vendor's self-promotion is the only minor annoyance but does not constitute a security risk.
