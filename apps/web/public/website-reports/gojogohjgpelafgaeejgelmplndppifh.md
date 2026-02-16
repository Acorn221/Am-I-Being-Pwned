# Vulnerability Assessment Report

## Extension Metadata
- **Name**: Unlimited Email Tracker by Snov.io
- **Extension ID**: gojogohjgpelafgaeejgelmplndppifh
- **User Count**: ~100,000
- **Version**: 6.0.34
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

The Unlimited Email Tracker by Snov.io is a legitimate email tracking extension that integrates with Gmail to track email opens, link clicks, and provides reminder/send-later functionality. The extension collects significant email metadata and user behavior data, which is sent to Snov.io's backend servers. While the extension appears to function as advertised with no overtly malicious code detected, it has moderate privacy concerns due to the extensive email tracking capabilities and data collection practices inherent to its core functionality.

**Overall Risk Level**: MEDIUM

The extension operates as expected for an email tracking service, but users should be aware that all tracked email content, recipients, timestamps, and interaction data are transmitted to Snov.io's servers.

## Vulnerability Analysis

### 1. Excessive Email Content Access - MEDIUM

**Severity**: MEDIUM
**Files**:
- `js/inbox-compose.js` (lines 374-464)
- `js/background/background.js` (lines 288-311)

**Description**:
The extension captures complete email content including subject, body HTML, all recipients (to/cc/bcc), sender information, and modifies email bodies to inject tracking pixels and wrap links before sending.

**Code Evidence**:
```javascript
// From inbox-compose.js
this.mailObj.from = this.getFromContact().emailAddress;
this.mailObj.subject = this.getSubject();
this.mailObj.body = this.getHTMLContent();
this.mailObj.to = [];
// Captures all recipients including BCC

// Tracking pixel injection
let a = `${l}/track/${i}.png?eId=` + n;
this.setBodyHTML(`${e}<img id="snvTrackImg" src="${a}" width="1" height="1" alt=""/>`);

// Link wrapping for click tracking
newUrl = `${l}/click?redirect=${encodeURIComponent(e)}&dID=` + i;
```

**Data Transmitted**:
The extension sends the following to `https://emailtracker.snov.io/trackData`:
- Complete email body HTML
- Subject line
- All recipient email addresses (to/cc/bcc)
- Sender email address
- Thread ID and message ID
- Gmail OAuth tokens
- User's hashId (account identifier)

**Verdict**: This is expected functionality for an email tracking service, but represents significant data collection. All email content passes through Snov.io's servers. Users must trust Snov.io with full access to their outgoing email data.

---

### 2. Cookie and Authentication Harvesting - MEDIUM

**Severity**: MEDIUM
**Files**:
- `js/background/checkAuth.js` (lines 42-71)
- `js/background/background.js` (lines 69-78)

**Description**:
The extension actively reads authentication cookies from the Snov.io domain to maintain user sessions and transmits JWT tokens with every API request.

**Code Evidence**:
```javascript
// From checkAuth.js
async getSelectorFromCookies() {
  return await this.getCookie(this.serverHost, "selector")
}
async getTokenFromCookies() {
  return await this.getCookie(this.serverHost, "token")
}

// Retrieves JWT from cookies
var e = await this.getCookie(this.serverHost, cookieJwtName);

// Sent with every request
headers: {
  "Content-type": "application/json",
  [headersJwtName]: jwt  // st-ua header
}
```

**Verdict**: This is standard authentication practice for extensions that require user accounts. The extension only accesses its own service's cookies (snov.io domains) and does not harvest cookies from other sites. The JWT-based authentication is appropriate for this use case.

---

### 3. Firebase Cloud Messaging Push Notifications - LOW

**Severity**: LOW
**Files**:
- `js/background/firebase.js` (lines 1-101)

**Description**:
The extension uses Firebase Cloud Messaging for push notifications about email opens, clicks, and reminders.

**Code Evidence**:
```javascript
// Firebase config (public keys)
const firebaseConfig = {
  apiKey: "AIzaSyDL6tRkUg0y7oUE2jkN2JkGQlT_pc4SZ3o",
  authDomain: "mail-tracker-extension.firebaseapp.com",
  projectId: "mail-tracker-extension",
  messagingSenderId: "143837462924"
};

// Device token registration
async function updateDeviceTokenApi(deviceToken, hashId, jwt) {
  return fetch(mainHost + "/updateDeviceToken", {
    method: "POST",
    body: JSON.stringify({
      hashId: hashId,
      deviceToken: deviceToken
    })
  })
}
```

**Verdict**: Standard use of Firebase for push notifications. The API keys are public by design. The extension registers device tokens with the backend to enable real-time notifications when tracked emails are opened or clicked. This is expected functionality.

---

### 4. Google Analytics Tracking - LOW

**Severity**: LOW
**Files**:
- `js/background/googleAnalyticsEvents.js` (lines 1-48)

**Description**:
The extension sends usage analytics to Google Analytics (UA-94112226-7) for tracking user interactions within the extension.

**Code Evidence**:
```javascript
class GoogleAnalyticsEvents {
  constructor() {
    this.trackingID = "UA-94112226-7";
    this.analyticsPath = "https://www.google-analytics.com/collect";
  }
  async send(eventAction) {
    const params = new URLSearchParams({
      v: "1",
      tid: this.trackingID,
      cid: this.gaCID,
      t: "event",
      ec: "SnovioExt",
      ea: eventAction
    });
    await fetch(this.analyticsPath, { method: "POST", body: params });
  }
}
```

Events tracked include: install, update, activateInOptions, sendEmailWithTracking, showSettings, clickHelp, star ratings, etc.

**Verdict**: Standard analytics implementation. The extension tracks user interactions for product improvement. No sensitive data appears to be sent to Google Analytics - only event names.

---

### 5. InboxSDK Third-Party Library - LOW

**Severity**: LOW
**Files**:
- `js/inbox-sdk.js` (lines 1-33)
- `js/utils/inboxsdk.js` (53,000+ lines)

**Description**:
The extension uses InboxSDK (sdk_snovio_tracker_3d88e65315) to integrate with Gmail's interface. InboxSDK is a legitimate third-party library maintained by Streak and Inbox by Gmail developers.

**Code Evidence**:
```javascript
InboxSDK.load(2, "sdk_snovio_tracker_3d88e65315").then(sdk => {
  this.userEmail = sdk.User.getEmailAddress();
  this.eId = md5(inboxAccount.userEmail);
});
```

**Verdict**: InboxSDK is widely used by legitimate Gmail extensions (Boomerang, Streak, etc.). The SDK provides safe APIs for Gmail integration without requiring direct DOM manipulation. This is best practice for Gmail extensions.

---

### 6. Email Link Rewriting - MEDIUM

**Severity**: MEDIUM
**Files**:
- `js/inbox-compose.js` (lines 394-414)

**Description**:
Before sending, the extension rewrites all links in email bodies to route through Snov.io's click tracking domain, then redirects to the original destination.

**Code Evidence**:
```javascript
// Wraps all links for click tracking
newUrl = `${trackHost}/click?redirect=${encodeURIComponent(originalUrl)}&dID=${draftId}`;
if (hashId) {
  newUrl = newUrl + "&hashId=" + hashId;
}
if (linkName) {
  newUrl = newUrl + "&linkName=" + linkName;
}
$(this).attr("href", newUrl);

// Excluded links
const DO_NOT_WRAP = [
  "unsubscribe", "redirect=", "snov.io", "chrome.google.com",
  "mail.google.com", "mailto:", "telnet:", "file:", "data:",
  "tel:", "cid:", "mid:", "skype:", "smsto:", "bitcoin:", "urn:",
  "ldap:", "sip:", "ftp:"
];
```

**Verdict**: This is standard functionality for email click tracking services. However, it means all links clicked by recipients route through Snov.io's servers before redirecting, allowing Snov.io to collect data on which links are clicked and when. The exclusion list appropriately prevents wrapping of unsubscribe links and non-HTTP protocols.

---

### 7. Remote Domain List Updates - LOW

**Severity**: LOW
**Files**:
- `js/background/background.js` (lines 42-58)

**Description**:
The extension periodically fetches a list of tracking domains from the server every 12 hours.

**Code Evidence**:
```javascript
function updateHosts(force = false) {
  chrome.storage.local.get(["dateLastUpdateHosts", "trackHosts"], data => {
    const shouldUpdate = !data.dateLastUpdateHosts ||
                         432e5 <= Date.now() - data.dateLastUpdateHosts; // 12 hours
    if (force || shouldUpdate) {
      fetch(appHost + "/api/getTrackDomainsList", {
        method: "POST"
      }).then(res => res.json()).then(res => {
        if (res.result && res.list !== "undefined") {
          trackHosts = res.list;
          chrome.storage.local.set({ trackHosts: trackHosts });
        }
      });
    }
  });
}
```

**Verdict**: This allows Snov.io to distribute tracking infrastructure across multiple domains and update the list dynamically. While this provides operational flexibility, it also means tracking domains can be changed server-side. The update interval (12 hours) is reasonable and not aggressive. No evidence of malicious use.

---

## False Positives

| Pattern Detected | Context | Reason for FP |
|-----------------|---------|---------------|
| `innerHTML` assignments | jQuery, InboxSDK library, HTML template creation | Standard DOM manipulation in content scripts for UI rendering. All HTML is constructed from static templates, not user input. |
| `new Function()` in pageWorld.js | InboxSDK wrapper functions | Part of InboxSDK's legitimate page-world communication layer. Not used for arbitrary code execution. |
| Cookie access | Authentication flow | Only accesses own service cookies from snov.io domains for user authentication. |
| Firebase public keys | Firebase config | Public API keys are standard for Firebase - not sensitive credentials. |
| MD5 hashing | Email ID generation | Used to create anonymous identifiers from email addresses for tracking. Not a security mechanism. |

---

## API Endpoints and Data Flow

### Primary Backend Host
- **Main API**: `https://emailtracker.snov.io`
- **App Host**: `https://app.snov.io`

### Key API Endpoints

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `/trackData` | POST | Submit tracked email for monitoring | Full email content, recipients, subject, body HTML, thread ID, message ID, hashId, JWT |
| `/trackHistory` | POST | Retrieve tracking history for a thread | Thread ID, JWT |
| `/trackStatistics` | POST | Get aggregate statistics | Sender list, date range, hashId, JWT |
| `/updateDeviceToken` | POST | Register Firebase device token | Device token, hashId, JWT |
| `/notificationsSettings` | GET/POST | Manage notification preferences | Settings object, hashId, JWT |
| `/senders` | GET | Get list of tracked senders | hashId, JWT |
| `/updateSenders` | POST | Update sender tracking settings | Sender data, JWT |
| `/enableSync` | POST | Enable contact sync to CRM | Sender email, sync settings, list ID, hashId, JWT |
| `/getSyncStatus` | GET | Check sync status | Sender email, hashId, JWT |
| `/checkToken` | POST | Verify Gmail OAuth token | Email account, JWT |
| `/checkAuth` | POST | Verify user authentication | Selector & token cookies |
| `/gmailOauth` | GET | Initiate Gmail OAuth flow | Registration ID, email account |
| `/api/getTrackDomainsList` | POST | Get tracking domain list | None |
| `/api/lists/get-by-user-id` | GET | Get user's CRM lists | None |
| `/cancelLastOpening` | POST | Cancel false-positive email open | Thread ID |
| `/getSendLaterSetting` | POST | Get scheduled send settings | Draft ID, JWT |
| `/setOldReminder` | POST | Set email reminder | Reminder settings, JWT |
| `/getSendLatersTime` | POST | Get scheduled send times | Draft IDs, JWT |

### External Services
- **Google Analytics**: `https://www.google-analytics.com/collect` (usage analytics)
- **Firebase**: `mail-tracker-extension.firebaseapp.com` (push notifications)

---

## Data Flow Summary

### Outbound Data Collection

1. **Email Content** (on send):
   - Subject line
   - Full HTML body content
   - All recipients (to/cc/bcc)
   - Sender email address
   - Thread ID and message ID
   - Draft ID for scheduled sends
   - Destination: `emailtracker.snov.io/trackData`

2. **Tracking Events**:
   - Email open timestamps
   - Link click events with URLs
   - Device information (via Firebase)
   - User's hashId (account identifier)
   - Destination: Firebase Cloud Messaging + backend API

3. **Authentication Data**:
   - Snov.io session tokens (JWT)
   - Gmail email addresses
   - Gmail OAuth tokens (for send-later feature)
   - Destination: `app.snov.io` and `emailtracker.snov.io`

4. **Usage Analytics**:
   - Extension events (install, activate, settings changes)
   - Feature usage patterns
   - Star ratings and feedback interactions
   - Destination: Google Analytics

### Inbound Data

1. **Tracking Results**: Email open/click notifications via Firebase
2. **Statistics**: Aggregate tracking data for dashboard
3. **Configuration**: Tracking domain list, notification settings
4. **Account Data**: User profile, payment plan status, CRM sync settings

---

## Privacy Concerns

### High-Risk Data Collection
1. **Complete Email Surveillance**: Every tracked email's full content is transmitted to Snov.io's servers, including:
   - Proprietary business information
   - Personal communications
   - Recipient lists (potential lead databases)
   - Email subject lines and bodies

2. **Recipient Profiling**: The extension can build profiles of:
   - Who receives emails from users
   - When recipients open emails
   - Which links recipients click
   - Email engagement patterns

3. **Gmail OAuth Token Transmission**: For the "send later" feature, Gmail OAuth tokens are sent to Snov.io's servers (`/gmailOauth` endpoint), granting them potential access to the user's Gmail account.

### Data Retention
The code does not specify data retention policies. Users should consult Snov.io's privacy policy to understand how long email content and tracking data are stored.

### Third-Party Data Sharing
No evidence in the code indicates data is shared with third parties beyond:
- Google Analytics (usage telemetry only)
- Firebase (notification delivery)

---

## Security Observations

### Positive Security Practices
1. **JWT Authentication**: Uses modern token-based authentication with expiry checks
2. **HTTPS-Only**: All network requests use HTTPS
3. **Limited Scope**: Only operates on `mail.google.com` domain
4. **No Code Injection**: No evidence of eval(), arbitrary code execution, or dynamic script loading
5. **CSP Present**: Content Security Policy defined in manifest (though allows Google Analytics and Facebook Connect)
6. **Session Validation**: Regular 15-second JWT validation checks prevent stale sessions

### Potential Security Issues
1. **No Code Signing**: Deobfuscated code suggests no code integrity checks
2. **Public Firebase Config**: Firebase keys are public (standard but allows potential abuse)
3. **Broad Host Permissions**: `*://*.snov.io/*` allows access to all Snov.io subdomains
4. **Dynamic Domain Updates**: Tracking domains can be changed server-side without user notification

---

## Recommendations for Users

1. **Understand Data Collection**: This extension sends complete email content to Snov.io. Only use for emails you're comfortable sharing with a third party.

2. **Review Privacy Policy**: Check Snov.io's privacy policy for data retention, processing location, and sharing practices.

3. **Avoid Sensitive Emails**: Do not track emails containing:
   - Confidential business information
   - Personal health information
   - Financial data
   - Legal communications

4. **Verify OAuth Scopes**: The Gmail OAuth integration for "send later" should be reviewed to understand what access is granted.

5. **Monitor Extension Updates**: Watch for permission changes in future updates that might expand data access.

---

## Conclusion

The Unlimited Email Tracker by Snov.io functions as advertised and does not contain overtly malicious code. However, the nature of email tracking inherently requires extensive data collection. The extension legitimately needs access to email content, recipients, and interaction data to provide its core functionality.

The **MEDIUM risk rating** reflects:
- ✅ No malware detected
- ✅ No obfuscated malicious code
- ✅ Legitimate business purpose
- ⚠️ Extensive email content collection
- ⚠️ All data transmitted to third-party servers
- ⚠️ Recipient privacy implications
- ⚠️ Gmail OAuth token transmission

Users should make an informed decision about whether the email tracking benefits outweigh the privacy implications of sharing all tracked email content with Snov.io.

---

## Overall Risk Assessment

**MEDIUM**

The extension is legitimate but collects significant sensitive data as part of its core email tracking functionality. Users must trust Snov.io with full access to their outgoing email content, recipient lists, and engagement data.
