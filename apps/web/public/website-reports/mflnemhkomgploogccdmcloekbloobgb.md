# RightInbox Email Security Analysis

## Extension Metadata
- **Name**: RightInbox: Email Reminders, Tracking, Notes
- **Extension ID**: mflnemhkomgploogccdmcloekbloobgb
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Version**: 11.0.2

## Executive Summary

RightInbox is a legitimate Gmail productivity extension that provides email scheduling, tracking, templates, and notes functionality. The extension transmits sensitive email metadata (subjects, recipients, email content) to remote servers for legitimate feature functionality. While no clear malicious intent was identified, the extension's broad data access and transmission of email metadata creates **privacy concerns** for users handling sensitive communications.

**Risk Level**: MEDIUM

The extension operates as designed for its advertised features but handles user email data extensively, sending compose headers (to/from/cc/bcc/subject) and tracking data to rightinbox.com servers. Users should be aware of this data sharing when composing emails.

## Vulnerability Analysis

### 1. Email Metadata Transmission to Remote Servers
**Severity**: MEDIUM
**Files**: `app/rightinbox-client-chrome.js` (lines 3399-3413, 6097-6167)
**Verdict**: Privacy Concern - Legitimate Functionality

**Description**:
The extension collects and transmits email compose headers to rightinbox.com servers for scheduling, tracking, and sequence features:

```javascript
function extendWithComposeHeaders(button, data, whichHeaders) {
  var parentWin = getParentWin(button),
    parentWin = {
      from: whichHeaders.from ? $("textarea[name='from'],select[name='from'],input[name='from']", parentWin).val() || ri.user : void 0,
      to: whichHeaders.to ? $("textarea[name='to'],input[name='to']", parentWin).val() : void 0,
      cc: whichHeaders.cc ? $("textarea[name='cc'],input[name='cc']", parentWin).val() : void 0,
      bcc: whichHeaders.bcc ? $("textarea[name='bcc'],input[name='bcc']", parentWin).val() : void 0,
      subject: whichHeaders.subject ? $("input[name='subject']", parentWin).val() : void 0
    };
  return $.extend(!0, data, whichHeaders.trackingId ? {
    trackingId: ri.trackingId[button.selector]
  } : void 0, whichHeaders.date ? {
    date: (new Date).toString()
  } : void 0), $.extend(!0, data, parentWin), data
}
```

Data sent via XMLHttpRequest to:
- `https://app.rightinbox.com/js/{requestId}/{action}`
- `https://init.rightinbox.com/js/{requestId}/{action}`
- `https://poll.rightinbox.com/js/{requestId}/{action}`
- `https://logger.rightinbox.com/log/{requestId}`

**Privacy Impact**:
- Email subjects may contain confidential information
- Recipient lists (to/cc/bcc) are transmitted
- Legitimate for scheduled send and email tracking features, but users should be informed

### 2. Email Tracking Implementation
**Severity**: LOW
**Files**: `app/rightinbox-client-chrome.js` (lines 688-706, 717-731)
**Verdict**: Legitimate Feature - Standard Email Tracking

**Description**:
The extension injects invisible tracking pixels into email bodies to detect opens and clicks:

```javascript
function handleInsertedLinks(trackButton) {
  parentWin = getParentWin(trackButton),
  editable = getEditable(parentWin)
  img = "<img id='trackingClick' style = 'width:0px;height:0px' src='TrackClickActive/ffoollllooww/" + ri.trackingId[trackButton.selector] + "/'>",
  0 === editable.find("#trackingClick").length && editable.append(img)
}

function putTrackingGif(trackButton) {
  img = "<img id='trackingGif' style = 'width:0px;height:0px' src='" + (() => {
  })() + "ggiiff/" + ri.trackingId[trackButton.selector] + "/'>",
  0 === editable.find("#trackingGif").length && editable.append(img)
}
```

This is a standard email tracking technique used by many email productivity tools. Tracking is user-initiated and disclosed.

### 3. Third-Party Integration: Mailshake
**Severity**: LOW
**Files**: `app/rightinbox-client-chrome.js` (lines 68-295)
**Verdict**: Legitimate Integration

**Description**:
The extension integrates with Mailshake (a sales engagement platform), allowing users to add email recipients to Mailshake campaigns directly from Gmail. Email addresses are transmitted to rightinbox.com servers:

```javascript
function mailshakeListAllCampaigns() {
  requestXMLHttp("mailshakeListAllCampaigns", {
    email: ""
  }, function(err, result) {
    // Campaign data handling
  })
}
```

This integration is disclosed in the extension's functionality and requires user action.

### 4. Background Script Message Handling
**Severity**: LOW
**Files**: `background.js` (lines 7-85)
**Verdict**: Clean - Proper CORS Bypass Pattern

**Description**:
The background script acts as a proxy for cross-origin requests using chrome.runtime.onMessage:

```javascript
chrome.runtime.onMessage.addListener(
  function (request, sender, sendResponse) {
    if (request.external == true) {
      if (request.conversationMode == true) {
        $.ajax({
          url: request.src,
          dataType: 'text',
          timeout: 30000,
          success: function (data, textStatus, jqXHR) {
            sendResponse({status: true, success: true, data: data});
          },
          // ...
        });
      } else if (request.stripe || request.mailMerge) {
        fetch(src, reqHash)
          .then(response => response.json())
          .then(res => {
            sendResponse({status: true, ...res});
          })
      }
    }
    return true;
  });
```

This is a standard pattern for MV3 extensions to handle cross-origin requests since content scripts cannot make arbitrary CORS requests. The message listener only responds to messages from the extension's own content scripts (implicit sender validation).

### 5. Cookie and Session Management
**Severity**: LOW
**Files**: `app/rightinbox-client-chrome.js` (lines 3830-3838, 6106-6110)
**Verdict**: Standard Session Management

**Description**:
The extension uses cookies for session management and user preferences:

```javascript
function setLocalPrefs(key, value, overWrite) {
  var currentCookie = $.cookie("rightinbox") || {};
  // ... cookie management logic
  $.cookie("rightinbox", currentCookie, {
    expires: 365,
    path: "/"
  });
}

// Session ID generation
sid = $.cookie("RIGSID") || uuid()
$.cookie("RIGSID", sid, {
  expires: 7,
  path: "/"
})
```

Standard cookie usage for maintaining user sessions and preferences. No sensitive data exfiltration detected.

### 6. OAuth Authentication Flow
**Severity**: LOW
**Files**: `app/rightinbox-client-chrome.js` (lines 3753, 6150-6167)
**Verdict**: Legitimate OAuth Implementation

**Description**:
The extension uses OAuth for authentication with Gmail API access:

```javascript
function redirectToAuth(url) {
  // OAuth redirect handling
}

// OAuth retry logic
data.tryOauth ? "handShake" === action ? (
  tryOauthPref = getLocalPrefs("tryOauth+" + email),
  setLocalPrefs("tryOauth+" + email, now),
  // ...
  ri.authCheck()
```

Standard OAuth implementation for Gmail integration. No credentials are hardcoded or mishandled.

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML` usage | Lines 503, 3735, 3979 | Used for HTML sanitization and DOM manipulation in trusted contexts (template rendering) |
| `Function()` constructor | Line 8159 | Part of bundled library (likely JSON parser polyfill) for browser compatibility |
| `fromCharCode` | Lines 7421-7600 | Base64 encoding/decoding utility functions (standard crypto operations) |
| `document.cookie` | Lines 7013-7236 | jQuery cookie plugin - standard cookie management |
| XHR with credentials | Line 7 | Legitimate API calls to rightinbox.com with user's session cookie |

## API Endpoints

| Endpoint | Purpose | Data Transmitted |
|----------|---------|------------------|
| `https://app.rightinbox.com/js/{id}/scheduleEmail` | Email scheduling | Email headers (to/from/cc/bcc/subject), date, tracking preferences |
| `https://app.rightinbox.com/js/{id}/addTemplate` | Template management | Template title, subject, HTML content |
| `https://app.rightinbox.com/js/{id}/addNote` | Email notes | Note content, email subject, thread ID |
| `https://app.rightinbox.com/js/{id}/trackEmail` | Email tracking | Tracking ID, email headers, preferences |
| `https://init.rightinbox.com/oauth2/user/{email}` | OAuth authentication | User email for OAuth flow |
| `https://poll.rightinbox.com/js/{id}/getRealTimeTrackingData` | Real-time tracking | Tracking status requests |
| `https://logger.rightinbox.com/log/{id}` | Error logging | Error logs and diagnostics |
| `https://app.mailshake.com/` | Mailshake integration | Campaign data, recipient emails |

## Data Flow Summary

1. **User Compose Email** → Extension reads Gmail compose window DOM
2. **User Clicks Schedule/Track** → Extension extracts email headers (to/from/cc/bcc/subject)
3. **Data Transmission** → Headers sent to rightinbox.com servers via XMLHttpRequest
4. **Server Processing** → RightInbox servers schedule email or setup tracking
5. **Tracking Pixels** → Invisible images injected into email body for open/click tracking
6. **OAuth Flow** → Standard Gmail OAuth for API access to send scheduled emails

**Sensitive Data Handled**:
- Email subjects (may contain confidential information)
- Recipient email addresses (to/cc/bcc)
- Email content (for templates and scheduled emails)
- Gmail thread IDs
- User's Gmail address

**Data Not Transmitted**:
- Full inbox contents (unless user actively schedules/tracks specific emails)
- Email passwords or OAuth tokens (handled via standard OAuth flow)
- Arbitrary email body content (only user-initiated actions)

## Overall Risk Assessment

**Risk Level: MEDIUM**

**Rationale**:
- **No Malicious Behavior Detected**: The extension operates as advertised for its stated features
- **Privacy Concerns**: Email metadata (subjects, recipients) transmitted to third-party servers
- **Legitimate Functionality**: All data collection appears necessary for advertised features
- **User Awareness**: Users may not fully understand extent of data sharing
- **Limited Permissions**: Manifest V3 with minimal host_permissions (only rightinbox.com)

**Recommendation**:
The extension is legitimate but users handling highly confidential emails should be aware that email metadata is transmitted to RightInbox servers for scheduling and tracking functionality. Organizations with strict data retention policies may want to review RightInbox's privacy policy before deployment.

**For Sensitive Environments**:
Consider alternative solutions that don't transmit email metadata to third-party servers, or ensure RightInbox's data handling meets organizational compliance requirements (GDPR, HIPAA, etc.).
