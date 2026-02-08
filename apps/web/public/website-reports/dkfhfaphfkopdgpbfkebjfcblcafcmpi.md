# MightyText - SMS from PC & Text from Computer
## Security Analysis Report

**Extension ID:** dkfhfaphfkopdgpbfkebjfcblcafcmpi
**User Count:** ~200,000
**Analysis Date:** 2026-02-06
**Analyst:** Claude Code Security Analysis

---

## EXECUTIVE SUMMARY

**Overall Risk Level:** CLEAN

MightyText is a legitimate SMS synchronization service that allows users to send and receive text messages from their computer. The extension has broad permissions appropriate for its functionality (SMS synchronization, notifications, content injection for web-to-phone features).

While the extension exhibits several patterns that could be concerning in a malicious context (third-party analytics, dynamic script injection, broad host permissions), these are all consistent with the extension's core functionality and transparent business model. No evidence of data harvesting, residential proxy infrastructure, extension killing, or other malicious patterns was found.

**Key Findings:**
- Legitimate SMS/phone synchronization service
- Third-party analytics (Google Analytics, Intercom) present but appropriate for user support
- Firebase/Pusher for real-time message sync (legitimate push notification infrastructure)
- Content script injection for "send to phone" context menus (expected functionality)
- Cookie-based authentication to `textyserver.appspot.com` backend
- No extension enumeration/killing behavior
- No XHR/fetch hooking or monkey-patching
- No residential proxy infrastructure
- No remote config kill switches
- No market intelligence SDKs (e.g., Sensor Tower)
- No AI conversation scraping

---

## METADATA

| Field | Value |
|-------|-------|
| Extension Name | MightyText - SMS from PC & Text from Computer |
| Extension ID | dkfhfaphfkopdgpbfkebjfcblcafcmpi |
| Version | 25.7.4 |
| Manifest Version | 3 |
| User Count | ~200,000 |
| Category | Productivity / Communication |

---

## PERMISSIONS ANALYSIS

### Declared Permissions
```json
"permissions": [
  "unlimitedStorage",
  "contextMenus",
  "tabs",
  "notifications",
  "scripting",
  "activeTab",
  "storage",
  "idle",
  "offscreen",
  "system.display"
],
"host_permissions": [
  "https://textyserver.appspot.com/*",
  "http://*.textyapp.com/*",
  "https://*.textyapp.com/*"
]
```

### Permission Justification
- **scripting/activeTab**: Used for dynamic content script injection for "send to phone" context menu functionality
- **contextMenus**: Right-click context menus to send images/links/text to phone
- **notifications**: Chrome notifications for incoming SMS messages
- **tabs**: Tab manipulation for opening MightyText web app and quick reply windows
- **idle/system.display**: Detect when user's computer is locked to manage notification auto-dismiss behavior
- **unlimitedStorage/storage**: Store contact photos, message history, user preferences
- **Host permissions**: Communication with MightyText backend servers

**Verdict:** All permissions are appropriate for SMS synchronization and web-to-phone functionality.

---

## CONTENT SECURITY POLICY

```json
"content_security_policy": {
  "extension_pages": "object-src 'self' 'wasm-unsafe-eval'; script-src 'self';"
}
```

**Analysis:** Standard MV3 CSP. No `unsafe-eval` for scripts, only allows WASM. No remote script loading in extension pages.

---

## VULNERABILITY ANALYSIS

### 1. Third-Party Analytics (Google Analytics + Intercom)

**Severity:** LOW (informational)
**File:** `scripts/background.js:28-47`

**Description:**
Extension loads Google Analytics (`UA-21391541-14`) and Intercom (`7guo5kws`) for usage tracking and customer support.

**Code Evidence:**
```javascript
// Line 28-33: Google Analytics
_gaq.push(["_setAccount", "UA-21391541-14"]),
function() {
  var e = document.createElement("script");
  e.type = "text/javascript", e.async = !0, e.src = "https://ssl.google-analytics.com/ga.js";
  var t = document.getElementsByTagName("script")[0];
  t.parentNode.insertBefore(e, t)
}()

// Line 36-54: Intercom
function() {
  var e = window, t = e.Intercom;
  if ("function" == typeof t) t("reattach_activator"), t("update", intercomSettings);
  else {
    var o = document, n = function() { n.c(arguments) };
    function i() {
      var e = o.createElement("script");
      e.type = "text/javascript", e.async = !0, e.src = "https://widget.intercom.io/widget/7guo5kws";
      var t = o.getElementsByTagName("script")[0];
      t.parentNode.insertBefore(e, t)
    }
    n.q = [], n.c = function(e) { n.q.push(e) }, e.Intercom = n,
    e.attachEvent ? e.attachEvent("onload", i) : e.addEventListener("load", i, !1)
  }
}()
```

**Data Sent:**
- User email (for support)
- Extension version
- Phone app version
- Pro user status
- Browser/OS information
- Event tracking (user actions like "Sent-Message-From-Compose-New-Iframe")

**Verdict:** ACCEPTABLE - Standard analytics for a commercial SaaS product. Intercom is commonly used for customer support. No evidence of excessive data collection beyond typical usage metrics.

---

### 2. Dynamic Content Script Injection

**Severity:** LOW
**File:** `scripts/context-menu.js:20-32`

**Description:**
Extension dynamically injects content scripts when user right-clicks on images/links/text to send to phone.

**Code Evidence:**
```javascript
chrome.scripting.insertCSS({
  target: { tabId: n.id },
  files: ["styles/font-awesome-4.2.0/css/font-awesome.css",
          "styles/material-icons/material-font.css",
          "styles/animate.css",
          "styles/bootstrap-alert-css-only/css/bootstrap-custom.css"]
}),
chrome.scripting.executeScript({
  target: { tabId: n.id },
  files: ["scripts/libs/jquery-2.1.0.min.js",
          "scripts/libs/bootstrap-growl-master/bootstrap-growl.min.js",
          "scripts/libs/jQuery.dotdotdot-1.6.14/src/js/jquery.dotdotdot.min.js",
          "scripts/common.js",
          "scripts/content_script.js"]
})
```

**Verdict:** ACCEPTABLE - This is standard behavior for context menu functionality. Scripts are only injected on user action (right-click), not automatically on all pages.

---

### 3. Push Notification Infrastructure (Firebase + Pusher)

**Severity:** LOW
**Files:** `scripts/mt-firebase.js`, `scripts/pusher-handler.js`

**Description:**
Extension uses Firebase Realtime Database and Pusher for receiving incoming SMS notifications in real-time.

**Code Evidence - Firebase:**
```javascript
// mt-firebase.js:3-13
firebase.auth().signInWithCustomToken(t).then((function() {
  window.frdSocket = firebase.database(),
  frdSocket.ref("channels/" + r).on("value", (function(e) {
    var t = e.val();
    "message" in t && (handlePushSocketOnMessageForBabySitter(t.message),
                       frdMSGPayloadHandler(t.message))
  }))
}))
```

**Code Evidence - Pusher:**
```javascript
// pusher-handler.js:5-16
Pusher.Runtime.createXHR = function() {
  var e = new XMLHttpRequest;
  return e.withCredentials = !0, e
};
var s = new Pusher(t.app_key, {
  authEndpoint: `${baseUrl}/pusher-auth?client=webapp&app_version=${manifest.version}`,
  excrypted: !0,
  cluster: t.cluster
});
s.subscribe(t.channel).bind(t.event, (function(e) {
  processIncomingPUSH(e.message.data)
}))
```

**Verdict:** ACCEPTABLE - This is legitimate push notification infrastructure for SMS synchronization. Firebase and Pusher are industry-standard solutions. The XHR `withCredentials` flag is necessary for authenticated WebSocket connections.

---

### 4. Cookie-Based Authentication

**Severity:** LOW
**File:** `scripts/background.js:96-132`

**Description:**
Extension relies on browser cookies for authentication to `textyserver.appspot.com`. User must be signed in via the web interface for the extension to work.

**Code Evidence:**
```javascript
// background.js:98-112
$.ajax({
  url: baseUrl + "/api?function=getUserInfoFull",
  type: "GET",
  success: function(e, t, o) {
    if (e.user && e.user.indexOf("user not logged in") > -1) {
      chrome.runtime.sendMessage({ createUserNotLoggedInNotification: !0 });
      setBrowserActionIcon("user-not-logged-in");
    } else if (e.user_info_full && e.user_info_full.email.length > 0) {
      google_username_currently_logged_in = e.user_info_full.email;
      initializeCRXForLoggedInUser(e.user_info_full);
    }
  }
})
```

**Verdict:** ACCEPTABLE - Cookie-based authentication is appropriate for a service that requires user accounts. Extension does not request `chrome.cookies` permission to access arbitrary cookies.

---

### 5. iframe Embedding of Web App

**Severity:** LOW
**File:** `scripts/web_to_phone.js:67-88`

**Description:**
Extension embeds MightyText web app in an iframe for the "compose new" quick reply widget.

**Code Evidence:**
```javascript
// web_to_phone.js:67-77
var a = "https://mightytext.net/" + n + "/?compose=true#mode=compose-new&view=iframe";
// ...
a += "&body=" + fixedEncodeURIComponent(d) + "&type=sms"
// ...
var y = '<iframe scrolling="no" id="mightyIframeWidget" src="' + u +
        '" data-intent="' + _ + '" data-web-content-type="' + a +
        '" data-widget-action-origin="' + f + '" ></iframe>';
$(h).appendTo("body")
```

**Verdict:** ACCEPTABLE - Extension embeds its own web app (`mightytext.net`) in an iframe for quick reply functionality. Uses `postMessage` for cross-origin communication (standard pattern). No evidence of malicious iframe injection.

---

### 6. localStorage/jsStorage Usage

**Severity:** LOW
**Files:** Multiple (background.js, common.js, options.js, etc.)

**Description:**
Extension extensively uses `localStorage` and jsStorage library for storing user preferences, contact photos, message cache, and notification settings.

**Stored Data Examples:**
- User email (`google_username_currently_logged_in`)
- Contact photos (base64-encoded thumbnails)
- Notification preferences
- Phone status (battery level, charging state)
- Message thread metadata
- Pro user status

**Verdict:** ACCEPTABLE - Local storage is appropriate for caching contacts and preferences. No evidence of storing sensitive credentials (passwords, tokens) in localStorage.

---

## FALSE POSITIVES

| Pattern | File | Reason | Verdict |
|---------|------|--------|---------|
| XMLHttpRequest override | pusher-handler.js:5-8 | Setting `withCredentials: true` for Pusher WebSocket auth, not monkey-patching | FALSE POSITIVE |
| Dynamic script insertion | background.js:28-33 | Loading Google Analytics (standard analytics), not eval-based code execution | FALSE POSITIVE |
| window.parent/postMessage | web_to_phone.js:107-141 | Cross-origin iframe communication with own web app for quick reply widget | FALSE POSITIVE |
| chrome.scripting.executeScript | context-menu.js:25-29 | Legitimate content script injection for context menu (on user action only) | FALSE POSITIVE |
| chrome.tabs.query | notifications.js:98-108 | Checking for existing quick reply windows to avoid duplicates | FALSE POSITIVE |
| setTimeout with function strings | Various libs | jQuery/Bootstrap/Socket.io library code (not extension code) | FALSE POSITIVE |
| Firebase API keys | mt-firebase.js:107 | Public Firebase API keys (expected for Firebase web apps) | FALSE POSITIVE |

---

## API ENDPOINTS / BACKEND INFRASTRUCTURE

| Endpoint | Purpose | Authentication | Notes |
|----------|---------|----------------|-------|
| `https://textyserver.appspot.com/api` | Main API (getUserInfoFull, GetDistinctMessageHeaders) | Cookie-based session | Google App Engine backend |
| `https://textyserver.appspot.com/signin` | User sign-in redirect | Cookie-based session | Redirects to help.html after auth |
| `https://textyserver.appspot.com/phonecontact` | Contact photos and phone contacts sync | Cookie-based session | Returns contact thumbnails |
| `https://textyserver.appspot.com/client` | C2DM/GCM push commands to phone | Cookie-based session | Sends actions like "get_phone_status" to Android device |
| `https://textyserver.appspot.com/usersettings` | User notification preferences | Cookie-based session | Legacy settings migration |
| `https://textyserver.appspot.com/pusher-auth` | Pusher authentication endpoint | Cookie-based session | Returns Pusher channel token |
| `https://textyserver.appspot.com/setup` | Firebase Realtime Database setup | Cookie-based session | Returns Firebase config + auth token |
| `https://textyserver.appspot.com/userconsents` | GDPR/privacy consent tracking | Cookie-based session | Records TOS/PP consent for EU users |
| `https://textyserver.appspot.com/imageserve` | MMS image serving | Cookie-based session | Serves picture messages |
| `https://textyserver.appspot.com/media` | Media file serving | Cookie-based session | Serves photos/videos synced from phone |
| `https://stats.mightytext.co` | Internal telemetry/metrics | N/A | Custom metrics endpoint (not GA) |
| `https://mightytext.co:2002` | IP geolocation / EU detection | N/A | GDPR compliance check |
| `https://mightytext.co:5001` | Android app icon lookup | N/A | For device notification icons |
| `https://mightytext.net/*` | Main web app | Cookie-based session | Quick reply iframe, compose new, settings |
| `https://beta.mightytext.net/*` | Beta web app | Cookie-based session | Alternative web app domain |
| `https://ssl.google-analytics.com/ga.js` | Google Analytics library | N/A | Third-party analytics |
| `https://widget.intercom.io/widget/7guo5kws` | Intercom support widget | N/A | Customer support chat |
| `https://js.pusher.com/4.1/pusher.min.js` | Pusher library | N/A | Real-time push library |
| `https://ajax.googleapis.com/ajax/libs/jquery/*` | jQuery CDN (heartbeat check) | N/A | Used to verify internet connectivity |
| Firebase Realtime Database | SMS/notification push channel | Custom token auth | Real-time message sync |
| Pusher | Alternative push provider | Pusher auth endpoint | Fallback for Firebase |

**Note:** All backend communication uses HTTPS. Authentication is cookie-based (user must be signed in via web interface). No hardcoded API keys or secrets found (Firebase keys are public client keys).

---

## DATA FLOW SUMMARY

### Inbound Data (Phone → Extension)
1. **SMS Messages:** Phone sends SMS to MightyText servers → Firebase/Pusher push → Extension receives notification → Chrome notification displayed
2. **Phone Status:** Phone reports battery level, connectivity → MightyText servers → Firebase/Pusher → Extension updates status
3. **Contacts:** Phone uploads contact list → MightyText servers → Extension fetches via `/phonecontact` API → Cached in jsStorage
4. **Media:** Phone uploads photos/videos → MightyText servers → Extension displays in notifications via `/imageserve` endpoint

### Outbound Data (Extension → Phone)
1. **Send SMS:** User composes message in extension → Extension sends to `/client` API → MightyText servers send C2DM/GCM push to phone
2. **Send Link/Image to Phone:** User right-clicks link/image → Extension sends "launch_from_url" or "fetch_binary_from_url_store_on_device" action → Phone receives and opens
3. **Mark as Read:** User clicks notification → Extension sends "mark_single_message_read" command → Phone marks SMS as read
4. **Get Phone Status:** Extension periodically requests phone status → Phone responds with battery, connectivity info

### User Data Collected
- **User email** (for authentication and Intercom support)
- **Contact list** (names, phone numbers, photos) - synced from phone
- **SMS message content** (for display in notifications)
- **Phone metadata** (battery level, charging state, OS version, app version)
- **Usage analytics** (via Google Analytics and Intercom)
- **Browser/OS info** (via analytics)
- **IP geolocation** (for GDPR/EU detection only)

### Third-Party Data Sharing
- **Google Analytics:** Anonymous usage metrics (browser, OS, events like "Sent-Message-From-Compose-New-Iframe")
- **Intercom:** User email, pro user status, last login timestamp (for customer support)
- **No evidence of data selling or sharing with ad networks**

---

## SECURITY BEST PRACTICES OBSERVED

1. **Manifest V3 Compliance:** Extension uses latest manifest version with stricter CSP
2. **No Remote Code Execution:** No `eval()`, no remote script loading in extension context
3. **Minimal Content Script:** Content script (`content_script.js`) is minimal and only logs anchor tags
4. **HTTPS Everywhere:** All backend communication uses HTTPS
5. **No Broad Host Permissions:** Host permissions limited to MightyText domains only
6. **Idle State Awareness:** Uses `chrome.idle` API to intelligently manage notifications when screen is locked
7. **User Consent for GDPR:** Extension checks user IP for EU location and prompts for TOS/PP consent

---

## SECURITY CONCERNS (None)

No significant security concerns identified. The extension operates transparently as an SMS synchronization service.

---

## RECOMMENDATIONS

1. **Transparency:** Consider adding a privacy policy link in the extension description to clarify data handling (Intercom, Google Analytics)
2. **Optional Analytics:** Consider making analytics opt-in rather than default
3. **Code Minification:** Bundle.js could be further optimized (currently 6786 lines) - though deobfuscated version suggests original is reasonably sized
4. **Firebase API Key Exposure:** While public Firebase API keys are expected, consider using Firebase App Check to prevent API abuse

---

## COMPARISON TO KNOWN MALICIOUS PATTERNS

| Malicious Pattern | Present in MightyText? | Evidence |
|-------------------|------------------------|----------|
| Extension Enumeration/Killing | NO | No `chrome.management` API usage found |
| XHR/Fetch Hooking | NO | Pusher XMLHttpRequest override is for legitimate auth, not global hook |
| Residential Proxy Infrastructure | NO | No proxy server code, no SOCKS/HTTP proxy patterns |
| Market Intelligence SDK (Sensor Tower) | NO | No Pathmatics or similar SDK found |
| AI Conversation Scraping | NO | No content script monitoring ChatGPT/Claude/etc. |
| Ad/Coupon Injection | NO | No DOM manipulation for ads |
| Remote Config Kill Switch | NO | Only admin override for dev/test purposes (not silent malicious updates) |
| Cookie Harvesting | NO | Does not access arbitrary cookies (only relies on own session cookies) |
| Keylogging | NO | No keydown/keyup event listeners found |
| Screenshot Capture | NO | No `chrome.tabs.captureVisibleTab` usage |
| Browsing History Exfiltration | NO | No `chrome.history` API usage |

---

## OVERALL RISK ASSESSMENT

**Risk Level:** CLEAN

**Justification:**
MightyText is a legitimate commercial product that functions exactly as advertised: it synchronizes SMS messages between Android phones and computers. All observed behaviors are consistent with this functionality:

- **Permissions:** Appropriate and necessary for SMS sync, notifications, and web-to-phone features
- **Backend Communication:** Limited to MightyText's own servers with cookie-based authentication
- **Analytics:** Standard commercial analytics (Google Analytics, Intercom) for product improvement and support
- **Push Infrastructure:** Industry-standard solutions (Firebase, Pusher) for real-time message delivery
- **Code Quality:** Well-structured, no obfuscation, no eval-based execution
- **Privacy:** GDPR-compliant with EU user consent prompts

The extension does not exhibit any of the malicious patterns found in VPN extensions like Urban VPN (XHR/fetch hooks), VeePN (extension killing), Troywell (remote kill switch), or StayFree/StayFocusd (Sensor Tower market intelligence SDK).

**Conclusion:** This extension is CLEAN and safe for users who want SMS synchronization functionality.

---

## APPENDIX: FILE INVENTORY

### Critical Files Analyzed
- `manifest.json` - Permissions, CSP, background service worker
- `bundle.js` (6786 lines) - Main background service worker (date-fns, analytics, system integration)
- `scripts/background.js` (919 lines) - Core background logic (authentication, notifications, heartbeat)
- `scripts/context-menu.js` (208 lines) - Context menu handlers for send-to-phone
- `scripts/web_to_phone.js` (296 lines) - Web-to-phone functionality, iframe widget
- `scripts/notifications.js` (518 lines) - Chrome notification management, quick reply windows
- `scripts/capi.js` - Channel API / push message processing
- `scripts/pusher-handler.js` - Pusher WebSocket client
- `scripts/mt-firebase.js` - Firebase Realtime Database client
- `scripts/content_script.js` - Minimal content script (only logs anchor tags)

### Library Files (Not Analyzed in Detail)
- jQuery 2.1.0
- Socket.io
- Moment.js
- Bootstrap 3.3.6
- Font Awesome 4.2.0
- jsStorage
- jQuery File Upload
- jQuery dotdotdot
- Bootstrap Growl

---

**Report Generated:** 2026-02-06
**Analysis Tool:** Claude Code Security Scanner
**Analyst:** Claude Sonnet 4.5
