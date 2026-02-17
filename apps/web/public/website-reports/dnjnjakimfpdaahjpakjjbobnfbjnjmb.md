# Security Analysis: WASender Messaging, AI replies, and WA CRM (dnjnjakimfpdaahjpakjjbobnfbjnjmb)

## Extension Metadata
- **Name**: WASender Messaging, AI replies, and WA CRM
- **Extension ID**: dnjnjakimfpdaahjpakjjbobnfbjnjmb
- **Version**: 1.0.31
- **Manifest Version**: 3
- **Estimated Users**: ~50,000
- **Developer**: wasender.ai
- **Analysis Date**: 2026-02-15

## Executive Summary
WASender is a WhatsApp Web automation extension that provides bulk messaging, contact management, and chatbot features. While the extension appears functionally legitimate for its stated purpose, analysis reveals **MEDIUM** risk due to hardcoded Firebase credentials that could be exploited by malicious actors, user IP geolocation tracking via an unencrypted HTTP endpoint, and extensive telemetry collection. The extension does not appear to be actively malicious but demonstrates poor security practices that create privacy and security risks for users.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. Hardcoded Firebase Credentials (Medium Severity)
**Severity**: MEDIUM
**Files**: `/content/firebaseconfig.js` (lines 3-12)

**Analysis**:
The extension contains hardcoded Firebase API credentials exposed in client-side JavaScript, creating a significant security vulnerability.

**Code Evidence**:
```javascript
function getFirebaseInstance() {
  let n = "attachments",
    e = {
      apiKey: "AIzaSyCeTx0Jh1bRXJHx8HDaozYDXZzptZ-a0Y4",
      authDomain: "waplugin-34798.firebaseapp.com",
      databaseURL: "https://waplugin-34798-default-rtdb.firebaseio.com",
      projectId: "waplugin-34798",
      storageBucket: "waplugin-34798.firebasestorage.app",
      messagingSenderId: "337497813025",
      appId: "1:337497813025:web:781b4ac8cad23291f33360",
      measurementId: "G-MZWGFZ4JX5"
    };
  // ...
  firebase.initializeApp(e)
```

**Security Implications**:
- **API Key Exposure**: The Firebase API key is visible to anyone who inspects the extension code
- **Storage Access**: The extension stores user attachments in Firebase Storage using phone numbers as paths (`attachments/${phoneNumber}/`)
- **Potential Abuse**: Malicious actors could potentially:
  - Access Firebase Storage if security rules are misconfigured
  - Enumerate stored attachments by phone number
  - Generate excessive Firebase API calls to incur costs for the developer
  - Use the credentials to access other Firebase services if they share the same project

**Storage Path Pattern** (lines 18-22):
```javascript
async function t(e) {
  attachmentsChildURL = n + "/" + e;  // "attachments/" + phoneNumber
  e = await (attachmentsChildRef = i().child(attachmentsChildURL)).listAll();
  if (e.items.length) return e.items;
  throw new Error("No Attachment Found")
}
```

**Risk Level**: Medium - While Firebase security rules may mitigate some risks, client-side credential exposure is a fundamental security anti-pattern.

---

### 2. User IP Geolocation via Unencrypted HTTP (Medium Severity)
**Severity**: MEDIUM
**Files**: `/common/country-finder.js` (line 1)

**Analysis**:
The extension tracks user geolocation by making an HTTP (not HTTPS) request to a third-party IP geolocation service during installation.

**Code Evidence**:
```javascript
function countryFinder(){
  return{
    find:async function(){
      try{
        var t=await(await fetch("http://ip-api.com/json")).json();
        if(t&&"success"==t.status&&t.countryCode)
          return t.countryCode
      }catch(t){}
    }
  }
}
```

**Trigger Point** (`/background/service-worker.js` lines 13-22):
```javascript
chrome.runtime.onInstalled.addListener(async function(e) {
  chrome.alarms.create("keepAlive", {
    periodInMinutes: .1
  }), chrome.tabs.create({
    url: "https://web.whatsapp.com"
  }), chrome.tabs.create({
    url: "https://wasender.ai/installed.html"
  });
  var a = await countryFinder().find();
  a && storageInstance.saveDefaultCountryCode(a)
})
```

**Security Implications**:
- **Unencrypted Transmission**: HTTP connection allows network intermediaries to see user IP addresses and responses
- **Privacy Concern**: User geolocation is determined without explicit consent
- **Third-Party Dependency**: Reliance on external service (ip-api.com) introduces privacy and availability risks
- **Man-in-the-Middle Risk**: HTTP traffic can be intercepted and modified

**Data Transmitted**:
- User's public IP address (sent to ip-api.com)
- Response contains: country code, status, potentially other geo data

**Risk Level**: Medium - While geolocation via IP is not inherently malicious, the use of HTTP instead of HTTPS and lack of user consent are concerning.

---

### 3. Extensive Telemetry and Analytics Collection (Low Severity)
**Severity**: LOW
**Files**: `/common/analytics.js` (entire file, 229 lines)

**Analysis**:
The extension implements comprehensive telemetry that tracks user behavior, messaging activity, and feature usage.

**Tracked Events**:
1. **Installation tracking** (line 11-13):
```javascript
logInstalls: async function(e) {
  await fetch("https://us-central1-waplugin-34798.cloudfunctions.net/logInstalls?refid=" + e)
}
```

2. **User revisits** (lines 14-16):
```javascript
logRevisits: async function(e, t) {
  await fetch(`https://us-central1-waplugin-34798.cloudfunctions.net/logRevists?name=${encodeURI(e)}&userid=${encodeURI(t)}&version=` + encodeURI(o?.version))
}
```

3. **Single message tracking** (lines 66-83):
```javascript
logSingleMsgDetail: async function(e, t, n) {
  console.log("manifestData", o), await fetch("https://us-central1-waplugin-34798.cloudfunctions.net/stats/singlemsg", {
    method: "POST",
    // ...
    body: JSON.stringify({
      message: t,          // Message content
      phoneNumber: n,      // Recipient phone number
      userid: e,           // User ID
      version: o?.version
    })
  })
}
```

4. **Bulk messaging tracking** (lines 85-101):
```javascript
logBulkMessageDetail: async function(e, t) {
  await fetch("https://us-central1-waplugin-34798.cloudfunctions.net/stats/bulkmsg", {
    // ...
    body: JSON.stringify({
      userid: e,
      taskData: t  // Bulk messaging task details
    })
  })
}
```

5. **Contact download tracking** (`/content/content.js` lines 778-798):
```javascript
async function logContactDownloadDetail(e, t) {
  try {
    await fetch(CONTACT_DOWNLOAD_DETAIL_URL, {
      method: "POST",
      // ...
      body: JSON.stringify({
        userid: e,
        downloadData: t  // Download statistics
      })
    })
  } catch (e) {}
}
```

6. **Feature upgrade clicks** (lines 18-35)
7. **Report downloads** (lines 37-56)
8. **Login attempts** (lines 60-65)
9. **Template saves** (lines 117-133)
10. **Ad displays** (lines 138-152)
11. **Help requests** (lines 180-199)

**Data Collected**:
- User phone number (from WhatsApp)
- User name
- Message content (for single messages)
- Recipient phone numbers
- Bulk messaging statistics
- Contact download counts
- Extension version
- Feature usage patterns
- License/subscription status

**Privacy Implications**:
- **Message Content**: Single messages are sent to developer's server (line 78)
- **Contact Data**: Phone numbers and messaging patterns tracked
- **User Identification**: User phone number serves as persistent identifier
- **No Opt-Out**: Telemetry appears mandatory for core functionality

**Mitigating Factors**:
- All telemetry uses HTTPS
- Telemetry endpoints are on developer's domain (waplugin-34798.cloudfunctions.net)
- No evidence of selling data to third parties
- Appears to be for product analytics and license enforcement

**Risk Level**: Low - While extensive, telemetry appears to be for legitimate business purposes (analytics, licensing). However, users should be aware of the data collection.

---

### 4. Service Worker Keep-Alive Mechanism (Informational)
**Severity**: INFORMATIONAL
**Files**: `/background/service-worker.js` (lines 14-15, 23-25)

**Analysis**:
The extension uses an alarm to prevent service worker termination, a common pattern in MV3 extensions but one that consumes additional system resources.

**Code Evidence**:
```javascript
chrome.runtime.onInstalled.addListener(async function(e) {
  chrome.alarms.create("keepAlive", {
    periodInMinutes: .1  // Every 6 seconds
  })
  // ...
})

chrome.alarms.onAlarm.addListener(e => {
  "keepAlive" === e.name && console.log("Service Worker is kept alive!")
})
```

**Purpose**: Prevents Chrome from terminating the service worker due to inactivity, ensuring message dispatching works reliably.

**Impact**:
- Increased memory usage
- More frequent background activity
- Potential battery impact on laptops

**Risk Level**: Informational - This is a documented workaround for MV3 service worker limitations, though it does consume more resources than necessary.

---

## Network Analysis

### External Endpoints Contacted

1. **us-central1-waplugin-34798.cloudfunctions.net** (Primary Backend)
   - Purpose: Telemetry, analytics, licensing, contact download stats
   - Protocol: HTTPS
   - Data Sent: User ID, phone numbers, message content (single msgs), feature usage
   - Frequency: On various user actions (install, message send, contact download, etc.)

2. **ip-api.com** (Geolocation Service)
   - Purpose: Determine user country code on installation
   - Protocol: HTTP (INSECURE)
   - Data Sent: User IP address (implicit)
   - Frequency: Once on installation
   - Risk: Unencrypted, third-party service

3. **wasender.ai** (Developer Website)
   - Purpose: Installation welcome page, uninstall survey, feature documentation
   - Protocol: HTTPS
   - Data Sent: Minimal (URL parameters)
   - Frequency: On install/uninstall events

4. **Firebase Services** (Storage and Realtime Database)
   - **waplugin-34798.firebaseapp.com** - Auth domain
   - **waplugin-34798-default-rtdb.firebaseio.com** - Realtime database
   - **waplugin-34798.firebasestorage.app** - File storage for attachments
   - Purpose: Store user attachments (images, documents)
   - Protocol: HTTPS
   - Data Sent: Attachments uploaded by user for bulk messaging
   - Storage Path: `attachments/{userPhoneNumber}/{filename}{timestamp}`

5. **web.whatsapp.com**
   - Purpose: Extension's primary operational context (WhatsApp Web)
   - Protocol: HTTPS
   - Note: Extension injects into and automates WhatsApp Web

### Data Flow Summary

```
User → Extension → Analytics Functions (message content, phone numbers, usage stats)
                 ↓
                 Firebase Storage (user attachments, keyed by phone number)
                 ↓
                 ip-api.com (IP geolocation, HTTP)
                 ↓
                 wasender.ai (install/uninstall redirects)
```

---

## Permission Analysis

### Declared Permissions

1. **storage** - Used extensively for:
   - User authentication state (phone number, name, auth ID)
   - Bulk messaging configuration (batch size, delays, messages)
   - Contact data (phone numbers, Excel file data)
   - Templates and chatbot config
   - UI state persistence
   - **Assessment**: Appropriate for stated functionality

2. **cookies** - Declared but not observed in deobfuscated code
   - Host permission for `https://wasender.ai/`
   - Likely for authentication/session management with backend
   - **Assessment**: Usage unclear from static analysis

3. **alarms** - Used for:
   - Service worker keep-alive (every 6 seconds)
   - **Assessment**: Appropriate but resource-intensive implementation

### Host Permissions

1. **https://wasender.ai/*** - Developer's domain
   - Used for installation/uninstall redirects
   - Potential cookie access for authentication
   - **Assessment**: Standard for extension backend communication

### Content Script Injection

- **Target**: `*://web.whatsapp.com/*`
- **Scripts Injected**: 37 JavaScript files including jQuery, Firebase, libphonenumber, XLSX parser
- **Purpose**: WhatsApp Web automation, DOM manipulation for bulk messaging
- **Assessment**: Extensive injection necessary for WhatsApp automation functionality

---

## Security Best Practices Violations

1. **Hardcoded Secrets**: Firebase credentials should use environment variables or server-side proxies
2. **HTTP Usage**: All network requests should use HTTPS (ip-api.com uses HTTP)
3. **Credential Exposure**: Client-side code should not contain full Firebase config
4. **Message Content Transmission**: Single message content sent to analytics server (privacy concern)
5. **No Privacy Policy Link**: Extension metadata should include privacy policy for data collection disclosure

---

## Legitimate Functionality

The extension provides the following features as advertised:

1. **Bulk Messaging**: Send messages to multiple WhatsApp contacts via CSV/Excel import
2. **Contact Management**: Download WhatsApp contacts, groups, labels to Excel
3. **Message Templates**: Save and reuse message templates
4. **Privacy Features**: Blur contact names, numbers, profile pictures, messages
5. **Contact Online Tracking**: Highlight and notify when contacts come online
6. **Read Receipt Control**: Toggle read receipts and typing indicators
7. **Message Restoration**: Save and restore deleted messages
8. **Chatbot**: Auto-reply functionality
9. **Attachment Forwarding**: Bulk send images, videos, documents

**Legitimate Use Cases**:
- Small business customer communication
- Event invitation distribution
- Community group management
- CRM integration for WhatsApp

---

## Obfuscation Analysis

**ext-analyzer Flag**: `obfuscated: true`

The code shows signs of minification and variable renaming but is not heavily obfuscated:
- Single-letter variable names (e, t, n, o, a, s, c, l)
- Minimized whitespace
- Some string obfuscation (concatenation patterns)
- However, code structure and logic remain readable after beautification

**Assessment**: Standard build minification rather than intentional malicious obfuscation.

---

## Data Exfiltration Analysis

**ext-analyzer Exfiltration Flows**: 4 flagged flows

1. **document.querySelectorAll → fetch(web.whatsapp.com)** - content/content.js
2. **document.getElementById → fetch(web.whatsapp.com)** - content/content.js
3. **chrome.tabs.query → *.src(web.whatsapp.com)** - chrome-msging.js ⇒ content.js
4. **chrome.tabs.query → fetch(web.whatsapp.com)** - chrome-msging.js ⇒ content.js

**Analysis**: These flows represent the extension's core functionality - extracting data from WhatsApp Web DOM to perform automation. The destination is `web.whatsapp.com` (WhatsApp's own domain), not a third-party server, so these are **false positives** for malicious exfiltration. The extension is reading WhatsApp's page to send messages programmatically.

**Actual Data Sent to Developer Servers**:
- User phone number, name (for authentication/identification)
- Message content (single messages only, for analytics)
- Recipient phone numbers (for messaging statistics)
- Contact download counts
- Feature usage events

This data transmission is disclosed in the context of a messaging/CRM tool, though users may not be fully aware of the extent of tracking.

---

## Contact Masking for Non-Premium Users

**Location**: `/content/content.js` (lines 807-860)

The extension implements phone number masking for users without "ninja" (premium) license:

```javascript
async function getSavedContacts(n) {
  let o = [];
  return n && (await isNinja() ? n.forEach((e, t) => {
    o.push({
      Name: n[t].name,
      PhoneNumber: n[t].phoneNumber  // Full number for premium users
    })
  }) : n.forEach((e, t) => {
    o.push({
      Name: n[t].name,
      PhoneNumber: n[t].phoneNumber.replace(/\d{6}$/, "****")  // Last 6 digits masked
    })
  })), o
}
```

**Purpose**: Upsell mechanism - free users see masked phone numbers (last 6 digits replaced with `****`) when downloading contacts.

**Assessment**: Legitimate freemium model implementation, though the masking happens client-side (user data is still fully accessible in WhatsApp Web itself).

---

## Hardcoded Phone Number

**Location**: `/content/content.js` (line 129)

```javascript
case MSG_RELOAD_ATTACHMENT:
  await sendMessage("918527440658", ""),
  await sendMessage(getMyPhoneNumber(), ""),
  o = getAttachment();
  break;
```

The extension contains a hardcoded Indian phone number (`+91 852 744 0658`) that receives a message during attachment reload operations.

**Implications**:
- This appears to be a developer debug/test number
- Messages sent are empty strings (`""`)
- Could be for usage tracking or testing purposes
- Minor privacy concern - sends a message to developer's number without user awareness

**Risk Level**: Low - Messages are empty, but presence of developer number in code is unusual.

---

## Final Risk Assessment

### Risk Score: MEDIUM

**Vulnerabilities Breakdown**:
- **Critical**: 0
- **High**: 0
- **Medium**: 2 (Hardcoded Firebase credentials, HTTP geolocation tracking)
- **Low**: 1 (Extensive telemetry collection)
- **Informational**: 1 (Service worker keep-alive)

### Recommendation

**For Users**:
- **Moderate Caution**: The extension performs its stated function but has security and privacy weaknesses
- Be aware that message content and recipient phone numbers are sent to developer's servers
- Geolocation tracking occurs on installation via unencrypted HTTP
- Consider whether bulk messaging use case justifies the extensive data collection

**For Developers**:
1. **Immediate**: Remove hardcoded Firebase credentials; use server-side proxy
2. **Immediate**: Switch ip-api.com to HTTPS endpoint (`https://ip-api.com/json`)
3. **High Priority**: Implement privacy policy and disclose data collection practices
4. **Medium Priority**: Reduce telemetry collection or make it opt-in
5. **Medium Priority**: Remove hardcoded phone number (918527440658) from code
6. **Low Priority**: Optimize service worker keep-alive mechanism to reduce resource usage

### Comparison to Similar Extensions

WASender exhibits typical patterns of WhatsApp automation extensions:
- Extensive DOM injection on web.whatsapp.com
- Bulk messaging and contact extraction
- Freemium licensing model with server-side validation

However, it demonstrates worse security practices than well-designed alternatives:
- Exposed API credentials
- Unencrypted third-party requests
- Message content transmission to analytics

---

## Conclusion

WASender is a **functionally legitimate** WhatsApp automation tool with **poor security implementation**. The extension is not actively malicious but exposes users to unnecessary privacy and security risks through hardcoded credentials, HTTP geolocation tracking, and extensive telemetry. Users seeking WhatsApp CRM functionality should be aware of these trade-offs. The developer should address the identified security issues to meet industry best practices.

**Final Verdict: MEDIUM Risk** - Use with caution; security improvements needed.
