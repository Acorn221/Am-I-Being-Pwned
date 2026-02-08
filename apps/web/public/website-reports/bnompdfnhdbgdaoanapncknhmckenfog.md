# Security Analysis: Email Tracker + Pixelblock Detector and Blocker

**Extension ID**: `bnompdfnhdbgdaoanapncknhmckenfog`
**Version**: 5.0.52
**Users**: ~300,000
**Risk Level**: MEDIUM
**Vendor**: emailtracker.website

---

## Executive Summary

Email Tracker + Pixelblock Detector & Blocker is a **legitimate email tracking utility** with moderate security concerns related to its invasive capabilities and privacy implications. The extension provides email read receipts and link tracking for Gmail, Outlook, and Yahoo Mail. While the extension's core functionality is as-advertised, it employs highly invasive techniques including **XHR/fetch hooking**, **Content Security Policy bypass**, **Worker thread injection**, and **extensive DOM manipulation**. The extension collects email metadata and sends it to `emailtracker.website` servers.

**Primary concerns**:
1. Aggressive XMLHttpRequest/fetch hooking on Gmail/Outlook/Yahoo webmail interfaces
2. CSP header stripping on Outlook domains to enable tracking pixel injection
3. Web Worker monkey-patching to intercept Outlook service worker requests
4. Link rewriting functionality that proxies all clicked links through tracking servers
5. Email content and metadata collection sent to third-party servers
6. Broad host permissions (`<all_urls>`) enabling access to all websites

**Verdict**: MEDIUM risk. Not malware, but implements highly invasive tracking infrastructure with significant privacy implications for user communications.

---

## Manifest Analysis

### Permissions (MV3)
```json
"permissions": [
  "tabs",
  "storage",
  "unlimitedStorage",
  "cookies",
  "declarativeNetRequest",
  "declarativeNetRequestWithHostAccess",
  "declarativeNetRequestFeedback",
  "gcm",
  "notifications",
  "scripting",
  "offscreen",
  "alarms",
  "webNavigation"
],
"host_permissions": ["<all_urls>"]
```

**Risk Assessment**:
- **`<all_urls>`**: Grants access to all websites, not just email providers (excessive)
- **`cookies`**: Used to set tracking cookies across multiple domains
- **`declarativeNetRequest*`**: Used for CSP bypass and tracker pixel blocking
- **`gcm`**: Firebase Cloud Messaging for real-time email open notifications
- **`scripting`**: Dynamic script injection for content script refresh

### Content Security Policy Bypass

**CRITICAL FINDING**: The extension strips CSP headers on Outlook domains:

```json
// declarative_net_request_rules.json
{
  "id": 5002,
  "action": {
    "type": "modifyHeaders",
    "responseHeaders": [
      {"header": "content-security-policy", "operation": "remove"},
      {"header": "content-security-policy-report-only", "operation": "remove"}
    ]
  },
  "condition": {
    "urlFilter": "*://outlook.live.com/*",
    "resourceTypes": ["main_frame", "sub_frame"]
  }
}
```

**Purpose**: Removes Outlook's CSP to allow tracking pixel injection
**Security Impact**: Weakens browser security protections on email providers
**Scope**: Affects `outlook.live.com`, `outlook.office.com`, `mail.live.com`, `outlook.office365.com`

---

## Background Script Analysis (`service_worker.js`)

### Network Infrastructure

**Backend Servers**:
```javascript
window.LOCATION_MAIN = "https://emailtracker.website/"
window.LOCATION_ACTION = window.LOCATION_MAIN + "a/"
window.LOCATION_TRACKERS = [
  window.LOCATION_ACTION,
  "https://my-email-signature.link/",
  "https://email-signature-image.com/"
]
```

### Cookie Management System

The extension sets tracking cookies across multiple domains:

```javascript
// Sets user tracking cookie on main domain
Background_cookie_set("user", a, (new Date).getTime() / 1e3 + 31536e3)

// Sets cookies on other tracking domains
LOCATION_TRACKERS.forEach(function(e, t) {
  0 != t && Background_cookie_set("user", a, ..., {url: e})
})

// Sets cookies on link shortener domains
Background_cookie_set("user", a, ..., {url: "http://bitt.site"})
Background_cookie_set("user", a, ..., {url: "http://bitli.pro"})
Background_cookie_set("user", a, ..., {url: "http://shortened-link.com"})
```

**Security Issue**: Cross-domain cookie setting for tracking infrastructure spanning multiple domains.

### Push Notification System

**GCM Registration** (Firebase Cloud Messaging):
```javascript
window.PUSH_GCM_ID = "171732813728"

chrome.instanceID.getToken({
  authorizedEntity: window.PUSH_GCM_ID,
  scope: "GCM"
}, function(t) {
  Xtion_fetch(window.LOCATION_ACTION + "notification_register", function(e) {
    Storage_update("notify", Xtion_object_merge(JSON.parse(e), {push: t}))
  }, {post: {id: t}})
})
```

**Purpose**: Real-time notifications when tracked emails are opened
**Data Flow**: Browser ← Firebase GCM ← emailtracker.website servers

### Dynamic NetRequest Rules

```javascript
function Generate_netrequest_rules() {
  Storage_get("email_ids", function(t) {
    (t ? JSON.parse(t) : []).forEach(function(t) {
      window.LOCATION_TRACKERS_V.forEach(function(e) {
        i.push({
          action: {type: "block"},
          condition: {
            urlFilter: e + "?u=" + t + "&",
            resourceTypes: ["main_frame", "image"]
          }
        })
      })
    })

    // Block own tracking pixels to prevent self-notification
    chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: o.map(e => e.id),
      addRules: i
    })
  })
}
```

**Purpose**: Blocks user's own tracking pixels from appearing in sent emails
**Legitimate use**: Prevents false positive notifications

### Analytics Integration

**Google Analytics 4** tracking:
```javascript
// lib/analytics.js
const MEASUREMENT_ID = 'G-PE1HNENJJT';
const API_SECRET = 'oV3mj2MESDK0jxtL7J6_4g';

async fireEvent(name, params = {}) {
  const response = await fetch(
    `${GA_ENDPOINT}?measurement_id=${MEASUREMENT_ID}&api_secret=${API_SECRET}`,
    {
      method: 'POST',
      body: JSON.stringify({
        client_id: await this.getOrCreateClientId(),
        events: [{name, params}]
      })
    }
  );
}
```

**Data Collected**: Install events, usage statistics
**Note**: Standard extension analytics (non-intrusive)

---

## Content Script Analysis (`content.js`)

### Email Provider Detection

The extension activates on multiple webmail platforms:
- Gmail (`mail.google.com`, `inbox.google.com`)
- Outlook (`mail.live.com`, `outlook.live.com`, `outlook.office.com`)
- Yahoo Mail (`mail.yahoo.com`)
- OWA (Outlook Web Access) at any domain (`*://*/owa/*`)

### Email Tracking Mechanism

**Tracking Pixel Injection**:
```javascript
function Tracker_insert(c, s, e, d, l, u) {
  Request_background(
    LOCATION_ACTION + "email?id_user=" + parseInt(c) +
    (t ? "&notify=" + parseInt(t.id) + "&notify_v=" + encodeURIComponent(t.v) : ""),
    function(t) {
      var n = JSON.parse(t);

      // Inject 1x1 tracking pixel
      s.insertAdjacentHTML("beforeend",
        '<img src="' + LOCATION_TRACKER_V + "?u=" + (u.uid_alias || c) +
        "&e=" + n.id + "&v=" + n.v +
        '" alt="" width="0" height="0" style="width:2px;max-height:0;overflow:hidden"/>'
      );
    }
  );
}
```

**Data Sent to Server**:
- User ID
- Email ID
- Notification token
- Tracking version

**Link Tracking/Rewriting**:
```javascript
// Collect all links from email body
e.forEach(function(e) {
  if (e.getAttribute("href") &&
      0 !== e.href.indexOf("mailto:") &&
      0 !== e.href.indexOf("tel:")) {
    i.push(e);
    a.push(e.href)
  }
});

// Send links to server for tracking URL generation
Request_background(LOCATION_ACTION + "email_links", function(t) {
  JSON.parse(t).forEach(function(e, t) {
    i[t].href = e  // Replace original URL with tracking redirect
  })
}, {post: Xtion_object_merge(n, {links: a})})
```

**Security Impact**: All links in outgoing emails are replaced with tracking redirects through `emailtracker.website` servers.

### Link Shortener Migration

```javascript
// Migrate old shortener domains to new ones
e.href = e.href.replace("http://bitt.site/", "https://bitli.pro/")
e.href = e.href.replace("http://bitli.pro/", "https://shortened-link.com/")
```

**Observation**: Extension has changed link tracking domains over time.

---

## Gmail-Specific Hooks (`lib/gmail.js`)

### XMLHttpRequest Interception

**INVASIVE TECHNIQUE**: Monkey-patches XMLHttpRequest to intercept Gmail API responses:

```javascript
var e = XMLHttpRequest.prototype,
    n = e.open,
    p = e.send;

e.open = function(e, t) {
  this._url = t;
  return n.apply(this, arguments)
}

e.send = function(e) {
  window.emailtracker_detector === d &&
    this.addEventListener("load", function() {
      if (~this._url.indexOf("search=")) {
        top.document.dispatchEvent(new CustomEvent("emailtracker_threads_old", {
          detail: {data: this.responseText}
        }));
      } else if (~this._url.indexOf("/bv?")) {
        top.document.dispatchEvent(new CustomEvent("emailtracker_threads", {
          detail: {data: this.responseText, type: "xhr_threads"}
        }));
      }
    });
  return p.apply(this, arguments)
}
```

**Purpose**: Intercepts Gmail's internal API responses to extract:
- Thread lists
- Message data
- Search results
- Email metadata

**Gmail API Endpoints Monitored**:
- `/bv?` - Gmail batch view API
- `search=` - Gmail search requests
- `/sync/u/0/i/s` - Gmail sync endpoint

### Internal API Hooking

```javascript
window._GM_setData = function(e) {
  t(e);
  if (window.emailtracker_detector === d && void 0 !== e) {
    // Extract Gmail internal data structures
    if (e.a6jdv && e.a6jdv[0] && e.a6jdv[0][2]) {
      top.document.dispatchEvent(new CustomEvent("emailtracker_threads", {
        detail: {data: e.a6jdv, type: "embedded_a6jdv"}
      }));
    }

    // Extract email aliases
    var aliases = (e, "sBEv4c", 8, 1);
    if (aliases && aliases.length) {
      top.document.dispatchEvent(new CustomEvent("emailtracker_info", {
        detail: {aliases: aliases}
      }));
    }
  }
}
```

**Security Concern**: Hooks into Gmail's internal JavaScript methods (`_GM_setData`) to extract undocumented data structures.

---

## Outlook-Specific Hooks (`lib/outlook2.js`)

### Fetch API Interception

**HIGHLY INVASIVE**: Completely replaces the global `fetch` function:

```javascript
var m = fetch;
window.fetch = function(e, a) {
  var url = e && e.url ? e.url : e;

  // Intercept email send operations
  if ((~url.indexOf("action=CreateItem") || ~url.indexOf("action=UpdateItem")) &&
      a && a.body) {
    var d = JSON.parse(a.body);
    if (d['Body']['MessageDisposition'] === 'SendAndSaveCopy') {
      var sid = 'emailtracker_send' + u();

      // Send to main thread for tracking pixel injection
      top.document.dispatchEvent(new CustomEvent("emailtracker_send", {
        detail: {sid: sid, post: d}
      }));

      // Wait for tracking pixel data from server
      return new Promise(function(resolve, reject) {
        // ... polling logic to modify email body before sending
      });
    }
  }

  // Capture authorization tokens
  var auth = a && a.headers ? a.headers.get("authorization") : null;
  if (auth && auth.includes && (auth.includes("usertoken") || auth.includes("Bearer"))) {
    window.emailtracker_authorization_token_ssjk939kjkkdjkjknhv0dd434E = auth;
    document.dispatchEvent(new CustomEvent("emailtracker_authorization", {
      detail: {body: auth}
    }));
  }

  return m.apply(this, arguments);
}
```

**Critical Findings**:
1. **Authorization Token Harvesting**: Captures Outlook OAuth Bearer tokens
2. **Email Body Modification**: Intercepts outgoing emails and injects tracking pixels server-side
3. **API Request Manipulation**: Modifies Outlook Web Services API calls

### Web Worker Injection

**EXTREME TECHNIQUE**: Monkey-patches the `Worker` constructor to inject tracking code into service workers:

```javascript
var l = window.Worker;
window.Worker = function(t, r) {
  var i = `
    (function(){
      var fetch_old = fetch;
      self.fetch = function(request, options) {
        var url = request && request['url'] ? request['url'] : request;

        // Intercept worker fetch calls
        if ((url.indexOf('action=CreateItem') !== -1 ||
             url.indexOf('action=UpdateItem') !== -1) &&
            options && options.body) {
          var d = JSON.parse(options.body);
          if (d['Body']['MessageDisposition'] === 'SendAndSaveCopy') {
            // Inject tracking via postMessage to main thread
            self.postMessage({type: 'emailtracker_send', sid: sid, post: d});

            // Wait for modified body from main thread
            return new Promise(function(resolve, reject) {
              var messageHandler = function(event) {
                if (event.data && event.data.type === 'emailtracker_send_response') {
                  if (event.data.modified_body) {
                    options.body = event.data.modified_body;
                  }
                  resolve(fetch_old.apply(self, args));
                }
              };
              self.addEventListener('message', messageHandler);
            });
          }
        }
        return fetch_old.apply(this, arguments);
      }
    })()
  `;

  var o = new Blob([i + "\n\n" + src], {type: "application/javascript"});
  return new l(URL.createObjectURL(o), r);
}
```

**Purpose**: Injects XHR/fetch hooks into Outlook's Web Workers to track emails even when sent via background threads.

### Service Worker Disabling

```javascript
if (window.trustedTypes && window.trustedTypes.createPolicy) {
  try {
    c = window.trustedTypes.createPolicy("owaLoopTrustedTypesPolicy", {
      createScriptURL: function(e) {return e}
    });
  } catch (e) {
    // Disable service workers if Trusted Types fails
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register = function() {
        return Promise.reject("Service workers disabled.");
      };
      navigator.serviceWorker.getRegistrations().then(e => {
        e.forEach(e => e.unregister());
      });
    }
  }
}
```

**Security Issue**: Disables Outlook service workers in some cases, potentially breaking functionality.

---

## Yahoo Mail Hooks (`lib/yahoo.js`)

**Minimal Implementation**: Yahoo uses simpler XHR interception:

```javascript
var e = XMLHttpRequest.prototype,
    s = e.open,
    t = e.send;

e.send = function(e) {
  this.addEventListener("load", function() {
    if (~this._url.indexOf("m=ListMessages") ||
        ~this._url.indexOf("m=ListFolderThreads")) {
      document.dispatchEvent(new CustomEvent("emailtracker_items", {
        detail: {body: this.responseText}
      }));
    }
  });
  return t.apply(this, arguments);
}
```

**Purpose**: Intercepts Yahoo Mail API responses for thread lists and messages.

---

## Data Collection & Privacy

### Email Metadata Collected

Based on API calls to `emailtracker.website/a/`:

1. **Email Identifiers**:
   - User email address
   - Recipient email addresses
   - Email subject lines
   - Message IDs
   - Thread IDs

2. **Tracking Events**:
   - Email send timestamps
   - Email open timestamps
   - Link click events (including which link)
   - View count per email
   - Device type (inferred from user agent)

3. **User Behavior**:
   - Email composition patterns
   - Sending frequency
   - Email alias usage
   - Inbox synchronization state

### Server-Side API Endpoints

```javascript
// User registration
LOCATION_ACTION + "user?e=" + encodeURIComponent(email)

// Email tracking pixel generation
LOCATION_ACTION + "email?id_user=" + user_id + "&notify=" + notify_id

// Link tracking URL generation
LOCATION_ACTION + "email_links" + {post: {links: [urls]}}

// Email metadata submission
LOCATION_ACTION + "email_sent" + {post: email_metadata}

// View count retrieval
LOCATION_ACTION + "email_views?id_source=" + email_id

// Notification sync
LOCATION_ACTION + "sync_email_ids" + {post: {emails: email_array}}
```

### Third-Party Data Sharing

**None detected** beyond the vendor's own infrastructure (`emailtracker.website`).

---

## Keylogger Analysis

**NO KEYLOGGER FOUND**

Keyboard event listeners are used **only** for:

```javascript
// Detect Ctrl+Enter to send email (Gmail/Outlook)
document.addEventListener("keydown", function(e) {
  if ((e.ctrlKey || e.metaKey) && e.keyCode === 13) {
    e.stopPropagation();
    // Trigger email send tracking
  }
});

// Detect Escape key to cancel compose
document.addEventListener("keydown", function(e) {
  if (e.keyCode === 27) { // ESC key
    cancel = 1;
  }
}, true);
```

**Verdict**: Keyboard listeners are **benign** — used only to detect send shortcuts, not to harvest keystrokes.

---

## Obfuscation & Dynamic Code

### Minimal Obfuscation

The extension is **lightly minified** but not heavily obfuscated:
- Variable names shortened (e.g., `function t(e, n)`)
- Comments removed
- No string encoding or polymorphic code

### Dynamic Code Evaluation

**Two instances found**:

1. **Gmail response parsing** (necessary for JSON parsing):
```javascript
t.push(new Function('"use strict"; return ' + e.trim())())
```
**Purpose**: Parse Gmail's non-standard JSON responses (newline-separated objects)
**Risk**: LOW (parsing Gmail API data, not arbitrary code execution)

2. **Inbox embedded data** (legacy Gmail interface):
```javascript
eval("window.embeddedAppData=" + Xtion_string_between(r, "preloadedData=", ";window.BT"));
```
**Purpose**: Extract preloaded data from Gmail HTML
**Risk**: MEDIUM (uses `eval` on page content, but scoped to Gmail's own data)

**No remote code execution detected** — all code is bundled with the extension.

---

## Extension Enumeration/Killing

**NO EXTENSION ENUMERATION FOUND**

The extension does **not**:
- Call `chrome.management.getAll()`
- Disable competing extensions
- Check for ad blockers or VPN extensions

---

## Remote Configuration

**NO REMOTE KILL SWITCH FOUND**

The extension does **not**:
- Fetch behavior configs from remote servers
- Support server-controlled feature flags
- Download executable code after installation

All functionality is hard-coded in the extension package.

---

## Comparison to Known Malicious Patterns

### Similar to VeePN/StayFree (Market Intelligence SDKs)
- ✅ XHR/fetch hooking (but limited to email providers, not all pages)
- ✅ Authorization token capture (Outlook only)
- ❌ NO extension inventory exfiltration
- ❌ NO residential proxy infrastructure
- ❌ NO AI conversation scraping

### Legitimate Use Case Validation
- ✅ Core functionality (email tracking) matches description
- ✅ User explicitly opts into tracking by installing extension
- ✅ No hidden data collection beyond stated purpose
- ✅ No third-party SDKs or analytics beyond GA4

**Verdict**: While invasive, the extension's behavior aligns with its stated purpose (email tracking).

---

## Security Vulnerabilities

### 1. CSP Bypass on Outlook Domains
**Severity**: HIGH
**Impact**: Weakens browser security protections on email providers
**Scope**: `outlook.live.com`, `outlook.office.com`, `mail.live.com`, `outlook.office365.com`

### 2. Authorization Token Harvesting
**Severity**: HIGH
**Finding**: Extension captures Outlook OAuth Bearer tokens
**Location**: `lib/outlook2.js:80-87`
**Risk**: Tokens stored in window scope could be exfiltrated by malicious scripts

```javascript
window.emailtracker_authorization_token_ssjk939kjkkdjkjknhv0dd434E = auth;
```

### 3. Global Fetch/XHR Monkey-Patching
**Severity**: MEDIUM
**Impact**: Breaks browser security model by intercepting all network requests on email pages
**Scope**: Gmail, Outlook, Yahoo Mail

### 4. Web Worker Code Injection
**Severity**: MEDIUM
**Finding**: Injects tracking code into service workers via Blob URLs
**Risk**: Could interfere with legitimate background processing

### 5. Excessive Host Permissions
**Severity**: LOW
**Finding**: `<all_urls>` permission when only email providers are needed
**Recommendation**: Restrict to specific webmail domains

---

## Privacy Concerns

### 1. Email Content Access
The extension has **full read/write access** to:
- Email subject lines
- Recipient lists (To, CC, BCC)
- Email body content (for pixel injection)
- All links in emails (for tracking rewriting)

### 2. Email Metadata Exfiltration
Data sent to `emailtracker.website` servers:
- User email address
- All recipient addresses
- Email subjects
- Send/open timestamps
- Link click data

### 3. Authorization Token Storage
Outlook OAuth tokens stored in page-accessible variables could be:
- Leaked via XSS vulnerabilities
- Intercepted by malicious content scripts
- Used for unauthorized account access

### 4. Cross-Domain Cookie Tracking
The extension sets cookies across multiple domains:
- `emailtracker.website`
- `my-email-signature.link`
- `email-signature-image.com`
- `bitt.site`, `bitli.pro`, `shortened-link.com`

---

## Detector Functionality (Pixelblock)

The extension's **secondary feature** is blocking tracking pixels from other services:

```javascript
var emailtracker_detector_blacklist = [
  {name: "HubSpot Sidekick", search: ["t.signaux", "t.senal", "t.sidekickopen"]},
  {name: "Banana Tag", search: "bl-1.com"},
  {name: "Boomerang", search: "mailstat.us/tr"},
  {name: "Yesware", search: ["app.yesware.com", "t.yesware.com"]},
  {name: "Mailtrack", search: ["https://mltrk.io/pixel/", "mailtrack.io"]},
  {name: "Mixmax", search: ["track.mixmax.com/api", "email.mixmax.com/e/o"]},
  // ... 40+ tracking services
]
```

**Irony**: Extension that injects tracking pixels also blocks competitors' tracking pixels.

---

## Recommendations

### For Users
1. **Privacy Trade-off**: Understand that using this extension means sending email metadata to a third-party service
2. **Enterprise Risk**: Do not use on corporate email accounts (violates data governance policies)
3. **Sensitive Communications**: Avoid using on emails containing confidential information
4. **Token Exposure**: Outlook users should be aware of OAuth token storage in page memory

### For Developers (emailtracker.website)
1. **Reduce Permissions**: Change from `<all_urls>` to specific email provider domains
2. **Token Security**: Store Outlook OAuth tokens in `chrome.storage.local`, not `window` variables
3. **CSP Bypass**: Explore alternatives to CSP header stripping (declarativeNetRequest allows pixel blocking without full CSP removal)
4. **Transparency**: Add privacy policy link to extension listing explaining data collection
5. **Code Minimization**: Remove unused link shortener domains (`bitt.site`, etc.)

### For Chrome Web Store Review Team
1. **Permission Audit**: Verify `<all_urls>` is justified (could be scoped to webmail domains)
2. **CSP Modification**: Review whether CSP stripping complies with CWS policies
3. **Worker Injection**: Assess whether Blob-based Worker monkey-patching violates security guidelines

---

## Comparison to Project Patterns

### Not Detected
- ❌ Extension enumeration/killing
- ❌ Residential proxy infrastructure
- ❌ Market intelligence SDKs (Sensor Tower, etc.)
- ❌ AI conversation scraping
- ❌ Ad/coupon injection
- ❌ Remote kill switches
- ❌ Dynamic code loading from servers
- ❌ Keyloggers

### Detected (Legitimate for Use Case)
- ✅ XHR/fetch hooking (limited to email providers)
- ✅ Cookie manipulation (for tracking infrastructure)
- ✅ CSP bypass (for pixel injection)
- ✅ OAuth token capture (Outlook only)

---

## Conclusion

**Email Tracker + Pixelblock Detector & Blocker** is a **legitimate but highly invasive** extension that provides email read receipt functionality. While not malware, it employs aggressive techniques typically associated with malicious extensions:

- **XHR/fetch monkey-patching** on webmail providers
- **CSP header stripping** to inject tracking pixels
- **Web Worker code injection** via Blob URLs
- **OAuth token harvesting** (Outlook)
- **Email metadata exfiltration** to third-party servers

**Key Distinction**: Unlike truly malicious extensions (e.g., VeePN, StayFree), this extension's invasive behavior is **directly related to its stated purpose** (email tracking). Users who install it are explicitly opting into this functionality.

**Risk Level: MEDIUM**
- High technical invasiveness, but transparent purpose
- Privacy concerns for email content/metadata
- Security risks from CSP bypass and token storage
- No evidence of hidden malicious behavior beyond stated tracking

**Recommendation**: Users should carefully consider the privacy implications before installing. Enterprise/corporate users should avoid this extension due to data governance concerns.

---

## File Paths

- **Manifest**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/bnompdfnhdbgdaoanapncknhmckenfog/deobfuscated/manifest.json`
- **Background Script**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/bnompdfnhdbgdaoanapncknhmckenfog/deobfuscated/service_worker.js`
- **Content Script**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/bnompdfnhdbgdaoanapncknhmckenfog/deobfuscated/content.js`
- **Gmail Hooks**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/bnompdfnhdbgdaoanapncknhmckenfog/deobfuscated/lib/gmail.js`
- **Outlook Hooks**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/bnompdfnhdbgdaoanapncknhmckenfog/deobfuscated/lib/outlook2.js`
- **Yahoo Hooks**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/bnompdfnhdbgdaoanapncknhmckenfog/deobfuscated/lib/yahoo.js`
- **NetRequest Rules**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/bnompdfnhdbgdaoanapncknhmckenfog/deobfuscated/declarative_net_request_rules.json`
