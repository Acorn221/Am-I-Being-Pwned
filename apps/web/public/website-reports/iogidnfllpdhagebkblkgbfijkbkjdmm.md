# Security Analysis: Stream Recorder - HLS & m3u8 Video Downloader (iogidnfllpdhagebkblkgbfijkbkjdmm)

## Extension Metadata
- **Name**: Stream Recorder - HLS & m3u8 Video Downloader
- **Extension ID**: iogidnfllpdhagebkblkgbfijkbkjdmm
- **Version**: 2.2.9
- **Manifest Version**: 3
- **Estimated Users**: ~1,000,000
- **Developer**: loadmonkey.inquiry@gmail.com
- **Homepage**: https://www.hlsloader.com/
- **Analysis Date**: 2026-02-14

## Executive Summary
Stream Recorder is a video downloader extension with **MEDIUM** risk status. While the extension provides legitimate HLS/m3u8 video download functionality, static analysis reveals suspicious data exfiltration patterns where browser fingerprinting data (navigator.userAgent) and page content reach network sinks pointing to the developer's domain (hlsloader.com). The extension uses extremely broad permissions (<all_urls>, webRequest) and heavily minified code that makes verification difficult. Given the 1M user base, the opaque data handling practices and potential fingerprinting warrant a MEDIUM risk classification pending further investigation.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. Potential Browser Fingerprinting & Data Exfiltration
**Severity**: MEDIUM-HIGH
**Category**: Privacy / Data Collection

**Analysis**:
The ext-analyzer detected 3 data exfiltration flows where sensitive browser data reaches fetch() network sinks:

1. **navigator.userAgent → fetch(www.hlsloader.com)** in bg.js
2. **navigator.userAgent → fetch(www.hlsloader.com)** in loader.js
3. **document.getElementById() → fetch(www.hlsloader.com)** in loader.js

**Code Evidence** (bg.js, line 60):
```javascript
c = navigator.userAgent,
d = c.includes("Firefox"),
l = (!c.includes("Edg") && c.includes("Chrome"), c.includes("Mobi"),
     c.includes("Chrome") && Number((c.match(/Chrome\/(\d+)/) || [])[1] || 0)
```

**Code Evidence** (content.js, line 6):
```javascript
t = navigator.userAgent
// Later referenced in message passing to service worker
```

**What is Being Collected**:
- Browser user agent string (contains: browser type, version, OS, device info)
- UUID (unique identifier stored in local storage)
- Usage counter (tracks extension usage)
- Session ID (generated per browser session)
- Page content accessed via document.getElementById()

**Where It's Sent**:
- Primary domain: `https://www.hlsloader.com/`
- Secondary domain: `https://www.altextension.com/stream/`

**Justification Concerns**:
- User agent collection may be for basic browser compatibility detection
- However, combined with UUID, counter, and session tracking, this creates a persistent fingerprint
- No privacy policy disclosed in manifest
- Heavily minified code prevents verification of exact data usage
- No clear user consent mechanism

**Impact**:
- User browsing patterns could be tracked across sessions via UUID
- Browser fingerprinting enables cross-site tracking even without cookies
- With <all_urls> permission, extension can observe all browsing activity
- 1M users means significant privacy exposure at scale

### 2. Excessive Permissions
**Severity**: MEDIUM
**Category**: Permission Overreach

**Permissions Granted**:
```json
{
  "permissions": [
    "webRequest",           // Read all HTTP requests
    "declarativeNetRequest", // Modify network requests
    "webNavigation",        // Track all page navigations
    "tabs",                 // Access to all tab information
    "scripting",            // Inject scripts into any page
    "offscreen",            // Background processing
    "storage"               // Local data storage
  ],
  "host_permissions": ["<all_urls>"]  // CRITICAL: Access to ALL websites
}
```

**Risk Analysis**:

| Permission | Declared Use | Actual Necessity | Risk |
|------------|--------------|------------------|------|
| `<all_urls>` | Detect HLS streams on any site | Could be scoped to specific video sites | HIGH |
| `webRequest` | Intercept video stream requests | Legitimate for stream detection | MEDIUM |
| `declarativeNetRequest` | Modify headers for CORS bypass | Enables request manipulation | MEDIUM |
| `tabs` | Manage download tabs | Overly broad | MEDIUM |
| `scripting` | Inject stream capture code | Required for functionality | LOW |

**Verdict**: Permissions are largely justified for video downloading but create significant attack surface.

### 3. Content Script Injection on All Pages
**Severity**: MEDIUM
**Files**: js/content.js

**Analysis**:
The extension injects content scripts on `<all_urls>` (except hlsloader.com/record.html), running at `document_start`. This gives the extension earliest possible access to every page the user visits.

**Code Evidence** (manifest.json):
```json
{
  "matches": ["<all_urls>"],
  "exclude_matches": ["https://www.hlsloader.com/*record.html*"],
  "js": ["js/content.js"],
  "run_at": "document_start"
}
```

**Content Script Behavior**:
- Sends "c2b_notify_ready" message with `document.title` and `darkmode` preference
- Registers "b2c_check_alive" and "b2c_check_navigation" message listeners
- Detects SPA navigation using Navigation API
- Has access to page DOM, cookies, localStorage on all sites

**Risk**:
While content script appears limited to navigation detection and title extraction, the broad injection creates opportunity for abuse. Combined with userAgent tracking, this enables comprehensive browsing surveillance.

### 4. MediaSource API Hooking
**Severity**: MEDIUM
**Category**: API Monkey-Patching
**Files**: bg.js (injected into MAIN world)

**Analysis**:
The extension monkey-patches the native MediaSource API to intercept video data:

**Code Evidence** (bg.js, function A):
```javascript
MediaSource = class extends n {
  constructor() {
    super(arguments);
    this._mediaSourceId = Math.floor(1e10 * Math.random())
  }
  addSourceBuffer(e) {
    const t = super.addSourceBuffer.apply(this, arguments),
      n = t.appendBuffer;
    t._bufferId = Math.floor(1e10 * Math.random());
    const i = this;
    return t.appendBuffer = function(t) {
      if (t.length || t.byteLength) {
        const n = new Blob([t]),
          r = URL.createObjectURL(n),
          c = {
            url: r,
            mimeType: e,
            mediaSourceId: i._mediaSourceId,
            bufferId: this._bufferId,
            timestamp: Date.now()
          };
        window.postMessage({cmd: o, params: a(c)}, s);
        setTimeout((() => { URL.revokeObjectURL(r) }), 6e4)
      }
      n.apply(this, arguments)
    }
  }
}
```

**Mechanism**:
1. Replaces native MediaSource constructor
2. Intercepts appendBuffer() calls
3. Creates blob URLs from video data
4. Posts data to content script via window.postMessage
5. Content script forwards to background via chrome.runtime.sendMessage

**Purpose**: Capture video stream data for HLS/DASH video downloading

**Risk**:
- Legitimate for video downloading functionality
- Modifies fundamental browser APIs, which is a common malware pattern
- Could be used to exfiltrate video content without user knowledge
- YouTube explicitly excluded (DISABLE_ON_YOUTUBE_REGEXP) suggesting awareness of ToS concerns

### 5. Offscreen Document Fetch Proxy
**Severity**: LOW-MEDIUM
**Category**: CORS Bypass
**Files**: js/offscreen.js

**Analysis**:
The extension uses an offscreen document to proxy fetch requests, bypassing CORS restrictions:

**Code Evidence** (offscreen.js):
```javascript
fetch(e, {
  method: o || "GET",
  mode: "cors",
  credentials: "include",
  headers: s
}).then((e =>
  e.ok ? e.blob() : t({ok: !1, message: e.status})
)).then((e => {
  const o = URL.createObjectURL(e);
  return setTimeout((() => { URL.revokeObjectURL(o) }), 1e4),
  t({ok: !0, blobUrl: o})
}))
```

**Purpose**: Fetch video segments that would otherwise be blocked by CORS

**Risk**:
- Enables fetching resources from any domain with credentials
- Could be abused to make authenticated requests to arbitrary sites
- However, appears limited to background-initiated requests (not content script)

### 6. UUID and Usage Tracking
**Severity**: LOW-MEDIUM
**Category**: Analytics / Telemetry

**Analysis**:
The extension generates and stores unique identifiers:

**Code Evidence** (bg.js):
```javascript
let H = -1, J = -1;
R.storage.local.get(["log", "uuid", "counter", "theme"]).then((e => {
  H = e.counter || 0,
  J = e.uuid,
  J || (J = _(), R.storage.local.set({uuid: J}))
}))
```

**Tracked Metrics**:
- UUID: Persistent unique identifier
- Counter: Usage count (incremented on certain actions)
- Session ID: Per-session identifier
- Theme preference (light/dark mode)

**Where Stored**: chrome.storage.local (persistent across sessions)

**Concerns**:
- UUID enables cross-session tracking
- Combined with userAgent, creates unique fingerprint
- No disclosure of what data is sent to hlsloader.com
- No opt-out mechanism visible

### 7. Remote Configuration
**Severity**: LOW-MEDIUM
**Category**: Remote Control

**Analysis**:
The extension fetches and applies remote configuration:

**Code Evidence** (bg.js):
```javascript
let N = {};
R.storage.local.get(["remoteConfig"]).then((e => {
  Object.assign(N, e.remoteConfig ?? {})
}))

// Later in message handler:
"send_remote_config" === a ? (
  (e => {
    const t = e?.remoteConfig;
    if (t) {
      const e = JSON.stringify(N),
        s = JSON.stringify(t);
      "{"===s?.at(0) && e !== s && (N = t,
        R.storage.local.set({remoteConfig: N}))
    }
  })(n), s(!0)
)
```

**Mechanism**:
- Receives "remoteConfig" via runtime message
- Validates JSON format
- Stores in local storage
- Applied to behavior globally via `N` object

**Risk**:
- Allows developer to change extension behavior remotely
- No signature verification visible
- Could be used as kill switch or to modify data collection
- Requires cooperation from loader.js page (only runs on hlsloader.com)

**Mitigation**: Remote config appears limited to messages from loader.js on hlsloader.com domain, not arbitrary external fetch.

---

## Attack Surface Analysis

### Open Message Handlers
The extension exposes multiple chrome.runtime.onMessage handlers:

**Background Script Handlers**:
- `c2b_notify_ready` - Accepts title and darkmode from content scripts
- `l2b_notify_ready` - Accepts counter from loader page
- `l2b_start_normal` - Starts video capture
- `l2b_set_dnr_session_rule` - Modifies declarativeNetRequest rules
- `l2b_fetch_request` - Proxies fetch via offscreen document
- `l2b_intercept_request` - Initiates request interception
- `c2b_intercept_ondata` - Receives intercepted data
- `send_remote_config` - Updates remote configuration

**Risk**: Message handlers accept data from any extension page but validate sender context. Most handlers require specific tab relationships (root/child) established through controlled page loads.

### Web Accessible Resources
**None declared** - Extension does not expose any resources to web pages.

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `www.hlsloader.com/*record.html*` | Video processing UI | Title, darkmode, counter, UUID, userAgent (suspected) | Per-session |
| `www.altextension.com/stream/` | Secondary domain | Unknown (same codebase reference) | Unknown |

### Data Flow Summary

**Data Collection**:
- ✓ navigator.userAgent (browser fingerprint)
- ✓ UUID (unique identifier)
- ✓ Counter (usage metrics)
- ✓ Session ID (per-session tracking)
- ✓ document.title (page titles)
- ✓ Dark mode preference
- ? Page content via document.getElementById (scope unclear)

**Data Transmission**:
- Suspected transmission to hlsloader.com based on static analysis flows
- Exact payloads cannot be verified due to heavy minification
- No external analytics SDKs detected (Google Analytics, etc.)

**Tracking/Analytics**: SUSPECTED
- UUID + userAgent = persistent fingerprint
- Counter tracks usage over time
- Session ID tracks per-session activity

---

## Code Quality & Obfuscation

### Obfuscation Level: HIGH

**Characteristics**:
- All JavaScript heavily minified (single-line functions)
- Variable names reduced to single characters
- No source maps provided
- Comments removed (except copyright header)
- Control flow flattening visible

**Code Metrics**:
- bg.js: 59 lines (heavily minified)
- loader.js: ~194KB (includes hls.js library + extension code)
- content.js: 5 lines (minified)
- offscreen.js: 5 lines (minified)

**Developer Note** (from bg.js header):
```
 *  For the sake of transparency and reliability we did not want to minify the source code.
 *  Disappointingly, an extension appeared that completely copied the code, contrary to our
 *  intentions, and we decided that we should minify it.
 *  Please contact us at loadmonkey.inquiry@gmail.com and we can provide you with more
 *  readable source code, if you need it.
```

**Assessment**: Developer acknowledges minification was added after v2.0.2 to prevent code copying. While understandable, this prevents security auditing and creates opacity around data handling practices.

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Browser fingerprinting | ✓ YES | navigator.userAgent + UUID + counter |
| Data exfiltration | ✓ SUSPECTED | Static analysis shows flows to fetch(hlsloader.com) |
| Extension enumeration/killing | ✗ No | No chrome.management API usage |
| XHR/fetch hooking | ✗ No | No XMLHttpRequest prototype modification |
| Residential proxy infrastructure | ✗ No | No proxy.settings API usage |
| Cookie harvesting | ✗ No | No cookie API access |
| Keylogging | ✗ No | No keyboard event listeners |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Cryptocurrency mining | ✗ No | No mining scripts detected |
| Remote code execution | ✗ No | No eval()/Function() with external data |
| MediaSource hooking | ✓ YES | Legitimate for video capture functionality |

---

## Legitimate Functionality Assessment

### Declared Purpose
Stream Recorder downloads HLS/m3u8/DASH video streams from websites.

### How It Works
1. **Detection**: webRequest API intercepts HTTP responses, filters by Content-Type for video/audio formats
2. **Parsing**: Detects m3u8 playlist files and media segments (TS fragments)
3. **Capture**: MediaSource hooking intercepts video data as it's played
4. **Processing**: Opens hlsloader.com/record.html page for download UI
5. **Download**: Assembles fragments and triggers browser download

### Legitimate Uses
- Download streaming videos for offline viewing
- Archive educational content
- Save videos from sites without download options
- Backup livestreams

### Functionality Verification
✓ Detects HLS/DASH streams via webRequest filtering
✓ Parses m3u8 playlist formats
✓ MediaSource hooking enables MSE capture
✓ Offscreen fetch bypasses CORS for segments
✓ Disabled on YouTube (respects platform ToS)
? Data collection purpose not clearly justified
? Fingerprinting not disclosed to users

---

## Privacy Concerns

### Level: MEDIUM-HIGH

**Concerns**:
1. **Fingerprinting**: userAgent + UUID + counter creates persistent tracking identifier
2. **Scope**: <all_urls> means extension observes ALL browsing activity
3. **Opacity**: Heavy minification prevents verification of data handling
4. **No Disclosure**: No privacy policy in manifest or store listing
5. **No Consent**: No opt-in/opt-out for analytics
6. **Cross-Session Tracking**: UUID persists across browser restarts

**Mitigating Factors**:
- Homepage domain (hlsloader.com) matches extension functionality
- No third-party analytics SDKs detected
- No evidence of data selling (but cannot be ruled out)
- Developer provides contact for source code access

**User Privacy Impact**: MEDIUM
- Browsing patterns potentially tracked across all sites
- Browser fingerprint can enable cross-site correlation
- No transparency around data retention or sharing practices

---

## Security Recommendations

### For Users
1. **CAUTION**: Only install if video downloading functionality is essential
2. Review what browsing data may be collected (userAgent, titles, usage)
3. Consider alternatives with more transparent data practices
4. Monitor network traffic to hlsloader.com for unexpected data
5. Limit usage to specific browsing sessions (not daily driver)

### For Developer
1. **Publish privacy policy** disclosing all data collection
2. **Provide source code** or reduce minification for transparency
3. **Scope permissions** to video streaming domains where possible
4. **Add analytics opt-out** for users who want functionality only
5. **Document remote config** behavior and security measures
6. **Implement cert pinning** for remote config to prevent MITM

### For Reviewers
1. **Request source code** from developer per their offer
2. **Network monitoring** to verify actual data transmission
3. **Decompilation** of minified code for full audit
4. **User consent audit** - verify GDPR/CCPA compliance
5. **Check store listing** for privacy policy disclosure

---

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Scoring Breakdown**:
- **Permissions**: HIGH (8/10) - <all_urls>, webRequest, tabs
- **Data Collection**: MEDIUM-HIGH (7/10) - Fingerprinting detected
- **Transparency**: LOW (3/10) - Heavy minification, no privacy policy
- **Malicious Intent**: LOW-MEDIUM (4/10) - No clear malware, but suspicious patterns
- **User Impact**: MEDIUM (6/10) - 1M users, privacy exposure
- **Code Quality**: MEDIUM (5/10) - Minified but functional

**Final Calculation**: (8+7+3+4+6+5)/6 = **5.5/10** = MEDIUM Risk

### Justification

**Why Not HIGH/CRITICAL**:
- Core functionality (video downloading) appears legitimate
- MediaSource hooking is appropriate for use case
- No evidence of credential theft, malware, or cryptomining
- Developer has established domain and contact info
- No third-party data sharing detected

**Why Not LOW/CLEAN**:
- **Browser fingerprinting** with userAgent + UUID tracking
- **Suspected data exfiltration** to hlsloader.com (needs verification)
- **Heavy obfuscation** prevents security audit
- **No privacy policy** or user disclosure
- **Excessive scope** with <all_urls> permission
- **1M users** amplifies privacy impact

### Conditional Upgrade to HIGH Risk If:
- Network analysis confirms userAgent transmission to hlsloader.com
- UUID/counter data confirmed sent without user consent
- Page content beyond titles collected via document.getElementById
- Remote config found modifying behavior maliciously
- Privacy policy remains undisclosed

---

## Recommendations

### User Verdict: **USE WITH CAUTION**

**Safe to use if**:
- You need HLS video downloading functionality
- You accept potential fingerprinting/analytics
- You limit extension to specific sessions (not daily driver)
- You trust the developer's domain (hlsloader.com)

**Avoid if**:
- Privacy is a primary concern
- You browse sensitive content (banking, health, etc.)
- You want transparent data practices
- Alternative video downloaders are acceptable

### For Chrome Web Store Team
**Recommended Actions**:
1. **Request privacy policy** - Developer must disclose data collection
2. **Verify data flows** - Confirm what's sent to hlsloader.com
3. **Audit remote config** - Ensure no malicious behavior changes
4. **Check GDPR compliance** - EU users need consent mechanism
5. **Monitor user complaints** - Watch for privacy violation reports

**Enforcement Level**: REVIEW REQUIRED
- Not immediate removal (no clear malware)
- Requires privacy policy and disclosure
- May need permission reduction (scope <all_urls> to video sites)
- Pending developer clarification on data practices

---

## Technical Summary

**Lines of Code**: ~200KB (mostly minified)
**External Dependencies**: hls.js (video streaming library)
**Third-Party Libraries**: None beyond hls.js
**Remote Code Loading**: None detected
**Dynamic Code Execution**: None detected (no eval/Function with user input)

---

## Conclusion

Stream Recorder - HLS & m3u8 Video Downloader provides legitimate video downloading functionality but exhibits concerning privacy practices. The combination of browser fingerprinting (userAgent + UUID), broad permissions (<all_urls>), and heavy code obfuscation creates opacity around data handling. Static analysis detected data flows from fingerprinting sources to network sinks pointing to the developer's domain (hlsloader.com), but exact payloads cannot be verified without network monitoring.

**The extension is not outright malicious** - it performs its advertised function and shows no evidence of credential theft, malware, or cryptomining. However, **the lack of privacy disclosure and suspected analytics tracking** at scale (1M users) warrant a **MEDIUM risk classification** pending developer clarification and policy disclosure.

Users seeking video downloading functionality can use this extension with caution, understanding potential privacy tradeoffs. However, privacy-conscious users should seek alternatives with more transparent practices.

**Final Verdict: MEDIUM** - Functional but privacy-concerning, requires disclosure.
