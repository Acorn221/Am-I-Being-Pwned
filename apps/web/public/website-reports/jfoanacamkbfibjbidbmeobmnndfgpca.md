# Security Analysis Report: DontPayFull - Automatic Coupon Finder

**Extension ID:** jfoanacamkbfibjbidbmeobmnndfgpca
**Version:** 2.1.27
**User Count:** ~40,000
**Risk Level:** MEDIUM
**Analysis Date:** 2026-02-15

---

## Executive Summary

DontPayFull is an automatic coupon finder extension that applies discount codes during checkout. The extension exhibits MEDIUM risk due to a postMessage vulnerability without origin validation, excessive use of sensitive permissions (management API, cookies across all URLs), and extensive user tracking. While the core functionality appears legitimate, the combination of security weaknesses and broad permissions creates potential attack vectors for malicious actors.

**Risk Score: 85/100** (from static analysis)

**Key Findings:**
- **HIGH:** postMessage listener without origin validation (line 4960 in content script)
- **MEDIUM:** Management permission enables enumeration of installed extensions
- **MEDIUM:** Cookie access across all URLs with auth token collection
- **LOW:** Extensive behavioral tracking sent to events.dpf.cloud

---

## Vulnerability Details

### 1. postMessage Without Origin Validation [HIGH]

**Location:** `dist/contentScripts/index.global.js:4960`

**Description:**
The extension registers a window message listener without validating the origin of incoming messages:

```javascript
window.addEventListener("message", r), s()
```

**Code Context:**
```javascript
const r = A => {
  const {
    data: {
      cmd: c,
      scope: l,
      context: g
    },
    ports: I
  } = A;
  if (c === "webext-port-offer" && l === t && g !== e)
    return window.removeEventListener("message", r),
           I[0].onmessage = n,
           I[0].postMessage("port-accepted"),
           o(I[0])
},
```

**Impact:**
While the handler checks for a specific command (`webext-port-offer`) and uses MessageChannel ports for communication, the lack of origin validation means any webpage can attempt to send messages to this listener. An attacker could potentially:
- Probe for the extension's presence
- Attempt to establish MessageChannel communication by spoofing the expected message format
- Exploit any weaknesses in the port-based message routing

**Exploitation Scenario:**
1. Malicious webpage sends crafted `webext-port-offer` message
2. Extension accepts the MessageChannel port without verifying sender origin
3. Attacker gains a communication channel to the extension's content script

**Mitigation:**
Add origin validation:
```javascript
window.addEventListener("message", (event) => {
  if (event.origin !== "expected-origin") return;
  r(event);
});
```

---

### 2. Management Permission - Extension Enumeration [MEDIUM]

**Permission:** `management`

**Description:**
The extension requests the `management` permission, which allows it to enumerate all installed extensions, enable/disable extensions, and access metadata about the user's extension ecosystem.

**Evidence:**
Manifest line 30:
```json
"permissions": [
  "tabs",
  "storage",
  "scripting",
  "webNavigation",
  "webRequest",
  "management",  // ← Sensitive permission
  "cookies",
  "alarms"
]
```

**Impact:**
- Privacy leak: Extension can fingerprint user by their installed extensions
- Creates attack surface for targeting specific extension combinations
- Could be used to detect security/privacy tools (VPNs, ad blockers, etc.)

**Justification Assessment:**
For a coupon finder extension, the `management` permission is NOT necessary for core functionality (finding and applying coupons). This appears to be excessive privilege.

---

### 3. Cookie Access Across All URLs [MEDIUM]

**Permissions:** `cookies` + `<all_urls>`

**Description:**
The extension accesses cookies across all websites, including reading authentication tokens and setting tracking cookies.

**Evidence:**

**Auth Cookie Access (line 9080):**
```javascript
async function f() {
  try {
    return await C.cookies.get(Z.AUTH_COOKIE)
  } catch (g) {
    return ze.error("getAuthCookie", g), ...
  }
}
```

**Cookie Definitions (lines 7371-7378):**
```javascript
AUTH_COOKIE: {
  url: "https://www.dontpayfull.com/",
  name: "AUTH_BEARER_DPF"
},
DPF_EXT_COOKIE: {
  url: "https://www.dontpayfull.com/",
  name: "dpf_ext"
}
```

**Cookie Setting (line 9948):**
```javascript
await C.cookies.set({
  ...Z.DPF_EXT_COOKIE,
  value: "1",
  expirationDate: Math.floor(Date.now() / 1e3) + 720 * 60  // 12 hours
})
```

**Impact:**
- Reads authentication bearer tokens from dontpayfull.com
- Sets tracking cookies with 12-hour expiration
- Could potentially access cookies from any visited site due to `<all_urls>` permission

**Data Flow:**
```
User visits site → Extension reads cookies →
Extracts user ID from auth token →
Includes in tracking payloads sent to events.dpf.cloud
```

**Privacy Concern:**
User tracking is tied to authenticated account via bearer token extraction.

---

### 4. Behavioral Tracking and Data Collection [LOW]

**Endpoint:** `https://events.dpf.cloud/automatic-coupons/cycles`

**Description:**
The extension tracks detailed user behavior during coupon application sessions and sends telemetry to events.dpf.cloud.

**Evidence (lines 2836-2843):**
```javascript
sendLog() {
  if (Di() || !this.codeApplyInfo.startedAt && !this.codeApplyInfo.endedAt)
    return Promise.resolve();
  const e = this.getLog();
  return fetch("https://events.dpf.cloud/automatic-coupons/cycles", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(e)
  })
}
```

**Data Collected (lines 2817-2831):**
```javascript
getLog() {
  return {
    tab_id: this.tabID,
    tv: this.codeApplyInfo.trainingVersion || "",
    session: this.codeApplyInfo.session || "",
    index: this.index > -1 ? this.index : -1,
    index_max: this.maxIndex ?? -1,
    sid: this.sid ?? -1,
    code: this.codeApplyInfo.codeInfo?.hash ?? this.code || "",
    code_type: this.codeApplyInfo.codeInfo?.type,
    is_code_hash: !!this.codeApplyInfo.codeInfo?.hash,
    steps: this.codeApplyInfo.steps || {},
    started_at: this.codeApplyInfo.startedAt || ...,
    ended_at: this.codeApplyInfo.endedAt || ...,
    last_error: this.error || "",
    session_stopped_by: this.stoppedBy || "",
    version: this.version || it.EXT_VERSION,
    session_group: ee.hashStr(r),  // MD5 hash
    release_type: this.releaseType || it.RELEASE_TYPE,
    // User ID added from auth cookie (line 9098)
    extra: { uid: p }
  }
}
```

**Tracking Endpoints (lines 7414-7415):**
```javascript
COUPON_VOTES: "https://events.dpf.cloud/extension/coupon_votes/",
EVENTS_LOG: "https://events.dpf.cloud/automatic-coupons/events/",
```

**Tracked Events:**
The extension logs 50+ different event types (line 7455+):
- page_view
- start_autoapply
- copy_code
- vote_code
- click_ext_icon
- best_code
- continue_checkout
- trace_hop_domains
- And many more...

**Impact:**
- Comprehensive user behavior profiling tied to authenticated user ID
- Detailed shopping session tracking (which stores, which coupons tried, timing)
- Could be used to build detailed purchasing profiles

**Privacy Assessment:**
While tracking for analytics is common in coupon extensions, the combination of:
1. Authenticated user tracking (via cookie-extracted UID)
2. Cross-site visibility (via `<all_urls>`)
3. Detailed behavioral telemetry

Creates a privacy concern.

---

## Network Endpoints

### Primary API
- **api.dontpayfull.com** - Main API for coupon data
  - `/api/v4/extensions/automatic-coupons/*`
  - Endpoints for active codes, expired codes, deals, trainings, etc.

### Tracking & Analytics
- **events.dpf.cloud** - Behavioral tracking
  - `/automatic-coupons/cycles` - Session logs
  - `/automatic-coupons/events/` - Event tracking
  - `/extension/coupon_votes/` - Coupon voting

- **www.google-analytics.com** - Google Analytics

### Error Monitoring
- **sentry.dpf.cloud** - Error reporting (Sentry)

### Legitimate External
- **www.w3.org** - Schema validation (benign, ext-analyzer detected as exfiltration but is false positive)

### Authentication
- **www.dontpayfull.com** - Auth cookies and user management

---

## Permissions Analysis

### Critical Permissions
| Permission | Justification | Risk Assessment |
|-----------|---------------|-----------------|
| `<all_urls>` | Apply coupons on any shopping site | **HIGH** - Necessary but broad |
| `management` | Extension enumeration | **HIGH** - NOT justified for coupon finder |
| `cookies` | Read auth tokens, set tracking cookies | **MEDIUM** - Partially justified |
| `webRequest` | Intercept network requests | **MEDIUM** - Use case unclear |

### Standard Permissions
| Permission | Justification | Risk Assessment |
|-----------|---------------|-----------------|
| `tabs` | Manage coupon UI, track tab state | **LOW** - Justified |
| `storage` | Store user preferences, cache | **LOW** - Justified |
| `scripting` | Inject coupon UI into pages | **LOW** - Justified |
| `webNavigation` | Detect checkout pages | **LOW** - Justified |
| `alarms` | Periodic cleanup tasks | **LOW** - Justified |

### Excessive Permissions
1. **`management`** - Can enumerate all installed extensions. No clear justification for coupon functionality.
2. **`webRequest`** - Typically used for request interception. Not clearly necessary for applying coupons.

---

## Code Quality & Security Practices

### Positive Findings
- Uses Content Security Policy (CSP) in manifest
- Implements timeout handling for fetch requests
- Error handling with Sentry integration
- Uses hashing (MD5) for session identifiers
- Validates code input lengths (max 40 characters for user codes)

### Security Concerns
- **Obfuscated code** - Large minified bundles (341KB background, 900KB+ content script)
- **No origin validation** on postMessage listener
- **Excessive permissions** not justified by functionality
- **WebAssembly present** (per ext-analyzer) - use case not clear
- **Broad host permissions** - `<all_urls>` grants access to all websites

---

## Static Analysis Findings (ext-analyzer)

**Risk Score:** 85/100

**Exfiltration Flows:** 3 detected
1. `document.querySelectorAll → fetch(www.w3.org)` - False positive (schema validation)
2. `document.getElementById → fetch(www.w3.org)` - False positive (schema validation)
3. `document.getElementById → fetch(events.dpf.cloud)` - **TRUE POSITIVE** - Behavioral tracking

**Attack Surface:**
- **HIGH:** postMessage listener without origin check (content script line 4960)

**Code Execution:** None detected

**Flags:**
- WASM: Present
- Obfuscated: Yes

---

## Data Flow Analysis

### Sensitive Data Collection Path

```
1. Page Visit
   ↓
2. Extension Detects Shopping Site
   ↓
3. Reads Auth Cookie (AUTH_BEARER_DPF)
   ↓
4. Extracts User ID from JWT/bearer token
   ↓
5. User Interacts with Coupons
   ↓
6. Extension Collects:
   - Tab ID
   - Session data
   - Codes tried (hashed)
   - Timing information
   - Success/failure status
   - User preferences
   ↓
7. Bundles with User ID (uid)
   ↓
8. POST to events.dpf.cloud/automatic-coupons/cycles
```

### Cross-Origin Communication

```
Web Page (any site)
   ↓ (postMessage - NO ORIGIN CHECK)
Content Script (window.addEventListener)
   ↓ (MessageChannel port)
Background Service Worker
   ↓ (chrome.runtime.sendMessage)
API Servers (events.dpf.cloud, api.dontpayfull.com)
```

---

## Attack Vectors

### 1. MessageChannel Hijacking
**Severity:** HIGH
**Prerequisites:** User visits attacker-controlled webpage
**Attack Flow:**
```javascript
// Malicious page
const channel = new MessageChannel();
window.postMessage({
  cmd: "webext-port-offer",
  scope: "[guessed namespace]",
  context: "[target context]"
}, "*", [channel.port2]);

channel.port1.onmessage = (msg) => {
  console.log("Extension response:", msg);
  // Potential to send malicious commands via MessageChannel
};
```

### 2. Extension Fingerprinting
**Severity:** MEDIUM
**Prerequisites:** None (requires management permission which extension has)
**Impact:** Extension can identify user by their installed extensions, creating a unique browser fingerprint for tracking across sites.

### 3. Cookie Theft (Theoretical)
**Severity:** LOW (limited to dontpayfull.com)
**Prerequisites:** None
**Impact:** Extension reads authentication cookies, which could be exfiltrated if extension were compromised or malicious update pushed.

---

## Privacy Implications

### User Tracking Profile
The extension can build detailed profiles containing:
- **Shopping Behavior:** Which stores visited, when, how often
- **Coupon Usage:** Which codes tried, success rates
- **Browser Fingerprint:** Via management permission (installed extensions)
- **Session Patterns:** Login state (via auth cookie), browsing times
- **Account Linkage:** Tracking tied to authenticated DontPayFull account

### Data Retention
Not specified in code or privacy policy analysis. Data sent to events.dpf.cloud retention period unknown.

---

## Recommendations

### For Users
1. **Acceptable Use Cases:**
   - Users comfortable with shopping behavior tracking
   - Users who trust DontPayFull's data practices
   - Users who want automated coupon application

2. **Risk Mitigation:**
   - Review extension permissions regularly
   - Use only on trusted shopping sites
   - Clear cookies/storage periodically
   - Monitor for unusual behavior

### For Developers
1. **CRITICAL:** Add origin validation to postMessage listener
   ```javascript
   window.addEventListener("message", (event) => {
     if (event.origin !== chrome.runtime.getURL("")) return;
     // Handle message
   });
   ```

2. **HIGH PRIORITY:** Remove `management` permission if not strictly necessary
   - Review code for actual usage
   - Remove if used only for analytics/fingerprinting

3. **MEDIUM PRIORITY:** Reduce cookie permission scope
   - Request cookies only for specific domains needed
   - Remove `<all_urls>` if possible, use specific shopping domains

4. **MEDIUM PRIORITY:** Implement webRequest justification or remove
   - Document why request interception is needed
   - Remove if only used for non-essential features

5. **LOW PRIORITY:** Transparency improvements
   - Document data collection practices
   - Provide opt-out for analytics tracking
   - Clear privacy policy in extension listing

---

## Compliance Considerations

### Chrome Web Store Policies
- **Data Collection Disclosure:** Extension should clearly disclose behavioral tracking and cookie access in privacy policy
- **Permissions Justification:** Management and webRequest permissions may trigger policy review
- **User Data Privacy:** Collection of auth tokens and user IDs should be disclosed

### GDPR/Privacy Laws
- **User Consent:** Behavioral tracking likely requires explicit consent in EU
- **Data Minimization:** Management permission appears excessive
- **Right to Erasure:** Should provide mechanism for users to delete collected data

---

## Technical Observations

### Build System
- Uses Vue.js framework (version 3.5.25)
- Vite-based build (references to dist/ output)
- TypeScript compiled to JavaScript
- Heavy use of webpack/rollup bundling

### Libraries Detected
- Vue.js 3.5.25
- webextension-polyfill (for cross-browser compatibility)
- MD5 hashing library (custom implementation)
- Promise queue library (p-queue)
- Event emitter (eventemitter3)
- Sentry SDK (error reporting)

### WebAssembly
Ext-analyzer detected WASM flag, but specific WASM module not identified in deobfuscated code. Possible uses:
- Cryptographic operations
- Performance-critical coupon matching
- Code obfuscation
- Third-party library dependency

---

## Comparison to Similar Extensions

Typical coupon finder extensions (Honey, Capital One Shopping, etc.) request similar permissions:
- ✅ `<all_urls>` - Standard for coupon finders
- ✅ `cookies` - Common for session management
- ✅ `tabs`, `storage`, `scripting` - Standard
- ❌ `management` - **UNCOMMON** - Most don't request this
- ❓ `webRequest` - Some use for optimization, not universal

**DontPayFull stands out for:**
1. Management permission (rare in this category)
2. No origin validation on postMessage (security issue)
3. More extensive tracking than typical (50+ event types)

---

## Verdict

**Risk Level: MEDIUM**

**Justification:**
DontPayFull is functionally a legitimate coupon finder extension, but exhibits security and privacy concerns that warrant a MEDIUM risk classification:

**Positive Factors:**
- Core functionality appears legitimate (automated coupon application)
- Uses standard web technologies (Vue.js, Chrome Extensions APIs)
- Implements error handling and CSP
- Focused on specific domain (dontpayfull.com) for auth

**Negative Factors:**
- **HIGH severity:** postMessage vulnerability without origin validation
- **Excessive permissions:** management API not justified for coupon finder
- **Extensive tracking:** 50+ event types tied to authenticated user
- **Cookie access:** Reads auth tokens across all sites (though only uses for own domain)
- **Code obfuscation:** Large minified bundles reduce transparency

**Not Classified as HIGH/CRITICAL because:**
- No evidence of malicious data exfiltration (tracking is disclosed functionality)
- Cookie access limited to legitimate domain (dontpayfull.com)
- No code execution vulnerabilities detected
- No remote code loading or eval() usage
- Tracking appears to be for legitimate business analytics

**Not Classified as LOW/CLEAN because:**
- PostMessage vulnerability creates exploitable attack surface
- Management permission enables privacy-invasive extension fingerprinting
- Combination of broad permissions + tracking creates risk
- Security best practices not followed (origin validation)

---

## Conclusion

DontPayFull is a legitimate coupon-finding extension with MEDIUM security risk. The primary concern is the postMessage vulnerability (no origin validation) which should be fixed immediately. The management permission appears excessive and should be removed unless strictly necessary. Users should be aware of extensive behavioral tracking tied to authenticated accounts.

**Recommended Actions:**
1. **Immediate:** Patch postMessage origin validation vulnerability
2. **Short-term:** Remove or justify management permission
3. **Medium-term:** Reduce cookie permission scope, improve tracking transparency

**For Users:** Acceptable for users comfortable with shopping behavior tracking and who trust DontPayFull's data practices. Not recommended for privacy-focused users.

---

**Analysis Date:** 2026-02-15
**Analyzer:** Claude Sonnet 4.5 (Static Analysis + Manual Code Review)
**Extension Version Analyzed:** 2.1.27
