# Security Analysis: Points Path for Google Flights (kblbdlhoeakihpcaimpdjnfkjffnhhej)

## Extension Metadata
- **Name**: Points Path for Google Flights
- **Extension ID**: kblbdlhoeakihpcaimpdjnfkjffnhhej
- **Version**: 1.9.20
- **Manifest Version**: 3
- **Estimated Users**: ~100,000
- **Developer**: pointspath.com
- **Analysis Date**: 2026-02-14

## Executive Summary
Points Path for Google Flights is a **legitimate travel comparison extension** that overlays frequent flyer points pricing onto Google Flights search results. The extension integrates with multiple airlines (Delta, Emirates, United, etc.) and provides value-add functionality for travelers seeking to maximize reward points. However, the extension exhibits **multiple security weaknesses** that create vulnerability and privacy risks:

1. **Content Security Policy with unsafe-eval** on both extension pages and sandbox
2. **Message handlers without proper origin validation**
3. **Third-party anti-bot service (TrueSign.ai)** with authentication token flows
4. **Analytics tracking** via Umami with anonymous ID generation
5. **Cross-site cookie manipulation** using cookies permission on airline websites

While no malicious behavior was detected, the combination of weak security practices and extensive third-party integrations elevates this extension to **MEDIUM risk**.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. Content Security Policy Weaknesses (HIGH)
**Severity**: HIGH
**Files**:
- `/extracted/manifest.json` (lines 20-23)

**Analysis**:
The extension declares dangerous CSP directives that allow dynamic code execution:

```json
"content_security_policy": {
  "extension_page": "script-src 'self' 'eval' 'unsafe-eval' 'wasm-unsafe-eval' 'https://*/*'; object-src 'self'",
  "sandbox": "sandbox allow-scripts; script-src 'self' 'eval' 'unsafe-eval' 'wasm-unsafe-eval' 'https://www.google-analytics.com/analytics.js' 'libs/exceljs.min.js'; object-src 'self'"
}
```

**Security Impact**:
- `unsafe-eval` permits `eval()` and `Function()` constructor usage, making the extension vulnerable to code injection attacks
- `'https://*/*'` allows loading scripts from any HTTPS domain
- If any data from Google Flights or airline websites reaches code execution contexts, an attacker-controlled page could achieve arbitrary code execution within the extension's privileged context

**Evidence from Code**:
The OpenTelemetry tracing library (used for debugging) references `localhost:9411` in default configs (`flightsContent.js:4688`), suggesting development artifacts remain in production. While the OTEL_EXPORTER_ZIPKIN_ENDPOINT is a config default and may not be actively used, it demonstrates the complex build pipeline that necessitated unsafe-eval.

**Justification**:
The CSP appears to be required for bundled dependencies (React, Material-UI, Excel export libraries) that use dynamic code generation. However, this creates an unnecessarily large attack surface.

**Verdict**: **HIGH RISK** - CSP defeats browser's defense-in-depth protections.

---

### 2. Postmessage Handler Without Origin Validation (HIGH)
**Severity**: HIGH
**Files**:
- `/deobfuscated/chunks/chunk-JPXJVAGD.js` (line 14750)

**Analysis**:
The extension registers a global `window.addEventListener("message")` handler for cross-origin iframe communication:

```javascript
this.recordCrossOriginIframes && window.addEventListener("message", this.handleMessage.bind(this))
```

**Handler Implementation** (line 14771):
```javascript
handleMessage(e) {
  let n = e;
  if (n.data.type !== "rrweb" || n.origin !== n.data.origin || !e.source) return;
  let s = this.crossOriginIframeMap.get(e.source);
  if (!s) return;
  let a = this.transformCrossOriginEvent(s, n.data.event);
  a && this.wrappedEmit(a, n.data.isCheckout)
}
```

**Vulnerability**:
The origin check compares `n.origin !== n.data.origin`, which is **circular logic**. The `n.origin` property is attacker-controlled if the message comes from an embedded iframe on a malicious airline booking page. An attacker could craft a message where both `origin` and `data.origin` match their malicious domain, bypassing the validation.

**Attack Scenario**:
1. User visits a compromised airline booking page (or malicious ad on legitimate airline site)
2. Attacker's iframe sends postMessage with `{type: "rrweb", origin: "https://evil.com", data: {origin: "https://evil.com", event: {...}}}`
3. Message passes validation and reaches `transformCrossOriginEvent()`
4. Attacker can inject DOM mutation events that manipulate the extension's state

**ext-analyzer Finding**:
```
[HIGH] window.addEventListener("message") without origin check
message data → fetch(api.pointspath.com) and fetch(edge.truesign.ai)
```

The dataflow tracer confirms that message data can reach network sinks, meaning an attacker could potentially trigger API calls to Points Path backend with manipulated data.

**Verdict**: **HIGH RISK** - Improper origin validation allows message injection attacks.

---

### 3. Third-Party Anti-Bot Service Integration (MEDIUM)
**Severity**: MEDIUM
**Files**:
- `/deobfuscated/chunks/content-HTRMGGTF.js` (lines 6948-7003)

**Analysis**:
The extension integrates with **TrueSign.ai**, an anti-bot/fraud detection service at `edge.truesign.ai`:

```javascript
async createTSToken() {
  try {
    let e = { signal: AbortSignal.timeout(1e3) },
      a = await fetch(`https://edge.truesign.ai/v2/${this.truesignEndpoint}`, {...e}),
      o = await a.json();
    return this.tsToken = o.token, this.tsToken || "no-token"
  } catch (e) {
    return console.error("Unable to request authentication token", e),
           this.tsToken = "unauthenticated", this.tsToken
  }
}
```

**Token Injection**:
The TrueSign token is injected into API requests either as query parameter or header:
```javascript
async applyQueryParams(e, a) {
  return ..., {
    ...this.truesignEndpoint ? { tsToken: await this.getTsToken() } : {},
    ...this.partnerKey ? { partnerKey: this.partnerKey } : {},
    appVersion: this.appVersion
  }
}

async applyHeaders(e) {
  let a = new Headers(e);
  return this.injectInto === "headers" && (
    this.truesignEndpoint && a.set("X-TS-Token", await this.getTsToken()),
    this.partnerKey && a.set("X-Partner-Key", this.partnerKey),
    a.set("X-App-Version", this.appVersion)
  ), a
}
```

**Privacy & Security Implications**:
- **Third-party tracking**: TrueSign.ai receives requests from the extension with browser fingerprinting data (likely sent in request to obtain token)
- **Dependency risk**: The extension's functionality depends on a third-party service's availability and trustworthiness
- **Data leakage**: Unknown what data TrueSign collects when issuing tokens (user agent, canvas fingerprints, WebGL data, etc.)
- **No user disclosure**: No privacy policy link in manifest or visible consent mechanism

**Legitimate Use Case**:
Anti-bot services are common in e-commerce and booking platforms to prevent scraping and fraud. Points Path likely uses this to access airline APIs without getting rate-limited or blocked.

**Verdict**: **MEDIUM RISK** - Legitimate functionality but introduces third-party privacy concerns.

---

### 4. Umami Analytics Tracking (MEDIUM)
**Severity**: MEDIUM
**Files**:
- `/deobfuscated/chunks/chunk-U7K6SCAA.js` (lines 921-1131)
- `/deobfuscated/flightsContent.js` (line 9814)

**Analysis**:
The extension implements **Umami** (open-source Google Analytics alternative) with persistent anonymous ID tracking:

```javascript
function wt() {
  return qt({
    websiteId: "fc84641c-5644-4973-ab78-774c8140a578",
    hostURL: "https://umami.pointspath.com"
  })
}
```

**Anonymous ID Generation**:
```javascript
async function ee() {
  let t = chrome.storage.sync.get("umamiAnonymousId");
  if ("umamiAnonymousId" in t && typeof t.umamiAnonymousId == "string")
    return t.umamiAnonymousId;
  {
    let e = `anon-${crypto.randomUUID()}`;
    return await chrome.storage.sync.set({ umamiAnonymousId: e }), e
  }
}
```

**Data Transmitted**:
The Umami tracker sends events to `https://umami.pointspath.com/api/send` including:
- Anonymous user ID (persisted in sync storage across devices)
- Page URLs (Google Flights search parameters revealing travel plans)
- Browser metadata (screen resolution, user agent)
- Event names (clicks, searches, feature usage)

**Privacy Impact**:
- **Travel intent tracking**: Search queries like origin/destination airports, dates, passenger counts are visible in URL parameters
- **Cross-device tracking**: Using `chrome.storage.sync` means the same anonymous ID follows the user across all synced Chrome instances
- **No opt-out mechanism**: Analytics run automatically with no user control

**Code Evidence** (`chunk-U7K6SCAA.js:1020`):
```javascript
function Q() {
  return lt || !t || !e || A && A.getItem("umami.disabled") ||
         M && !st.includes(S) || L && Et()
}
```
The disable check looks for `localStorage.getItem("umami.disabled")`, but this is inaccessible to users and not documented.

**Cross-Site Sharing**:
The `checkoutContent.js` script posts Umami user ID to pointspath.com via postMessage:
```javascript
async function n() {
  let i = await t();
  window.postMessage({umami:{user:i}}, "https://pointspath.com/")
}
```

This shares the anonymous tracking ID with the Points Path website, enabling cross-context tracking.

**Verdict**: **MEDIUM RISK** - Extensive usage analytics without clear disclosure or opt-out.

---

### 5. Cross-Site Cookie Manipulation (LOW)
**Severity**: LOW
**Files**:
- `/deobfuscated/background.js` (lines 221-260)

**Analysis**:
The extension uses the `cookies` permission to read/write cookies on airline domains:

```javascript
async function ae(e, t) {
  return await chrome.cookies.set({
    url: e,
    name: "_points_path_internal",
    value: "test"
  }), await chrome.cookies.get({
    url: e,
    name: t
  })
}

async function ie(e, t, r, o) {
  let { httpOnly: s, path: n, maxAge: i, sameSite: a } = o;
  await chrome.cookies.set({
    url: e, name: t, value: r,
    httpOnly: s, expirationDate: be(i), path: n, sameSite: a
  })
}

async function ce(e, t) {
  return await chrome.cookies.remove({ url: e, name: t })
}
```

**Use Case**:
Background script exports `getCookie`, `setCookie`, and `removeCookie` functions that content scripts call via message passing (`background.js:280-285`). This allows the extension to maintain session state across airline booking sites.

**Legitimate Justification**:
Points Path needs to:
1. Store user preferences (e.g., preferred airline programs)
2. Maintain authentication state with airline loyalty programs
3. Track which flights the user has viewed for price comparison

**Potential Abuse**:
- **Session hijacking**: If compromised, the extension could exfiltrate airline session cookies
- **CSRF attacks**: Setting arbitrary cookies could bypass CSRF protections on airline sites
- **Privacy leakage**: Reading cookies reveals logged-in status and user IDs across airline sites

**Mitigating Factors**:
- Cookies are only accessed via explicit message commands from content scripts
- No evidence of cookie exfiltration in network flows
- Cookie names used are extension-specific (`_points_path_internal`)

**Verdict**: **LOW RISK** - Necessary functionality with proper scoping, but increases attack surface.

---

### 6. Overly Broad Web Accessible Resources (LOW)
**Severity**: LOW
**Files**:
- `/extracted/manifest.json` (lines 433-444)

**Analysis**:
```json
"web_accessible_resources": [{
  "resources": ["images/*", "fonts/CabinVariableFont.ttf", "*.js"],
  "matches": ["<all_urls>"]
}]
```

**Vulnerability**:
The `*.js` wildcard makes **all JavaScript files** accessible to any website. This enables:
- **Extension fingerprinting**: Websites can detect the extension by probing for `chrome-extension://kblbdlhoeakihpcaimpdjnfkjffnhhej/background.js`
- **Code analysis**: Attackers can reverse-engineer the extension's logic by downloading all JS files
- **XSSI attacks**: If any JS file contains JSONP-style callbacks or dynamic data, it could leak information

**Impact**:
While images and fonts are reasonable to expose, exposing all JavaScript is excessive. The extension only needs to inject specific content scripts, not make them web-accessible.

**Verdict**: **LOW RISK** - Enables fingerprinting but no direct exploitation vector.

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Sensitivity |
|--------|---------|------------------|-------------|
| `api.pointspath.com` | Backend API | Search params, flight details, user prefs | HIGH |
| `edge.truesign.ai` | Anti-bot tokens | Browser fingerprints (likely) | MEDIUM |
| `umami.pointspath.com` | Analytics | Anonymous ID, page views, events | MEDIUM |
| `api.delta.com` | Delta award search | Flight queries, session cookies | HIGH |
| `hxjqzkcirzhjvtubefie.supabase.co` | Database (Supabase) | User settings, saved searches (likely) | MEDIUM |
| `vio-wrapper-api-cd-6981968610.europe-west4.run.app` | Viator tours API | Unknown (likely travel recommendations) | LOW |
| Airline domains | Price comparisons | Flight search parameters | HIGH |

### Data Flow Summary

**Data Collection**:
- Google Flights search parameters (origin, destination, dates, passengers, cabin class)
- Tab URLs for flight comparison context
- Chrome storage sync data (settings, anonymous analytics ID)
- Airline cookies (for session management)

**Data Transmission**:
- **Points Path API**: All flight search data to generate award pricing
- **TrueSign.ai**: Authentication requests (unknown payload)
- **Umami Analytics**: Page views, events, anonymous user ID
- **Airline APIs**: Flight search queries (Delta, Emirates, etc.)

**Third-Party Sharing**:
- Supabase backend receives unknown data (likely user accounts, saved searches)
- TrueSign.ai receives browser fingerprints for token generation
- Umami receives de-identified usage analytics

**No browsing data beyond flight searches is collected or transmitted.**

---

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `activeTab` | Read Google Flights DOM for price injection | Low (standard) |
| `storage` | Store user preferences and cache | Low (local only) |
| `webRequest` | Intercept airline API calls for data extraction | Medium (passive observation) |
| `declarativeNetRequestWithHostAccess` | Modify X-Frame-Options headers to embed airline content | Medium (functional) |
| `cookies` | Read/write airline session cookies | **High** (session access) |
| `scripting` | Inject content scripts into flight search pages | Low (standard) |
| `host_permissions` (Google Flights) | Access search results DOM | Low (functional) |
| `host_permissions` (Delta API) | Query award availability | Medium (airline API access) |
| `host_permissions` (pointspath.com) | Communicate with backend | Low (own domain) |
| `optional_host_permissions` (430+ domains) | Access all major airlines/OTAs | **High** (broad scope) |

**Assessment**: Permission scope is appropriate for declared functionality. The cookies permission combined with 430+ optional airline domains creates significant privilege if all are granted, but most users will only enable specific airlines.

---

## Code Quality Observations

### Positive Indicators
1. **No credential harvesting** - No attempts to read passwords or payment info
2. **No ad injection** - No DOM manipulation for advertising purposes
3. **No extension enumeration** - No `chrome.management` API abuse
4. **Transparent functionality** - Behavior matches user expectations (price overlay)
5. **Modern architecture** - React-based, modular code structure

### Negative Indicators
1. **CSP with unsafe-eval** - Defeats XSS protections
2. **Weak origin validation** - Postmessage handler vulnerable to injection
3. **No privacy policy link** - Manifest lacks `privacy_policy` field (MV3 best practice)
4. **Development artifacts** - OTEL tracing code, localhost:9411 references
5. **Obfuscated analytics** - Umami disable mechanism hidden from users
6. **Third-party dependencies** - TrueSign.ai integration not disclosed

### Obfuscation Level
**MEDIUM** - Webpack bundling creates minified variable names, but logic is traceable. API calls and data flows are identifiable through static analysis.

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✓ **Yes** | webRequest API used (passive observation only) |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | Scoped to flight search pages |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✗ No | Only flight price overlays |
| Remote config/kill switches | ✗ No | No remote code loading |
| Cookie harvesting | ⚠ **Partial** | Cookies accessed for session management, not exfiltration |
| Hidden data exfiltration | ⚠ **Partial** | Analytics tracking via Umami (disclosed functionality) |

**Conclusion**: No malicious patterns detected. Behaviors align with legitimate flight comparison service.

---

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Justification**:
1. **Legitimate core functionality** - Provides real value (award pricing comparison)
2. **Multiple security weaknesses** - CSP, origin validation, third-party integrations
3. **Privacy concerns** - Analytics tracking, third-party anti-bot service
4. **No malicious intent** - No evidence of data exfiltration, credential theft, or malware behavior
5. **User expectation alignment** - Extension does what it claims (compare flight prices with points)

### Risk Breakdown
- **Code Execution Risk**: MEDIUM (CSP allows eval, but no active exploitation)
- **Data Exfiltration Risk**: LOW (analytics only, no sensitive data theft)
- **Privacy Risk**: MEDIUM (tracking via Umami, TrueSign fingerprinting)
- **Session Hijacking Risk**: LOW (cookie access for functional purposes)
- **Supply Chain Risk**: MEDIUM (TrueSign.ai dependency, Supabase backend)

### Recommendations

**For Users**:
- Extension is **safe to use** for its intended purpose
- Be aware that search activity is tracked via analytics
- Review optional airline permissions - only grant what you need
- Consider that TrueSign.ai may fingerprint your browser

**For Developers** (Points Path team):
- **HIGH PRIORITY**: Remove CSP `unsafe-eval` or migrate to eval-free dependencies
- **HIGH PRIORITY**: Fix postmessage origin validation (use allowlist, not circular check)
- **MEDIUM PRIORITY**: Add privacy policy link to manifest
- **MEDIUM PRIORITY**: Implement user-accessible analytics opt-out toggle
- **MEDIUM PRIORITY**: Disclose TrueSign.ai integration in privacy policy
- **LOW PRIORITY**: Reduce web_accessible_resources scope (exclude `*.js`)
- **LOW PRIORITY**: Remove development artifacts (OTEL localhost references)

### User Privacy Impact
**MODERATE** - The extension tracks flight searches for analytics and uses third-party anti-bot service. Users seeking maximum privacy should avoid, but average users face minimal risk. No financial data or credentials are accessed.

---

## Technical Summary

**Lines of Code**: ~350,000 (bundled with React, MUI, OTEL libraries)
**External Dependencies**: React, Material-UI, Umami, OpenTelemetry, Supabase, TrueSign.ai
**Remote Code Loading**: None
**Dynamic Code Execution**: Potentially via CSP unsafe-eval (not observed in analysis)
**Obfuscation**: Webpack minification (standard build process)

---

## Conclusion

Points Path for Google Flights is a **legitimate browser extension** providing award travel price comparison functionality. The extension demonstrates **no malicious behavior** such as credential theft, ad injection, or data exfiltration. However, it exhibits **multiple security and privacy weaknesses**:

1. Weak CSP enabling potential code injection
2. Postmessage handler vulnerable to origin spoofing
3. Third-party anti-bot service with unknown data collection
4. Analytics tracking without user control
5. Broad cookie access across airline domains

These issues elevate the risk level from CLEAN to **MEDIUM**. The extension is **safe for use** by travelers seeking points comparison, but users should be aware of analytics tracking and third-party integrations. Developers should prioritize fixing the CSP and origin validation vulnerabilities.

**Final Verdict: MEDIUM** - Functional extension with security debt that should be addressed.
