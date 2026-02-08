# Surfe Extension Security Analysis Report

## Metadata
- **Extension Name**: Surfe
- **Extension ID**: kojhcdejfimplnokhhhekhiapceggamn
- **Version**: 2.7.57
- **User Count**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Surfe is a CRM integration extension that operates primarily on LinkedIn, allowing users to access and manage their CRM (HubSpot, Pipedrive, Salesforce, Copper, Google Sheets) directly from LinkedIn profiles. The extension collects LinkedIn session cookies and user data, then synchronizes this information with backend CRM systems via the Surfe API (`https://api.surfe.com`).

**Overall Risk Assessment**: **LOW**

The extension exhibits expected behavior for a legitimate CRM integration tool. While it accesses sensitive LinkedIn cookies and implements extensive data collection, these practices serve the extension's stated purpose of CRM synchronization. The extension does not exhibit malicious patterns such as ad injection, extension killing, proxy infrastructure, or undisclosed data exfiltration.

## Vulnerability Analysis

### 1. LinkedIn Cookie Harvesting (MEDIUM Severity)

**Files**:
- `background.js` (lines 19359-19377)

**Description**: The extension actively harvests LinkedIn authentication cookies including `li_at`, `li_a`, and `JSESSIONID`.

**Code Evidence**:
```javascript
const hh = async () => {
  chrome.cookies.getAll({
    domain: `www.${r}`  // www.linkedin.com
  }, (e => {
    const t = ["JSESSIONID", "li_at", "li_a"],
      n = {};
    e.forEach((e => {
      "JSESSIONID" === e.name ? n.sessionID = e.value.split('"').join("") :
      t.includes(e.name) && (n[e.name] = e.value,
      ("li_a" === e.name || "li_at" === e.name) &&
      (n.li_a_expiration = e.expirationDate?.toString()))
    })), If(n)
  }));
```

**Verdict**: **Expected Behavior**

This is standard functionality for a LinkedIn CRM integration tool. The extension needs LinkedIn session cookies to authenticate API requests on behalf of the user. The cookies are:
- Stored in chrome.storage.local (not transmitted externally without purpose)
- Used for legitimate LinkedIn API interactions
- Part of the extension's core CRM synchronization feature

**Severity Justification**: MEDIUM because while the behavior is legitimate, cookie harvesting always represents elevated privilege that could be misused if the extension were compromised.

---

### 2. HubSpot Cookie Collection (LOW Severity)

**Files**:
- `background.js` (lines 19335-19345)

**Description**: Extension collects HubSpot authentication cookies (`hubspotapi-csrf`, `__cf_bm`, `hubspotapi`).

**Code Evidence**:
```javascript
chrome.cookies.getAll({
  domain: ".hubspot.com"
}, (e => {
  for (let t = 0; t < e.length; t++)
    "hubspotapi-csrf" === e[t].name && If({hubspotapi_csrf: e[t].value.split('"').join("")}),
    "__cf_bm" === e[t].name && If({__cf_bm: e[t].value.split('"').join("")}),
    "hubspotapi" === e[t].name && If({hubspotapi: e[t].value.split('"').join("")})
}));
```

**Verdict**: **Expected Behavior**

HubSpot is one of the supported CRM integrations. Collecting these cookies is necessary for authenticated HubSpot API calls.

**Severity**: LOW - legitimate functionality for HubSpot CRM integration.

---

### 3. Extensive Data Collection via DataDog (MEDIUM Severity)

**Files**:
- `background.js` (lines 19223-19261)

**Description**: The extension implements DataDog logging SDK with comprehensive user tracking.

**Code Evidence**:
```javascript
tn.init({
  clientToken: t,
  site: "datadoghq.eu",
  forwardErrorsToLogs: !0,
  forwardConsoleLogs: ["info", "error"],
  sampleRate: 100,
  service: "extension",
  silentMultipleInit: !0,
  version: e,
  beforeSend: e => /* filtering logic */
});

tn.setLoggerGlobalContext({
  company_key: o,
  email: r,
  extension_version: e,
  name: n,
  userInfo: {
    name: n, email: r, company: i, company_key: o,
    crm: a, locale: s, deviceID: u,
    initilizationTimestamp: Ff
  }
});
```

**Verdict**: **Expected Behavior with Privacy Considerations**

DataDog is a legitimate error tracking and logging service. The extension sends:
- User name and email
- Company information
- Device ID
- Error logs and console output
- Extension version and initialization timestamp

**Concerns**:
- 100% sample rate means all users are tracked
- Personal identifying information (email, name) sent to third-party (DataDog EU)
- Console logs forwarded externally could leak sensitive debugging data

**Severity**: MEDIUM - This is standard telemetry for enterprise SaaS tools, but users should be aware their PII is shared with DataDog.

---

### 4. Backend API Communication (LOW Severity)

**Files**:
- `background.js` (lines 17780-17848)

**Description**: All data flows through Surfe's backend API at `https://api.surfe.com` (or `https://api.prod.surfe.com`).

**Code Evidence**:
```javascript
const s = new URL(t, e.baseUrl ?? "https://api.prod.surfe.com");
return fetch(i, {
  method: e,
  headers: {
    Accept: "application/json",
    "Content-Type": "application/json",
    "Extension-Version": zf(),
    Authorization: `Bearer ${o}`,
    ...n
  },
  body: a,
  signal: r?.signal
})
```

**Verdict**: **Expected Behavior**

The extension communicates with its own backend for:
- User authentication
- CRM data synchronization
- Contact/company information export
- List export functionality

**Severity**: LOW - standard client-server architecture for a SaaS product.

---

### 5. Content Script Injection on LinkedIn (LOW Severity)

**Files**:
- `manifest.json` (content_scripts)
- `background.js` (lines 19121-19131)

**Description**: Extension injects content scripts into all LinkedIn pages at document_start.

**Code Evidence (manifest.json)**:
```json
"content_scripts":[{
  "run_at":"document_start",
  "matches":["https://linkedin.com/*","https://www.linkedin.com/*"],
  "js":["assets/scripts/boot.js"],
  "all_frames":true
}]
```

**Verdict**: **Expected Behavior**

Content scripts run on LinkedIn to:
- Extract profile/company information from the DOM
- Inject Surfe UI elements (CRM widgets)
- Enable side panel functionality
- Capture LinkedIn messaging data (for CRM conversation sync)

**Severity**: LOW - required for core functionality of LinkedIn CRM integration.

---

### 6. LinkedIn Messaging Data Access (MEDIUM Severity)

**Files**:
- `assets/scripts/emberMessage.js` (lines 1-180)

**Description**: Extension accesses LinkedIn's internal Ember.js render tree to extract messaging/conversation data.

**Code Evidence**:
```javascript
window.addEventListener("message", (function(e) {
  if ("https://www.linkedin.com" !== e.origin) return;
  if (!e.data || "EMBER_MESSAGE" !== e.data.type) return;

  const n = Object.values(r.nodes).filter((e => t.includes(e.name)));
  // Extracts conversation threads, messages, profiles
  window.dispatchEvent(new CustomEvent("messageThreadConv", {
    detail: { data: s }
  }))
}));
```

**Verdict**: **Expected Behavior**

For a CRM tool, capturing LinkedIn conversations makes sense - sales teams often want to log LinkedIn messages in their CRM. However:

**Concerns**:
- Accesses private message content
- Relies on LinkedIn's internal Ember.js structure (fragile, may break)
- No clear user notification that messages are being captured

**Severity**: MEDIUM - Functionality is legitimate for CRM use case, but involves accessing private communications.

---

### 7. fetch API Proxy/Hook (LOW Severity)

**Files**:
- `assets/scripts/index.js`

**Description**: Extension patches window.fetch to hide extension ID in certain requests.

**Code Evidence**:
```javascript
window.fetch = new Proxy(window.fetch, {
  apply: function(e, n, t) {
    if (t.length > 0 && "string" == typeof t[0] &&
        t[0].includes("lnokhhhekhiapce")) {
      t[0] = "chrome-extension://xxxxxxxxxxxxxxxx/index.js"
    }
    return e.apply(n, t)
  }
});
```

**Verdict**: **Defensive Measure**

This appears to be protection against LinkedIn detecting/blocking the extension by obfuscating the extension ID in fetch requests. While technically a "hook", it's:
- Limited in scope (only modifies URLs containing the extension ID)
- Not intercepting user data
- Not manipulating responses

**Severity**: LOW - benign defensive coding.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `dangerouslySetInnerHTML` | Multiple React components | Standard React SVG rendering, not XSS vector |
| `__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED` | background.js, inject.js | React internal API reference, not malicious |
| XMLHttpRequest hooks | background.js (DataDog SDK) | DataDog RUM SDK instrumentation for performance monitoring |
| `eval` patterns | None found | No dynamic code execution detected |
| Extension enumeration | None found | No evidence of detecting/disabling other extensions |

---

## API Endpoints Analysis

| Endpoint | Purpose | Data Transmitted |
|----------|---------|------------------|
| `https://api.surfe.com` (primary) | Main backend API | User auth tokens, CRM data, LinkedIn profile info |
| `https://api.prod.surfe.com` (fallback) | Production API endpoint | Same as above |
| `https://api.leadjet.io` | Legacy/alternate domain | Registration redirects |
| `https://datadoghq.eu` | Telemetry/logging | Error logs, user metadata, console output |
| `https://app.surfe.com` | Web application | Frontend interface, auth flows |

**All endpoints use HTTPS with Bearer token authentication.**

---

## Data Flow Summary

1. **LinkedIn Cookie Collection**:
   - `li_at`, `li_a`, `JSESSIONID` → chrome.storage.local
   - Sent to Surfe API for authenticated LinkedIn scraping

2. **Profile/Company Data Extraction**:
   - Content scripts parse LinkedIn DOM
   - Extracted data: name, title, company, email, phone, location
   - Transmitted to `api.surfe.com` with user's auth token

3. **CRM Synchronization**:
   - User connects CRM (HubSpot, Pipedrive, etc.)
   - CRM cookies collected for auth
   - Extension acts as middleware: LinkedIn ↔ Surfe API ↔ CRM

4. **Messaging Data**:
   - LinkedIn conversations extracted via Ember.js introspection
   - Message threads, participant profiles sent to backend
   - Stored in user's connected CRM

5. **Telemetry**:
   - All errors, user actions, page loads sent to DataDog
   - Includes PII: email, name, company key

---

## Permission Analysis

| Permission | Usage | Risk |
|------------|-------|------|
| `storage` | Store user settings, auth tokens, LinkedIn cookies | LOW - standard |
| `tabs` | Query tabs, reload tabs, inject scripts | LOW - required for content injection |
| `cookies` | Access LinkedIn/HubSpot cookies | MEDIUM - sensitive but necessary |
| `scripting` | Inject content scripts dynamically | LOW - standard MV3 pattern |
| `sidePanel` (optional) | Chrome side panel UI | LOW - UI feature |

**Host Permissions**:
- `https://linkedin.com/*` - Core functionality
- `https://*.hubspot.com/*` - HubSpot CRM integration
- `https://*.surfe.com/*` - Backend communication
- `https://leadjet.io/*` - Legacy/partner domain

**No dangerous permissions**: No webRequest, declarativeNetRequest, or proxy permissions.

---

## Content Security Policy

The extension does not define a custom CSP in manifest.json, relying on Chrome's default MV3 CSP:
- `script-src 'self'` (no remote scripts)
- `object-src 'self'` (no plugins)
- No unsafe-eval or unsafe-inline

**Verdict**: Secure CSP posture.

---

## Overall Risk Assessment: **LOW**

### Justification:

**Why not CLEAN:**
- Extension collects sensitive LinkedIn session cookies
- Accesses private LinkedIn messages
- Sends PII to third-party (DataDog)
- Implements fetch API hooking

**Why not MEDIUM/HIGH:**
- All sensitive data access serves stated CRM integration purpose
- No malicious patterns detected:
  - ✅ No ad/coupon injection
  - ✅ No extension enumeration/killing
  - ✅ No residential proxy infrastructure
  - ✅ No remote code execution
  - ✅ No obfuscated malicious payloads
  - ✅ No undisclosed data exfiltration
- Uses secure authentication (Bearer tokens)
- HTTPS for all network communication
- Standard telemetry practices for enterprise SaaS

**Caveats**:
1. Users should understand that LinkedIn cookies and messages are accessed/transmitted
2. PII is shared with DataDog (EU region) for logging
3. Extension relies on reverse-engineering LinkedIn's internal Ember.js structure (could break)
4. Trust in Surfe's backend security is required (all data flows through their API)

### Recommendation:
**CLEAN with disclosure**. The extension performs as advertised for a CRM integration tool. Users should be informed via privacy policy that:
- LinkedIn authentication cookies are collected
- LinkedIn messages may be logged in CRM
- Error telemetry (including email/name) sent to DataDog

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Notes |
|-------------------|----------|-------|
| Extension killing/enumeration | ❌ No | No detection of other extensions |
| XHR/fetch global hooks | ⚠️ Limited | Only hooks own extension ID, not intercepting user traffic |
| Residential proxy infra | ❌ No | No proxy configuration detected |
| Remote config/kill switches | ❌ No | No remote code loading |
| Market intelligence SDKs | ❌ No | No Sensor Tower, Pathmatics, etc. |
| AI conversation scraping | ⚠️ Partial | LinkedIn messages captured, but for stated CRM purpose |
| Ad/coupon injection | ❌ No | No DOM manipulation for ads |
| Heavy obfuscation | ❌ No | Standard webpack minification only |
| Keylogging | ❌ No | No keystroke capture detected |
| Credential theft | ❌ No | Cookies used for auth, not exfiltrated for theft |

---

## Conclusion

Surfe is a **legitimate CRM integration extension** with appropriate permissions and data access patterns for its stated purpose. While it handles sensitive data (LinkedIn cookies, private messages, HubSpot credentials), this is necessary for CRM synchronization functionality.

The extension exhibits good security practices:
- Manifest V3 compliance
- HTTPS-only communication
- Token-based authentication
- No dynamic code execution
- Standard enterprise telemetry

**Final Risk Level**: **LOW**

Users should use this extension with understanding that:
1. It has full access to LinkedIn profile data and messages
2. Data is synchronized to connected CRM systems via Surfe's backend
3. Some PII is transmitted to DataDog for error tracking
4. The extension operates as a trusted intermediary between LinkedIn and CRM platforms
