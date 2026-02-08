# Vulnerability Report: Crumbs - Keep your data safe & block cookies

## Extension Metadata
- **Extension ID**: akommlakkhgbjbidpkkdcgbjgbeemdik
- **Extension Name**: Crumbs - Keep your data safe & block cookies
- **Version**: 2.8.1
- **Author**: Eyeo GmbH (makers of Adblock Plus)
- **User Count**: ~10,000
- **Manifest Version**: 3

## Executive Summary

Crumbs is a legitimate privacy-focused browser extension developed by Eyeo GmbH. The extension provides cookie blocking, tracker protection, fingerprinting defense, email relay/masking services, and implements the Global Privacy Control (GPC) signal.

**Overall Risk Assessment: CLEAN**

While the extension requests extensive permissions appropriate for its privacy protection functionality, the code analysis reveals no malicious behavior, data exfiltration, or hidden backdoors. All data collection is limited to anonymized telemetry for product improvement, which is standard for Eyeo products. The extension's behavior aligns with its stated privacy-protection purpose.

## Permissions Analysis

### Declared Permissions
```json
"permissions": [
  "tabs",
  "webRequest",
  "declarativeNetRequest",
  "declarativeNetRequestFeedback",
  "webNavigation",
  "storage",
  "unlimitedStorage",
  "history",
  "scripting",
  "alarms",
  "contextMenus",
  "cookies"
],
"host_permissions": ["<all_urls>"]
```

### Permission Justification
- **tabs/webNavigation**: Required for tracking page loads and applying content scripts
- **declarativeNetRequest**: Used for blocking trackers/cookies via DNR rulesets (344k+ blocking rules)
- **storage/unlimitedStorage**: Stores filter lists, user preferences, and email relay aliases
- **history**: Used for interest taxonomy categorization (privacy-preserving browsing pattern analysis)
- **scripting**: Injects privacy shims (cookie blocking, GPC signal, fingerprinting protection)
- **cookies**: Monitors and blocks third-party tracking cookies
- **host_permissions**: Required to apply content scripts and blocking rules across all websites

**Verdict**: All permissions are necessary for stated functionality. No permission abuse detected.

## Content Security Policy
No CSP defined in manifest (relies on browser defaults). This is acceptable for MV3 extensions.

## Vulnerability Assessment

### 1. Data Collection & Telemetry

**Severity**: LOW
**Files**: `background.js` (lines 30827-30828, 17300-17468)

**Description**:
The extension implements telemetry via Eyeo's infrastructure:
- Production telemetry: `https://crumbs.telemetry.eyeo.com/topic/crumbs_event/version/3`
- Staging telemetry: `https://test-telemetry.data.eyeo.it/topic/crumbs_event/version/3`
- Error tracking: Sentry SDK with tunnel via `https://raven.crumbs.org`

**Code Evidence**:
```javascript
// background.js line 58
n = "https://crumbs.telemetry.eyeo.com/topic/crumbs_event/version/3"

// background.js line 30827
dsn: "https://4af5b6e4c3824c80a27d68e0dcb93df0@o526868.ingest.sentry.io/4505245016784896",
tunnel: "https://raven.crumbs.org"
```

The telemetry system tracks:
- Interest categories from browsing (taxonomy-based, anonymized)
- Extension usage statistics
- Error/crash reports via Sentry

**Verdict**: ACCEPTABLE - Telemetry is user-controllable via settings (`share_statistics` flag), uses privacy-preserving aggregation, and aligns with Eyeo's transparent data practices. No PII or browsing URLs are transmitted.

---

### 2. Email Relay & API Key Storage

**Severity**: LOW
**Files**: `email-relay.js`, `relay-auth.js`

**Description**:
The extension provides an email relay/masking service integrated with Crumbs' backend:
- API endpoints: `https://api-relay.crumbs.org`, `https://relay.crumbs.org`
- Stores API keys in local storage: `settings.set("api_key", value)`
- Auto-fills masked email addresses into form fields

**Code Evidence**:
```javascript
// relay-auth.js lines 954-964
function n() {
  var e = document.querySelector("crumbs-token");
  if (e) {
    var s = e.dataset.apiKey;
    return r().runtime.sendMessage({
      type: "settings.set",
      name: "api_key",
      value: s
    }), s
  }
  return null
}
```

**Potential Concern**: API keys are stored in extension local storage and transmitted to Crumbs domains. However, this is standard practice for authenticated services.

**Verdict**: ACCEPTABLE - The email relay is an opt-in feature. API key storage follows industry standards. Communication is limited to official Crumbs domains over HTTPS.

---

### 3. Cookie Blocking Shims

**Severity**: NONE
**Files**: `content-scripts/cookie-remove.shim.js`, `content-scripts/cookie-expire.shim.js`

**Description**:
Injects JavaScript shims to block cookie-setting attempts at the DOM level:

**Code Evidence**:
```javascript
// cookie-remove.shim.js
Object.defineProperty(Document.prototype, "cookie", {
  set: t(e.set, {
    apply: (t, e, o) => Reflect.apply(t, e, [""])  // Blocks cookie writes
  })
});

Object.defineProperty(CookieStore.prototype, "set", {
  value: t(e.value, {
    apply: (t, e, o) => Promise.reject(new DOMException("An unknown error occurred..."))
  })
});
```

**Verdict**: LEGITIMATE - This is core privacy functionality. The shims prevent websites from setting cookies via `document.cookie` and the Cookie Store API, which is the extension's primary purpose.

---

### 4. Fingerprinting Protection

**Severity**: NONE
**Files**: `content-scripts/fingerprint-shield.js`, `content-scripts/gpc.shim.js`

**Description**:
Implements anti-fingerprinting measures and Global Privacy Control:
- Randomizes canvas/WebGL fingerprints using seedable RNG (MurmurHash3)
- Sets `navigator.globalPrivacyControl = true`

**Code Evidence**:
```javascript
// gpc.shim.js
Object.defineProperty(Navigator.prototype, "globalPrivacyControl", {
  value: !0,
  writable: !1
});
```

**Verdict**: LEGITIMATE - Standard privacy protection techniques. GPC is a W3C standard for communicating user privacy preferences.

---

### 5. Declarative Net Request Rules

**Severity**: NONE
**Files**: `rulesets/D72B6F06-52B2-4FED-96A2-1BF59CDD7AEC` (344k lines), others

**Description**:
The extension loads extensive DNR rulesets for blocking trackers/cookies:
- Main ruleset: 344,744 lines of tracker blocking rules
- Rules block tracking parameters (`&action=js_stats&`, `&event=view&`, `&http_referer=`)
- Filter list updates from `https://filterlist.crumbs.org/crumbs/crumbs_extension.json`

**Sample Rules**:
```json
{
  "priority": 1000,
  "condition": {
    "urlFilter": "&http_referer=",
    "resourceTypes": ["script", "xmlhttprequest"],
    "excludedDomains": ["biletomat.pl", "facebook.com", "jobscore.com"]
  },
  "action": { "type": "block" },
  "id": 1882
}
```

**Verdict**: LEGITIMATE - These are standard tracker blocking rules similar to those used by uBlock Origin and Adblock Plus. No evidence of selective allowlisting for financial gain.

---

### 6. Interest Taxonomy Tracking

**Severity**: LOW
**Files**: `background.js` (lines 25594-25607)

**Description**:
The extension categorizes browsing history into "interest" categories for privacy-preserving analytics:
- Fetches taxonomy: `https://filterlist.crumbs.org/meta-domains.json`, `meta-interests.json`
- Maps visited domains to interest categories
- Stores aggregated interest counts in IndexedDB

**Code Evidence**:
```javascript
// background.js lines 25595-25602
ready: async function() {
  na || (sa = await da("https://filterlist.crumbs.org/meta-domains.json"),
         la = await da("https://filterlist.crumbs.org/meta-interests.json"),
         na = !!sa)
},
resolve: function(e, o = "") {
  const a = new URL(e).hostname.replace(/^www\./, "");
  return sa[a]?.category  // Maps domain to category
}
```

**Privacy Concern**: The extension tracks which interest categories users visit (e.g., "technology", "shopping"), though not specific URLs.

**Verdict**: ACCEPTABLE WITH CAVEATS - Interest tracking is anonymized and aggregated. However, users should be clearly informed about this feature. The tracking appears to be for improving filter lists rather than advertising.

---

### 7. Idle Detection Tracking

**Severity**: LOW
**Files**: `content-scripts/idle-detection.js`

**Description**:
Monitors user interactions (clicks, keypresses, mouse movements) to detect active browsing sessions:

**Code Evidence**:
```javascript
// idle-detection.js lines 883-892
const r = ((e, r) => {
  let s;
  return (...r) => {
    clearTimeout(s), s = setTimeout((() => {
      e.apply(null, r)
    }), 500)
  }
})((r => {
  r.isTrusted && !r.repeat && e.runtime.sendMessage({
    type: "INTERACT"
  })
}));
["click", "keypress", "mousemove"].forEach((e => {
  window.addEventListener(e, r, !1)
}))
```

**Verdict**: ACCEPTABLE - Idle detection is used to determine active browsing time for telemetry accuracy. Event details are not captured—only a debounced "user is active" signal.

---

## False Positives

| Pattern | Location | Reason for False Positive |
|---------|----------|--------------------------|
| Sentry SDK hooks | `background.js` | Standard error tracking SDK (Eyeo-owned infrastructure) |
| Browser polyfill | All scripts | Mozilla's webextension-polyfill for cross-browser compatibility |
| `postMessage` usage | `email-relay.js` | Legitimate iframe communication for email relay menu |
| IndexedDB operations | `background.js` | Local storage for filter lists and preferences (no sync to server) |
| Random number generation | `fingerprint-shield.js` | Seedable RNG for consistent fingerprint randomization (privacy feature) |
| History access | `background.js` | Used only for local interest categorization, not transmitted |
| Cookie permission | manifest.json | Required to block third-party cookies (core feature) |

## API Endpoints Inventory

| Endpoint | Purpose | Data Transmitted | Risk Level |
|----------|---------|------------------|------------|
| `crumbs.telemetry.eyeo.com` | Anonymized usage telemetry | Interest category counts, extension version, error logs | LOW |
| `api-relay.crumbs.org` | Email relay service API | API key, masked email aliases | LOW |
| `relay.crumbs.org` | Email relay web interface | User authentication tokens | LOW |
| `filterlist.crumbs.org` | Filter list updates | None (fetch only) | NONE |
| `raven.crumbs.org` | Sentry error tunnel | Error stack traces, browser info | LOW |
| `stage.crumbs.org` / `stage-relay.crumbs.org` | Staging environments | Same as production (staging builds only) | LOW |

**Network Security**: All endpoints use HTTPS. No third-party tracking domains contacted.

## Data Flow Summary

```
User Browsing → Content Scripts (Cookie/Tracker Blocking) → No Data Sent
User Browsing → Interest Taxonomy → IndexedDB (Local Storage)
User Interaction → Idle Detection → "INTERACT" Message (Local)
Extension Errors → Sentry SDK → raven.crumbs.org (Error Reports)
Telemetry Opt-In → Background Script → crumbs.telemetry.eyeo.com (Aggregated Stats)
Email Relay Use → API Calls → api-relay.crumbs.org (Masked Emails)
```

**Key Privacy Features**:
- No browsing URLs transmitted to servers
- Interest taxonomy stored locally only (not synced unless telemetry enabled)
- Cookie permission used for blocking, not harvesting
- History permission used for local categorization, not exfiltration

## Obfuscation Analysis

**Level**: Moderate (webpack bundling + minification)

The extension uses standard webpack bundling with minification. No deliberate obfuscation beyond build tooling. The code is readable with standard deobfuscation tools. Module names and string literals are intact, suggesting no intent to hide functionality.

## Comparison to Known Threats

**Not Present**:
- ❌ Remote code execution / `eval()` abuse
- ❌ Cryptocurrency mining
- ❌ Ad injection
- ❌ Credential harvesting
- ❌ Screenshot capture
- ❌ Keylogging
- ❌ Extension fingerprinting/killing
- ❌ Residential proxy infrastructure
- ❌ Market intelligence SDKs (Sensor Tower, etc.)
- ❌ Unauthorized data exfiltration

**Present (Legitimate)**:
- ✅ Telemetry (opt-in, anonymized)
- ✅ Error tracking (Sentry)
- ✅ Cookie blocking (core feature)
- ✅ Email relay (opt-in service)

## Developer Reputation

**Eyeo GmbH** is the established company behind Adblock Plus, one of the most widely used ad blockers. They have a public track record in the privacy/ad-blocking space since 2011. While their "Acceptable Ads" program has been controversial, there is no history of malware or data abuse.

## Recommendations

1. **User Transparency**: Clearly disclose interest taxonomy tracking in the privacy policy
2. **Telemetry Controls**: Ensure `share_statistics` setting is easily accessible
3. **API Key Security**: Consider using browser identity APIs instead of storing API keys in local storage
4. **Filter List Verification**: Implement signature verification for downloaded filter lists

## Overall Risk Assessment

**CLEAN**

**Rationale**:
- All permissions are justified and used as intended
- No malicious code patterns detected
- Telemetry is limited, anonymized, and controllable
- Developed by reputable company (Eyeo GmbH)
- Email relay service follows industry-standard practices
- Tracker blocking behavior matches stated purpose
- No evidence of data exfiltration beyond disclosed telemetry

**User Impact**: This extension genuinely enhances user privacy by blocking cookies, trackers, and fingerprinting attempts. The telemetry and email relay features are transparent opt-in services that do not compromise the core privacy-protection mission.

**Deployment Recommendation**: Safe for use. Suitable for privacy-conscious users who trust Eyeo's data handling practices.
