# Security Analysis Report: Auto Refresh Plus

## Metadata
- **Extension ID**: ffejlioijcokmblckiijnjcmfidjppdn
- **Extension Name**: Auto Refresh Plus
- **Version**: 3.0.0
- **User Count**: ~100,000 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Auto Refresh Plus is an extension that allows users to automatically refresh browser tabs at specified intervals. The extension implements **privacy-invasive analytics tracking** that collects detailed browsing navigation data without adequate user disclosure. The tracking system monitors every page navigation, generating unique user IDs, and transmitting URL navigation flows (including referrer chains) to a remote server with Base64-encoded payloads and credentials included in requests.

**Primary Concerns**:
1. **Undisclosed browsing history collection** - Tracks all page navigations with referrer chains
2. **Persistent user tracking** - Generates and stores permanent unique identifiers
3. **Base64 obfuscation** - Encodes analytics payloads (likely to evade inspection)
4. **Credentials included in analytics** - Uses `credentials: "include"` sending cookies/auth headers
5. **Opt-out bypass** - Sets `privacyOff: true` on updates, potentially bypassing consent

## Vulnerability Details

### VULN-001: Comprehensive Browsing History Collection
**Severity**: HIGH
**File**: `background.js` (lines 88-112)
**Type**: Privacy violation / Undisclosed tracking

**Description**:
The extension implements a sophisticated browsing history tracking system that monitors all tab navigation events and reports URL transitions to `autorefreshplus.in/api/v1/analytics`.

**Code Evidence**:
```javascript
// background.js lines 88-95
reportAction = async (t, e, a, o) => {
  const r = {
    tis: (new Date).toISOString(),  // Timestamp
    uid: a,                           // Unique user ID
    docref: e,                        // Referrer URL
    uri: t                            // Current URL
  };
  await postData(`${BASEURL}/api/v1/analytics`, r)
};

// Lines 97-112 - Tab update listener
chrome.tabs.onUpdated.addListener((async (t, e, a) => {
  const { status: o } = e, { url: r } = a;
  if ("complete" === o) {
    const e = await tabInfo(t);
    let a = await getFromLocalStorage("uid"),
      o = e?.url;
    isValidPage(r) && r !== o && await reportAction(r, o, a);
    // Stores referrer chain
    let s = await getFromStorage("referrertabs") || {};
    s[t] = { url: r }, await setToStorage("referrertabs", s)
  }
}))
```

**Verdict**: CONFIRMED VULNERABILITY
- Tracks ALL page navigations (not just refreshed pages)
- Collects full URL navigation chains with referrers
- Operates continuously, regardless of extension active usage
- No apparent user control or granular consent mechanism

---

### VULN-002: Persistent Cross-Session User Tracking
**Severity**: HIGH
**File**: `background.js` (lines 113-121)
**Type**: Privacy violation / Fingerprinting

**Description**:
Extension generates a unique identifier (UUID v4) on installation and stores it permanently in local storage. This UID is transmitted with every navigation event, enabling persistent cross-session user tracking.

**Code Evidence**:
```javascript
// background.js lines 5-7
genrateId = () => ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g,
  (t => (t ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> t / 4).toString(16)))

// Lines 113-121
chrome.runtime.onInstalled.addListener((async function(t) {
  const { reason: e } = t, a = genrateId();
  if ("install" == e)
    await setToLocalStorage("uid", a),
    await setToLocalStorage("privacyOff", !1);
  else if ("update" == e) {
    await setToLocalStorage("privacyOff", !0),  // Sets privacy bypass on update!
    await getFromLocalStorage("uid") || await setToLocalStorage("uid", a)
  }
}))
```

**Verdict**: CONFIRMED VULNERABILITY
- Permanent unique identifier enables long-term user profiling
- UID persists across browser sessions and extension reinstalls (unless cleared manually)
- Combined with URL tracking creates detailed browsing profiles

---

### VULN-003: Base64 Payload Encoding (Anti-Inspection)
**Severity**: MEDIUM
**File**: `background.js` (lines 73-84)
**Type**: Obfuscation / Evasion technique

**Description**:
Analytics payloads are Base64-encoded before transmission. While not inherently malicious, this encoding serves no legitimate technical purpose (HTTP already handles binary data) and appears designed to obscure payload contents from casual inspection.

**Code Evidence**:
```javascript
// background.js lines 73-84
const postData = async (t, e) => {
  try {
    const a = await fetch(t, {
      method: "POST",
      credentials: "include",  // Includes cookies/auth headers
      headers: {
        "Content-Type": "application/json"
      },
      body: btoa(JSON.stringify(e))  // Base64 encode the JSON payload
    });
    return await a.json()
  } catch (t) {}
}
```

**Verdict**: CONFIRMED SUSPICIOUS BEHAVIOR
- No technical justification for Base64-encoding JSON data
- Combined with `credentials: "include"` increases privacy risk
- Pattern commonly used to evade automated content scanning

---

### VULN-004: Credentialed Cross-Origin Requests
**Severity**: MEDIUM
**File**: `background.js` (line 77)
**Type**: Privacy leak / CORS misconfiguration

**Description**:
Analytics requests include `credentials: "include"`, causing the browser to send cookies and authentication headers to `autorefreshplus.in`. This allows the server to correlate extension analytics with website user accounts if the user is logged into the domain.

**Code Evidence**:
```javascript
const a = await fetch(t, {
  method: "POST",
  credentials: "include",  // ⚠️ Sends cookies/auth headers
  headers: { "Content-Type": "application/json" },
  body: btoa(JSON.stringify(e))
});
```

**Verdict**: CONFIRMED VULNERABILITY
- Unnecessary inclusion of credentials in analytics requests
- Enables cross-referencing extension usage with user accounts
- Violates principle of least privilege

---

### VULN-005: Privacy Consent Bypass on Updates
**Severity**: MEDIUM
**File**: `background.js` (line 119), `assets/index-DeGHaBf1.js` (lines 11182-11207)
**Type**: Consent violation

**Description**:
On extension updates, the code automatically sets `privacyOff: true`, which disables the privacy consent banner. This means existing users who may have previously declined consent will have tracking re-enabled without renewed consent.

**Code Evidence**:
```javascript
// background.js line 119
else if ("update" == e) {
  await setToLocalStorage("privacyOff", !0),  // Force privacy banner off
  // ...
}

// index-DeGHaBf1.js - Consent banner only shows if privacyOff is false
chrome.storage.local.get("privacyOff", L => {
  L.privacyOff && Y(!0)  // Hide consent if privacyOff is true
})
```

**Verdict**: CONFIRMED VULNERABILITY
- Updates bypass previous consent decisions
- Privacy banner suppressed after updates without user re-confirmation
- Non-compliant with privacy consent best practices

---

## False Positives Analysis

| Pattern | Location | Verdict | Reason |
|---------|----------|---------|--------|
| React framework code | `assets/index-DeGHaBf1.js` | FALSE POSITIVE | Standard React/ReactDOM library code |
| `styled-components` library | `assets/index-DeGHaBf1.js` | FALSE POSITIVE | Legitimate CSS-in-JS styling library |
| `postMessage` in scheduler | `assets/index-DeGHaBf1.js` line 218 | FALSE POSITIVE | MessageChannel for React Scheduler (internal timing) |
| MutationObserver | `assets/index-DeGHaBf1.js` lines 5-12 | FALSE POSITIVE | Standard module preload optimization |
| Chrome i18n API usage | `assets/index-DeGHaBf1.js` lines 11182-11215 | FALSE POSITIVE | Localization strings |

---

## API Endpoints

| Endpoint | Method | Purpose | Data Sent | Credentials |
|----------|--------|---------|-----------|-------------|
| `https://autorefreshplus.in/api/v1/analytics` | POST | Navigation tracking | `{tis, uid, docref, uri}` (Base64) | ✓ Included |
| `https://autorefreshplus.in/privacy` | N/A | Privacy policy link | N/A | N/A |

---

## Data Flow Summary

1. **Installation/Update**:
   - Generate/retrieve UUID → Store as `uid` in `chrome.storage.local`
   - On update: Set `privacyOff: true` (bypass consent)

2. **Navigation Tracking** (Continuous):
   - `chrome.tabs.onUpdated` listener monitors all tab navigations
   - For each page load completion:
     - Retrieve stored `uid` from local storage
     - Retrieve previous URL from session storage (referrer chain)
     - Check if URL changed and is HTTP/HTTPS
     - Call `reportAction(currentURL, referrerURL, uid)`
   - `reportAction` → `postData`:
     - Create payload: `{tis: timestamp, uid: userId, docref: referrer, uri: currentURL}`
     - Base64-encode JSON payload
     - POST to `autorefreshplus.in/api/v1/analytics` with credentials

3. **Core Functionality** (Auto-refresh):
   - User sets refresh interval in popup
   - Background script uses `setInterval` + `chrome.tabs.reload()`
   - Displays countdown badge on extension icon

**Key Concern**: Navigation tracking operates independently of the auto-refresh feature. Users likely expect tracking only for refreshed pages, but ALL navigations are monitored.

---

## Permissions Analysis

| Permission | Declared | Used | Justified | Risk |
|------------|----------|------|-----------|------|
| `storage` | ✓ | ✓ | Partial | Stores UID, consent flags |
| `host_permissions: <all_urls>` | ✓ | ✗ | NO | **Not needed** - No content scripts, no URL-specific logic except tracking |

**Concern**: `<all_urls>` permission grants access to all websites but is not required for tab reloading functionality. This over-permission facilitates the privacy-invasive tracking behavior.

---

## Content Security Policy

**Manifest CSP**: Not explicitly defined (uses MV3 defaults)
- No unsafe-eval, no inline scripts
- No CSP-related vulnerabilities identified

---

## Overall Risk Assessment

**RISK LEVEL: HIGH**

### Risk Justification:
1. **Scope of Data Collection**: Comprehensive browsing history (all URLs + referrers) with unique user tracking
2. **Lack of Transparency**: Extension name/description suggest auto-refresh utility, not analytics platform
3. **User Base Impact**: ~100,000 users affected by undisclosed tracking
4. **Technical Evasion**: Base64 encoding + credentials inclusion + consent bypass patterns
5. **Excessive Permissions**: `<all_urls>` not required for core functionality

### Comparison to Legitimate Extensions:
- **Similar Extensions**: Most auto-refresh tools (Tab Reloader, Super Auto Refresh) do NOT track navigation history
- **Analytics Best Practices**: Extensions with legitimate analytics typically:
  - Clearly disclose data collection in store listing
  - Collect only feature usage metrics (not browsing history)
  - Use anonymous analytics (not persistent UIDs)
  - Respect opt-out choices across updates

### Chrome Web Store Policy Violations:
Likely violates:
- **User Data Policy**: "Limited Use" (collecting more data than needed for stated purpose)
- **Privacy Disclosure**: Browsing history collection not disclosed in store listing
- **Consent Requirements**: Privacy consent reset on updates

---

## Recommendations

### For Users:
1. **Uninstall immediately** if privacy is a concern
2. If continued use: Clear extension storage and monitor network traffic
3. Use alternative extensions (Tab Reloader Auto, Super Auto Refresh) with no tracking

### For Developers:
1. Remove navigation tracking entirely (not related to core feature)
2. If analytics needed:
   - Collect only feature usage (refresh count, interval settings)
   - Use anonymous/aggregated data
   - Obtain explicit opt-in consent
   - Respect consent across updates
3. Remove `<all_urls>` permission (not required)
4. Remove Base64 encoding (no legitimate purpose)
5. Remove `credentials: "include"` from analytics requests
6. Update store listing with full disclosure

### For Chrome Web Store Review:
1. Request detailed privacy disclosure
2. Verify browsing history collection necessity
3. Review consent mechanism and update behavior
4. Consider delisting until privacy controls implemented

---

## Conclusion

Auto Refresh Plus implements **privacy-invasive browsing history tracking** disguised as a simple utility extension. The combination of comprehensive URL monitoring, persistent user identification, payload obfuscation, and consent bypass mechanisms constitute a **HIGH privacy risk** for ~100,000 users. The extension collects significantly more data than required for its stated functionality and employs techniques commonly associated with malicious extensions.

**PRIMARY VERDICT**: HIGH RISK - Privacy-invasive tracking without adequate disclosure or consent mechanisms.
