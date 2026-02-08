# Security Analysis Report: QR Code Reader Extension

## Extension Metadata
- **Extension ID**: likadllkkidlligfcdhfnnbkjigdkmci
- **Name**: QR Code Reader
- **Version**: 2.0.3
- **Manifest Version**: 3
- **User Count**: ~200,000
- **Analysis Date**: 2026-02-06

## Executive Summary

**Overall Risk Level: MEDIUM**

QR Code Reader is a legitimate QR code scanning and generation extension with moderate privacy concerns. The extension implements:
- Remote message/notification system that can display arbitrary content to users
- URL shortening service with user data transmission to third-party servers
- Google Analytics tracking with session data collection
- Hardcoded cryptographic credentials for API authentication
- Optional online QR decoding that uploads image data to external services

While the extension provides genuine QR code functionality, it includes third-party data collection mechanisms that are not fully transparent to users. No malicious code patterns (XHR/fetch hooking, extension enumeration, keyloggers, ad injection) were detected.

---

## Vulnerability Details

### 1. REMOTE MESSAGE/NOTIFICATION SYSTEM (MEDIUM Severity)

**File**: `/scripts/shared.js` (lines 1336-1498)

**Description**: The extension fetches remote JSON configuration from two endpoints and displays messages/notifications to users. This system can be controlled server-side without requiring extension updates.

**Code Evidence**:
```javascript
// Remote message URLs
_ = ["https://dsnetx.web.app/apps/firelinks/msg.json",
     "https://dsnet.bitbucket.io/apps/ext/msg/msg.json"];

function z() {
  C.log("Loading messages...");
  const t = `${_[E]}?ref=${w}&r=${Math.random()}`;
  fetch(t, {
    cache: "no-store"
  }).then(e => e.json()).then(e => {
    R(w, "Notif", "Loaded"), O(e) ? (E++, C.log(`Failed, retrying - ${E}`),
    E < _.length && setTimeout(z, 100)) : (E = 0, at(e))
  })
}

// Messages can be targeted by extension ID, version, browser
function lt(t) {
  // ... filtering logic for extension ID, version, browser
  if (t.includes("#")) {
    const a = t.split("#");
    let s;
    if (a && a[1].includes("<")) {
      if (s = Number(a[1].replace("<", "")), n < s) return !0
    }
  }
}
```

**Message Display Methods**:
- `WEBUI`: jQuery notify plugin (default)
- `WEBALERT`: Browser alert() - blocks UI
- Can display HTML content via `data-notify-html`

**Risks**:
- Server can push arbitrary notifications without CWS review
- Messages displayed only between hours 7-22 (evasion tactic)
- Support for repeating messages based on `repeatXHours` parameter
- Targeting by extension version allows A/B testing/gradual rollout
- No integrity verification (unsigned JSON)

**Verdict**: CONCERNING - While currently used for legitimate feature announcements, this infrastructure could be repurposed for phishing, scams, or malicious redirects.

---

### 2. URL SHORTENING WITH USER DATA TRANSMISSION (MEDIUM Severity)

**File**: `/scripts/shared.js` (lines 332-367), `/scripts/common.js` (line 37)

**Description**: When users create QR codes for links, the extension sends user data (URLs, names, QR type) to third-party shortening services.

**Code Evidence**:
```javascript
// Third-party URL shortener services
QR_SERVICES: [
  "https://hybridapps.net/apps/URLShortner/bitly.php",
  "https://amazonspot.net/apps/URLShortner/bitly.php"
]

async function Se(t) {
  let e;
  for (const n of g.QR_SERVICES) {
    try {
      const a = new URL(n);
      a.searchParams.append("src", g.APP_ID);
      a.searchParams.append("type", "QR");
      a.searchParams.append("qrData", Te(JSON.stringify(t)));  // User data encoded
      a.searchParams.append("svcEnv", "QRCdOrg");
      e = await ve(a, "POST", null)
    } catch (a) {
      r.gaEventALV("QR_SERVICE_FAILED", n, a);
      continue
    }
  }
}
```

**Data Transmitted**:
- User's original URL/text
- QR code name (potentially revealing context)
- QR type (link, SMS, phone, etc.)
- Extension ID (`QrExt04-CH-v203`)

**Risks**:
- Sensitive URLs (internal dashboards, private documents) leaked to third parties
- No clear disclosure in UI that data leaves the extension
- `hybridapps.net` and `amazonspot.net` - unclear ownership/privacy policy
- Base64-encoded JSON (`Te()` function) provides minimal obfuscation

**Verdict**: PRIVACY RISK - Users may unknowingly share private URLs with third-party services.

---

### 3. HARDCODED CRYPTOGRAPHIC CREDENTIALS (LOW-MEDIUM Severity)

**File**: `/scripts/shared.js` (lines 857-870)

**Description**: API authentication uses hardcoded private key and token embedded in client-side code.

**Code Evidence**:
```javascript
function Ue(t, e) {
  const n = "Ek7lKS7294GeJz27RWMRgurovetXQj7haD6naj6nGVQ=",  // Private key
    a = "arBpuFqJ16avSsHO43u9iDmJdaBP8XPx",                // Token
    s = new oe.ec("secp256k1"),
    i = _e(k.Buffer.from(le(JSON.stringify({
      ...t,
      token: a,
      stamp: e
    })))),
    l = k.Buffer.from(n, "base64");
  return k.Buffer.from(s.sign(i, l, {
    canonical: !0
  }).toDER()).toString("base64")
}
```

**Risks**:
- Private key (secp256k1) exposed in plaintext
- Anyone can extract and impersonate the extension to backend API
- Token `arBpuFqJ16avSsHO43u9iDmJdaBP8XPx` also hardcoded
- Used for `qrcd.org/flProxy` API calls (QR decoding service)

**Verdict**: POOR SECURITY PRACTICE - While primarily an API design flaw rather than user threat, this allows unauthorized API access.

---

### 4. OPTIONAL ONLINE QR DECODING (LOW-MEDIUM Severity)

**File**: `/scripts/shared.js` (lines 893-929)

**Description**: Users can enable online QR decoding which uploads captured screenshots/images to `qrcd.org` servers.

**Code Evidence**:
```javascript
function ee(t) {
  return Fe("decodeQRCode", {
    url: t  // Image data URL
  }, "POST", "multiple=1&all_fields=1").then(e => JSON.parse(e))
}

const h = `https://qrcd.org/flProxy?url=${encodeURIComponent(s)}`;
return fetch(h, l).then(c => c.json())
```

**What Gets Uploaded**:
- `chrome.tabs.captureVisibleTab()` screenshots (when scanning from active tab)
- Base64 image data URLs
- Full image content visible in user's browser

**Mitigations**:
- Feature is OFF by default
- Requires explicit user opt-in via settings
- Fallback to local ZXing library if offline decode works

**Risks**:
- Screenshots may contain sensitive information beyond QR code
- PII, financial data, internal systems could be exposed
- `qrcd.org` receives images without clear privacy policy link at opt-in

**Verdict**: ACCEPTABLE WITH CONCERNS - Opt-in model is good, but disclosure could be clearer.

---

### 5. GOOGLE ANALYTICS SESSION TRACKING (LOW Severity)

**File**: `/scripts/common.js` (lines 118-175)

**Description**: Comprehensive analytics tracking including session duration, feature usage, error states.

**Code Evidence**:
```javascript
const S = "TUPmjqdgS1uW6XUrdz14ow",  // API secret
  m = "G-N23YH0B9JD";                // Measurement ID

let d = async (e, t, o, s) => {
  // ...
  const g = {};
  g[e] = n, s && s.sessionId && (
    g.session_id = s.sessionId,
    g.engagement_time_msec = s.engagementTime
  );
  await fetch(`https://www.google-analytics.com/mp/collect?measurement_id=${m}&api_secret=${S}`, {
    method: "POST",
    body: JSON.stringify({
      client_id: c,
      events: [{
        name: I,
        params: g
      }]
    })
  })
}
```

**Data Collected**:
- Session IDs and engagement time
- Feature usage patterns (QR create/read/history)
- Error events with details
- User actions (copy, download, share)
- Generated client ID stored in `chrome.storage.local`

**Verdict**: STANDARD TELEMETRY - Common for free extensions, but API secret exposure is poor practice.

---

### 6. LEGACY CLIPBOARD API USAGE (INFO)

**File**: `/scripts/shared.js` (lines 610-618)

**Description**: Uses deprecated `document.execCommand('copy')` for clipboard operations.

**Code Evidence**:
```javascript
function j() {
  return function(e) {
    t && (t = !1, setTimeout(() => {
      const n = document.createElement("div");
      n.style.position = "absolute", n.style.top = "-999px", n.style.left = "-999px",
      n.contentEditable = "true", document.body.appendChild(n), n.innerHTML = e,
      n.focus(), document.execCommand("SelectAll"), document.execCommand("copy", !1),
      document.body.removeChild(n), t = !0
    }, 0))
  }
}
```

**Verdict**: LOW RISK - Deprecated but functional. Should migrate to modern Clipboard API.

---

## False Positive Analysis

| Pattern | File | Line | Assessment | Reason |
|---------|------|------|------------|--------|
| `fetch()` calls | `shared.js` | Multiple | **LEGITIMATE** | Used for GA, URL shorteners, QR decode API - all disclosed features |
| `innerHTML` usage | `libs/jquery.js` | Multiple | **FALSE POSITIVE** | jQuery library DOM manipulation |
| `addEventListener` | `vendors.js` | Multiple | **FALSE POSITIVE** | ZXing barcode reader library (video/image events) |
| `chrome.storage.local` | `common.js` | Multiple | **LEGITIMATE** | Settings and QR history storage |
| Remote JSON fetch | `shared.js` | 1365 | **CONCERNING** | Message system - see Vuln #1 |

---

## API Endpoints & External Communication

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://dsnetx.web.app/apps/firelinks/msg.json` | Remote notifications | Extension ID, version | Medium |
| `https://dsnet.bitbucket.io/apps/ext/msg/msg.json` | Remote notifications (fallback) | Extension ID, version | Medium |
| `https://hybridapps.net/apps/URLShortner/bitly.php` | URL shortening | User URLs, QR names, extension ID | Medium |
| `https://amazonspot.net/apps/URLShortner/bitly.php` | URL shortening (fallback) | User URLs, QR names, extension ID | Medium |
| `https://qrcd.org/flProxy` | Online QR decode | Screenshot images (opt-in) | Medium |
| `https://www.google-analytics.com/mp/collect` | Analytics | Usage telemetry, session data | Low |
| `https://ggle.io/*` | Install/uninstall/help pages | Browser navigation only | None |

**Domain Ownership Concerns**:
- `dsnetx.web.app` - Firebase hosting (unclear owner)
- `dsnet.bitbucket.io` - Bitbucket static hosting (unclear owner)
- `hybridapps.net` - Third-party URL shortener (no visible privacy policy)
- `amazonspot.net` - Third-party URL shortener (unrelated to Amazon, concerning naming)
- `ggle.io` - URL shortener mimicking "google.io" - questionable branding

---

## Data Flow Summary

```
USER ACTIONS:
├─ Create QR Code (Link)
│  ├─> Stored locally (chrome.storage.local)
│  └─> Sent to hybridapps.net/amazonspot.net for shortening
│      └─> Short URL returned and cached
│
├─ Scan QR Code
│  ├─> Local decode attempt (ZXing library)
│  └─> If enabled: Upload screenshot to qrcd.org
│      └─> Decoded text returned
│
├─ Open Popup
│  └─> Fetch remote messages from dsnetx.web.app
│      └─> Display notifications (if targeted to this version)
│
└─ All User Actions
   └─> Send telemetry to Google Analytics
       └─> Event name, labels, session duration
```

---

## Permissions Analysis

```json
"permissions": [
  "tabs",         // Read tab URLs - used for auto-filling QR create form
  "activeTab",    // Screenshot capture for QR scanning
  "unlimitedStorage",  // Large QR history storage
  "storage",      // Settings and cache
  "contextMenus", // Right-click menu integration
  "scripting"     // Content script injection for in-page QR display
]
```

**Assessment**: Permissions are appropriate for stated functionality. No excessive privileges.

**CSP**: No `content_security_policy` defined (default MV3 restrictions apply).

---

## Code Quality & Security Practices

### Positive Findings:
- ✅ Manifest V3 (modern security model)
- ✅ No extension enumeration/killing
- ✅ No XHR/fetch hooking or monkey-patching
- ✅ No ad injection or DOM manipulation
- ✅ No keyloggers or input capture
- ✅ Uses legitimate libraries (jQuery, Bootstrap, ZXing)
- ✅ Online decode is opt-in, not default
- ✅ No obfuscated or packed code

### Negative Findings:
- ❌ Hardcoded cryptographic credentials
- ❌ Remote message system without integrity checks
- ❌ Undisclosed third-party data sharing (URL shorteners)
- ❌ No visible privacy policy in extension UI
- ❌ Uses deprecated clipboard API
- ❌ GA API secret exposed in client code
- ❌ Message display limited to 7am-10pm (evasion-like behavior)

---

## Comparison to Known Malicious Patterns

| Pattern | Present? | Notes |
|---------|----------|-------|
| Extension enumeration/killing | ❌ No | Clean |
| XHR/fetch hooking | ❌ No | Clean |
| Residential proxy infrastructure | ❌ No | Clean |
| Market intelligence SDK (Sensor Tower) | ❌ No | Clean |
| AI conversation scraping | ❌ No | Clean |
| Ad injection | ❌ No | Clean |
| Remote kill switch | ⚠️ Partial | Message system could disable features |
| Cookie harvesting | ❌ No | Clean |
| DOM keyloggers | ❌ No | Clean |

---

## Recommendations

### For Users:
1. **Disable online QR decode** unless absolutely needed (default is already off)
2. **Avoid creating QR codes for sensitive URLs** - use offline mode or different tool
3. **Review browser permissions** - consider revoking if only scanning, not creating
4. Check `qrcd.org/privacy.html` for data handling policies

### For Developer:
1. **Remove remote message system** or implement signed JSON with integrity verification
2. **Disclose third-party data sharing** prominently in UI before first use
3. **Migrate to modern Clipboard API** (`navigator.clipboard`)
4. **Remove hardcoded credentials** - use per-installation tokens or public API
5. **Add privacy policy link** in extension settings and create QR flow
6. **Consider self-hosted URL shortener** to eliminate third-party data sharing
7. **Remove time-based message filtering** (7am-10pm logic appears evasive)

### For Researchers:
- Monitor `dsnetx.web.app/apps/firelinks/msg.json` for message content changes
- Check if `hybridapps.net` and `amazonspot.net` are reused across extensions
- Investigate relationship between these domains and extension developer

---

## Overall Risk Assessment

**Risk Level: MEDIUM**

**Rationale**:
QR Code Reader is a **functional, legitimate extension** that provides real QR scanning/generation capabilities. However, it implements **privacy-invasive data collection** through URL shortening services and a **concerning remote message system** that could be weaponized.

The extension does not exhibit malicious behaviors seen in VPN malware (extension killing, ad injection, SDK harvesting), but the **lack of transparency** about third-party data sharing and the **server-controlled messaging** infrastructure represent moderate risks.

**Key Concerns**:
1. User URLs sent to unknown third parties without clear disclosure
2. Remote message system can display arbitrary content
3. Hardcoded API credentials enable impersonation

**Mitigating Factors**:
1. No active malicious code detected
2. 200K users with generally positive reviews (no red flags)
3. Sensitive features (online decode) are opt-in
4. No excessive permissions beyond stated functionality

---

## Conclusion

QR Code Reader sits in the **gray area between legitimate software and privacy-invasive tooling**. While it delivers promised functionality, the remote messaging infrastructure and undisclosed third-party data sharing warrant a **MEDIUM** risk classification. Users who only scan QR codes (not create) and keep online decode disabled face minimal risk. Users who create QR codes for sensitive URLs should seek alternatives.

The extension would benefit significantly from:
- Transparency improvements (privacy policy, data sharing disclosures)
- Removal of remote message infrastructure
- Migration to self-hosted or disclosed shortening services
