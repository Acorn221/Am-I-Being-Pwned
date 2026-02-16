# Security Analysis Report

**Extension Name:** 穿梭Transocks回国加速器 - 海外华人回国追剧听歌
**Extension ID:** ikobbjiomdcedikdmkfhlhoagpailcbh
**Version:** 3.4.0
**User Count:** ~100,000
**Risk Level:** MEDIUM

---

## Executive Summary

Transocks is a Chinese VPN service marketed to overseas Chinese users for accessing geo-restricted content in China. The extension implements canvas fingerprinting to generate persistent device identifiers, transmits browsing metadata and user agent information to backend servers, and uses encrypted API communication. While these practices may be justified for legitimate VPN authentication and abuse prevention, the extension also incentivizes users to leave positive Chrome Web Store reviews in exchange for VIP access, constitutes review manipulation.

**Primary Concerns:**
- Canvas fingerprinting used to generate persistent device "MAC address"
- Exfiltration of user agent, tab information, and storage data to backend servers
- Encrypted API communication obscuring data transmission details
- Review manipulation through VIP incentives
- Broad host permissions enabling traffic inspection

---

## Vulnerability Details

### 1. Canvas Fingerprinting for Device Tracking (HIGH)

**Location:** `background.js:3758-3774`

**Evidence:**
```javascript
V = () => J(void 0, void 0, void 0, (function*() {
  return new Promise((e, t) => {
    const n = new OffscreenCanvas(200, 20),
      r = n.getContext("2d"),
      o = "i9asdm..$#po((^@KbXrww!~cz";
    r.textBaseline = "top", r.font = "16px 'Arial'", r.textBaseline = "alphabetic", r.rotate(.05), r.fillStyle = "#f60", r.fillRect(125, 1, 62, 20), r.fillStyle = "#069", r.fillText(o, 2, 15), r.fillStyle = "rgba(102, 200, 0, 0.7)", r.fillText(o, 4, 17), r.shadowBlur = 10, r.shadowColor = "blue", r.fillRect(-20, 10, 234, 5), n.convertToBlob().then(t => {
      const n = new FileReader;
      n.readAsDataURL(t), n.onloadend = () => {
        const t = n.result.split(",")[1],
          r = Object(I.sha256)(t);
        e(r)
      }
    }).catch(e => {
      t(e)
    })
  })
}));
```

**Description:**
The extension generates a SHA-256 hash of canvas rendering data to create a persistent device fingerprint. This value is used as a "mac" (MAC address equivalent) in all API requests to identify the device across sessions, even after uninstallation/reinstallation.

**Risk:** Canvas fingerprinting enables persistent cross-session tracking and cannot be cleared by users through normal browser privacy controls.

---

### 2. User Data Exfiltration to Backend Servers (HIGH)

**Location:** `background.js:4066-4090`, `js/popup.js:12550-12590`

**Evidence:**
```javascript
const h = {
  target: t,
  device: "chrome",
  mac: l,  // Canvas fingerprint
  org: "transocks_pro",
  app_version: c.version,
  language: a.language
};
e.langue || Object.assign(h, e), (null === (i = null === (o = u) || void 0 === o ? void 0 : o.token) || void 0 === i ? void 0 : i.access_token) && (h.access_token = u.token.access_token);
```

**Login exfiltration:**
```javascript
const i = navigator.userAgent,
  o = i.split("(")[1].split(")")[0],  // OS info
  a = i.split(")")[2].split(" ")[1].split("/")[1],  // Browser version
  l = yield this.extFetch({
    email: e,
    password: t,
    autokick: 1,
    auth_type: "jwt",
    auth: "email",
    app_version: at.version,
    model: o,
    os: a
  }, "login");
```

**Description:**
The extension transmits to `webapi.fobwifi.com`:
- Canvas fingerprint (as "mac")
- Chrome storage data (`chrome.storage.local.get`)
- Tab information (`chrome.tabs.query`)
- User agent strings (parsed into model/OS/browser version)
- Extension version
- Language preferences
- Authentication tokens

**Risk:** Excessive data collection beyond what's necessary for VPN functionality. User browsing metadata and device characteristics are persistently tracked.

---

### 3. Encrypted API Communication (MEDIUM)

**Location:** `background.js:3776-3796`, `background.js:3798-3823`

**Evidence:**
```javascript
function $(e, t, n = !1) {
  if (!e.encrypted) return e;
  let r;
  if (t ? r = u + l : n && (r = u + l), L(W(Object(q.HmacSHA1)(`encrypted=${e.encrypted}&t=${e.t}`, r).toString())) !== e.sign) return e;
  const o = e.t.toString().slice(-8),
    i = new Uint8Array(I.sha256.arrayBuffer(U(r + o))),
    s = new Uint8Array(I.sha256.arrayBuffer(K(i, U(r + o)))).slice(0, 16),
    a = function(e) {
      const t = self.atob(e),
        n = t.length,
        r = new Uint8Array(n);
      for (let e = 0; e < n; e++) r[e] = t.charCodeAt(e);
      return r
    }(e.encrypted),
    c = new M.a.ModeOfOperation.cbc(i, s),
    h = M.a.utils.utf8.fromBytes(D.padding.pkcs7.strip(c.decrypt(a))),
    f = JSON.parse(h);
  return Object.assign(Object.assign({}, f), {
    t: e.t
  })
}
```

**Description:**
API responses are encrypted using AES-CBC with HMAC-SHA1 signatures. While encryption protects data in transit, it also obscures the full extent of data collection from inspection. Request bodies are also encrypted before transmission using similar mechanisms.

**Risk:** Encrypted communication prevents users and security researchers from fully auditing what data is being transmitted.

---

### 4. Review Manipulation / Incentivized Reviews (MEDIUM)

**Location:** `js/popup.js:13408-13414`, `background.js:3140-3141`

**Evidence:**
```javascript
{
  type: "toUrl",
  icon: "menu_Icon_thumb_nor",
  title: n.leave_a_comment,
  onClick: () => {
    Ht(nt)  // Opens Chrome Web Store review page
  }
}
```

**Localized strings:**
```javascript
rate_transocks: "Rate Transocks,get a three-day VIP!",
leave_a_comment: "Review",
```

**Chinese version:**
```javascript
rate_transocks: "给穿梭评分，获赠3天vip！",  // "Rate Transocks, get 3 days VIP!"
leave_a_comment: "给个好评",  // "Give a good review"
```

**Description:**
The extension incentivizes users to leave Chrome Web Store reviews in exchange for 3 days of VIP access. This violates Chrome Web Store Developer Program Policies section on review manipulation.

**Risk:** Inflates extension ratings artificially, misleading potential users about the extension's quality and trustworthiness.

---

### 5. Eval Usage in Cryptographic Context (LOW)

**Location:** `background.js:622-623`, `js/popup.js:577-578`

**Evidence:**
```javascript
var crypto = eval("require('crypto')"),
  Buffer = eval("require('buffer').Buffer"),
```

**Description:**
The code attempts to dynamically require Node.js modules using `eval()`. While this appears to be dead code from a build tool (likely webpack) and won't execute in the browser context, it represents poor coding practices.

**Risk:** Low - likely non-functional dead code, but demonstrates insecure coding patterns.

---

## Network Endpoints

The extension communicates with the following domains:

1. **webapi.fobwifi.com** - Primary API endpoint
   - User authentication
   - VPN server configuration
   - Canvas fingerprint transmission
   - User metadata collection

2. **b.kolavpn.xyz** - Backup API endpoint
   - Fallback for primary domain failures

3. **www.transocks.com.cn** - Payment/marketing portal
   - VIP subscription management
   - User redirection on install

4. **chrome.google.com/webstore** - Chrome Web Store
   - Review manipulation target
   - Opens extension review page when users click "leave a comment"

**API Communication Flow:**
```
Extension → Encrypt(user_data + canvas_fingerprint + tabs + storage)
         → POST /ext/gateway → webapi.fobwifi.com
         ← Encrypted response with VPN configuration
```

---

## Permissions Analysis

**Declared Permissions:**
- `proxy` - Required for VPN functionality (legitimate use)
- `webRequest` - Monitor all network requests across all sites
- `storage` - Store user authentication tokens and preferences
- `alarms` - Schedule periodic connection checks
- `webRequestAuthProvider` - Handle proxy authentication

**Host Permissions:**
- `http://*/*` - Access all HTTP sites
- `https://*/*` - Access all HTTPS sites

**Concern:** The combination of `webRequest` and broad host permissions enables the extension to inspect all user web traffic. While necessary for VPN functionality, this creates significant privacy risks if the backend servers are compromised or logs are retained.

---

## Code Execution Risks

**Dynamic Code Evaluation:**
- `eval("require('crypto')")` - Lines 622-623 (background.js), 577-578 (popup.js)
- `new Function("return this")()` - Lines 1131 (background.js), 1251 (popup.js)

These appear to be webpack bundle artifacts and are unlikely to execute in the extension context. No evidence of runtime remote code execution was found.

---

## Message Handler Security

**Location:** `background.js:4503-4519`

**Evidence:**
```javascript
chrome.runtime.onMessage.addListener((function(e, t, n) {
  if (t.id === chrome.runtime.id) switch (e[N.popupKey]) {
    case v.breakConnect:
      Ce();
      break;
    case v.connecting:
      Re();
      break;
    case "reconnect":
      ! function() {
        me(this, void 0, void 0, (function*() {
          Q(v.breakConnect, "connectStatus"), Ce(() => {
            Q(v.connecting, "connectStatus"), Re()
          })
        }))
      }()
  }
}))
```

**Assessment:**
The message handler properly validates sender ID (`t.id === chrome.runtime.id`), restricting message processing to internal components only. No external message handling vulnerabilities detected.

---

## Data Flow Summary

**Sources (Sensitive Data Collection):**
1. Canvas fingerprinting → SHA-256 hash
2. `chrome.storage.local` → User preferences, auth tokens
3. `chrome.tabs.query` → Active tab information
4. `navigator.userAgent` → Browser/OS fingerprinting
5. Extension version → Software versioning

**Sinks (External Transmission):**
1. `fetch(webapi.fobwifi.com)` - Primary backend (4 exfiltration flows detected)
2. `fetch(chrome.google.com)` - CWS review page (metadata leakage)

**ext-analyzer findings:**
- 4 HIGH-severity exfiltration flows detected
- 1 open message handler (validated sender, low risk)
- Code obfuscation present (webpack bundling)
- No WASM detected

---

## Recommendations

### For Users:
1. **Understand the privacy trade-off**: This extension collects extensive device and browsing metadata
2. **Review alternatives**: Consider VPN solutions with stronger privacy commitments
3. **Monitor permissions**: Be aware that all web traffic can be inspected by the extension
4. **Avoid incentivized reviews**: Do not leave reviews in exchange for VIP access

### For Developers:
1. **Reduce data collection**: Limit fingerprinting to authentication-required scenarios
2. **Implement transparency**: Provide clear privacy policy explaining all data collection
3. **Remove review incentives**: Eliminate VIP rewards for Chrome Web Store reviews (policy violation)
4. **Consider alternative authentication**: Use less invasive device identification methods
5. **Minimize permissions**: Scope host permissions to specific domains if possible

### For Chrome Web Store:
1. **Review manipulation violation**: Extension offers VIP benefits for reviews
2. **Privacy disclosure**: Verify privacy policy adequately discloses canvas fingerprinting
3. **Permission justification**: Broad host permissions should be reviewed

---

## Final Verdict

**Risk Level: MEDIUM**

Transocks is a functional VPN service with legitimate use cases for accessing geo-restricted Chinese content. However, it implements aggressive user tracking (canvas fingerprinting, metadata collection) and violates Chrome Web Store policies through review manipulation incentives.

The extension is **not malware** in the traditional sense - it provides the advertised VPN functionality. However, it collects more data than strictly necessary and employs tactics that reduce user privacy and marketplace integrity.

**Vulnerability Breakdown:**
- **Critical:** 0
- **High:** 2 (canvas fingerprinting, data exfiltration)
- **Medium:** 2 (encrypted comms, review manipulation)
- **Low:** 1 (eval in dead code)

**Recommended Action:** Flagged for review manipulation policy violation and privacy disclosure requirements.
