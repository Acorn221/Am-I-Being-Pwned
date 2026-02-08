# Security Analysis Report: Total WebShield

## Extension Metadata
- **Extension Name**: Total WebShield: Chrome Antivirus Protection
- **Extension ID**: bobjajapamhdnbnimmaddcceeckkoiff
- **Version**: 3.3.0
- **User Count**: ~100,000
- **Developer**: Protected.net
- **Analysis Date**: 2026-02-07

## Executive Summary

Total WebShield is a legitimate commercial security extension developed by Protected.net (part of the TotalAV family of products). The extension provides web protection features including ad blocking, malware site blocking, tracking protection, and data breach monitoring. After comprehensive analysis, this extension shows **CLEAN** security posture with proper authentication, reasonable permissions usage, and legitimate functionality aligned with its stated purpose.

The extension implements privacy-focused features like referrer header removal, Do Not Track, and fingerprinting resistance (Firefox only). Cookie access is limited to authentication purposes with TotalAV services. No evidence of malicious data exfiltration, residential proxy infrastructure, or unauthorized tracking was found.

## Vulnerability Analysis

### 1. CLEAN - Legitimate Authentication Flow
**Severity**: INFORMATIONAL
**Files**: `app/background/background.min.js` (lines 4877-4896)
**Code**:
```javascript
autoLogin() {
  return new Promise((e => re(this, void 0, void 0, (function*() {
    yield C.X.log(Z.AUTO_SIGNUP, "Requesting LC cookies for primary and parent domains (using browser API)"),
    Promise.all(this.getAutoLoginCookieDomains().map((e => ee.get({
      name: "LC",
      url: e
    })))).then((t => re(this, void 0, void 0, (function*() {
      yield C.X.log(Z.AUTO_SIGNUP, "Request for login cookies succeeded", t);
      const r = t.find((e => e && e.value));
      if (!r) return yield C.X.log(Z.AUTO_SIGNUP, "No login cookies found."), e(null);
      yield C.X.log(Z.AUTO_SIGNUP, "Cookie found so attempting authentication.", r),
      u.L.authenticateWithCookie(r.value).then((t => re(this, void 0, void 0, (function*() {
        yield C.X.log(Z.AUTO_SIGNUP, "Successfully authed through API using cookie")
      }))))
    }))))
  }))))
}
```
**Verdict**: BENIGN - This is standard first-party authentication. The extension reads login cookies (named "LC") from TotalAV family domains (totalav.com, totalwebshield.com, etc.) to authenticate users. Cookies are only accessed from owned domains listed in `externally_connectable`, and authentication is performed against the vendor's own API endpoints. This is legitimate session management.

### 2. CLEAN - Privacy Protection Features
**Severity**: INFORMATIONAL
**Files**: `app/background/background.min.js` (lines 6310-6369)
**Code**:
```javascript
if (!0 === l && !1 === e.trackingProtection.enabled) {
  // Enable tracking protection
  t.trackingProtection.activeBaseRuleId = e, t.trackingProtection.enabled = !0
} else !1 === l && !0 === e.trackingProtection.enabled && {
  // Disable tracking protection
  i.push(e.trackingProtection.activeBaseRuleId),
  t.trackingProtection.activeBaseRuleId = null,
  t.trackingProtection.enabled = !1
}
// Also handles referrerProtection, resistFingerprinting features
```
**Verdict**: BENIGN - The extension implements legitimate privacy features including tracker blocking, referrer header removal, Do Not Track headers, and fingerprinting resistance (Firefox only). These are user-beneficial features consistent with a security/privacy product.

### 3. CLEAN - Search Results Enhancement
**Severity**: INFORMATIONAL
**Files**: `app/safe_results/safe_results.min.js` (lines 62-79)
**Code**:
```javascript
replaceSpinnerWithShieldIcon(e, t, s, n) {
  const l = r.s.getHostname(e.link.dataset.safe_results_url);
  e.iconContainer.dataset.safe_results_domain = l,
  n && (e.iconContainer.dataset.safe_results_category = n),
  e.iconContainer.innerHTML = this.getWebShieldIconHtml(t),
  e.iconContainer.addEventListener("click", (e => {
    e.preventDefault(), e.stopPropagation(),
    a.n.sendMessage(i.t.OPEN_SAFE_RESULTS_LANDER, {
      domain: l,
      category: n
    })
  }))
}
```
**Verdict**: BENIGN - The extension adds safety icons to search results on Google, Bing, Yahoo, etc. (as declared in manifest content_scripts). When clicked, it shows a safety report for the domain. The innerHTML usage here is controlled (only SVG icons generated internally) and doesn't pose XSS risks. This is legitimate search enhancement functionality.

### 4. CLEAN - Web Shield URL Checking
**Severity**: INFORMATIONAL
**Files**: `app/background/background.min.js` (lines 6080-6099)
**Code**:
```javascript
executeWebShieldEvent(e) {
  return new Promise((t => Ye(this, void 0, void 0, (function*() {
    const d = yield ae.c.getWebShieldResponse(l.s.stripPort(e.url));
    if (e.documentLifecycle === Re.PRERENDER) return s(), t();
    if (!d || "crypto" === d.key && !Ze.J.isBlockCryptominingSites() ||
        "low_trust" === d.key && !Ze.J.isBlockLowTrustSites()) return s(), t();
    // Block malicious sites
  }))))
}
```
**Verdict**: BENIGN - The extension checks URLs against a web shield service (likely TotalAV's reputation database) to identify crypto-mining sites, low-trust sites, and malware. This is the core functionality of an anti-malware browser extension. URL checking is done server-side through the vendor's API.

### 5. CLEAN - Ad Blocking Implementation
**Severity**: INFORMATIONAL
**Files**: `app/adblock_content/adblock_content.min.js` (lines 1066-2043)
**Code**:
```javascript
// Ad blocker uses standard techniques:
// - Element hiding via CSS
// - Script blocking via content scripts
// - Uses web_accessible_resources for redirect scripts
// - Standard filter list processing (filter_3.bin, filter_3.txt)
```
**Verdict**: BENIGN - The extension includes a comprehensive ad blocker using industry-standard techniques (similar to uBlock Origin/AdGuard). The web-accessible-resources directory contains standard redirect scripts for blocking fingerprinting (fingerprintjs2.js, fingerprintjs3.js), analytics (google-analytics.js), and ads (googlesyndication-adsbygoogle.js). Element picker and filter lists follow typical ad blocker architecture.

### 6. CLEAN - RPC Server for External Communication
**Severity**: INFORMATIONAL
**Files**: `app/background/background.min.js` (lines 48-74)
**Code**:
```javascript
t.RpcServer = class {
  constructor() {
    this.messageListeners = new s.MessageListeners,
    this.registerDefaultMessageListeners()
  }
  bootstrap() {
    a.RuntimeApi.onMessageExternal("*", ((e, t, r) => {
      const i = this.messageListeners.get(r);
      return Promise.race(i.map((r => r(e, t))))
    }))
  }
}
```
**Verdict**: BENIGN - The RPC server handles external messages from the domains listed in `externally_connectable` (totalav.com, totalwebshield.com, etc.). This allows the vendor's websites to check if the extension is installed and authenticate users. The listener for "is_installed" and "auth_with_token" are standard integration patterns. No arbitrary code execution or malicious message handling detected.

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML` usage | safe_results.min.js:64,72 | Controlled SVG icon generation - content is hardcoded SVG markup, not user input |
| `new Function()` | background.min.js:3389 | Part of bundled polyfill/promise library (likely from webpack/babel transforms), not dynamic code execution |
| Cookie access | background.min.js:4774-4780 | First-party authentication only - reading "LC" cookies from TotalAV family domains |
| `fetch()` calls | background.min.js:6051,7910 | Legitimate API calls to vendor services for URL reputation and user authentication |
| `postMessage` | background.min.js:1818-4701 | Standard message passing for extension architecture and React components |

## API Endpoints

| Endpoint Pattern | Purpose | Data Sent |
|------------------|---------|-----------|
| `https://www.totalav.com/*` | Authentication, user account | Cookies (LC), JWT tokens |
| `https://www.totalwebshield.com/*` | Product-specific features | User preferences, settings |
| `https://api.totalav.com/*` (inferred) | Web shield reputation, data breach | URLs (hashed/stripped), email addresses |
| `https://secure.totalav.com/*` (inferred) | Payment, subscription | User account data |
| `https://dashboard.totalav.com/*` | User dashboard | Session data |

Note: Specific API endpoints are referenced via utility functions like `a.o.getBrandDomain()` and `B.s.api()`, so exact URLs are constructed dynamically.

## Data Flow Summary

### Data Collection
1. **Authentication Data**: Login cookies (LC) from TotalAV domains, JWT tokens for session management
2. **Browsing Context**: URLs visited (for web shield scanning), search engine queries (for safe results feature)
3. **Extension State**: User preferences, feature enable/disable status, rating prompt dismissals
4. **Privacy Metrics**: Count of trackers blocked, DNT headers added, referrer headers removed (for internal metrics)

### Data Storage
- **chrome.storage.local**: User preferences, authentication tokens, feature settings
- **chrome.cookies**: Read-only access to first-party "LC" cookies for auto-login
- No evidence of localStorage/sessionStorage abuse

### Data Transmission
- All communication with TotalAV services (first-party)
- URL reputation checks (URLs sent to vendor's web shield API)
- Data breach monitoring (user email sent to vendor API)
- No third-party analytics, ad networks, or unauthorized tracking

### Privacy Controls
- Fingerprinting resistance (Firefox)
- Referrer header removal
- Do Not Track headers
- Tracker blocking via ad blocker
- User has control over all features via popup/settings

## Risk Assessment

### Overall Risk: **CLEAN**

**Justification**:
- Legitimate commercial product from established security vendor (Protected.net/TotalAV)
- Permissions aligned with stated functionality (web protection, ad blocking, privacy features)
- No evidence of unauthorized data collection, malicious behavior, or deceptive practices
- Cookie access limited to first-party authentication with owned domains
- Proper use of externally_connectable to restrict which websites can interact with extension
- Standard security extension architecture with URL reputation checking
- Privacy-enhancing features (tracking protection, referrer removal) work as advertised
- No residential proxy infrastructure, no extension enumeration, no market intelligence SDKs

**Security Strengths**:
- Manifest v3 (modern, more secure)
- Content Security Policy enforced
- Declarative Net Request for ad/tracker blocking
- Proper message validation in RPC server
- Auto-logout on 401 API responses
- Feature disabling on account expiry

**Minor Observations** (not vulnerabilities):
- Extensive permissions (alarms, scripting, contentSettings, cookies, privacy, storage, tabs, webRequest, declarativeNetRequest, webNavigation, `<all_urls>`) - justified for security/ad-blocking product
- Download protection feature monitors downloads (legitimate for anti-malware)
- Injects content scripts into all URLs (necessary for ad blocking and web protection)

## Conclusion

Total WebShield is a **CLEAN** extension. It is a legitimate commercial security product that implements web protection, ad blocking, tracking protection, and data breach monitoring. All functionality aligns with its stated purpose. No malicious code, unauthorized tracking, or privacy violations detected. The extension properly authenticates with vendor services, checks URL reputations for malware, and provides user-beneficial privacy features.

**Recommendation**: SAFE for users seeking an all-in-one security/privacy extension from TotalAV/Protected.net.
