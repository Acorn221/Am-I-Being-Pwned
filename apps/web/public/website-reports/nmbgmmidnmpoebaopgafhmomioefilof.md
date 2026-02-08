# VPN Master - Security Analysis Report

## Extension Metadata

- **Extension Name**: VPN Master
- **Extension ID**: nmbgmmidnmpoebaopgafhmomioefilof
- **Version**: 2.3
- **User Count**: ~10,000
- **Rating**: 3.6/5
- **Analysis Date**: 2026-02-08

## Executive Summary

VPN Master is a free VPN browser extension that provides proxy functionality through the 1clickvpn.com infrastructure. While the extension delivers its core VPN functionality as advertised, it implements an **aggressive advertising monetization system** that intercepts user link clicks and redirects them through affiliate/advertising networks. The extension also collects extensive user data and phoning home behavior that raises privacy concerns.

**Overall Risk Level**: **MEDIUM**

The extension is not outright malicious, but the undisclosed click interception and affiliate redirect system constitutes deceptive behavior that users are unlikely to be aware of or consent to in an informed manner.

---

## Vulnerability Details

### 1. MEDIUM - Click Interception and Affiliate Link Injection

**Severity**: MEDIUM
**Category**: Ad Injection / Affiliate Fraud
**Files**: `js/ads.js`, `js/sw.js` (lines 2374-2438)

**Description**:
The extension injects a content script (`ads.js`) on all web pages that intercepts user clicks on links. When a user clicks on a link matching domains in a server-controlled whitelist, the extension:

1. Prevents the default navigation
2. Sends the URL to `https://data.trendcampaign.com/link/` to get an affiliate redirect URL
3. Redirects the user through an interstitial page (`goto.html`) showing a 3-second countdown
4. Completes the redirect to the affiliate URL

**Code Evidence** (`js/ads.js`):

```javascript
function y() {
  document.addEventListener("click", (t => {
    // ... click interception logic ...
    let c = m(o.hostname, n);
    c && (s[c] || (t.preventDefault(), p(i, c)))
  }), !1)
}

function p(t, e) {
  setTimeout((() => {
    t.dataset.ex_adv_fin || (t.dataset.ex_adv_fin = "1", t.click())
  }), 3e3), chrome.runtime.sendMessage({
    action: "check_ads_possibility",
    domain: e,
    target: t.getAttribute("target"),
    url: t.href
  }).then((e => {
    e || t.dataset.ex_adv_fin || (t.dataset.ex_adv_fin = "1", t.click())
  }))
}
```

**Background Service Worker** (`js/sw.js`):

```javascript
o = "https://data.trendcampaign.com/link/",

function h(t) {
  const r = f(t);
  return fetch(r, {
    signal: n
  })
  .then((t => t.json()))
  .then((t => {
    if (t && t.url) {
      const r = new URL(t.url);
      if (r.href) return l(r.href)
    }
    return null
  }))
}

chrome.runtime.onMessage.addListener(((t, r, n) => {
  if ("check_ads_possibility" === t.action && t.url) return h(t.url).then((e => {
    if (e && r && r.tab && r.tab.id) return u(t.domain), "_blank" === t.target ?
      chrome.tabs.create({ url: e }) :
      chrome.tabs.update(r.tab.id, { url: e }), void n(!0);
    n(!1)
  })), !0
}))
```

**Impact**:
- Users are unknowingly redirected through affiliate networks
- The interstitial delay (3 seconds) degrades user experience
- Potential revenue theft from legitimate website operators
- Violates user trust and informed consent principles

**Verdict**: This is deceptive monetization behavior. While users can opt-out via settings, the default behavior intercepts clicks without clear disclosure at install time.

---

### 2. MEDIUM - Extensive Data Collection and Remote Config

**Severity**: MEDIUM
**Category**: Data Exfiltration / Privacy
**Files**: `js/sw.js` (lines 2540-2596)

**Description**:
The extension collects and transmits extensive user data to `https://info.vpnbreeze.com/config.json` including:

- Extension version
- User identifier (generated pseudonymous ID)
- Proxy connection statistics (quality reports)
- Timestamp data
- IP address and geolocation information

**Code Evidence**:

```javascript
function A(t, r, n) {
  let e = n || {};
  return O(t).then((function(r) {
    return e.extension_version = chrome.runtime.getManifest().version,
           e[m().K] = $(t),
           e.user = r,
           e
  })).then((t => JSON.stringify(t)))
}

function w(t, r, n) {
  return A(t, r, n).then((t => k.Pt(m().Y, t))).then((function(t) {
    const n = Date.now(),
          e = t || {};
    return r || (e[m().D] = n), R(e)
  })).then((() => !0))
}

const C = {
  bt(t, r) {
    let n, e;
    const i = Date.now();
    return Promise.all([E("refresh_h"), E(m().D)]).then((function(o) {
      if ([n, e] = o, n = n || 6, t || P(e, n, i)) return w(i, t, r)
    })).catch((function(t) {}))
  }
}
```

**Remote Configuration**:
The extension fetches remote configuration from `https://info.vpnbreeze.com/config.json` which controls:
- Advertising domain whitelist (`advertising_domains_list`)
- Advertising blacklist (`advertising_black_list`)
- Feature toggles

**Impact**:
- User behavior tracking across sessions
- Remote control over advertising injection behavior
- Potential for malicious updates via remote config without extension update
- Privacy concerns for users expecting a simple VPN

**Verdict**: Excessive data collection for a VPN extension. Remote config capability allows operators to modify behavior post-install.

---

### 3. LOW - Overly Broad Host Permissions

**Severity**: LOW
**Category**: Excessive Permissions
**Files**: `manifest.json`

**Description**:
The extension requests `*://*/*` host permissions, granting access to all websites.

**Code Evidence**:

```json
"host_permissions": [
  "*://*/*"
]
```

**Impact**:
While this is typical for VPN extensions (needed for proxy functionality and content script injection), it grants the extension complete visibility into all user browsing activity.

**Verdict**: Necessary for VPN functionality but increases attack surface if extension is compromised.

---

### 4. LOW - Third-Party API Dependencies

**Severity**: LOW
**Category**: Supply Chain Risk
**Files**: `js/sw.js`

**Description**:
The extension relies on multiple third-party services for IP detection and authentication:

- `https://api.1clickvpn.com` - Proxy server authentication and registration
- `https://stats.1clickvpn.com` - Proxy quality statistics
- `https://ipinfo.io`, `https://ifconfig.co`, `https://api.myip.com`, `https://ipapi.co`, `https://ip.seeip.org` - IP geolocation services
- `https://data.trendcampaign.com` - Advertising affiliate network

**Impact**:
- Dependency on external services creates availability risks
- Compromise of third-party services could affect extension security
- User data exposed to multiple third parties

**Verdict**: Standard practice for VPN extensions but increases trust boundary.

---

## False Positives

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| `new Function("return this")()` | `js/sw.js:2467` | Webpack global detection polyfill (standard bundler pattern) | FP - Safe |
| `.innerHTML` usage | `js/popup.js`, `js/goto.js` | Used for UI rendering, not dynamic code execution | FP - Safe |
| CryptoJS library | `js/sw.js:397-1000+` | Standard AES encryption library for secure communication | FP - Safe |
| Proxy settings manipulation | `js/sw.js` | Core VPN functionality - expected behavior | FP - Expected |
| webRequest listener | `js/sw.js:2831` | Proxy authentication - required for VPN operation | FP - Expected |

---

## API Endpoints & External Services

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://api.1clickvpn.com/rest/v1/registrations/` | Anonymous user registration | Client app metadata, browser type | Medium |
| `https://api.1clickvpn.com/rest/v1/security/tokens/accs` | Access token retrieval | Authorization bearer token | Low |
| `https://api.1clickvpn.com/rest/v1/security/tokens/accs-proxy` | Proxy authentication token | Proxy signature, bearer token | Low |
| `https://stats.1clickvpn.com/api/rest/v2/entrypoints/countries` | Proxy server list retrieval | Authorization bearer token | Low |
| `https://info.vpnbreeze.com/config.json` | Remote configuration + telemetry | User ID, extension version, stats, IP info | Medium |
| `https://data.trendcampaign.com/link/` | Affiliate link generation | Subid, target URL | **High** |
| `https://ipinfo.io/`, `https://ifconfig.co/json`, etc. | IP geolocation detection | User IP address (implicit) | Low |

---

## Data Flow Summary

### User Data Collection:
1. **User Identifier**: Pseudonymous user ID generated and stored (`user` key in storage)
2. **Browsing Data**: Link clicks on whitelisted domains intercepted and logged
3. **Connection Metadata**: Proxy connection quality reports, timestamps
4. **IP/Location**: Real IP address and country code collected via third-party APIs
5. **Extension Metadata**: Version, browser type

### Data Transmission:
- **Primary Backend**: `info.vpnbreeze.com/config.json` - receives user ID, version, stats
- **Advertising Network**: `data.trendcampaign.com` - receives clicked URLs with tracking subid
- **Analytics**: Connection quality data sent to 1clickvpn.com infrastructure

### Remote Control:
- Advertising domain whitelist fetched from `info.vpnbreeze.com/config.json`
- Extension behavior can be modified via remote config without user consent

---

## Positive Security Features

1. **User Opt-Out**: Settings page allows users to disable advertising (though default is opt-in)
2. **Advertising Blacklist**: Excludes Google, Bing, Yahoo from click interception
3. **AES Encryption**: Uses CryptoJS for encrypted communication with backend
4. **Proxy Authentication**: Implements proper authentication for proxy connections
5. **No Keylogging**: Does not capture keystrokes or form inputs
6. **No Cookie Harvesting**: Does not extract cookies or session tokens
7. **No Extension Enumeration**: Does not detect or interfere with other extensions (verified)

---

## Recommendations

### For Users:
1. **Review Settings**: Immediately disable advertising in Options page
2. **Privacy Trade-off**: Understand that "free" VPN is monetized through affiliate redirects
3. **Consider Alternatives**: Evaluate paid VPN services with clearer privacy policies
4. **Monitor Behavior**: Watch for unexpected redirects when clicking links

### For Developers:
1. **Disclosure**: Clearly disclose affiliate redirect monetization at install time
2. **Opt-In Default**: Change default to require user consent for advertising
3. **Minimize Data**: Reduce telemetry collection to only essential metrics
4. **Transparency**: Publish clear privacy policy explaining data flows

---

## Overall Risk Assessment

**Risk Level**: **MEDIUM**

### Breakdown:
- **Malicious Intent**: Low - Extension provides functional VPN service
- **Deceptive Practices**: Medium-High - Click interception not clearly disclosed
- **Privacy Impact**: Medium - Extensive data collection and third-party sharing
- **Security Vulnerabilities**: Low - No critical security flaws identified
- **User Control**: Medium - Opt-out available but not default

### Rationale:
VPN Master is a functional VPN extension with aggressive monetization that crosses ethical boundaries. The click interception and affiliate redirect system is implemented in a way that most users will be unaware of, constituting deceptive behavior. However, the extension is not outright malware - it delivers VPN functionality, doesn't steal credentials, and provides opt-out mechanisms.

The extension requires invasive permissions appropriate for VPN functionality but uses them for advertising purposes beyond the core VPN feature. Users seeking a privacy-focused VPN should avoid this extension. Users willing to accept advertising in exchange for free VPN service should explicitly enable advertising after being informed, rather than having it enabled by default.

---

## Technical Notes

- **Manifest Version**: 3 (Modern Chrome extension architecture)
- **Build System**: Webpack bundled
- **Code Quality**: Heavily minified/obfuscated variable names but deobfuscated successfully
- **CSP**: Not explicitly defined (relies on default MV3 CSP)
- **Encryption**: CryptoJS library for AES encryption of proxy credentials
- **Persistence**: Uses both `chrome.storage.local` and `chrome.storage.sync`

---

**Report Generated**: 2026-02-08
**Analyst**: Security Research Agent (Claude Sonnet 4.5)
