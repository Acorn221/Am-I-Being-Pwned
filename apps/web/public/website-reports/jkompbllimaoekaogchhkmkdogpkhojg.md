# Security Analysis Report: DS Amazon Quick View

## Extension Metadata
- **Extension ID**: jkompbllimaoekaogchhkmkdogpkhojg
- **Extension Name**: DS Amazon Quick View
- **Version**: 3.3.35
- **Estimated Users**: ~600,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

**Overall Risk Level: CLEAN**

DS Amazon Quick View is a legitimate utility extension for Amazon sellers and shoppers that displays product ranking, Best Seller Rank (BSR), and seller information directly on Amazon search results and category pages. The extension operates transparently, with no malicious behavior detected. Its primary functionality involves scraping public Amazon product pages to extract and display ranking information inline, along with legitimate affiliate marketing through promotional notifications.

**Key Findings:**
- ✅ Minimal permissions (storage + Amazon host permissions only)
- ✅ No extension enumeration or killing behavior
- ✅ No XHR/fetch hooking or monkey-patching
- ✅ No data exfiltration or telemetry to third-party servers
- ✅ No keyloggers, credential harvesting, or cookie theft
- ✅ Legitimate scraping of public Amazon data only
- ⚠️ In-extension affiliate promotions (transparent, user-controllable)
- ⚠️ A/B testing for promotional messages (privacy-neutral)
- ⚠️ Fetch with credentials:include for Amazon requests (necessary for functionality)

## Manifest Analysis

### Permissions
```json
"permissions": ["storage"]
"host_permissions": [
  "*://*.amazon.com/*",
  "*://*.amazon.co.uk/*"
]
```

**Assessment**: Minimal and appropriate permissions. Only requests storage (for settings) and access to Amazon domains where it operates.

### Content Security Policy
```json
"content_security_policy": {}
```

**Assessment**: Empty CSP (defaults to Manifest V3 defaults which are strict). No dynamic code execution vectors.

### Content Scripts
Two content scripts injected on Amazon.com/co.uk:
1. **content-script-0.js** (with jQuery) - Main functionality for rank display and product data extraction
2. **content-script-1.js** - Captcha detection helper for iframes

**Assessment**: Appropriately scoped to Amazon domains only.

### Background Service Worker
**sw_background.js** - Minimal wrapper that imports background.js

**Assessment**: Standard Manifest V3 pattern.

## Vulnerability Analysis

### 1. Amazon Product Data Scraping
**Severity**: CLEAN
**Files**: js/content-script-0.js (lines 248-529), js/background.js (lines 165-193)

**Behavior**:
The extension scrapes public Amazon product pages to extract:
- Best Seller Rank (BSR) from product detail pages
- Sub-category rankings
- FBA seller information from offer listing pages
- Product ASIN identifiers
- Seller names and fulfillment methods

**Technical Implementation**:
```javascript
// Background.js - Fetch with credentials to maintain Amazon session
fetch(e, {
  method: "GET",
  mode: "cors",
  credentials: "include"  // Lines 168-169
}).then(...)
```

Content script sends URLs to background worker via TaskManager queue, which fetches HTML and returns it for parsing. The extension uses `credentials: "include"` to maintain the user's Amazon session state, which is necessary to see the same product information the user would see (pricing, availability, seller options).

**Verdict**: ✅ **CLEAN** - This is legitimate functionality. The extension:
- Only scrapes public product information visible to the logged-in user
- Does not exfiltrate data to external servers
- Uses credentials only for Amazon requests (necessary for captcha handling and accurate product data)
- Parses HTML locally in content script context

### 2. Captcha Detection and Handling
**Severity**: CLEAN
**Files**: js/content-script-0.js (lines 1-40), js/content-script-1.js (entire file)

**Behavior**:
When Amazon returns a captcha page (rate limiting), the extension:
1. Detects captcha HTML (`validateCaptcha` string or `#captchacharacters` element)
2. Displays an iframe overlay with the captcha page
3. Pauses the TaskManager queue
4. Uses postMessage between frames to coordinate captcha detection

**Code Analysis**:
```javascript
// content-script-1.js - Cross-frame captcha detection
window.parent !== window && (Captcha.find() ?
  window.parent.postMessage({
    cmd: "xtaqv.captcha_reveal",
    data: ""
  }, "*") : // Lines 41-46
  chrome.runtime.sendMessage({cmd: "captcha.resolved"})
);
```

**Verdict**: ✅ **CLEAN** - The postMessage usage is narrowly scoped to captcha coordination. The wildcard target origin (`"*"`) is acceptable here since:
- Messages only contain command strings, no sensitive data
- The iframe src is always an Amazon captcha URL
- This is a standard pattern for iframe-parent coordination

### 3. Affiliate Marketing Promotions
**Severity**: LOW (Transparent)
**Files**: js/content-script-0.js (lines 42-143), js/popup.js, html/popup.html

**Behavior**:
The extension displays in-page promotional notifications for:
- Chrome Web Store reviews ("storervw" notification)
- RevSeller tool (FBA calculator) with referral code DS20
- Developer's other extensions

**Promotional URLs**:
- `https://www.revseller.com/32851/304.html` (RevSeller affiliate link)
- `https://crushtrk.com/?a=1344&c=7&p=r&s1=` (Helium10 affiliate - commented out)
- `https://chrome.google.com/webstore/detail/ilpimgbmpmhfhdaaeepjokoigelkfbee` (Premium version upsell)
- `https://chrome.google.com/webstore/detail/cmjihoeplpkmlmbbiiognkceoechmand` (Online Seller Addon)

**A/B Testing**:
```javascript
// background.js - Generate random A/B bucket (1-100)
void 0 === a.ab && (a.ab = Math.ceil(100 * Math.random())) // Line 71
```

Notifications are gated by visit count and A/B test bucket to vary promotional content.

**Verdict**: ⚠️ **ACCEPTABLE** - Affiliate marketing is:
- Transparent (clearly labeled as promotions)
- User-controllable (dismissible, "remind me later" options)
- Privacy-neutral (no external tracking pixels or beacons)
- Limited frequency (5-day delay between notifications: `432e5` ms = 120 hours)

### 4. Analytics Event Tracking
**Severity**: CLEAN
**Files**: js/content-script-0.js (lines 107-112), js/popup.js (lines 30-36)

**Behavior**:
The extension sends analytics events when users click promotional links:
```javascript
chrome.runtime.sendMessage({
  cmd: "cpa.sendEvent",
  data: ["click", e]
})
```

**Verdict**: ✅ **CLEAN** - The "cpa.sendEvent" message handler is **not implemented** in background.js. These are phantom analytics calls that do nothing. No external analytics service is loaded or contacted.

### 5. Session and Visit Tracking
**Severity**: CLEAN
**Files**: js/background.js (lines 212-231)

**Behavior**:
Local-only session tracking for notification frequency control:
```javascript
Session = {
  init: function() {
    chrome.storage.local.get("sessionStorage", function(s) {
      n.visit && (e = parseInt(n.visit), t = parseInt(n.visitTimestamp))
      // Increment visit count after 5 days
      Date.now() - t > 432e5 && (t = Date.now(), e++, a())
    })
  }
}
```

**Verdict**: ✅ **CLEAN** - All storage is local (chrome.storage.local). No data leaves the browser.

### 6. CamelCamelCamel Integration
**Severity**: CLEAN
**Files**: js/content-script-0.js (lines 350-356, 514-518)

**Behavior**:
The extension generates CamelCamelCamel price history URLs (third-party price tracker):
```javascript
var a = "http://" + T() + ".camelcamelcamel.com/product/" + e;
```

**Verdict**: ✅ **CLEAN** - Links are only generated for display. No automatic requests to CamelCamelCamel. User must click to visit. The free version shows placeholder images instead of actual charts and promotes the premium version.

## False Positive Analysis

| Pattern | Context | Verdict |
|---------|---------|---------|
| `innerHTML` usage | HTML generation for rank display (lines 315, 355, 470-512) | ✅ FP - All innerHTML sources are locally generated strings, not external data |
| `fetch` with `credentials: "include"` | Amazon product page fetching (lines 168-169) | ✅ FP - Necessary to maintain Amazon session for accurate product data |
| `postMessage` with wildcard origin | Captcha iframe coordination (line 41) | ✅ FP - No sensitive data transmitted, standard iframe pattern |
| Analytics event tracking | "cpa.sendEvent" messages (lines 33, 110) | ✅ FP - Handler not implemented, no actual tracking occurs |
| A/B testing | Random bucket assignment (line 71) | ✅ FP - Local only, no external service integration |

## API Endpoints and External Connections

| Domain | Purpose | Risk Level |
|--------|---------|------------|
| `*.amazon.com` | Product page scraping (user-initiated) | ✅ CLEAN |
| `*.amazon.co.uk` | Product page scraping (user-initiated) | ✅ CLEAN |
| `camelcamelcamel.com` | Price history links (never auto-fetched) | ✅ CLEAN |
| `revseller.com` | Affiliate promotion link | ⚠️ LOW |
| `crushtrk.com` | Affiliate promotion link (commented out) | ⚠️ LOW |
| `chrome.google.com/webstore` | Extension upsells and reviews | ✅ CLEAN |

**No data exfiltration detected.** All external connections are user-initiated link clicks or Amazon page scraping.

## Data Flow Summary

### Data Collected
1. **Amazon ASINs**: Extracted from product listings (never sent externally)
2. **User settings**: Stored locally (showExtInfo, hideSubrank, hidePremium, etc.)
3. **Visit count**: Local session tracking for notification frequency
4. **A/B bucket**: Random 1-100 number for notification variants

### Data Storage
- **chrome.storage.local**: All settings, session data, notification dismissal states
- **No external storage**: No databases, no remote APIs

### Data Transmission
- **None**: Extension does not transmit any data to external servers
- **Amazon requests**: Only fetch public product pages using user's existing session

## Chrome API Usage

| API | Usage | Risk |
|-----|-------|------|
| `chrome.storage.local` | Settings and session persistence | ✅ LOW |
| `chrome.runtime.sendMessage` | Internal content↔background messaging | ✅ LOW |
| `chrome.tabs.sendMessage` | Background→content messaging | ✅ LOW |
| `chrome.tabs.create` | Open welcome page on install | ✅ LOW |
| `chrome.tabs.query` | Broadcast settings updates | ✅ LOW |
| `chrome.action.setIcon` | Toggle on/off icon state | ✅ LOW |
| `chrome.runtime.getURL` | Load extension resources | ✅ LOW |

**No sensitive APIs**: No access to chrome.management, chrome.cookies, chrome.webRequest, chrome.downloads, chrome.history, or chrome.webNavigation.

## Malicious Pattern Check

| Malicious Pattern | Detected? | Evidence |
|-------------------|-----------|----------|
| Extension enumeration/killing | ❌ NO | No chrome.management API |
| XHR/fetch hooking | ❌ NO | No prototype manipulation |
| Residential proxy infrastructure | ❌ NO | No proxy logic |
| Remote config/kill switches | ❌ NO | No external config fetching |
| Market intelligence SDKs | ❌ NO | No Sensor Tower, Pathmatics, etc. |
| AI conversation scraping | ❌ NO | Only operates on Amazon domains |
| Ad/coupon injection | ❌ NO | No DOM manipulation for ads |
| Obfuscation | ❌ NO | Code is readable (variable minification only) |
| Dynamic code execution | ❌ NO | No eval(), Function(), or CSP bypasses |
| Keylogging | ❌ NO | No keyboard event listeners |
| Cookie harvesting | ❌ NO | No cookie access |
| Credential theft | ❌ NO | No form interception |
| History tracking | ❌ NO | No navigation monitoring |
| Screenshot capture | ❌ NO | No tabs.captureVisibleTab |

## Security Recommendations

### For Users
1. ✅ **Safe to use** - No security concerns detected
2. Be aware that promotional notifications will appear (dismissible, configurable)
3. Promotional links contain affiliate referral codes (standard practice)
4. Premium version (paid) available if you want additional features

### For Developers
1. Consider implementing CSP explicitly rather than relying on defaults
2. Remove phantom analytics calls ("cpa.sendEvent") if not used
3. Consider making promotional frequency more transparent in settings
4. The A/B testing could be documented in privacy policy

### For Researchers
This extension is a good example of:
- Legitimate web scraping for utility purposes
- Transparent affiliate marketing integration
- Clean Manifest V3 implementation
- Appropriate permission scoping

## Conclusion

**Final Verdict: CLEAN**

DS Amazon Quick View is a legitimate, well-implemented extension for Amazon sellers and shoppers. It provides genuine utility by displaying product ranking information inline on Amazon pages. The extension:

- Uses minimal permissions appropriately
- Operates transparently with no deceptive behavior
- Contains no malware, spyware, or data exfiltration
- Implements standard affiliate marketing in a user-friendly way
- Respects user privacy (all data stays local)
- Has no extension killing, hooking, or malicious patterns

The promotional notifications are the only potentially annoying aspect, but they are:
- Clearly labeled
- Easily dismissed
- Frequency-limited (5-day intervals)
- Configurable (can hide premium upsells)
- Privacy-neutral (no external tracking)

This extension poses no security risk and operates as advertised.

---

**Analyst Notes**: This extension stands in stark contrast to the malicious VPN extensions analyzed previously (Urban VPN, StayFree, StayFocusd, etc.). It demonstrates what a clean, utility-focused extension looks like: narrow permission scope, transparent operation, local-only data storage, and no hooking/hijacking behavior. The affiliate marketing, while commercial, is implemented ethically and transparently.
