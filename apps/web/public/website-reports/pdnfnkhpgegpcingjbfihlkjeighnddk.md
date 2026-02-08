# Chrome Extension Security Analysis Report

## Extension Metadata

- **Extension Name:** Unblock Youku - 海外华人回国追剧听歌加速器 - 云界 VPN
- **Extension ID:** pdnfnkhpgegpcingjbfihlkjeighnddk
- **Version:** 6.1.4
- **User Count:** ~1,000,000 users
- **Manifest Version:** 3
- **Analysis Date:** 2026-02-08

## Executive Summary

Unblock Youku is a well-established geo-unblocking extension (originally open-source at github.com/Unblocker/Unblock-Youku) that enables users outside mainland China to access Chinese streaming services. The extension recently commercialized under the "Rift VPN" brand, adding Firebase authentication, tiered service (free/VIP), and subscription management.

**Overall Risk Level: CLEAN**

The extension exhibits standard VPN/proxy functionality with no malicious behavior. All suspicious patterns identified in automated triage are false positives from React library code and legitimate geo-unblocking DOM manipulation. The extension has transparent architecture, proper security controls, and limited data collection.

## Vulnerability Assessment

### CRITICAL Severity Issues
**Count: 0**

No critical vulnerabilities identified.

### HIGH Severity Issues
**Count: 0**

No high-severity vulnerabilities identified.

### MEDIUM Severity Issues
**Count: 0**

No medium-severity vulnerabilities identified.

### LOW Severity Issues
**Count: 1**

#### 1. Overly Broad Host Permissions

**Severity:** LOW
**Location:** `manifest.json` lines 25-28
**CWE:** CWE-250 (Execution with Unnecessary Privileges)

**Description:**
The extension requests broad host permissions (`http://*/*` and `https://*/*`) which exceed the principle of least privilege.

**Evidence:**
```json
"host_permissions": [
  "http://*/*",
  "https://*/*"
]
```

**Impact:**
While the extension only actively manipulates content on specific Chinese streaming domains and only proxies traffic matching PAC script rules, the broad permissions technically grant access to all websites.

**Mitigation:**
This is functionally justified because the PAC (Proxy Auto-Config) script needs to route traffic from hundreds of different Chinese streaming domains. The extension correctly filters actual functionality to specific domains via:
- Content scripts: Only injected on specific domains (manifest.json lines 46-93)
- PAC script: Only routes traffic matching specific URL patterns (background.iife.js)
- Header modification: Only applies to specific domains (background.iife.js, function `Si`)

**Verdict:** ACCEPTABLE - The broad permissions are necessary for the extension's core functionality. Actual usage is properly scoped.

## False Positive Analysis

All automated triage flags are false positives:

| Pattern | Location | Verdict | Explanation |
|---------|----------|---------|-------------|
| `innerHTML` usage | `content_scripts/unblockcn.js:12-25` | **FALSE POSITIVE** | User-protection feature that warns about malicious UnblockCN clone. Only runs on extension-related domains. |
| `innerHTML` usage | `content_scripts/tudou.js:10` | **FALSE POSITIVE** | Core geo-unblocking functionality - modifies `tvcCode` parameter on Tudou video player to bypass region checks. |
| `dangerouslySetInnerHTML` | `popup/assets/index-MzlFArbm.js` | **FALSE POSITIVE** | React 18 library internals for DOM reconciliation and SVG handling. Not custom code. |
| Keyboard event listeners | `popup/assets/index-MzlFArbm.js` | **FALSE POSITIVE** | React synthetic event system - standard library code, not a keylogger. |
| `querySelector` usage | `popup/assets/index-MzlFArbm.js` | **FALSE POSITIVE** | React DOM operations, CSS-in-JS (Ant Design), and Vite module preloading. Standard framework behavior. |

## API Endpoints Analysis

| Endpoint | Purpose | Data Transmitted | Risk Level |
|----------|---------|------------------|------------|
| `secure.unblockpro.app:8088` | HTTP proxy server | Proxied Chinese streaming traffic, auth credentials | LOW |
| `riftvpn.ai/*` | Account management | User login credentials, email, subscription status | LOW |
| `us-central1-anku-e1b04.cloudfunctions.net` | Firebase Cloud Functions | User UUID, skip queue requests, device management | LOW |
| `anku-e1b04.firebaseapp.com` | Firebase Authentication | Email/password, OAuth tokens (Google/Apple) | NONE |
| `www.google-analytics.com/mp/collect` | Analytics telemetry | User ID, VPN status, UI events, locale, session data | NONE |
| `www.googleapis.com` | Firebase Auth API | Auth tokens | NONE |
| `www.gstatic.com` | Firebase SDK | None - CDN only | NONE |
| `clients2.google.com` | Extension updates | Extension ID | NONE |
| `www.uku.im` | Landing page | None - opened on install | NONE |

### Cloud Functions Used:
1. **getProxyCredentials** - Issues temporary proxy credentials (username, password, expireTime)
2. **getAppLogin** - Checks subscription/login status
3. **resetUserDevice** - Removes registered devices from account

## Data Flow Summary

### Data Collection:
1. **User Authentication:**
   - Email/password or OAuth credentials (Google, Apple)
   - Stored in Firebase Authentication
   - Extension stores: user ID, email, tier (free/vip), referral code, account creation timestamp

2. **Device Tracking:**
   - Generates UUID on installation: `chrome.storage.sync.set({userUUID: randomUUID})`
   - Used for device management (max devices per account)

3. **Analytics Data:**
   - Google Analytics events: VPN connect/disconnect, login events, errors
   - Payload includes: user ID, tier, locale, session ID, engagement time
   - Counter tracking for event frequency in `chrome.storage.local`

4. **Proxy Credentials:**
   - Temporary credentials stored in `chrome.storage.local`
   - Format: `{username, password, expireTime}`
   - Auto-refresh every 1 minute via chrome.alarms

### Data Not Collected:
- Browsing history
- Visited URLs (except extension usage analytics)
- Page content or form data
- Cookies from user-visited sites
- Keystrokes or user input on web pages
- Screenshots or DOM snapshots

### Network Modification:
1. **Proxy Configuration:** PAC script routes only Chinese streaming domains through proxy
2. **Header Injection:** Adds `X-Forwarded-For` header with spoofed Chinese IP (`220.181.111.x`) to specific streaming APIs
3. **Cookie Cleanup:** Clears cookies only for proxy server origins (`secure.unblockpro.app`, `unblockpro.app`)

## Permissions Analysis

| Permission | Usage | Justification | Risk |
|------------|-------|---------------|------|
| `proxy` | Sets PAC script via `chrome.proxy.settings.set()` | Core VPN functionality | NONE |
| `storage` | Stores user state, credentials, preferences | Standard extension storage | NONE |
| `declarativeNetRequestWithHostAccess` | Injects X-Forwarded-For header | Geo-unblocking requirement | LOW |
| `alarms` | 1-minute interval for credential refresh | Prevents expired credentials | NONE |
| `webRequest` | Handles proxy auth challenges | Required for authenticated proxy | LOW |
| `webRequestAuthProvider` | Enables async blocking in onAuthRequired | Technical requirement | NONE |
| `browsingData` | Clears proxy-related cookies only | Credential hygiene | NONE |
| `host_permissions: *://*/*` | Enables PAC proxy on all sites | Broad but functionally necessary | LOW |

### Permission Verdict:
All permissions are justified for the extension's stated functionality. The broad host permissions are the only concern but are properly scoped in practice.

## Content Security Policy

```json
"content_security_policy": {
  "action": "default_popup allow-scripts; script-src 'self' https://www.gstatic.com/ https://*.firebaseio.com https://www.googleapis.com"
}
```

**Assessment:** SECURE - CSP restricts script loading to self and trusted Firebase/Google domains only. No unsafe-eval or unsafe-inline.

## Security Controls

### Positive Security Features:
1. **Scoped Proxy Authentication:** `webRequest.onAuthRequired` correctly filters to only respond to challenges from `secure.unblockpro.app`
2. **Externally Connectable Restriction:** Only `https://riftvpn.ai/*` can send external messages
3. **Content Script Isolation:** Scripts only run on specific Chinese streaming domains
4. **Firebase Security:** Uses standard Firebase Auth with proper token refresh
5. **No Dynamic Code Execution:** No `eval()`, `new Function()`, or remote script loading

### Security Weaknesses:
1. Proxy credentials stored in plaintext in `chrome.storage.local` (acceptable for VPN extensions)
2. API keys visible in source (Firebase public API keys - acceptable per Firebase documentation)
3. Google Analytics API secret in code (intentional for Measurement Protocol)

## Behavioral Analysis

### What the Extension DOES:
- Routes Chinese streaming domain traffic through proxy server
- Spoofs X-Forwarded-For header on specific streaming APIs
- Modifies DOM on specific streaming sites to bypass geo-checks
- Manages user authentication via Firebase
- Tracks VPN usage analytics via Google Analytics
- Displays warning about malicious UnblockCN clone

### What the Extension DOES NOT DO:
- Enumerate or disable other extensions
- Inject ads, affiliate links, or tracking pixels
- Harvest credentials, cookies, or form data from web pages
- Keylog or monitor user input
- Scrape page content or browsing history
- Intercept or modify web page network requests (XHR/fetch)
- Exfiltrate data to unknown third parties
- Use dynamic code evaluation (eval/Function)

## Open Source Heritage

The extension has transparent origins:
- Original repository: `github.com/Unblocker/Unblock-Youku`
- Documented fight against malicious clone at `github.com/Unblocker/malicious-unblockcn`
- Content script `unblockcn.js` references GitHub issues #468, #452, #589
- Recently commercialized with Rift VPN branding

## Code Architecture

### Background Service Worker (background.iife.js, 1590 lines):
- Firebase SDK (~70% of file)
- Proxy management (PAC script generation, credential handling)
- Authentication flow (email/password, Google OAuth, Apple OAuth)
- Google Analytics integration
- declarativeNetRequest rules for header modification

### Content Scripts (4 files, <50 lines each):
- `tudou.js` - Modifies Tudou player geo-check
- `play.baidu.js` - Removes isForeign flag on Baidu
- `music.163.js` - Sets GAbroad=false on NetEase Music
- `unblockcn.js` - Warning banner about malicious clone

### Popup UI:
- React 18 + Ant Design
- User login, VPN toggle, settings, referral system
- All UI interactions open riftvpn.ai for account management

### No Obfuscation:
Code is minified via Vite/Rollup but not obfuscated. Standard bundler output.

## Compliance Assessment

### Privacy Policy:
Not directly analyzed, but data collection is transparent:
- User account data (email, tier)
- VPN usage analytics
- Device UUID for multi-device management

### GDPR/Privacy Concerns:
- Minimal data collection
- No tracking of browsing behavior outside extension usage
- Analytics can be disabled by user (not collecting browsing history)

### Terms of Service:
Extension opens riftvpn.ai for registration/subscriptions. Pricing and terms hosted externally.

## Overall Risk Assessment

**Risk Level: CLEAN**

This extension is a legitimate geo-unblocking VPN with standard functionality for its category. All automated security flags are false positives from React library code and legitimate DOM manipulation for geo-unblocking.

### Risk Factors:
✓ Well-established open-source heritage
✓ Transparent architecture
✓ Limited data collection
✓ Standard Firebase/Google infrastructure
✓ No malicious patterns detected
✓ Proper security controls

### Minor Concerns:
- Broad host permissions (functionally justified)
- Proxy credentials in plaintext storage (standard for VPN extensions)
- Google Analytics tracking (standard practice, non-invasive)

### Recommendation:
**CLEAN - No security action required.** This extension can be safely used for its intended purpose of accessing Chinese streaming content from outside mainland China.

## Detailed Findings Reference

### Content Script Analysis:

**content_scripts/unblockcn.js** (26 lines):
```javascript
// Warning banner injected on unblockcn.com domains
document.body.innerHTML = '<div>Warning about malicious UnblockCN clone...</div>' + document.body.innerHTML;
```
Purpose: User protection against malicious competitor. Not a security risk.

**content_scripts/tudou.js** (14 lines):
```javascript
// Injects script to modify Tudou player geo-restriction
list[i].innerHTML = list[i].innerHTML.replace("tvcCode=5001", "tvcCode=-1");
```
Purpose: Core geo-unblocking functionality. Standard for this extension category.

**content_scripts/music.163.js** (11 lines):
```javascript
// Sets GAbroad=false on NetEase Music
window.GAbroad = window.contentFrame.GAbroad = false;
```
Purpose: Bypasses region check. Legitimate use case.

### Manifest Analysis:

**Externally Connectable:**
```json
"externally_connectable": {
  "matches": ["https://riftvpn.ai/*"]
}
```
Allows riftvpn.ai website to pass OAuth credentials after login. Properly scoped.

**Content Scripts Scope:**
- Only 4 specific domains (tudou.com, baidu.com, music.163.com, unblockcn.com)
- All scripts under 50 lines
- No wildcard content script injection

**Background Service Worker:**
- Single file: `background.iife.js`
- Mostly Firebase SDK code
- Clear separation of concerns

## Conclusion

Unblock Youku (Rift VPN) is a **CLEAN** extension with no security vulnerabilities or malicious behavior. It serves its stated purpose of geo-unblocking Chinese streaming services through standard VPN/proxy techniques. All automated security flags are false positives from legitimate library code.

The extension can be safely used by its target audience (Chinese diaspora accessing media from abroad).
