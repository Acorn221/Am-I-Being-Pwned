# Security Analysis Report: ЮБуст - VPN для YouTube

## Metadata
- **Extension ID**: jddgbeighonaipjikdnfdpiefhoomlae
- **Extension Name**: ЮБуст - VPN для YouTube (YouBoost - VPN for YouTube)
- **Version**: 8.9.0
- **User Count**: ~2,000,000 users
- **Analysis Date**: 2026-02-08
- **Overall Risk**: MEDIUM

## Executive Summary

YouBoost (ЮБуст) is a free VPN service marketed to Russian-speaking users for unblocking YouTube content. The extension implements legitimate VPN proxy functionality but exhibits several concerning behaviors that warrant a MEDIUM risk rating:

**Key Concerns:**
1. **Extension Conflict Management**: Actively disables competing VPN/proxy extensions via `chrome.management.setEnabled()`
2. **Invasive Permissions**: Requests `<all_urls>` and extensive tracking permissions beyond YouTube scope
3. **Remote Configuration**: Fetches configuration from remote servers with fallback infrastructure
4. **Analytics & Tracking**: Sends extensive telemetry to Google Analytics and Sentry error tracking
5. **Ad/Content Injection**: Injects custom UI elements and potentially manipulates YouTube video playback

The extension serves its stated purpose (YouTube proxy) but uses aggressive tactics to maintain control and collects extensive usage data.

## Vulnerability Details

### HIGH SEVERITY

#### 1. Extension Enumeration & Disabling (HIGH)
**Severity**: HIGH
**File**: `background/service_worker.js` (lines 3255-3258, 9404)
**Category**: Extension Interference

**Description:**
The extension enumerates all installed extensions with `proxy` permissions and actively disables competing extensions when the user takes action in the popup.

**Evidence:**
```javascript
// Line 3255-3258: Enumerate proxy extensions
const n = (yield a.w.management.getAll()).filter(e => {
  var t;
  return e.id !== a.w.runtime.id && e.enabled &&
    (null === (t = e.permissions) || void 0 === t ? void 0 : t.includes("proxy"))
});

// Line 9404: Disable conflicting extension
yield r.w.management.setEnabled(n, !1),
yield(0, nn._)(),
yield(0, $.e)(C.E.ExtensionMonitoringUpdated, void 0)
```

**Impact:**
- Monitors for competing VPN/proxy extensions (internal list includes multiple VPN providers)
- Disables other extensions without clear opt-in from user
- Tracks conflicts via Google Analytics: `proxy_controlled_by_other_extension`, `vpn_extension_conflict`, `ad_blocker_conflict`
- Detects and monitors ad blockers (uBlock Origin, AdGuard, etc.)

**Verdict**: This is standard behavior for VPN extensions to prevent proxy conflicts, but the aggressive tracking and monitoring of ad blockers extends beyond legitimate conflict resolution.

---

#### 2. Extensive Data Collection & Exfiltration (HIGH)
**Severity**: HIGH
**File**: `background/service_worker.js` (lines 1947, 3111-3112)
**Category**: Privacy / Data Exfiltration

**Description:**
Extension sends extensive telemetry to multiple endpoints including Google Analytics with full measurement protocol.

**Evidence:**
```javascript
// Line 1947: Sentry error tracking
dsn: "https://c2f4bcd761ecf1d52eae25b1bb1c2b0c@sentry-ws-1.vpnn.space/2"

// Line 3111-3112: Google Analytics with full event tracking
yield fetch("https://www.google-analytics.com/mp/collect?measurement_id=G-XCPV2XK66M&api_secret=1zMpXYLcSSyNDx1wyIgUdQ", {
  method: "POST",
  body: JSON.stringify(o)
})
```

**Data Collected:**
- User actions and interactions (tab updates, server changes, premium status)
- Extension conflicts and installed extensions
- Device IDs and user IDs (persistent tracking)
- Tab URLs and browsing patterns on YouTube
- Error logs and stack traces (via Sentry)

**Verdict**: Extensive analytics beyond what's necessary for core VPN functionality. The GA measurement ID and API secret are hardcoded, enabling persistent cross-session tracking.

---

### MEDIUM SEVERITY

#### 3. Remote Configuration & Kill Switch (MEDIUM)
**Severity**: MEDIUM
**File**: `background/service_worker.js` (lines 1017, 1036-1037, 2294)
**Category**: Remote Configuration

**Description:**
Extension fetches configuration from remote servers with automatic fallback mechanism. Configuration controls proxy behavior, ad injection timing, and feature flags.

**Evidence:**
```javascript
// Primary: Google Cloud Storage
n.startsWith("https://storage.googleapis.com/") && t && (n = n.replace("https://storage.googleapis.com/", t))

// Fallback to Yandex Cloud
yield(0, u.lR)({
  [c.U.ConfigsBaseUrl]: "https://storage.yandexcloud.net/vpnn-web-configs/"
})

// Fetches script registry
const n = t ? "uboost/pca-scripts-registry-google-test.json" : "uboost/pca-scripts-registry-google.json"
```

**Remote Endpoints:**
- `storage.googleapis.com` (primary)
- `storage.yandexcloud.net/vpnn-web-configs/` (fallback)
- `sentry-ws-1.vpnn.space` (error tracking)
- `vpnn.loan` (backup infrastructure)
- `uboost.space`, `ubst.space`, `cukubst.top` (service domains)

**Impact:**
- Developer can push configuration updates to change behavior
- No code signing or integrity verification observed
- Potential for feature flags to enable/disable functionality remotely

**Verdict**: Standard practice for VPN services but creates dependency on remote infrastructure with multiple backup domains suggesting resilience against takedowns.

---

#### 4. YouTube Content Manipulation & Ad Injection (MEDIUM)
**Severity**: MEDIUM
**File**: `content_scripts/content-7.js`, `scripts/adRollsInPage.js`, multiple content scripts
**Category**: Content Injection

**Description:**
Extension injects multiple content scripts into YouTube pages and manipulates video player behavior. Script `adRollsInPage.js` creates a message-passing API to control YouTube player.

**Evidence:**
```javascript
// adRollsInPage.js: YouTube API wrapper
window.addEventListener("message", o => {
  const d = o.data;
  if (!(o => o && o.source === e && "YT_METHOD_CALL" === o.type &&
    ("pauseVideo" === o.method || "playVideo" === o.method || "getPlayerState" === o.method))(d)) return;
  const n = document.getElementById("movie_player");
  n[t](); // Call player method
})
```

**Injected Content:**
- 12 content scripts on YouTube (`content-0.js` through `content-11.js`)
- Web-accessible resources for custom UI (fonts, images, cross icon)
- Message-passing system to control video playback
- Ad banner system controlled by alarms (`ShowAdPremiumBanner`, `ShowMidRoll`)
- Custom UI elements injected on Yandex search results (`content-11.js`)

**Impact:**
- Can pause/play videos programmatically
- Injects premium upgrade banners periodically
- May inject mid-roll content (timing controlled by remote config)
- Modifies YouTube UI without clear disclosure

**Verdict**: Goes beyond simple proxy functionality. The ad injection and player control mechanisms are concerning but appear limited to self-promotion rather than third-party ads.

---

#### 5. Cookie & Storage Access Across All URLs (MEDIUM)
**Severity**: MEDIUM
**File**: `manifest.json`, `background/service_worker.js` (lines 2165-2181)
**Category**: Privacy / Cookie Harvesting

**Description:**
Extension requests `cookies` permission with `<all_urls>` host permission, enabling access to cookies from any website. Background script actively reads/writes cookies.

**Evidence:**
```javascript
// Line 2165-2167: Set cookie on arbitrary domain
yield r.w.cookies.set(u({
  url: `https://${t}`,
  name: e,
  // ...
}))

// Line 2179-2181: Read cookie from arbitrary domain
const n = yield r.w.cookies.get({
  url: `https://${t}`,
  name: e
})
```

**Permissions:**
- `cookies` permission
- `<all_urls>` host permission
- `storage` permission (local/sync)

**Impact:**
- Can read/write cookies on any website (not just YouTube)
- Persistent storage for user tracking
- No evidence of actual cross-site cookie harvesting, but capability exists

**Verdict**: Excessive permissions for stated functionality. VPN for YouTube should not need cookie access to all websites.

---

### LOW SEVERITY (Not Flagged)

#### Premium Trial System
The extension implements a trial system checking with backend API (`https://${e}/api/v2/check-trial`). This is standard freemium behavior.

#### Proxy Authentication
Standard proxy authentication using `chrome.webRequest.onAuthRequired` with credentials stored in extension storage. This is legitimate VPN functionality.

#### Alarm-based Scheduling
Uses Chrome alarms API for periodic tasks (banner display, server rotation). Standard extension practice.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `eval()` matches | All content scripts | False positive - matched on `.getFullYear()`, `.valueOf()`, etc. (legitimate Date methods) |
| React `dangerouslySetInnerHTML` | `content-7.js` line 171 | Standard React pattern for rendering HTML - part of framework |
| Sentry SDK hooks | Throughout | Legitimate error tracking service integration |
| `Function.prototype.bind.call` | `content-7.js` line 26 | Standard polyfill pattern, not dynamic code execution |
| IndexedDB/localStorage | Multiple files | Standard browser storage APIs for extension state |

---

## API Endpoints & External Communications

### Backend Services
| Endpoint | Purpose | Risk |
|----------|---------|------|
| `storage.googleapis.com` | Remote configuration (primary) | Medium - Remote control |
| `storage.yandexcloud.net/vpnn-web-configs/` | Remote configuration (fallback) | Medium - Backup infrastructure |
| `sentry-ws-1.vpnn.space` | Error tracking | Low - Standard telemetry |
| `www.google-analytics.com/mp/collect` | User analytics | High - Extensive tracking |
| `vpnn.loan`, `vpnn.space` | Service domains | Medium - Multiple backup domains |
| `uboost.space`, `ubst.space` | Service domains | Low - Main service infrastructure |

### Chrome APIs Used
- `chrome.management.getAll()` - Enumerate extensions
- `chrome.management.setEnabled()` - Disable other extensions
- `chrome.proxy.settings` - Configure proxy (legitimate VPN use)
- `chrome.webRequest.onAuthRequired` - Proxy authentication
- `chrome.cookies.get/set()` - Cookie manipulation
- `chrome.tabs.*` - Tab tracking and manipulation
- `chrome.alarms.*` - Scheduled tasks

---

## Data Flow Summary

```
User Browser
    ↓
[YouBoost Extension]
    ↓
    ├─→ Google Analytics (user_id, device_id, actions, conflicts)
    ├─→ Sentry (errors, stack traces, URLs)
    ├─→ Google Cloud Storage (config fetch)
    ├─→ Yandex Cloud (config fetch - fallback)
    └─→ VPN Proxy Servers (legitimate traffic routing)

Content Scripts:
    ↓
YouTube Pages (12 content scripts)
    ├─→ Video player manipulation
    ├─→ UI injection (banners, premium prompts)
    └─→ Tab/URL tracking → Background → Analytics

Extension Monitoring:
    ↓
chrome.management.getAll() → List of installed extensions
    └─→ Track VPN/proxy/ad-blocker conflicts → Google Analytics
```

---

## Overall Risk Assessment: MEDIUM

### Rationale for MEDIUM (not HIGH):
1. **Serves Stated Purpose**: The extension does provide YouTube unblocking via VPN proxy, which is its advertised function
2. **No Clear Malware**: No evidence of credential theft, cryptocurrency mining, or third-party ad injection beyond self-promotion
3. **Aggressive but Not Malicious**: Extension conflict management and tracking are aggressive but within bounds of competitive VPN market
4. **Transparent Infrastructure**: Uses well-known services (Google Cloud, Sentry) rather than completely opaque infrastructure

### Concerning Aspects:
1. **Excessive Permissions**: `<all_urls>` and `cookies` permission exceed what's needed for YouTube-only VPN
2. **Extension Disabling**: Automatically disables competing extensions (though this is VPN-standard behavior)
3. **Extensive Tracking**: Sends detailed usage data to Google Analytics including extension conflicts and user behavior
4. **Remote Control**: Configuration fetched from remote servers could change behavior without extension update
5. **Ad Injection**: Injects content and manipulates video playback beyond core proxy functionality

### Recommendation:
**MEDIUM Risk** - The extension is more invasive than necessary but serves its stated purpose. Users should be aware that:
- Their YouTube usage is tracked and sent to analytics
- Other VPN/proxy extensions may be automatically disabled
- The extension can inject content and control video playback
- Cookies can be accessed across all websites (not just YouTube)

For privacy-conscious users or enterprise environments, the extensive tracking and broad permissions warrant caution. For general users seeking YouTube unblocking in regions with censorship, the core functionality works as advertised despite the concerning privacy implications.
