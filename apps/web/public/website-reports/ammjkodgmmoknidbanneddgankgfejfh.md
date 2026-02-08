# Security Analysis Report: 7TV

## Extension Metadata
- **Name**: 7TV
- **Extension ID**: ammjkodgmmoknidbanneddgankgfejfh
- **Version**: 3.1.14
- **User Count**: ~3,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

7TV is a legitimate browser extension that enhances Twitch, YouTube, and Kick streaming platforms with custom emotes, cosmetics, and additional features. The extension demonstrates professional development practices with proper permission handling, minimal required permissions, and clear intended functionality. No malicious behavior, privacy violations, or significant security vulnerabilities were identified during analysis.

**Overall Risk Assessment**: **CLEAN**

The extension uses optional permissions appropriately, connects to legitimate 7TV and third-party emote APIs, and implements standard messaging patterns without suspicious data collection or malicious code patterns.

## Vulnerability Assessment

### No Critical or High-Severity Issues Identified

After comprehensive analysis of background scripts, content scripts, worker files, and 62 asset modules, no exploitable vulnerabilities or malicious patterns were found.

## Detailed Findings

### 1. Manifest Permissions & CSP Analysis

**Permissions Requested**:
- `scripting` - For injecting site enhancement scripts
- `storage` - For storing user settings and emote cache
- `activeTab` - For interacting with the current tab

**Optional Permissions** (user-granted):
- `management` - For detecting conflicts with other extensions (benign use)
- Optional host permissions: `*.youtube.com/*`, `*.kick.com/*`, `*.7tv.app/*`, `*.7tv.io/*`

**Host Permissions**:
- `*://*.twitch.tv/*` - Primary platform integration

**Verdict**: Permission model is minimal and appropriate. The use of optional permissions demonstrates good security hygiene by requesting additional access only when needed. The `management` permission is used for extension compatibility checking, not malicious enumeration.

**File**: `manifest.json`

### 2. Background Script Analysis

**File**: `background.js` (78KB)

**Key Functionality**:
- Permission request handling via `chrome.permissions.request()`
- Extension update checking via `chrome.runtime.requestUpdateCheck()`
- Message passing to content scripts for coordinating updates and settings sync
- IndexedDB schema management using Dexie.js (version 2.4-2.6)

**IndexedDB Schema** (stores emote and user data):
```javascript
{
  channels: "id,timestamp",
  emoteSets: "id,timestamp,priority,provider,scope",
  emotes: "id,timestamp,name,owner.id",
  cosmetics: "id,timestamp,kind",
  entitlements: "id,scope,timestamp,user_id,platform_id",
  settings: "key"
}
```

**Message Types Handled**:
- `permission-request` - Prompts user for optional permissions
- `update-check` - Checks for extension updates
- `update-ready` - Broadcasts to tabs when update available
- `settings-sync` - Synchronizes settings across tabs

**Verdict**: Clean implementation. No suspicious network calls, no data exfiltration, no dynamic code execution. Permission requests properly prompt the user.

### 3. Content Script Analysis

**File**: `content.js` (2.1KB, minified)

**Key Functionality**:
- Injects `site.js` module into Twitch pages
- Creates a BroadcastChannel (`seventv-app-broadcast-channel`) for cross-context communication
- Loads emoji SVG assets from extension package
- Injects stylesheet for 7TV UI elements
- Relays permission requests and update checks between page and background script

**DOM Manipulation**:
- Creates hidden emoji container div (SVG assets for rendering)
- Injects script tag with `worker_url` and `extension_origin` attributes
- Uses `innerHTML` only for loading SVG content (not user-controlled)

**Message Flow**:
```
Page Context ←→ BroadcastChannel ←→ Content Script ←→ Background Script
```

**Verdict**: Standard content script architecture. No keylogging, no cookie harvesting, no malicious DOM manipulation. The `innerHTML` usage is for static emoji SVGs loaded from the extension package, not user input.

### 4. Worker & Site Scripts

**File**: `worker.js` (125KB) and `site.js` (1.1KB entry point)

**Key Functionality**:
- Vite-bundled application modules (62 asset files)
- Dexie.js IndexedDB wrapper for local emote caching
- WebSocket connection to `wss://events.7tv.io/v3` for real-time emote updates
- Integration with third-party emote platforms:
  - 7TV API: `https://7tv.io/v3`
  - BetterTTV API: `https://api.betterttv.net/3`
  - FrankerFaceZ API: `https://api.frankerfacez.com/v1`

**Data Storage**:
- Local caching of emotes, cosmetics, user settings
- No sensitive data collection
- No authentication tokens stored insecurely

**Verdict**: Legitimate emote platform integration. WebSocket used for real-time emote subscription updates, consistent with the extension's stated purpose.

### 5. Network Communication Analysis

**API Endpoints**:

| Endpoint | Purpose | Data Sent | Verdict |
|----------|---------|-----------|---------|
| `https://7tv.io/v3` | Fetch 7TV emotes and cosmetics | User/channel IDs | Legitimate |
| `wss://events.7tv.io/v3` | Real-time emote updates | Subscription messages | Legitimate |
| `https://api.betterttv.net/3` | Fetch BTTV emotes | Channel/user queries | Legitimate |
| `https://api.frankerfacez.com/v1` | Fetch FFZ emotes | Channel/user queries | Legitimate |

**Verdict**: All network communication is consistent with emote platform functionality. No data exfiltration, no tracking pixels, no advertising SDKs detected.

### 6. Security Pattern Analysis

**Checked For** (Results: None Found):
- ✅ No `eval()`, `Function()`, or dynamic code execution
- ✅ No keyloggers or input monitoring
- ✅ No cookie or localStorage harvesting beyond extension settings
- ✅ No XHR/fetch hooking or traffic interception
- ✅ No extension enumeration or killing (management permission used benignly)
- ✅ No residential proxy infrastructure
- ✅ No remote config/kill switches
- ✅ No ad/coupon injection
- ✅ No AI conversation scraping
- ✅ No market intelligence SDKs (Sensor Tower, Pathmatics, etc.)
- ✅ No obfuscation beyond standard minification

### 7. False Positives Table

| Pattern | File | Explanation |
|---------|------|-------------|
| `innerHTML` usage | `content.js` | Loading static SVG emoji assets from extension package, not user input |
| Dexie.js IndexedDB wrapper | `background.js`, `worker.js` | Standard database library for emote caching |
| BroadcastChannel messaging | `content.js` | Standard cross-context communication pattern |
| Optional `management` permission | `manifest.json` | Used for detecting extension conflicts, not enumeration |

## Data Flow Summary

```
User visits Twitch/YouTube/Kick
    ↓
Content script injects site.js
    ↓
Site.js loads worker.js (emote engine)
    ↓
Worker fetches emotes from 7TV/BTTV/FFZ APIs
    ↓
Emotes cached in IndexedDB
    ↓
WebSocket subscribes to real-time updates
    ↓
Emotes rendered in chat UI
```

**Privacy Considerations**:
- Channel/user IDs are sent to emote APIs (necessary for functionality)
- No PII collection beyond platform usernames (public information)
- Settings stored locally via chrome.storage
- WebSocket connection for real-time features (disclosed functionality)

## Code Quality & Security Hygiene

**Positive Indicators**:
- Manifest V3 compliance (modern security model)
- Minimal permission requests with optional permissions
- No external script loading from CDNs
- Proper use of web_accessible_resources
- Source maps included (`.map` files) for debugging
- Structured IndexedDB schema versioning
- Professional Vite build toolchain

## Conclusion

7TV is a **CLEAN** extension that serves its intended purpose of enhancing streaming platform experiences with custom emotes and cosmetics. The extension demonstrates good security practices:

1. **Minimal permissions** - Only requests what's needed
2. **Transparent functionality** - All network calls align with stated purpose
3. **No malicious patterns** - Extensive analysis found no privacy violations, data theft, or malware
4. **Professional development** - Modern build tools, proper permission handling, and clean architecture

While the extension is invasive in the sense that it modifies streaming platform UIs and maintains persistent connections to emote services, this is clearly its intended and disclosed functionality. Users installing 7TV expect these modifications and integrations.

**Recommendation**: Safe for users who want custom emote functionality on streaming platforms. No security concerns identified.

---

## Overall Risk Level: **CLEAN**

No vulnerabilities or malicious behavior detected. Extension operates as intended with appropriate permissions and transparent functionality.
