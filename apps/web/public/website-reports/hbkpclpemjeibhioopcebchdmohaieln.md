# Vulnerability Report: BTRoblox - Making Roblox Better

## Extension Metadata
- **Extension ID**: hbkpclpemjeibhioopcebchdmohaieln
- **Extension Name**: BTRoblox - Making Roblox Better
- **Version**: 3.6.22
- **User Count**: ~5,000,000
- **Developer**: AntiBoomz
- **Manifest Version**: 3

## Executive Summary

BTRoblox is a feature-rich enhancement extension for Roblox.com that adds quality-of-life improvements including ad blocking, enhanced navigation, item previews, server details, and various UI enhancements. The extension demonstrates **clean implementation with no malicious behavior**. It exclusively interacts with legitimate Roblox domains (*.roblox.com, *.rbxcdn.com) and one content API (ButterCMS) for blog feed functionality.

The codebase (~26,000 lines across 52 JS files) shows professional development practices with well-structured code, proper error handling, and a comprehensive feature system. While the extension requests significant permissions and performs page manipulation, all functionality serves the stated purpose of enhancing the Roblox user experience.

**Overall Risk Assessment**: **CLEAN**

## Vulnerability Analysis

### 1. Permissions Analysis - CLEAN
**Severity**: N/A
**Files**: manifest.json
**Verdict**: CLEAN

**Permissions Requested**:
- `declarativeNetRequestWithHostAccess` - Used for dynamic content injection and ad blocking
- `notifications` - Browser notifications for group shout alerts
- `contextMenus` - Right-click context menu additions
- `scripting` - Script injection for features
- `storage` - Settings and cache storage
- `alarms` - Periodic background tasks

**Host Permissions**:
- `*://*.roblox.com/` - Primary Roblox domain
- `*://*.rbxcdn.com/` - Roblox CDN for assets

**Analysis**: All permissions are justified and necessary for the extension's advertised functionality. The extension appropriately restricts itself to Roblox domains only.

### 2. Network Communication - CLEAN
**Severity**: N/A
**Files**: js/rbx/RobloxApi.js, js/feat/blogfeed.js, js/feat/groupshout.js
**Verdict**: CLEAN

**External API Endpoints**:
1. **Roblox Official APIs** (122 references across codebase):
   - accountinformation.roblox.com
   - assetdelivery.roblox.com
   - avatar.roblox.com
   - badges.roblox.com
   - catalog.roblox.com
   - economy.roblox.com
   - friends.roblox.com
   - games.roblox.com
   - groups.roblox.com
   - inventory.roblox.com
   - presence.roblox.com
   - thumbnails.roblox.com
   - users.roblox.com

2. **ButterCMS Blog Feed** (1 endpoint):
   - `https://api.buttercms.com/v2/pages/long_form_page/` - Fetches Roblox newsroom posts with hardcoded auth token

**Code Evidence**:
```javascript
// blogfeed.js:17
const feedUrl = `https://api.buttercms.com/v2/pages/long_form_page/?locale=en&preview=0&page=1&page_size=3&fields.page_type.localized_slug=newsroom&fields.unlist_page=false&order=-displayed_publish_date&auth_token=137ac5a15935fab769262b6167858b427157ee3d`
```

**Analysis**: All network calls are to legitimate Roblox services for intended functionality. The ButterCMS call fetches public blog posts from Roblox's official newsroom. No data exfiltration detected.

### 3. CSRF Token Handling - CLEAN
**Severity**: N/A
**Files**: js/rbx/RobloxApi.js
**Verdict**: CLEAN (Legitimate Use)

**Code Evidence**:
```javascript
// RobloxApi.js:138, 164
cachedXsrfToken = document.querySelector("meta[name='csrf-token']")?.dataset.token ?? null

// RobloxApi.js:167
init.headers["X-CSRF-TOKEN"] = cachedXsrfToken
```

**Analysis**: The extension reads Roblox's CSRF token from the page to make authenticated API requests on behalf of the user. This is standard practice for extensions that enhance web applications and is used only for legitimate Roblox API calls with `credentials: "include"`.

### 4. XHR/Fetch Hijacking - CLEAN
**Severity**: N/A
**Files**: js/inject.js
**Verdict**: CLEAN (Enhancement Feature)

**Code Evidence**:
```javascript
// inject.js:52-134
hijackFunction(window, "fetch", (target, thisArg, args) => {
    // Intercepts fetch calls to modify requests/responses
})

hijackFunction(XMLHttpRequest.prototype, "open", (target, xhr, args) => {
    // Intercepts XHR to modify requests/responses
})
```

**Analysis**: The extension hijacks fetch/XHR to intercept Roblox API responses for feature enhancement (e.g., modifying UI data, adding extra information). The hijacking is implemented via Proxy objects and only applies transforms registered through `xhrTransforms` array. This is a legitimate technique for browser extensions that enhance web applications. No malicious modifications detected.

### 5. Ad Blocking Implementation - CLEAN
**Severity**: N/A
**Files**: js/feat/adblock.js
**Verdict**: CLEAN

**Code Evidence**:
```javascript
// adblock.js:5-45
const iframeSelector = `.ads-container iframe,.abp iframe,...`
// Removes ad iframes and blocks third-party ad scripts
script.src.includes("imasdk.googleapis.com") ||
script.src.includes("googletagmanager.com") ||
script.src.includes("radar.cedexis.com")
```

**Analysis**: Implements client-side ad blocking by removing ad containers and blocking third-party ad/analytics scripts. This is a user-beneficial feature with no privacy concerns.

### 6. Data Storage - CLEAN
**Severity**: N/A
**Files**: js/feat/settings.js, js/feat/shareddata.js
**Verdict**: CLEAN

**Analysis**: Uses `chrome.storage.local` for:
- User settings/preferences
- Cached blog feed data
- Group shout notifications cache
- Extension state management

No sensitive data collection or transmission detected. Storage is used purely for legitimate feature state.

### 7. Content Script Injection - CLEAN
**Severity**: N/A
**Files**: js/inject.js, js/main.js, manifest.json
**Verdict**: CLEAN

**Analysis**: Injects content scripts into Roblox pages to:
- Modify page DOM for UI enhancements
- Add feature functionality (hover previews, navigation improvements)
- Hook into Angular/React frameworks for template modification

All injection is scoped to Roblox domains and serves legitimate enhancement purposes.

### 8. Dynamic Code Execution - CLEAN
**Severity**: N/A
**Files**: N/A
**Verdict**: CLEAN

**Analysis**: No instances of `eval()`, `new Function()`, or other dangerous dynamic code execution patterns found. The extension uses only static code with proper Proxy-based interception patterns.

## False Positive Analysis

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| XHR/Fetch Hijacking | js/inject.js:52-213 | Legitimate feature enhancement technique for browser extensions |
| CSRF Token Reading | js/rbx/RobloxApi.js:138,164 | Standard practice for authenticated API calls on behalf of user |
| Proxy Objects | js/inject.js:44,89,373 | Used for non-invasive function interception, not malicious hooking |
| ButterCMS API Key | js/feat/blogfeed.js:17 | Public read-only token for fetching Roblox blog posts |
| DeclarativeNetRequest | js/feat/shareddata.js:20 | Used for data passing between contexts, not for blocking/redirecting user traffic |

## API Endpoints Summary

| Domain | Purpose | Data Sent | Risk |
|--------|---------|-----------|------|
| *.roblox.com | Official Roblox APIs | User credentials (session cookies), API requests | CLEAN - Intended functionality |
| *.rbxcdn.com | Roblox CDN | Asset requests | CLEAN - Static resources |
| api.buttercms.com | Blog feed | None (public read) | CLEAN - Public content API |

## Data Flow Summary

```
User Browser
    ↓
BTRoblox Extension
    ↓
├─→ roblox.com APIs (authenticated with user session)
│   └─→ Fetch user data, game info, avatar details, etc.
│
├─→ rbxcdn.com (unauthenticated)
│   └─→ Load asset resources, images, models
│
└─→ buttercms.com (unauthenticated, read-only)
    └─→ Fetch Roblox blog posts for display
```

**No data exfiltration detected.** All data flows serve legitimate enhancement features.

## Feature Analysis

**Core Features**:
1. **Ad Blocking** - Removes Roblox ads and tracking scripts
2. **Navigation Enhancement** - Improved site navigation and search
3. **Item Previews** - 3D preview of catalog items and avatars
4. **Server Details** - Shows game server regions and details
5. **Group Shout Alerts** - Notifications for group announcements
6. **Robux to Cash Converter** - Display real-world value of Robux
7. **Settings Modal** - Comprehensive user configuration
8. **Avatar Editor Enhancements** - Remove accessory limits, full-range body colors
9. **Catalog Improvements** - Show owned assets, enhanced filtering
10. **Profile Enhancements** - Embedded inventory, additional user info

All features are clearly beneficial to users and operate transparently.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Rationale**:
BTRoblox is a well-developed, legitimate browser extension that enhances the Roblox user experience. The extension:

✅ **Only communicates with official Roblox domains** (plus one public blog API)
✅ **Implements no data exfiltration or tracking**
✅ **Uses permissions appropriately for stated functionality**
✅ **Contains no malicious code patterns**
✅ **Shows professional development practices**
✅ **Operates transparently with user control**
✅ **Ad blocking benefits user privacy**
✅ **No evidence of cryptocurrency mining, proxying, or other abuse**

**Invasiveness Justification**: While the extension is highly invasive (page manipulation, XHR hijacking, extensive permissions), this invasiveness is **necessary and justified** for its feature set. The extension fundamentally modifies how users interact with Roblox, which requires deep integration. All modifications serve the explicit purpose of improving user experience.

**Comparison to Malicious Extensions**: Unlike malicious extensions that hide their behavior, BTRoblox openly implements all features with clear user-facing settings. The codebase is well-commented and structured, suggesting open-source or transparency-focused development.

## Recommendations

1. **For Users**: This extension is safe to use and provides genuine value for Roblox users.
2. **For Security Researchers**: No security concerns identified. Extension follows best practices.
3. **For Developers**: Consider open-sourcing the codebase to increase transparency and community trust.

## Conclusion

BTRoblox is a **CLEAN** extension with no security vulnerabilities or malicious behavior. It serves its advertised purpose of enhancing the Roblox experience through legitimate means. The 5 million user base is justified by the extension's comprehensive feature set and quality implementation.
