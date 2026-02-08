# YTBlock - Block any content from YouTube™ Security Analysis

## Extension Metadata
- **Extension Name**: YTBlock - Block any content from YouTube™
- **Extension ID**: nedcanggplmbbgmlpcjiafgjcpdimpea
- **Version**: 5.16.6
- **Approximate User Count**: ~50,000
- **Manifest Version**: 3
- **Author**: Edoan

## Executive Summary

YTBlock is a YouTube content blocking extension that allows users to filter videos, channels, comments, posts, and playlists based on various criteria (keywords, channels, tags, etc.). The extension appears to be a legitimate productivity/content filtering tool with no evidence of malicious behavior.

The extension uses the YouTube Data API v3 (optional, user-provided API key) to fetch video metadata for advanced filtering features. All network communication is limited to:
1. YouTube's public API endpoints (googleapis.com/youtube/v3)
2. YouTube's internal API (youtube.com/youtubei/v1/player) for video metadata
3. CloudFlare CDN for Font Awesome stylesheet (cosmetic)

The codebase is clean, with standard use of Chrome extension APIs, local storage for user preferences, and no suspicious patterns such as data exfiltration, extension enumeration, proxy infrastructure, or malicious SDK injection.

**Overall Risk Assessment: CLEAN**

## Vulnerability Analysis

### 1. Network Communication - CLEAN
**Severity**: N/A
**Files**: background.js (line 9599), content-scripts/content.js (line 10776, 12078), chunks/options-MxBidfeU.js (line 5625)

**Description**:
The extension makes limited network requests exclusively to legitimate YouTube/Google services:

```javascript
// background.js:9599 - YouTube Data API v3 for video metadata
fetch(`https://www.googleapis.com/youtube/v3/videos?id=${y}&key=${m}&part=snippet,contentDetails,statistics`)

// content-scripts/content.js:10776 - YouTube internal API for video details
fetch("https://www.youtube.com/youtubei/v1/player", {
  body: JSON.stringify({
    context: { client: { clientName: "WEB", clientVersion: "2.20230327.07.00" }},
    videoId: r
  }),
  method: "POST"
})

// content-scripts/content.js:13386 - Font Awesome CDN (cosmetic)
h.href = "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css"
```

**Verdict**: All network requests are to trusted Google/YouTube endpoints and CloudFlare CDN. No third-party analytics, tracking, or data exfiltration detected.

---

### 2. Data Storage & Privacy - CLEAN
**Severity**: N/A
**Files**: background.js, chunks/popup-B7jN7_Xo.js, chunks/options-MxBidfeU.js

**Description**:
The extension stores user preferences and blocking rules exclusively in Chrome local storage:
- Blocked video/channel/comment/post/playlist lists
- User configuration (API keys, preset settings, schedules)
- Extension state (enabled/disabled, active preset)
- UI preferences (theme, changelog version tracking)

All data is stored locally using `chrome.storage.local` with no evidence of synchronization to external servers. LocalStorage is used minimally for UI state (extension enabled state, dark mode preference).

**Verdict**: All user data remains local. No external data transmission or unauthorized data collection.

---

### 3. Chrome API Usage - CLEAN
**Severity**: N/A
**Files**: manifest.json, background.js

**Permissions Requested**:
```json
"permissions": ["storage", "contextMenus", "unlimitedStorage", "alarms"]
"optional_permissions": ["downloads", "notifications"]
"host_permissions": ["*://*.youtube.com/*"]
```

**API Usage Analysis**:
- `chrome.storage`: Used appropriately for storing blocking rules and preferences
- `chrome.contextMenus`: Creates right-click menus for blocking content (lines 9722-9849 in background.js)
- `chrome.alarms`: Schedules preset activation/deactivation based on user-configured time schedules (line 10479)
- `chrome.notifications`: Optional permission for update notifications (line 10432)
- `chrome.downloads`: Optional permission (likely for export functionality)
- `chrome.tabs`: Used for badge counters and inter-tab messaging (lines 10459, 5542)

**Verdict**: All API usage is appropriate and matches the extension's stated functionality. No abuse of sensitive APIs detected.

---

### 4. Content Script Behavior - CLEAN
**Severity**: N/A
**Files**: content-scripts/content.js (13,803 lines), content-scripts/content.css

**Description**:
The content script runs on `*://*.youtube.com/*` and performs DOM manipulation to:
- Hide blocked videos, comments, posts, playlists based on user rules
- Inject UI elements for blocking controls
- Monitor page navigation (YouTube SPA) to reapply filters
- Extract video/channel metadata for keyword matching

Key behaviors observed:
```javascript
// Line 13386 - Injects Font Awesome stylesheet for UI icons
h.href = "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css"

// Line 13408 - Maintains blocking counters
const c = () => {
  const h = {};
  Object.keys(a).forEach(y => {
    const b = y, k = a[b].size;
    h[b] = k
  });
  return h
}
```

**Verdict**: Content script behavior is benign and focused on content filtering. No keylogging, credential theft, or malicious DOM manipulation detected.

---

### 5. Dynamic Code & Obfuscation - CLEAN
**Severity**: N/A
**Files**: background.js, localize.js

**Description**:
The extension uses standard JavaScript frameworks (jQuery 3.7.1, Lodash, Vue.js) which contain minimal dynamic code patterns. One instance of `Function()` constructor found:

```javascript
// background.js:1531 - Lodash internal fallback for global object detection
tt = Is || Ko || Function("return this")()
```

This is a standard Lodash pattern for cross-environment compatibility and is not used maliciously.

**Verdict**: No malicious dynamic code execution. Standard framework usage.

---

### 6. innerHTML Usage - FALSE POSITIVE
**Severity**: N/A
**Files**: chunks/popup-B7jN7_Xo.js, chunks/options-MxBidfeU.js, background.js

**Description**:
Multiple instances of `innerHTML` usage detected, primarily in:
1. **Vue.js templating** (chunks/popup-B7jN7_Xo.js lines 697-718) - Rendering localized block count messages
2. **jQuery DOM manipulation** (background.js lines 7046, 7487) - Standard jQuery `.html()` method
3. **Localization system** (localize.js line 5300) - Inserting translated text into DOM

All `innerHTML` usage is for rendering user preferences or localized text, not for executing untrusted content.

**Verdict**: FALSE POSITIVE - Standard framework usage for UI rendering.

---

### 7. Messaging & Communication - CLEAN
**Severity**: N/A
**Files**: background.js (lines 5525-5546)

**Description**:
The extension implements a message-passing system between background/content scripts:

```javascript
// background.js:5525 - Receives messages from content scripts
J.runtime.onMessage.addListener((c, k, O) => {
  const P = c;
  P.__handled && P.messageId === m && y(P.message, k, O)
})

// background.js:5532 - Sends messages to content scripts
J.runtime.sendMessage({
  __handled: !0,
  messageId: m,
  message: y
})
```

Messages include: block/unblock actions, badge counter updates, storage queries, and option page requests.

**Verdict**: Internal messaging system is properly scoped and secure. No external message handling.

---

### 8. YouTube Data API Integration - CLEAN
**Severity**: N/A
**Files**: background.js (line 9599), chunks/options-MxBidfeU.js (line 5625)

**Description**:
The extension allows users to optionally provide their own YouTube Data API v3 key for advanced features (viewing video tags, channel-based blocking). The API key:
- Is user-provided (not hardcoded)
- Stored in `chrome.storage.local`
- Used exclusively for YouTube API queries
- Never transmitted to third parties

API validation logic in chunks/options-MxBidfeU.js (lines 5622-5660) tests the key against a known video ID and displays error/success messages.

**Verdict**: API key handling is secure and transparent. User maintains control of their own key.

---

## False Positive Analysis

| Pattern | Location | Reason for False Positive |
|---------|----------|--------------------------|
| `innerHTML` | popup-B7jN7_Xo.js:697-718 | Vue.js template rendering for localized block counts |
| `innerHTML` | background.js:7046,7487 | jQuery `.html()` method for DOM manipulation |
| `innerHTML` | localize.js:5300 | i18n system inserting translated strings |
| `Function()` | background.js:1531 | Lodash internal global object detection |
| `keydown` listeners | Various files | Standard UI event handling (jQuery, Vue.js frameworks) |
| `localStorage` | chunks/*.js | UI state persistence (theme, extension enabled flag) |

---

## API Endpoints Summary

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://www.googleapis.com/youtube/v3/videos` | Fetch video metadata | Video IDs, user API key | LOW - Public API, user controls key |
| `https://www.youtube.com/youtubei/v1/player` | Fetch video details (internal) | Video IDs | LOW - YouTube internal API |
| `https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css` | Load icon font | None (CSS request) | NEGLIGIBLE - Static CDN resource |

---

## Data Flow Summary

```
User Actions (block/unblock)
  → Content Script (DOM filtering)
    → Background Script (storage operations)
      → chrome.storage.local (persistent rules)

Optional: User provides API key
  → Stored in chrome.storage.local
    → Used for YouTube API queries (metadata enrichment)
      → Results displayed in extension UI
```

**No data leaves the user's browser except for:**
1. YouTube API requests (user-initiated, using user's API key)
2. YouTube internal API queries (for video metadata during filtering)

---

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

### Summary
YTBlock is a legitimate YouTube content filtering extension with clean code, appropriate permission usage, and no malicious behavior. The extension:
- ✅ Uses only necessary permissions for its stated functionality
- ✅ Makes network requests exclusively to YouTube/Google services
- ✅ Stores all user data locally (no external transmission)
- ✅ Contains no tracking, analytics, or data exfiltration
- ✅ Uses standard web frameworks (jQuery, Vue.js, Lodash) appropriately
- ✅ Implements secure messaging between extension components
- ✅ Provides transparent API key management (user-controlled)

### Recommendation
**APPROVED FOR USE** - This extension poses no security risk to users. It functions as advertised (content blocking on YouTube) with no hidden malicious functionality.

### Notes
- The extension uses manifest v3, indicating active maintenance
- Code is well-structured with clear separation between background/content scripts
- No evidence of code obfuscation beyond standard JavaScript minification
- Donation links present (Patreon, PayPal, etc.) suggest legitimate independent developer
