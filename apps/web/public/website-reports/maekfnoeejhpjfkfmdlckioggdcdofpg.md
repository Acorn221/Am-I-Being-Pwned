# Security Analysis: Adblocker for Youtube

## Extension Metadata
- **Extension ID**: maekfnoeejhpjfkfmdlckioggdcdofpg
- **Name**: Adblocker for Youtube (branded as "Awesome Youtube Videos")
- **Version**: 3.3.1
- **Users**: ~400,000
- **Manifest Version**: 3
- **Homepage**: https://enhanced-videos.dllplayer.com/
- **Analysis Date**: 2026-02-06

## Executive Summary

**OVERALL RISK: LOW**

This extension is a legitimate YouTube ad blocker and video enhancement tool. The extension provides genuine ad-blocking functionality through multiple mechanisms (DOM manipulation, MutationObserver-based auto-clickers, and declarativeNetRequest rules), along with video enhancement features like volume boosting, screenshot capture, theater mode, and floating video.

The extension does make network requests to YouTube's Data API v3 (using a public API key) to fetch video metadata and channel statistics for display purposes. It also tracks install/uninstall events by opening homepage URLs, but does not exfiltrate user data or perform malicious activities.

**Key Findings:**
- ✅ No data exfiltration detected
- ✅ No XHR/fetch hooking or interception
- ✅ No extension enumeration or killing behavior
- ✅ No SDK injection (Sensor Tower, etc.)
- ✅ No cookie harvesting
- ✅ No keylogging
- ⚠️ Uses YouTube Data API v3 with hardcoded public API key (expected false positive)
- ⚠️ Opens homepage URLs on install/uninstall (monetization tracking)
- ⚠️ Contains large autoads.js file (4212 lines) but legitimate functionality

## Detailed Findings

### 1. Manifest Analysis

**Permissions:**
```json
"permissions": ["storage", "scripting", "sidePanel"]
"host_permissions": ["*://*.youtube.com/"]
```

**Verdict:** ✅ SAFE
- Minimal, appropriate permissions for a YouTube enhancement extension
- `storage`: Local settings persistence
- `scripting`: Dynamic script injection for ad blocking
- `sidePanel`: Side panel UI (MV3 pattern)
- `host_permissions`: YouTube-only access (properly scoped)

**Content Security Policy:**
- ✅ No CSP relaxation detected
- ✅ No unsafe-eval or unsafe-inline

**Externally Connectable:**
```json
"externally_connectable": {
  "matches": ["https://*.youtube.com/*", "https://youtube.com/*"]
}
```
- ✅ Only allows YouTube domains to communicate with extension (legitimate use case)

### 2. Background Service Worker

**File:** `/js/bg-worker.js` → imports `background.js`, `common.js`, `settings.js`, `welcome.js`

**Key Behaviors:**

**2.1 Install/Uninstall Tracking (welcome.js)**
```javascript
chrome.runtime.onInstalled.addListener(details => {
    if (details.reason == "install") {
        chrome.tabs.create({ url: homepage + "/welcome" });
    }
});
chrome.runtime.setUninstallURL(homepage + "/uninstall");
```

**Verdict:** ⚠️ LOW RISK (Monetization Tracking)
- Opens `https://enhanced-videos.dllplayer.com/welcome` on install
- Sets uninstall URL to track removals
- Common monetization pattern, not malicious
- Does not exfiltrate user data

**2.2 Message Handling (background.js)**
- ✅ Listens for internal extension messages only
- ✅ Handles settings sync, blacklist management, watch history (local only)
- ✅ Dynamic script injection for ad blocking (`skipad.js`, `skipad-once.js`)
- ✅ Translation loading via XHR (local extension files only)
- ✅ Download permission requests for JSON export (user-initiated)

**2.3 Side Panel Integration**
```javascript
chrome.action.onClicked.addListener(({ id }) => {
    chrome.sidePanel.setOptions({ enabled: true, path: "/popup.html", tabId: id });
    chrome.sidePanel.open({ tabId: id });
});
```
- ✅ Modern MV3 pattern for UI display

### 3. Content Scripts Analysis

**Injection Points:**
1. `common.js` - document_start (all frames)
2. `autoads.js` + `skipstartads.js` - document_start (ad detection/blocking)
3. `content.js` + `youtube-ui.js` - document_end (UI enhancements)

**3.1 Ad Blocking Mechanisms**

**A. DOM-Based Ad Removal (skipstartads.js)**
```javascript
#checkAd() {
    const renderer = document.querySelector("ytd-display-ad-renderer");
    if (renderer) {
        renderer.closest("ytd-rich-item-renderer").style.setProperty("display", "none", "important");
    }

    const player = this.#player;
    if (player.classList.contains("ad-showing")) {
        const video = player.querySelector("video");
        const btn = player.querySelector(".ytp-ad-skip-button");
        if (btn) {
            btn.click();
        } else {
            video.currentTime = isNaN(video.duration) ? 0 : video.duration;
        }
    }
}
```

**Verdict:** ✅ SAFE - Legitimate Ad Blocking
- Uses MutationObserver to detect ads in real-time
- Auto-clicks skip button or fast-forwards video to end
- Hides display ad renderers with CSS
- Removes anti-adblock popups (`ytd-enforcement-message-view-model`)

**B. Auto-Clicker Pattern (skipad.js)**
```javascript
var classList = [
    'videoAdUiSkipButton',
    'ytp-ad-skip-button ytp-button',
    'ytp-ad-overlay-close-button',
];

function checkAndClickButtons() {
    existingButtons(classList).forEach(button => {
        if (!isBtnVisible(button)) {
            triggerClickWhenVisible(button);
        } else {
            triggerClick(button);
        }
    });
}
```

**Verdict:** ✅ SAFE - Legitimate Ad Skip Automation
- Well-documented, transparent ad-skipping logic
- Uses MutationObserver on `ytd-player` element
- Waits for button visibility before clicking (mimics human behavior)

**3.2 Video Enhancement Features (content.js)**

**A. Volume Scroll Control**
```javascript
onVideoElScroll(e) {
    event.preventDefault();
    const video = this.ui.getPlayerVideoEl();
    let volume = parseInt(video.volume * 100) + delta;
    video.volume = volume / 100;
}
```
- ✅ Mouse wheel control for volume adjustment

**B. Audio Boosting (up to 600%)**
```javascript
const audioContext = new AudioContext();
const source = audioContext.createMediaElementSource(video);
that.gainNode = audioContext.createGain();
that.gainNode.gain.value = boostingValue; // Up to 3.5x
source.connect(that.gainNode);
that.gainNode.connect(audioContext.destination);
```
- ✅ Uses Web Audio API for legitimate volume amplification

**C. Screenshot Capture**
```javascript
onScreenshotButtonClick() {
    const videoEl = this.ui.getPlayerVideoEl();
    const canvas = document.createElement("canvas");
    canvas.width = videoEl.videoWidth;
    canvas.height = videoEl.videoHeight;
    const canvasContext = canvas.getContext("2d");
    canvasContext.drawImage(videoEl, 0, 0);

    canvas.toBlob(blob => {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = "screenshot.png";
        a.click();
    });
}
```
- ✅ Canvas-based screenshot functionality (legitimate)

**D. Theater Mode & Floating Video**
- ✅ Manipulates YouTube's native theater mode
- ✅ Picture-in-Picture API for floating video
- ✅ No malicious DOM manipulation

**3.3 YouTube Data API Integration (autoads.js)**

**API Key Usage:**
```javascript
xhr.open('GET', 'https://www.googleapis.com/youtube/v3/videos?id=' + video_id +
    '&key=AIzaSyCXRRCFwKAXOiF1JkUBmibzxJF1cPuKNwA&part=snippet', true);

xhr.open('GET', 'https://www.googleapis.com/youtube/v3/channels?id=' + channel_id +
    '&key=AIzaSyCXRRCFwKAXOiF1JkUBmibzxJF1cPuKNwA&part=statistics', true);
```

**Verdict:** ✅ EXPECTED FALSE POSITIVE - Public API Key
- Uses YouTube Data API v3 to fetch video upload dates and channel video counts
- API key is public and quota-limited by Google (standard practice)
- No user data sent to API (only public YouTube IDs)
- Responses used only for display enhancement (e.g., "Uploaded 3 days ago", "1,234 videos")

### 4. Network Activity Analysis

**External Domains:**
1. `https://www.googleapis.com/youtube/v3/*` - YouTube Data API (legitimate)
2. `https://enhanced-videos.dllplayer.com/` - Homepage (install/uninstall tracking)
3. `https://www.cinemamode.co/` - Defined in `Common.SERVER_URL` but **NOT USED** in any network calls

**Verdict:** ✅ SAFE
- No data exfiltration detected
- No user tracking beyond install/uninstall events
- No third-party analytics SDKs
- API calls are read-only and public data only

### 5. Storage Usage

**chrome.storage.local:**
- `options` - User settings (volumeScroll, theaterOnStart, disableToolbar, player_ads)
- `analyzer` - Local usage analytics (date/hour bucketed, not exfiltrated)
- `blacklist` - User's blacklisted channels/videos (local only)
- `watched` - Watched video tracking (local only, user-controlled)

**Verdict:** ✅ SAFE
- All storage is local-only
- No data exfiltration to remote servers
- User privacy preserved

### 6. Dynamic Code Execution

**chrome.scripting.executeScript:**
```javascript
chrome.scripting.executeScript({
    target: { tabId },
    files: [once ? "js/skipad-once.js" : "js/skipad.js"],
})
```

**Verdict:** ✅ SAFE
- Only injects static bundled scripts (no remote code)
- User-triggered via "Remove Ads" button or keyboard shortcut
- No eval() or Function() constructor usage
- Scripts are included in CRX package (reviewable)

### 7. Rate Notification Feature

```javascript
if (!document.querySelector('.it-rate-notify') && Object.keys(items).length > 10 && items.rate_notify !== 5) {
    var popup = document.createElement('div');
    popup.innerHTML = 'Do you enjoy ImprovedTube?' +
        '<button onclick="window.open(\'https://chromewebstore.google.com/detail/.../reviews\');">Yes</button>' +
        '<button>No</button>';
    document.body.appendChild(popup);
    chrome.storage.local.set({ rate_notify: 5 });
}
```

**Verdict:** ✅ SAFE - Standard Review Request
- Shows once after user has configured 10+ settings
- Links to Chrome Web Store review page
- No tracking of user response beyond dismissal flag

### 8. Keyboard Shortcut Handling

**Manifest Commands:**
- `Ctrl+Shift+Space` (Mac: MacCtrl+Shift+Space) - Cinema mode
- `Alt+S` - Create screenshot
- `Ctrl+Space` (Mac: MacCtrl+Space) - Float video
- `Ctrl+Delete` (Mac: MacCtrl+Delete) - Remove ads

**Implementation:**
```javascript
chrome.commands.onCommand.addListener(function (command) {
    chrome.tabs.sendMessage(tab.id, {
        message: "yt-extender-keyboard-shortcut",
        command: command
    });
});
```

**Verdict:** ✅ SAFE
- Standard keyboard shortcut API usage
- No keylogging detected
- Commands trigger legitimate extension features

## False Positives Identified

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| **Hardcoded API Key** | `autoads.js:554,596` | YouTube Data API v3 public key for fetching video/channel metadata | ✅ Expected FP |
| **XMLHttpRequest Usage** | `background.js:30-54`, `autoads.js:554,596` | Loading translations & YouTube API calls (read-only) | ✅ Expected FP |
| **innerHTML Usage** | `Localize.js:31` | Chrome i18n message localization (`__MSG_*__` replacement) | ✅ Expected FP |
| **createElement('script')** | `content.js:527` (commented out) | Dead code, not executed | ✅ Expected FP |
| **SVG createElementNS** | `content.js:267-268` | Creating SVG icons for UI buttons | ✅ Expected FP |

## API Endpoints Summary

| Endpoint | Purpose | Data Sent | Verdict |
|----------|---------|-----------|---------|
| `https://www.googleapis.com/youtube/v3/videos` | Fetch video upload date | Video ID (public) | ✅ Safe |
| `https://www.googleapis.com/youtube/v3/channels` | Fetch channel statistics | Channel ID (public) | ✅ Safe |
| `https://enhanced-videos.dllplayer.com/welcome` | Install tracking | None (page load only) | ⚠️ Monetization |
| `https://enhanced-videos.dllplayer.com/uninstall` | Uninstall tracking | None (page load only) | ⚠️ Monetization |
| `https://enhanced-videos.dllplayer.com/tutorial` | Help documentation | None (user-initiated) | ✅ Safe |
| `https://www.cinemamode.co/` | Defined but **unused** | N/A | ✅ Safe |

## Data Flow Summary

```
User YouTube Activity → Local Storage Only
├─ Watched videos → chrome.storage.local (not exfiltrated)
├─ Blacklisted channels → chrome.storage.local (not exfiltrated)
├─ User settings → chrome.storage.local (not exfiltrated)
└─ Usage analytics → chrome.storage.local (not exfiltrated)

Extension Install/Uninstall → Homepage URL Open
└─ https://enhanced-videos.dllplayer.com/welcome or /uninstall
   └─ No user data in URL parameters
   └─ Standard page load tracking (server logs only)

YouTube Video Metadata → YouTube Data API v3
├─ Public video IDs → https://www.googleapis.com/youtube/v3/videos
├─ Public channel IDs → https://www.googleapis.com/youtube/v3/channels
└─ Response: Video upload date, channel video count (displayed in UI)
```

## Security Checklist

- ✅ No XHR/fetch hooking or interception
- ✅ No extension enumeration (`chrome.management`)
- ✅ No extension killing/disabling
- ✅ No residential proxy infrastructure
- ✅ No remote configuration/kill switches
- ✅ No market intelligence SDKs (Sensor Tower, etc.)
- ✅ No AI conversation scraping
- ✅ No ad injection (removes ads instead)
- ✅ No coupon injection
- ✅ No obfuscation (readable code)
- ✅ No cookie harvesting
- ✅ No keylogging
- ✅ No postMessage eavesdropping
- ✅ No credential theft
- ✅ No dynamic code loading from remote sources
- ⚠️ Install/uninstall tracking (homepage URLs)
- ⚠️ Hardcoded YouTube Data API key (public, expected)

## Code Quality Observations

**Positive:**
- Well-structured, modular code organization
- Extensive inline comments and documentation
- Uses modern ES6+ class syntax
- MV3 best practices (service worker, declarativeNetRequest concepts)
- No code obfuscation

**Neutral:**
- Large autoads.js file (4212 lines) contains many features
- Some commented-out dead code
- Uses jQuery (legacy, but not malicious)
- "ImprovedTube" references suggest code reuse from another project

## Recommendations

1. **For Users:** ✅ Safe to use. This extension performs as advertised.
2. **For Developers:**
   - Consider removing dead code references to `cinemamode.co` to reduce confusion
   - The "ImprovedTube" branding inconsistency suggests code forking - ensure license compliance
   - API key should ideally use a backend proxy to prevent quota abuse
3. **For Reviewers:** No security concerns requiring removal from store.

## Overall Risk Assessment

**RISK LEVEL: LOW**

This extension is a legitimate YouTube ad blocker and video enhancement tool. The install/uninstall tracking is the only privacy consideration, which is a standard monetization practice and does not exfiltrate user data. The YouTube Data API usage is appropriate and uses public data only.

**Risk Breakdown:**
- **Data Exfiltration Risk:** ✅ None
- **Malicious Code Risk:** ✅ None
- **Privacy Risk:** ⚠️ Low (install/uninstall tracking only)
- **Security Risk:** ✅ None
- **Deceptive Behavior:** ✅ None

**Recommendation:** CLEAN - Safe for use.

---

**Analysis Completed:** 2026-02-06
**Analyst:** Claude Sonnet 4.5
**Files Analyzed:** 17 JavaScript files, manifest.json, 2 HTML files
