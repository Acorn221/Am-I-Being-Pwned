# Security Analysis: Open in VLC™ media player (ihpiinojhnfhpdmmacgmpoonphhimkaj)

## Extension Metadata
- **Name**: Open in VLC™ media player
- **Extension ID**: ihpiinojhnfhpdmmacgmpoonphhimkaj
- **Version**: 0.4.3
- **Manifest Version**: 3
- **Estimated Users**: ~300,000
- **Developer**: webextension.org
- **Analysis Date**: 2026-02-14

## Executive Summary
Open in VLC is a **CLEAN** browser extension that enables users to open media URLs directly in VLC media player (or alternative players like PotPlayer, QMPlay2). The extension uses native messaging to communicate with a locally-installed native client that launches the media player with appropriate command-line arguments. Analysis of all data flows confirms that only expected data (media URLs, referrer, user-agent) is transmitted to the local VLC application, with no external data exfiltration or malicious behavior.

**Overall Risk Assessment: CLEAN**

## Vulnerability Assessment

### 1. Native Messaging Data Flow (EXPECTED BEHAVIOR)
**Severity**: N/A (Legitimate Functionality)
**Files**:
- `/worker.js` (lines 30-65, 243-306)
- `/open.js` (lines 8-186)
- `/native.js` (lines 2-73)
- `/data/helper/index.js` (lines 73-116)

**Analysis**:
The ext-analyzer correctly identified three data flows where `chrome.storage.local.get()` data flows to `chrome.runtime.sendNativeMessage()`. However, this is the core functionality of the extension and operates exactly as advertised.

**Data Flow Breakdown**:

**Flow 1: M3U8 Playlist Generation** (`worker.js`, lines 30-65)
```javascript
const toM3U8 = (urls, callback, tab) => chrome.storage.local.get({
  'use-page-title': true,
  'send-referrer': true,
  'send-user-agent': true,
  'runtime': 'com.add0n.node'
}, prefs => chrome.runtime.sendNativeMessage(prefs.runtime, {
  permissions: ['crypto', 'fs', 'os', 'path', 'child_process'],
  args: [`#EXTM3U\n` +
    (prefs['send-referrer'] && tab.url ? '#EXTVLCOPT:http-referrer=' + tab.url + '\n' : '') +
    (prefs['send-user-agent'] ? '#EXTVLCOPT:http-user-agent=' + navigator.userAgent + '\n' : '') +
    urls.map(url => {
      if (tab.title && prefs['use-page-title']) {
        return `#EXTINF:-1,${tab.title}` + '\n' + url;
      }
      return url;
    }).join('\n')],
  script: `...` // Node.js script to write temp M3U8 file
}, callback));
```

**Data Transmitted to Native Client**:
- Media URLs (from user's current page)
- Page title (if enabled in settings)
- Referrer URL (current tab URL, if enabled)
- User-agent string (browser's UA, if enabled)

**Purpose**: When opening multiple media links, the extension creates a temporary M3U8 playlist file and passes it to VLC. The referrer and user-agent are VLC command-line options that help VLC access protected media streams.

**Flow 2: Media Player Execution** (`open.js`, lines 12-186)
```javascript
const open = async (tab, tabId, referrer) => {
  const prefs = await chrome.storage.local.get({
    'media-player': 'VLC',
    'path': null,
    'send-title-meta': true,
    'one-instance': true,
    'send-referrer': true,
    'send-user-agent': true,
    'custom-arguments': [],
    'runtime': 'com.add0n.node'
  });

  const args = {
    pre: [],
    url,
    post: []
  };

  // Build VLC command-line arguments
  if (prefs['send-referrer'] && referrer) {
    args.pre.push('--http-referrer', referrer);
  }
  if (prefs['send-user-agent']) {
    args.pre.push('--http-user-agent', navigator.userAgent);
  }
  if (title && prefs['send-title-meta']) {
    args.post.push(`:meta-title=${title}`);
  }

  native.exec(executable.path, [
    ...args.pre,
    args.url,
    ...args.post
  ]);
}
```

**Data Transmitted**:
- Media URL to play
- Referrer URL (for authentication)
- User-agent (for authentication)
- Page title (for media library metadata)
- VLC executable path (determined locally)

**Flow 3: Native Client Detection** (`open.js`, lines 143-162)
```javascript
const r = await chrome.runtime.sendNativeMessage(prefs.runtime, {
  permissions: ['fs'],
  args: [...paths],
  script: `
    const fs = require('fs');
    const exist = path => new Promise(resolve => fs.access(path, fs.F_OK, e => {
      resolve(e ? false : true);
    }));
    Promise.all(args.map(exist)).then(d => {
      push({d});
      done();
    }).catch(e => push({e: e.message}));
  `
});
```

**Purpose**: On Windows, the extension uses the native client to check which VLC installation path exists (Program Files vs Program Files (x86)) to determine the correct executable path.

**Verdict**: **NOT MALICIOUS** - All three flows are legitimate operations for a VLC launcher extension:
1. Creating M3U8 playlists with metadata
2. Launching VLC with media URLs and HTTP headers
3. Auto-detecting VLC installation path

**Critical Safety Indicators**:
- Native messaging sends data to **local native client only** (installed on user's machine)
- No external network requests with user data
- User controls all settings (referrer/user-agent can be disabled)
- Only current page URL and detected media URLs are sent
- No browsing history, cookies, or cross-site data collection

---

### 2. Media Link Detection via webRequest
**Severity**: N/A (Legitimate Functionality)
**Files**: `/worker.js` (lines 127-170)

**Analysis**:
The extension monitors HTTP responses to detect media files (video/audio) on pages.

**Code Evidence**:
```javascript
chrome.webRequest.onHeadersReceived.addListener(d => {
  const href = d.url.toLowerCase();

  let type;
  if (href.includes('.m3u8')) {
    type = 'm3u8';
  }
  else {
    const header = d.responseHeaders.find(h => {
      return (h.name === 'Content-Type' || h.name === 'content-type') &&
        (h.value.startsWith('video') || h.value.startsWith('audio'));
    });
    if (header) {
      type = header.value.split('/')[1].split(';')[0];
    }
  }

  if (type) {
    const size = d.responseHeaders.filter(h => h.name.toLowerCase() === 'content-length')
                  .map(o => o.value).shift();
    store(d, type, size);
  }
}, {
  urls: ['*://*/*'],
  types: ['main_frame', 'other', 'xmlhttprequest', 'media']
}, ['responseHeaders']);
```

**Detection Logic**:
1. Monitors HTTP responses for media content types (video/*, audio/*)
2. Checks for `.m3u8` file extensions (HTTP Live Streaming)
3. Extracts media type and file size from headers
4. Stores URLs in tab-specific memory (not persistent storage)

**Data Storage** (`worker.js`, lines 90-125):
```javascript
const store = async (d, type, size = '') => {
  chrome.scripting.executeScript({
    target: { tabId: d.tabId },
    func: (max, href, type, size) => {
      self.links = self.links || new Map();
      self.links.set(href, { type, size });
      // cleanup
      if (self.links.size > max) {
        const firstKey = self.links.keys().next().value;
        self.links.delete(firstKey);
      }
      return self.links.size;
    },
    args: [store.prefs['max-number-of-items'], d.url, type, size]
  });
}
```

**Storage Scope**:
- Media links stored in **page-specific memory** (`self.links` in content script context)
- Not transmitted to external servers
- Limited to 100 items per tab (configurable)
- Cleared when tab is closed or navigated

**Verdict**: **NOT MALICIOUS** - This is standard behavior for media detection extensions. The extension monitors network traffic to find playable media but does not exfiltrate URLs.

---

### 3. GitHub API Access
**Severity**: N/A (Expected Behavior)
**Files**: `/data/helper/index.js` (lines 28-56)

**Analysis**:
The extension's helper page downloads the native client installer from GitHub releases.

**Code Evidence**:
```javascript
const req = new XMLHttpRequest();
req.open('GET', 'https://api.github.com/repos/andy-portmen/' + repo + '/releases/latest');
req.responseType = 'json';
req.onload = () => {
  chrome.downloads.download({
    filename: os + '.zip',
    url: req.response.assets.filter(a => a.name === os + '.zip')[0].browser_download_url
  }, () => {
    toast.notify('Wait for the download to complete before extracting and installing it.', 'success');
  });
};
```

**Purpose**:
- Fetches latest version info from `https://api.github.com/repos/andy-portmen/native-client/releases/latest`
- Downloads platform-specific installer (windows.zip, mac.zip, linux.zip)
- Only triggered when user clicks "Download Native Client" button

**Data Transmitted**:
- None (read-only API call)
- No user data, extension ID, or telemetry

**Verdict**: **NOT MALICIOUS** - Legitimate installer download mechanism. The extension requires a native client to function and provides an automated installer.

---

### 4. Context Menu Integration
**Severity**: N/A (Legitimate Functionality)
**Files**: `/context.js` (lines 1-179)

**Analysis**:
Creates context menu items for right-click integration.

**Menu Items**:
- "Open in VLC" - On video/audio elements, media links, YouTube pages
- "Copy Media Links to the Clipboard" - Copies detected media URLs
- "Send Page Link to VLC" - Sends current page URL to VLC (useful for YouTube)
- "Change Media Player" - Switch between VLC/PotPlayer/QMPlay2
- "Download Live Streams" - Links to HLS downloader tool
- "Convert to MP3" - Links to webbrowsertools.com converter

**External Links** (context.js, lines 147-155):
```javascript
else if (info.menuItemId === 'mp3-converter') {
  chrome.tabs.create({
    url: 'https://webbrowsertools.com/convert-to-mp3/'
  });
}
else if (info.menuItemId === 'download-hls') {
  chrome.tabs.create({
    url: 'https://webextension.org/listing/hls-downloader.html'
  });
}
```

**Verdict**: **NOT MALICIOUS** - Menu items link to related tools from the same developer. No data is transmitted with these links.

---

### 5. Web Accessible Resources
**Severity**: N/A (Safe Implementation)
**Manifest**:
```json
"web_accessible_resources": [{
  "resources": ["/data/inject/*"],
  "matches": ["*://*/*"]
}]
```

**Analysis**:
The extension injects a media link picker UI when multiple media files are detected on a page.

**Injection Flow** (`worker.js`, lines 218-230):
```javascript
else if (links.length > 1) {
  await chrome.scripting.insertCSS({
    target: { tabId: tab.id },
    files: ['/data/inject/inject.css']
  });
  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    files: ['/data/inject/inject.js']
  });
}
```

**Injected UI** (`data/inject/inject.js`):
- Creates a `<dialog>` element with iframe
- Loads `/data/inject/index.html` (list of detected media links)
- User can select which media file(s) to open in VLC
- Completely local UI with no external data transmission

**Verdict**: **NOT MALICIOUS** - Standard UI injection for multi-file selection.

---

### 6. FAQ/Install Notification
**Severity**: N/A (Standard Practice)
**Files**: `/worker.js` (lines 322-347)

**Analysis**:
Opens FAQ page on install/update (similar to Easy Auto Refresh example).

**Code Evidence**:
```javascript
const {homepage_url: page, name, version} = getManifest();
onInstalled.addListener(({reason, previousVersion}) => {
  management.getSelf(({installType}) => installType === 'normal' && storage.local.get({
    'faqs': true,
    'last-update': 0
  }, prefs => {
    if (reason === 'install' || (prefs.faqs && reason === 'update')) {
      const doUpdate = (Date.now() - prefs['last-update']) / 1000 / 60 / 60 / 24 > 45;
      if (doUpdate && previousVersion !== version) {
        tabs.create({
          url: page + '?version=' + version + (previousVersion ? '&p=' + previousVersion : '') + '&type=' + reason,
          active: reason === 'install'
        });
        storage.local.set({'last-update': Date.now()});
      }
    }
  }));
});
```

**Behavior**:
- **Install**: Opens `https://webextension.org/listing/open-in-vlc.html?version=0.4.3&type=install`
- **Update**: Opens same URL (max once every 45 days) with `&p=[old_version]&type=update`
- **Disabled by**: Setting `faqs: false` in options

**Data Transmitted**:
- Version numbers only (via URL parameters)
- No user ID, browsing data, or telemetry

**Verdict**: **NOT MALICIOUS** - Standard onboarding/changelog notification.

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `api.github.com/repos/andy-portmen/native-client/releases/latest` | Native client installer version check | None (read-only) | On-demand (user clicks "Download") |
| `webextension.org/listing/open-in-vlc.html` | FAQ/changelog page | Version numbers only | Install + updates (45-day throttle) |

### Local Communication

| Destination | Purpose | Data Transmitted |
|-------------|---------|------------------|
| Native Client (`com.add0n.node` or `org.webextension.bun`) | Launch VLC with media URL | Media URL, referrer (optional), user-agent (optional), page title (optional) |

**Data Collection**: NONE
**User Data Transmitted**: NONE (beyond current page URL/media URLs to local VLC)
**Tracking/Analytics**: NONE
**Third-Party Services**: NONE

---

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `nativeMessaging` | Required to communicate with local VLC launcher | Low (local only) |
| `storage` | Settings and preferences | Low (local only) |
| `contextMenus` | Right-click "Open in VLC" menu | Low (functional) |
| `webRequest` | Detect media files in HTTP responses | Low (read-only) |
| `scripting` | Inject media picker UI, store detected links | Low (functional) |
| `host_permissions: <all_urls>` | Detect media on any page | Medium (broad but necessary) |
| `optional: downloads` | Download native client installer | Low (optional, user-initiated) |

**Assessment**: All permissions are justified and used appropriately for a VLC launcher extension.

---

## Content Security Policy
```json
No CSP declared in manifest.json (Manifest V3 default applies)
```
**Note**: Manifest V3 extensions have built-in CSP protections that prevent inline script execution and eval().

---

## Code Quality Observations

### Positive Indicators
1. No dynamic code execution (`eval()`, `Function()`, `new Function()`)
2. No external script loading from CDNs
3. No XHR/fetch hooking or monkey-patching
4. No extension enumeration or killing
5. No residential proxy infrastructure
6. No market intelligence SDKs
7. No cookie harvesting
8. No data exfiltration to external servers
9. Clean separation of concerns (background, content, options, helper)
10. User-configurable privacy settings (disable referrer/user-agent transmission)

### Obfuscation Level
**Low** - Code is beautified JavaScript with standard minification. No deliberate obfuscation.

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage beyond self-check |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | No API interception |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Remote config/kill switches | ✗ No | No remote code loading |
| Cookie harvesting | ✗ No | No cookie access |
| GA/analytics proxy bypass | ✗ No | No analytics manipulation |
| Hidden data exfiltration | ✗ No | All network calls are transparent and documented |

---

## False Positive Analysis

### ext-analyzer Findings Explained

**Finding**: "EXFILTRATION (3 flows): chrome.storage.local.get → chrome.runtime.sendNativeMessage"

**Explanation**: The static analyzer correctly identified data flows from storage to native messaging, but flagged them as "exfiltration." However:

1. **Native messaging is LOCAL communication** - Data is sent to a native application installed on the user's machine, NOT to external servers
2. **This is the core feature** - The entire purpose of the extension is to send media URLs to VLC
3. **User-controlled data** - Only media URLs from the current page are sent, with user-configurable privacy options
4. **No sensitive data** - No cookies, passwords, browsing history, or cross-site data is transmitted

**Verdict**: These are **FALSE POSITIVES**. Native messaging to local applications is not data exfiltration.

---

## Overall Risk Assessment

### Risk Level: **CLEAN**

**Justification**:
1. **No malicious behavior detected** across all attack vectors
2. **Legitimate functionality** - Extension operates exactly as advertised (VLC launcher)
3. **No external data exfiltration** - All sensitive operations are local (native messaging to user's VLC)
4. **Minimal network activity** - Only GitHub API for installer downloads and FAQ pages
5. **User privacy controls** - Settings to disable referrer/user-agent transmission
6. **Transparent operation** - All features are user-visible and documented
7. **No tracking or analytics** - No telemetry, user IDs, or behavioral data collection

### Recommendations
- **No action required** - Extension is safe for use with ~300K users
- Users concerned about privacy can disable referrer/user-agent transmission in settings
- Native client must be installed separately (available on GitHub: andy-portmen/native-client)

### User Privacy Impact
**MINIMAL** - The extension only accesses:
- Current page URL (to detect media files and send referrer to VLC)
- Media URLs detected on current page (sent to local VLC only)
- No cross-site tracking, cookies, or history access
- No data aggregation or external transmission (except FAQ page visits)

---

## Architecture Summary

**Core Workflow**:
1. User visits page with media content (video, audio, YouTube)
2. Extension monitors `webRequest` to detect media files (via Content-Type headers)
3. Detected media URLs stored in tab-specific memory
4. User clicks extension icon or right-clicks media element
5. Extension sends URL + optional metadata to **local native client** via `chrome.runtime.sendNativeMessage()`
6. Native client launches VLC (or PotPlayer/QMPlay2) with URL as command-line argument
7. VLC plays media from original URL (with referrer/user-agent if needed for authentication)

**Key Security Properties**:
- **All communication is local** (browser ↔ native client ↔ VLC)
- **No external servers** receive user data (except anonymous FAQ page visits)
- **User controls data flow** (settings for referrer/user-agent)
- **Transparent operation** (all features visible in UI)

---

## Technical Summary

**Lines of Code**: ~1,200 (deobfuscated, excluding libraries)
**External Dependencies**: None (uses built-in Chrome APIs only)
**Third-Party Libraries**: termlib_parser.js (command-line argument parsing, MIT license)
**Remote Code Loading**: None
**Dynamic Code Execution**: None

---

## Conclusion

Open in VLC is a **clean, legitimate browser extension** that provides VLC media player integration for web browsers. The ext-analyzer correctly identified data flows to native messaging, but these are not "exfiltration" in the malicious sense - they represent the core functionality of sending media URLs to the user's locally-installed VLC application.

All network activity is limited to:
1. GitHub API for native client installer downloads (user-initiated)
2. FAQ/changelog pages on install/update (throttled, no telemetry)

No user data is collected, transmitted to external servers, or used for tracking. The extension respects user privacy with configurable settings for referrer/user-agent transmission.

**Final Verdict: CLEAN** - Safe for use by ~300,000 users. The extension delivers exactly what it promises with no hidden malicious behavior.
