# Security Analysis: V Video Downloader PoVim (pahfjgdhbjfpmeanibapkglolhkocoaj)

## Extension Metadata
- **Name**: V Video Downloader PoVim
- **Extension ID**: pahfjgdhbjfpmeanibapkglolhkocoaj
- **Version**: 1.9
- **Manifest Version**: 3
- **Estimated Users**: ~20,000
- **Developer**: Unknown
- **Analysis Date**: 2026-02-15

## Executive Summary
V Video Downloader PoVim is a Vimeo video downloader extension that provides legitimate video downloading functionality but also includes **concerning monetization mechanisms** including remote promotional content fetching, automatic affiliate tab injection, and user tracking. While the core video download functionality is legitimate, the extension engages in undisclosed advertising and tracking behaviors that violate user privacy expectations. The extension fetches promotional content from third-party servers and automatically opens hidden affiliate tabs when users navigate to certain domains.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. Remote Promotional Content Fetching
**Severity**: MEDIUM
**Files**:
- `/js/bg.js` (lines 360-384)

**Analysis**:
The background script periodically fetches promotional configuration from a third-party tracking domain `info.userlistingstats.com` every 6 hours and stores the results in local storage.

**Code Evidence** (`bg.js`):
```javascript
function s() {
  const e = 216e5; // 6 hours in milliseconds
  chrome.storage.local.get(n.S).then((t => {
    if (t[n.S] && t[n.S] + e > Date.now()) return Promise.reject("not_time_to_fetch")
  })).then((() => Promise.all([o.Ee(n.F), i.Ee()]))).then((e => {
    const [t, r] = e, o = {
      [n.J]: r,
      _n: "povim"
    };
    t && (o[n.F] = !0);
    const i = "https://info.userlistingstats.com/promo2.json?" + new URLSearchParams(o);
    return fetch(i)
  })).then((e => e.json())).then((e => {
    chrome.storage.local.set({
      [n.S]: Date.now()
    }),
    e[n.p] && chrome.storage.local.set({
      [n.p]: e[n.p]  // d_list - domain list
    }),
    e[n.k] && chrome.storage.local.set({
      [n.k]: e[n.k]  // ssid - session ID
    }),
    e[n.re] && chrome.storage.local.set({
      [n.re]: e[n.re]  // s_list
    })
  }))
}
s() // Executes on extension load
```

**Data Transmitted**:
- `ud`: Unique user identifier (generated timestamp-based ID)
- `_n`: Extension identifier ("povim")
- `isAdsAllowed`: User consent status for ads

**Data Received & Stored**:
- `d_list`: Domain coverage list for affiliate injection
- `ssid`: Server-assigned session ID for tracking
- `s_list`: Additional server-controlled list

**Privacy Concerns**:
- Creates persistent user tracking identifier (`ud`) stored in sync storage
- Unique ID generated in `/js/bg.js` module 9, lines 399-413:
```javascript
function e() {
  const e = Math.round(Date.now() / 1e3).toString(),
    t = "abcdefghijklmnopqrstuvwxyz",
    r = (e, r) => Array.from({
      length: e + Math.floor(Math.random() * (r - e + 1))
    }, (() => t[Math.floor(26 * Math.random())])).join("");
  let n = r(1, 3), o = n.length;
  for (let t = 0; t < e.length; t++) {
    n += e[t], n += Math.random() < .85 ? r(1, 3) : "", o = n.length - n.lastIndexOf("-") - 1;
    const i = t === e.length - 1;
    (!i && o >= 8 || !i && o >= 4 && Math.random() < .25) && (n += "-", o = 0)
  }
  return n
}
```
This creates a unique tracking ID like `"abc-1234-def-5678"` based on Unix timestamp plus random letters.

**Verdict**: **MEDIUM SEVERITY** - Undisclosed remote configuration and user tracking.

---

### 2. Automatic Affiliate Tab Injection
**Severity**: MEDIUM
**Files**:
- `/js/bg.js` (lines 436-503)

**Analysis**:
The extension monitors tab navigation and automatically creates hidden affiliate tabs to `browser.datarealtinne.com` when users visit domains in the remotely-fetched coverage list.

**Code Evidence** (`bg.js`):
```javascript
const c = "https://browser.datarealtinne.com/link/";

const d = (e, t, r) => {
  a ? a.tab_id === e && "complete" === t.status && r.url && r.url.includes(a.hostname) &&
    (clearTimeout(a.rt), a = null, setTimeout((() => {
      chrome.tabs.remove(e)  // Auto-closes tab after 1 second
    }), 1e3))
  : t.url && Promise.resolve().then((() => {
      const r = new URL(t.url);
      if (!r.protocol.startsWith("http") || r.hash || r.port) return !1;
      if (l[e]) return !1;
      l[e] = !0, setTimeout((function() {
        delete l[e]
      }), 1e4);
      const o = r.hostname;
      return n.Me(o)  // Check if hostname in coverage list
    })).then((e => e && i.Te(e).then((t => !t && i.be(e).then((() => !0))))))
    .then((e => e && $(t.url)))  // Create affiliate tab
};

function $(e) {
  const t = new URL(e).hostname;
  let r;
  const n = setTimeout((() => {
    chrome.tabs.remove(r), a = null
  }), 1e4);  // 10-second timeout
  return h(e).then((e => chrome.tabs.create({
    url: e,
    pinned: true,
    index: 0,
    active: false  // Created in background (hidden)
  }))).then((e => {
    r = e.id, a = {
      hostname: t,
      rt: n,
      tab_id: e.id
    }
  }))
}

function h(e) {
  return chrome.storage.local.get(o.k).then((t => {
    const r = t[o.k] || "",  // Session ID from server
      n = new URLSearchParams({
        sid: r,
        dest: e  // User's actual destination URL
      });
    return `${c}?${n}`  // https://browser.datarealtinne.com/link/?sid=...&dest=...
  }))
}
```

**Behavior**:
1. Extension monitors all tab navigations via `chrome.tabs.onUpdated`
2. When user navigates to a domain in the server-provided `d_list`
3. Creates hidden background tab to `browser.datarealtinne.com/link/?sid=[sessionId]&dest=[userUrl]`
4. Tab is pinned, inactive (hidden from user)
5. After destination loads or 10s timeout, tab auto-closes

**Data Exfiltrated**:
- User's browsing destination URL
- Server-assigned session ID
- Implicit: User's IP address (via HTTP request)

**User Consent**:
The extension shows a privacy policy modal on first use (`app.js` lines 296-315), but the consent text does not clearly disclose affiliate tab injection or tracking:
```javascript
const d = `<a href="${o().G}" target="_blank" class="povim-link">${i}</a>`,
  a = `
    <div class="povim-modal-root">
      <div class="povim-card">
        <div class="povim-content">
          <div class="povim-text">
            ${chrome.i18n.getMessage("privacyText",[d])}
          </div>
          <button id="js-povim-accept" class="povim-btn">
            ${chrome.i18n.getMessage("modalAccept")}
          </button>
        </div>
      </div>
    </div>
  `;
```
The modal links to `https://sites.google.com/view/povim-video-downloader` but does not explicitly mention automatic tab creation or affiliate monetization.

**Verdict**: **MEDIUM SEVERITY** - Undisclosed background tab injection for affiliate tracking.

---

### 3. User Tracking and Session Management
**Severity**: MEDIUM
**Files**:
- `/js/bg.js` (module 9, lines 396-429)
- `/js/bg.js` (module 11, lines 504-524)
- `/js/bg.js` (module 12, lines 525-551)

**Analysis**:
The extension implements a comprehensive tracking system with unique user IDs, session IDs, domain coverage lists, and visit caching.

**Tracking Components**:

1. **Unique User ID (`ud`)**:
   - Generated on first run using timestamp + randomized letter patterns
   - Stored in `chrome.storage.sync` for cross-device persistence
   - Sent to `info.userlistingstats.com` on every config fetch

2. **Server Session ID (`ssid`)**:
   - Received from `info.userlistingstats.com/promo2.json`
   - Stored locally and attached to affiliate tab URLs
   - Used to track user navigation events server-side

3. **Domain Coverage List (`d_list`)**:
   - Array of domains received from remote server
   - Checked against user navigation to trigger affiliate tabs
   - Updated every 6 hours

4. **Visit Cache (`d_cache`)**:
   - Tracks which domains have already triggered affiliate tabs
   - 30-day expiration (`2592e5` milliseconds)
   - Prevents duplicate affiliate triggers per domain

**Code Evidence** (visit cache, `bg.js` module 12):
```javascript
const t = 2592e5; // 30 days
return {
  Ne: () => chrome.storage.local.get(n.v).then((r => {
    e = r[n.v] || {};
    const o = Object.keys(e).length;
    e = Object.fromEntries(Object.entries(e).filter((([e, r]) =>
      r + t > Date.now()))), // Filter expired entries
    o > Object.keys(e).length && chrome.storage.local.set({
      [n.v]: e
    })
  })),
  be: t => (e[t] = Date.now(), chrome.storage.local.set({
    [n.v]: e
  })),
  Te(t) {
    const r = this;
    return Promise.resolve().then((() => {
      if (!e) return r.Ne()
    })).then((() => r.Ue(t)))
  },
  Ue: t => !!e[t]
}
```

**Data Persistence**:
- User ID synced across devices via `chrome.storage.sync`
- Session ID and domain lists in `chrome.storage.local`
- Visit cache expires after 30 days

**Verdict**: **MEDIUM SEVERITY** - Persistent cross-device user tracking without clear disclosure.

---

### 4. Privacy Policy Consent Flow
**Severity**: LOW (Informational)
**Files**:
- `/js/app.js` (lines 296-315)
- `/js/options.js` (lines 145-164)

**Analysis**:
The extension implements a consent modal on first use that requests permission for "promotional content" delivery.

**User-Facing Messages** (from `_locales/en/messages.json`):
- `privacyPolicyLink`: "Privacy Policy"
- `privacyText`: Text that includes link to privacy policy
- `modalAccept`: "Accept" button text

**Consent Storage**:
```javascript
// Check policy acceptance
s.de: () => Promise.all([chrome.storage.sync.get(i.h),
  chrome.storage.local.get(i.h)]).then((([t, o]) =>
    t && void 0 !== t[i.h] ? t[i.h] :
    !(!o || void 0 === o[i.h]) && o[i.h]
  ))

// Update ads status
s.me: function(t) {
  return this.nt({
    [i.M]: t,  // isAdsAllowed
    [i.h]: !0   // isPolicyAccept
  })
}
```

**User Control**:
The extension includes an options page (`html/options.html`) with a checkbox to enable/disable promotional content:
```javascript
let t = e.checked || !1;
o.Z({
  title: "upd_ads_status",
  status: t
})
```

When ads are disabled, the tab injection listener is removed:
```javascript
chrome.storage.onChanged.addListener(((e, t) => {
  "sync" === t && e[o.F] && !1 === e[o.F].newValue && u()
}))

function u() {
  chrome.tabs.onUpdated.removeListener(d)  // Remove tab monitor
}
```

**Privacy Policy Location**: `https://sites.google.com/view/povim-video-downloader`

**Transparency Issues**:
- Privacy policy link is not directly accessible in Chrome Web Store listing
- Modal consent text does not explicitly mention automatic tab creation
- Does not clearly explain unique ID generation and tracking

**Verdict**: **LOW SEVERITY** - Consent mechanism exists but lacks transparency.

---

## Network Analysis

### External Domains Contacted

| Domain | Purpose | Data Sent | Trigger |
|--------|---------|-----------|---------|
| `player.vimeo.com` | Video config fetching | Video IDs, storage data, tab URLs | User downloads video |
| `api.vimeo.com` | JWT token & video metadata | Video IDs, authorization headers | Video downloads |
| `vimeo.com` | JWT authentication | None (receives JWT token) | Background fetch every 6h |
| `info.userlistingstats.com` | Remote config & tracking | User ID, ads consent status | Every 6 hours |
| `browser.datarealtinne.com` | Affiliate tracking | Session ID, destination URL | User navigates to coverage domains |
| `sites.google.com` | Privacy policy | None | User clicks policy link |
| `chromewebstore.google.com` | Rate prompts | Extension ID | After 5 successful downloads |

### ext-analyzer Findings Context

The ext-analyzer flagged 5 HIGH-severity exfiltration flows:
1. `chrome.storage.local.get → fetch(player.vimeo.com)` - **LEGITIMATE**: Fetching video config
2. `chrome.storage.sync.get → fetch(player.vimeo.com)` - **LEGITIMATE**: Fetching video config
3. `chrome.tabs.query → fetch(player.vimeo.com)` - **LEGITIMATE**: Video download
4. `chrome.storage.local.get → fetch` (offscreen.js) - **LEGITIMATE**: Video segment downloads
5. `chrome.storage.local.get → fetch(player.vimeo.com)` (app.js → bg.js) - **LEGITIMATE**: Video metadata

**Attack Surface Findings**:
- Message handlers accepting data from options.js, bg.js, offscreen.js to trigger fetch calls
- innerHTML injection with `chromewebstore.google.com` - used for rate-us modal (low risk)
- CSP allows `'unsafe-eval'` in extension pages - required for WASM video processing

**Code Execution Risk**:
The CSP policy includes `'wasm-unsafe-eval'` which is required for FFmpeg.js video merging in the offscreen document:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'; worker-src 'self' 'wasm-unsafe-eval';"
}
```

This is **LEGITIMATE** use for video processing (merging separate audio/video streams from Vimeo).

---

## Permission Analysis

### Declared Permissions
| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `downloads` | Required for saving downloaded videos | LOW |
| `offscreen` | Used for FFmpeg video merging (Manifest V3 worker alternative) | LOW |
| `webRequest` | Captures Vimeo config URLs from network requests | MEDIUM |
| `tabs` | Required for tab injection, video page detection | MEDIUM |
| `storage` | Stores settings, tracking IDs, remote config | MEDIUM |

### Host Permissions
- `https://*.vimeo.com/*` - Necessary for content script injection and video downloading

### Permission Concerns
1. **webRequest + tabs**: Combined, these allow monitoring all user navigation and injecting affiliate tabs
2. **storage.sync**: Enables cross-device tracking persistence
3. **No activeTab pattern**: Extension could monitor all Vimeo navigation without explicit user interaction

---

## Technical Deep-Dive: Video Download Mechanism

The extension's core functionality is legitimate Vimeo video downloading using multiple fallback strategies:

**Download Flow**:
1. Content script detects Vimeo video page
2. User clicks download button
3. Extension fetches video config from `player.vimeo.com/video/[ID]/config`
4. Parses available quality options (progressive MP4 or DASH streams)
5. For progressive: Direct download via `chrome.downloads.download()`
6. For DASH:
   - Fetches separate video/audio segments
   - Downloads to ArrayBuffers in offscreen document
   - Merges using FFmpeg.wasm
   - Creates blob URL and triggers download

**Code Evidence** (offscreen.js, FFmpeg merge):
```javascript
async q(t, e, n) {
  const i = this;
  null === this.F && (this.F = new o, await this.F.$({
    coreURL: `chrome-extension://${chrome.runtime.id}/js/wasm/ffmpeg-core.js`,
    wasmURL: `chrome-extension://${chrome.runtime.id}/js/wasm/ffmpeg-core.wasm`
  })),
  await this.F.P("video.mp4", t),
  await this.F.P("audio.mp4", e),
  await this.F.v("-i video.mp4 -i audio.mp4 -map 0:v -map 1:a -c:v copy -y output.mp4".split(" "));
  return (await this.F.k("output.mp4")).buffer
}
```

This is standard FFmpeg usage for muxing streams and is **LEGITIMATE**.

---

## Monetization Analysis

The extension uses multiple monetization strategies:

1. **Affiliate Tab Injection**: Primary revenue via `browser.datarealtinne.com` redirects
2. **Rate-Us Prompts**: After 5 successful downloads, opens Chrome Web Store review page
3. **Remote Configuration**: Server controls which domains trigger affiliate tabs

**Rate-Us Flow** (`app.js`, module 14):
```javascript
se(t) {
  chrome.storage.local.get(null, (function(o) {
    if (o && void 0 !== o.rate_us && !0 === o.rate_us) return t(!0);
    if (o && o.success_dw && parseInt(o.success_dw) > 5) return t(!1);
    let e = (o && o.success_dw ? parseInt(o.success_dw) : 0) + 1;
    return 5 === e && chrome.storage.local.set({
      rate_us: !0
    }, (function() {
      t(!0)
    })), chrome.storage.local.set({
      success_dw: e
    }), t(!1)
  }))
}
```

After 5 downloads, opens:
```javascript
window.open(n.v + "/reviews")
// https://chromewebstore.google.com/detail/[extension-id]/reviews
```

This is **ACCEPTABLE** behavior for free extensions.

---

## WASM Usage Analysis

The extension includes WebAssembly binaries for FFmpeg video processing:

**Files**:
- `/js/wasm/ffmpeg-core.js` (not readable - binary loader)
- `/js/wasm/ffmpeg-core.wasm` (compiled FFmpeg)

**Usage Context**:
WASM is loaded exclusively in the offscreen document for merging Vimeo's separate video and audio streams. This is necessary because Vimeo serves DASH adaptive streams as separate files.

**Risk Assessment**: **LOW** - WASM is standard for FFmpeg.js and is required for the extension's core functionality.

---

## Obfuscation Analysis

The extension code is **heavily obfuscated** with:
- Webpack module bundling
- Variable name mangling (single letters: `t`, `e`, `o`, `r`, `n`)
- String constant extraction
- Control flow flattening

**Evidence of Obfuscation** (`bg.js`):
```javascript
var e = [, e => {
  e.exports = function() {
    return {
      t(e, t, r) {
        fetch(e, t).then((e => {
          if (200 !== e.status) throw new Error("fetch err");
          return e.json()
        })).then(r)
      },
      i: (e, t) => fetch(e, t).then((e => {
        if (200 !== e.status) throw new Error("fetch err");
        return e.json()
      })),
      // ... 80+ more single-letter method names
```

String constants extracted to module 2:
```javascript
e => {
  e.exports = function() {
    return {
      p: "d_list",
      v: "d_cache",
      P: "get_video_info",
      S: "rq_t",
      // ... 40+ more obfuscated constants
```

**Purpose**: Likely to hide tracking and monetization logic from casual inspection.

**Verdict**: Obfuscation combined with undisclosed tracking is a **RED FLAG**.

---

## Comparison to Similar Extensions

Legitimate Vimeo downloaders typically:
- Do NOT fetch remote configuration from third-party tracking domains
- Do NOT create hidden affiliate tabs
- Do NOT implement persistent cross-device user tracking
- DO clearly disclose any monetization in store listing and privacy policy

**Examples of Clean Behavior**:
- Download buttons only on Vimeo
- Direct download via `chrome.downloads` API
- No network requests beyond Vimeo API
- Optional donation links (transparent)

**V Video Downloader PoVim** differs by including undisclosed tracking and affiliate injection.

---

## Recommendations

### For Users:
1. **Be Aware**: Extension creates hidden background tabs for affiliate tracking
2. **Review Permissions**: Consider if tracking is acceptable trade-off for free functionality
3. **Check Settings**: Disable "promotional content" in extension options if desired
4. **Monitor Network**: Use browser DevTools to observe affiliate tab creation
5. **Alternative**: Consider browser.datarealtinne.com blocking via hosts file or network rules

### For Developers/Reviewers:
1. **Transparency Required**: Chrome Web Store listing should disclose affiliate monetization
2. **Privacy Policy**: Should explicitly mention unique ID generation, tab injection, and data sharing
3. **Consent Modal**: Should clearly explain tracking before collecting consent
4. **Permission Justification**: webRequest + tabs combination enables broad surveillance
5. **Code Review**: Obfuscation hinders security review and violates developer program policies

### For Chrome Web Store:
1. **Review**: Extension may violate policies on undisclosed monetization
2. **Disclosure**: Affiliate tab injection should be clearly stated in listing
3. **Privacy**: User tracking via unique IDs requires clear opt-in consent

---

## Conclusion

V Video Downloader PoVim provides legitimate Vimeo video downloading functionality using industry-standard techniques (FFmpeg.wasm, DASH stream merging). However, the extension includes **concerning privacy and transparency issues**:

**Legitimate Components**:
- Video config fetching from Vimeo APIs
- Progressive and DASH video downloads
- FFmpeg.wasm video/audio merging
- Rate-us prompts after 5 downloads

**Problematic Components**:
- Remote configuration fetching from tracking domain
- Automatic hidden affiliate tab injection
- Persistent unique user ID generation and tracking
- 30-day visit caching to track user behavior
- Code obfuscation to hide tracking logic
- Insufficient consent disclosure

**Final Verdict**: **MEDIUM RISK**

The extension is not malware and provides real value to users, but engages in **undisclosed tracking and affiliate injection** that violates user privacy expectations. Users who accept affiliate-based monetization in exchange for free software may find this acceptable, but the lack of transparency is problematic.

**Recommended Actions**:
- Developer should add clear disclosure to Chrome Web Store listing
- Privacy policy should explicitly document tracking and tab injection
- Consent modal should be more specific about data collection
- Consider making affiliate monetization opt-in rather than opt-out

---

**Analysis completed**: 2026-02-15
**Analyst**: Claude Sonnet 4.5 (Automated Security Analysis)
