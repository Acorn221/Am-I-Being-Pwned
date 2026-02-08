# Flash Copilot (闪记) - Security Vulnerability Report

**Extension ID:** klokphhomfboclhpijjcgbpdjoccaagc
**Version:** 11.5.0
**Manifest:** V3
**Marketed As:** "Flash Copilot - Powered by DeepSeek" -- AI assistant with web notes, bilingual translation, bookmarks
**Backend Domain:** kjeek.com (registered to Chinese entity)
**Secondary Domain:** switcher.kjeek.com (HTTP, not HTTPS)
**Triage Flags:** 29 T1, 34 T2, 28 V1, 20 V2

---

## Executive Summary

Flash Copilot is a Chinese-developed productivity extension that functions as a web annotation, bookmark manager, translation tool, and video note-taking assistant. It markets itself as "DeepSeek powered" but the DeepSeek integration is limited to translation features. The extension requests extremely broad permissions (history, tabs, bookmarks, scripting, `<all_urls>`) and injects 7 content scripts into every page the user visits.

**The extension is NOT outright malware**, but exhibits several **MEDIUM-HIGH risk** privacy and security concerns:

1. **Broad browsing history harvesting** (10,000 entries, 1 year lookback) for a search feature that does not require it at this scale
2. **Cross-origin ChatGPT session token theft** -- the extension fetches the user's ChatGPT `accessToken` from `chatgpt.com/api/auth/session` using credentials, then uses it to read, list, and delete ChatGPT conversations via the backend API
3. **Telemetry beacon to kjeek.com** that transmits device fingerprint, OS, browser, install age, usage statistics, login status, VIP status, and feature counters
4. **Hardcoded AES-128-GCM encryption keys** embedded in every JS bundle, used to encrypt user identity tokens client-side with no key rotation
5. **html2canvas page screenshots** captured on every page (when workspace features are enabled) and sent to the background script
6. **HTTP (not HTTPS) switcher endpoint** at `http://switcher.kjeek.com` for user/guest API calls -- vulnerable to MITM
7. **Full bookmark tree access and cloud sync** to kjeek.com servers
8. **Annotation content with page URLs uploaded to kjeek.com** including the full page URL, content, keywords, and images

The extension does NOT exhibit: extension enumeration, ad injection, search manipulation, proxy infrastructure, or obfuscated/packed malicious payloads. The code is webpack-bundled but not deliberately obfuscated beyond standard minification.

---

## Vulnerability Details

### VULN-01: Excessive Browsing History Harvesting
**Severity:** MEDIUM | **CVSS 3.1:** 5.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)
**Files:** `background.js:761-768`, and duplicated across ALL 17 JS bundles

```javascript
const A = (new Date).getTime(), t = await chrome.history.search({
    text: '',
    maxResults: 1e4,        // 10,000 results
    startTime: A - 31536e6  // 1 year lookback (365 days in ms)
});
let r = 0, n = [];
for (const o of t) if ((q(o.title, e) || q(o.url, e)) && n.push(o), r++, r > 100) break;
```

**Analysis:** The extension searches the user's entire browsing history (up to 10,000 entries spanning one full year) every time the user triggers the "search-flash" unified search feature. While it filters results client-side to 100 matches, the full 10,000-entry dataset is pulled into memory first. This data includes page titles and full URLs. The history data is used for a local search feature and the results are displayed in the popup UI -- they are NOT directly exfiltrated to kjeek.com. However, the data flows through the background script where it could theoretically be intercepted if the extension were updated with malicious code.

**PoC Scenario:** User triggers Alt+Comma (page menu) and types a search. The extension silently pulls 10,000 history entries including banking sites, medical portals, and private URLs. If a future update adds telemetry to this code path, the entire browsing profile is exposed.

**Verdict:** TRUE POSITIVE -- excessive data access beyond minimum necessary. The search could use `maxResults: 100` directly instead of pulling 10,000 then filtering.

---

### VULN-02: Cross-Origin ChatGPT Session Token Theft and Conversation Access
**Severity:** HIGH | **CVSS 3.1:** 7.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)
**File:** `background.js:18335-18400`

```javascript
async function n() {
    try {
        let e = await fetch('https://chatgpt.com/api/auth/session', {
            method: 'GET',
            mode: 'cors',
            credentials: 'include'   // Sends ChatGPT cookies
        });
        return (await e.json()).accessToken;  // Steals the access token
    } catch (e) {}
}

// Uses stolen token to list conversations
const r = await fetch(`https://chatgpt.com/backend-api/conversations?offset=${t}&limit=${A}&order=updated`, {
    headers: { authorization: 'Bearer ' + e },
    method: 'GET', mode: 'cors'
});

// Uses stolen token to read individual conversations
let t = await fetch('https://chatgpt.com/backend-api/conversation/' + A, {
    headers: { authorization: 'Bearer ' + e },
    method: 'GET', mode: 'cors'
});

// Uses stolen token to DELETE conversations (set is_visible: false)
let t = await fetch('https://chatgpt.com/backend-api/conversation/' + A, {
    headers: { authorization: 'Bearer ' + e, 'Content-Type': 'application/json' },
    method: 'PATCH', mode: 'cors',
    body: JSON.stringify({ is_visible: false })
});
```

**Analysis:** The extension leverages its `<all_urls>` host permission to make cross-origin requests to `chatgpt.com` with the user's cookies (`credentials: 'include'`). It extracts the ChatGPT `accessToken` and then uses it to:
1. **List all conversations** (up to 100 at a time)
2. **Read full conversation contents** by ID
3. **Delete conversations** by setting `is_visible: false`

This is triggered by the `sync-chats-1` message handler (background.js:1536) which runs once per day. The conversations are stored in local IndexedDB via Dexie. While this appears to be a "ChatGPT conversation manager" feature, the user may not realize the extension has full read/write/delete access to their entire ChatGPT history.

**PoC Scenario:** User installs Flash Copilot. Without explicit consent per-conversation, the extension silently reads all ChatGPT conversations (which may contain proprietary code, medical questions, legal queries, passwords shared in chat, etc.) and stores them locally. A future update could exfiltrate this data to kjeek.com.

**Verdict:** TRUE POSITIVE -- unauthorized cross-origin credential reuse to access a third-party service's private API.

---

### VULN-03: Device Fingerprint + Usage Telemetry Beacon to kjeek.com
**Severity:** MEDIUM | **CVSS 3.1:** 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
**File:** `background.js:12182-12214` (sign endpoint), `background.js:2160-2168` (data assembly)

```javascript
// Data assembly (background.js:2166):
let A = await Object(n.h)(),              // device ID
    t = Object(r.H)(),                     // OS
    o = Object(r.F)(),                     // browser
    i = await Object(n.j)(),              // install days
    a = chrome.runtime.getManifest().version,
    s = ue,                                // dl (download limit flag)
    c = le,                                // fl (feature limit flag)
    u = ie,                                // vl (version limit)
    l = await Object(n.E)();              // ??? joined with comma
    d = await Object(n.q)(),              // lkt (last key time)
    h = await Object(n.p)(),              // lkhs (last key history?)
    p = await Object(n.v)(),              // user info (nickname, isVip)
    g = await Object(n.x)();              // usage stats total

// POST to kjeek.com/xapi/open/sign
let B = {
    device: e, version: A, os: t, browser: r,
    installDays: n, dl: o, fl: i, vl: a,
    tksY: s, lkt: c, lkhs: u, nn: l,
    ls: d, iv: h, tm: f, tt: p
};
fetch('https://kjeek.com/xapi/open/sign', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', device: e },
    credentials: 'include',
    body: JSON.stringify(B)
})
```

**Analysis:** On every tab activation (after 60-second cooldown), the extension sends a comprehensive telemetry beacon to `kjeek.com/xapi/open/sign` containing: device fingerprint, OS, browser type, extension version, days since install, feature usage flags, last activity timestamp, login status, VIP status, and aggregate usage statistics. A separate `stats` endpoint (background.js:12346) also receives usage counters.

**Verdict:** TRUE POSITIVE -- telemetry without clear disclosure. The data enables user profiling and activity tracking.

---

### VULN-04: Hardcoded AES-128-GCM Encryption Key
**Severity:** MEDIUM | **CVSS 3.1:** 5.9 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N)
**File:** `background.js:10972-10989` (and duplicated in all 17 JS files)

```javascript
const n = r('ahc56J2DTDJDYxHJ'),  // AES-128 key (16 bytes)
      o = r('VBkC68eZ3QxU');       // GCM IV (12 bytes)

async function a(e) {
    const t = (new TextEncoder).encode(e),
          r = await i(n),
          a = await window.crypto.subtle.encrypt({
              name: 'AES-GCM', iv: o
          }, r, t);
    return Array.from(new Uint8Array(A)).map(e => e.toString(16).padStart(2,'0')).join('');
}
```

**Analysis:** The extension uses AES-128-GCM to encrypt user identity tokens (nickname + VIP status) before sending them via messages. However:
1. The key `ahc56J2DTDJDYxHJ` and IV `VBkC68eZ3QxU` are hardcoded in plaintext in ALL 17 JavaScript files
2. The IV is static (never changes), which is a critical misuse of AES-GCM -- reusing an IV with the same key completely breaks GCM's authentication guarantees
3. Any attacker who reads the extension source (it's a public CWS extension) can decrypt all tokens

**Verdict:** TRUE POSITIVE -- cryptographic misuse. Static IV + hardcoded key = no real encryption. The `fct` token sent to kjeek.com API endpoints can be trivially forged.

---

### VULN-05: html2canvas Page Screenshots on Every Page
**Severity:** MEDIUM | **CVSS 3.1:** 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
**File:** `content-frame.js:1245-1255` (trigger), `content-frame.js:25796-25809` (capture)

```javascript
// Triggered when workspace/tab features are enabled
async function C() {
    b && (E || (E = !0, setTimeout(() => {
        Object(a.a)(document.body, (function(e) {
            Object(s.qb)({
                name: 'capture-tab',
                imgURL: e                // Base64 PNG screenshot
            });
        })), E = !1;
    }, 1e4)));
}

// The capture function uses html2canvas:
function l(e, t) {
    n()(e, { useCORS: true, logging: false }).then(e => {
        var A = /* crop to viewport */;
        return t && t(A), A;
    });
}
```

**Analysis:** When the workspace/tab management feature is enabled, the content script renders the entire `document.body` to a canvas using html2canvas, crops it to the viewport, and converts it to a base64 PNG data URL. This screenshot is sent to the background script via `capture-tab` message and stored in memory for the tab switcher UI. The screenshot is taken on scroll events with a 10-second debounce. The screenshots appear to stay local (used for tab preview thumbnails), but the full page content -- including sensitive data visible on screen -- is captured.

**Verdict:** TRUE POSITIVE -- captures page content including potentially sensitive information (banking dashboards, emails, medical records). Data stays local but creates an attack surface if a future update exfiltrates it.

---

### VULN-06: HTTP (Unencrypted) Switcher API Endpoint
**Severity:** MEDIUM | **CVSS 3.1:** 5.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N)
**File:** `background.js:19303`

```javascript
const r = false,
      n = 'http://switcher.kjeek.com',          // HTTP, not HTTPS!
      o = n + '/api/user/current',
      i = n + '/api/guest';
```

**Analysis:** The `switcher.kjeek.com` endpoint is accessed over plain HTTP. While the `d()` function that checks this currently always returns `false` (the feature appears disabled), the endpoint URLs are present and could be activated by a server-side config change. Any data sent to this endpoint (user status, authentication) would be transmitted in cleartext, vulnerable to MITM attacks on public WiFi or compromised networks.

**Verdict:** TRUE POSITIVE -- insecure transport. Currently inactive but the code path exists.

---

### VULN-07: Full Bookmark Tree Exfiltration to kjeek.com
**Severity:** MEDIUM | **CVSS 3.1:** 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
**File:** `background.js:613-670` (bookmark access), `background.js:2100-2119` (cloud sync)

```javascript
// Reads entire bookmark tree
const A = se(await chrome.bookmarks.getTree(), e => !e.url && e.id > 0)

// Syncs annotations (which include URLs) to cloud
for (let n of e) {
    let e = await Object(i.s)(n.url);   // Get all annotations for URL
    for (let A of e) n.title || (n.title = A.title), delete A.url;
    n.annos = e;
    let o = await Object(f.L)(t, n, Q, U);  // Upload to kjeek.com
}
```

**Analysis:** The extension reads the full bookmark tree (all folders, all bookmarks with URLs and titles) and uses it for search. For VIP users, it also syncs annotation data (which includes page URLs, titles, content, and keywords) to `kjeek.com/xapi/annotation`. The bookmark count is sent as part of telemetry (`Se.bookmarksCnt`).

**Verdict:** TRUE POSITIVE -- bookmark data and annotation content (including URLs of annotated pages) are transmitted to Chinese servers.

---

### VULN-08: Broad Content Script Injection on All Pages
**Severity:** LOW-MEDIUM | **CVSS 3.1:** 3.7 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N)
**File:** `manifest.json:133-149`

```json
"content_scripts": [{
    "matches": ["<all_urls>"],
    "js": [
        "content-frame.js", "outline-frame.js", "highlight-frame.js",
        "video-notes-frame.js", "translate-frame.js", "video2pdf-frame.js",
        "anno-frame.js"
    ],
    "run_at": "document_end"
}]
```

**Analysis:** Seven content scripts are injected into EVERY page the user visits, including banking sites, email, healthcare portals, etc. The content scripts:
- Create a full-page iframe overlay for the UI
- Observe DOM mutations via MutationObserver
- Read page headings/structure for outline generation
- Can capture page screenshots via html2canvas
- Read page images and links
- On `chatgpt.com`, read and interact with conversation content

While the content scripts primarily support legitimate features (translation, annotations, outlines), the sheer attack surface is concerning.

**Verdict:** TRUE POSITIVE -- unnecessarily broad injection scope. Many features (video notes, PDF tools) only need specific site access.

---

## False Positive Analysis

| Flag Category | Example Location | Assessment | Explanation |
|---|---|---|---|
| `dynamic_function` (new Function) | `background.js:5535`, `background.js:13405`, etc. | **FALSE POSITIVE** | AJV JSON Schema validator library generates validation functions dynamically. Standard library pattern (`new Function('self','RULES','formats',...)`). Present in all bundles. |
| `dynamic_function` (Function('return this')) | `background.js:18417`, `content-frame.js:17808`, etc. | **FALSE POSITIVE** | Standard global-this polyfill pattern: `t = t \|\| new Function('return this')()`. Used by webpack/regenerator-runtime to get global scope. |
| `dynamic_function` (regeneratorRuntime) | `background.js:17203` | **FALSE POSITIVE** | `Function('r', 'regeneratorRuntime = r')(n)` -- standard regenerator-runtime polyfill for async/await support. |
| `dynamic_eval` (eval/require) | `main.js:62541` | **FALSE POSITIVE** | `const worker = eval('require')(this.workerSrc)` -- Tesseract.js OCR library worker loading pattern. Only triggers in Node.js context (not in extension). |
| `dynamic_script_exec` (new Function for setImmediate) | `background.js:5535`, `content-frame.js:4995` | **FALSE POSITIVE** | `'function' != typeof e && (e = new Function('' + e))` -- Dexie.js/setImmediate polyfill converting string callbacks to functions. Library code. |
| `script_injection` (createElement script) | `content-frame.js:3392-3393` | **FALSE POSITIVE** | setImmediate polyfill using `onreadystatechange` on script elements. Standard async scheduling pattern, not remote code injection. |
| `broad_content_script` | `manifest.json:134-136` | **TRUE POSITIVE** | See VULN-08 above. `<all_urls>` match is overly broad. |
| `history_access` | `background.js:761` | **TRUE POSITIVE** | See VULN-01 above. Legitimate feature but excessive scope. |
| html2canvas/toDataURL | `content-frame.js:25796` | **TRUE POSITIVE** | See VULN-05. Page screenshot capture. |
| `clipboard` references | `background.js:10780-10781` | **FALSE POSITIVE** | SpreadJS spreadsheet library constants (`CLIPBOARD_READER`, `CLIPBOARD_WRITER`). String constants in a spreadsheet engine, not actual clipboard access. |
| `screenshot` references | `video-notes-frame.js:1410` | **PARTIAL TRUE POSITIVE** | Video screenshot feature for taking notes on YouTube videos. Captures video frame, not full page. Legitimate feature for the stated purpose. |
| XMLHttpRequest | `background.js:22776-22782` | **FALSE POSITIVE** | html2canvas library's XHR capability detection. Not used for data exfiltration. |
| `crypto.subtle` usage | `background.js:5995` | **FALSE POSITIVE** | Dexie.js database library using SHA-512 for internal operations. Not related to data encryption/exfiltration. |
| `importScripts` | `background.js:17378` | **FALSE POSITIVE** | Tesseract.js OCR worker spawning. Creates a worker blob with `importScripts` to load the OCR engine. Legitimate library usage. |
| `localStorage` | `background.js:9267` | **FALSE POSITIVE** | Dexie.js storage mutation detection. Library internal signaling mechanism. |

---

## Domain Analysis

| Domain | Protocol | Purpose | Risk |
|---|---|---|---|
| `kjeek.com` | HTTPS | Primary backend -- user auth, annotations, books, video notes, stats, telemetry | **MEDIUM** -- Chinese-registered, receives browsing data |
| `switcher.kjeek.com` | **HTTP** | User/guest API (currently disabled via `return false`) | **HIGH** -- Unencrypted, MITM vulnerable |
| `chatgpt.com` | HTTPS | Cross-origin session theft for conversation sync | **HIGH** -- Unauthorized API access |
| `translate.googleapis.com` | HTTPS | Google Translate API (free tier) | LOW |
| `edge.microsoft.com` | HTTPS | Microsoft Translator auth token | LOW |
| `transmart.qq.com` | HTTPS | Tencent Translation API | LOW |
| `www.youdao.com` | HTTPS | Youdao dictionary iframe embed | LOW |
| `tessdata.projectnaptha.com` | HTTPS | Tesseract.js OCR language data | LOW |

---

## Data Flow Summary

### Data Collected Locally
- Full browsing history (10,000 entries, 1 year)
- All open tabs (URLs, titles, window IDs)
- Full bookmark tree
- Page screenshots (base64 PNG)
- ChatGPT conversations (full content)
- Page structure/headings (outline)
- Page images and links
- User annotations and highlights

### Data Sent to kjeek.com
- Device fingerprint (device ID, OS, browser)
- Extension version and install age
- Usage statistics (feature counters, total actions)
- Login status, VIP status, nickname
- Annotation content with page URLs
- Book/PDF uploads
- Video notes
- Translation requests (to Tencent API via kjeek.com proxy)
- Bookmark count (not full tree, just count)

### Data NOT Sent (stays local)
- Browsing history results (used for local search only)
- Page screenshots (stored in memory for tab preview)
- ChatGPT conversations (stored in local IndexedDB)
- Full bookmark tree (only count is sent)

---

## Overall Risk Assessment

### Rating: **MEDIUM-HIGH**

**Justification:**

The extension is a legitimate productivity tool with real features (translation, annotation, bookmarks, video notes). It is NOT outright malware -- there is no obfuscated payload, no ad injection, no extension killing, and no residential proxy infrastructure.

However, it exhibits several concerning patterns:

1. **Permission overcollection** -- `history`, `bookmarks`, `<all_urls>`, `scripting` permissions are broader than necessary for most features
2. **Cross-origin credential abuse** -- stealing ChatGPT session tokens to read/write/delete conversations is a serious privacy violation
3. **Persistent telemetry** -- device fingerprinting and usage tracking to Chinese servers without clear user consent
4. **Cryptographic negligence** -- hardcoded AES key with static IV provides zero security
5. **Broad content injection** -- 7 content scripts on all pages creates massive attack surface for future malicious updates

The biggest risk factor is the **update vector**: kjeek.com already receives device IDs and usage data. A future extension update (auto-applied by Chrome) could activate the currently-disabled `switcher.kjeek.com` endpoint, begin exfiltrating the locally-collected browsing history, ChatGPT conversations, or page screenshots with minimal code changes.

**Recommendation:** Users should be warned about the ChatGPT session access and broad history harvesting. The extension should be flagged for CWS policy review regarding cross-origin credential usage and undisclosed telemetry.
