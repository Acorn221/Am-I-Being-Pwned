# Security Analysis: Popup Blocker Pro

**Extension ID:** kiodaajmphnkcajieajajinghpejdjai
**Version:** 2.0.5
**Risk Level:** MEDIUM
**User Count:** 300,000

## Executive Summary

Popup Blocker Pro is a popup-blocking extension that intercepts `window.open()` calls to prevent unwanted popup windows. While the core blocking functionality appears legitimate, the extension collects and transmits browsing data to a developer-controlled server (`api.popup-blocker.org`) without adequate disclosure. This includes full URLs of visited pages and inventories of third-party scripts loaded on those pages. Additionally, the extension contains a postMessage handler vulnerability that lacks origin validation.

## Risk Classification: MEDIUM

**Justification:** The extension collects browsing data (URLs visited, script inventories) and sends it to a third-party server without clear user disclosure in the privacy policy context typically expected for such behavior. This falls into the MEDIUM category: disclosed data collection practices that may have undisclosed aspects, or security vulnerabilities affecting user privacy.

## Vulnerabilities & Concerns

### 1. Undisclosed Browsing Data Collection [MEDIUM]

**Location:** `js/popup.js:10799-10807`, `js/content.js:10932-10954`

**Description:**
The extension implements a "feedback" mechanism that collects detailed browsing information from visited pages and sends it to `https://api.popup-blocker.org/white-list/notblock`. When users click a feedback button in the popup, the extension:

1. Collects the full URL of the current page (`rootUrl`)
2. Collects the hostname (`rootDomain`)
3. Scans all `<script>` tags on the page and in iframes
4. Filters for third-party scripts (excluding whitelisted domains like Google, Facebook, Cloudflare, etc.)
5. Sends this data to the developer's server

**Code Evidence:**
```javascript
// js/popup.js:10838-10848
function compiledDate(request, sender) {
    const domain = new URL(sender.tab.url).host;
    const rootUrl = sender.tab.url;
    data.rootDomain = domain;
    data.rootUrl = rootUrl;
    if (request.data.scripts) {
        data.rootScripts = request.data.scripts;
    } else if (request.data.frame) {
        data.frames.push(request.data.frame);
    }
}
```

**Data Sent:**
```javascript
// js/popup.js:10799-10804
fetch(API_URL + "/white-list/notblock", {
    method: 'POST',
    body: JSON.stringify(data),  // Contains: rootUrl, rootDomain, rootScripts, frames
    headers: { 'Content-Type': 'application/json' }
})
```

**Impact:**
- **Browsing history exposure:** Full URLs (including query parameters, paths) sent to third party
- **Script fingerprinting:** Detailed inventory of third-party scripts reveals user's browsing patterns
- **Potential PII exposure:** URLs may contain sensitive data in query strings

**Disclosure Assessment:**
While this is ostensibly a "feedback" feature triggered by user action, the extent of data collection (full URLs, complete script inventories from all frames) is likely not transparent to users. The privacy policy at `popup-blocker.org` should be reviewed to verify disclosure adequacy.

---

### 2. Whitelist Synchronization to Remote Server [MEDIUM]

**Location:** `js/sw.js:11242-11255`

**Description:**
The extension synchronizes user whitelist data (domains where popup blocking is disabled) to `https://api.popup-blocker.org/white-list/create`:

```javascript
async function syncSettings() {
    const synced = await lss.get("has_synced_to_server4");
    if (synced) return;

    const whitelist = await lss.get("pb_whitelist");
    await fetch(conf["API_URL"] + "/white-list/create", {
        method: "POST",
        body: JSON.stringify({ urls: whitelist }),
        headers: { "Content-Type": "application/json" },
    });
    lss.set({ has_synced_to_server4: true });
}
```

**Also triggered on:**
- User manually whitelisting a domain (`js/popup.js:10774`, `js/options.js:10847`, `js/content.js:10861`)

**Impact:**
User's whitelist reveals which websites they visit that have aggressive popup behavior. This data is sent to the developer's server and could be used to:
- Build browsing profiles
- Identify users across installations (if combined with other identifiers)
- Reveal preferences and behavior patterns

---

### 3. postMessage Handler Without Origin Validation [MEDIUM]

**Location:** `js/content.js:10830-10840`

**Description:**
The content script registers a window-level postMessage handler that processes messages without validating the sender's origin:

```javascript
window.addEventListener("message", function receiveMessage(event) {
    if (event.data.type && (event.data.type == "blockedWindow")) {
        var args = JSON.parse(event.data.args);
        chrome.storage.sync.get("pb_numOfBlocks", function (data) {
            data.pb_numOfBlocks++;
            chrome.storage.sync.set(data)
        });
        // ... display notification UI
    }
});
```

**Attack Vector:**
Malicious websites or third-party scripts injected into pages can send crafted messages to:
- Increment the blocked popup counter arbitrarily
- Trigger notification UI spam
- Potentially exploit parsing vulnerabilities in `JSON.parse(event.data.args)`

**Missing Control:**
```javascript
// Should validate:
if (event.origin !== expectedOrigin) return;
```

**Impact:**
Low-to-medium severity. While the handler only modifies a counter and displays notifications, the lack of origin validation is a security anti-pattern that could enable UI spoofing or data corruption attacks.

---

### 4. Google Analytics Usage [LOW]

**Location:** `js/sw.js:11142-11162`

**Description:**
The extension implements basic Google Analytics tracking for usage telemetry:

```javascript
async function api(data) {
    if (navigator.doNotTrack) return;

    data.v = "1";
    data.tid = "UA-60779109-1";
    data.cid = await ls.get("cid");  // Random client ID stored in chrome.storage.local

    return await fetch("http://www.google-analytics.com/collect?" +
        new URLSearchParams(data).toString());
}
```

**Events Tracked:**
- `app-started` (on browser startup)
- `app-installed` (first install)
- `app-update-v{version}` (version updates)
- `context-disable-enable` (pause/unpause extension)
- `context-hide-show` (show/hide notifications)

**Impact:**
Standard analytics implementation. Respects Do Not Track header. Only sends basic event category/action/label data, no browsing history. This is common practice but worth noting for completeness.

---

## Data Flow Analysis

### Exfiltration Flows (from ext-analyzer)

1. **chrome.storage.sync.get → fetch(www.google-analytics.com)**
   - Source: Extension settings
   - Sink: Google Analytics
   - Data: Client ID (random), event categories
   - **Assessment:** Benign telemetry

2. **chrome.storage.local.get → fetch(www.google-analytics.com)**
   - Source: Extension settings
   - Sink: Google Analytics
   - Data: Client ID
   - **Assessment:** Benign telemetry

3. **User whitelist → fetch(api.popup-blocker.org)**
   - Source: `chrome.storage.sync` (pb_whitelist)
   - Sink: Developer server
   - Data: Domains where popups are allowed
   - **Assessment:** Privacy concern - reveals browsing patterns

4. **Page URLs + script inventory → fetch(api.popup-blocker.org)**
   - Source: Content script DOM scanning + tab URLs
   - Sink: Developer server
   - Data: Full URLs, third-party script sources, iframe data
   - **Assessment:** Privacy concern - detailed browsing activity

---

## Attack Surface Analysis

### Open Message Handlers
- **window.addEventListener("message")** in `content.js:10830`
  - No origin validation
  - Processes `blockedWindow` message type
  - Parses arbitrary JSON from `event.data.args`

### Permissions Analysis

| Permission | Justification | Concern |
|------------|---------------|---------|
| `storage` | Store whitelist, settings | ✓ Legitimate |
| `webRequest` | Monitor popup attempts | ✓ Legitimate |
| `declarativeNetRequest` | Block popup requests | ✓ Legitimate |
| `tabs` | Access tab URLs, reload tabs | ⚠️ Used to collect URLs |
| `contextMenus` | Add context menu items | ✓ Legitimate |
| `*://*/*` (host_permissions) | Run on all pages | ⚠️ Required for blocking, but enables broad access |

**Concern:** The combination of `tabs` permission and `<all_urls>` host permissions enables the URL collection behavior described above.

---

## Code Quality Observations

### Positive
- Respects Do Not Track for analytics
- Webpack bundled (indicates modern dev practices)
- Uses MV3 APIs (future-compatible)
- Core popup blocking logic appears sophisticated

### Negative
- No origin validation on postMessage handler
- Mixes HTTP and HTTPS (Google Analytics uses HTTP URL)
- Obfuscated code (webpack-bundled, but could be more readable)
- Extensive third-party script scanning without clear user notice

---

## Recommendations

### For Users
1. **Review privacy implications:** Understand that this extension sends browsing data to `api.popup-blocker.org`
2. **Avoid clicking feedback button** unless comfortable sharing full URL and script data
3. **Consider alternatives:** Evaluate whether similar popup blockers have better privacy practices
4. **Examine privacy policy:** Visit `popup-blocker.org` to verify data handling practices

### For Developers
1. **Add origin validation** to postMessage handler:
   ```javascript
   window.addEventListener("message", function receiveMessage(event) {
       if (event.origin !== window.location.origin) return;
       // ... rest of handler
   });
   ```

2. **Improve transparency:**
   - Clearly disclose URL and script collection in CWS privacy policy
   - Add in-extension privacy notice before feedback submission
   - Consider making remote data collection opt-in

3. **Minimize data collection:**
   - Hash or anonymize URLs before transmission
   - Send only domain names, not full URLs with paths/query strings
   - Reduce script inventory detail (e.g., count instead of full list)

4. **Use HTTPS for all endpoints:**
   - Update Google Analytics to HTTPS URL
   - Ensure all `api.popup-blocker.org` calls use HTTPS (currently they do)

5. **Add user controls:**
   - Setting to disable remote whitelist sync
   - Clear data deletion mechanism
   - Transparency dashboard showing what data was sent

---

## Conclusion

Popup Blocker Pro provides legitimate popup-blocking functionality but implements data collection practices that likely exceed user expectations for this type of extension. The collection of full URLs and third-party script inventories poses privacy risks, particularly if not adequately disclosed. The postMessage vulnerability, while not immediately exploitable for severe impact, represents poor security hygiene.

**Overall Risk: MEDIUM** — The extension has legitimate functionality but collects browsing data in ways that may not be fully transparent to users. Users seeking maximum privacy should evaluate alternatives or use this extension with awareness of its data transmission behavior.

---

## References

- **Manifest Version:** 3
- **Homepage:** http://popup-blocker.org
- **API Endpoint:** https://api.popup-blocker.org
- **Analytics ID:** UA-60779109-1
- **Web Accessible Resources:** `js/inject.js`, `js/cancel-inject.js`, images

## Technical Details

**Core Mechanism:**
The extension injects `js/inject.js` into page context, which overrides `window.open()` with custom logic. When popup attempts are detected, they're evaluated against heuristics (e.g., was the call triggered by clicking on document/body element? Is there a full-screen transition?). Blocked attempts trigger a postMessage to the content script, which updates counters and optionally shows notifications.

**Whitelist Domains (excluded from feedback scanning):**
- google.com, cloudflare.com, google-analytics.com, facebook.com
- googleapis.com, doubleclick.net, youtube.com, reddit.com
- googletagmanager.com, twitter.com, pinterest.com, gstatic.com

This whitelist suggests the extension is aware that script scanning could be perceived as sensitive, as it explicitly excludes major platforms.
