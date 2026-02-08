# Vulnerability Report: Clipboard History Manager - Secure, Fast, and Open Source

**Extension ID:** ombhfdknibjljckajldielimdjcomcek
**Version:** 1.4.18
**Author:** Andy Young <andyluyoung@gmail.com>
**Manifest Version:** 3
**Triage Flags:** V1=4, V2=1 (postmessage_no_origin, dynamic_tab_url)
**Date:** 2026-02-06

---

## Executive Summary

**Verdict: CLEAN -- No verified vulnerabilities found.**

All triage flags are false positives caused by standard library patterns from `@plasmohq/messaging` (Plasmo framework), `@instantdb/core` (InstantDB real-time database SDK), and React scheduler internals. The extension's architecture properly isolates sensitive clipboard data within extension-only contexts that web pages cannot reach.

---

## Architecture Overview

| Component | File | Purpose |
|-----------|------|---------|
| Background service worker | `static/background/index.js` | Message routing, clipboard entry storage, context menus, paste injection |
| Offscreen document | `offscreen.07c5b12a.js` | Clipboard monitoring via `document.execCommand("paste")` polling |
| Popup/Side panel | `popup.100f6462.js` | UI for viewing/searching clipboard history |
| Sign-in tab | `tabs/sign-in.880d9c48.js` | Magic code auth flow for cloud sync feature |

**Permissions:** storage, offscreen, clipboardRead, clipboardWrite, unlimitedStorage, contextMenus, scripting, activeTab, sidePanel

**Backend:** InstantDB (appId: `2f06026c-6dc9-4190-90ce-0628007dfb22`) at `api.instantdb.com` for cloud sync. Website: `https://www.clipboardhistory.io`

---

## Triage Flag Analysis

### Flag 1: `postmessage_no_origin` (V1=4 occurrences)

#### 1a. Plasmo Messaging Relay (`@plasmohq/messaging`)

**Files:** `offscreen.07c5b12a.js:116`, `popup.100f6462.js:64618`

```js
// Validation function for incoming postMessages
u = (e, t) => !t.__internal
  && e.source === globalThis.window      // <-- self-message check
  && e.data.name === t.name
  && (void 0 === t.relayId || e.data.relayId === t.relayId)
```

```js
// Outbound postMessage uses same-origin targetOrigin
r.postMessage({ ... }, { targetOrigin: e.targetOrigin || "/" })
```

**Assessment: FALSE POSITIVE.**

This is the Plasmo framework's relay system for internal extension communication. The `e.source === globalThis.window` check ensures only self-originated messages are accepted -- this is a deliberate design for relaying between in-page Plasmo modules within the same window context. These contexts are:

- Offscreen document: `chrome-extension://[id]/offscreen.bf42e808.html`
- Popup: `chrome-extension://[id]/popup.html`

Web pages have no access to these windows. The `targetOrigin: "/"` (same-origin) on outbound messages is correct. Even without the source check, web content cannot reach these extension-internal pages.

#### 1b. InstantDB Devtool Message Handler

**Files:** `offscreen.07c5b12a.js:4966-4980`, `tabs/sign-in.880d9c48.js:42717-42731`, `popup.100f6462.js:61356`

```js
function a(e) {
    e.source === o.element.contentWindow              // iframe source check
      && e.data?.type === "close"                     // only "close" command
      && r.isVisible() && u()                         // toggles UI visibility
}
addEventListener("message", a)
```

**Assessment: FALSE POSITIVE (dead code path).**

This handler accepts messages only from a specific iframe (`contentWindow` check) and only processes `{type: "close"}` to toggle UI visibility. More importantly, the devtool is gated by:

```js
// Only activates on localhost
r.allowedHosts.includes(window.location.hostname) && createDevtool(...)
```

Default `allowedHosts` is `["localhost"]`. In extension context, `window.location.hostname` is the extension ID (e.g., `ombhfdknibjljckajldielimdjcomcek`), so `createDevtool` is never called. The iframe is never created. The message handler is never registered.

#### 1c. InstantDB BroadcastChannel

**Files:** `offscreen.07c5b12a.js:613`, `tabs/sign-in.880d9c48.js:38364`, `popup.100f6462.js:56989`

```js
this._broadcastChannel = new BroadcastChannel("@instantdb")
this._broadcastChannel.addEventListener("message", e => {
    if (e.data?.type === "auth") {
        let e = yield this.getCurrentUser();
        this.updateUser(e.user)
    }
})
```

**Assessment: FALSE POSITIVE.**

BroadcastChannel is inherently scoped to same-origin. Only pages under `chrome-extension://[extension-id]/` can participate. The handler only processes `{type: "auth"}` messages and triggers a user refresh (no data exfiltration, no action beyond UI state update). External pages cannot post to this channel.

#### 1d. React/MessageChannel Scheduler

**Files:** `popup.100f6462.js:6706-6707`, `tabs/sign-in.880d9c48.js:6706-6707`

```js
var A = new MessageChannel, L = A.port2;
A.port1.onmessage = O;
i = function() { L.postMessage(null) }
```

**Assessment: FALSE POSITIVE.**

This is the React scheduler's internal mechanism for scheduling microtasks via MessageChannel. It is a well-known React internals pattern. The two ports are local variables with no external exposure.

### Flag 2: `dynamic_tab_url` (V2=1 occurrence)

**File:** `tabs/sign-in.880d9c48.js:6933`

```js
window.location.replace(`${x.default.BASE_URL}/checkout/${e.id}`)
```

Where:
- `x.default.BASE_URL` = `"https://www.clipboardhistory.io"` (hardcoded at `offscreen.07c5b12a.js:5064`)
- `e.id` = InstantDB user ID (server-generated UUID, from authenticated auth response)

**Assessment: FALSE POSITIVE.**

The base URL is hardcoded. The `e.id` is a server-returned user ID appended as a path segment (not controlling the scheme, host, or full URL). This is a standard post-auth checkout redirect. Not exploitable.

---

## Additional Security Observations (Not Vulnerabilities)

### `onMessageExternal` Handler

**File:** `static/background/index.js` (line 1, minified)

```js
chrome.runtime.onMessageExternal.addListener((e,t,r) => (e?.name, !0))
```

This is Plasmo framework boilerplate. It uses the comma operator to evaluate `e?.name` (discard) and return `true`. Returning `true` holds the message channel open but never sends a response. Since `manifest.json` has no `externally_connectable` key, no web page can invoke this handler -- only other extensions can. The handler performs no actions and returns no data.

### Clipboard Data Handling

The extension polls clipboard via `document.execCommand("paste")` every 800ms in the offscreen document (`offscreen.07c5b12a.js:228-236`). Clipboard content is sent to the background service worker via `chrome.runtime.sendMessage` and stored in:
1. Local storage (via `chrome.storage`)
2. Cloud storage (via InstantDB at `api.instantdb.com`) when the user is signed in

Cloud sync is opt-in (requires sign-in). Data in transit goes over WSS/HTTPS. The InstantDB app ID is hardcoded, not dynamically configurable.

### `chrome.scripting.executeScript` Usage

**File:** `static/background/index.js` (offset ~625828)

```js
function M(e) { document.execCommand("insertText", void 0, e) }
// ...
chrome.scripting.executeScript({
    target: { tabId: t.id },
    func: M,
    args: [i.content]
})
```

This injects clipboard content into the active tab to perform paste operations (context menu paste, keyboard shortcut paste). The `content` comes from the user's own stored clipboard entries. This is expected functionality for a clipboard manager and requires `activeTab` + `scripting` permissions which are declared.

---

## Conclusion

All four `postmessage_no_origin` flags and the single `dynamic_tab_url` flag are false positives arising from:
- `@plasmohq/messaging` relay (self-window messaging in extension-only contexts)
- `@instantdb/core` devtool (dead code -- only activates on localhost)
- `@instantdb/core` BroadcastChannel (same-origin scoped)
- React scheduler internals (private MessageChannel)
- Hardcoded base URL with server-generated path segment

No real vulnerabilities were identified. The extension is a legitimate clipboard manager with cloud sync capabilities.
