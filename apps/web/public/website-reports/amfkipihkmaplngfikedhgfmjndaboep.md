# Vulnerability Report: Scratchpad (amfkipihkmaplngfikedhgfmjndaboep)

**Extension:** Scratchpad v22.53.11
**ID:** amfkipihkmaplngfikedhgfmjndaboep
**Manifest Version:** 3
**Permissions:** `scripting`, `storage`, `tabs`
**Host Permissions:** `https://*.scratchpad.com/*`, `https://localhost.dev:5002/*`
**Externally Connectable:** `https://*.scratchpad.com/*`, `https://localhost.dev:8090/*`, `https://localhost.dev:5002/*`
**Triage Flags:** V1=12, V2=23

---

## Summary

Scratchpad is a legitimate Salesforce CRM productivity tool that overrides the new tab page and injects content scripts into scratchpad.com and Salesforce domains. The extension has a moderate attack surface due to missing postMessage origin validation in a content script that bridges web page messages to the extension backend, combined with web-accessible resources that accept unvalidated postMessages. A hardcoded Bugsnag API key is exposed but has limited security impact. Several other flagged patterns (dynamic tab URLs, window.open, innerHTML) were verified as false positives.

**Overall Risk: LOW-MEDIUM** -- The vulnerabilities require either a compromise of scratchpad.com or exploitation of web-accessible resource iframes, and the impact is limited to local storage manipulation and UI abuse within the extension context.

---

## VULN-01: postMessage Listener Without Origin Validation in Content Script

| Property | Value |
|---|---|
| **CVSS 3.1** | **5.6 Medium** |
| **Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L` |
| **Affected File** | `contentScratchpad.js:3740-3748` |
| **CWE** | CWE-346: Origin Validation Error |

### Description

The content script `contentScratchpad.js` registers a `window.addEventListener("message", ...)` handler that forwards message data directly to the extension background via `chrome.runtime.sendMessage()` **without validating `event.origin`**. The handler checks only that `event.data.type === "crx.openPath"` and that `chrome.i18n` is available, then forwards the entire `event.data` object to the background script.

```javascript
// contentScratchpad.js:3740-3748
window.addEventListener("message", (function n(r) {
    if (!chrome.runtime.id) return window.removeEventListener("message", n, !0), ...;
    const u = t().get(r, ["data", "type"]);
    try {
        "crx.openPath" === u && chrome.i18n && chrome.i18n.getUILanguage() &&
            chrome.runtime.sendMessage(chrome.runtime.id, r.data, t().noop)
    } catch (n) { console.error(n) }
}), !0)
```

The background script processes `crx.openPath` messages from content scripts (verified by `if (!t.tab) return !0` at background.js:21772) and stores `payload.path` and `payload.view` to extension local storage without sanitization:

```javascript
// background.js:21800-21808
else if ("crx.openPath" === e.type) ! function(e) {
    let { view: t, path: r } = e;
    r && Kt(r),  // stores to "redirect_to" key
    t && Wt(t),  // stores to "view" key
    chrome.tabs.create({ url: uo })  // opens chrome://newtab (hardcoded)
}(e.payload);
```

### Mitigating Factor

This content script is only injected into pages whose URL starts with `https://app.scratchpad.com` (checked by function `bo()` at background.js:21702-21703). This means exploitation requires either:
- An XSS vulnerability on `app.scratchpad.com`
- A compromised iframe embedded within `app.scratchpad.com`
- A man-in-the-middle attack (unlikely given HTTPS)

### Proof of Concept

If an attacker achieves XSS on `app.scratchpad.com`, the following script would inject arbitrary values into the extension's local storage and force-open a new tab:

```javascript
// Injected on any page at app.scratchpad.com
window.postMessage({
    type: "crx.openPath",
    payload: {
        path: "/attacker-controlled-redirect",
        view: "attacker-controlled-view"
    }
}, "*");
```

The stored `redirect_to` and `view` values are later read by the newtab page (newtab.js:82819-82820) and used to influence navigation/routing within the extension's new tab UI. While the new tab URL itself is hardcoded to `chrome://newtab`, the stored path could influence in-app routing on the next load.

### Impact

- **Storage Poisoning:** Attacker can write arbitrary values to extension local storage keys `redirect_to` and `view`, potentially redirecting the user within the Scratchpad app on next new tab open
- **Denial of Service:** Repeatedly triggering this opens new tabs
- **Chaining Risk:** If stored values are later used unsafely (e.g., in URL construction or innerHTML), impact escalates

---

## VULN-02: postMessage Without Origin Validation in Web-Accessible Resource Iframe

| Property | Value |
|---|---|
| **CVSS 3.1** | **4.3 Medium** |
| **Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` |
| **Affected File** | `iframeGlobalSearch.js:165636-165645` |
| **CWE** | CWE-346: Origin Validation Error |

### Description

The `iframeGlobalSearch.html` page (a web-accessible resource available to `<all_urls>`) listens for `window.addEventListener("message", ...)` without validating the sender's origin. It accepts messages where `data.type === "globalSearch.launchIframe"` and dispatches them into the extension's Redux/Vuex store:

```javascript
// iframeGlobalSearch.js:165636-165645
window.addEventListener("message", (e => {
    Dn()(e, ["data", "type"]) === Le.EW && t.dispatch(function(e) {
        return {
            type: vs,  // "@window.message"
            payload: { event: e }
        }
    }(e))
}), !1)
```

The dispatched action is handled by a saga (iframeGlobalSearch.js:161153-161183) that processes `payload.event.data.payload` fields including `host`, `initialRecord`, `recordId`, `objType`, `sidebarMode`, `data`, and `resetStack` -- all controlled by the attacker.

Since `iframeGlobalSearch.html` is declared as a web-accessible resource with `matches: ["<all_urls>"]`, any website can embed it in an iframe:

```html
<iframe src="chrome-extension://amfkipihkmaplngfikedhgfmjndaboep/iframeGlobalSearch.html"></iframe>
```

### Mitigating Factor

- The extension ID must be known (it is publicly available on the Chrome Web Store)
- MV3 web-accessible resources are partitioned per-frame in modern Chrome, limiting cross-origin iframe embedding effectiveness
- The resulting actions appear to manipulate UI state within the iframe (sidebar mode, record display) rather than performing privileged operations

### Proof of Concept

```html
<!-- Attacker page at evil.com -->
<iframe id="target" src="chrome-extension://amfkipihkmaplngfikedhgfmjndaboep/iframeGlobalSearch.html"></iframe>
<script>
document.getElementById('target').onload = function() {
    this.contentWindow.postMessage({
        type: "globalSearch.launchIframe",
        payload: {
            host: "evil.com",
            initialRecord: { Name: "Fake Record" },
            recordId: "001FAKE",
            objType: "Account",
            sidebarMode: "view",
            data: {},
            resetStack: true
        }
    }, "*");
};
</script>
```

### Impact

- **UI Spoofing:** Attacker can inject fake CRM record data into the extension's global search sidebar, potentially misleading users into trusting fabricated Salesforce data
- **State Manipulation:** Extension store state can be corrupted, affecting subsequent user interactions
- **Information Disclosure (Limited):** Depending on how the extension renders the injected data, error messages or internal state might leak

---

## VULN-03: Cookie-Check postMessage Handler Without Origin Validation

| Property | Value |
|---|---|
| **CVSS 3.1** | **3.1 Low** |
| **Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N` |
| **Affected Files** | `5312.js:92-106`, `5603.js:92-106`, `7984.js:73-83`, `8744.js:92-106`, `3594.js:92-106`, `4927.js:73-83`, `7308.js:92-106`, `newtab.js:22726-22740` |
| **CWE** | CWE-346: Origin Validation Error |

### Description

Multiple chunk files and newtab.js implement a third-party cookie detection mechanism that embeds an iframe from `https://sp-prod-cookie-check.netlify.app/` and listens for a postMessage response. The listener does not validate the origin of the incoming message:

```javascript
// 5312.js:92-106 (representative example)
const w = () => new Promise((e => {
    const r = setTimeout((() => {
        e(!0), window.removeEventListener("message", t), document.body.removeChild(o)
    }), 2e3),
    t = s => {
        clearTimeout(r), window.removeEventListener("message", t), document.body.removeChild(o),
        s.data && "boolean" == typeof s.data.isThirdPartyCookieEnabled && e(s.data.isThirdPartyCookieEnabled)
    };
    window.addEventListener("message", t);
    const o = document.createElement("iframe");
    o.setAttribute("src", "https://sp-prod-cookie-check.netlify.app/"), ...
}))
```

Any page (or iframe on the same page) can send a postMessage with `{isThirdPartyCookieEnabled: false}` to influence the extension's cookie detection result.

### Mitigating Factor

- The handler only accepts a boolean value (`typeof s.data.isThirdPartyCookieEnabled === "boolean"`), severely limiting the attack surface
- The handler has a 2-second timeout after which it defaults to `true`
- The cookie-check result only affects whether the extension uses cookie-based or alternative authentication flows -- not a direct security bypass
- On newtab.js, this runs in the extension's own page (chrome-extension:// origin), limiting who can postMessage to it

### Proof of Concept

```javascript
// On the same page where the extension's content script runs (e.g., scratchpad.com)
window.postMessage({ isThirdPartyCookieEnabled: false }, "*");
```

### Impact

- **Authentication Flow Manipulation:** An attacker can force the extension to believe third-party cookies are disabled (or enabled), potentially causing it to use a less secure or more cumbersome authentication flow
- Impact is very limited given the boolean-only data type constraint

---

## VULN-04: Hardcoded Bugsnag API Key

| Property | Value |
|---|---|
| **CVSS 3.1** | **3.7 Low** |
| **Vector** | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Affected Files** | `background.js:19402`, `newtab.js:23986` |
| **CWE** | CWE-798: Use of Hard-Coded Credentials |

### Description

The Bugsnag error reporting API key is hardcoded in the extension source:

```javascript
// background.js:19402
apiKey: "6d988b88442ddd1cef8dcbe2e1232102",
releaseStage: "production",
enabledReleaseStages: ["production"],
appVersion: "22.53.11",
```

The same key appears in `newtab.js:23986`.

### Mitigating Factor

- Bugsnag API keys are typically **write-only** for error submission and do not grant access to read error data or project settings
- This is an extremely common pattern in client-side applications -- Bugsnag's own documentation acknowledges the key is embedded in client code
- The key does not provide access to user data, credentials, or sensitive systems

### Proof of Concept

An attacker could use this key to submit fake error reports to Scratchpad's Bugsnag project:

```javascript
fetch("https://notify.bugsnag.com/", {
    method: "POST",
    headers: {
        "Bugsnag-Api-Key": "6d988b88442ddd1cef8dcbe2e1232102",
        "Bugsnag-Payload-Version": "4"
    },
    body: JSON.stringify({
        events: [{
            exceptions: [{ errorClass: "FakeError", message: "Injected by attacker" }],
            app: { version: "22.53.11", releaseStage: "production" }
        }]
    })
});
```

### Impact

- **Error Report Pollution:** Attacker can flood Scratchpad's Bugsnag project with fake error reports, potentially obscuring real issues
- **Minor Information Leak:** The API key confirms the use of Bugsnag and the production release stage configuration
- No access to user data or system internals

---

## False Positives / Verified Non-Issues

### postMessage to `"*"` in contentQuickeditAnywhere.js

**File:** `contentQuickeditAnywhere.js:3971`

```javascript
c.contentWindow.postMessage(t, "*")
```

This sends a postMessage **to** the extension's own iframe (iframeGlobalSearch.html) embedded in the page. The `*` target origin is used because the destination is a chrome-extension:// URL. While `*` is technically less restrictive than specifying the extension origin, the data being sent is internally generated (globalSearch.launchIframe messages with CRM record data), not user-controlled. The content script is only injected on permitted host pages. **Not a vulnerability.**

### Axios postMessage Scheduler

**Files:** `background.js:17805-17812`, `iframeNotesList.js:27444-27451`, `newtab.js:149943-149949`

The Axios HTTP library uses `postMessage("axios@random", "*")` as a microtask scheduler. The handler properly validates `source === self && data === randomToken`. This is a well-known Axios internal pattern. **Not a vulnerability.**

### newtab.js postMessage with Origin Check

**File:** `newtab.js:171818-171826`

```javascript
window.self.addEventListener("message", (async e => {
    if (zl()(e.origin, `chrome-extension://${chrome.runtime.id}`) && e.data === Xl.wK) { ... }
}))
```

This handler **properly validates** that the origin matches the extension's own chrome-extension:// origin. **Not a vulnerability.**

### OAuth postMessage Handlers

**Files:** `newtab.js:77230-77234`, `iframeNotesList.js:33447-33451`, `iframeGlobalSearch.js:75424-75428`

```javascript
a = e => {
    if (e.origin === c[t]) {  // validated against per-provider allowlist
        if (r(), "ok" !== e.data.status) return o?.close(), void i(e.data);
        n(e.data), o?.close()
    }
}
```

These OAuth callback handlers **properly validate** the origin against a per-provider allowlist (`c[t]` / `Iy[t]`). **Not a vulnerability.**

### innerHTML with $sanitize

**File:** `167.js:326-329`

```javascript
innerHTML: e.$sanitize(s.primary)
innerHTML: e.$sanitize(s.secondary)
```

These innerHTML usages pass through a `$sanitize` function before rendering. **Not a vulnerability.**

### innerHTML in Vue Reactive Bindings

**Files:** `6978.js:171`, `1920.js:1057`, various chunk files

These are Vue 3 reactive binding patterns where `innerHTML` is bound to computed values derived from internal store state (audit trail fields, formatted CRM field values). The data source is the Salesforce API via Scratchpad's backend, not direct user input. While technically the Salesforce data could contain HTML, this is mitigated by the extension page's CSP (`script-src 'self'`) which prevents script execution from injected HTML. **Low risk, not a practical vulnerability.**

### ProseMirror Paste Handler

**File:** `9732.js:5810`

```javascript
r.innerHTML = function(e) {
    let t = window.trustedTypes;
    return t ? t.createPolicy("detachedDocument", { createHTML: e => e }).createHTML(e) : e
}(e)
```

This is ProseMirror's standard paste HTML parsing on a **detached DOM element** (not inserted into the live document). It uses Trusted Types when available. This is expected rich text editor behavior. **Not a vulnerability.**

### Dynamic window.open Calls

**File:** `newtab.js:164946`

```javascript
window.open(e.data.url, "billing")
```

This `window.open` is triggered by a Redux action (`zt.Iu`) dispatched from within the extension's own store. The URL comes from an API response (billing portal URL), not from external postMessage. **Not a vulnerability.**

### externally_connectable with localhost.dev

**File:** `manifest.json:56-57`

```json
"https://localhost.dev:8090/*",
"https://localhost.dev:5002/*"
```

These are development URLs. `localhost.dev` resolves to 127.0.0.1 and has a valid HTTPS certificate. While leaving development origins in production manifests is not ideal, exploitation would require the attacker to be running a server on the user's localhost on those specific ports. **Negligible risk in practice.**

---

## Recommendations

1. **Add origin validation to contentScratchpad.js postMessage handler** -- Check `event.origin` against `"https://app.scratchpad.com"` before forwarding messages to `chrome.runtime.sendMessage()`
2. **Add origin validation to iframeGlobalSearch.js postMessage handler** -- Check `event.origin` matches the expected content script origin or `chrome-extension://${chrome.runtime.id}`
3. **Add origin validation to cookie-check postMessage handlers** -- Verify that the response comes from `https://sp-prod-cookie-check.netlify.app`
4. **Remove localhost.dev entries from externally_connectable** in production builds
5. **Consider rotating the Bugsnag API key** now that it is publicly documented (though impact is minimal)
