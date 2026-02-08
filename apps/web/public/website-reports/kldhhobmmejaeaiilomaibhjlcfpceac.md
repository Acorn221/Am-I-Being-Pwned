# Vulnerability Report: Fatkun Image Search (kldhhobmmejaeaiilomaibhjlcfpceac)

**Extension:** Fatkun (Image Search) v4.0.5
**Manifest Version:** 3
**Permissions:** scripting, storage, downloads, contextMenus, declarativeNetRequest
**Host Permissions:** `<all_urls>`
**Content Scripts:** Injected on `<all_urls>`, all frames, including about:blank
**Triage Flags:** V1=4, V2=4 -- innerhtml_dynamic, postmessage_no_origin, dynamic_tab_url, dynamic_window_open

---

## Executive Summary

The extension contains **4 verified vulnerabilities**, all stemming from missing `postMessage` origin validation in content scripts and extension pages. The content script runs on every page in every frame, and the extension actively strips Content-Security-Policy and X-Frame-Options headers from all pages via declarativeNetRequest rules, which significantly expands the attack surface. The most severe vulnerability allows any web page to trigger arbitrary tab navigation via the extension's privileged APIs.

---

## VULN-01: Arbitrary Tab Creation via Unauthenticated postMessage (open-1688-offer)

**CVSS 3.1:** 6.1 (Medium)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**File:** `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/kldhhobmmejaeaiilomaibhjlcfpceac/deobfuscated/chunks/searchImage-CTwcFIA7.js` : lines 8213-8226

**Description:**

The searchImage page (an extension page opened via `chrome-extension://` URL) registers a `window.addEventListener("message", ...)` handler that processes incoming messages without checking `event.origin` or `event.source`. When a message with `cmd: "open-1688-offer"` is received, it extracts `data.data.offerId` and uses it to construct a URL that is opened in a new tab via `chrome.tabs.create()`:

```javascript
x.data.cmd === "open-1688-offer" && ((y = x.data.data) != null && y.offerId) && chrome.tabs.query({
  active: !0,
  currentWindow: !0
}, O => {
  const C = O[0];
  C != null && C.id && chrome.tabs.create({
    url: `https://${p.soutuDomain}/image-search/red?id=${x.data.data.offerId}`,
    openerTabId: C.id
  })
})
```

The `offerId` value is user-controlled and injected directly into the URL path without sanitization. While the domain is currently `fanli.fatkun.net` (from `simgConfigV2` in storage), the `offerId` can contain path traversal or query injection characters. More importantly, any iframe embedded in the searchImage page (which the extension deliberately embeds for search engine interaction) can send this message to the parent extension page.

**PoC Exploit Scenario:**

1. The user opens Fatkun's searchImage page to perform an image search.
2. The extension loads a third-party site (e.g., 1688.com, google.com) in an iframe within the extension page. The extension's declarativeNetRequest rules (rule IDs 1, 5) strip X-Frame-Options and CSP from these sites, enabling framing.
3. The framed third-party page (or an attacker who has XSS on that page) sends: `window.parent.postMessage({cmd: "open-1688-offer", data: {offerId: "../../phishing-page"}}, "*")`
4. The extension creates a new tab to `https://fanli.fatkun.net/../../phishing-page`, which resolves to the attacker-controlled path on the domain.

**Impact:** Attacker-controlled tab navigation originating from a trusted extension context. Can be used for phishing (user trusts extension-initiated navigations) or to redirect affiliate/tracking flows.

---

## VULN-02: Unauthenticated Image Search Trigger via postMessage (start-search-img)

**CVSS 3.1:** 4.3 (Medium)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N`

**File:** `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/kldhhobmmejaeaiilomaibhjlcfpceac/deobfuscated/content-scripts/content.js` : lines 734-735

**Description:**

The content script (injected on ALL pages, ALL frames, including about:blank) listens for `window.message` events and processes the `start-search-img` command without any origin check:

```javascript
window.addEventListener("message", t => {
    t.data.cmd == "start-search-img" && be(t.data.data)
})
```

The `be()` function at line 725-730 takes the `data.dataUri` from the message, resizes it, and then calls site-specific search functions that manipulate file inputs, trigger form submissions, and navigate the page. No origin or source validation is performed.

Any page can send this message to trigger automatic image search actions on the current page, including:
- Setting file inputs on Google, Baidu, Bing, 1688, Alibaba, AliExpress, Taobao, made-in-china.com
- Triggering form submissions and click events
- Navigating the page (line 602: `location.href = o.data.url.replace("http://", "https://")` for made-in-china.com)

**PoC Exploit Scenario:**

1. User has Fatkun installed and visits any page with an iframe.
2. Attacker iframe sends: `window.parent.postMessage({cmd: "start-search-img", data: {dataUri: "data:image/jpeg;base64,/9j/4AAQ..."}}, "*")`
3. If the parent page is google.com, the extension automatically opens Google's image search lens, uploads the attacker's image, and submits the search -- all without user interaction beyond visiting the page.

**Impact:** Unauthorized UI manipulation on major search engines and e-commerce platforms. Can be used to: trigger unwanted searches, manipulate shopping search results, or cause unexpected page navigations. The made-in-china.com path at line 602 is particularly dangerous as it navigates the entire page based on server response data.

---

## VULN-03: Content Script Invalidation via postMessage Spoofing (WXT Framework DoS)

**CVSS 3.1:** 4.3 (Medium)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L`

**File:** `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/kldhhobmmejaeaiilomaibhjlcfpceac/deobfuscated/content-scripts/content.js` : lines 865-892

**Description:**

The extension uses the WXT framework's content script lifecycle management, which relies on `window.postMessage` to coordinate between old and new content script instances. The `stopOldScripts()` method sends a message with `type: SCRIPT_STARTED_MESSAGE_TYPE` (which resolves to `"<extensionId>:content:wxt:content-script-started"`), and `listenForNewerScripts()` listens for this exact message type to abort/invalidate the current content script context:

```javascript
stopOldScripts() {
    window.postMessage({
        type: E.SCRIPT_STARTED_MESSAGE_TYPE,
        contentScriptName: this.contentScriptName,
        messageId: Math.random().toString(36).slice(2)
    }, "*")
}
```

```javascript
listenForNewerScripts(t) {
    let n = !0;
    const o = i => {
        if (this.verifyScriptStartedEvent(i)) {
            this.receivedMessageIds.add(i.data.messageId);
            // ... calls this.notifyInvalidated()
        }
    };
    addEventListener("message", o), ...
}
```

The `verifyScriptStartedEvent` checks that the `type` matches and `contentScriptName` is `"content"`, but does NOT check `event.origin` or `event.source`. The extension ID is discoverable (it is a public CWS extension with a fixed ID: `kldhhobmmejaeaiilomaibhjlcfpceac`), so the message type string is fully predictable.

**PoC Exploit Scenario:**

1. Attacker page includes JavaScript:
```javascript
window.postMessage({
    type: "kldhhobmmejaeaiilomaibhjlcfpceac:content:wxt:content-script-started",
    contentScriptName: "content",
    messageId: "attacker-" + Math.random()
}, "*");
```
2. The content script's `listenForNewerScripts` handler fires, calling `notifyInvalidated()`, which calls `this.abort("Content script context invalidated")`.
3. All WXT-managed intervals, timeouts, and event listeners are cancelled. The content script becomes non-functional on that page.

**Impact:** Any web page can silently disable the Fatkun content script, preventing the image search overlay buttons from appearing. This is a denial of service against the extension's functionality. While low severity on its own, it demonstrates the fragility of relying on postMessage without origin checks for security-sensitive lifecycle management.

---

## VULN-04: Cross-Origin Data Injection via postMessage (google-nps)

**CVSS 3.1:** 3.1 (Low)
**Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N`

**File:** `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/kldhhobmmejaeaiilomaibhjlcfpceac/deobfuscated/content-scripts/content.js` : lines 464-465

**Description:**

On Google search pages, the content script stores arbitrary data from postMessage into a module-scoped variable without origin validation:

```javascript
location.href.match(/google\.com\/search/) && window.addEventListener("message", e => {
    e.data.cmd == "google-nps" && (_ = e.data.data)
});
```

The `_` variable is later used in `P.getImgUrl()` (lines 496-503) to resolve image URLs:

```javascript
if (o) {
    const i = (o.getAttribute("jsdata") || "").split(";")[2];
    if (i && _) {
        const s = _[i];
        if (s) return s[3][0]  // Returns attacker-controlled URL
    }
}
```

This URL is subsequently passed to `chrome.runtime.sendMessage({cmd: "simg-dl", data: {url: t}})` (line 522-527) which triggers `chrome.downloads.download({url: x.data.url, ...})` (line 8150-8152 in searchImage chunk).

**PoC Exploit Scenario:**

1. User visits Google Image Search with Fatkun installed.
2. An iframe on the page (or an ad, or a compromised element) sends:
```javascript
window.parent.postMessage({
    cmd: "google-nps",
    data: {"some-jsdata-key": [null, null, null, ["https://evil.com/tracking-pixel.jpg"]]}
}, "*");
```
3. When the user clicks the Fatkun download button on a Google Images result whose `jsdata` attribute contains `"some-jsdata-key"`, the extension resolves the image URL from the attacker-injected data instead of the real Google data.
4. The extension downloads `https://evil.com/tracking-pixel.jpg` instead of the intended image.

**Impact:** Attacker can redirect image downloads to arbitrary URLs when the user uses Fatkun's download feature on Google Images. Requires specific conditions (Google Images page + matching jsdata keys), hence the higher attack complexity. Could be used for tracking or delivering unexpected content.

---

## Additional Security Observations (Non-Vulnerability)

### Universal CSP and X-Frame-Options Stripping

**File:** `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/kldhhobmmejaeaiilomaibhjlcfpceac/deobfuscated/background.js` : lines 33-48, 138-154

The extension uses `declarativeNetRequest` to strip `content-security-policy` and `X-Frame-Options` headers from ALL `main_frame` and `sub_frame` responses (rule ID 1), plus additional targeted CSP removal for pinterest.com, alibaba.com, google.com, and instagram.com (rule IDs 5, 42).

This is not a vulnerability in the extension itself, but it **degrades the security posture of every website the user visits** by removing clickjacking protections and CSP restrictions. This makes the user more vulnerable to attacks on websites that rely on these headers for defense.

### innerHTML Usage

The two `innerHTML` assignments in content.js (lines 204 and 569) use hardcoded static SVG strings (ImageSearchIcon and DownloadIcon respectively). These are NOT vulnerable -- the content is fully static template literals with no dynamic interpolation. The innerHTML references in `client-DvBhRfBy.js` are part of the React runtime (`dangerouslySetInnerHTML` implementation) -- this is standard React behavior and not a direct vulnerability in the extension code.

---

## Summary Table

| ID | Title | CVSS | Severity | File |
|----|-------|------|----------|------|
| VULN-01 | Arbitrary Tab Creation via Unauthenticated postMessage | 6.1 | Medium | searchImage-CTwcFIA7.js:8213-8226 |
| VULN-02 | Unauthenticated Image Search Trigger via postMessage | 4.3 | Medium | content.js:734-735 |
| VULN-03 | Content Script Invalidation via postMessage Spoofing | 4.3 | Medium | content.js:865-892 |
| VULN-04 | Cross-Origin Data Injection via postMessage | 3.1 | Low | content.js:464-465 |

## Recommended Mitigations

1. **Add origin checks to all `window.addEventListener("message", ...)` handlers.** Every handler should validate `event.origin` against expected values (e.g., the extension's own origin for extension-page-to-extension-page communication, or specific allowed domains for cross-origin communication).

2. **Use `event.source` validation** to ensure messages come from expected windows (e.g., known iframe references).

3. **Scope CSP/X-Frame-Options stripping** -- Rule ID 1 strips these headers from ALL pages. This should be scoped only to the specific domains the extension needs to frame (1688.com, google.com, etc.), not applied universally.

4. **For the WXT script lifecycle**: use `chrome.runtime` messaging instead of `window.postMessage` for content script coordination, as runtime messages cannot be forged by web pages.

5. **Sanitize the `offerId` parameter** in VULN-01 to ensure it contains only numeric characters before constructing the URL.
