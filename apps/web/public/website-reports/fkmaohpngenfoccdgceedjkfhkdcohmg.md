# Vulnerability Report: Figma Chrome Extension

**Extension:** Figma (fkmaohpngenfoccdgceedjkfhkdcohmg)
**Version:** 1.3.8
**Manifest Version:** 3
**Analysis Date:** 2026-02-06
**Triage Flags:** V1=5, V2=1 -- csp_unsafe_inline, innerhtml_dynamic, postmessage_no_origin, dynamic_tab_url

---

## Summary

Two verified low-severity vulnerabilities were found, both related to missing postMessage origin validation. The extension's content_script.js correctly validates message origins, but two other components (figma_content_script.js and file_picker.js) do not. The innerHTML and CSP flags are false positives -- innerHTML usages are properly sanitized with DOMPurify, and the CSP only weakens `style-src`, not `script-src`.

---

## VULN-01: postMessage Handler Without Origin Validation in figma_content_script.js

**CVSS 3.1:** 4.3 (Medium)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N
**File:** `js/figma_content_script.js:6-7`

### Description

The `figma_content_script.js` registers a `window.addEventListener("message", ...)` handler on all pages matching `https://figma.com/*`, `https://staging.figma.com/*`, `https://local.figma.engineering:8443/*`, and `https://gov.figma.com/*`. The handler does **not** check `event.origin` before processing the message.

When the handler receives a message with `event.data === "close_desktop_interstitial_tab"`, it calls `sendMessageToBackground("CLOSE_TAB")`, which causes the background service worker to call `chrome.tabs.remove()` on the sender's tab.

```javascript
// figma_content_script.js:6-7
window.addEventListener("message", (e => {
  "close_desktop_interstitial_tab" === e.data && (0, o.sendMessageToBackground)("CLOSE_TAB")
}))
```

The background handler at `background.js:4914-4918`:
```javascript
case "CLOSE_TAB":
  return (0, a.asynchronousResult)(n, p, (() => r(void 0, void 0, void 0, (function*() {
    var e, n;
    (null === (e = t.tab) || void 0 === e ? void 0 : e.id) && (yield chrome.tabs.remove(null === (n = t.tab) || void 0 === n ? void 0 : n.id))
  }))))
```

### PoC Exploit Scenario

1. User navigates to `https://www.figma.com/some-page`
2. A Figma page contains a third-party iframe or an XSS on figma.com allows an attacker to inject JavaScript
3. The attacker script executes: `window.postMessage("close_desktop_interstitial_tab", "*")`
4. The content script receives this message (no origin check), sends `CLOSE_TAB` to the background
5. The background service worker closes the user's current Figma tab

### Impact

An attacker who can execute JavaScript in the context of a figma.com page (via XSS on figma.com, or from an embedded third-party iframe) can force-close the user's current Figma tab, causing loss of any unsaved work. The attack requires the user to be on a figma.com page. The attacker cannot escalate this to close arbitrary tabs -- only the tab where the content script is injected.

### Mitigating Factors

- The content script only runs on figma.com domains, so the attacker must already have script execution on figma.com (e.g., via XSS or an embedded iframe)
- The action is limited to closing the current tab -- no data exfiltration or code execution
- Cross-origin iframes on figma.com would need to target `window.parent.postMessage()` or `window.postMessage()` on the main frame

---

## VULN-02: postMessage Handler Without Origin Validation in file_picker.js (Web-Accessible Resource)

**CVSS 3.1:** 3.1 (Low)
**Vector:** CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N
**File:** `js/file_picker.js:212-228` (receiver), `js/file_picker.js:241,247,260,276,284,492` (sender)

### Description

The `file_picker.html` is listed as a web-accessible resource available to `https://www.google.com/*` and `https://calendar.google.com/*`:

```json
"web_accessible_resources": [{
  "resources": ["img/*.png", "font/*.woff2", "file_picker.html"],
  "matches": ["https://www.google.com/*", "https://calendar.google.com/*"]
}]
```

The file_picker.js message handler does **not** validate `event.origin`:

```javascript
// file_picker.js:212-228
function e(e) {
  const l = e.data;
  switch (l.type) {
    case "files_loaded":
      if (d(l.currentEditor), t(l.files || null), a(l.filesLoading || !1), l.files) {
        const e = {};
        l.files.forEach((t => { e[t.key] = t })), r(e)
      } else r({});
      break;
    case "selected_files_changed":
      C(l.selectedFileKeys);
      break;
    case "is_search":
      O(l.value)
  }
}
return window.addEventListener("message", e), () => {
  window.removeEventListener("message", e)
}
```

Additionally, the file_picker sends messages to its parent with `"*"` as the target origin:

```javascript
// file_picker.js:241
window.parent.postMessage(e, "*")  // file_clicked with fileKey
// file_picker.js:247
window.parent.postMessage(e, "*")  // file_double_clicked with fileKey
```

### PoC Exploit Scenario

1. Attacker controls a page on `https://www.google.com/` (e.g., via Open Redirect, reflected XSS, or a Google AMP page)
2. Attacker embeds the extension's file_picker in an iframe:
   ```html
   <iframe id="picker" src="chrome-extension://fkmaohpngenfoccdgceedjkfhkdcohmg/file_picker.html"></iframe>
   ```
3. Attacker sends crafted messages to inject fake file data:
   ```javascript
   document.getElementById("picker").contentWindow.postMessage({
     type: "files_loaded",
     currentEditor: "figma",
     files: [{key: "attacker-key", name: "Important Doc", editorType: "figma", thumbnailUrl: "https://evil.com/phishing.png"}],
     filesLoading: false
   }, "*");
   ```
4. The file picker renders the attacker-controlled file list
5. When the user clicks a file, the file_picker sends `file_clicked` or `file_double_clicked` with the file key back to the attacker's parent page (via `postMessage("*")`)

### Impact

- **UI Spoofing:** An attacker can inject fake Figma file listings into the file picker, potentially for phishing (e.g., displaying a fake "shared file" to trick the user)
- **Information leakage is minimal:** The messages sent back to the parent contain only the file keys that the attacker already injected
- **No privilege escalation:** The content_script.js (the legitimate parent) validates message origin at line 1092 (`if (e.origin !== E) return`), so even if the file_picker sends messages with `"*"`, the content_script will discard them from non-extension origins. The attack only works in an attacker-controlled parent frame context.

### Mitigating Factors

- Requires attacker-controlled JavaScript execution on `google.com` or `calendar.google.com` domains
- The content_script.js properly validates origin on its message listener (line 1092), preventing the attacker from triggering real actions (attach_files, create_file, etc.) through the content script
- File data rendered via React (no innerHTML), so attacker-controlled file names/URLs cannot cause XSS
- The `thumbnailUrl` is used as a CSS `backgroundImage` via styled-components, which is sanitized by React's style handling

---

## False Positives (Triage Flag Review)

### FP-01: csp_unsafe_inline

The manifest CSP is:
```
default-src 'self'; connect-src https://api.figma.com https://figma.com https://www.figma.com https://*.sentry.io; img-src *; style-src 'unsafe-inline'; object-src 'none'
```

The `'unsafe-inline'` applies **only** to `style-src`, not `script-src`. Since `script-src` is not explicitly declared, it inherits from `default-src 'self'`, which blocks inline script execution. The `style-src 'unsafe-inline'` is required by the extension's use of styled-components (CSS-in-JS) and cannot be used to execute JavaScript. **Not a vulnerability.**

### FP-02: innerhtml_dynamic

All `innerHTML` assignments in `vendor.js` fall into two categories:
1. **DOMPurify sanitized** (lines 14423, 14439): `r.innerHTML = o.default.sanitize(e)` -- properly sanitized via DOMPurify before assignment
2. **React framework internals** (lines 4053, 7178): Standard React DOM operations for SVG namespace handling and element creation
3. **DOMPurify library internals** (lines 2092, 2120, 2139, 2252): Part of the DOMPurify sanitization engine itself

**Not a vulnerability.**

### FP-03: dynamic_tab_url

The `chrome.tabs.create({url: e})` at `background.js:4698` is part of the OAuth login flow. The URL `e` is constructed at line 4679 as a hardcoded `https://www.figma.com/oauth?...` URL with PKCE parameters. The URL is not user-controlled or externally influenced. **Not a vulnerability.**

---

## Observation: Unused SageMaker Host Permission

The manifest declares a host permission for an AWS SageMaker endpoint:
```json
"host_permissions": ["*://t-boweisvde9h9.us-west-2.experiments.sagemaker.aws/*"]
```

This endpoint identifier (`t-boweisvde9h9`) is not referenced anywhere in the extension's JavaScript code. This appears to be a development/testing artifact that was not removed before publication. While not a vulnerability itself, it grants the extension unnecessary network access to this endpoint, violating the principle of least privilege.

---

## Overall Risk Assessment

**Overall Risk: LOW**

The Figma extension is a legitimate Google Calendar integration with standard OAuth-based authentication. The two verified vulnerabilities are both low-impact postMessage issues:
- VULN-01 can close a tab but requires script execution on figma.com
- VULN-02 allows UI spoofing of the file picker but requires script execution on google.com and cannot escalate to real actions due to proper origin checking in the content_script

No data exfiltration, no credential theft, no code execution, and no malicious behavior was identified.
