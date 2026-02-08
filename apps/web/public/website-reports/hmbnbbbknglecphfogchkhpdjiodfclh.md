# Vulnerability Report: QuickForm - Autofill Forms Quickly

**Extension ID:** hmbnbbbknglecphfogchkhpdjiodfclh
**Version:** 1.10.2
**Author:** Albert Gabdullin (quickform.pro@gmail.com)
**Manifest Version:** 3
**Framework:** Plasmo (React-based)
**Triage Flags:** V1=4, V2=1 -- innerhtml_dynamic, postmessage_no_origin, dynamic_tab_url

---

## Executive Summary

After thorough analysis of the content script (`content.883ade9e.js`), background service worker (`static/background/index.js`), and supporting files, **all three triage flags resolve to false positives or low-severity library-level issues**. No real exploitable vulnerabilities were found that would affect end users.

The extension is a straightforward form autofill tool built on the Plasmo framework. It stores form profiles in `chrome.storage.local` and fills them on demand via Chrome extension messaging (`chrome.runtime.onMessage`). There are no external network calls, no data exfiltration, and no dynamic code execution.

---

## Triage Flag Analysis

### Flag 1: `innerhtml_dynamic`

**Verdict: FALSE POSITIVE (React framework internals)**

All `innerHTML` usage in `content.883ade9e.js` and `popup.100f6462.js` is within React's reconciliation engine:

- **Line 491** (`content.883ade9e.js`): React property registry string
  ```js
  "children dangerouslySetInnerHTML defaultValue defaultChecked innerHTML ...".split(" ").forEach(...)
  ```
  This is React enumerating known DOM property names for its internal property system. Not a write operation.

- **Lines 845-848** (`content.883ade9e.js`): React SVG namespace handler
  ```js
  if ("http://www.w3.org/2000/svg" !== e.namespaceURI || "innerHTML" in e) e.innerHTML = t;
  else {
    (ef = ef || document.createElement("div")).innerHTML = "<svg>" + t.valueOf().toString() + "</svg>";
  }
  ```
  This is React's internal SVG rendering path, operating on React-controlled virtual DOM nodes. The values (`t`) come from React's reconciler, not from user/page-controlled input.

- **Line 5439** (`content.883ade9e.js`): React `<script>` element creation workaround
  ```js
  (e = u.createElement("div")).innerHTML = "<script></script>"
  ```
  Standard React workaround for creating script elements via DOM. Static content only.

No application code in this extension uses `innerHTML` with dynamic user or page-controlled content.

---

### Flag 2: `postmessage_no_origin`

**Verdict: FALSE POSITIVE (Plasmo library relay -- exported but never invoked by application code)**

The `@plasmohq/messaging` library (bundled at lines ~7490-7522 and ~9097-9156) includes a `window.postMessage`-based relay mechanism for bridging communication between MAIN world scripts and content scripts.

**Relay validation function** (line 7499):
```js
d = (e, t) => !t.__internal && e.source === globalThis.window && e.data.name === t.name
    && (void 0 === t.relayId || e.data.relayId === t.relayId)
```

This checks `e.source === globalThis.window` but does NOT check `e.origin`. In theory, any JavaScript running in the same page could forge a matching `postMessage` if it knew the `name` and `relayId`. The relay function `h = e => C(e, f)` would forward such messages to `chrome.runtime.sendMessage`.

**However, this is dead code.** The application uses:
- `useMessage` (line 7557, function `L`) which internally calls `p` (line 7522)
- `p` uses `chrome.runtime.onMessage.addListener` -- the secure Chrome extension messaging channel

The relay functions (`useMessageRelay`, `useRelay`, `relayMessage`, `sendToBackgroundViaRelay`, `sendViaRelay`) are exported from the Plasmo library but **never called** by any application code in this extension. The content script registers no relay listeners.

The `targetOrigin` in outgoing `postMessage` calls defaults to `"/"` (same-origin), which is correct restrictive behavior for the response path.

---

### Flag 3: `dynamic_tab_url`

**Verdict: FALSE POSITIVE (extension-internal URL with UUID)**

**Background script** (line 82-83):
```js
r?.redirect && chrome.tabs.create({
  url: `/options.html#/lite/edit/${r.id}`
})
```

- `r.id` is a UUID v4 generated at content script line 8943: `(0, o.v4)()`
- The message arrives via `chrome.runtime.onMessage` (extension-internal only)
- The URL template uses a relative path `/options.html#/...` which resolves to the extension's own origin (`chrome-extension://hmbnbbbknglecphfogchkhpdjiodfclh/options.html#/lite/edit/<uuid>`)
- The `onMessageExternal` listener (line 62) does NOT route to the `saveDetectedProfile` handler -- it is a no-op

Even if `r.id` were attacker-controlled, injecting into a `#` fragment of an extension-local HTML page has no security impact -- the fragment is parsed by the React Router in `options.html`, not by the server or browser navigation.

---

## Additional Observations

### `onMessageExternal` No-Op Listener

**File:** `static/background/index.js`, line 62
**Code:**
```js
chrome.runtime.onMessageExternal.addListener((e, t, r) => (e?.name, !0))
```

This accepts external messages from any other installed Chrome extension and returns `true` (keeping the response channel open), but performs no action. Without an `externally_connectable` manifest key, web pages cannot send messages -- only other extensions can.

**Assessment:** This is a Plasmo framework boilerplate pattern. It has no handler logic and does not expose any functionality. It is not exploitable but represents unnecessary attack surface. Best practice would be to either remove it or restrict it to specific extension IDs.

**Severity:** Informational / Code Quality

---

### Form Data Storage Security

The extension stores autofill profiles (including form field values like names, addresses, emails, passwords) in `chrome.storage.local`. This data:
- Is accessible to any code running within the extension's context
- Is not encrypted at rest
- Is standard practice for Chrome extension autofill tools
- Is equivalent to how Chrome's built-in autofill stores data

**Assessment:** Expected behavior for this class of extension. Not a vulnerability.

---

## Verified Vulnerabilities

**None.**

All triage flags were false positives caused by:
1. React framework internal DOM manipulation (innerHTML)
2. Plasmo messaging library relay exports that are bundled but unused (postMessage)
3. Extension-internal URL construction with UUID values (dynamic_tab_url)

---

## Risk Rating

**CLEAN** -- No exploitable vulnerabilities identified. The extension performs its stated function (form autofilling) using standard Chrome extension APIs and does not exhibit malicious behavior.
