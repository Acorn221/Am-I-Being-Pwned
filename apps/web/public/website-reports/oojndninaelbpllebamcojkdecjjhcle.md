# Vulnerability Report: Chat to Notion (oojndninaelbpllebamcojkdecjjhcle)

**Extension:** Chat to Notion v2.0.1
**Author:** Theo Lartigau
**Manifest Version:** 3
**Analysis Date:** 2026-02-06
**Triage Flags:** V1=10, V2=0 (innerhtml_dynamic, postmessage_no_origin)

---

## Executive Summary

Chat to Notion is a Plasmo-based extension that saves conversations from ChatGPT, Claude, DeepSeek, and Mistral to Notion databases. The extension captures HTTP request headers (including authorization tokens and session cookies) via `webRequest.onSendHeaders` to authenticate its own API calls to conversation endpoints.

After thorough analysis of all JS files, the triage flags are largely **false positives** caused by bundled library code. However, one low-severity finding and two informational observations warrant documentation.

---

## Triage Flag Disposition

### Flag: `innerhtml_dynamic` -- FALSE POSITIVE

All `innerHTML` assignments in the codebase fall into three categories, none of which represent real vulnerabilities:

1. **React DOM reconciliation** (chatgpt.d4913cf1.js:1, claude.42a83eca.js:1, deepseek.71939a0e.js:1, mistral.435ef3c1.js:1, popup.c8d8412b.js:1, tabs/update.2a597087.js:1) -- React's internal SVG namespace handler: `if ("http://www.w3.org/2000/svg" !== e.namespaceURI || "innerHTML" in e) e.innerHTML = t`. This is standard React behavior for setting SVG content.

2. **HTML entity parsing library** (all bundled files) -- A character reference decoder: `n.innerHTML = r; t = n.textContent`. Uses a temporary `<i>` element to decode HTML entities. Standard library pattern.

3. **DOM content reading (not writing)** in fetchFullPage.4d269ce4.js:68 -- `e.innerHTML` is READ from existing `.markdown` elements on the ChatGPT page and sent as conversation data. This is reading existing DOM content, not injecting untrusted data.

### Flag: `postmessage_no_origin` -- FALSE POSITIVE (with caveat)

The `@plasmohq/messaging` library (bundled in auth.075e4944.js, popup.c8d8412b.js, autoSave.b328673b.js) defines a postMessage relay system with the following validation function:

```javascript
// auth.075e4944.js:94
d = (e, t) => !t.__internal
  && e.source === globalThis.window
  && e.data.name === t.name
  && (void 0 === t.relayId || e.data.relayId === t.relayId)
```

This checks `e.source === globalThis.window` but does NOT check `e.origin`. However, the relay functions (`relayMessage`, `sendToBackgroundViaRelay`, `sendViaRelay`) are **never invoked** by any content script in this extension. They are only exported as part of the `@plasmohq/messaging` library module but the extension exclusively uses `sendToBackground()` (which uses `chrome.runtime.sendMessage` internally), bypassing the postMessage relay entirely. Since the relay listener is never registered, there is no active attack surface.

---

## Findings

### Finding 1: Authorization Header and Cookie Capture via webRequest

| Property | Value |
|----------|-------|
| **Severity** | Informational |
| **CVSS 3.1** | 0.0 (N/A -- by design, not a vulnerability) |
| **Affected File** | `static/background/index.js` (line 1, long line) |

**Description:**

The extension uses `chrome.webRequest.onSendHeaders` with `["requestHeaders", "extraHeaders"]` to capture full HTTP request headers from XHR requests to ChatGPT, Claude, DeepSeek, and Mistral. This includes:

- `Authorization` headers (Bearer tokens) for ChatGPT, DeepSeek, Mistral
- `Cookie` headers (session cookies) for Claude

The captured headers are stored in Plasmo's encrypted session storage (`secretKeyList: ["token", "cacheHeaders"]`) and used to make authenticated API calls to fetch conversation data for saving to Notion.

```javascript
// Background script - header capture
let c = (e, t) => {
  s.set(o.STORAGE_KEYS.cacheHeaders, { model: e, headers: t }),
  i.set(o.STORAGE_KEYS.hasCacheHeaders, !0)
};

chrome.webRequest.onSendHeaders.addListener(e => {
  // Captures Authorization headers from ChatGPT, DeepSeek, Mistral
  // Captures Cookie headers from Claude
  if (e.requestHeaders.some(e => "authorization" === e.name.toLowerCase()) && e.url.includes("chatgpt.com")) {
    c("chatgpt", e.requestHeaders);
    return;
  }
  // ... similar for other services
}, {
  urls: ["https://chatgpt.com/*", "https://chat.deepseek.com/*", "https://chat.mistral.ai/*", "https://claude.ai/*"],
  types: ["xmlhttprequest"]
}, ["requestHeaders", "extraHeaders"]);
```

**Assessment:** This is legitimate functionality required for the extension's core purpose (saving conversations). The headers are stored encrypted in session storage (not persistent) and are only used to call the respective AI service APIs. They are NOT exfiltrated to the extension's backend server (`chatgpt-to-notion.onrender.com`). The `onrender.com` server is only used for Notion OAuth token exchange.

**Risk:** If the extension were compromised (supply chain attack, developer account takeover), these cached credentials could theoretically be exfiltrated. Users should be aware the extension has access to their AI service session tokens while active.

---

### Finding 2: Broad `scripting` Permission with executeScript on AI Chat Tabs

| Property | Value |
|----------|-------|
| **Severity** | Informational |
| **CVSS 3.1** | 0.0 (N/A -- by design, not a vulnerability) |
| **Affected File** | `static/background/index.js` (line 1, long line) |

**Description:**

The extension uses `chrome.scripting.executeScript` to inject fetch calls directly into Claude, DeepSeek, and Mistral tabs. This is done because these services require same-origin requests with credentials:

```javascript
// Claude conversation fetch via executeScript
let o = await chrome.scripting.executeScript({
  target: { tabId: n.id },
  func: (e, t, r) => fetch(
    `https://claude.ai/api/organizations/${r}/chat_conversations/${t}?tree=True...`,
    { method: "GET", headers: e, mode: "cors", credentials: "include" }
  ).then(e => e.json()),
  args: [t, e, a]
});
```

**Assessment:** This pattern injects code into the active tab to make authenticated requests. It is used legitimately to fetch conversation history. The injected function is hardcoded (not dynamic) and only fetches from the expected AI service domains. The `scripting` permission combined with the host permissions for these domains is the minimum required for this functionality.

---

### Finding 3: No-op `onMessageExternal` Listener

| Property | Value |
|----------|-------|
| **Severity** | Informational |
| **CVSS 3.1** | 0.0 (N/A -- no exploitable behavior) |
| **Affected File** | `static/background/index.js` (line 1, long line) |

**Description:**

The background script registers an `onMessageExternal` listener that does nothing meaningful:

```javascript
chrome.runtime.onMessageExternal.addListener((e, t, r) => (e?.name, !0));
```

This reads `e.name` (comma operator discards the result) and returns `true` (keeping the message channel open). Without an `externally_connectable` manifest key, this listener can only be triggered by other installed extensions, not websites. No `externally_connectable` key was found in the manifest.

**Assessment:** This appears to be boilerplate from the Plasmo framework. It has no functional impact -- the listener does not route messages to any handlers and does not send any response data. There is no security risk since: (a) no data is returned to the caller, (b) no operations are triggered, and (c) without `externally_connectable`, web pages cannot invoke it.

---

## Architecture Summary

| Component | File | Purpose |
|-----------|------|---------|
| Background Service Worker | `static/background/index.js` | Message routing, webRequest header capture, Notion API calls |
| Auth Content Script | `auth.075e4944.js` | OAuth redirect handler on Notion site |
| AutoSave Content Script | `autoSave.b328673b.js` | Auto-save conversations on ChatGPT/DeepSeek |
| Fetch Full Page | `fetchFullPage.4d269ce4.js` | Extract full ChatGPT conversation via DOM |
| Chat UI Content Scripts | `chatgpt.d4913cf1.js`, `claude.42a83eca.js`, `deepseek.71939a0e.js`, `mistral.435ef3c1.js` | React UI overlay for save button |
| Popup Content Script | `popup.c8d8412b.js` | Injected popup on chat pages |
| Popup Page | `popup.html` + `popup.100f6462.js` | Extension popup (settings, DB selection) |
| Update Tab | `tabs/update.2a597087.js` | Post-update changelog page |

### Permissions Analysis

| Permission | Justification |
|------------|--------------|
| `storage` | Stores Notion DB config, user preferences |
| `tabs` | Query active tab for conversation context |
| `webRequest` | Capture auth headers for API calls |
| `scripting` | Inject fetch calls into Claude/DeepSeek/Mistral tabs |
| Host: `api.notion.com` | Notion API for saving conversations |
| Host: `chatgpt-to-notion.onrender.com` | OAuth token exchange backend |
| Host: ChatGPT/Claude/DeepSeek/Mistral | Content script injection and API access |

### External Communications

| Endpoint | Data Sent | Purpose |
|----------|-----------|---------|
| `chatgpt-to-notion.onrender.com/token/new` | Notion OAuth code | Token exchange |
| `chatgpt-to-notion.onrender.com/token` | workspace_id, user_id | Token refresh |
| `api.notion.com/v1/*` | Conversation data (via Notion SDK) | Save to Notion |
| `maxai.me/partners/installed/chatgpt-to-notion/` | None (redirect on install) | Install tracking |
| `extensions-hub.com/partners/uninstalled` | None (set as uninstall URL) | Uninstall tracking |

---

## Conclusion

**Overall Risk: LOW**

No exploitable vulnerabilities were found. Both triage flags (`innerhtml_dynamic` and `postmessage_no_origin`) are false positives caused by bundled library code (React DOM internals and unused Plasmo messaging relay functions, respectively).

The extension's design requires capturing AI service session credentials, which it handles appropriately using encrypted session storage. The credentials are used locally for their intended purpose (fetching conversations) and are not exfiltrated. The extension's backend server (`chatgpt-to-notion.onrender.com`) is only involved in Notion OAuth token exchange, not in handling AI service credentials.

The primary residual risk is supply-chain: if the extension or its backend were compromised, the cached auth headers for ChatGPT/Claude/DeepSeek/Mistral could be exfiltrated. This is inherent to the extension's architecture and cannot be mitigated without fundamentally changing how it works.
