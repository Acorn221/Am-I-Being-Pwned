# Vulnerability Report: Расширение для плагина Госуслуг (Gosuslugi Plugin Extension)

## Metadata
| Field | Value |
|-------|-------|
| Extension ID | pbefkdcndngodfeigfdgiodgnmbgcfha |
| Name | Расширение для плагина Госуслуг |
| Version | 1.2.8 |
| Manifest Version | 2 |
| Users | ~5,000,000 |
| Permissions | `nativeMessaging` |
| Content Script Scope | Russian government domains (gosuslugi.ru, minsvyaz.ru, rt.ru, voskhod.ru, etc.) |

## Executive Summary

This is the official browser extension companion for the Gosuslugi (Russian Government Services) cryptographic plugin ("IFC Plugin"). It acts as a **pure message relay bridge** between whitelisted Russian government web pages and a locally installed native messaging host (`ru.rtlabs.ifcplugin`). The extension is developed by RT Labs (Rostelecom), the official contractor for Russian e-government infrastructure.

The extension is minimal (~40 lines of background JS, ~40 lines of content JS), requests only the `nativeMessaging` permission, and restricts content script injection to a narrow whitelist of Russian government domains. There is **no data collection, no remote endpoints, no dynamic code execution, no obfuscation, and no malicious behavior**.

## Vulnerability Details

### V-001: postMessage with wildcard origin (LOW)

| Field | Value |
|-------|-------|
| Severity | LOW |
| File | `content.js:15, 23` |
| CWE | CWE-345 (Insufficient Verification of Data Authenticity) |

**Code:**
```javascript
WND.postMessage(JSON.stringify({type: "FROM_IFC_EXT", msg_data: msg}), "*");
WND.postMessage(JSON.stringify({type: "IFC_EXT_DISCONNECT"}), "*");
```

**Analysis:** The content script uses `postMessage` with `"*"` as the target origin when sending messages from the native host back to the page. Since content scripts are only injected on whitelisted government domains, the actual attack surface is limited. However, using `"*"` instead of the specific origin is a minor hygiene issue.

**Verdict:** Low severity. The content scripts only run on whitelisted government domains, so the wildcard origin has minimal practical impact. The receiving page would need to be the government site itself.

### V-002: Message relay without payload validation (LOW)

| Field | Value |
|-------|-------|
| Severity | LOW |
| File | `background.js:32-36`, `content.js:26-39` |
| CWE | CWE-20 (Improper Input Validation) |

**Code:**
```javascript
// background.js - relays content script messages to native host
port.onMessage.addListener(function (msg) {
    if (NativePort)
        NativePort.postMessage(msg);
    else
        port.disconnect();
});

// content.js - relays page messages to background
if (event_data.type && (event_data.type === "TO_IFC_EXT")) {
    if (port)
        port.postMessage(event_data.msg_data);
}
```

**Analysis:** Messages are relayed without schema validation between the page, content script, background script, and native host. However, the content script does verify `event.source === WND` (same-window origin check) and checks for the `TO_IFC_EXT` message type. The native host application itself is the trust boundary and would need to validate its own input.

**Verdict:** Low severity. This is a message bridge pattern with basic type checking. The native host (`ru.rtlabs.ifcplugin`) is the actual security boundary and is responsible for its own input validation.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `postMessage(*, "*")` | content.js:15,23 | Noted as LOW finding - limited to government domains |
| `document.createElement('div')` | content.js:1,10 | DOM marker for extension detection - benign |
| `JSON.parse(event.data)` | content.js:33 | Wrapped in try/catch, standard message parsing |

## API Endpoints Table

| Endpoint | Type | Purpose |
|----------|------|---------|
| `ru.rtlabs.ifcplugin` | Native Messaging Host | Local cryptographic plugin by RT Labs |
| None | HTTP/HTTPS | Extension makes zero network requests |

## Data Flow Summary

```
Government Web Page (gosuslugi.ru etc.)
    ↓ window.postMessage({type: "TO_IFC_EXT", msg_data: ...})
Content Script (content.js)
    ↓ chrome.runtime.connect() / port.postMessage()
Background Script (background.js)
    ↓ chrome.runtime.connectNative('ru.rtlabs.ifcplugin')
Native Messaging Host (local IFC Plugin)
    ↓ (response flows back up the same chain)
Government Web Page
```

The extension is a **bidirectional message relay** with no data storage, no network calls, and no side effects beyond DOM marker elements for extension detection.

## Overall Risk Assessment

**CLEAN**

This extension is a legitimate, minimal native messaging bridge for the Russian government services cryptographic plugin. It has:
- Only 1 permission (`nativeMessaging`) - the minimum required for its function
- Content scripts strictly scoped to Russian government domains
- Zero network requests / remote endpoints
- Zero data collection or storage
- Zero dynamic code execution (`eval`, `Function()`, remote script loading)
- Zero obfuscation
- ~80 total lines of clear, readable JavaScript
- A straightforward bidirectional message relay architecture

The two LOW findings (wildcard postMessage origin and lack of payload schema validation) are minor hygiene issues that do not constitute security vulnerabilities given the restricted execution context. The extension does exactly what it claims: bridges communication between government websites and a locally installed cryptographic plugin.
