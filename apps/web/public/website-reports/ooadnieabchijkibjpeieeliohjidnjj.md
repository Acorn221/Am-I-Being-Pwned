# Vulnerability Report: 네이버 동영상 플러그인 (Naver Video Plugin)

## Metadata
| Field | Value |
|-------|-------|
| Extension ID | ooadnieabchijkibjpeieeliohjidnjj |
| Name | 네이버 동영상 플러그인 (Naver Video Plugin) |
| Version | 1.0.2.4 |
| Manifest Version | 3 |
| Users | ~5,000,000 |
| Total JS Files | 2 (background.js, content.js) |

## Executive Summary

This is a lightweight Naver first-party extension that bridges Naver's video web pages with a local native messaging host application. It uses Manifest V3 with minimal permissions (`activeTab`, `nativeMessaging`) and its content script is scoped exclusively to `*.naver.com` and `*.navercorp.com` domains. The extension contains no obfuscation, no remote code loading, no data exfiltration logic, and no third-party SDKs. The codebase is small (~150 lines total) and straightforward.

Two low-severity findings are noted: the content script uses `postMessage` with a wildcard origin (`'*'`), and the native messaging host name is constructed from external input without validation. Neither issue represents a realistic exploit path given the domain-restricted scope.

## Vulnerability Details

### 1. postMessage with Wildcard Origin (LOW)

- **Severity:** LOW
- **File:** `content.js` (line 27)
- **Code:**
  ```js
  window.postMessage(data, '*');
  ```
- **Description:** The `passToWeb` function sends messages using `window.postMessage` with a wildcard `'*'` target origin. This means any frame in the page (including potentially malicious iframes) could receive these messages. However, the content script only runs on `*.naver.com` and `*.navercorp.com` domains, and the data being passed originates from the extension's own native messaging host responses. The risk is limited to information leakage within Naver's own pages.
- **Verdict:** Low risk. The domain restriction significantly limits the attack surface. An attacker would need to inject a malicious iframe on naver.com to intercept these messages. Best practice would be to specify the Naver origin explicitly instead of `'*'`.

### 2. Unvalidated Native Host Name Construction (LOW)

- **Severity:** LOW
- **File:** `background.js` (lines 29, 104)
- **Code:**
  ```js
  var hostName = svc + "_" + ver;
  // ...
  port[svc] = chrome.runtime.connectNative(hostName);
  ```
- **Description:** The native messaging host name is built by concatenating `request.svc` and `request.ver` from external messages received via `onMessageExternal`. While `externally_connectable` restricts senders to `*.naver.com`/`*.navercorp.com`, the `svc` and `ver` values are not validated or sanitized before being used in `connectNative()`. Chrome's native messaging system requires pre-registered host names in the browser's native messaging manifests, which provides a built-in safeguard — `connectNative` will simply fail if the host name doesn't match a registered application. No injection or arbitrary execution is possible through this path.
- **Verdict:** Low risk. Chrome's native messaging registration requirement prevents abuse. However, input validation would be good defensive practice.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `window.postMessage` | content.js:27 | Legitimate bridge between extension and web page; domain-scoped |
| `chrome.runtime.connectNative` | background.js:105 | Legitimate native messaging for video plugin functionality |
| `chrome.runtime.onMessageExternal` | background.js:10 | Legitimate external messaging scoped to Naver domains only |

## API Endpoints Table

| Endpoint / Host | Type | Purpose |
|-----------------|------|---------|
| `{svc}_{ver}` (native host) | Native Messaging | Connects to local native application for video processing |
| `*.naver.com` / `*.navercorp.com` | Content Script Injection | Runs content script on Naver domains |

No HTTP/HTTPS fetch or XHR calls are made by the extension itself. All network communication is handled through Chrome's native messaging protocol to a local application.

## Data Flow Summary

1. **Naver web page** sends an external message to the extension via `chrome.runtime.sendMessage` (permitted by `externally_connectable`).
2. **Background script** receives the message, extracts `svc`, `ver`, and `param` fields.
3. **Background script** connects to a native messaging host named `{svc}_{ver}` using `chrome.runtime.connectNative`.
4. **Native host** responds; background script forwards the response to the originating tab via `chrome.tabs.sendMessage`.
5. **Content script** receives the response and passes it to the web page via `window.postMessage`.

Data flows exclusively between Naver web pages and a locally installed native application. No data is sent to external servers, no cookies or browsing data are accessed, and no user tracking occurs.

## Overall Risk Assessment

**CLEAN**

This is a minimal, purpose-built extension by Naver Corporation to facilitate communication between their video web service and a locally installed native application (likely a video codec or DRM helper). The permission set is minimal (only `activeTab` and `nativeMessaging`), the content script scope is tightly restricted to Naver's own domains, and the codebase is small and transparent with no obfuscation. The two low-severity findings (wildcard postMessage origin and unvalidated native host name construction) are mitigated by domain restrictions and Chrome's native messaging registration requirements respectively. There is no evidence of malicious behavior, data exfiltration, ad injection, proxy infrastructure, or any activity beyond its stated purpose.
