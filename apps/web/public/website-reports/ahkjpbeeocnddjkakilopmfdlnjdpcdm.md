# Vulnerability Report: Kaspersky Protection

## Metadata
- **Extension Name:** Kaspersky Protection
- **Extension ID:** ahkjpbeeocnddjkakilopmfdlnjdpcdm
- **Version:** 2.13.33.2
- **Manifest Version:** 3
- **User Count:** ~20,000,000
- **Analysis Date:** 2026-02-08

## Executive Summary

Kaspersky Protection is the official browser companion extension for Kaspersky's desktop antivirus/internet security product. It communicates exclusively via Chrome's `nativeMessaging` API with the locally installed Kaspersky product (`com.kaspersky.ahkjpbeeocnddjkakilopmfdlnjdpcdm.host`). The extension provides web protection features including: URL reputation checking (URL Advisor), phishing detection, ad/banner blocking, password strength checking, compromised account detection, virtual keyboard for secure input, cookie consent auto-clicking, and a malicious extension remover.

The extension requests extensive permissions (`<all_urls>`, `webRequest`, `cookies`, `management`, `nativeMessaging`, `scripting`, `tabs`, `webNavigation`, `declarativeNetRequest`, `storage`, `alarms`, `contextMenus`) and injects content scripts into all web pages. However, **all data flows go through the native messaging channel to the locally installed Kaspersky product** -- there are zero hardcoded remote endpoints, zero `fetch()`/`XMLHttpRequest`/`WebSocket` calls, and zero dynamic code execution (`eval`/`new Function`). The CSP is restrictive: `script-src 'self'; connect-src 'self'; object-src 'self'`.

While the extension is highly invasive by nature (it monitors all web traffic, intercepts form submissions, reads page DOM, tracks search queries, monitors cookies, and can remove other extensions), every capability directly serves a legitimate antivirus/internet security function and all data is processed locally via the native host, not sent to remote servers from the extension itself.

## Vulnerability Details

### INFO-01: Broad Permission Surface
- **Severity:** INFORMATIONAL
- **Files:** `manifest.json`
- **Code:** `"host_permissions": ["<all_urls>"]`, permissions include `webRequest`, `cookies`, `management`, `nativeMessaging`, `scripting`, `tabs`, `webNavigation`, `declarativeNetRequest`
- **Verdict:** EXPECTED - These permissions are required for a comprehensive browser security product. All capabilities serve legitimate antivirus functions.

### INFO-02: Password Hash Submission to Native Host
- **Severity:** INFORMATIONAL
- **Files:** `content/website_credentials.js`
- **Code:**
  ```javascript
  var hash = ns.md5(element.value) || "";
  var url = GetFormAction(parentForm) || document.location.toString() || "";
  var args = { url: url, passwordHash: hash };
  m_callFunction("wsc.WebsiteCredentialSendPasswordHash", args);
  ```
- **Verdict:** EXPECTED - The extension monitors password input fields and sends MD5 hashes (not plaintext) to the local Kaspersky product for compromised password checking. This is a standard feature of Kaspersky's "Data Leak Checker" / compromised credentials detection. The hash is sent only via nativeMessaging to the local product, never to any remote server from the extension.

### INFO-03: Account Name Collection on Form Submit
- **Severity:** INFORMATIONAL
- **Files:** `content/compromised_account.js`
- **Code:**
  ```javascript
  accounts.push(ns.ToBase64(accountElement.value));
  // ...
  CallService("onAccount", { accounts: accounts });
  ```
- **Verdict:** EXPECTED - On form submission, login field values are Base64-encoded and sent to the local Kaspersky product for compromised account checking. This is standard functionality for Kaspersky's identity protection features.

### INFO-04: Full DOM Content Sent to Native Host
- **Severity:** INFORMATIONAL
- **Files:** `content/webpage.js`
- **Code:**
  ```javascript
  m_callFunction("wp.content", { dom: document.documentElement.innerHTML });
  ```
- **Verdict:** EXPECTED - Page DOM content is sent to the local Kaspersky product for phishing/malware page analysis. This is core antivirus functionality.

### INFO-05: Search Query Monitoring
- **Severity:** INFORMATIONAL
- **Files:** `content/search_activity.js`
- **Code:**
  ```javascript
  m_callFunction("sam.SearchResult2", searchResult);
  // searchResult includes: url, queryText, typedText
  ```
- **Verdict:** EXPECTED - Search queries are sent to the local Kaspersky product for Safe Search / parental control features. Data goes only to the native host.

### INFO-06: Extension Removal Capability
- **Severity:** INFORMATIONAL
- **Files:** `additional/extension_remover.js`, `background/extension_remover_background.js`
- **Code:**
  ```javascript
  ApiCall(browsersApi.management.uninstall).Start(settings.id);
  ```
- **Verdict:** EXPECTED - The extension can uninstall other extensions flagged by Kaspersky as malicious. This is a legitimate security feature triggered by the local Kaspersky product when it detects a dangerous extension. The UI (`extension_remover.html`) shows the user a confirmation dialog before removal.

### INFO-07: Web Request Interception
- **Severity:** INFORMATIONAL
- **Files:** `background/enhance_extension.js`
- **Code:**
  ```javascript
  browsersApi.webRequest.onBeforeSendHeaders.addListener(onBeforeSendHeaders, filter);
  browsersApi.webRequest.onHeadersReceived.addListener(onHeadersReceived, filter);
  // Sends request headers, response headers, URLs to native host
  ```
- **Verdict:** EXPECTED - Full web request monitoring (URLs, headers, redirects) is sent to the local Kaspersky product for web threat protection, anti-phishing, and safe browsing. This is core functionality.

### INFO-08: Cookie Read/Write via Native Host Commands
- **Severity:** INFORMATIONAL
- **Files:** `background/browser_cookie.js`
- **Code:**
  ```javascript
  ApiCall(browsersApi.cookies.getAll).Start({ url: getCookieDetails.url });
  ApiCall(browsersApi.cookies.set).Start(cookieArg);
  ```
- **Verdict:** EXPECTED - The local Kaspersky product can instruct the extension to read and set cookies. This supports Kaspersky's Safe Money / online banking protection features.

### INFO-09: Self-Uninstall on Native Host Disconnection
- **Severity:** INFORMATIONAL
- **Files:** `background/native_messaging_accessor.js`
- **Code:**
  ```javascript
  function RemoveSelfIfNeed() {
      browsersApi.storage.local.get(["InstalledBeforeProduct"], values => {
          if (values.InstalledBeforeProduct === false)
              browsersApi.management.uninstallSelf();
      });
  }
  ```
- **Verdict:** EXPECTED - If the native messaging host is not found (Kaspersky product uninstalled), and the extension was installed after the product, it uninstalls itself. This is clean lifecycle management.

### INFO-10: Tab URL and Navigation Monitoring
- **Severity:** INFORMATIONAL
- **Files:** `background/web_navigation.js`, `content/web_session_monitor.js`
- **Verdict:** EXPECTED - Navigation events (onCommitted, onBeforeNavigate, onBeforeRedirect), tab creation/removal, and page focus/blur events are tracked and reported to the native host. This supports Kaspersky's browsing history protection, parental controls, and safe browsing features.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML` read | `content/webpage.js`, `background/user_feedback_background.js` | Reading DOM for phishing analysis and broken webpage reporting - legitimate security feature |
| `document.location.href` redirect | `background/extension.js` Redirect function | Command from native Kaspersky product for blocking redirect - legitimate security feature |
| `cookies.getAll` / `cookies.set` | `background/browser_cookie.js` | Controlled by local Kaspersky product for Safe Money protection |
| `management.uninstall` | `additional/extension_remover.js` | User-confirmed removal of extensions flagged as malicious by Kaspersky AV |
| `management.uninstallSelf` | `background/native_messaging_accessor.js` | Lifecycle cleanup when Kaspersky product is uninstalled |
| `declarativeNetRequest.updateSessionRules` | `background/enhance_extension.js` | Blocking URLs flagged by Kaspersky product as malicious |
| MD5 password hashing | `content/website_credentials.js` | Compromised credential checking via local product |
| Base64 encoding of login values | `content/compromised_account.js` | Identity protection via local product |
| `tabs.executeScript` | `background/extension.js` | Executing reload/redirect commands from native host |
| XHR header monitoring | `background/xhr_tracker.js` | Detecting CORS/XSS attacks |

## API Endpoints Table

| Endpoint | Type | Purpose |
|----------|------|---------|
| `com.kaspersky.ahkjpbeeocnddjkakilopmfdlnjdpcdm.host` | Native Messaging Host | **Only communication channel** - all data flows through this local native messaging connection to the installed Kaspersky product |
| `http://touch.kaspersky.com` | Internal URL pattern | Used by extension remover background to detect Kaspersky internal pages for redirect handling |
| `https://clients2.google.com/service/update2/crx` | Chrome Update URL | Standard Chrome Web Store auto-update endpoint |

**Note:** There are ZERO remote HTTP/HTTPS/WebSocket endpoints called directly by the extension. All network communication is handled by the locally installed Kaspersky product via the native messaging channel.

## Data Flow Summary

```
[Web Pages] --content scripts--> [Extension Background (Service Worker)]
                                        |
                                        | (nativeMessaging only)
                                        v
                              [Local Kaspersky Product]
                              (com.kaspersky.*.host)
```

1. **Content scripts** inject into all HTTP/HTTPS pages and collect: page DOM, URLs, form data (password hashes, login names), search queries, link URLs for categorization, navigation events, focus/blur events
2. **Content scripts** communicate with the **background service worker** via `chrome.runtime.connect()` ports
3. **Background service worker** aggregates data and sends it via `chrome.runtime.connectNative()` to the **local Kaspersky product**
4. **Local Kaspersky product** sends commands back: URL verdicts, redirect/block instructions, settings updates, extension removal requests
5. **No data leaves the extension to any remote server** - the Kaspersky product handles all external network communication

## Overall Risk Assessment

**CLEAN**

This is a legitimate browser security extension from Kaspersky, one of the world's largest cybersecurity companies. While it is exceptionally invasive (monitoring all web traffic, reading DOM content, tracking form submissions, intercepting cookies, and capable of removing other extensions), every capability directly serves a documented antivirus/internet security function. Key factors supporting CLEAN classification:

1. **No remote endpoints** - Zero `fetch()`, `XMLHttpRequest`, `WebSocket`, or any external network calls from the extension code
2. **No dynamic code execution** - Zero `eval()`, `new Function()`, `import()`, or dynamic script injection
3. **Restrictive CSP** - `script-src 'self'; connect-src 'self'; object-src 'self'`
4. **Native messaging only** - All data flows to the locally installed Kaspersky product via native messaging
5. **No obfuscation** - Code is clean, well-structured, and readable with descriptive function/variable names
6. **Proper security checks** - Validates sender IDs, checks `runtime.lastError`, proper error handling
7. **Password protection** - Sends MD5 hashes of passwords, not plaintext
8. **User consent** - Extension removal shows confirmation UI before acting
9. **20M users** from a well-known security vendor with extensive third-party auditing
