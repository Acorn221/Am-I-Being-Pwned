# VULN_REPORT: Monica: All-In-One AI Assist & Smartest AI Agent

## Metadata
- **Extension Name:** Monica: All-In-One AI Assist & Smartest AI Agent
- **Extension ID:** ofpnmcalabcbjgholdjcjblkibolbppb
- **Version:** 9.0.6
- **Manifest Version:** 3
- **User Count:** ~3,000,000
- **Analysis Date:** 2026-02-08

## Permissions Analysis
| Permission | Risk | Justification |
|---|---|---|
| `host_permissions: <all_urls>` | HIGH (scope) | Required for AI assistant features on all pages |
| `storage` | LOW | Local extension storage |
| `scripting` | MEDIUM | Used for content script injection and page interaction |
| `sidePanel` | LOW | Side panel UI feature |
| `contextMenus` | LOW | Right-click context menu integration |
| `optional: tabs` | MEDIUM | Requested for Browser Operator feature |
| `optional: tabGroups` | LOW | Tab group management |
| `optional: activeTab` | LOW | Active tab interaction |

## Executive Summary

Monica is a legitimate, full-featured AI assistant extension with ~3M users. It provides AI chat (GPT-4o, Claude, Gemini, etc.), web page summarization, translation, writing assistance, image generation, PDF reading, YouTube subtitle extraction, search enhancement, and a "Browser Operator" agent feature. The extension is developed by Monica.im (butterfly-effect.dev).

The extension is **highly invasive in scope** -- it injects a content script on all URLs, accesses page content for AI features, monitors text selection, captures visible tabs for screenshots, and sends user behavior events to its API. However, all of these behaviors are **consistent with its stated AI assistant functionality**. No evidence of malicious behavior, data exfiltration beyond intended features, hidden proxy infrastructure, market intelligence SDKs, or obfuscated payloads was found.

## Vulnerability Details

### 1. XHR Prototype Hooking in YouTube Injected Script
- **Severity:** LOW
- **File:** `static/youtube-injected-script.js`
- **Code:**
  ```javascript
  const originOpen = XMLHttpRequest.prototype.open
  const open = function () {
    // intercepts YouTube timedtext API calls
    if (_url && isSubtitleRequest(_url) && videoId === requestVideoId) {
      window.postMessage({ type: 'monica-getTimedtextUrl', url: _url, videoId: videoId }, '*')
    }
    return originOpen.apply(this, arguments)
  }
  Object.defineProperty(XMLHttpRequest.prototype, 'open', { value: open, writable: true })
  ```
- **Verdict:** This hooks `XMLHttpRequest.prototype.open` to intercept YouTube subtitle/timedtext API requests. The purpose is to extract subtitle URLs for the video summarization feature. This is narrowly scoped (only targets `/api/timedtext` on YouTube) and consistent with the extension's stated functionality. **Not malicious, but notable XHR hooking.**

### 2. PDF Selected Text Polling
- **Severity:** LOW
- **File:** `static/pdf-injected-script.js`
- **Code:**
  ```javascript
  setInterval(() => {
    document.querySelector('embed').postMessage({ type: 'getSelectedText' }, '*')
  }, 200)
  ```
- **Verdict:** Polls the PDF embed every 200ms for selected text. Used for "ask AI about selected text" feature. Aggressive polling interval but functionally benign.

### 3. External Message Handler (Browser Operator)
- **Severity:** MEDIUM
- **File:** `background.js`
- **Code:**
  ```javascript
  chrome.runtime.onMessageExternal.addListener((n,i) => {
    if (n.name === "browserOperator.requestPermission") {
      let o = i?.tab?.id;
      nU(r => { o && Yd.sendMessage({tabId: o, name: "browserOperator.permissionResult", data: r}) })
    }
  })
  ```
- **Verdict:** The extension exposes an external message handler that allows Monica's own web properties (monica.im, powerup.monica.im, monica.butterfly-effect.dev -- per `externally_connectable` in manifest) to request additional permissions (tabs, tabGroups, activeTab) and trigger browser automation via the "Browser Operator" feature. This is gated by `externally_connectable` domain restrictions and requires explicit user permission grant via `chrome.permissions.request()`. **Not a vulnerability per se, but the Browser Operator feature grants Monica's server-side AI significant browser control once permissions are granted.**

### 4. Broad Content Script Injection on Install/Update
- **Severity:** LOW
- **File:** `background.js`
- **Code:**
  ```javascript
  at.default.tabs.query({}).then(n => {
    n.forEach(i => {
      i.id && at.default.scripting.executeScript({files:["content.js"], target:{tabId:i.id}}).catch(() => {})
    })
  })
  ```
- **Verdict:** On install/update, re-injects content.js into all open tabs. Standard pattern for extensions that need to maintain functionality across updates.

### 5. User Behavior Event Tracking with URL Collection
- **Severity:** LOW
- **File:** `background.js`
- **Code:**
  ```javascript
  push(e) {
    N.isWeb && (e.extData || (e.extData = {}), e.extData.url = window.location.href);
    this.events.push(e);
    this.doChecking();
  }
  ```
- **Verdict:** Behavior events collect URLs but only in the web app context (`N.isWeb` check), not from the extension content script. Events are batched and sent to Monica's API. Event types are feature-specific (e.g., `context_menu_click`, `extension_install`, `chat_toolbar_click`) -- not broad browsing surveillance.

### 6. Screen Capture via captureVisibleTab
- **Severity:** LOW
- **File:** `background.js`
- **Code:**
  ```javascript
  async captureVisibleTab() {
    return Ce.getBrowser().tabs.captureVisibleTab(void 0, {format: "jpeg"})
  }
  ```
- **Verdict:** Used for "Screenshot & Ask AI" feature. Standard API usage consistent with stated functionality.

## False Positive Table
| Pattern | Location | Reason |
|---|---|---|
| `eval()` (3 in background, 12 in content) | background.js, content.js | All instances are within bundled library code (webpack/Parcel runtime, polyfills) -- standard `new Function()` patterns for environment detection |
| `new Function("")` | content.js | Webpack feature detection for strict mode -- not dynamic code execution |
| `innerHTML` usage | content.js | React/D3/PDF.js/Readability library code for DOM rendering, not injection vectors |
| `postMessage` | content.js | PDF.js worker communication, internal messaging framework -- not cross-origin data exfiltration |
| `document.cookie` | background.js, content.js | Axios HTTP client cookie handling and Monica web app theme persistence -- not cookie harvesting |
| `Proxy` objects | background.js | MobX state management library -- not proxy infrastructure |
| `atob`/`btoa`/`fromCharCode` | background.js | Standard base64 encoding in Axios auth headers and media file handling |
| Keyboard event listeners | content.js | React synthetic event system and standard DOM event handling -- not keyloggers |
| `getSelection()` | content.js | PDF.js text selection and Monica's "explain selected text" AI feature |
| `getPageContent()` | content.js | Search engine result parsing for search enhancement sidebar -- extracts search result titles/snippets on Google/Bing/DuckDuckGo etc., not arbitrary page scraping |

## API Endpoints Table
| Endpoint | Method | Purpose |
|---|---|---|
| `https://api.monica.im/*` | POST | Primary API (chat, generation, user actions) |
| `https://api.monica.im/agent_v1/*` | POST | AI agent/Browser Operator API |
| `wss://api.monica.im/centrifugo/connection/websocket` | WSS | Real-time WebSocket for Browser Operator |
| `wss://note.monica.im/` | WSS | Real-time notes/memo sync |
| `wss://monica.im/api/realtime` | WSS | Real-time AI streaming |
| `wss://monica.im/api/realtime_v2` | WSS | Real-time AI streaming v2 |
| `https://api-edge.cognitive.microsofttranslator.com/translate` | POST | Microsoft Translation API |
| `https://edge.microsoft.com/translate/auth` | GET | Microsoft Translator auth token |
| `https://assets.monica.im/*` | GET | Static assets (images, fonts, audio) |
| `https://agent.monica.im/` | Various | Agent service |
| `https://monica.im/*` | Various | Main website (auth, web app) |

## Data Flow Summary

1. **Content Script -> Background:** User interactions (text selection, context menu, keyboard shortcuts) trigger messages from content.js to background.js via `chrome.runtime.sendMessage`.
2. **Background -> Monica API:** Background script sends authenticated requests to `api.monica.im` for AI generation, chat, translation, OCR, image tools, and more.
3. **Monica Web -> Extension:** Monica.im web properties can communicate with the extension via `externally_connectable` for Browser Operator permission requests and session management.
4. **WebSocket Channels:** Real-time streaming for AI responses and Browser Operator control via Centrifugo WebSocket.
5. **Page Content Access:** Content script extracts search results from search engines (Google, Bing, DuckDuckGo, etc.) for search enhancement. YouTube subtitle URLs are intercepted for video summarization. PDF text selection is monitored for AI Q&A.
6. **Behavior Telemetry:** Feature usage events (not browsing history) are batched and reported to Monica's API with feature-specific event names.

## Overall Risk Assessment

**CLEAN**

Monica is a highly capable, legitimately invasive AI assistant. It requires broad permissions (`<all_urls>`, `scripting`, screen capture) and accesses page content -- but all observed behaviors directly serve its stated AI assistant features (chat, summarization, translation, writing, search enhancement, Browser Operator). Key findings:

- **No malicious data exfiltration** -- telemetry is feature-scoped, not browsing surveillance
- **No hidden proxy/VPN infrastructure**
- **No market intelligence SDKs** (Sensor Tower, Pathmatics, etc.)
- **No extension enumeration or killing**
- **No ad/coupon injection**
- **No obfuscated payloads** -- code is webpack-bundled but standard
- **No remote config kill switches** beyond standard A/B experiment flags
- **XHR hooking is narrowly scoped** to YouTube subtitle extraction only
- **External messaging is restricted** to Monica's own domains via `externally_connectable`

The Browser Operator feature is the most security-sensitive aspect, as it allows Monica's server-side AI to automate browser actions, but it requires explicit user permission grants and is a marketed premium feature, not hidden functionality.
