# Security Analysis Report: Send Anywhere For Gmail

## Metadata
- **Extension Name**: Send Anywhere For Gmail
- **Extension ID**: amjmjholfoknokffkiolahocokcaecnc
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Version**: 24.0.2
- **Analysis Date**: 2026-02-07

## Executive Summary

Send Anywhere For Gmail is a legitimate file transfer extension that integrates with Gmail to enable file sharing through the Send Anywhere service. The extension demonstrates **good security practices** with appropriate permission usage, secure communication patterns, and transparent data handling. All network requests are directed to the extension's own infrastructure (send-anywhere.com). The extension uses Google Analytics for telemetry and integrates with Gmail via the InboxSDK library. No malicious behavior detected.

**Overall Risk Assessment: LOW**

## Vulnerability Details

### 1. Overly Permissive Web Accessible Resources
**Severity**: LOW
**Files**: `manifest.json` (lines 36-66)
**Code**:
```json
"web_accessible_resources": [
  {
    "matches": ["*://*/*", "file:///*"],
    "resources": ["file-upload.html", "pdf-upload.html",
                  "embedded-webapp.html", "img/ic_gmail.png", "*.js"]
  }
]
```
**Details**: The extension makes several resources (including `*.js` wildcard) accessible to all origins (`*://*/*`). While this enables the extension's cross-origin functionality, it could theoretically allow malicious sites to fingerprint the extension or detect its presence.

**Verdict**: This is a common pattern for extensions that need to inject UI across multiple domains. The exposed resources don't contain sensitive data, but the wildcard JS pattern is unnecessarily broad. **NOT MALICIOUS** - standard extension development practice with minor room for improvement.

---

### 2. Cookie Access to Third-Party Domain
**Severity**: LOW
**Files**: `manifest.json` (line 70), `chunk-821d2586.js` (lines 260-291)
**Code**:
```javascript
chrome.cookies.getAll({url: S}, function(s) {
  if (s.length > 0) {
    var c = {device_key: "", profile_name: ""};
    for (var a in s) {
      var u = s[a];
      if (u.name === "profile_name") n = u.value;
      else if (u.name === "device_key") c.device_key = u.value;
      else if (u.name === "session_key") {
        var l = V(u.value);
        i = p.getAppConfig("userId"), i && i !== l.id ? i = void 0 : l.id && (i = l.id)
      }
    }
  }
})
```
**Details**: Extension reads cookies from `send-anywhere.com` to maintain session state and device registration. This is used for legitimate authentication with the Send Anywhere service. The extension stores `device_key`, `profile_name`, and parses `session_key` (which is JWT-decoded to extract user ID).

**Verdict**: Legitimate authentication mechanism. The extension syncs session state between the extension and the web application. **NOT MALICIOUS** - necessary for the extension's core functionality.

---

### 3. Dynamic Script Injection in Gmail
**Severity**: LOW
**Files**: `chunk-821d2586.js` (lines 785-791), `inboxsdk.min.js`
**Code**:
```javascript
if (e.type === "inboxsdk__injectPageWorld" && t.tab) {
  chrome.scripting.executeScript({
    target: {tabId: t.tab.id},
    world: "MAIN",
    files: ["inboxsdk.min.js"]
  })
}
```
**Details**: Extension injects InboxSDK (a third-party library from Streak) into Gmail's main world execution context. InboxSDK is a well-known, legitimate library for Gmail integration (8,365 lines). This enables the extension to add UI elements to Gmail's compose interface.

**Verdict**: Standard practice for Gmail extensions. InboxSDK is a reputable library used by many extensions. The injection only occurs on Gmail/Inbox domains as specified in manifest. **NOT MALICIOUS** - legitimate third-party integration.

---

### 4. File Download and Upload Functionality
**Severity**: LOW
**Files**: `chunk-821d2586.js` (lines 452-657)
**Code**:
```javascript
async function ge(e, t) {
  try {
    const n = await fetch(e);
    if (!n.ok) throw new Error("failed to download data");
    const s = await n.arrayBuffer(),
      c = new Blob([s], {type: r});
    he(c, t, i)
  } catch (n) {
    d.error("[ERROR] downloadData ", n)
  }
}

async function he(e, t, n) {
  const i = {mode: "upload", file: [{name: n, size: e.size}]},
    r = await fetch(H.POST.KEY, {
      method: "POST",
      body: JSON.stringify(i),
      headers: {"Content-Type": "application/json"}
    });
  const o = await r.json();
  const s = new FormData;
  s.append("sendanywhereExtension", e, n),
  await me(o.weblink, s, o.key);
}
```
**Details**: Extension downloads files from user-selected URLs and uploads them to Send Anywhere servers. File operations include:
- Image context menu upload
- PDF sharing from Gmail attachments
- Thumbnail generation for images (300x300, JPEG compression)
- Progress tracking with abort controller

All uploads go to `send-anywhere.com` API endpoints (`/web/api/key` for key creation, then to upload endpoint).

**Verdict**: This is the core functionality of a file transfer extension. All operations are initiated by explicit user actions (context menu clicks, button clicks). **NOT MALICIOUS** - expected behavior for file sharing extension.

---

### 5. Embedded Iframe Communication
**Severity**: LOW
**Files**: `popup.js`, `embedded-wepapp.js`, `refresh-social-token.js`
**Code**:
```javascript
// refresh-social-token.js
async function a() {
  const r = await chrome.runtime.sendMessage({type: "get_app_hostname"});
  e.src = r + "/refresh-social-token", e.style.display = "none",
  n && n.appendChild(e)
}
window.addEventListener("message", function(n) {
  const e = document.getElementById("sa-refresh-iframe");
  !e || e.contentWindow !== n.source ||
    n.data.action === "remove_iframe" && t()
}, !1);
```
**Details**: Extension creates hidden iframes to `send-anywhere.com` for:
- Session token refresh
- OAuth/social login coordination
- Settings synchronization

PostMessage communication validates iframe source before processing messages.

**Verdict**: Standard cross-origin authentication pattern with proper origin validation. The iframe communication is limited to the extension's own backend. **NOT MALICIOUS** - secure implementation of cross-domain authentication.

---

### 6. Google Analytics Telemetry
**Severity**: LOW
**Files**: `chunk-821d2586.js` (lines 356-432), `chunk-d0d759b3.js` (lines 28-47)
**Code**:
```javascript
const ce = "https://www.google-analytics.com/mp/collect";
class ue {
  async fireEvent(t, n = {}, i) {
    const r = {
      client_id: await this.getOrCreateClientId(),
      events: [{name: t, params: n}]
    };
    await fetch(this.gaUrl, {method: "POST", body: JSON.stringify(r)});
  }
}
// GA4 Measurement IDs
CHROME.PROD: {
  MEASUREMENT_ID: "G-ZCJGSKCHZ4",
  API_SECRET: "eCAdjiVlTQCUkeKeTsclzQ"
}
```
**Details**: Extension sends anonymized usage telemetry to Google Analytics 4:
- Event types: `page_view`, `pdf_share_bt`, `gmail_bt`, `gmail_attach`, `send_start`, `slack_bt`, `slack_attach`
- Client ID generated via `crypto.randomUUID()` and stored in `chrome.storage.local`
- Session tracking with 30-minute timeout
- User properties synchronized from web app

**Verdict**: Standard analytics implementation with anonymous identifiers. No PII collected. Events track feature usage only. **NOT MALICIOUS** - transparent telemetry.

---

### 7. Context Menu Injection
**Severity**: LOW
**Files**: `chunk-821d2586.js` (lines 759-774)
**Code**:
```javascript
function D(e) {
  e == "image" ? chrome.contextMenus.create({
    id: "sa_img_context",
    title: chrome.i18n.getMessage("upload_image"),
    contexts: ["image"]
  }) : e == "editable" && chrome.contextMenus.create({
    id: "sa_editable_context",
    title: chrome.i18n.getMessage("gmail_hover_title"),
    contexts: ["editable"],
    documentUrlPatterns: ["*://*.slack.com/*"]
  })
}
```
**Details**: Extension adds right-click context menu entries:
1. "Upload image" on images (all sites where enabled)
2. Send Anywhere option on editable fields (Slack only)

Both require explicit user interaction to trigger.

**Verdict**: Context menus are user-initiated and limited to specific patterns. No automatic activation. **NOT MALICIOUS** - standard UX pattern.

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| InboxSDK script injection | `chunk-821d2586.js:785` | Legitimate third-party library (Streak's InboxSDK) for Gmail integration. Widely used by reputable extensions. |
| Wildcard web accessible resources | `manifest.json:42` | Overly broad but necessary for cross-origin UI injection. No sensitive data exposed. |
| Cookie reading | `chunk-821d2586.js:260` | Authentication with own backend (send-anywhere.com). Standard session management. |
| Google Analytics hooks | `chunk-821d2586.js:356` | Standard GA4 implementation for anonymous usage analytics. |
| Hidden iframe creation | `refresh-social-token.js:12` | Cross-domain authentication pattern with proper origin validation. |

## API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `https://send-anywhere.com/web/api/device` | POST | Device registration |
| `https://send-anywhere.com/web/api/key` | POST | Create file transfer key |
| `https://send-anywhere.com/web/api/key/{key}` | DELETE | Cancel/delete transfer |
| `https://www.google-analytics.com/mp/collect` | POST | Analytics telemetry |
| `https://send-anywhere.com/refresh-social-token` | GET (iframe) | OAuth token refresh |
| `https://send-anywhere.com/settings` | GET (iframe) | Settings page |

All endpoints are HTTPS and controlled by the extension vendor (Send Anywhere).

## Data Flow Summary

1. **User Authentication**:
   - User logs in via embedded iframe to send-anywhere.com
   - Session cookies (`session_key`, `device_key`, `profile_name`) stored on send-anywhere.com domain
   - Extension reads cookies to maintain session state
   - Device registration sent to `/web/api/device` with browser/extension metadata

2. **File Transfer**:
   - User clicks context menu or Gmail button to share file
   - Extension creates transfer key via POST to `/web/api/key`
   - File uploaded to Send Anywhere servers via FormData
   - Progress tracked, shareable link returned to user
   - Optional thumbnail generation for images (client-side, 300x300 JPEG)

3. **Gmail Integration**:
   - InboxSDK injected into Gmail's main world context
   - Extension adds "Send Anywhere" button to compose toolbar
   - Click triggers file selection and upload flow
   - No email content harvesting detected

4. **Analytics**:
   - Button clicks and feature usage tracked via GA4
   - Anonymous client ID (UUID) generated locally
   - Event names: `gmail_bt`, `send_start`, `pdf_share_bt`, etc.
   - No file contents or PII sent to analytics

5. **Permissions Usage**:
   - `cookies`: Read session from send-anywhere.com (auth)
   - `storage`: Store settings and client ID
   - `contextMenus`: Add "Upload image" option
   - `tabs`: Inject UI and send messages to active tab
   - `scripting`: Inject InboxSDK and content scripts
   - `activeTab`: Access current tab for file operations

## Content Security Policy

**Manifest CSP**: `script-src 'self'; object-src 'self';`

Strong CSP with no `unsafe-eval` or `unsafe-inline`. All scripts loaded from extension package. No remote script execution possible.

## Overall Risk Assessment

**Risk Level**: **LOW**

### Justification:
- All network requests go to legitimate, vendor-controlled domains (send-anywhere.com, google-analytics.com)
- No evidence of data exfiltration beyond declared file transfer functionality
- Strong CSP prevents code injection attacks
- Cookie access limited to own backend for authentication
- InboxSDK is a reputable third-party library
- Permissions appropriately scoped for functionality
- User-initiated actions required for all file operations
- Transparent analytics with anonymous identifiers
- No obfuscation (beyond standard minification)

### Recommendations:
1. Narrow web accessible resources wildcard (`*.js` → specific filenames)
2. Consider Content-Security-Policy for injected iframes
3. Add subresource integrity (SRI) for InboxSDK if possible
4. Document analytics collection in privacy policy

### Verdict:
**CLEAN** - This is a legitimate, well-designed file transfer extension with no malicious behavior. All functionality aligns with the extension's stated purpose. Security practices are above average for browser extensions.
