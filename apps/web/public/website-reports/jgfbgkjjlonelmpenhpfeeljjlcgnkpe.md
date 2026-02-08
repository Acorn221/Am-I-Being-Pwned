# Vulnerability Report: ClassLink OneClick Extension

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | ClassLink OneClick Extension |
| Extension ID | jgfbgkjjlonelmpenhpfeeljjlcgnkpe |
| Version | 12.6 |
| Manifest Version | 3 |
| User Count | ~18,000,000 |
| Publisher | ClassLink |

## Executive Summary

ClassLink OneClick is a Single Sign-On (SSO) extension used widely in K-12 education to automate logins to web applications. The extension injects content scripts on every page (`*://*/*`), manages SSO authentication flows by interacting with ClassLink's launchpad domains, and tracks application usage analytics. While the extension requests broad permissions including `*://*/*` host permissions and injects content scripts on all pages, these permissions are clearly necessary for its SSO automation functionality. The extension communicates only with ClassLink-owned domains and does not exhibit malicious behavior.

**However, there are notable security concerns**: the extension contains an arbitrary script execution pathway (`execute-script` message handler) that allows ClassLink servers to inject arbitrary JavaScript into the MAIN world of any tab, and uses AES-encrypted credentials decrypted client-side with an MD5-derived key. These are architectural concerns inherent to SSO automation but present real attack surface.

## Vulnerability Details

### VULN-001: Arbitrary Script Execution via `execute-script` Message Handler
- **Severity**: MEDIUM
- **File**: `background.js`
- **Code**:
```javascript
"execute-script"==n.type && chrome.scripting.executeScript({
    target:{tabId:c},
    func:function(e){
        var t=document.createElement("script");
        t.textContent=e;
        document.documentElement.appendChild(t);
        t.remove()
    },
    args:[n.data],
    world:"MAIN"
})
```
- **Verdict**: The background script listens for `execute-script` messages from content scripts and injects arbitrary JavaScript into the MAIN world of the sender's tab. This code creates a `<script>` element with arbitrary content. The script content originates from `pre_auth_script` and `post_auth_script` fields in the ClassLink server response (`appResponse`). While only triggered by ClassLink SSO flows from trusted ClassLink domains, if the ClassLink server were compromised, this could be used to inject arbitrary code into any page where SSO is active. The message originates from content scripts on ClassLink domains, so it requires the user to be on a ClassLink page. This is a design choice for SSO flexibility but carries inherent risk.

### VULN-002: Broad Content Script Injection on All URLs
- **Severity**: LOW
- **File**: `manifest.json`
- **Code**:
```json
"content_scripts":[{
    "all_frames":true,
    "matches":["*://*/*"],
    "js":["detection.js","jquery-3.5.0.min.js","crypto_aes.js","injected.js"]
}]
```
- **Verdict**: Four content scripts (including jQuery 3.5.0 and CryptoJS AES) are injected into every page and every frame. This is a large attack surface. However, the content scripts are designed to detect ClassLink SSO pages and only activate SSO logic on ClassLink domains. The `detection.js` script simply appends a hidden div with the extension version on `browsersso/` pages. The `injected.js` script listens for messages but only processes SSO-related commands. This is consistent with the extension's purpose as a universal SSO tool.

### VULN-003: Client-Side Credential Decryption with MD5-Derived Key
- **Severity**: LOW
- **File**: `injected.js`, `crypto_aes.js`
- **Code**:
```javascript
CryptoJS.AES.decrypt(o.appResponse.userauth[0][r], o.gwstokenMd5).toString(CryptoJS.enc.Utf8)
```
- **Verdict**: User credentials (usernames, passwords) are AES-encrypted by the ClassLink server and sent to the extension, which decrypts them client-side using `gwstokenMd5` as the key. MD5 is cryptographically weak. The decrypted credentials are then filled into login forms. This is inherent to the SSO automation model -- credentials must be available in the browser to auto-fill. The encryption is transport-level obfuscation, not a true security boundary. The real security boundary is HTTPS transport and the ClassLink authentication token (`gwstoken`).

### VULN-004: jQuery 3.5.0 Included (Known CVEs)
- **Severity**: LOW
- **File**: `jquery-3.5.0.min.js`
- **Verdict**: jQuery 3.5.0 is bundled. While this version addressed the major XSS vulnerability (CVE-2020-11022/CVE-2020-11023) that affected earlier versions, it is still an older library. No active exploitation path exists in the context of this extension since user-controlled HTML is not parsed through jQuery's HTML processing.

### VULN-005: postMessage Listener Without Origin Validation
- **Severity**: MEDIUM
- **File**: `injected.js`
- **Code**:
```javascript
window.addEventListener("message", function(e) {
    try {
        var t = JSON.parse(atob(e.data));
        if ("stopapptimers" == t.type)
            chrome.runtime.sendMessage(chrome.runtime.id, t, function(e) { ... });
        else if (new RegExp(i).test(e.origin))
            // ... processes autolaunch, apptimer, ssosignout
    } catch(e) {}
})
```
- **Verdict**: The extension listens for `window.postMessage` events on ClassLink pages. The `stopapptimers` message type is processed WITHOUT checking `e.origin`, meaning any page could send a `stopapptimers` command via postMessage if the content script is running. However, the impact is limited to stopping app usage timers. For the other message types (autolaunch, apptimer, ssosignout), origin IS validated against ClassLink domains. The `stopapptimers` bypass has minimal security impact.

### VULN-006: Trusted Domain Persistence in chrome.storage.sync
- **Severity**: LOW
- **File**: `injected.js`
- **Code**:
```javascript
n("#clTrustedProcess .cl_okbtn").unbind("click").click(function() {
    chrome.storage.sync.get(s, function(e) {
        if (-1 == (e = e && e[s] ? e[s] : []).indexOf(window.location.hostname)) {
            e.push(window.location.hostname);
            var t = {};
            t[s] = e;
            chrome.storage.sync.set(t)
        }
    })
})
```
- **Verdict**: When a non-ClassLink domain references ClassLink resources, the extension prompts the user to trust the domain. Once trusted, the domain is persisted in `chrome.storage.sync` (synced across devices). A social engineering attack could trick users into trusting malicious domains to enable SSO auto-fill on attacker-controlled pages. Impact depends on the broader SSO flow configuration.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `createElement("script")` | `background.js` | Part of `execute-script` handler for SSO pre/post auth scripts from ClassLink server -- NOT a false positive, flagged as VULN-001 |
| `innerHTML` | `injected.js` | Reading `head[0].innerHTML` to extract `appResponse` and `gwstokenMd5` from ClassLink SSO pages -- reading, not writing arbitrary content |
| `keydown`/`keypress` events | `injected.js` | Simulating keyboard input for SSO credential auto-fill into login forms -- expected SSO behavior |
| `btoa`/`atob` | `background.js`, `injected.js` | Base64 encoding/decoding of storage keys (`islogin_` prefixed hostnames) and postMessage data -- standard encoding, not obfuscation |
| `chrome.scripting.executeScript` | `background.js` | Used to inject content scripts into ClassLink tabs and execute SSO-related scripts -- core SSO functionality |
| jQuery `$.ajax`/`$.get` | `jquery-3.5.0.min.js` | Standard jQuery library, not called by extension code directly for network requests |

## API Endpoints Table

| Endpoint | Method | Purpose | Auth |
|----------|--------|---------|------|
| `https://analytics-log.classlink.io/launch/v1p0/launch` | POST | Log app launch event | `gws` token |
| `https://analytics-log.classlink.io/activity/v1p0/activity` | POST | Report active usage time (300s intervals) | launchToken |
| `https://analytics-log.classlink.io/activity/v1p0/close` | POST | Report tab close with active seconds | launchToken |
| `https://analytics-log-beta.classlink.io/*` | POST | Beta environment analytics (same endpoints) | `gws` token |
| `https://{LaunchpadUri}/clsso/{appId}` | GET (tab) | ClassLink SSO redirect | Session |
| `https://{LaunchpadUri}/browsersso/{appId}` | GET (tab) | Browser-based SSO launch | Session |
| `https://{LaunchpadUri}/ltisso/{appId}` | GET (tab) | LTI SSO launch | Session |
| `https://{LaunchpadUri}/focussso/{appId}` | GET (tab) | Focus SSO launch | Session |
| `https://{LaunchpadUri}/oneroster/{appId}` | GET (tab) | OneRoster SSO launch | Session |
| `https://{LaunchpadUri}/custom/*/{appId}` | GET (tab) | Custom SSO integrations | Session |

## Data Flow Summary

1. **Content script injection**: `detection.js`, `jquery-3.5.0.min.js`, `crypto_aes.js`, and `injected.js` are injected into ALL pages and frames.
2. **Detection**: `detection.js` creates a hidden marker div on `browsersso/` pages to signal extension presence.
3. **SSO trigger**: On ClassLink launchpad/browsersso pages, `injected.js` extracts `appResponse` (encrypted credentials, selectors, SSO config) and `gwstokenMd5` from the page HTML.
4. **Credential decryption**: AES-encrypted credentials are decrypted client-side using the MD5-derived `gwstokenMd5` key.
5. **Form filling**: Decrypted credentials are filled into login form fields using jQuery selectors defined by the ClassLink server.
6. **SSO task execution**: For advanced SSO, a task-based system in `background.js` orchestrates multi-step login flows (wait for URL, redirect, click, input, reCAPTCHA).
7. **Script execution**: `pre_auth_script` and `post_auth_script` from the server can be executed in the MAIN world via the `execute-script` message handler.
8. **Analytics**: App launch, activity (5-minute heartbeats), and close events are reported to `analytics-log.classlink.io` with the ClassLink `gwstoken`.
9. **Auto-launch**: On ClassLink home pages, the extension can auto-open configured applications in new tabs.
10. **SSO sign-out**: Tabs are opened to sign-out URLs provided by the ClassLink launchpad.

All network communication goes exclusively to ClassLink-owned domains (`*.classlink.com`, `*.classlink.io`, `*.classlink.eu`). No third-party data exfiltration, no ad injection, no proxy infrastructure, no market intelligence SDKs.

## Overall Risk: **CLEAN**

**Rationale**: ClassLink OneClick is a legitimate SSO automation tool used by millions of students and educators in K-12 institutions. While it requests broad permissions (`*://*/*` host permissions, content script injection on all pages, `scripting` permission), these are architecturally necessary for its function of automating logins across arbitrary web applications. The extension communicates exclusively with ClassLink-owned infrastructure. There is no evidence of malicious behavior, data exfiltration, ad injection, proxy usage, or market intelligence SDK embedding. The identified security concerns (arbitrary script execution from server config, client-side credential decryption, postMessage origin bypass for timer stopping) are inherent design trade-offs of an SSO automation platform, not indicators of malicious intent. The extension serves its stated purpose for its 18 million users.
