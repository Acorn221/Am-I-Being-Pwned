# Grammarly - Attack Surface Map

**Extension ID:** `kbfnbcaeplbcioakkpcpgfkobkghlhen`
**Version:** 14.1271.0
**Size:** 44MB
**Users:** 43M+

## Permissions Analysis

| Permission | Risk | Notes |
|------------|------|-------|
| `http://*/*`, `https://*/*` | HIGH | Full web access |
| `cookies` | HIGH | Can read all cookies |
| `identity` | MEDIUM | OAuth access |
| `scripting` | MEDIUM | Can inject scripts |
| `tabs` | MEDIUM | Tab info access |
| `storage` | LOW | Local storage |

### Optional Permissions
- `nativeMessaging` - Desktop app integration
- `clipboardRead` - Paste text

### Content Scripts
- `all_frames: true` on `<all_urls>` (with exclusions)
- Runs on almost every website
- Multiple specialized scripts for Gmail, GDocs, etc.

### Externally Connectable
```json
{
  "matches": ["https://*.grammarly.com/*"]
}
```
**Good:** Only grammarly.com can send external messages. No `ids` field = no extension-to-extension messaging.

---

## Attack Vectors Investigated

### 1. External Messaging
- **No `onMessageExternal` handlers found**
- Only grammarly.com domains can connect
- **Result:** Not exploitable

### 2. eval() Usage (Line 28241)
```javascript
var mod = eval("quire".replace(/^/, "re"))(moduleName);
```
- Webpack bundler pattern for dynamic `require()`
- Not user-controllable
- **Result:** Safe

### 3. innerHTML Usage (Line 15448)
```javascript
t.documentElement.innerHTML = et ? re : i
```
- Inside DOMPurify sanitizer
- Input passed through `createHTML()` TrustedTypes
- **Result:** Safe

### 4. CODE_SPLITTING_INJECT Handler (Line 91788)
```javascript
if (n && "CODE_SPLITTING_INJECT" === n.type && n.file) {
    executeScript(n.file, tabId, frameId)
}
```
- Accepts filename from message and executes it
- **BUT:** Uses `chrome.runtime.onMessage` (internal only)
- Web pages cannot send messages to this handler
- **Result:** Safe (only extension's own content scripts can call it)

### 5. tabs.create/update
- Multiple locations but all use internal URLs or grammarly.com URLs
- No user-controllable URL navigation found
- **Result:** Safe

### 6. gOS-sandbox.html (Web Accessible Resource)
```javascript
// Accepts messages from parent
self.addEventListener("message", (e => {
    if (e.source !== self.parent) return;
    switch (n.type) {
        case "setSource":  // URL validated against whitelist
            t.includes(s) && (i.src = n.url)  // Only allows Grammarly CDN
```
- **Web accessible** - any page can embed it
- Accepts `setSource`, `postMessage`, `setMessagePort` from parent
- **BUT:** URL whitelist validates against:
  - `https://d3ttvzt45fz9bg.cloudfront.net`
  - `https://applet-bundles.grammarly.net`
- **Result:** Can't load arbitrary URLs, limited to Grammarly applets

### 7. inkwell/index.html (Web Accessible Resource)
- Another web-accessible page for AI writing features
- Communicates via extension internal messaging
- No direct postMessage exploitation found
- **Result:** Safe

### 8. Content Script postMessage Handlers
```javascript
// Line 51649 - validates source
if (!t.source || t.source !== self.top) return;
```
- All handlers check `source === self.top`
- Messages validated for `__grammarly` property structure
- **Result:** Safe

---

## Conclusion

**Verdict: No standalone exploits found.**

Despite massive codebase (44MB) and reading all text users type:
- No external message handlers
- eval/innerHTML properly protected
- Internal code splitting uses extension-only messaging
- URL navigation uses hardcoded domains

The extension is well-architected from a security perspective. Attack surface is limited to:
1. XSS on grammarly.com (would enable external messaging)
2. Compromise of Grammarly's servers (would enable malicious updates)
