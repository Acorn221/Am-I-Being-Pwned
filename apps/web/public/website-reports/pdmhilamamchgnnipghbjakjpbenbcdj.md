# Security Analysis: Impero Education Pro

**Extension ID**: pdmhilamamchgnnipghbjakjpbenbcdj
**Version**: 1.1.13
**Users**: 400,000
**Risk Level**: MEDIUM
**Manifest Version**: 2

## Executive Summary

Impero Education Pro is a legitimate enterprise classroom monitoring and content filtering extension designed for educational environments. The extension connects to a locally-installed Impero server via WebSocket (localhost:30019) to receive content filtering policies. It extracts full page HTML/DOM content from all websites visited by students and sends it to the local server for policy-based analysis. Blocked content is replaced using `document.write()` with server-provided HTML.

While the extension's behavior involves significant data collection and code execution capabilities, this is **disclosed and appropriate for its intended use case** as a classroom management tool deployed via MDM/enterprise policies. The risk level is MEDIUM rather than HIGH because all communication is with localhost (not external servers), and the extension is designed for supervised educational environments where students are aware of monitoring.

**Key Concerns**:
1. Unrestricted message-based `document.write()` from background page
2. Full page content extraction and transmission to local server
3. Wide attack surface if local Impero server is compromised
4. No origin validation on message handlers

## Detailed Findings

### MEDIUM: Unrestricted Page Replacement via document.write()

**Files**: `js/ext_content.js` (lines 1-13), `js/Content.js` (lines 1-9)

The extension's content scripts accept messages from the background page to completely replace page content using `document.write()`:

```javascript
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (msg.text && (msg.text == "set_content")) {
        if (msg.content !== null) {
            console.info("Replacing Page");
            document.write(msg.content);
            document.close();
        }
    }
});
```

**Attack Vector**: If an attacker gains control of the background page (via compromised local server or extension vulnerability), they can inject arbitrary HTML/JavaScript into any page the user visits. The `document.write()` call completely replaces the page DOM with attacker-controlled content.

**Mitigations in place**:
- Messages only originate from the extension's own background page (Chrome restricts `chrome.runtime.sendMessage` to same extension)
- No external connections - all filtering decisions come from localhost server

**Recommendation**: Add sender validation to ensure messages originate from the extension's background page. Consider using safer DOM manipulation methods instead of `document.write()`.

---

### MEDIUM: Full Page Content Exfiltration to Localhost

**Files**: `js/Content.js` (lines 11-30), `src/bg/background.js` (lines 119-126), `js/ConnLayer.js` (lines 106-109)

The extension extracts and transmits complete page HTML to the local WebSocket server:

```javascript
var textToScan_tk7Sc4GOkj = "";
window.addEventListener('pageshow' , function(element){
    AddTextFromElement_tk7Sc4GOkj(document, "***ELEMENT*** > ");
    chrome.runtime.sendMessage({type: "check_content", content: textToScan_tk7Sc4GOkj});
});

function AddTextFromElement_tk7Sc4GOkj(element, prefix) {
    if (textToScan_tk7Sc4GOkj.length < 10000000) {
        if (textToScan_tk7Sc4GOkj.indexOf(element.innerHTML) < 0) {
            textToScan_tk7Sc4GOkj += prefix + element.innerHTML + " ";
            for (child of element.children) {
                AddTextFromElement_tk7Sc4GOkj(child, prefix + "> ");
            }
        }
    }
}
```

**Data collected**:
- Complete page HTML (up to 10MB per page)
- URL and tab ID
- Page content from all frames (`all_frames: true` in manifest)

**Transmission**:
```javascript
ConnectionLayer.prototype.SendRequest = function (url, content, contentType, tabID) {
    var request = new Request('check-content',
        new CheckRequest(url, JSON.stringify(content), 'google-chrome', contentType, tabID.toString()));
    return this.SendMessage(request);
};
```

**Privacy Impact**: Captures all browsing activity including:
- Search queries
- Form inputs (visible in page HTML)
- Authentication pages
- Personal communications
- Medical/financial information

**Justification**: This is expected behavior for classroom monitoring software in educational settings where students are notified of monitoring. The data stays on the local network (localhost connection only).

**Risk factors**:
- If the local Impero server is compromised, attacker gains access to all browsing data
- No TLS/encryption on WebSocket connection (ws:// not wss://)
- Content includes sensitive data from all websites

---

### MEDIUM: Localhost WebSocket Server Dependency Creates Attack Surface

**Files**: `js/WebSocket.js` (lines 6-37), `js/ConnLayer.js` (lines 79-88)

The extension connects to `ws://localhost:30019` and accepts filtering directives:

```javascript
WebsocketConnection.prototype.open = function (port) {
    var ws = this.webSocket = new WebSocket("ws://localhost:" + port);
    // ...
};

comms.setAutoReconnect(true);
comms.start(30019);
```

**Attack Vector**: If the local Impero server is compromised or replaced with a malicious localhost WebSocket server:

1. **Surveillance**: Attacker receives all browsing activity from victim
2. **Page Injection**: Attacker sends malicious HTML to replace any page via `onblock` handler:
   ```javascript
   comms.onblock = function (e) {
       contentController.add(e.url, e.replacementHtml, e.tabID);
       setAllDomContent(e.url, e.tabID);
   };
   ```
3. **Credential Harvesting**: Injected phishing pages can steal credentials from any domain
4. **Policy Manipulation**: Attacker controls allow/block decisions, whitelist, and settings

**Mitigations needed**:
- TLS encryption (wss:// instead of ws://)
- Server authentication to prevent rogue localhost servers
- Message signing/HMAC to verify server authenticity

---

### LOW: Missing Origin Validation on Message Handlers

**Files**: `js/ext_content.js` (lines 1-13), `js/Content.js` (lines 1-9)

Message handlers do not validate the sender origin:

```javascript
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (msg.text && (msg.text == "get_content")) {
        sendResponse({ content: document.all[0].outerHTML, tab: msg.tabId });
    }
    // No sender validation
});
```

**Impact**: While `chrome.runtime.sendMessage()` is restricted to the same extension, best practice is to explicitly validate `sender.id` to prevent potential issues if Chrome's security model changes or if vulnerabilities are discovered.

**Recommendation**:
```javascript
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    if (sender.id !== chrome.runtime.id) return;
    // ... handle message
});
```

---

## Additional Behaviors

### Content Filtering and Redirection

**Files**: `js/WebRequestHandlers.js` (lines 15-23, 36-66)

The extension modifies Google and YouTube URLs to enforce SafeSearch and YouTube EDU:

```javascript
if (extSettings.isUsingGoogleSafeSearch() && isUrlGoogle(currentUrl)) {
    newurl = buildRedirectForGoogle(currentUrl); // Adds &safe=active
} else if (extSettings.isUsingYoutubeEdu() && isUrlYoutube(currentUrl)) {
    newurl = buildRedirectForYoutube(currentUrl); // Adds edufilter
}
```

This is standard classroom safety functionality.

### Whitelist Functionality

The extension supports URL whitelisting to skip content checking for trusted domains. This reduces unnecessary data transmission for approved educational resources.

---

## Permissions Analysis

| Permission | Justification | Risk |
|------------|---------------|------|
| `tabs` | Required for tab URL tracking and content script injection | Standard |
| `<all_urls>` | Needed to monitor all websites for content filtering | High privilege but justified |
| `webRequest` + `webRequestBlocking` | Used for SafeSearch/YouTube EDU redirection | Appropriate |

All permissions are necessary for the extension's stated functionality.

---

## Data Flow Summary

1. **User visits any webpage** → Content script injected on all frames
2. **Page loads** → `pageshow` event triggers full DOM extraction (up to 10MB)
3. **Content sent to background** → Via `chrome.runtime.sendMessage`
4. **Background sends to localhost** → WebSocket to `ws://localhost:30019`
5. **Server analyzes content** → Checks against filtering policies
6. **Server responds** → `block` (with replacement HTML) or `allow`
7. **If blocked** → `document.write(replacementHtml)` replaces page

---

## Risk Assessment

**Overall Risk**: MEDIUM

**Justification**:
- This is a **disclosed enterprise monitoring tool** designed for educational settings
- All data transmission is to **localhost only** (not external servers)
- Behavior is **appropriate for stated purpose** (classroom content filtering)
- Students in managed environments are typically **aware of monitoring**
- Extension is deployed via **MDM/Group Policy**, not user choice

**Risk would be HIGH/CRITICAL if**:
- Data was sent to external servers without disclosure
- Extension was marketed to general consumers as a "utility"
- No local server requirement (direct cloud connection)

**Current Risks**:
- Compromised local Impero server = complete surveillance + phishing capability
- Unencrypted WebSocket (ws:// not wss://) allows local network eavesdropping
- No authentication between extension and server
- `document.write()` creates XSS-like attack vector if server is compromised

---

## Recommendations

### For Developers (Impero Solutions Ltd)

1. **Add TLS encryption** - Switch to `wss://` with certificate pinning
2. **Implement server authentication** - Shared secret or certificate validation
3. **Sign messages** - HMAC to prevent tampering
4. **Validate message senders** - Check `sender.id` in all message handlers
5. **Replace document.write()** - Use safer DOM manipulation (e.g., `innerHTML` with sanitization)
6. **Add content security** - Sanitize server-provided replacement HTML
7. **Implement rate limiting** - Prevent abuse if server is compromised

### For Administrators

1. **Secure the Impero server** - Harden localhost server against compromise
2. **Network segmentation** - Isolate student networks from potential threats
3. **Regular updates** - Keep extension and server software current
4. **Monitor server access** - Log all filtering decisions and changes
5. **Transparent policies** - Ensure students/parents understand monitoring scope

### For Users

This extension should **only be used in managed educational environments** where:
- IT administrators have installed and configured the Impero server
- Students are informed of monitoring policies
- Use is part of institutional acceptable use policy

**Do not install this extension** on personal devices outside of school/institutional management.

---

## Conclusion

Impero Education Pro is a legitimate classroom monitoring tool with significant data collection and code execution capabilities. Its security posture is appropriate for a **disclosed enterprise tool deployed in managed environments**, but the lack of encryption and authentication creates risks if the local Impero server is compromised.

The **MEDIUM risk rating** reflects that while the extension's capabilities are powerful (full content extraction, page replacement), they are:
1. Disclosed in the extension's name and description
2. Limited to localhost communication (no external data exfiltration)
3. Appropriate for the educational monitoring use case
4. Deployed in environments where students expect monitoring

Organizations using this extension should ensure the local Impero server is properly secured, as it represents a critical trust boundary for student browsing privacy and security.
