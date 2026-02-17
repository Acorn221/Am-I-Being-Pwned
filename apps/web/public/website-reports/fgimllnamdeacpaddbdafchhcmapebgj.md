# Security Analysis: VKSaver - скачать музыку ВК

**Extension ID:** fgimllnamdeacpaddbdafchhcmapebgj
**Version:** 5.25.3
**Users:** 500,000
**Risk Level:** MEDIUM
**Manifest:** V3

## Executive Summary

VKSaver is a popular Russian-language extension (500K users) that enables downloading music and videos from VK.com (VKontakte social network). The extension implements its core functionality through content scripts and a service worker using webpack-bundled, obfuscated code. While the extension's primary purpose appears legitimate, it contains **two medium-severity security vulnerabilities** related to insecure message handling and one privacy concern regarding error telemetry.

The extension does **not** exhibit malicious behavior such as data exfiltration, credential theft, or malware characteristics. However, the postMessage handlers lack proper origin validation, creating exploitable attack surface for cross-site scripting if a malicious website can frame or interact with VK pages.

## Vulnerability Assessment

### MEDIUM: Insecure postMessage Handlers (No Origin Validation)

**Severity:** MEDIUM
**CWE:** CWE-346 (Origin Validation Error)
**CVSS:** 5.4 (Medium)

The extension implements multiple `window.addEventListener("message")` handlers in EntryPoint.js without validating `event.origin`. This creates a vulnerability where malicious web pages could potentially send crafted messages to trigger unintended behavior.

**Affected Code Patterns:**
```javascript
// Pattern 1: VKS_REQUEST handler (async)
window.addEventListener("message",(async r=>{
    if(r.data.type===`VKS_REQUEST_${t}`) {
        // NO r.origin check
        // Processes r.data.requestData
        window.postMessage({type:`VKS_RESPONSE_${t}`, responseData:o, ...}, window.location.origin)
    }
}))

// Pattern 2: VKS_RESPONSE handler
window.addEventListener("message",i),
window.postMessage({type:`VKS_REQUEST_${e}`, requestId:n, requestData:t, ...}, window.location.origin)
```

**Attack Scenario:**
1. Malicious website embeds VK page in iframe or opens popup
2. Sends crafted `VKS_REQUEST_*` messages with malicious `requestData`
3. Extension processes message without origin validation
4. Could trigger DOM manipulation via innerHTML or modify extension state

**Evidence from ext-analyzer:**
```
ATTACK SURFACE:
  [HIGH] window.addEventListener("message") without origin check    EntryPoint.js:1
  message data → *.src(github.com)    from: EntryPoint.js ⇒ EntryPoint.js
  message data → fetch(github.com)    from: EntryPoint.js ⇒ EntryPoint.js
  message data → *.innerHTML(github.com)    from: EntryPoint.js ⇒ EntryPoint.js
```

**Mitigation:**
```javascript
window.addEventListener("message", (event) => {
    // Validate origin before processing
    if (event.origin !== window.location.origin) {
        return; // Reject messages from external origins
    }
    // Process event.data
});
```

### MEDIUM: innerHTML Usage with Untrusted Data

**Severity:** MEDIUM
**CWE:** CWE-79 (Cross-site Scripting)

The extension uses `innerHTML` to render dynamic content in 12+ locations. While most appear to process VK API responses, the combination with unvalidated postMessage handlers creates a potential XSS chain.

**Affected Patterns:**
```javascript
const e=document.createElement("textarea");
return e.innerHTML=t, e.value

const e=document.createElement("div");
return e.innerHTML=t, e.firstElementChild

n=document.createElement("div");
n.innerHTML=a;
const i=n.querySelector(`[data-movie-id="${e}"]`)
```

**Risk Amplification:**
If an attacker can control message data via the postMessage vulnerability, they could potentially inject HTML/JavaScript through these innerHTML assignments, especially in the DOM creation patterns.

### LOW: Error Telemetry to Third-Party Endpoint

**Severity:** LOW
**Category:** Privacy / Information Disclosure
**Endpoint:** `https://dl1.audiovk.com/desktop/api/v0/onException`

The extension sends error telemetry containing browser fingerprinting data to a developer-controlled endpoint:

**checkLegacyBrowser.js:**
```javascript
fetch("https://dl1.audiovk.com/desktop/api/v0/onException?pluginVersion="+getPluginVersion(),{
    method:"POST",
    body:JSON.stringify({
        type:"Plugin.Errors.LegacyBrowser",
        details:{
            screen:{width:window.screen.width, height:window.screen.height, orientation:window.screen.orientation.type},
            time:(new Date).toISOString(),
            userAgent:window.navigator.userAgent,
            pluginVersion:getPluginVersion(),
            pageUrl:window.location.href
        }
    }),
    mode:"no-cors"
})
```

**EntryPoint.js error reporting:**
```javascript
await fetch(`${a()}/desktop/api/v0/onException?pluginVersion=${S()}`,{
    method:"POST",
    body:/* error details */,
    mode:"no-cors"
})
```

**Data Collected:**
- Screen dimensions and orientation
- User agent string
- Current page URL (on VK.com)
- Extension version
- Error stack traces

**Privacy Impact:**
While this is standard error tracking for debugging, it creates a passive tracking mechanism that could correlate user sessions. The `mode:"no-cors"` prevents response reading but still transmits data.

## Positive Security Findings

### No Data Exfiltration
Despite the ext-analyzer flag for "EXFILTRATION" flow `document.querySelectorAll → fetch(github.com)`, analysis reveals this is a **false positive**:
- The "github.com" references are from **core-js library attribution**: `https://github.com/zloirock/core-js/blob/v3.23.3/LICENSE`
- No actual network requests to GitHub
- querySelectorAll usage targets VK UI elements (`.audio_row`, `.wall_text`, video elements) for legitimate download functionality

### No Credential Theft
- No access to `chrome.cookies` or password fields
- Storage API usage limited to extension configuration
- No keylogging or form interception

### Appropriate Permissions
All permissions align with stated functionality:
- `downloads` - Required for downloading media files
- `storage` - Extension settings persistence
- Host permissions scoped to VK domains and VK CDN domains
- `declarativeContent` - Popup activation logic

### Legitimate Core Functionality
The extension implements expected VK downloader features:
- Injects download buttons into VK music/video pages via content scripts
- Uses `chrome.downloads` API to save media files
- Modifies VK UI with custom CSS (`modify.css`)
- Supports VK audio playlists, video clips, and individual tracks

## Code Quality Observations

### Obfuscation
The extension uses **webpack bundling** with **minified code** (267KB single-line EntryPoint.js). This is common for modern JavaScript build toolchains but reduces code auditability:
- Module IDs like `t.exports=function(t){if(o(t))return t;throw n(a(t)+" is not a function")}`
- Mangled variable names: `o,a,n,i,s,c,l,d,u,p,h,f,m,v,y,w,g,_,k,b,A`
- Not malicious obfuscation (no string encryption or eval chains)
- Standard webpack output pattern

### Communication Pattern
The extension uses a **request-response message pattern** for background-content script communication:
```
Content Script → window.postMessage(VKS_REQUEST_${type}) → Same Page
                  ↓
           Message Handler
                  ↓
Same Page → window.postMessage(VKS_RESPONSE_${type}) → Content Script
```

This is an **unconventional pattern** - typically extensions use `chrome.runtime.sendMessage()` for cross-context communication. Using `window.postMessage()` within the same origin suggests the developer may be working around manifest V3 service worker limitations or coordinating between multiple content script instances.

## Technical Details

**Manifest Configuration:**
- Service worker: `EntryPoint.js`
- Content scripts: `checkLegacyBrowser.js`, `EntryPoint.js` (injected at `document_start` on `*.vk.com`)
- Web accessible resources: SVG icons, CSS, EntryPoint.js (accessible from VK domains)

**DOM Manipulation:**
The extension extensively modifies VK pages:
- 49 `querySelectorAll()` calls targeting VK UI elements
- Injects download buttons into audio rows (`.audio_row`)
- Modifies video player interfaces
- Adds playlist download functionality

**Network Endpoints:**
1. `https://dl1.audiovk.com/desktop/api/v0/onException` - Error telemetry
2. VK.com domains - Extension operates on these hosts
3. No third-party analytics (Google Analytics, etc.)
4. No ad networks or affiliate links

## Risk Scoring

| Category | Score | Justification |
|----------|-------|---------------|
| **Data Access** | 3/10 | Accesses DOM elements on VK.com but no sensitive user data |
| **Network Activity** | 4/10 | Error telemetry to developer server; no bulk data transmission |
| **Permissions** | 5/10 | Downloads + broad host permissions, but appropriate for functionality |
| **Code Security** | 6/10 | postMessage vulnerabilities + innerHTML usage |
| **Privacy** | 5/10 | Error tracking with fingerprinting data |
| **Overall Risk** | **MEDIUM** | Vulnerable but not malicious; legitimate functionality with security gaps |

## Recommendations

### For Users
- **Safe to use** for downloading VK media, but be aware:
  - Error reports sent to developer server include browsing metadata
  - Extension has broad access to VK.com content
  - 500K users suggests community trust, but vulnerabilities exist

### For Developers
1. **CRITICAL:** Add origin validation to all `window.addEventListener("message")` handlers
2. **HIGH:** Replace `innerHTML` with safer alternatives (`textContent`, `createElement()`)
3. **MEDIUM:** Make error telemetry opt-in with user consent
4. **LOW:** Consider switching to `chrome.runtime.sendMessage()` for background communication
5. **LOW:** Provide unminified source code or source maps for transparency

### For Security Researchers
The postMessage vulnerability could be exploited via:
1. Malicious VK post containing iframe to attacker-controlled domain
2. Browser extension that can inject scripts into VK pages
3. Man-in-the-middle attack modifying VK page JavaScript

## Compliance & Privacy

**GDPR Considerations:**
- Error telemetry likely constitutes personal data (IP address, user agent)
- No visible privacy policy or consent mechanism
- User should be informed of data collection

**Chrome Web Store Policies:**
- Complies with stated functionality (music/video downloader)
- Obfuscation is borderline but appears to be build artifact, not intentional hiding
- Error telemetry should be disclosed in privacy policy

## Conclusion

VKSaver is a **functionally legitimate** extension with a **significant user base** (500K) providing valuable VK.com media downloading capabilities. However, it suffers from **common web security anti-patterns**:

1. Missing origin validation in postMessage handlers (textbook vulnerability)
2. Unsafe DOM manipulation via innerHTML
3. Undisclosed error telemetry with fingerprinting

**The extension is NOT malware** - there's no evidence of:
- Credential theft
- Cryptocurrency mining
- Affiliate fraud
- Data exfiltration beyond error reporting
- Malicious code injection

**Risk verdict: MEDIUM** - The vulnerabilities are exploitable but require specific attack scenarios (malicious page interacting with VK). For typical users downloading music/videos, the practical risk is low. Developers should prioritize fixing the postMessage handlers to prevent potential XSS exploitation.

---

**Analysis Date:** 2026-02-15
**Analyzer:** Claude Sonnet 4.5 + ext-analyzer v1.0
**Methodology:** Static analysis (Babel AST + regex patterns) + manual code review
