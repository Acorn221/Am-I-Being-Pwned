# Adobe Acrobat Chrome Extension Security Analysis

## Metadata

| Field | Value |
|-------|-------|
| Extension Name | Adobe Acrobat: PDF edit, convert, sign tools |
| Extension ID | efaidnbmnnnibpcajpcglclefindmkaj |
| Version | 26.1.2.1 |
| Users | ~339,000,000 |
| Analysis Date | 2026-02-08 |
| Analyst | Claude Sonnet 4.5 |

---

## Executive Summary

**Overall Risk Level: CLEAN**

Adobe Acrobat is a legitimate, professionally developed extension from Adobe Inc. with 339 million users. The extension provides PDF viewing, editing, and conversion functionality with deep integration into Google Workspace, Outlook, LinkedIn, WhatsApp, ChatGPT, and other platforms.

**Key Findings:**
- ✅ All network calls go to legitimate Adobe domains
- ✅ No credential theft, malware, or proxy infrastructure
- ✅ Legitimate business purpose for extensive permissions
- ⚠️ Remote code execution from CDN (supply chain risk concern)
- ⚠️ Missing DNS security controls (no CAA records or DNSSEC)
- ⚠️ innerHTML injection from remote source

**Verdict:** While the extension itself is CLEAN and serves its intended purpose, it employs a remote execution architecture that creates supply chain risk exposure for 339M users. The code is legitimate but the architectural choices warrant documentation.

---

## Vulnerability Details

### 1. Remote Code Execution from CDN (Architectural Concern)

**Severity:** LOW (legitimate use, but architectural risk)
**Category:** Supply Chain Risk
**Status:** By design, not exploited

**Description:**
The extension loads and executes JavaScript from Adobe's CDN at runtime for feature deployment (primarily the "Edit in Adobe Express" integration on Google Drive/Gmail).

**Files:**
- `/content_scripts/remote-execution/re-content-script.js`
- `/content_scripts/remote-execution/message-handler.js`
- `/content_scripts/remote-execution/dom-operations.js`

**Code Evidence:**
```javascript
// re-content-script.js - Loads remote execution framework
const remoteExecutionCdnUrlPromise = chrome.runtime.sendMessage({
  main_op: "get-remote-execution-cdn-url"
});

// Fetches: https://acrobat.adobe.com/dc-chrome-extension/build-re-index.html
```

**DOM Manipulation from Remote Code:**
```javascript
// dom-operations.js:120-135
function appendHtmlToTarget(e) {
  const { payload: t } = e;
  const targetNode = findElementByStrategy({
    getElementBy: t.getTargetElementBy,
    targetElementSelector: t.targetElementSelector
  });

  if (targetNode) {
    const div = document.createElement("div");
    div.innerHTML = t.html;  // HTML from CDN
    targetNode.insertBefore(div, targetNode.firstChild);
  }
}
```

**Available Commands to Remote Code:**
- `APPEND_HTML_TO_TARGET` - Inject HTML via innerHTML
- `INJECT_IFRAME` - Create iframes
- `DOCUMENT_GET_ELEMENT` - Query DOM elements
- `DOCUMENT_REMOVE_ELEMENT` - Remove elements
- `SUBSCRIBE_TO_EVENT_HANDLER` - Attach event listeners
- `GET_STORAGE_VALUE` / `SET_STORAGE_VALUE` - Access chrome.storage
- `START_MUTATION_OBSERVER` - Watch DOM changes
- `DOWNLOAD_BUFFER_FROM_URL` - Download assets

**CDN Details:**
- Base URL: `https://acrobat.adobe.com/dc-chrome-extension/`
- Cache: 10 minutes (`max-age=600`)
- Origin: AWS S3 (encrypted, versioned)
- Distribution: Akamai EdgeKey

**Risk Assessment:**
- **Current state:** Legitimate Adobe code, proper origin validation
- **Risk:** IF Adobe CDN compromised → malicious code executes on all sites user visits
- **Scope:** 339M users × all websites (extension has `<all_urls>`)
- **Propagation:** 10-minute cache = fast spread

**Mitigations in Place:**
- Extension validates parent origin before executing commands
- Approved extension ID whitelist (7 IDs)
- CSP headers on CDN resources
- HTTPS-only, HSTS enabled
- S3 versioning and encryption

**Missing Mitigations:**
- No CAA records (any CA can issue certificates)
- No DNSSEC (DNS hijacking possible)
- CORS allows `*` (should be extension origins only)
- No Subresource Integrity (SRI) hashes

**Verdict:** This is legitimate functionality by design, but creates supply chain risk. The concern is valid for a security researcher to note, but does not indicate malicious intent. The extension serves its intended purpose properly.

---

### 2. Extensive Site Access with Content Script Injection

**Severity:** LOW (legitimate business purpose)
**Category:** Privacy/Permissions
**Status:** By design

**Description:**
Content scripts inject into ALL web pages at `document_start` to enable PDF viewing and conversion features.

**Manifest Evidence:**
```json
{
  "content_scripts": [{
    "matches": ["file://*/*", "http://*/*", "https://*/*"],
    "run_at": "document_start",
    "js": [
      "content_scripts/embeddedpdfs/embedded-pdf-touch-point-event-listener.js",
      "libs/jquery-3.1.1.min.js",
      "content_scripts/ch-content-script.js",
      // ... 30+ scripts
    ]
  }]
}
```

**Site-Specific Integrations:**
- **Google Workspace:** Gmail, Drive, Docs (PDF tools, Express integration)
- **Microsoft:** Outlook (all domains) - PDF attachment handling
- **Social:** LinkedIn, Facebook, WhatsApp - Image editing
- **AI:** ChatGPT, Gemini - Screenshot/image editing
- **General:** Embedded PDFs on any website

**Permissions:**
```json
{
  "permissions": [
    "contextMenus", "tabs", "downloads", "nativeMessaging",
    "webRequest", "webNavigation", "storage", "scripting",
    "alarms", "offscreen", "cookies", "sidePanel", "fileSystem"
  ],
  "host_permissions": ["<all_urls>"],
  "optional_permissions": ["history", "bookmarks"]
}
```

**Cookie Access:**
```javascript
// service-worker.js:143 - Adobe IMS cookie monitoring
chrome.cookies?.onChanged?.addListener(e => {
  const { name: o, domain: s } = e?.cookie || {};
  if (s?.includes("services.adobe.com")) {
    if ("ims_sid" === o) {
      f.resetSignInStatusCooldown();
    } else if ("gds" === o && e?.removed) {
      // Gen AI session cleanup
    }
  }
});
```

**Verdict:** While permissions are extensive, they are necessary for the advertised functionality. Cookie access is limited to Adobe's own domains for authentication. No evidence of credential harvesting or unauthorized data collection.

---

## False Positive Analysis

| Pattern | Context | Verdict |
|---------|---------|---------|
| `innerHTML` usage | DOM manipulation in React components, SVG rendering | **Known FP** - React/library use |
| `eval()` in jQuery | jQuery library (v3.1.1) - standard animation easing | **Known FP** - Third-party library |
| `fetch()` to Adobe domains | Analytics, authentication, feature flags | **Legitimate** |
| Cookie monitoring | Adobe IMS authentication state tracking | **Legitimate** - own domain only |
| `chrome.storage.local` | Feature state, FTE tracking, preferences | **Normal** extension storage |
| XPath evaluation | DOM queries for dynamic site integration | **Legitimate** - `document.evaluate()` |
| Remote iframe injection | Adobe Express editor, sign-in flows | **Legitimate** - all from `acrobat.adobe.com` |

---

## API Endpoints Table

| Domain | Purpose | Risk |
|--------|---------|------|
| `acrobat.adobe.com` | Main app hosting, CDN | Low |
| `documentcloud.adobe.com` | Document services | Low |
| `dc-api.adobe.io` | REST API (convert, compress, etc.) | Low |
| `ims-na1.adobelogin.com` | Authentication (IMS) | Low |
| `auth.services.adobe.com` | IMS library | Low |
| `sstats.adobe.com` | Analytics (Adobe Experience Platform) | Low |
| `p13n.adobe.io` | Personalization API (Floodgate) | Low |
| `cc-embed.adobe.com` | Adobe Express embed plugin | Low |
| `acroipm2.adobe.com` | In-product messaging | Low |
| `*.akamaiedge.net` | CDN edge nodes | Low |

**All endpoints are legitimate Adobe infrastructure.**

---

## Data Flow Summary

### Inbound Data
1. **PDF Files:** Local files, URLs, Google Drive IDs → Sent to Adobe's conversion service
2. **Web Pages:** HTML snapshots → Converted to PDF via Adobe service
3. **Images:** User uploads → Adobe Express for editing
4. **Authentication:** IMS tokens from Adobe login

### Outbound Data
1. **Analytics:** Usage events → `sstats.adobe.com` (Adobe Analytics)
2. **Logs:** Errors/debug → `dc-api.adobe.io/logging`
3. **Feature Flags:** Extension state → `p13n.adobe.io` (Floodgate)
4. **Conversion Jobs:** PDF/HTML → `dc-api.adobe.io`

### Storage
- **chrome.storage.local:** User preferences, FTE state, session data
- **chrome.storage.session:** Temporary tab state
- **IndexedDB:** Temporary URL buffer (URLs of PDFs being viewed)

**Privacy Assessment:**
- User data sent to Adobe's servers (expected for cloud-based PDF tools)
- Analytics collection (standard for large extensions)
- No third-party data sharing detected
- No credential theft or exfiltration

---

## Security Architecture Review

### Positive Security Controls

✅ **Content Security Policy:**
```javascript
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self';
    frame-src https://use.typekit.net https://assets.adobedtm.com
    https://*.adobecontent.io https://*.adobelogin.com
    https://acrobat.adobe.com https://adobe.com"
}
```

✅ **External Connectivity Restrictions:**
```json
"externally_connectable": {
  "ids": ["bngnhmnppadfcmpggglniifohlkmddfc"],
  "matches": [
    "https://*.adobe.com/*",
    "https://adobe.com/*"
  ]
}
```

✅ **HTTPS Enforcement:** All network calls over TLS
✅ **Origin Validation:** Remote execution validates sender origin
✅ **No Obfuscation:** Code is readable, standard minification only
✅ **Signed Extension:** Verified Chrome Web Store signature

### Areas of Concern (Not Vulnerabilities)

⚠️ **Missing DNS Security:**
- No CAA records on `adobe.com` → Any CA can issue certificates
- No DNSSEC → DNS hijacking possible (though unlikely at Adobe's scale)

⚠️ **Remote Code Architecture:**
- innerHTML from CDN creates XSS vector if CDN compromised
- 10-minute cache enables fast propagation of malicious updates
- CORS `*` allows any site to fetch the code (should be extension-only)

⚠️ **Broad Permissions:**
- `<all_urls>` grants access to every website
- Necessary for functionality but increases blast radius if compromised

---

## Comparison to Malicious Extensions

| Characteristic | Malicious VPN Extensions | Adobe Acrobat |
|----------------|-------------------------|---------------|
| **Obfuscation** | Heavy, multi-layer | None (standard minification) |
| **Code Quality** | Poor, sloppy | Professional, clean |
| **Domains** | Suspicious, new | Well-established Adobe |
| **Purpose** | Hidden (proxy, ad injection) | Clear (PDF tools) |
| **Permissions** | Excessive, unexplained | Extensive but justified |
| **Updates** | Stealth modifications | Version controlled, documented |
| **Company** | Shell companies, fake devs | Adobe Inc. (public company) |

---

## Overall Risk Assessment

### Risk Level: **CLEAN**

**Rationale:**
1. **Legitimate Publisher:** Adobe Inc., established company with security team
2. **Clear Functionality:** All features match advertised purpose
3. **No Malicious Behavior:** No credential theft, ad injection, or proxy abuse
4. **Professional Development:** High code quality, proper error handling
5. **Transparent Data Usage:** Adobe's privacy policy covers extension

**Supply Chain Risk Note:**
The remote execution architecture is a valid security concern for researchers and infrastructure planners, but does not make the extension itself malicious. It's comparable to:
- Chrome auto-updates (Google controls what code runs)
- Electron apps with auto-update (developer controls updates)
- Web apps (server controls all code)

The difference is that browser extensions have elevated privileges, making the CDN a high-value target. However, Adobe's security posture (large security team, bug bounty program, Akamai CDN) mitigates this concern significantly.

---

## Recommendations

### For Adobe (Best Practices)

**Critical:**
1. Add CAA records: `adobe.com CAA 0 issue "digicert.com"`
2. Enable DNSSEC on `adobe.com`
3. Restrict CORS from `*` to specific extension origins
4. Consider bundling remote execution code in extension (eliminates CDN risk)

**Recommended:**
1. Implement Subresource Integrity (SRI) for CDN resources
2. Add code signing/signature validation for remote code
3. Reduce cache TTL from 600s to 60s
4. Document the 7 extension IDs in CSP whitelist

### For Users

**Safe to Use:** This extension is legitimate and safe for its intended purpose (PDF tools).

**Privacy Consideration:** Adobe collects usage analytics and document metadata. Review Adobe's privacy policy if concerned.

**Trust Assumption:** Using this extension means trusting Adobe's security (like using any Adobe product).

---

## Conclusion

The Adobe Acrobat Chrome Extension is a **CLEAN**, professionally developed extension serving its advertised purpose. It employs extensive permissions for legitimate functionality across Google Workspace, Microsoft Outlook, and other platforms.

The remote code execution architecture is a valid architectural concern from a supply chain security perspective, but does not constitute malicious behavior. The extension would benefit from implementing DNS security controls (CAA, DNSSEC) to reduce supply chain risk, but these are defense-in-depth measures rather than indicators of compromise.

**Recommendation for users:** Safe to install and use.
**Recommendation for Adobe:** Implement suggested DNS security controls.
**Recommendation for researchers:** Monitor CDN for changes; note architectural pattern.

---

## Appendix: Code Review Samples

### Sample 1: Authentication (Legitimate)
```javascript
// sw_modules/auth-provider.js
async checkSignInStatus() {
  const token = await this.getIMSToken();
  if (token && !this.isTokenExpired(token)) {
    this.signedIn = true;
  }
}
```

### Sample 2: Analytics (Standard Practice)
```javascript
// common/analytics.js:509
await fetch(`https://sstats.adobe.com/ee/v1/interact?configId=${configId}`, {
  method: "POST",
  body: JSON.stringify({
    events: [{ xdm: { eventType: "web.webpagedetails.pageViews" } }]
  })
});
```

### Sample 3: Remote Execution Validation
```javascript
// re-content-script.js
function setupMessageListener() {
  window.addEventListener("message", function(e) {
    if (!reUtils.isValidMessageOrigin(e.origin)) return;  // Origin check
    if (isBridgeIframe(e.source)) {
      messageHandler.handleCdnMessage(e.data);
    }
  });
}
```

All code samples show legitimate, professional development practices.
