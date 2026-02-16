# Security Analysis Report: Todoist for Gmail

## Metadata
- **Extension Name**: Todoist for Gmail: Planner & Calendar
- **Extension ID**: clgenfnodoocmhnlnpknojdbjjnmecff
- **Version**: 7.5.2
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Todoist for Gmail is a legitimate productivity extension that integrates Todoist task management with Gmail. The extension uses the InboxSDK framework to interact with Gmail's interface. **No critical security vulnerabilities or malicious behavior detected.** The extension follows legitimate development practices, with minimal permissions and proper security boundaries. The only elevated concern is the dependency on third-party InboxSDK infrastructure and the embedded iframe loading the Todoist web application.

**Overall Risk Assessment: LOW**

## Vulnerability Details

### 1. InboxSDK Third-Party Dependency
**Severity**: LOW
**Component**: content.js (InboxSDK framework)
**Verdict**: Acceptable Risk (Legitimate Framework)

**Description**:
The extension uses InboxSDK, a third-party framework for Gmail integrations. InboxSDK makes network calls to external infrastructure:
- `https://api.inboxsdk.com/api/v2/events/oauth` - OAuth token retrieval
- `https://api.inboxsdk.com/api/v2/errors` - Error logging
- `https://pubsub.googleapis.com/v1/projects/mailfoogae/topics/events:publish` - Event telemetry

**Code Evidence**:
```javascript
// content.js:6462
url: "https://api.inboxsdk.com/api/v2/events/oauth",
XMLHttpRequest: (0, v.np)()

// content.js:6469
url: `https://pubsub.googleapis.com/v1/projects/mailfoogae/topics/events:publish?key=${encodeURIComponent("AIzaSyAwlvUR2x3OnCeas8hW8NDzVMswL5hZGg8")}`,
method: "POST",
headers: {
  Authorization: `Bearer ${t}`,
  "Content-Type": "application/json"
}
```

**Analysis**:
- InboxSDK is a legitimate, well-known framework developed by Streak for Gmail integrations
- Telemetry appears limited to framework usage events, not user data exfiltration
- OAuth tokens are for InboxSDK API access, not Gmail account access
- Event data is throttled (12000ms intervals) and sent to Google Cloud Pub/Sub

**Mitigation**: This is standard practice for InboxSDK-based extensions and considered acceptable for productivity tools.

---

### 2. Embedded Todoist Web Application (iframe)
**Severity**: LOW
**Component**: frame.html, frame.js
**Verdict**: Expected Behavior (Legitimate Integration)

**Description**:
The extension loads the Todoist web application in an iframe with clipboard write permissions:

**Code Evidence**:
```html
<!-- frame.html:11 -->
<iframe
    frameborder="0"
    style="width: 100%; height: 100%"
    id="todoist_frame"
    src="https://app.todoist.com/app?mini=1"
    allow="clipboard-write"
/>
```

**Analysis**:
- The iframe loads the legitimate Todoist web application (`app.todoist.com`)
- Clipboard-write permission allows users to copy tasks/links to clipboard
- postMessage communication is used to pass email data from Gmail to the Todoist iframe
- No sensitive Gmail data (passwords, tokens) is transmitted

**Communication Flow**:
```javascript
// background.js:58-64
const r = `${e}--/--${t}`;  // email_href + email_title
const o = document.getElementById("todoist_iframe");
if (o) {
  const e = o.contentWindow;
  if (e) try {
    e.postMessage(r, "*")
  } catch {}
}
```

**Risk**: The wildcard `"*"` targetOrigin in postMessage could allow any site to receive the message if the iframe is hijacked. However, the data passed (email subject/link) is low-sensitivity.

**Mitigation**: Recommend changing postMessage targetOrigin from `"*"` to `"https://app.todoist.com"` in future versions.

---

### 3. Content Script Scope & Permissions
**Severity**: CLEAN
**Component**: manifest.json
**Verdict**: Minimal Attack Surface

**Description**:
The extension requests minimal permissions appropriate for its functionality:

**Permissions Analysis**:
```json
"permissions": ["scripting"],
"host_permissions": [
  "http://*.todoist.com/*",
  "https://*.todoist.com/*",
  "https://mail.google.com/*",
  "http://mail.google.com/*"
]
```

**Content Script Scope**:
```json
"matches": ["http://mail.google.com/*", "https://mail.google.com/*"],
"run_at": "document_end"
```

**Analysis**:
- No dangerous permissions (cookies, webRequest, tabs, debugger)
- Host permissions limited to Todoist domains and Gmail
- No background page network interception
- Content script injected only on Gmail, not all sites
- `scripting` permission used only for legitimate InboxSDK injection

---

### 4. Background Script Behavior
**Severity**: CLEAN
**Component**: background.js
**Verdict**: No Malicious Activity

**Description**:
The background service worker has minimal functionality:

**Code Analysis**:
```javascript
// background.js:4-17
chrome.runtime.onMessage.addListener((e, t, r) => {
  if ("inboxsdk__injectPageWorld" === e.type && t.tab)
    if (chrome.scripting) {
      // Injects pageWorld.js into MAIN world for InboxSDK
      chrome.scripting.executeScript({
        target: { tabId: t.tab.id, documentIds: e, frameIds: o },
        world: "MAIN",
        files: ["pageWorld.js"]
      })
    }
})

// background.js:43-67
chrome.tabs.onUpdated.addListener((e, t, r) => {
  // Monitors Gmail page loads, sends email data to Todoist iframe
  if (r.url?.includes("mail.google.com") && t.status === "complete") {
    chrome.scripting.executeScript({
      target: { tabId: e },
      func: () => setTimeout(() => {
        // Extracts email_href and email_title from TDOpts
        // Sends to iframe via postMessage
      }, 200)
    })
  }
})
```

**Analysis**:
- No network calls from background script
- No cookie/storage access
- Only monitors Gmail tabs for page load completion
- postMessage relay is legitimate extension architecture
- No extension enumeration or killing behavior

---

## False Positive Analysis

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| `innerHTML` usage | content.js:98, pageWorld.js:448 | InboxSDK uses Trusted Types policy `inboxSdk__removeHtmlTagsPolicy` to sanitize HTML | FP - Secure |
| `XMLHttpRequest` hooking | pageWorld.js:32-421 | InboxSDK hooks XHR for API response modification (framework feature) | FP - Framework |
| `window.open` override | pageWorld.js:462-483 | InboxSDK temporarily overrides for link interception (clean pattern) | FP - Framework |
| Google API calls | content.js:14592 | Calls `people-pa.clients6.google.com` for contact autocomplete | FP - Gmail Integration |
| `addEventListener` patterns | Throughout | Standard DOM event handling for UI interactions | FP - Normal |
| `document.querySelector` | Throughout | DOM element selection for UI injection | FP - Normal |
| `fromCharCode` usage | content.js:grep results | Used for digest/hash generation, not obfuscation | FP - Crypto |

## API Endpoints & Data Flow

| Endpoint | Purpose | Data Transmitted | Risk Level |
|----------|---------|------------------|------------|
| `https://api.inboxsdk.com/api/v2/events/oauth` | InboxSDK authentication | OAuth tokens for SDK API | LOW |
| `https://api.inboxsdk.com/api/v2/errors` | Error reporting | Stack traces, error messages | LOW |
| `https://pubsub.googleapis.com/v1/projects/mailfoogae/topics/events:publish` | Telemetry | SDK usage events (throttled) | LOW |
| `https://people-pa.clients6.google.com/$rpc/...` | Contact lookup | Email addresses for autocomplete | LOW |
| `https://app.todoist.com/app?mini=1` | Todoist web app | Email subject lines, links | LOW |

**Data Flow Summary**:
1. Content script (InboxSDK) monitors Gmail DOM for UI elements
2. Background script detects Gmail page loads
3. Email subject/link extracted from Gmail page variables (`TDOpts`)
4. Data passed via postMessage to Todoist iframe
5. User manually creates tasks in Todoist with Gmail context
6. InboxSDK telemetry sent to Google Cloud Pub/Sub (usage stats only)

**No Evidence Of**:
- Email content exfiltration
- Password/credential harvesting
- Cookie stealing
- XHR/fetch hooking for malicious purposes
- Extension enumeration/killing
- Remote code execution
- Keyloggers
- Ad/coupon injection
- Market intelligence SDKs
- Residential proxy infrastructure

---

## Security Strengths

1. **Manifest V3 Compliance**: Uses modern service worker architecture
2. **Minimal Permissions**: Only requests necessary capabilities
3. **CSP Compliance**: No inline scripts, uses bundled JS
4. **Third-Party Framework**: InboxSDK is a reputable, audited framework
5. **No Dangerous APIs**: No webRequest, cookies, debugger, or tabs manipulation
6. **Secure Communication**: Uses message passing instead of direct DOM access
7. **Legitimate Business Model**: Todoist is an established productivity SaaS with 100K+ users

---

## Recommendations

### For Developers (Todoist Team)
1. **Fix postMessage targetOrigin**: Change from `"*"` to `"https://app.todoist.com"` in background.js:63
2. **Document InboxSDK Dependency**: Make telemetry data collection transparent in privacy policy
3. **Consider CSP Headers**: Add Content-Security-Policy to frame.html for defense-in-depth

### For Users
- This extension is **SAFE TO USE** for its intended purpose
- Be aware that InboxSDK collects usage telemetry (anonymized)
- Review Todoist's privacy policy for data handling practices

---

## Overall Risk Assessment

**Risk Level: LOW**

### Justification:
- Legitimate productivity extension with transparent functionality
- Uses well-established InboxSDK framework (industry standard)
- Minimal permissions appropriate for Gmail integration
- No malicious code patterns detected
- Reputable developer (Todoist/Doist) with established business
- Small attack surface (limited to Gmail + Todoist domains)
- No evidence of data exfiltration, tracking, or malware behavior

### Security Score Breakdown:
- **Code Quality**: 8/10 (Clean, bundled code with proper error handling)
- **Permission Model**: 9/10 (Minimal, appropriate permissions)
- **Privacy Practices**: 7/10 (InboxSDK telemetry should be more transparent)
- **Architecture**: 8/10 (Good separation of concerns, minor postMessage fix needed)

**Conclusion**: Todoist for Gmail is a **CLEAN** extension with no significant security concerns. The identified issues are minor best-practice violations, not exploitable vulnerabilities. Recommended for use by security-conscious users seeking Gmail-Todoist integration.
