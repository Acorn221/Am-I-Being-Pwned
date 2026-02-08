# Vulnerability Report: Browse AI Extension

## Metadata
- **Extension Name:** Browse AI: Fast Web Scraping & Monitoring
- **Extension ID:** obpcenkclppghkfpielmefegceegofeh
- **Version:** 2.2.3
- **User Count:** ~100,000
- **Manifest Version:** 3
- **Analysis Date:** 2026-02-07

## Executive Summary

Browse AI is a legitimate web scraping and automation tool that allows users to record browser interactions and extract data from websites. The extension implements appropriate security controls for its functionality and does not exhibit malicious behavior. The extension uses optional permissions (cookies, tabs, webRequest, webNavigation) that are requested at runtime and are necessary for its core web automation features. All network communication is directed to legitimate Browse AI infrastructure.

**Overall Risk Level: CLEAN**

The extension demonstrates responsible security practices including:
- Proper use of Content Security Policy (CSP)
- Restricted externally_connectable to only Browse AI domains
- Optional permissions model requiring user consent
- No evidence of data exfiltration, residential proxy infrastructure, or malicious SDK injection
- Transparent data collection with Datadog logging SDK for application monitoring

## Vulnerability Details

### 1. Cookie Access with Optional Permissions
**Severity:** LOW (False Positive - Legitimate Functionality)
**Location:** `service_worker.js:42960-42974`, `service_worker.js:43614-43648`
**Code Evidence:**
```javascript
const getDomainCookies = ({
  domain,
  name,
  exclude = []
}) => new Promise(
  (resolve) => chrome.cookies.getAll({ domain, name }, (cookies) => {
    resolve(
      cookies.filter((cookie) => cookie.expirationDate && cookie.expirationDate > 0).filter(
        (cookie) => exclude.findIndex(
          (excludedCookie) => excludedCookie.domain === cookie.domain && excludedCookie.name === cookie.name
        ) === -1
      )
    );
  })
);
```

**Analysis:** The extension accesses cookies for websites being automated, which is necessary for:
1. Recording user sessions including authentication state
2. Replaying automated workflows with proper cookies
3. Web scraping that requires authenticated access

The cookies permission is marked as **optional** in manifest.json and only requested when users explicitly start recording workflows. Cookie data is sent to Browse AI backend (`https://internal-api.browse.ai`) for storing with robot configurations.

**Verdict:** BENIGN - Required for legitimate automation functionality

---

### 2. WebRequest API Usage for Network Monitoring
**Severity:** LOW (False Positive - Legitimate Functionality)
**Location:** `service_worker.js:44155-44179`, `service_worker.js:44202-44222`
**Code Evidence:**
```javascript
chrome.webRequest.onCompleted.addListener(
  onCompletedResponseHandler,
  {
    tabId: recorderTab.id,
    urls: ["http://*/*", "https://*/*"]
  },
  ["responseHeaders"]
);
```

**Analysis:** The extension monitors HTTP requests/responses during recording to:
1. Capture cookies set by websites during navigation
2. Record network activity as part of automation workflows
3. Detect content types and response headers

The webRequest listener is:
- Scoped to specific recorder tab only (not global)
- Used during active recording sessions only
- Properly cleaned up when recording stops
- Marked as optional permission requiring user consent

**Verdict:** BENIGN - Standard automation tool behavior

---

### 3. Datadog Telemetry SDK Integration
**Severity:** LOW (False Positive - Legitimate Monitoring)
**Location:** `service_worker.js:6293-6301`, `popup.js:37437-37491`
**Code Evidence:**
```javascript
const clientToken = define_process_env_default$5.DATADOG_CLIENT_TOKEN ||
  define_process_env_default$5.REACT_APP_DATADOG_CLIENT_TOKEN;
if (clientToken && getExtensionEnv() !== "content") {
  datadogLogs.init({
    clientToken,
    datacenter: "us",
    forwardErrorsToLogs: true,
    sampleRate: 100
  });
}
```

**Client Token:** `pub829657516887adb6c583bd9646064850`

**Analysis:** The extension uses Datadog's browser logging SDK for application monitoring. This is a standard observability practice used by legitimate software companies. The telemetry:
- Uses public client token (not sensitive)
- Logs errors and debugging information
- Does not log sensitive user data (PII, passwords, etc.)
- Is only initialized in background/popup contexts, not content scripts

**Verdict:** BENIGN - Standard application monitoring

---

### 4. Chrome Extension Message Passing
**Severity:** LOW (False Positive - Required Functionality)
**Location:** `content_script.js:47689`, `service_worker.js:12130`
**Code Evidence:**
```javascript
chrome.runtime.sendMessage(fr(fr({}, e), {}, {
  from: i
}), (function(e) {
  a(new CustomEvent("browse-ai_call-remote-function-result", {
    detail: e
  }))
}))
```

**Analysis:** The extension uses standard Chrome message passing to coordinate between:
- Content scripts injected into web pages
- Background service worker
- Popup UI

All message handlers implement proper origin checking and are scoped to the extension's own runtime.

**Verdict:** BENIGN - Standard extension architecture

---

### 5. External Message Listener for Dashboard Integration
**Severity:** LOW (False Positive - Documented Feature)
**Location:** `service_worker.js:43659-43748`
**Code Evidence:**
```javascript
chrome.runtime.onMessageExternal.addListener(
  (message, _sender, sendResponse) => {
    if (typeof message === "object") {
      if (message.type === "record" || message.type === "re-record") {
        // Handle recording requests from dashboard
      }
    }
  }
);
```

**Analysis:** The extension accepts messages from external origins, but this is properly restricted:
- `externally_connectable` in manifest limits to Browse AI domains only:
  - `https://dashboard.browse.ai/*`
  - `https://dashboard.browseai.com/*`
  - `https://qa-dashboard.browse.ai/*`
  - `https://qa-dashboard.browseai.com/*`
- Used to allow dashboard website to trigger recordings
- Implements authentication checks before accepting commands

**Verdict:** BENIGN - Properly secured external communication

## False Positive Analysis

| Finding | Why It's a False Positive |
|---------|--------------------------|
| Cookie harvesting | Cookies are collected only during user-initiated recording sessions for legitimate automation purposes. Optional permission model requires explicit user consent. |
| Network request interception | WebRequest API is used to monitor network activity only in recorder tabs, necessary for capturing complete automation workflows. Properly scoped and cleaned up. |
| Telemetry/tracking | Datadog SDK is used for application error monitoring, not user tracking. Standard practice for SaaS applications. |
| innerHTML usage (53 occurrences) | Used by React framework for DOM rendering, not for injecting malicious content. Standard web framework behavior. |
| Base64 encoding (30 occurrences) | Used by bundled libraries (React, Lodash) for standard encoding operations, not obfuscation. |

## API Endpoints & Data Flow

### Primary API Endpoint
- **Base URL:** `https://internal-api.browse.ai`
- **Purpose:** GraphQL API for robot management, user authentication, and data storage

### Dashboard Endpoints
- **Login/Activation:** `https://dashboard.browse.ai/extension-activate`
- **Dashboard:** `https://dashboard.browse.ai`
- **Marketing Site:** `https://browse.ai/`
- **Support:** `https://browse.ai/support`

### Data Flow Summary

1. **User Authentication:**
   - User activates extension via `dashboard.browse.ai/extension-activate`
   - Authentication token stored in `chrome.storage.local`
   - Token sent with GraphQL requests to `internal-api.browse.ai`

2. **Recording Workflow:**
   - User initiates recording from popup or dashboard
   - Extension requests optional permissions (cookies, tabs, webRequest)
   - Content script injected into target page
   - User interactions captured with DOM selectors, timestamps
   - Cookies collected from recorded domains
   - Steps uploaded to Browse AI API via GraphQL mutation

3. **Data Stored Locally:**
   - User info (email, role, team)
   - Recording state and steps
   - Recorder tab information
   - Collected cookies (during active recording)

4. **Data Sent to Backend:**
   - Recorded automation steps (DOM selectors, events, timestamps)
   - Website cookies (only from sites being automated)
   - Chrome version, extension version
   - Error logs (via Datadog SDK)

## Security Strengths

1. **Content Security Policy:** Strict CSP with `script-src 'self'` prevents code injection
2. **Optional Permissions Model:** Sensitive permissions (cookies, webRequest) require user approval
3. **Scoped Listeners:** WebRequest/WebNavigation listeners limited to specific recorder tabs
4. **Proper Cleanup:** All listeners and state properly cleaned up after recording
5. **Origin Restrictions:** External messages only accepted from verified Browse AI domains
6. **No Dynamic Code Execution:** No use of `eval()`, `Function()`, or unsafe innerHTML patterns
7. **Transparent Logging:** Datadog integration uses public token and logs errors only

## Potential Privacy Considerations (Not Vulnerabilities)

1. **Cookie Collection:** The extension collects cookies from websites during automation recording. This is disclosed functionality required for the product to work. Users explicitly consent by granting cookies permission.

2. **Telemetry:** Error logs sent to Datadog may contain debugging context about user actions. This is standard application monitoring practice.

3. **Data Retention:** Recorded automation workflows (including cookies) are stored on Browse AI servers. Users should review Browse AI's privacy policy.

## Recommendations

**For Users:**
- Only use Browse AI on websites where you're comfortable sharing cookies and session data
- Review what permissions you grant when starting recordings
- Be aware recorded workflows are stored in Browse AI cloud

**For Developers:**
- Consider adding more granular cookie filtering options
- Implement automatic cookie expiration/cleanup for old recordings
- Add privacy controls to limit what data is included in Datadog logs
- Consider offering self-hosted deployment option for enterprise users concerned about data residency

## Overall Risk Assessment

**Risk Level: CLEAN**

Browse AI is a legitimate web automation tool that properly implements necessary Chrome APIs for its functionality. The extension:
- Uses permissions appropriately for stated purpose
- Implements security best practices (CSP, origin restrictions, optional permissions)
- Has no malicious behavior patterns (no ad injection, no proxy infrastructure, no extension killing)
- Communicates only with legitimate Browse AI infrastructure
- Provides transparency about data collection

**No security vulnerabilities or malicious behavior detected.**
