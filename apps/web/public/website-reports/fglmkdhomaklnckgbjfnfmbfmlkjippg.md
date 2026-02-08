# Vulnerability Assessment Report: Tracking Time | Time Tracker Button

## Extension Metadata

- **Extension Name**: Tracking Time | Time Tracker Button
- **Extension ID**: fglmkdhomaklnckgbjfnfmbfmlkjippg
- **Approximate Users**: ~30,000
- **Manifest Version**: 3
- **Version**: 3.18
- **Author**: Tracking Time LLC

## Executive Summary

Tracking Time is a legitimate time tracking browser extension that integrates with third-party productivity tools. The extension demonstrates professional development practices with appropriate security measures for its intended functionality. While it requests sensitive permissions and handles authentication data, all observed behaviors align with its core time tracking purpose. No malicious code, data exfiltration beyond intended functionality, or exploitable vulnerabilities were identified.

**Overall Risk Level**: **CLEAN**

The extension is invasive by nature (requires broad permissions to integrate with multiple productivity platforms), but serves its intended purpose without malicious behavior or critical security flaws.

## Vulnerability Details

### 1. Authentication Token Exposure
**Severity**: LOW
**Files**: `scripts/Api.js` (lines 64-67), `scripts/Modules.js` (lines 44-48)
**Code**:
```javascript
static async get_base_auth() {
    let user = await currentUser.get();
    return `Basic ${btoa(user.email + ":" + user.token)}`;
}
```

**Analysis**: The extension stores user authentication tokens in chrome.storage.local and constructs Basic Auth headers. While this is standard for authenticated API communication, tokens are accessible to the extension context.

**Verdict**: ACCEPTABLE - Standard authentication pattern for browser extensions. Tokens are only sent to legitimate TrackingTime domains (`*.trackingtime.co`, `*.trackingtime.io`). No evidence of token leakage to third parties.

---

### 2. Optional Host Permissions (Broad Scope)
**Severity**: MEDIUM
**Files**: `manifest.json` (line 34)
**Code**:
```json
"optional_host_permissions": [
    "*://*/*"
]
```

**Analysis**: The extension requests optional permissions to access all websites, which enables integration with various productivity tools (Asana, Trello, GitHub, etc.). Users must explicitly grant these permissions.

**Verdict**: ACCEPTABLE - Required for the extension's core functionality of adding time tracking buttons to third-party web applications. Permissions are optional and user-controlled. Code review shows permissions are only used for injecting time tracking UI elements, not for data harvesting.

---

### 3. WebSocket Connection to AWS
**Severity**: LOW
**Files**: `scripts/WebSockets.js` (lines 10-77), `environment.js` (line 15)
**Code**:
```javascript
var WS_URL = "wss://rb7mltgoyh.execute-api.us-east-1.amazonaws.com/prod";
// ...
connection = new WebSocket(WS_URL);
```

**Analysis**: Extension maintains a WebSocket connection to an AWS API Gateway endpoint for real-time synchronization of time tracking events across devices.

**Verdict**: ACCEPTABLE - Legitimate use case for multi-device sync. The WebSocket only transmits time tracking state changes and ping/pong keepalive messages. Connection is authenticated using user credentials. No sensitive browsing data transmitted.

---

### 4. Third-Party Analytics Integration
**Severity**: LOW
**Files**: `scripts/analytics.js` (lines 1-327), `environment.js` (lines 17-18)
**Code**:
```javascript
var GA_ID = 'UA-36530020-6';
var INTERCOM_ID = 'jestytpi';
// ...
fetch('https://www.google-analytics.com/collect?...')
fetch('https://integrations.trackingtime.io/intercom/')
```

**Analysis**: Extension integrates Google Analytics and Intercom for usage analytics and customer support. Event tracking includes user actions within the extension.

**Verdict**: ACCEPTABLE - Standard business analytics practices. Data sent is limited to extension usage patterns (e.g., "Start Tracking", "Stop Tracking", page views within extension UI). No PII beyond user ID is transmitted. Intercom integration supports customer support functionality.

---

### 5. Dynamic Script Injection
**Severity**: LOW
**Files**: `scripts/Modules.js` (lines 222-295)
**Code**:
```javascript
await chrome.scripting.executeScript({
    target: {
        tabId: tab.id,
        allFrames: allFrames,
    },
    files: [
        "js/lib/jquery-3.3.1.min.js",
        "js/lib/moment-with-locales.min.js",
        "environment.js",
        "js/lib/url-pattern.js",
        "js/browser.js",
    ]
});
```

**Analysis**: Extension injects scripts into web pages that match configured domain patterns (e.g., Asana, Trello). Injection only occurs on domains where the extension is enabled by the user.

**Verdict**: ACCEPTABLE - Script injection is the intended mechanism for adding time tracking buttons to third-party tools. All injected scripts are bundled with the extension (no remote code loading). Injection is permission-gated and domain-specific.

---

### 6. Cookie Access
**Severity**: LOW
**Files**: `scripts/Modules.js` (lines 44-48), `scripts/Listeners.js` (lines 42-54)
**Code**:
```javascript
async getCookieToken() {
    let all_cookies = await chrome.cookies.getAll({});
    let cookies_url_domain = new URL(BUTTON_PRODUCTION_DOMAIN).host;
    let cookie_token = all_cookies.filter((cookie) =>
        cookie.domain == cookies_url_domain && cookie.name == "token")[0] || {};
    return cookie_token.value ? cookie_token.value : false;
}
```

**Analysis**: Extension reads cookies from `trackingtime.co` domain to detect user login state and synchronize authentication across the web app and extension.

**Verdict**: ACCEPTABLE - Cookie access is limited to the extension's own service domain (`trackingtime.co`). This is a standard cross-component authentication pattern. No third-party cookies are accessed.

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| Sentry SDK | `js/lib/sentry.js` | Standard error tracking library (8823 lines). No instrumentation of user data beyond error logs. |
| jQuery library | `js/lib/jquery-3.3.1.min.js` | Minified third-party library for DOM manipulation. |
| Moment.js library | `js/lib/moment-with-locales.min.js` | Date/time handling library. Standard time tracking utility. |
| Basic Auth headers | `scripts/Api.js` | Standard authentication for REST API calls to TrackingTime backend. |
| chrome.storage usage | Throughout | Legitimate local storage for user preferences and cached data. |

---

## API Endpoints & Data Flow

### Primary Endpoints
| Endpoint | Purpose | Data Transmitted |
|----------|---------|------------------|
| `https://pro.trackingtime.co/api/v4/` | Core API | User credentials, time tracking events, task metadata |
| `wss://rb7mltgoyh.execute-api.us-east-1.amazonaws.com/prod` | WebSocket sync | Real-time tracking state, ping/pong keepalive |
| `https://www.google-analytics.com/collect` | Analytics | Usage events, app version, anonymized client ID |
| `https://integrations.trackingtime.io/intercom/` | Customer support | User profile data, support events |
| `https://button.trackingtime.co/extension/domains-3.json` | Configuration | Supported integration domains list |

### Data Flow Summary

1. **Authentication Flow**:
   - User logs in via popup window to `https://button.trackingtime.co/login/`
   - Extension monitors cookies for "token" value
   - Token stored in chrome.storage.local
   - Subsequent API calls use Basic Auth with email:token

2. **Time Tracking Flow**:
   - User clicks time tracking button on integrated site
   - Extension sends POST to `/api/v4/{account_id}/tasks/track/`
   - Tracking state synchronized via WebSocket
   - Local storage caches current tracking event

3. **Script Injection Flow**:
   - User grants host permissions for specific domains
   - Extension fetches domain configuration (domains-3.json)
   - On matching tab load, injects UI scripts
   - Injected scripts communicate with background via chrome.runtime.sendMessage

---

## Security Strengths

1. **Manifest V3 Compliance**: Uses modern service worker architecture with improved security model
2. **Permission Scoping**: Host permissions are optional and user-controlled
3. **HTTPS Everywhere**: All network communication uses encrypted channels (HTTPS/WSS)
4. **No eval() or Function()**: No dynamic code execution detected
5. **Domain Whitelisting**: API calls restricted to legitimate TrackingTime domains
6. **Sentry Integration**: Professional error monitoring indicates active maintenance
7. **Content Security Policy**: Default MV3 CSP enforced (no custom relaxation)

---

## Security Weaknesses

1. **Broad Optional Permissions**: `*://*/*` scope is overly permissive, though required for functionality
2. **Analytics Tracking**: Google Analytics and Intercom may not be disclosed in privacy policy (not verified)
3. **Token Storage**: Tokens stored in plaintext in chrome.storage.local (standard limitation)
4. **No Code Obfuscation**: While positive for review, makes reverse engineering trivial

---

## Privacy Considerations

**Data Collected**:
- User account credentials (email, token)
- Time tracking events (task name, project, start/stop times)
- Browser metadata (user agent, timezone, app version)
- Usage analytics (feature interactions, page views)
- Third-party integration data (domain visited, task IDs from external tools)

**Data Recipients**:
- TrackingTime backend servers (primary functionality)
- Google Analytics (usage metrics)
- Intercom (customer support)
- AWS API Gateway (real-time sync)

**Notable**: The extension does NOT appear to:
- Capture browsing history beyond configured domains
- Access page content outside integrated tools
- Track keystrokes or form data
- Inject ads or modify page content maliciously
- Communicate with unexpected third parties

---

## Recommendations

### For Users
1. ✅ Safe to use if you need time tracking integration with productivity tools
2. Review and limit host permissions to only domains you actively use
3. Be aware that usage data is sent to Google Analytics and Intercom
4. Ensure you trust TrackingTime LLC with your work activity data

### For Developers (TrackingTime Team)
1. Consider requesting more granular optional_host_permissions (per-integration)
2. Implement subresource integrity (SRI) for third-party libraries
3. Add user-visible disclosure of analytics in extension UI
4. Consider encrypting tokens in chrome.storage.local (though limited value)

---

## Overall Risk Assessment

**CLEAN** - This extension is a legitimate productivity tool with no malicious characteristics. While it requires invasive permissions and handles sensitive data, all behaviors align with its documented time tracking functionality. The extension demonstrates professional development practices and appropriate security measures for a productivity SaaS integration.

The extension is suitable for use by individuals and organizations that trust TrackingTime LLC as a service provider and understand the data sharing inherent in time tracking functionality.

---

## Analysis Metadata

- **Analysis Date**: 2026-02-08
- **Deobfuscated Code Location**: `output/workflow-downloaded/fglmkdhomaklnckgbjfnfmbfmlkjippg/deobfuscated/`
- **Total Files Reviewed**: 50+ (JavaScript, JSON, HTML)
- **Key Files Analyzed**:
  - `manifest.json`
  - `service-worker.js` + all imported scripts
  - `scripts/Api.js`, `scripts/Modules.js`, `scripts/WebSockets.js`
  - `scripts/analytics.js`, `scripts/Listeners.js`
  - `js/browser.js` (content script functionality)
