# Security Analysis Report: Folio - Manage Real Estate Deals from Gmail

## Extension Metadata
- **Extension Name**: Folio: Manage Real Estate Deals from Gmail
- **Extension ID**: ecaieeiecbdhkcgknidmfelflleobbnp
- **Version**: 1.2.47055
- **Users**: ~40,000
- **Manifest Version**: 3
- **Developer**: Amitree (amitree.com)

## Executive Summary

Folio is a legitimate real estate transaction management extension that integrates with Gmail to help real estate professionals manage closing timelines, documents, and communications. The extension uses InboxSDK to interact with Gmail and requires significant permissions to function.

The extension implements several invasive features including full Gmail access, Google Contacts synchronization, cookie management, and real-time communication via Pusher. While these capabilities are extensive, they appear to serve the stated functionality of managing real estate transactions from Gmail. Analytics tracking via Mixpanel is present but standard for the industry.

**Overall Risk Assessment**: CLEAN (with invasive permissions appropriate for stated functionality)

The extension demonstrates professional development practices, clear legitimate business purpose, and transparent data handling. No evidence of malicious behavior, credential theft, market intelligence SDKs, residential proxy infrastructure, or other red flags was identified.

## Manifest Analysis

### Permissions
```json
"permissions": [
  "storage",
  "cookies",
  "scripting"
]
```

### Host Permissions
```json
"host_permissions": [
  "https://www.amitree.com/",
  "https://apis.google.com/",
  "https://mail.google.com/*"
]
```

### Content Security Policy
```json
"content_security_policy": {
  "sandbox": "sandbox allow-scripts; script-src 'self'; object-src 'self'"
}
```

**Analysis**:
- CSP is properly configured with sandbox restrictions
- Permissions are extensive but appropriate for a Gmail productivity tool
- Host permissions limited to legitimate services (Amitree backend, Google APIs, Gmail)
- External connectivity restricted to Amitree domain via `externally_connectable`

### Content Scripts
- Runs on `https://mail.google.com/*` at `document_end`
- Loads vendor.js, folio.js, and inject-css.js
- Uses InboxSDK (legitimate Gmail integration framework)

### Background Service Worker
- Modern MV3 service worker architecture
- Module-based with clean separation of concerns

## Vulnerability Assessment

### 1. Gmail Access & Data Collection
**Severity**: INFORMATIONAL
**Files**: `assets/folio.js`, `pageWorld.js`, `assets/background.js`
**Details**:

The extension has comprehensive Gmail access through InboxSDK:
- Thread and message reading
- Email header extraction
- Contact information parsing
- Gmail thread identification and tracking

**Code Evidence**:
```javascript
// background.js:100-135
static downloadGoogleContacts(
  { accessToken, pageToken, url, maskName, maskItems },
  callback
) {
  const params = { pageSize: MAX_PAGE_SIZE }
  params[maskName] = maskItems.join(',')
  if (pageToken) params['pageToken'] = pageToken

  const endpoint = `${url}?${new URLSearchParams(params)}`
  const config = {
    method: 'GET',
    credentials: 'omit',
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  }

  fetch(endpoint, config)
    .then(response => response.json())
    .then(jsonResponse => {
      callback(jsonResponse)
      // Handles pagination for large contact lists
```

**Verdict**: CLEAN - Gmail access is the core functionality. The extension helps manage real estate transactions from Gmail, requiring email and contact access. Access tokens are passed from content script (where user authenticates) and used only for legitimate Google APIs.

### 2. Cookie Management
**Severity**: LOW
**Files**: `assets/background.js`
**Details**:

Background script handles cookie operations for the extension:
```javascript
// background.js:197-201
} else if (message.name === SET_COOKIE_MESSAGE) {
  chrome.cookies.set.apply(chrome.cookies, message.args)
} else if (message.name === GET_COOKIE_MESSAGE) {
  chrome.cookies.get(message.args[0], sendResponse)
  return typeof sendResponse === 'function'
```

**Verdict**: CLEAN - Cookie access limited to chrome.cookies API (not document.cookie scraping). Used for authentication state management with Amitree backend. Standard pattern for extensions requiring persistent sessions.

### 3. Analytics & Telemetry (Mixpanel)
**Severity**: INFORMATIONAL
**Files**: `assets/mixpanel.js`, `assets/mixpanel-message-manager.js`
**Details**:

Mixpanel analytics SDK integrated for user behavior tracking:
- Token: `f2e400c1bb39dfe2653a021b96f9a68d`
- Device ID persistence in local storage
- Standard event tracking (init, register, people.set, identify, track, reset)
- Allowlist-based message processing for security

**Code Evidence**:
```javascript
// mixpanel-message-manager.js:50-65
static async initialize() {
  const result = await chrome.storage.local.get('folio_mixpanel_device_id')
  const persistedDeviceId = result.folio_mixpanel_device_id
  const config = { device_id: persistedDeviceId }

  super.process({
    name: 'mixpanel.init',
    args: ['f2e400c1bb39dfe2653a021b96f9a68d', config],
  })

  if (!persistedDeviceId) {
    return chrome.storage.local.set({
      folio_mixpanel_device_id: mixpanel.get_property('$device_id'),
    })
  }
}
```

**Verdict**: CLEAN - Standard analytics implementation. Mixpanel is a legitimate product analytics platform. No evidence of excessive data collection beyond normal usage patterns.

### 4. Real-time Communication (Pusher)
**Severity**: INFORMATIONAL
**Files**: `assets/pusher.js`, `assets/pusher-bridge.js`, `assets/pusher-message-manager.js`
**Details**:

WebSocket-based real-time updates via Pusher:
- Authenticated channels with auth endpoint at Amitree backend
- Channel subscription/unsubscription management
- Event binding for real-time notifications
- Secure connection with forceTLS enabled

**Code Evidence**:
```javascript
// pusher-bridge.js:21-29
connect({ pusherApiKey, authEndpoint, headers }) {
  const disableStats = true
  const forceTLS = true

  return new Pusher(
    pusherApiKey,
    { authEndpoint, auth: { headers }, disableStats, forceTLS },
  )
}
```

**Verdict**: CLEAN - Pusher is a legitimate real-time messaging service. Used for collaborative features and live updates in shared real estate timelines. Connections authenticated via Amitree backend.

### 5. Network Request Proxying
**Severity**: LOW
**Files**: `assets/network-request-manager.js`
**Details**:

Background script proxies network requests to bypass CORS:
- Handles AJAX and file upload requests from content scripts
- Includes automatic error reporting to Amitree backend
- Rate-limited error reporting (max 5 per minute)

**Code Evidence**:
```javascript
// network-request-manager.js:6-30
static async process(opts, sendResponse) {
  try {
    const { url, requestOpts } = this.buildFetchOptions(opts)

    // 991Emergency - cache 301 loop - cache busting
    const bustingUrl = this.bustCache(url)

    const response = await fetch(bustingUrl, requestOpts)
    const processedResponse = await this.processResponse(response)

    if (!response.ok) this.reportFailure(response, url, requestOpts)

    sendResponse(processedResponse)
```

Error reporting endpoint:
```javascript
// network-request-manager.js:136-148
const url = "https://www.amitree.com/folio_ajax_error"
const method = 'POST'
const data = {
  initial_request_url: initialUrl,
  initial_request_method: initialOpts.method,
  initial_request_status: response.status,
  initial_request_payload: initialOpts.body
}
```

**Verdict**: CLEAN - Standard CORS workaround pattern for Chrome extensions. Error reporting helps developers debug production issues. Only reports to legitimate Amitree domain, rate-limited to prevent abuse.

### 6. Google Ads Conversion Tracking
**Severity**: INFORMATIONAL
**Files**: `assets/background.js`
**Details**:

Install event triggers Google Ads conversion:
```javascript
// background.js:31-36
static onInstallGoogleListener(details) {
  if (details.reason !== 'install') return

  const url = 'https://www.googleadservices.com/pagead/conversion/999678629/?label=i2u0CKnkqmkQpcXX3AM&guid=ON&script=0'
  fetch(url, { mode: 'no-cors', })
}
```

**Verdict**: CLEAN - Standard Google Ads conversion pixel for marketing attribution. Single no-cors request on install, no ongoing tracking.

### 7. InboxSDK Integration
**Severity**: INFORMATIONAL
**Files**: `pageWorld.js`, `assets/folio.js`
**Details**:

Uses InboxSDK for Gmail integration:
- Legitimate framework from Streak (https://www.inboxsdk.com/)
- Page world injection for accessing Gmail's internal APIs
- Thread identification and UI manipulation

**Code Evidence**:
```javascript
// background.js:176-188
if (message.type === 'inboxsdk__injectPageWorld' && sender.tab) {
  chrome.scripting.executeScript({
    target: { tabId: sender.tab.id },
    world: 'MAIN',
    files: ['pageWorld.js'],
  })
    .then(() => sendResponse(true))
    .catch(err => {
      console.error('pageWorld.js injection failed', err)
      sendResponse(false)
    })

  return true
}
```

**Verdict**: CLEAN - InboxSDK is a well-known, legitimate framework used by many Gmail extensions. Proper error handling and standard implementation pattern.

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `innerHTML` usage | pageWorld.js, folio.js, vendor.js | InboxSDK and Ember framework DOM manipulation, not XSS |
| `eval` patterns | vendor.js | Ember.js template compilation, not dynamic code execution |
| `fetch` references | vendor.js | Ember Data polyfill definitions, not hooking |
| Authorization headers | background.js | Google OAuth tokens for legitimate API access |
| Cookie access | mixpanel.js | Standard Mixpanel SDK cookie management |
| `postMessage` | pusher-bridge.js | Chrome extension messaging, not cross-origin exploitation |

## API Endpoints & Data Flows

### Amitree Backend Endpoints
| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://www.amitree.com/folio_ajax_error` | Error reporting | Failed request details, status codes |
| `https://www.amitree.com/folio/install_redirect` | Post-install onboarding | Installation metadata |
| `https://www.amitree.com/folio/uninstall` | Uninstall feedback | User ID (if set) |
| `https://deployer.amitree.com/pull-request` | Developer tools | Branch name (dev builds only) |

### Google Services
| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://apis.google.com/*` | Contacts API | OAuth token, pagination params |
| `https://mail.google.com/*` | Gmail integration | Thread IDs, search queries |
| `https://www.googleadservices.com/pagead/conversion/*` | Ads conversion | Install event (one-time) |

### Third-Party Services
| Service | Purpose | Data Sent |
|---------|---------|-----------|
| Mixpanel | Analytics | User events, device ID, feature usage |
| Pusher | Real-time messaging | Channel subscriptions, auth headers |

## Data Flow Summary

1. **User Authentication**: User authenticates with Google OAuth in content script context, access tokens passed to background script for API calls
2. **Gmail Data**: Email threads, messages, and contacts read via Gmail APIs and InboxSDK, sent to Amitree backend for processing
3. **Real Estate Data**: Transaction timelines, documents, and contacts managed through Amitree platform
4. **Real-time Updates**: Pusher WebSocket connections for collaborative features
5. **Analytics**: Usage events tracked via Mixpanel for product analytics
6. **Error Reporting**: Failed network requests reported to Amitree for debugging

## Security Strengths

1. **MV3 Migration**: Modern Manifest V3 architecture with service workers
2. **CSP Configuration**: Proper sandbox and script-src restrictions
3. **Host Permissions**: Limited to necessary domains only
4. **Error Handling**: Comprehensive try-catch blocks and error reporting
5. **Rate Limiting**: Error reports limited to 5 per minute
6. **Authentication**: Proper OAuth flow with Google APIs
7. **External Connectivity**: Restricted to Amitree domain
8. **TLS Enforcement**: Pusher connections use forceTLS

## Recommendations

1. **For Users**: This is a legitimate productivity tool for real estate professionals. Users should understand it has full access to Gmail data as required for its core functionality.

2. **For Developers**:
   - Consider adding more granular permission requests (optional permissions)
   - Implement content security logging for audit trail
   - Consider user-facing privacy dashboard showing what data is accessed

3. **For Security Reviewers**: Extension follows best practices for a Gmail integration tool with appropriate permissions for stated functionality.

## Overall Risk Assessment

**Risk Level**: CLEAN

**Justification**:
Folio is a legitimate real estate transaction management tool that requires extensive Gmail access to deliver its core value proposition. All invasive features (Gmail access, contacts sync, cookie management, real-time communication) directly serve the stated functionality.

The extension demonstrates:
- Professional development by established company (Amitree)
- Appropriate use of permissions for stated features
- No evidence of credential theft, market intelligence, or proxy infrastructure
- Standard analytics implementation
- Proper security practices (CSP, HTTPS, OAuth)
- Transparent data flows to company backend

While the permissions are broad, they are necessary for a tool that manages real estate transactions from Gmail. No malicious behavior detected.

## Detailed File Analysis

### Critical Files
1. **manifest.json** - Properly configured MV3 manifest
2. **assets/background.js** (7.6KB) - Clean background script with standard messaging
3. **assets/folio.js** (7.7MB) - Main application logic (Ember.js app bundle)
4. **assets/vendor.js** (9.6MB) - Dependencies (Ember, InboxSDK, frameworks)
5. **pageWorld.js** (561KB) - InboxSDK page world injection
6. **assets/network-request-manager.js** (5.4KB) - CORS proxy for API calls
7. **assets/pusher-bridge.js** (3.7KB) - Real-time messaging bridge
8. **assets/mixpanel.js** (211KB) - Analytics SDK

### Code Quality
- Well-structured with clear separation of concerns
- Modern ES6+ JavaScript with modules
- Comprehensive error handling
- Professional development practices evident throughout

## Conclusion

Folio is a CLEAN extension that serves a legitimate business purpose for real estate professionals. While it requires extensive permissions, these are appropriate and necessary for managing real estate transactions directly from Gmail. No security vulnerabilities or malicious behavior identified.
