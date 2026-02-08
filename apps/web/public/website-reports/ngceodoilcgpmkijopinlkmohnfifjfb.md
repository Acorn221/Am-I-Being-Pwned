# Security Analysis Report: Focus To-Do Pomodoro Timer & To Do List

## Extension Metadata
- **Extension ID**: ngceodoilcgpmkijopinlkmohnfifjfb
- **Name**: Focus To-Do: Pomodoro Timer & To Do List
- **Version**: 7.1.1
- **Users**: ~500,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

Focus To-Do is a legitimate Pomodoro timer and productivity application with **NO MALICIOUS BEHAVIOR DETECTED**. The extension operates as a standalone popup window application with minimal permissions, legitimate cloud sync functionality, and standard payment processing. All findings relate to poor security practices (hardcoded credentials) rather than malicious intent.

**Overall Risk Rating**: **LOW**

The extension poses minimal security risk. The primary concern is a hardcoded STOMP/WebSocket credential for message queue authentication, which represents a vulnerability but not active malware. The extension does not inject content scripts, does not manipulate web pages, and does not harvest user data beyond its stated productivity tracking functionality.

---

## Vulnerability Analysis

### 1. Hardcoded Message Queue Credentials
**Severity**: MEDIUM
**Files**:
- `/WebContent/js/main.js` (line 21907)

**Details**:
The extension contains hardcoded credentials for a STOMP WebSocket message queue connection:

```javascript
n.stompClient = Stomp.client("wss://mq.focustodo.net:61615")
n.stompClient.connect("guest", "qwe!@#123", function(e) {
```

**Credential Details**:
- **Service**: STOMP WebSocket (ActiveMQ/RabbitMQ)
- **Endpoint**: `wss://mq.focustodo.net:61615`
- **Username**: `guest`
- **Password**: `qwe!@#123`
- **Purpose**: Real-time sync notifications (SYNC, UPDATE_USER_INFO, PURCHASE_SUCCESS, LOGOUT events)

**Verdict**: **LEGITIMATE BUT INSECURE**

This is a read-only guest credential for receiving push notifications about cross-device sync events. The message queue uses topic-based filtering with user-specific selectors (`uid='...' and clientId<>'...'`), limiting the damage from credential exposure. However, this remains a security anti-pattern that could allow unauthorized message injection or denial-of-service attacks.

**Impact**: Low - Credential exposure could allow attackers to connect to the message queue but appears limited to guest-level read access with user-specific filtering.

---

### 2. Embedded PayPal Client ID
**Severity**: LOW
**Files**:
- `/WebContent/js/main.js` (line 85971)
- `/WebContent/purchase.html`

**Details**:
```javascript
url: "https://www.paypal.com/sdk/js?client-id=AQUunfB4uV358EOeJcCtjn3JosWTgpCRanqfmuMgr4O3VQcqcvYGYfVsko1wBQBrwRJQBKntYFRp0BBQ"
```

**Verdict**: **FALSE POSITIVE**

This is a PayPal public client ID, which is intended to be embedded in client-side code for payment processing. This is standard practice and does not represent a security vulnerability. PayPal's SDK architecture requires public client IDs for browser-based checkout flows.

---

### 3. User Authentication and Password Handling
**Severity**: LOW
**Files**:
- `/WebContent/js/main.js` (lines 9540-9950)

**Details**:
The extension transmits user credentials for registration/login:

```javascript
// Registration endpoint
url: t.serverUrl + "v63/user/register"
data: {
  account: a,
  password: r,
  client: v.default.shared.name,
  expiredDate: p.default.shared.accountExpiredDate
}

// Login endpoint
url: t.serverUrl + "v63/user/login"
data: {
  account: a,
  password: r,
  client: v.default.shared.name
}
```

**Verdict**: **CLEAN**

All authentication requests use HTTPS (`https://www.focustodo.net/`), include `withCredentials: true` for cookie-based session management, and employ proper CORS configuration. Password reset functionality sends verification emails through server-side logic. No plaintext password storage detected in extension code.

---

## Data Collection & Privacy Analysis

### Sync Functionality
**Files**: `/WebContent/js/main.js` (line 17040-17090)

**Data Synchronized to Server**:
- **Productivity Data**: Pomodoro sessions, tasks, subtasks, schedules, projects
- **User Account Info**: Account ID, PID, UID, username, avatar
- **Configuration Data**: Daily goals, timer settings, user preferences
- **Premium Status**: Account expiration dates, purchase receipts

**Endpoint**: `POST https://www.focustodo.net/v64/sync`

**Verdict**: **LEGITIMATE BUSINESS FUNCTIONALITY**

The extension syncs productivity data to enable cross-device functionality (iOS, Android, Windows, Mac apps mentioned in code). All sync operations:
- Require user authentication (cookies: ACCT, PID, UID, JSESSIONID)
- Use HTTPS with `withCredentials: true`
- Are explicitly part of the app's value proposition (cloud sync)
- Do NOT access browsing history, cookies, or other browser data outside the extension

**Data Types Collected**:
1. **Tasks/Projects**: User-created todo items, project names, deadlines
2. **Pomodoro Sessions**: Work session timestamps, durations, completion status
3. **User Preferences**: Timer settings, notification preferences, UI configuration
4. **Account Info**: Email/username, premium subscription status, avatar image

This is **standard SaaS behavior** for a productivity app with cloud sync.

---

## Permissions Analysis

### Declared Permissions (manifest.json)
```json
"permissions": [
  "storage",           // Local data persistence
  "unlimitedStorage",  // For task/pomodoro history
  "notifications",     // Timer completion alerts
  "system.display"     // Window positioning
]
```

**Verdict**: **MINIMAL & APPROPRIATE**

All permissions are justified:
- **storage/unlimitedStorage**: Required for local IndexedDB task/pomodoro databases
- **notifications**: Timer completion alerts (legitimate UX feature)
- **system.display**: Used for centering popup window on user's screen

**No Dangerous Permissions**:
- ✅ No `webRequest` (cannot intercept network traffic)
- ✅ No `cookies` (cannot steal session tokens from other sites)
- ✅ No `tabs` (cannot enumerate or monitor browser tabs)
- ✅ No `management` (cannot kill other extensions)
- ✅ No `host_permissions` (cannot access web page content)

---

## Code Architecture Analysis

### Background Script (`background.js`)
**Lines**: 99 total

**Functionality**:
1. Window management (create/focus popup window)
2. Notification click handling (focus app on notification interaction)
3. Badge text management (display timer countdown on extension icon)
4. Local storage for window ID persistence

**Verdict**: **CLEAN** - Only standard window/notification management, no network requests.

---

### Main Application (`WebContent/js/main.js`)
**Lines**: 93,536 total (bundled with React, jQuery, Moment.js, Redux, etc.)

**Major Components**:
1. **Libraries**: React 16.x, Redux, jQuery 3.x, Moment.js, React-DnD, Bootstrap Datepicker
2. **User Authentication**: Login/register/password reset flows
3. **Data Models**: Tasks, Pomodoros, Projects, Subtasks, Schedules (IndexedDB storage)
4. **Sync Engine**: Bi-directional data sync with `focustodo.net` API
5. **Payment Integration**: PayPal SDK for premium subscriptions
6. **WebSocket Client**: STOMP protocol for real-time sync notifications
7. **Audio Engine**: Timer sounds using Web Audio API (`fetch('./audio/')`)

**Network Endpoints**:
- **Primary API**: `https://www.focustodo.net/`
- **Backup API**: `https://app.hk1.focustodo.net/`
- **Message Queue**: `wss://mq.focustodo.net:61615`
- **Purchase API**: `v63/purchase/paypal-transaction`

**Verdict**: **CLEAN** - Standard SaaS application architecture with legitimate cloud sync.

---

### Other Files
- **`purchase.js`** (5,911 lines): PayPal checkout UI with jQuery/Buffer libraries
- **`resetpassword.js`** (4,959 lines): Password reset form with jQuery
- **`index.html`**: Minimal bootstrap HTML loading `main.js`

---

## API Endpoint Summary

| Endpoint | Method | Purpose | Data Sent | Risk |
|----------|--------|---------|-----------|------|
| `v63/user/register` | POST | User registration | account, password, client | LOW - HTTPS only |
| `v63/user/login` | POST | User authentication | account, password, client | LOW - HTTPS only |
| `v63/user` (update) | POST | Update username/password | acct, name, pid, uid | LOW - Auth required |
| `v60/user/expired-date` | GET/POST | Check/upload premium status | acct, receipt (encrypted) | LOW - Auth required |
| `v64/sync` | POST | Sync productivity data | projects, tasks, pomodoros, schedules | LOW - Core feature |
| `v64/user/config` | POST | Sync user preferences | dailyGoals, settings | LOW - Auth required |
| `v63/purchase/paypal-transaction` | GET | Create PayPal order | productId, acct | LOW - Payment flow |
| `v65/access` | GET | Server health check | none | LOW - Ping only |
| `wss://mq.focustodo.net:61615` | WebSocket | Real-time sync notifications | STOMP subscribe with UID filter | MEDIUM - Hardcoded creds |

**All API calls use**:
- ✅ HTTPS/WSS encryption
- ✅ `withCredentials: true` for session cookies
- ✅ CORS with `crossDomain: true`
- ✅ Timeout limits (300s = 5 minutes)

---

## False Positives

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| `password:` keys in data objects | Multiple locations | Legitimate authentication parameters sent to own API |
| `withCredentials: true` | All AJAX calls | Standard CORS configuration for cookie-based auth |
| PayPal Client ID | `main.js:85971` | Public client ID (not a secret) for payment processing |
| `fetch('./audio/')` | Audio engine | Loading local audio files from extension package |
| `JSEncrypt` library | Receipt encryption | Encrypting purchase receipts with server's public key (RSA) |
| STOMP WebSocket | `main.js:21907` | Real-time push notification system (not data exfil) |
| `eval`/`innerHTML` | jQuery/React internals | Standard library operations within bundled code |

---

## Comparison to Known Malware Patterns

### ❌ NOT PRESENT:
- **Extension Enumeration**: No `chrome.management` calls
- **Extension Killing**: No `chrome.management.setEnabled(false)` patterns
- **XHR/Fetch Hooking**: No `XMLHttpRequest.prototype.send` or `window.fetch` patching
- **Content Scripts**: Zero content scripts injected into web pages
- **Cookie Harvesting**: No `chrome.cookies` API usage
- **Tab Monitoring**: No `chrome.tabs` queries or event listeners
- **Ad Injection**: No DOM manipulation of external pages
- **Residential Proxy**: No proxy configuration or traffic routing
- **Market Intelligence SDKs**: No Sensor Tower Pathmatics or similar SDKs
- **AI Conversation Scraping**: No targeting of ChatGPT/Claude/Gemini pages
- **Remote Config/Kill Switch**: Config from API but benign (timer settings, not behavior control)
- **Obfuscated Code**: Code is webpack-bundled but not intentionally obfuscated

---

## Privacy Considerations

**Data Stays Within Extension Ecosystem**:
- The extension operates as an isolated popup window
- NO interaction with web pages user visits
- NO access to browsing history, cookies, or form data from other sites
- Data collection limited to user's own task/timer data within the app

**Third-Party Integrations**:
1. **PayPal**: Standard payment processor for premium subscriptions
2. **FocusTodo Servers**: First-party API for cloud sync (not third-party data broker)

**User Transparency**:
- Extension description clearly states it's a Pomodoro timer/to-do list
- Cloud sync functionality is core advertised feature
- No hidden data collection beyond stated productivity tracking

---

## Code Quality Observations

### ✅ Good Practices:
- Manifest V3 compliance (modern security model)
- Minimal permissions for stated functionality
- HTTPS-only API communication
- Proper error handling in AJAX calls
- Session timeout management
- Multiple server fallback for reliability

### ⚠️ Areas for Improvement:
1. **Hardcoded Credentials**: STOMP password should be rotated and secured
2. **Code Bundling**: 93K line minified bundle makes auditing difficult
3. **Comments in Chinese**: Some code comments in Chinese (lines 12, 36, 62 in background.js)
4. **Error Swallowing**: Many `error: function() {}` empty handlers
5. **Timeout Length**: 5-minute timeout on sync requests is excessive

---

## Data Flow Summary

```
┌─────────────────────────────────────────────────────────────┐
│ USER ACTIONS (within popup window)                          │
│  - Create tasks/projects                                    │
│  - Run pomodoro timers                                      │
│  - Update settings                                          │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ LOCAL STORAGE (IndexedDB)                                   │
│  - Tasks, Pomodoros, Projects, Schedules                    │
│  - User preferences, timer state                            │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ SYNC ENGINE (when user logged in)                           │
│  POST https://www.focustodo.net/v64/sync                    │
│  - Uploads unsync'd data (tasks/pomodoros/projects)         │
│  - Downloads server-side changes                            │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ REAL-TIME NOTIFICATIONS (WebSocket)                         │
│  wss://mq.focustodo.net:61615                               │
│  - Receives push notifications for:                         │
│    • SYNC: Trigger sync when other device makes changes     │
│    • UPDATE_USER_INFO: Avatar/username changed              │
│    • PURCHASE_SUCCESS: Premium upgrade completed            │
│    • LOGOUT: Remote logout from another device              │
└─────────────────────────────────────────────────────────────┘
```

**No data leaves the FocusTodo ecosystem** - extension does not communicate with any third-party analytics, advertising, or data broker services (except PayPal for payments).

---

## Overall Risk Assessment

### Risk Level: **LOW**

**Justification**:
1. **No Web Page Access**: Extension cannot read or modify user's browsing activity
2. **Minimal Permissions**: Only 4 permissions, all justified and non-invasive
3. **Transparent Functionality**: Operates as advertised (timer + cloud sync)
4. **No Malware Patterns**: Zero presence of extension killing, XHR hooking, ad injection, or data exfiltration
5. **First-Party API**: All data sent to developer's own servers, not third-party brokers
6. **HTTPS/WSS Only**: All network traffic encrypted

**Primary Concern**:
- Hardcoded STOMP credentials (Medium severity) - Could allow unauthorized access to message queue

**Secondary Concerns**:
- Large bundled codebase makes comprehensive audit challenging
- Empty error handlers hide potential issues

---

## Recommendations

### For Users:
- ✅ **SAFE TO USE** - Extension operates as advertised with no malicious behavior
- Consider logging in only if you need cross-device sync (offline mode available)
- Premium features use legitimate PayPal processing (no payment data stored in extension)

### For Developers:
1. **Rotate STOMP Credentials**: Use per-user auth tokens instead of shared guest password
2. **Implement Proper Error Logging**: Replace empty error handlers with proper logging
3. **Code Splitting**: Break up 93K line main.js for better maintainability and auditing
4. **Security Audit**: Consider third-party penetration testing of STOMP/API infrastructure
5. **Rate Limiting**: Implement API rate limits to prevent abuse if credentials leak

---

## Conclusion

**Focus To-Do is CLEAN**. This is a legitimate productivity application that collects only the data necessary for its core functionality (Pomodoro tracking + task management with optional cloud sync). The extension poses minimal security risk to users and does not exhibit any of the malicious patterns found in VPN malware, market intelligence SDKs, or other predatory extensions.

The hardcoded STOMP credential represents a **security anti-pattern** but not active malware. The risk is limited by topic-based filtering and appears to provide read-only guest access for push notifications.

**Final Verdict**: **CLEAN** (with minor security hygiene concerns)
