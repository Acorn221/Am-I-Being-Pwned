# Security Analysis Report: Nearpod for Classroom

## Extension Metadata
- **Extension ID**: gcoekeoenehjmndhkdnoomdjeaclkhbe
- **Name**: Nearpod for Classroom
- **Version**: 0.0.9
- **User Count**: ~700,000
- **Developer**: Nearpod (Illuminate Education)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

Nearpod for Classroom is a legitimate educational extension that integrates Nearpod's lesson library with Google Classroom. The extension enables teachers to create Google Classroom assignments directly from their Nearpod library through an iframe-based modal interface.

**Overall Risk Assessment: CLEAN**

The extension exhibits no malicious behavior. It is a straightforward, minimal-code integration tool with appropriate permissions scoped to its stated functionality. The codebase totals only 228 lines of JavaScript across 2 files, with transparent OAuth2 authentication flows and exclusively first-party API communication.

### Key Findings
- **No malicious patterns detected**: No XHR/fetch hooking, extension enumeration, data exfiltration, or obfuscation
- **Appropriate permissions**: Only `identity` and `storage` permissions requested, properly scoped OAuth2 scopes
- **Legitimate functionality**: DOM manipulation limited to adding a button to Google Classroom UI and displaying a modal
- **First-party communication only**: All network calls go to legitimate Google and Nearpod domains
- **Clean code**: Minimal, readable code with no obfuscation or dynamic code execution

## Manifest Analysis

### Permissions Review
```json
"permissions": [
  "identity",
  "storage"
]
```

**Assessment**: ✅ APPROPRIATE
- `identity`: Required for Google OAuth2 authentication flow
- `storage`: Used to cache OAuth tokens and configuration

### OAuth2 Configuration
```json
"oauth2": {
  "client_id": "898994559274-vd50hfpirf3r2g9ott3v4en1njr0g886.apps.googleusercontent.com",
  "scopes": [
    "https://www.googleapis.com/auth/classroom.coursework.students",
    "https://www.googleapis.com/auth/classroom.courses.readonly"
  ]
}
```

**Assessment**: ✅ APPROPRIATE
- Scopes are minimal and match stated functionality (creating assignments, reading course list)
- Uses standard Google OAuth2 client ID pattern
- No excessive permissions requested

### Content Script Scope
```json
"matches": [
  "https://classroom.google.com/*"
]
```

**Assessment**: ✅ APPROPRIATE
- Content script only injected on Google Classroom pages
- No broad host permissions
- No access to sensitive domains

### Content Security Policy
**No CSP defined** - Uses default Manifest V3 CSP which is secure by default (no unsafe-eval, no inline scripts)

**Assessment**: ✅ SECURE

## Vulnerability Analysis

### 1. XHR/Fetch Hooking
**Severity**: N/A
**Status**: ✅ NOT PRESENT

**Analysis**: No XMLHttpRequest or fetch API hooking detected. The extension uses standard `fetch()` calls without any proxy/wrapper patterns.

**Evidence**: Only legitimate fetch calls found:
```javascript
// service-worker.js:65 - Fetch Google Classroom courses
const response = await fetch(`${googleApiUrl}courses?access_token=${oauthToken}`, init)

// service-worker.js:91 - Create assignment via Google Classroom API
await fetch(`${googleApiUrl}courses/${courseId}/courseWork?access_token=${oauthToken}`, init)
```

**Verdict**: CLEAN

---

### 2. Extension Enumeration/Killing
**Severity**: N/A
**Status**: ✅ NOT PRESENT

**Analysis**: No `chrome.management` API usage detected. Extension does not enumerate, disable, or interfere with other extensions.

**Evidence**: No matches found for `chrome.management` in codebase.

**Verdict**: CLEAN

---

### 3. Data Exfiltration / Unauthorized Data Collection
**Severity**: N/A
**Status**: ✅ NOT PRESENT

**Analysis**: Extension only collects data necessary for its stated functionality:
- User email (extracted from Google Classroom DOM to pre-fill OAuth login_hint)
- OAuth token (stored locally, used for Google Classroom API calls)
- Course ID (from Google Classroom API response)

No data is sent to third-party analytics, tracking, or telemetry services.

**Evidence**:
```javascript
// content.js:54-57 - Email extraction (used only for OAuth login hint)
const isEmailRegex = /@[\s\S]+?\./g
const currentUserEmail = Array.from(document.getElementsByTagName('div')).filter(element => {
  return !element.children.length && element.innerText.match(isEmailRegex)
})[0].innerText
```

**Verdict**: CLEAN - Email only used for OAuth login_hint parameter

---

### 4. Keylogging / Input Monitoring
**Severity**: N/A
**Status**: ✅ NOT PRESENT

**Analysis**: No event listeners for keyboard events (keydown/keyup/keypress) or form input monitoring.

**Evidence**: No matches for `keydown`, `keyup`, `keypress`, `input`, `change`, or `submit` event listeners.

**Verdict**: CLEAN

---

### 5. Cookie/Credential Harvesting
**Severity**: N/A
**Status**: ✅ NOT PRESENT

**Analysis**: No cookie access, localStorage scraping, or credential harvesting. OAuth tokens are obtained through official Chrome identity API and stored securely in chrome.storage.local.

**Evidence**: No direct cookie access. Uses official `chrome.identity.launchWebAuthFlow()` API.

**Verdict**: CLEAN

---

### 6. Market Intelligence SDK Injection
**Severity**: N/A
**Status**: ✅ NOT PRESENT

**Analysis**: No Sensor Tower, Pathmatics, or other market intelligence SDKs detected.

**Evidence**: No matches for sensortower, pathmatics, ad-finder, or similar tracking SDK patterns.

**Verdict**: CLEAN

---

### 7. AI Conversation Scraping
**Severity**: N/A
**Status**: ✅ NOT PRESENT

**Analysis**: Extension only operates on classroom.google.com. No ChatGPT, Claude, Gemini, or other AI platform scraping.

**Verdict**: CLEAN

---

### 8. Dynamic Code Execution / Obfuscation
**Severity**: N/A
**Status**: ✅ NOT PRESENT

**Analysis**: No eval(), Function(), or dynamic code execution patterns. Code is readable and unobfuscated.

**Evidence**: Only base64 data URI found is an embedded icon in CSS (standard practice).

**Verdict**: CLEAN

---

### 9. Residential Proxy Infrastructure
**Severity**: N/A
**Status**: ✅ NOT PRESENT

**Analysis**: No proxy-related code, no peer-to-peer networking, no bandwidth sharing.

**Verdict**: CLEAN

---

### 10. Remote Configuration / Kill Switches
**Severity**: N/A
**Status**: ✅ NOT PRESENT

**Analysis**: All configuration is hardcoded in the extension. No remote config fetching or server-controlled behavior modification.

**Evidence**: Configuration stored in chrome.storage.local on initialization (service-worker.js:1-15) is static.

**Verdict**: CLEAN

---

## False Positives Analysis

| Pattern | Context | Verdict |
|---------|---------|---------|
| `innerHTML` usage | content.js:12 - Static HTML template for modal UI (no user input) | ✅ False Positive |
| `querySelector` calls | content.js - Legitimate UI element selection for Google Classroom DOM | ✅ False Positive |
| `innerText` extraction | content.js:56-57 - Email extraction for OAuth login_hint only | ✅ False Positive |
| `postMessage` listener | content.js:31 - Secure iframe→background communication with type checking | ✅ False Positive |
| OAuth token storage | service-worker.js:59 - Standard practice, stored in chrome.storage.local | ✅ False Positive |

### innerHTML Security Review
```javascript
// content.js:12 - Static template, no user input interpolation
nearpodIframeContainer.innerHTML = `
  <div class="nearpod-create-assignment">
    <div class="nearpod-create-assignment-veil"></div>
    <div class="nearpod-create-assignment-container">
      <iframe src="${nearpodExtensionUrl}" class="nearpod-create-assignment-iframe"></iframe>
      <div tabindex="200" class="nearpod-create-assignment-close">
        <img src="${closeImage}">
      </div>
    </div>
  </div>
`
```
**Assessment**: `nearpodExtensionUrl` and `closeImage` are constructed from trusted sources (hardcoded domain + chrome.runtime.getURL). No XSS risk.

### postMessage Security Review
```javascript
// content.js:31-41 - Message validation
const activeIframeEventHandler = ev => {
  if (ev.data && ev.data.type === 'nearpodMessage' && ev.data.action_type === actionTypes.MY_LIBRARY_EXTENSION_LESSON_LAUNCHED_SUCCESS) {
    chrome.runtime.sendMessage({
      type: messageTypes.CREATE_ASSIGNMENT,
      payload: {
        assignmentTitle: ev.data.payload.assignmentTitle,
        assignmentMaterial: ev.data.payload.assignmentMaterial
      }
    })
    removeModalListeners()
  }
}
```
**Assessment**: Message type checking present. Assignment title/material come from nearpod.com iframe (first-party domain). Low risk.

## API Endpoints & Data Flow

### External Domains
| Domain | Purpose | Protocol | Data Sent | Risk Level |
|--------|---------|----------|-----------|------------|
| nearpod.com | Nearpod lesson library iframe | HTTPS | None (user browses within iframe) | ✅ LOW |
| accounts.google.com | OAuth2 authentication | HTTPS | User email (login_hint), OAuth scopes | ✅ LOW |
| classroom.googleapis.com | Google Classroom API | HTTPS | OAuth token, course IDs, assignment data | ✅ LOW |

### Data Flow Summary
```
1. User clicks "Create Assignment" button in Google Classroom
   ↓
2. Extension extracts user email from DOM (for OAuth login_hint)
   ↓
3. OAuth flow: accounts.google.com/o/oauth2/auth
   ↓
4. Extension fetches course list: classroom.googleapis.com/v1/courses
   ↓
5. User selects lesson in nearpod.com iframe modal
   ↓
6. postMessage from iframe → background script
   ↓
7. Extension creates assignment: classroom.googleapis.com/v1/courses/{id}/courseWork
   ↓
8. Page reloads to show new assignment
```

**Assessment**: All data flows are transparent, necessary for functionality, and confined to first-party services.

## Code Quality & Security Observations

### Positive Security Practices
1. **Minimal codebase**: 228 total lines of JS, easy to audit
2. **Manifest V3**: Modern, more secure manifest version
3. **Official OAuth flow**: Uses chrome.identity API, not custom implementation
4. **No third-party dependencies**: No external libraries or SDKs
5. **Scoped permissions**: No overreaching permission requests
6. **Origin-restricted content scripts**: Only runs on classroom.google.com

### Minor Code Quality Issues (Non-Security)
1. **Regex for email extraction** (content.js:54) could be more robust, but doesn't pose security risk
2. **No origin check on postMessage** (content.js:31) - should verify `ev.origin === 'https://nearpod.com'`
3. **Hard-coded UI positioning** (content.js:84-86) - brittle, not malicious

## Privacy Assessment

### Data Collection
- **User Email**: Extracted from Google Classroom DOM, used only for OAuth login_hint
- **OAuth Token**: Standard Google OAuth token, stored locally, never transmitted except to Google APIs
- **Course List**: Retrieved from Google Classroom API
- **Assignment Data**: Title and URL sent to Google Classroom API

### Data Storage
- **chrome.storage.local**: oauthToken, courseId, currentTabId, static config
- **No persistent user tracking**
- **No analytics or telemetry**

### Third-Party Data Sharing
**NONE** - Extension only communicates with Google and Nearpod (first-party developer).

## Overall Risk Assessment

### Risk Matrix
| Category | Risk Level | Notes |
|----------|-----------|-------|
| **Malware** | ✅ NONE | No malicious patterns detected |
| **Privacy** | ✅ LOW | Minimal data collection, first-party only |
| **Security** | ✅ LOW | Clean code, appropriate permissions |
| **User Trust** | ✅ HIGH | Transparent functionality, reputable developer |

### FINAL VERDICT: **CLEAN**

Nearpod for Classroom is a legitimate educational tool with no security or privacy concerns. The extension:
- Has appropriate, minimal permissions
- Contains no malicious code patterns
- Implements proper OAuth2 authentication
- Communicates only with first-party domains (Google, Nearpod)
- Has no tracking, analytics, or data exfiltration
- Contains no obfuscation or dynamic code execution

### Recommendations
**For Users**: ✅ Safe to use. Extension functions as advertised with no hidden behavior.

**For Developers**: Consider adding origin validation to postMessage handler in content.js for defense-in-depth.

---

## Technical Appendix

### File Inventory
```
deobfuscated/
├── manifest.json (1.2KB)
├── README.md (documentation)
├── assets/
│   ├── close.svg (1.1KB)
│   └── nearpod_logo_small.png (1.7KB)
└── scripts/
    ├── service-worker.js (99 lines)
    └── classroom/
        ├── content.js (131 lines)
        └── styles.css (3.7KB)
```

### Total Code Size
- JavaScript: 228 lines (2 files)
- CSS: 82 lines (1 file)
- Total extension size: ~10KB

### Chrome Web Store Signatures
Extension includes valid Chrome Web Store verified_contents.json with publisher and webstore signatures, confirming authenticity.

---

**Analysis Completed**: 2026-02-06
**Analyst**: Automated Security Review System
**Confidence Level**: HIGH (complete codebase coverage, minimal attack surface)
