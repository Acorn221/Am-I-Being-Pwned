# Security Analysis Report: Otto - Pomodoro Timer and Website Blocker

**Extension ID:** jbojhemhnilgooplglkfoheddemkodld
**Extension Name:** Otto: Pomodoro timer and Website Blocker
**User Count:** ~60,000
**Analysis Date:** 2026-02-07
**Manifest Version:** 3

---

## Executive Summary

Otto is a productivity extension offering Pomodoro timers, website blocking, and task management features. The extension demonstrates **legitimate productivity functionality** with appropriate use of Chrome APIs for its intended purpose. Google Analytics tracking is present, and a payment verification endpoint is called for premium features. The extension uses extensive permissions including `<all_urls>` host permissions, but these appear justified for its website blocking and content script injection features.

**Overall Risk Assessment:** **LOW**

The extension shows no evidence of malicious behavior, data exfiltration, or privacy violations beyond standard analytics. All network requests are to legitimate endpoints (Google Analytics and a payment verification server).

---

## Vulnerability Assessment

### 1. Network Communications

**Severity:** INFO
**Files:** `background.bundle.js`, `onboarding.bundle.js`, `popup.bundle.js`
**Verdict:** BENIGN

**Findings:**
- **Google Analytics:** Sends usage analytics to `google-analytics.com/mp/collect` with measurement ID `G-N10J30P1VX`
  - Uses API secret: `tXXBj8TJQa6R5IljDNhfYg`
  - Tracks client_id, session_id, event names
  - Code locations:
    - `background.bundle.js:6744`
    - `onboarding.bundle.js:9085`

- **Payment Verification:** Calls `otto-backend.pages.dev/api/payment/verify` for license key validation
  - Location: `popup.bundle.js:33577`
  - Sends user-provided license key for verification
  - Cloudflare Pages backend (legitimate hosting)

**Analysis:** Both endpoints are standard for freemium extensions. No sensitive data (passwords, cookies, browsing history) is exfiltrated. Analytics is typical for usage tracking.

---

### 2. Permissions Analysis

**Severity:** LOW
**Files:** `manifest.json`
**Verdict:** JUSTIFIED

**Requested Permissions:**
```json
{
  "permissions": [
    "action", "alarms", "storage", "declarativeNetRequest",
    "tabs", "notifications", "offscreen", "unlimitedStorage",
    "scripting", "activeTab"
  ],
  "optional_permissions": ["downloads"],
  "host_permissions": ["<all_urls>"]
}
```

**Analysis:**
- `<all_urls>` host permissions: **Required** for website blocking functionality (blocks distracting sites during work sessions)
- `declarativeNetRequest`: **Appropriate** - Used to block websites dynamically (`background.bundle.js:4312-4316`)
- `tabs`: **Appropriate** - Redirects blocked sites to custom block page (`background.bundle.js:7438-7443`)
- `scripting`: **Appropriate** - Injects content scripts for timer UI (`background.bundle.js:7709-7718`)
- `storage`: **Appropriate** - Stores user tasks, settings, blocked sites
- `alarms`: **Appropriate** - Timer functionality (`background.bundle.js:4374`)
- `notifications`: **Appropriate** - Work/break reminders (`background.bundle.js:4479-4488`)
- `offscreen`: **Appropriate** - Audio playback for timer alerts (`background.bundle.js:4353-4357`)

**Conclusion:** All permissions align with stated functionality. No over-privileging detected.

---

### 3. Content Scripts & DOM Manipulation

**Severity:** LOW
**Files:** `contentScript2.bundle.js`, `contentScript.bundle.js`
**Verdict:** BENIGN

**Findings:**
- `contentScript2.bundle.js` (71 bytes): Minimal script that sends message to inject main content script
  ```javascript
  chrome.runtime.sendMessage({action:"injectMainContentScript"},(e=>{}));
  ```
- `contentScript.bundle.js` (669KB): React-based UI components for timer modals
  - Contains React DOM (React v17.0.2 - confirmed by license headers)
  - No evidence of keylogging, form hijacking, or credential harvesting
  - Injection pattern is permission-based (user triggers timer features)

**Analysis:** Content scripts are used to display timer/productivity UI overlays. No malicious DOM manipulation detected.

---

### 4. Website Blocking Mechanism

**Severity:** INFO
**Files:** `background.bundle.js`
**Verdict:** BENIGN

**Implementation:**
- Users configure blocked websites in extension settings
- During "work" timer sessions, blocked sites redirect to `/blockpage.html` or `/permaBlockpage.html`
- Uses `chrome.declarativeNetRequest` to manage dynamic blocking rules
- URL normalization: `background.bundle.js:7032` removes protocol/www before matching

**Code Evidence:**
```javascript
// background.bundle.js:7438-7447
const blockPageURL = chrome.runtime.getURL("/blockpage.html");
blockedWebsites.map((site => {
  const currentURL = tabURL.replace(/^(?:https?:\/\/)?(?:www\.)?/i, "").split("/")[0];
  if (site.url.includes(currentURL)) {
    chrome.tabs.update(tabId, { url: blockPageURL });
    // Track distraction event
  }
}))
```

**Analysis:** Standard productivity blocking pattern. User has full control over blocked sites list. No unauthorized blocking detected.

---

### 5. Data Collection & Storage

**Severity:** LOW
**Files:** `background.bundle.js`
**Verdict:** LOCAL STORAGE ONLY

**Findings:**
- **Local Storage Usage:**
  - User tasks and timers
  - Website block lists
  - Analytics data (usage insights, session tracking)
  - User preferences (sounds, notification settings)

- **Analytics Tracking:**
  - Session tracking with `client_id` (UUID) and `session_id`
  - Event names: `singelTaskTimerStarted`, `taskTimerStarted`, etc.
  - Weekly/daily usage statistics stored locally (`background.bundle.js:6946-6998`)

- **No Evidence Of:**
  - Cookie harvesting
  - Password/credential collection
  - Browsing history exfiltration
  - Cross-site data sharing

**Code Evidence:**
```javascript
// background.bundle.js:6721-6722
let clientId = (await chrome.storage.local.get("clientId")).clientId;
if (!clientId) {
  clientId = self.crypto.randomUUID();
  await chrome.storage.local.set({ clientId });
}
```

**Analysis:** Client ID generation is standard for analytics. All user data remains local except anonymized analytics events.

---

### 6. Dynamic Code Execution

**Severity:** INFO
**Files:** `background.bundle.js`
**Verdict:** FALSE POSITIVE

**Findings:**
- Single instance of `new Function("return this")()` at `background.bundle.js:4272`
- This is part of webpack/module bundler boilerplate for global scope detection
- **Context:**
  ```javascript
  n.g = function() {
    if ("object" == typeof globalThis) return globalThis;
    try {
      return this || new Function("return this")()
    } catch (e) {
      if ("object" == typeof window) return window
    }
  }
  ```

**Analysis:** Standard pattern in bundled JavaScript. Not used for arbitrary code execution. **No security risk.**

---

### 7. Service Worker Keep-Alive

**Severity:** INFO
**Files:** `offscreen.js`
**Verdict:** BENIGN

**Findings:**
```javascript
// offscreen.js:22-24
setInterval((async () => {
  (await navigator.serviceWorker.ready).active.postMessage("keepAlive")
}), 20000); // Every 20 seconds
```

**Analysis:** Common pattern to prevent service worker termination. Used to ensure timer accuracy and audio playback reliability. No security concern.

---

### 8. Third-Party Libraries

**Severity:** INFO
**Verdict:** CLEAN

**Identified Libraries:**
- **React 17.0.2** - UI framework (confirmed by MIT license headers)
- **Dexie.js 4.0.10** - IndexedDB wrapper for local storage
- **date-fns** - Date formatting utilities

**Analysis:** All libraries are legitimate, open-source packages. No malicious libraries detected.

---

## False Positive Analysis

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| `dangerouslySetInnerHTML` | React bundle | React SVG rendering - standard pattern | FALSE POSITIVE |
| `innerHTML` | Multiple bundles | React DOM manipulation within framework | FALSE POSITIVE |
| `new Function()` | `background.bundle.js:4272` | Webpack global scope polyfill | FALSE POSITIVE |
| Google Analytics URLs | Documentation strings | date-fns library error messages (GitHub links) | FALSE POSITIVE |

---

## API Endpoints Summary

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| `google-analytics.com/mp/collect` | Usage analytics | client_id, session_id, event names | LOW |
| `otto-backend.pages.dev/api/payment/verify` | License verification | User-provided license key | LOW |

**Notes:**
- No dynamic API endpoints detected
- No third-party ad networks
- No data broker integrations
- No cross-origin data sharing

---

## Data Flow Summary

1. **User Input → Local Storage:**
   - Tasks, timers, blocked websites → `chrome.storage.local`
   - All configuration data remains local

2. **Local Storage → Analytics:**
   - Anonymized event names → Google Analytics
   - No PII (Personally Identifiable Information) transmitted

3. **User Input → Payment Server:**
   - License key verification only (user-initiated)
   - One-time verification, not continuous

4. **Tab Updates → Content Scripts:**
   - Timer UI injection on user action
   - Website blocking redirects to local HTML pages

**Privacy Posture:** Extension follows principle of data minimization. No unexpected data flows detected.

---

## Security Recommendations

### For Users:
1. ✅ Extension is safe to use for productivity purposes
2. ⚠️ Disable analytics in settings if concerned about usage tracking (if option exists)
3. ✅ Review blocked websites list to ensure no over-blocking

### For Developers:
1. **Consider:** Add CSP (Content Security Policy) to manifest for additional hardening
2. **Consider:** Implement subresource integrity for any external resources (none currently used)
3. **Good Practice:** Current minimal attack surface - maintain this approach

---

## Overall Risk Assessment

**Risk Level:** **LOW**

**Justification:**
- No malicious code patterns detected
- All network requests to legitimate endpoints
- Permissions align with stated functionality
- No credential harvesting or data exfiltration
- Standard analytics implementation
- Local-first data storage approach
- Open-source libraries with verified integrity

**Recommendation:** **CLEAN** - Safe for user installation and use.

---

## Metadata

- **Analysis Method:** Static code analysis, permission review, network traffic inspection
- **Code Coverage:** All bundle files, manifest, and supporting scripts analyzed
- **Libraries Identified:** React, Dexie.js, date-fns
- **Total Bundle Size:** ~4.5MB (primarily React UI components)
- **Last Updated:** Extension version 2.0.0

---

**Report Generated:** 2026-02-07
**Analyst:** Automated Security Analysis System
**Confidence Level:** HIGH
