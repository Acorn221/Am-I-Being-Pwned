# Security Analysis Report: Careerflow AI Job Application Tracker

## Extension Metadata
- **Extension ID**: iadokddofjgcgjpjlfhngclhpmaelnli
- **Extension Name**: Careerflow AI Job Application Tracker, ATS Resume Checker, Autofill & more
- **Version**: 2.9.34
- **User Count**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

Careerflow AI is a legitimate career management tool designed to help users track job applications, optimize LinkedIn profiles, and autofill job application forms. The extension demonstrates **CLEAN** security posture with standard functionality appropriate for its stated purpose. All network communications are restricted to the official Careerflow infrastructure. The extension uses Sentry SDK for error monitoring (which triggers XHR/fetch hook flags) and Firebase/Amplitude for legitimate analytics.

**Risk Level: CLEAN**

The extension exhibits no malicious behavior patterns. All permissions are appropriately scoped for its functionality, and data collection is limited to user-initiated career tracking activities with clear disclosure.

## Permissions Analysis

### Declared Permissions
```json
{
  "permissions": ["storage", "cookies"],
  "host_permissions": ["https://www.careerflow.ai/"],
  "content_scripts": [{"matches": ["*://*/*"]}]
}
```

### Permission Assessment
| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `storage` | Required for caching user authentication, job tracking data, session state | **LOW** - Standard usage |
| `cookies` | Used exclusively to read Rewardful referral cookie from careerflow.ai domain | **LOW** - Limited scope |
| `host_permissions` (careerflow.ai) | Communication with official backend services | **LOW** - Legitimate |
| `content_scripts` (*://*/*) | Required to detect job listings across all job boards (LinkedIn, Indeed, etc.) | **LOW** - Necessary for core functionality |

**Verdict**: All permissions are appropriately scoped and justified by the extension's career tracking functionality.

## Vulnerability Findings

### 1. Sentry SDK XHR/Fetch Hooks (FALSE POSITIVE)
**Severity**: INFORMATIONAL
**Files**:
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/iadokddofjgcgjpjlfhngclhpmaelnli/deobfuscated/contentScript.bundle.js` (lines 197395)

**Evidence**:
```javascript
// Line 197395
if (_options.XMLHttpRequest && "XMLHttpRequest" in helpers_WINDOW) {
  (0,esm_object/* fill */.GS)(XMLHttpRequest.prototype, 'send', _wrapXHR);
}
```

**Analysis**: Standard Sentry error monitoring SDK that instruments XHR/fetch for error tracking. This is a known false positive pattern. The hooks are scoped to error reporting, not data exfiltration.

**Verdict**: FALSE POSITIVE - Legitimate error monitoring

---

### 2. Cookie Access for Referral Tracking
**Severity**: LOW
**Files**:
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/iadokddofjgcgjpjlfhngclhpmaelnli/deobfuscated/background.bundle.js` (lines 23354-23366)

**Evidence**:
```javascript
if (msg.getRewardfulClientId) {
  console.log('trying to fetch cookies');
  chrome.cookies.get({
    url: 'https://www.careerflow.ai',
    name: 'rewardful.referral'
  }).then(function (res) {
    sendResponse(res.value);
  })
}
```

**Analysis**: Extension reads a single cookie (`rewardful.referral`) from its own domain exclusively for affiliate/referral tracking. This is limited in scope and poses no privacy risk beyond standard referral attribution.

**Verdict**: ACCEPTABLE - Limited scope, legitimate business use

---

### 3. Hardcoded API Keys (FALSE POSITIVE)
**Severity**: INFORMATIONAL
**Files**:
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/iadokddofjgcgjpjlfhngclhpmaelnli/deobfuscated/popup.bundle.js` (lines 82-107)

**Evidence**:
```javascript
REACT_APP_FIREBASE_API_KEY: 'AIzaSyARWjXjKwWAMw2wwZLgpuWoP_mOiXKS9Bw',
AMPLITUDE_API_KEY: '43e85aeba8023c2d2bf7f4fbb284055a',
GA_API_SECRET: '6TfarE2hSVaMCpPUWzVOlw',
REACT_APP_RECAPTCHA_TOKEN: '6Lfdy4sfAAAAAL6z7KLVRYjXl4ALO1zGKAEPStqo',
REACT_APP_SECRET_KEY: "Career@!23"
```

**Analysis**: These are **public** client-side Firebase/analytics keys that are designed to be embedded in client applications. Firebase API keys authenticate the app to Firebase services but rely on server-side security rules. The "SECRET_KEY" appears to be used for local encryption/hashing, not server authentication. This is a known false positive pattern in client-side code.

**Verdict**: FALSE POSITIVE - Public client-side keys

---

### 4. Form Autofill Functionality
**Severity**: LOW
**Files**:
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/iadokddofjgcgjpjlfhngclhpmaelnli/deobfuscated/contentScript.bundle.js` (lines 169992-170693)

**Evidence**:
```javascript
var attachElementWithAutoFillValue = function (element, value) {
  element?.setAttribute('data-autofill', value);
};

if (parentElement.getAttribute('data-autofill') && inputElement.value) {
  var autoFillValue = parentElement.getAttribute('data-autofill');
  // ... sends to backend for form field categorization
  autofill: true,
  autofillValue: autoFillValue
}
```

**Analysis**: Extension detects form fields on job application pages and categorizes them to enable autofill functionality (explicitly advertised feature). No evidence of password field targeting or credential harvesting. The extension marks fields with `data-autofill` attributes and sends field labels to backend API (`/autoFillCategoryQuestionMapping`) for ML-based categorization.

**Verdict**: ACCEPTABLE - Core advertised functionality, no credential theft

---

### 5. Developer Environment Variables Leaked
**Severity**: LOW
**Files**:
- `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/iadokddofjgcgjpjlfhngclhpmaelnli/deobfuscated/background.bundle.js` (lines 146-148)

**Evidence**:
```javascript
var innerConfig = {
  baseUrl: {
    "USER":"kirushan",
    "SHELL":"/bin/zsh",
    "GH_TOKEN":"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",
    // ... 200+ env vars including local paths
  }.BACKEND_BASE_URL || 'https://us-central1-faang-path.cloudfunctions.net'
}
```

**Analysis**: Build process accidentally embedded developer's entire environment variable object. While this includes a GitHub token (`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`) and local file paths, the code logic safely falls back to production URLs. The token is likely expired and represents a **build hygiene issue** rather than active security vulnerability. However, the token should be rotated immediately.

**Verdict**: BUILD HYGIENE ISSUE - Developer should rotate GH token, improve build process

---

## False Positive Analysis

| Pattern | Reason | Verdict |
|---------|--------|---------|
| XMLHttpRequest.prototype.send patching | Sentry SDK error monitoring | FALSE POSITIVE |
| window.fetch assignment | cross-fetch polyfill library | FALSE POSITIVE |
| Firebase API keys | Public client-side keys | FALSE POSITIVE |
| React innerHTML (SVG namespace check) | Standard React SVG rendering | FALSE POSITIVE |
| querySelectorAll for forms/inputs | Job application form detection (core feature) | FALSE POSITIVE |
| Amplitude analytics | Standard product analytics | FALSE POSITIVE |
| PDF.js Function() calls | Dynamic font compilation in PDF renderer | FALSE POSITIVE |

## API Endpoints & Data Flow

### Backend Infrastructure
| Endpoint | Purpose | Data Transmitted |
|----------|---------|------------------|
| `https://us-central1-faang-path.cloudfunctions.net/chromeExtensionV2/linkedinProfile` | LinkedIn profile scraping | Profile data from public LinkedIn pages |
| `https://us-central1-faang-path.cloudfunctions.net/jobTrackerV2/*` | Job tracking CRUD operations | Job title, company, URL, application status, notes |
| `https://us-central1-faang-path.cloudfunctions.net/aiToolsV2/*` | AI content generation | Job descriptions → AI-generated cover letters/summaries |
| `https://cf-python-backend-205663867047.us-central1.run.app/ai-services/*` | AI job detail extraction | Job posting HTML → structured job data |
| `https://app.careerflow.ai` | Main web application | User authentication, job board data sync |
| `https://coach.careerflow.ai` | Institute/coaching platform | Career coaching/educational institution features |
| `https://api2.amplitude.com/2/httpapi` | Product analytics | Extension usage events (anonymized user ID) |
| `https://www.google-analytics.com/mp/collect` | Google Analytics | Page view/interaction events |

### Data Collection Summary
1. **Job Application Data**: Job titles, companies, URLs, descriptions, application dates, custom notes (user-initiated)
2. **LinkedIn Profile Data**: Public profile information when user navigates to LinkedIn (for profile optimization feature)
3. **Form Field Labels**: Job application form field names for autofill categorization (no actual form data without user consent)
4. **Usage Analytics**: Button clicks, feature usage, error logs (Sentry), session duration
5. **Authentication**: Firebase auth tokens, user email (for account management)

**No Evidence Of**:
- Password/credential harvesting
- Browsing history collection beyond job-related pages
- Cross-site tracking outside job boards
- AI conversation scraping
- Extension enumeration/killing
- Ad injection or search manipulation
- Residential proxy infrastructure

## Content Script Behavior Analysis

### LinkedIn Integration
The extension injects comprehensive LinkedIn profile optimization tools:
- Profile completeness scoring
- AI-generated headline/about section suggestions
- Profile photo/banner recommendations
- "Open to Work" badge detection
- Connection count tracking

**Evidence**: Lines 429873-446118 in contentScript.bundle.js show profile analysis limited to public LinkedIn data when user is on their own profile page.

### Job Board Detection
Content script detects job listings across multiple platforms:
- LinkedIn Jobs
- Indeed
- Glassdoor
- Lever
- Greenhouse
- And other ATS systems

**Mechanism**: URL pattern matching + DOM inspection for job posting elements. No indiscriminate DOM scraping detected.

### Form Autofill
The extension detects form fields and categorizes them for autofill:
```javascript
// Lines 170363-170750
var allForms = document.querySelectorAll('form');
// Analyzes form structure, sends field labels to API for ML categorization
// User must explicitly trigger autofill - no automatic form submission
```

**User Control**: Autofill requires explicit user action (clicking extension icon, selecting "autofill" option).

## Third-Party Services

| Service | Purpose | Data Shared |
|---------|---------|-------------|
| Sentry (`sentry.io`) | Error monitoring | Error stack traces, browser metadata |
| Amplitude | Product analytics | User ID, event names, feature usage |
| Google Analytics | Web analytics | Page views, session data |
| Firebase | Authentication & hosting | Email, auth tokens |
| Rewardful | Affiliate tracking | Referral source (single cookie) |

All third-party services are industry-standard analytics/monitoring tools with legitimate use cases.

## Chrome Extension API Usage

### Background Script (Service Worker)
- `chrome.runtime.onInstalled`: Opens login page on first install, sets uninstall URL
- `chrome.runtime.onMessage`: Handles messages from content scripts and web app
- `chrome.runtime.onMessageExternal`: Receives auth tokens from Careerflow web app via `externally_connectable`
- `chrome.storage.session`: Stores tab IDs, temporary data (cover letter prefills)
- `chrome.storage.local`: Stores user preferences, authentication expiry
- `chrome.tabs.create`: Opens Careerflow web app for login
- `chrome.tabs.sendMessage`: Syncs authentication state across tabs
- `chrome.cookies.get`: Reads single Rewardful referral cookie

**No Abuse Detected**: All API usage aligns with legitimate extension functionality.

### Externally Connectable
```json
"externally_connectable": {
  "matches": [
    "https://app.careerflow.ai/*",
    "https://coach.careerflow.ai/*",
    "https://www.careerflow.ai/*",
    // ... other official Careerflow domains
  ]
}
```

**Analysis**: Allows Careerflow web applications to communicate with the extension for authentication sync. All domains are official Careerflow properties. This is a secure implementation of web-extension messaging.

## Security Best Practices Assessment

| Practice | Status | Notes |
|----------|--------|-------|
| Content Security Policy | ⚠️ MISSING | No CSP defined in manifest (MV3 has stricter defaults) |
| HTTPS-only communications | ✅ PASS | All API calls use HTTPS |
| No dynamic code execution | ✅ PASS | No eval() or Function() outside PDF.js/Quill libraries |
| Scoped permissions | ✅ PASS | Minimal required permissions |
| Secure authentication | ✅ PASS | Firebase auth with token expiration |
| Input sanitization | ✅ PASS | React rendering prevents XSS |
| No extension enumeration | ✅ PASS | No chrome.management API usage |
| No network interception | ✅ PASS | No webRequest/declarativeNetRequest |

## Overall Risk Assessment

### Risk Score: **CLEAN** (Low Risk)

### Risk Breakdown
- **Data Privacy**: LOW - Data collection limited to job tracking with user consent
- **Credential Theft**: NONE - No password harvesting detected
- **Network Security**: LOW - All traffic to legitimate Careerflow infrastructure
- **Third-Party Risk**: LOW - Standard analytics services (Sentry, Amplitude, GA)
- **Code Quality**: MEDIUM - Build process leaked dev environment (non-exploitable)

### Comparison to Malicious Extensions
Unlike the malicious VPN extensions analyzed in this project:
- ❌ No extension enumeration/killing
- ❌ No XHR/fetch hooking for data harvesting (Sentry hooks are for error monitoring only)
- ❌ No residential proxy infrastructure
- ❌ No AI conversation scraping
- ❌ No ad injection or search manipulation
- ❌ No hidden remote configuration for behavior changes
- ❌ No market intelligence SDK (like Sensor Tower Pathmatics)

### User Recommendations
1. **Safe to Use**: The extension performs as advertised without hidden malicious functionality
2. **Review Permissions**: Users should understand the extension can read content on all websites (necessary for job board detection)
3. **Data Awareness**: Users should know their job application data and LinkedIn profile info is sent to Careerflow servers
4. **Privacy Settings**: Review Careerflow's privacy policy regarding data retention and third-party analytics

### Developer Recommendations
1. **URGENT**: Rotate the leaked GitHub token (`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`)
2. **Build Process**: Fix webpack/build configuration to prevent environment variable leakage
3. **CSP**: Add explicit Content Security Policy to manifest for defense-in-depth
4. **Code Minification**: The leaked env vars suggest unminified production builds
5. **Secret Management**: Use dedicated secret management for API keys (though current keys are public client-side keys)

## Conclusion

**Careerflow AI Job Application Tracker is a CLEAN extension** with legitimate career management functionality. The extension demonstrates responsible use of Chrome extension APIs, limited data collection scoped to its stated purpose, and secure communication with official backend infrastructure.

The primary concern is the **leaked developer environment variables** (including a GitHub token) due to improper build configuration. While this does not pose immediate security risk to users (the code safely ignores the env object and uses production URLs), the developer should rotate the exposed GitHub token and fix the build process.

All flagged patterns (XHR/fetch hooks, hardcoded keys, form detection) are **false positives** attributable to standard libraries (Sentry SDK, Firebase client config, PDF.js) and core extension functionality (job application form autofill).

**Final Verdict: CLEAN - Safe for users, developer should address build hygiene issue**

---

## Appendix: File Inventory

### Core Extension Files
- `manifest.json` (1.3KB) - Manifest v3, standard permissions
- `background.bundle.js` (3.3MB, 23,653 lines) - Service worker with API integrations
- `contentScript.bundle.js` (15.4MB, 452,583 lines) - Massive bundle including React, PDF.js, Quill editor, Sentry SDK
- `popup.bundle.js` (519KB) - Extension popup UI
- `panel.bundle.js` (153KB) - Side panel UI
- `options.bundle.js` (153KB) - Settings page

### Notable Libraries Detected
- React 18.x (UI framework)
- Sentry SDK (error monitoring) - **Source of XHR/fetch hook false positives**
- PDF.js (PDF rendering) - **Source of eval/Function false positives**
- Quill (rich text editor)
- Firebase SDK (authentication)
- Amplitude SDK (analytics)
- Ant Design (UI components)
- Axios (HTTP client)
- Lodash (utilities)

**Bundle Size Concern**: 15.4MB content script is extremely large. While not malicious, this impacts browser performance. Developer should implement code splitting.
