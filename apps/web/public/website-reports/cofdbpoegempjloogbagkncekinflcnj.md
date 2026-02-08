# Security Analysis Report: DeepL Translate and Write with AI

## Extension Metadata
- **Extension Name**: DeepL: translate and write with AI
- **Extension ID**: cofdbpoegempjloogbagkncekinflcnj
- **Version**: 1.72.0
- **User Count**: ~4,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

DeepL is a legitimate translation and writing assistance extension from DeepL SE, a well-established German translation service provider. The extension requests extensive permissions appropriate for its core functionality (translation, text improvement, screenshot OCR). Analysis reveals **legitimate use of sensitive permissions** for authentication and feature delivery, with proper integration of Sentry error tracking and Statsig A/B testing. While the extension has broad access capabilities, all observed behaviors align with its documented purpose as a professional translation tool.

**Overall Risk Level**: **CLEAN**

The extension is invasive by necessity (translation requires content access, authentication requires cookies), but demonstrates responsible data handling practices consistent with DeepL's privacy policy and business model as a professional translation service.

## Vulnerability Analysis

### 1. Cookie Access - CLEAN (Authentication Purpose)

**Severity**: INFORMATIONAL
**Files**: `background.js`
**Permission**: `cookies` in manifest

**Finding**:
The extension uses `chrome.cookies.get()` and `chrome.cookies.getAll()` to access DeepL-specific cookies from `deepl.com` domain:

```javascript
// Authentication session validation
const e = yield chrome.cookies.getAll({domain:"deepl.com",name:"dl_session"});

// User ID tracking for DeepL account
const e = yield chrome.cookies.get({name:"dapUid",url:"https://www.deepl.com"});

// Experiment overrides for A/B testing
const e = yield chrome.cookies.get({name:"dl_experiment_override",url:"https://www.deepl.com"});

// Release group feature flagging
const e = yield chrome.cookies.getAll({domain:"deepl.com",name:"releaseGroups"});

// Test environment detection
const e = yield chrome.cookies.getAll({domain:"deepl.com",name:"dl_brex_playwright_env"});
```

**Verdict**: **LEGITIMATE**. Cookie access is strictly scoped to `deepl.com` domain for:
- User authentication (Pro account login)
- A/B test variant assignment
- Feature flag delivery
- Test environment detection

No evidence of cross-domain cookie theft or credential harvesting. Cookies are only read from DeepL's own infrastructure.

---

### 2. Content Script Injection - CLEAN (Translation Functionality)

**Severity**: INFORMATIONAL
**Files**: `build/content.js` (1.1MB), `manifest.json`
**Permission**: `<all_urls>` content script match pattern

**Finding**:
Content script runs on all pages (`<all_urls>`) at `document_idle` to enable text selection and translation:

```json
"content_scripts": [{
  "matches": ["<all_urls>"],
  "css": ["build/content.css"],
  "js": ["build/content.js"],
  "run_at": "document_idle",
  "all_frames": false
}]
```

The content script accesses:
- `window.getSelection()` (2 occurrences) - for text selection detection
- DOM manipulation for translation overlay UI
- PostMessage communication with background script

**Verdict**: **LEGITIMATE**. All-URLs access is required for a translation extension to:
- Detect selected text on any webpage
- Inject translation overlays
- Provide context menu translation

No evidence of:
- Keylogging or input field monitoring
- Password/credit card harvesting
- Ad injection or DOM manipulation beyond translation UI
- Third-party SDK injection

---

### 3. Third-Party Services Integration - CLEAN (Standard Tooling)

**Severity**: INFORMATIONAL
**Files**: `background.js`, `build/content.js`
**Endpoints Identified**:

**Sentry (Error Tracking)**:
```
https://0d368beeb4bc3e66f983b2c83eb342dc@o4509354486530048.ingest.de.sentry.io/4509882758201424
```
- 107 references in code
- Standard Sentry SDK integration for crash reporting
- XMLHttpRequest.prototype instrumentation for error breadcrumbs (standard Sentry behavior)

**Statsig (A/B Testing)**:
```
https://api.statsigcdn.com/v1
https://statsigapi.net/v1/sdk_exception
https://prodregistryv2.org/v1
https://featureassets.org/v1
```
- 28 references in code
- Feature flag and experimentation platform
- Used for controlled feature rollouts

**DeepL Experimentation**:
```
https://experimentation.deepl.com/experiments
```
- Internal A/B testing infrastructure

**Qualtrics Surveys**:
```
https://deepl.qualtrics.com/jfe/form/SV_5hVyvZAQlQOL5RQ
https://deepl.qualtrics.com/jfe/form/SV_eJxAD8c7J5hqSRU
```
- User feedback survey platform

**Verdict**: **LEGITIMATE**. All third-party services are standard enterprise tools:
- Sentry is the industry-standard error tracking service
- Statsig is a reputable A/B testing platform
- Qualtrics is a professional survey platform
- No market intelligence SDKs (Sensor Tower, Pathmatics) detected

The XMLHttpRequest.prototype instrumentation is **Sentry's standard breadcrumb tracking** for debugging, not malicious XHR hooking.

---

### 4. Permissions Analysis - CLEAN (Justified by Functionality)

**Declared Permissions**:
```json
[
  "activeTab",        // Translate current page content
  "storage",          // Save user preferences
  "contextMenus",     // Right-click translation menu
  "tabs",             // Manage translation tabs
  "scripting",        // Inject translation overlays
  "declarativeNetRequest",  // Modify referer header (see below)
  "identity",         // OAuth login flow
  "tts",              // Text-to-speech for translations
  "alarms",           // Periodic sync/cleanup
  "webRequest",       // Monitor network requests
  "cookies",          // DeepL account authentication
  "sidePanel"         // Chrome side panel UI
]
```

**Host Permissions**:
```json
[
  "*://*.deepl.com/*",
  "https://api-test.deepl.com/v1/*",
  "https://api.deepl.com/v1/*"
]
```

**Declarative Net Request Rule**:
```json
{
  "action": {
    "type": "modifyHeaders",
    "requestHeaders": [{
      "header": "referer",
      "operation": "set",
      "value": "https://www.deepl.com/"
    }]
  },
  "condition": {
    "excludedDomains": ["deepl.com"],
    "urlFilter": "*://*.deepl.com/jsonrpc?client=chrome-extension,*",
    "resourceTypes": ["xmlhttprequest"]
  }
}
```

**Verdict**: **LEGITIMATE**. The referer header modification is scoped to DeepL's own API endpoints and likely required for CORS/authentication. All permissions have clear justification:
- Translation requires content script injection (`scripting`, `activeTab`)
- Pro account features require authentication (`cookies`, `identity`)
- TTS for pronunciation assistance (`tts`)
- Side panel for persistent translation interface (`sidePanel`)

---

### 5. Chrome API Usage - CLEAN (No Malicious Patterns)

**Detected Chrome APIs**:
```
chrome.action           - Extension toolbar icon
chrome.alarms           - Periodic background tasks
chrome.commands         - Keyboard shortcuts (Ctrl+Shift+Y)
chrome.contextMenus     - Right-click translation
chrome.cookies          - DeepL session management
chrome.declarativeNetRequest - Referer header modification
chrome.identity         - OAuth authentication
chrome.management       - getSelf() only (version checking)
chrome.runtime          - Message passing
chrome.scripting        - Content script injection
chrome.sidePanel        - Side panel UI
chrome.storage          - Local preferences
chrome.tabs             - Tab management
chrome.tts              - Text-to-speech
chrome.webRequest       - Request monitoring
```

**Critical Check - chrome.management Usage**:
```javascript
chrome.management.getSelf  // Only method used - benign
```

**Verdict**: **CLEAN**. No evidence of:
- Extension enumeration (`chrome.management.getAll()`)
- Extension killing (`chrome.management.setEnabled()`)
- Malicious use of webRequest for traffic interception
- All API usage aligns with translation/authentication functionality

---

### 6. Tesseract OCR Integration - CLEAN (Screenshot Translation)

**Files**:
```
tesseract/tesseract-core-lstm.wasm.js (3.9MB)
tesseract/tesseract-core-simd-lstm.wasm.js (3.9MB)
tesseract/tesseract-core-simd.wasm.js (4.7MB)
tesseract/tesseract-core.wasm.js (4.7MB)
tesseract/tesseract.min.js
tesseract/worker.min.js
tesseract/lang-data/ (OCR language models)
```

**Verdict**: **LEGITIMATE**. Tesseract is the open-source OCR engine for the extension's screenshot translation feature. WASM files are standard Tesseract.js library builds. The CSP allows WASM execution:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
}
```

---

## API Endpoints Summary

| Endpoint | Purpose | Sensitivity |
|----------|---------|-------------|
| `https://api.deepl.com/jsonrpc` | Translation API | Medium (text content) |
| `https://api.deepl.com/termbases/jsonrpc` | Glossary/terminology | Low |
| `https://w.deepl.com/oidc/*` | OAuth authentication | High (credentials) |
| `https://auth.deepl.com` | Auth service | High (credentials) |
| `https://experimentation.deepl.com/experiments` | A/B tests | Low |
| `https://s.deepl.com/chrome/statistics` | Usage analytics | Medium (usage data) |
| `https://write-*.deepl.com/jsonrpc` | Writing assistance API | Medium (text content) |
| `https://ita-*.deepl.com/v1` | Interactive translation | Medium (text content) |
| `https://oneshot-*.deepl.com/v1` | Single translation | Medium (text content) |
| Sentry ingest endpoint | Error reporting | Medium (debug data) |
| Statsig CDN | Feature flags | Low |

**Data Flow**:
1. User selects text → Content script detects selection → Sends to background script
2. Background script → DeepL API (with auth headers if Pro user)
3. Translation result → Displayed in overlay/side panel
4. User preferences/settings → `chrome.storage.local` (not synced)
5. Error events → Sentry (crash diagnostics)
6. Feature flags → Statsig → Determines UI/feature availability

---

## False Positives

| Pattern | Context | Explanation |
|---------|---------|-------------|
| `XMLHttpRequest.prototype` modification | Sentry SDK instrumentation | Standard Sentry breadcrumb tracking for debugging, not malicious XHR hooking |
| `new Worker()` references | Sentry compression worker | Sentry's transport compression worker for efficient error reporting |
| Cookie access | DeepL domain only | Legitimate authentication for Pro account features |
| `innerHTML` (not detected) | N/A | No dangerous DOM manipulation found |
| `eval()` / `Function()` (not detected) | N/A | No dynamic code execution found |

---

## Privacy & Data Handling

Per the extension's privacy policy (`privacy-policy.html`):

1. **Free Users**: Translated text is stored temporarily to improve translation quality (training neural networks)
2. **Pro Users**: Translated text is **not** stored or used for training
3. **Technical Data Collected**:
   - Domain names visited (not full URLs)
   - User agent, OS, browser version
   - Extension usage patterns (feature usage, settings changes)
   - Login/logout events
4. **Local Storage**: User preferences (target language, blacklisted domains) stored locally, not synced
5. **No Cookies Set**: Uses `localStorage` instead of cookies for client-side state

**Compliance**: Privacy policy references GDPR compliance and data processing agreements for Pro users handling personal data in translations.

---

## Managed Policy Schema

The extension supports enterprise deployment with managed policies (`schema.json`):

```json
{
  "requireLogin": boolean,         // Force login wall
  "suggestIdp": string,            // Suggest SSO identity provider
  "customExtensionIcon": boolean,  // White-label icon for DeepL Home
  "enforceSsoAutologin": boolean,  // Skip onboarding, go to SSO
  "skipOnboarding": boolean,       // Skip install onboarding
  "preventFeedbackSurvey": boolean,// Disable survey popups
  "hideWrite": boolean             // Hide writing assistance features
}
```

This is standard for enterprise Chrome extensions deployed via Google Workspace admin policies.

---

## Security Recommendations

1. **For Users**:
   - Extension is safe for general use
   - Pro subscription recommended if translating sensitive/personal data (data processing agreement)
   - Review domains you allow translation on (extension allows blacklisting)

2. **For DeepL**:
   - Consider scoping cookie access to specific names instead of `getAll()` (defense in depth)
   - Add Content Security Policy hash whitelisting for inline scripts (currently uses `'self'`)
   - Document the referer header modification in user-facing privacy policy

3. **For Enterprise Admins**:
   - Use managed policy `requireLogin: true` to enforce Pro account usage
   - Consider `hideWrite: true` if only translation (not writing assistance) is needed
   - Review `suggestIdp` for SSO integration with corporate identity providers

---

## Overall Risk Assessment

**Risk Level**: **CLEAN**

**Justification**:
DeepL is a legitimate, professionally developed translation extension from a reputable company (DeepL SE, Germany). While the extension requests extensive permissions and has broad access to web content, this is **necessary and appropriate** for a translation service. Key factors supporting the CLEAN rating:

1. **Established Company**: DeepL SE is a well-known professional translation service with 4M+ users
2. **Transparent Privacy Policy**: Clear disclosure of data handling practices, GDPR compliance
3. **Scoped Data Access**: Cookies limited to `deepl.com`, no third-party domains accessed
4. **No Malicious Patterns**: Zero evidence of keylogging, ad injection, proxy infrastructure, market intelligence SDKs, or extension manipulation
5. **Standard Tooling**: Uses industry-standard services (Sentry, Statsig) appropriately
6. **Business Model Alignment**: Freemium model with paid Pro tier aligns incentives (no need for data harvesting/ad injection)
7. **Enterprise Features**: Managed policy support indicates corporate customers and compliance requirements

**Invasiveness Explanation**:
The extension is invasive (all-URLs access, cookies, webRequest) because translation inherently requires:
- Reading text from all websites user visits
- Authenticating Pro users via DeepL cookies
- Monitoring network requests to DeepL APIs for error handling

This invasiveness serves the **documented, user-consented purpose** of providing translation services. There is no evidence of dual-use or hidden functionality.

**No Critical Vulnerabilities Identified**.
