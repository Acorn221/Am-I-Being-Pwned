# Security Analysis Report: AI Grammar and Spell Checker by Ginger

## Extension Metadata

| Property | Value |
|----------|-------|
| **Extension Name** | AI Grammar and Spell Checker by Ginger |
| **Extension ID** | kdfieneakcjfaiglcfcgkidlkmlijjnh |
| **Version** | 2.15.357 |
| **Estimated Users** | ~600,000 |
| **Manifest Version** | 3 |
| **Developer** | Ginger Software Ltd. (gingersoftware.com) |

---

## Executive Summary

**Overall Risk Assessment: LOW**

Ginger Grammar and Spell Checker is a **legitimate grammar checking tool** with standard functionality for its category. The extension demonstrates professional development practices, appropriate security controls, and transparent data handling. While it has broad permissions and collects user text for processing, this is expected and necessary for its core grammar/spelling correction features.

**Key Findings:**
- ✅ No malicious patterns detected
- ✅ No extension enumeration or killing mechanisms
- ✅ No residential proxy infrastructure
- ✅ No market intelligence SDKs (e.g., Sensor Tower)
- ✅ No XHR/fetch hooking beyond standard libraries
- ✅ No hardcoded secrets or credentials
- ✅ Legitimate OAuth2 implementation
- ✅ Appropriate CSP configuration
- ⚠️ Text content sent to Ginger servers (expected for grammar checking)
- ⚠️ Google Analytics tracking present (standard telemetry)
- ⚠️ Broad host permissions (necessary for all-page grammar checking)

---

## Manifest Analysis

### Permissions

```json
"permissions": [
  "tabs",
  "background",
  "cookies",
  "storage"
],
"host_permissions": [
  "https://*/",
  "http://*/"
]
```

**Assessment:** Permissions are appropriate for a grammar checking extension:
- `tabs`: Required to identify active page context
- `cookies`: Used for authentication with Ginger services
- `storage`: Stores user preferences and session data
- `host_permissions`: Necessary to inject grammar checking on all pages

### Content Security Policy

```json
"content_security_policy": {
  "extension_page": "script-src 'self' 'unsafe-eval' https://www.google-analytics.com https://www.googletagmanager.com https://ssl.google-analytics.com https://*.gingersoftware.com; object-src 'self'",
  "sandbox": "sandbox allow-scripts; script-src 'self' 'unsafe-eval' 'wasm-unsafe-eval'",
  "worker-src": "script-src 'self' 'unsafe-eval' https://www.google-analytics.com https://www.googletagmanager.com https://ssl.google-analytics.com https://*.gingersoftware.com; object-src 'self'"
}
```

**Assessment:** CSP allows:
- `unsafe-eval`: Required for bundled libraries (jQuery, Angular) - **standard for extensions**
- Google Analytics: Standard telemetry
- Ginger domains only: Properly restricted to first-party services

### Externally Connectable

```json
"externally_connectable": {
  "matches": ["*://gingersoftware.com/*", "*://www.gingersoftware.com/*"]
}
```

**Assessment:** Properly restricted to vendor's own domain. No third-party message passing.

### OAuth2 Configuration

```json
"oauth2": {
  "client_id": "957889341671-e142n1opuadcgtsgvc3dfoct07q2gtrd.apps.googleusercontent.com",
  "scopes": [
    "https://www.googleapis.com/auth/plus.me",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile"
  ]
}
```

**Assessment:** Standard Google OAuth for user authentication. Minimal scopes requested (profile/email only).

---

## Vulnerability Analysis

### 1. Text Data Collection (Grammar Processing)

**Severity:** LOW (Expected Functionality)
**Files:** `content/js/content.min.js`, `background/js/background_2.15.357.min.js`

**Description:**
The extension collects user-typed text from input fields and contenteditable elements to send to Ginger's API servers for grammar/spelling analysis.

**Code Evidence:**

```javascript
// background/js/background_2.15.357.min.js (lines 220-236)
var checkSentence = function(sentence, next, apiProperties) {
    var payload = {
        securedPage: "false",
        lang: gingerModule.get("widget.config").get("dialect"),
        apiKey: gingerModule.get("widget.config").get("apiKey"),
        clientVersion: gingerModule.get("widget.config").get("version"),
        text: sentence.text,
        isOnTheFly: "false"
    };
    var url = apiProperties?.apiName === "orthographe"
        ? gingerModule.get("widget.config").get("urlOrthographe")
        : gingerModule.get("widget.config").get("urlDocument");
```

**API Endpoints:**
- `https://api-extension.gingersoftware.com/Ginger/correct/jsonSecured/GingerTheUserTextFull`
- `https://api-extension.gingersoftware.com/correction/v1/document`
- `https://orthographe.reverso.net/api/v1/Spelling/`
- `https://definition-api.reverso.net/v1/api/definitions`
- `https://synonyms.reverso.net/api/v2/search/en/`
- `https://rephrasesrv.gingersoftware.com/rephrase/rephrase`

**Verdict:** ✅ **FALSE POSITIVE** - This is the core functionality of a grammar checker. Text must be sent to backend services for AI-powered correction. All endpoints are legitimate Ginger/Reverso APIs.

---

### 2. Cookie Access for Authentication

**Severity:** LOW (Standard Authentication)
**Files:** `background/js/background_2.15.357.min.js`

**Description:**
The extension reads and writes authentication cookies for the `gingersoftware.com` domain.

**Code Evidence:**

```javascript
// background/js/background_2.15.357.min.js (lines 246-258)
var setCookies = function(name, cookie, expirationDate) {
    gingerModule.get("gingerchromeext.browser").cookies.set({
        url: gingerModule.get("gingerchromeext.background.config").get("urlBase"),
        name: name,
        value: cookie,
        expirationDate: expirationDate,
        domain: ".gingersoftware.com",
        path: "/"
    });
};

// Session management (lines 1263-1286)
gingerModule.get("gingerchromeext.browser").cookies.get({
    url: gingerModule.get("gingerchromeext.background.config").get("urlBase"),
    name: "authToken"
}, function(cookie) {
    if (cookie && cookie.value) {
        var authToken = cookie.value;
        getUserIdByToken(authToken).then(...)
    }
});
```

**Verdict:** ✅ **FALSE POSITIVE** - Standard authentication mechanism. Cookies are scoped to vendor's own domain only.

---

### 3. Google Analytics Tracking

**Severity:** LOW (Standard Telemetry)
**Files:** `background/js/background_2.15.357.min.js`

**Description:**
The extension sends usage analytics to Google Analytics 4 for feature tracking and onboarding metrics.

**Code Evidence:**

```javascript
// background/js/background_2.15.357.min.js (lines 866-915)
var googleAnalytics4 = function(props) {
    var ga4BaseUrl = prodMode === "production"
        ? gingerModule.get("gingerchromeext.background.config").get("urlGA4")
        : gingerModule.get("gingerchromeext.background.config").get("urlGA4Debug");
    var measurementID = gingerModule.get("gingerchromeext.background.config").get("measurementID");
    var apiKey = gingerModule.get("gingerchromeext.background.config").get("gaApiKey");
    var url = `${ga4BaseUrl}?measurement_id=${measurementID}&api_secret=${apiKey}`;

    var params = {
        ...props,
        engagement_time_msec: 1,
        user_status: userStatus,
        version: version,
        platform: isMac ? "Mac" : "Windows",
        browser: browser
    };
```

**Events Tracked:**
- Correction suggestions displayed/accepted
- Synonym lookups
- Rephrase feature usage
- Login/logout events
- Premium upgrade prompts
- Onboarding milestones (1, 3, 10, 30 uses)

**Data Sent:**
- Event names (e.g., "Suggestion_approve_click")
- User status (free/registered/premium)
- Extension version
- Platform (Mac/Windows)
- Browser type
- Feature-specific metadata (trigger, interface, hostname)

**Verdict:** ✅ **ACCEPTABLE** - Standard product analytics. No PII beyond user status tier. Google Analytics is disclosed in extension description and privacy policy.

---

### 4. Input Field Monitoring

**Severity:** LOW (Core Functionality)
**Files:** `content/js/content.min.js`

**Description:**
The extension monitors all textarea and contenteditable elements on pages for grammar checking.

**Code Evidence:**

```javascript
// content/js/content.min.js (lines 3224-3227)
var module = gingerModule.load("widget.inputFinder", function() {
    var config = {
        selector: "textarea, *[contenteditable]"
    };
```

**Exclusions:**
The extension properly respects disabling mechanisms:
```javascript
// content/js/content.min.js (lines 3312-3313)
if (activeInput && !activeInput.data("gingerWidgetFieldId")
    && activeInput.attr("disableGinger") !== "true"
    && activeInput.attr("data-ginger") !== "false"
    && (activeInput.is(config.selector) || isContentEditableAttr)
    && !areaConfig.disabled)
```

**Site-Specific Handling:**
The extension has explicit support for major platforms:
- Gmail (`mail.google.com`)
- LinkedIn
- Facebook
- Google Docs
- Outlook
- Microsoft Teams
- CKEditor
- Notion
- Qualtrics

**Verdict:** ✅ **FALSE POSITIVE** - Standard behavior for grammar checkers. No data collection from password fields or sensitive inputs.

---

### 5. Google Docs Canvas Manipulation

**Severity:** LOW (Google Docs Integration)
**Files:** `gdocs/gdoc_prebuild.js`

**Description:**
The extension patches Canvas API methods to prevent interference with Google Docs' grammar/spell checking underlines.

**Code Evidence:**

```javascript
// gdocs/gdoc_prebuild.js (lines 19-46)
const LINE_COLORS = ["#dd0000", "#4285f4"];
const RECT_COLORS = ["#fce8e6", "#e8f0fe"];

const lineToPrototype = CanvasRenderingContext2D.prototype.lineTo;
CanvasRenderingContext2D.prototype.lineTo = function (t, s) {
    if ((!this.strokeStyle || !LINE_COLORS.includes(this.strokeStyle.toLowerCase()))
        && !isDisabled()) {
        return lineToPrototype.apply(this, arguments)
    }
};

const fillRectPrototype = CanvasRenderingContext2D.prototype.fillRect;
CanvasRenderingContext2D.prototype.fillRect = function (t, e, n, r) {
    if ((!this.fillStyle || !RECT_COLORS.includes(this.fillStyle.toLowerCase()))
        && !isDisabled()) {
        return fillRectPrototype.apply(this, arguments);
    }
};
```

**Purpose:** Prevents double-underlining by blocking Google Docs' native spell check visuals when Ginger is active. Only blocks specific colors used by Google Docs.

**Verdict:** ✅ **FALSE POSITIVE** - Necessary for Google Docs integration to avoid visual conflicts. Only affects rendering, not data collection.

---

### 6. React Event Injection

**Severity:** LOW (Framework Compatibility)
**Files:** `injection/js/inject_script.min.js`

**Description:**
The extension injects helpers to trigger React component events for text replacement.

**Code Evidence:**

```javascript
// injection/js/inject_script.min.js (lines 7-86)
var findReactProp = function(elem) {
    for (var key in elem) {
        if (key.indexOf("__reactInternalInstance") === 0
            || key.indexOf("__reactProps")) {
            return elem[key].memoizedProps || elem[key]._currentElement.props;
        }
    }
    return null;
};

document.addEventListener("gingerModule-eventEmitter-react-fire", function(e) {
    var reactProps = findReactProp(document.activeElement);
    if (e.detail.event) {
        var eventName = e.detail.event;
        if (reactProps && eventName && reactProps[eventName]) {
            reactProps[eventName](eventParams);
        }
    }
});
```

**Purpose:** Allows correction suggestions to properly update React-controlled inputs (e.g., Facebook, Twitter). React components require synthetic events to trigger state updates.

**Verdict:** ✅ **FALSE POSITIVE** - Standard technique for React compatibility. Only triggers events on user-initiated corrections.

---

## False Positives Summary

| Pattern | Reason | Verdict |
|---------|--------|---------|
| **Text data collection** | Core grammar checking functionality - text must be analyzed by backend AI | ✅ Expected |
| **Cookie access** | Standard authentication for user accounts | ✅ Legitimate |
| **Google Analytics** | Product telemetry for feature usage tracking | ✅ Standard |
| **Input monitoring** | Required to detect text fields for grammar checking | ✅ Necessary |
| **Canvas API patching** | Google Docs integration to prevent visual conflicts | ✅ Compatibility |
| **React event injection** | Framework compatibility for text replacement | ✅ Standard |
| **jQuery `eval` usage** | Part of bundled jQuery library (vendor.js) | ✅ Library FP |

---

## API Endpoints & Data Flow

### First-Party Endpoints (Ginger Software)

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `api-extension.gingersoftware.com/correction/v1/document` | Grammar/spelling correction | User text, language, user ID (if logged in) |
| `rephrasesrv.gingersoftware.com/rephrase/rephrase` | Sentence rephrasing | Text to rephrase, user ID |
| `auth.gingersoftware.com/isValidToken/` | Token validation | Auth token |
| `umservices.gingersoftware.com/UM_LoginBased/UMOperations/jsonSecured/GetUserDetails` | User profile data | User ID, API key |
| `umservices.gingersoftware.com/Subscriptions/GetSubscriptionsByUserIdentifier` | Subscription status | User ID, API key |
| `smb.gingersoftware.com/Teams` | Team account features | Team ID, user ID |

### Third-Party Endpoints (Reverso - Legitimate Partner)

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `definition-api.reverso.net/v1/api/definitions` | Word definitions | Search word |
| `synonyms.reverso.net/api/v2/search/en/` | Synonym suggestions | Search word |
| `orthographe.reverso.net/api/v1/Spelling/` | French spelling | Text to check |
| `lang-utils-api.reverso.net/langdetect` | Language detection | Text sample |

### Analytics

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `www.google-analytics.com/mp/collect` | GA4 telemetry | Event names, user status tier, version, platform |

**Assessment:** All endpoints belong to Ginger Software or their documented partner Reverso (dictionary/translation provider). No suspicious third-party data exfiltration detected.

---

## Data Flow Summary

```
User Types Text
    ↓
Content Script (content.min.js)
    ↓
Background Script (background_2.15.357.min.js)
    ↓
Ginger API (api-extension.gingersoftware.com)
    ↓
Returns Grammar Suggestions
    ↓
Display to User
```

**Optional Flows:**
- **Synonyms:** User selects word → Query Reverso API → Display alternatives
- **Definitions:** User requests definition → Query Reverso API → Display result
- **Rephrase:** User requests rephrase → Query Ginger Rephrase API → Display options
- **Analytics:** User action → Send event to Google Analytics

**User Control:**
- Users can disable extension per-site via domain blacklist
- Extension respects `spellcheck="false"` attributes
- Extension respects `disableGinger="true"` attributes
- Extension can be paused via popup toggle

---

## Privacy Considerations

### What Data Is Collected?

1. **Text Content** (Functional Requirement)
   - User-typed text in textarea/contenteditable fields
   - Sent to Ginger APIs for grammar/spelling analysis
   - **Purpose:** Core functionality - text must be analyzed
   - **Mitigation:** Users control which sites extension runs on

2. **User Account Data** (If Logged In)
   - Email address (via Google OAuth)
   - Subscription status (free/premium)
   - User ID (Ginger-generated)
   - **Purpose:** Account management, subscription enforcement
   - **Storage:** Chrome Sync Storage

3. **Usage Analytics** (Google Analytics)
   - Feature usage events (corrections accepted, synonyms viewed)
   - User tier (free/registered/premium)
   - Extension version
   - Platform/browser type
   - Page hostname (for event context)
   - **Purpose:** Product improvement, onboarding optimization
   - **No PII:** No email, no names, no text content

### What Is NOT Collected?

❌ Password field contents (no evidence of password monitoring)
❌ Credit card numbers
❌ Social Security numbers
❌ Banking information
❌ Browsing history beyond current page hostname
❌ Full page content (only focused input field text)
❌ Other extension IDs or presence

---

## Comparison to Malicious Patterns

### Extension Enumeration/Killing
**Status:** ❌ NOT PRESENT

No evidence of:
- `chrome.management.getAll()`
- `chrome.management.setEnabled()`
- Extension inventory collection
- Extension disabling mechanisms

**Verdict:** CLEAN

---

### XHR/Fetch Hooking (Market Intelligence)
**Status:** ❌ NOT PRESENT

No evidence of:
- Sensor Tower Pathmatics SDK
- XHR/Fetch prototype patching
- HTTP response interception
- Ad creative scraping
- AI conversation scraping

**Verdict:** CLEAN

---

### Residential Proxy Infrastructure
**Status:** ❌ NOT PRESENT

No evidence of:
- Proxy configuration APIs
- Proxy vendor SDKs (Luminati/Oxylabs)
- `chrome.proxy` usage
- SOCKS/HTTP proxy setup
- P2P networking

**Verdict:** CLEAN

---

### Remote Code Execution
**Status:** ❌ NOT PRESENT

No evidence of:
- Dynamic script loading from external servers
- `eval()` with user-controlled strings (only library usage)
- Remote config controlling behavior
- Kill switches or "thanos" mechanisms

**Note:** `unsafe-eval` in CSP is for bundled libraries (jQuery, Angular) - standard practice.

**Verdict:** CLEAN

---

### Sensitive Data Harvesting
**Status:** ❌ NOT PRESENT

No evidence of:
- Password field targeting
- Credit card pattern matching
- Form autofill interception
- Clipboard stealing
- Screenshot capture (beyond feature screenshots)

**Verdict:** CLEAN

---

## Overall Risk Assessment

### Risk Level: **LOW** ✅

### Justification:

1. **Legitimate Business Model**
   - Established company (Ginger Software Ltd.)
   - Freemium grammar checking service
   - Transparent revenue model (premium subscriptions)
   - No ad injection or hidden monetization

2. **Appropriate Permissions**
   - All permissions justified by functionality
   - No overreach (e.g., no `management`, `webRequest`, `declarativeNetRequest`)
   - Proper permission scoping

3. **Standard Data Practices**
   - Text collection necessary for grammar checking
   - Authentication via standard OAuth2
   - Analytics via standard Google Analytics
   - No sensitive data harvesting

4. **Professional Development**
   - Clean, well-structured code
   - Proper error handling
   - Framework compatibility (React, Google Docs, CKEditor)
   - Regular updates (version 2.15.357)

5. **User Controls**
   - Per-site disabling
   - Respect for opt-out attributes
   - Visible extension behavior

### Risks to Users:

⚠️ **Privacy Consideration:** User text is sent to Ginger servers for processing. Users should:
- Be aware that typed text is analyzed by third-party servers
- Avoid using the extension on highly sensitive documents if concerned
- Review Ginger's privacy policy at gingersoftware.com

⚠️ **Google OAuth Dependency:** Extension uses Google account for login. Users trusting Ginger are implicitly trusting:
- Ginger's handling of Google profile data
- Ginger's API security

### Recommended User Actions:

✅ **Safe to Use** for general writing (emails, social media, documents)
⚠️ **Use Caution** with highly confidential content (legal docs, trade secrets, classified info)
✅ **Disable on Sensitive Sites** using per-site blacklist if needed
✅ **Review Privacy Policy** at https://www.gingersoftware.com/privacy-policy

---

## Conclusion

**AI Grammar and Spell Checker by Ginger is a LEGITIMATE, LOW-RISK extension** that functions as advertised. It demonstrates:

✅ Transparent functionality (grammar/spelling checking)
✅ Professional development practices
✅ Appropriate permission usage
✅ Standard data collection for core features
✅ No malicious patterns or hidden functionality
✅ Established company with clear business model

**No security vulnerabilities or malicious behavior detected.**

The extension operates within expected norms for AI-powered grammar checkers. Text collection is inherent to the functionality (text must be sent to AI servers for analysis), similar to competitors like Grammarly, ProWritingAid, and LanguageTool.

**Recommendation:** **CLEAN** - Suitable for general use with standard privacy considerations for cloud-based text processing services.

---

## References

- Extension Page: https://chrome.google.com/webstore/detail/kdfieneakcjfaiglcfcgkidlkmlijjnh
- Developer Website: https://www.gingersoftware.com
- Privacy Policy: https://www.gingersoftware.com/privacy-policy
- API Partner: Reverso (https://reverso.net) - Legitimate dictionary/translation service

---

**Report Generated:** 2026-02-06
**Analyst:** Claude Code Security Analysis
**Analysis Version:** Deep Dive Comprehensive Security Review
