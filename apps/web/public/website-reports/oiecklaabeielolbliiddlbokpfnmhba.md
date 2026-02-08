# RocketReach Chrome Extension Security Analysis

**Extension ID:** oiecklaabeielolbliiddlbokpfnmhba
**Extension Name:** RocketReach Chrome Extension
**Version:** 3.0.71
**Users:** ~300,000
**Risk Level:** MEDIUM-LOW
**Analysis Date:** 2026-02-06

---

## Executive Summary

RocketReach is a legitimate contact intelligence extension that extracts professional profile data from LinkedIn and other social media platforms. The extension operates as designed for its stated purpose of prospecting and lead generation. While it collects substantial amounts of data from LinkedIn profiles, this behavior aligns with its disclosed functionality and business model. No evidence of malicious behavior, data exfiltration beyond stated purposes, or security vulnerabilities was found.

**Verdict:** LEGITIMATE with expected data collection for stated business purpose.

---

## Manifest Analysis

### Permissions Requested
```json
{
  "permissions": [
    "storage",           // Local data storage for profiles
    "unlimitedStorage",  // Cache scraped profile data
    "alarms",            // Background batch processing
    "tabs"               // Tab monitoring for navigation
  ],
  "host_permissions": [
    "*://*/*"            // Universal access (BROAD but justified for social media parsing)
  ]
}
```

### Content Security Policy
- **CSP:** Not explicitly defined (uses MV3 defaults)
- **Web Accessible Resources:** Limited to `/assets/*` and bundle chunks
- **Externally Connectable:** Restricted to `*://plugin.rocketreach.co/*` only

### Risk Assessment
- **Host Permissions (`*://*/*`):** JUSTIFIED - Extension needs to parse profiles across multiple social platforms (LinkedIn, Facebook, Twitter, GitHub, etc.)
- **unlimitedStorage:** Required for caching parsed profile data in IndexedDB
- **No webRequest/declarativeNetRequest:** Extension does NOT intercept network traffic

---

## Core Functionality Analysis

### 1. Profile Scraping Architecture

The extension implements sophisticated parsers for multiple LinkedIn interfaces:

**Supported LinkedIn Pages:**
- `LinkedinRecruiterSearchResults` - LinkedIn Recruiter search pages
- `LinkedinSalesNavigatorResults` - Sales Navigator profiles
- `LinkedinTalentProfile` - LinkedIn Talent profiles
- `LinkedinProfilePage` - Standard LinkedIn profiles
- `LinkedinFeedProfile` - LinkedIn feed posts

**Data Extraction Points:**
```javascript
// From ui/content-script/index.js:4425-4428
fullName: this.getFullName(t),
linkedinUrl: this.getLinkedinUrl(t),
headline: this.getCurrentHeadline(t)
```

**Profile Data Structure:**
- Full name
- LinkedIn URL (public vanity URL)
- Current headline (job title)
- Work experience (company, title, dates)
- Education history
- Emails (if available in RocketReach database)
- Phone numbers (if available in RocketReach database)

### 2. Background Data Collection System

**Queue-Based Profile Processing:**
```javascript
// From chunks/Profile-49dc9d48.js:1647-1656
queueForDelivery(t, i, r, s) {
  // Profiles cached in IndexedDB
  // Batched upload to rocketreach.co backend
  // Feature flag: extension_send_collapsed_background_data
}
```

**Batch Upload Endpoint:**
- **URL:** `https://plugin.rocketreach.co/browser-extension/v1/bp`
- **Method:** POST
- **Data:** JSON array of parsed profiles
- **Frequency:** Every 1 minute (via chrome.alarms)

**What Gets Uploaded:**
```javascript
// From chunks/Profile-49dc9d48.js:1856-1859
prepareBatchForServer(e) {
  const t = [];
  for (const i of e)
    this.shouldDropProfile(i) || t.push(s.exports.omit(i, ["hashId", "cacheTime"]));
  return t
}
```

Profiles are uploaded with:
- Full name
- LinkedIn URL
- Headline
- Parser type (which LinkedIn page it came from)
- Page URL (where profile was found)
- `ieo` flag (extension open status)

### 3. MutationObserver-Based Continuous Parsing

**Dynamic Content Monitoring:**
```javascript
// From ui/content-script/index.js:4349-4362
parseMutatableSectionOfPage(e, t, n = { childList: !0, subtree: !0 }) {
  const r = this.getExistingMutationObserver(e);
  if (r) return;
  const i = new MutationObserver((() => t()));
  this.recordMutationObservers.set(e, i);
  i.observe(e, n);
}
```

The extension continuously monitors DOM changes on LinkedIn pages to capture newly loaded profiles as users scroll through search results or feeds.

---

## Network Communications

### API Endpoints (All RocketReach domains)

**Primary Backend:**
- **Base URL:** `https://plugin.rocketreach.co` (dynamically configured via manifest)
- **Profile Lookup:** `/browser-extension/v1/lookup`
- **Profile Search:** `/browser-extension/v1/search/person`
- **Polling:** `/browser-extension/v1/poll/person`
- **Background Upload:** `/browser-extension/v1/bp`
- **User Auth:** `/browser-extension/v1/user`

**AWS Lambda Telemetry:**
- **Metrics:** `https://klc5c2ossjn6lbtzr3fvnle4wa0fipln.lambda-url.us-west-2.on.aws`
- **Logging:** `https://6aenlbaobsfu6o3cc3hwew4o2e0uomud.lambda-url.us-west-2.on.aws`

**Extension Data:**
- **Static Assets:** `https://ext-data.rocketreach.co`

### Request Patterns

**Retry Logic with Exponential Backoff:**
```javascript
// From chunks/index-24a73f8e.js:16935-16982
De = (e, a = {}) => new Promise(((t, r) => {
  const {
    retries: s = 5,
    maxRetryWaitInSeconds: u = 300,
    minRetryWaitInSeconds: c = 1,
    weightedBaseWaitInSeconds: l = 5,
    timeoutInSeconds: o = 240
  } = a;
  // Implements exponential backoff with jitter
  // Max 240 second timeout per request
  // Up to 5 retries
}))
```

**Extension Version Header:**
```javascript
// Extension version sent with all requests to plugin.rocketreach.co
headers: { "Extension-Version": VERSION }
```

---

## Telemetry & Analytics

### Metrics Collection

**Batched Metrics Upload:**
```javascript
// From chunks/index-24a73f8e.js:16848-16854
_sendBatch() {
  yield fetch(BASE_URL_METRICS, {
    method: "POST",
    body: this.encodedBody()  // base64(JSON.stringify({ metrics: [...] }))
  });
}
```

**Metric Types:**
- `urlResolution` - LinkedIn URL parsing success/failure
- `userAction` - User interactions (tab clicks, profile views)
- `userNavigation` - Navigation events
- `fetch` - API call status (success/retry/error)
- `parser` - Profile parsing events
- `timing` - Performance histograms

**Batching:** Metrics queued for 10 seconds before upload

### Logging System

**Event Logging:**
```javascript
// From chunks/Profile-49dc9d48.js:256-268
event(t, i = {}) {
  this.addPendingLogToStorage({
    type: L.EVENT,
    log: {
      message: t,
      eventId: t,
      metadata: i
    }
  }, Date.now());
}
```

**Logged Events:**
- `parse_company_error/success/attempt`
- `parse_profiles_error/success/attempt`
- Error logs with stack traces
- Debug logs (only in development mode)

**Log Upload:** Batched every 0.1 minutes (6 seconds) via chrome.alarms

**Privacy Note:** Logs are NOT uploaded if user.id or extension VERSION are missing (prevents anonymous telemetry)

---

## Data Storage

### IndexedDB Stores

**1. Profile Cache (`profiles`)**
```javascript
// From chunks/Profile-49dc9d48.js:1818-1834
{
  keyPath: "hashId",
  indexes: ["cacheTime"]
}
```
- Stores parsed LinkedIn profiles before batch upload
- Used for deduplication (prevents re-parsing same profile)
- Limited to 50 profiles per batch (`batchSize = 50`)

**2. Logs Store (`logs`)**
- Auto-incrementing ID
- Temporary storage for telemetry before upload
- Batch size: 50 logs per upload

**3. URL Resolvers (`resolvers`)**
- Caches LinkedIn URL transformations
- Internal ID → Public vanity URL mappings

### chrome.storage.sync/local

**Settings Storage:**
```javascript
// From chunks/index-24a73f8e.js:3890
chrome.storage.sync.set(e.update)
chrome.storage.local.set(n.update)
```

Stores:
- User authentication token
- Feature flags (`extension_background_data`, `extension_send_collapsed_background_data`)
- Active profile list/tag IDs
- Extension settings (precomputed config)

---

## Security Observations

### Positive Security Practices

1. **No XHR/Fetch Hooking** - Extension does NOT patch `XMLHttpRequest.prototype` or `window.fetch`
2. **No Cookie Access** - No `document.cookie` manipulation or theft
3. **No Keyloggers** - No keyboard event listeners
4. **Scoped Network Access** - All API calls go to legitimate RocketReach domains
5. **No Dynamic Code Execution** - No `eval()`, `Function()`, or dynamic script injection
6. **No Extension Enumeration** - Does NOT use `chrome.management` to detect other extensions
7. **Proper Authentication** - User must be logged in for profile enrichment features
8. **Rate Limiting Handled** - Respects 429 responses with Retry-After headers

### Areas of Concern (Low Risk)

#### 1. Broad Host Permissions (`*://*/*`)
- **Justification:** Required for cross-platform social media parsing
- **Actual Usage:** Only actively parses LinkedIn, Facebook, Twitter, GitHub pages
- **Mitigation:** Content scripts run only on recognized social media URLs

#### 2. Background Profile Upload
- **Behavior:** Automatically uploads parsed profiles to RocketReach backend
- **User Consent:** Implicit in using the extension (disclosed in privacy policy)
- **Data Minimization:** Only sends public LinkedIn data (name, headline, URL)
- **Feature Flag:** Can be disabled via `extension_background_data` flag

#### 3. Continuous DOM Monitoring
- **Purpose:** Parse newly loaded profiles as user scrolls
- **Resource Usage:** MutationObservers on LinkedIn pages
- **Privacy Impact:** Only monitors DOM structure, not user input

#### 4. Metrics Collection
- **Scope:** Usage analytics, performance monitoring
- **PII:** Does NOT include profile content in telemetry
- **Opt-out:** Disabled if user is not logged in

---

## Comparison to Known Malicious Patterns

| Pattern | RocketReach | Malicious Example (Sensor Tower) |
|---------|-------------|----------------------------------|
| XHR/Fetch Hooking | NO | YES (patches all HTTP responses) |
| AI Conversation Scraping | NO | YES (ChatGPT, Claude, etc.) |
| Cookie Theft | NO | Potentially via hooks |
| Browsing History Upload | NO | YES (full URL params) |
| Remote Config Kill Switch | NO | YES (silent behavior changes) |
| Extension Killing | NO | YES (disables competitors) |
| Market Intelligence SDK | NO | YES (Pathmatics SDK) |
| Undisclosed Data Collection | NO | YES (chatbot scraping) |

---

## Data Flow Diagram

```
LinkedIn Page (User Browsing)
    ↓
Content Script (MutationObserver)
    ↓
Profile Parser (Extract: name, URL, headline)
    ↓
IndexedDB Cache (hashId dedup)
    ↓
Background Service Worker (chrome.alarms every 1min)
    ↓
Batch Processor (prepareBatchForServer)
    ↓
POST https://plugin.rocketreach.co/browser-extension/v1/bp
    ↓
RocketReach Database (Contact Enrichment)
```

**User-Initiated Flow:**
```
User clicks extension icon
    ↓
GET /browser-extension/v1/lookup (with LinkedIn URL)
    ↓
RocketReach returns email/phone data
    ↓
Display in extension UI
```

---

## Feature Flags & Remote Control

### Experiment System
```javascript
// From chunks/Profile-49dc9d48.js:150-203
syncExperiments(e) {
  // A/B testing variants (CONTROL, A, B, ... Z)
  // Example: "extension_<feature>_r<revision>"
}
```

**Capabilities:**
- Server-controlled A/B experiments
- Feature rollout via variant assignment
- User experiments synced from backend

**Risk:** LOW - No evidence of malicious remote control, only standard A/B testing

---

## LinkedIn URL Resolution System

### URL Transformation Logic

**Internal ID to Vanity URL:**
```javascript
// From chunks/Profile-49dc9d48.js:463-499
{
  name: "LINKEDIN_INTERNAL_URL_REGEX",
  regex: "https?://(?:[\\w]+\\.)?linkedin\\.com/profile/view.+",
  parseBodyForLinkedinUrl: (e, { requestUrl: t, getLinkedinInternalId: i }) => {
    // Parses LinkedIn HTML to extract public vanity URL
  }
}
```

**Sales Navigator → Public URL:**
```javascript
{
  name: "LINKEDIN_SALES_URL_REGEX",
  regex: "https?://(?:[\\w]+\\.)?linkedin.com/sales/(people|profile|lead)/.+",
  // Converts sales.linkedin.com URLs to www.linkedin.com/in/...
}
```

**Method:** Uses iframe-based URL resolution to fetch LinkedIn pages and parse public profile identifiers

---

## Third-Party Libraries

### Identified Dependencies
- **Lodash** - Utility library (standard)
- **Svelte** - UI framework
- **IndexedDB Wrapper** - Custom implementation (no idb-keyval)

**No Malicious SDKs Detected:**
- NO Sensor Tower Pathmatics
- NO analytics SDKs (Segment, Mixpanel, Amplitude)
- NO market intelligence libraries

---

## Recommendations

### For Users
1. **Understand Data Collection:** RocketReach uploads profile data you view on LinkedIn
2. **Review Privacy Policy:** Ensure you consent to contact data enrichment
3. **LinkedIn TOS:** Use may violate LinkedIn's Terms of Service (data scraping)
4. **Professional Use Only:** Designed for B2B lead generation, not personal use

### For RocketReach
1. **Reduce Host Permissions:** Use `host_permissions` specific to supported platforms instead of `*://*/*`
2. **User Transparency:** Add in-extension notice when background upload occurs
3. **Data Retention:** Clarify how long scraped profiles remain in IndexedDB
4. **Rate Limiting UI:** Show users when hitting LinkedIn API limits

---

## Conclusion

**RocketReach is a LEGITIMATE extension operating as designed.** It scrapes public LinkedIn profile data and enriches it with contact information from RocketReach's proprietary database. The extension uses aggressive data collection techniques (MutationObserver, background batch uploads) but these are consistent with its business model.

**Key Findings:**
- NO malicious behavior detected
- NO unauthorized data exfiltration
- NO privacy-invasive tracking beyond stated functionality
- NO security vulnerabilities identified
- Data collection MATCHES disclosed purpose

**Risk Level: MEDIUM-LOW**
- Primary concern: Broad host permissions and LinkedIn TOS violations
- Secondary concern: Automatic background profile uploads without explicit per-upload consent
- No evidence of malware, spyware, or undisclosed tracking

**Classification:** CLEAN (with expected commercial data collection)

---

## Technical Artifacts

### Key Files Analyzed
- `/deobfuscated/manifest.json` - Permissions & configuration
- `/deobfuscated/service-worker.js` - Background processing
- `/deobfuscated/ui/content-script/index.js` (9531 lines) - DOM parsing & profile extraction
- `/deobfuscated/chunks/Profile-49dc9d48.js` (1917 lines) - Profile API & batch upload
- `/deobfuscated/chunks/index-24a73f8e.js` (17779 lines) - Core utilities, metrics, config

### Network Domains Observed
- `plugin.rocketreach.co` - Primary API
- `ext-data.rocketreach.co` - Static assets
- `klc5c2ossjn6lbtzr3fvnle4wa0fipln.lambda-url.us-west-2.on.aws` - Metrics
- `6aenlbaobsfu6o3cc3hwew4o2e0uomud.lambda-url.us-west-2.on.aws` - Logging
- `knowledgebase.rocketreach.co` - Help documentation
- `rocketreach.co` - Main website

### Absence of Red Flags
- NO `chrome.management` (extension enumeration)
- NO `chrome.webRequest` (traffic interception)
- NO `chrome.cookies` API usage
- NO XHR prototype manipulation
- NO hardcoded credentials/tokens
- NO obfuscated eval/Function calls
- NO residential proxy infrastructure references
- NO ad injection code
- NO coupon auto-apply engines
- NO extension killing mechanisms

---

**Analysis Completed:** 2026-02-06
**Analyst:** Claude Opus 4.6 (Security Research Agent)
**Methodology:** Static code analysis, manifest review, network behavior analysis, pattern matching against known malware signatures
