# Security Analysis: Opus Advisor (kgmohllpiohdkkhhkfneojbadinddkpm)

## Extension Metadata
- **Name**: Opus Advisor
- **Extension ID**: kgmohllpiohdkkhhkfneojbadinddkpm
- **Version**: 2.54.0
- **Manifest Version**: 3
- **Estimated Users**: 200,000
- **Developer**: Unknown (Opus EPS internal)
- **Analysis Date**: 2026-02-14

## Executive Summary
Opus Advisor is an enterprise help documentation tool that displays context-aware guidance and step-by-step tutorials ("Follow Me" mode) while users navigate web applications. While the extension appears to serve a legitimate enterprise purpose, it exhibits **HIGH RISK** behavior due to broad data collection, user tracking, and transmission of browsing activity to third-party analytics endpoints. The extension collects tab URLs, user IP addresses, tenant information, and navigation patterns, sending this data to both company-controlled APIs and AWS analytics infrastructure.

**Overall Risk Assessment: HIGH**

## Vulnerability Assessment

### 1. Extensive Browsing Data Collection and Exfiltration
**Severity**: HIGH
**Files**:
- `/background.js` (lines 1370-1434)
- `/config/config.js` (line 6)

**Analysis**:
The extension implements comprehensive tracking of user web navigation on targeted applications, collecting and transmitting detailed analytics to AWS endpoints.

**Code Evidence** (`background.js`):
```javascript
chrome.tabs.onUpdated.addListener(async function(tabId, changeInfo, tab) {
  if (changeInfo.status === "complete") {
    try {
      let userDetails = await getUserDetails();
      const url = new URL(tab.url);
      const domain = url.hostname;
      const ipAddress = await fetchIpAddress(); // Fetches user's public IP from api.ipify.org

      const requestData = {
        eventId: 1,
        type: "Web Navigation",
        source: "WebAdvisor",
        targetAppId: matchedTarget.id,
        targetAppName: matchedTarget.name,
        tenantId: userDetails.tenantId,
        userId: userDetails.id,
        userActivationTime: userDetails.tenant.userActivationTime,
        ipAddress: ipAddress,
        dateTime: new Date().toISOString(),
        spanId: crypto.randomUUID(),
        payload: {
          document: "Website Navigation",
          documentId: "tab-" + tabId,
          step: "Tab-update",
          url: tab.url  // FULL URL transmitted
        }
      };
      await sendPostRequestToAWS(requestData, authToken);
    }
  }
});

async function sendPostRequestToAWS(requestData, authToken) {
  let Url = `${Config.ANALYTICS_INGSN_URL}/ingest`;
  // https://s2djscfihk.execute-api.us-west-2.amazonaws.com/prod/ingest
  const response = await fetch(Url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${authToken}`
    },
    body: JSON.stringify(requestData)
  });
}
```

**Data Transmitted to AWS**:
- Full tab URLs for all visited pages in "target applications"
- User's public IP address (fetched from `api.ipify.org`)
- User ID and tenant ID
- Exact timestamps of navigation events
- User activation time from tenant configuration
- Unique span IDs for tracking sessions

**Target Application Matching** (`background.js` lines 414-493):
```javascript
async function fetchOrGetCachedTargetUrls(authToken) {
  const response = await fetch(
    `${Config.DomainUrlV2}/categories`,
    {
      headers: { authorization: authToken, ... }
    }
  );
  const targetUrls = data
    .filter(category => category.isDataCaptureAllow === true &&
                        category.categoryContexts &&
                        category.categoryContexts.length > 0)
    .map(category => ({
      name: category.name,
      id: category.id,
      urls: category.categoryContexts.map(context => context.url)
    }));
  // Cache for 8 hours
  chrome.storage.local.set({ target_applications: { targetUrls, timestamp: Date.now() }});
  return targetUrls;
}
```

**Implications**:
1. The extension fetches a list of "target applications" from the company's API
2. Only URLs matching these targets are tracked (conditional surveillance)
3. Data is transmitted to AWS analytics endpoint, not just company servers
4. IP address collection enables geolocation tracking
5. Tenant/user IDs enable cross-session user profiling
6. 8-hour cache means targets are refreshed multiple times per day

**Verdict**: **HIGH RISK** - This is active user surveillance and data exfiltration. While potentially legitimate for enterprise usage analytics, the broad scope (all navigation on target apps), IP address collection, and third-party AWS transmission constitute privacy concerns.

---

### 2. Document Completion Tracking with Full Browsing Context
**Severity**: MEDIUM
**Files**: `/background.js` (lines 1979-2038)

**Analysis**:
When users complete interactive "Follow Me" tutorials, the extension sends comprehensive completion data including current tab URLs and titles.

**Code Evidence**:
```javascript
async function SendCompleteDocumentStatementAsync() {
  let userDetails = await chrome.storage.local.get("current_user_profile");
  userDetails = userDetails.current_user_profile;
  userId = userDetails.id;
  userName = userDetails.loginName;
  tenancyId = userDetails.tenantId;
  tenancyName = userDetails.tenant.tenancyName;

  chrome.tabs.query({ active: true, currentWindow: true }, async function(tabs) {
    let caption = '';
    let url = '';
    if (tabs.length > 0) {
      caption = tabs[0].title;  // Page title
      url = tabs[0].url;        // Full URL
    }

    var data = {
      document: {
        docType: 8,
        id: docId,
        name: docName
      },
      result: {
        max: totalSteps,
        min: 0,
        raw: matchedSteps,
        completion: true,
        scaled: scaled
      },
      userId: userId,
      userName: userName,
      tenancyId: tenancyId,
      tenancyName: tenancyName,
      verb: "completed",
      duration: new Date().getTime() - initTime.getTime(),
      initTime: initTime,
      caption: caption,  // Current page title
      url: url,          // Current page URL
      contextRegistrationId: ''
    };
    doPostV2("/lrs/completed_test", data); // Sends to api.internal.opuseps.com
  });
}
```

**Data Transmitted**:
- Current active tab URL and title (may be unrelated to tutorial)
- User identity (ID, login name)
- Tenant information
- Tutorial completion metrics
- Session duration
- Timestamps

**Verdict**: **MEDIUM RISK** - Collects current browsing context even if unrelated to the tutorial being completed. Less severe than #1 since it only fires on tutorial completion, not continuous navigation.

---

### 3. Microphone Permission Without Clear Justification
**Severity**: MEDIUM
**Files**:
- `/manifest.json` (lines 79-80)
- `/eassistant.js` (lines 252, 310)
- `/content.js` (line 42)

**Analysis**:
The extension requests `microphone` and `audioCapture` permissions, which are unusual for a help documentation tool.

**Manifest Declaration**:
```json
"permissions": [
  "storage",
  "activeTab",
  "scripting",
  "tabs",
  "management",
  "microphone",
  "audioCapture"
]
```

**Usage in Code**:
```javascript
// eassistant.js
ifrm.allow = 'microphone'; // Iframe granted microphone access
```

**Observations**:
1. The extension's description mentions "dynamically suggests help documents" - no mention of audio features
2. Iframes loaded from S3/CloudFront are granted microphone access
3. The embedded Angular application (loaded dynamically) may have audio recording capabilities
4. No evidence of actual microphone usage in the analyzed code, but permission is granted to embedded web apps

**Potential Use Cases** (speculative):
- Voice-guided tutorials
- Audio annotations on help documents
- Voice commands for navigation
- Screen recording with audio for training materials

**Verdict**: **MEDIUM RISK** - Overly broad permissions that could enable audio surveillance. While potentially used for legitimate features, lack of transparency is concerning.

---

### 4. Broad Host Permissions and Content Script Injection
**Severity**: MEDIUM
**Files**:
- `/manifest.json` (lines 82-84, 26-71)
- `/background.js` (lines 271-305)

**Analysis**:
The extension has access to all HTTP/HTTPS websites and injects extensive content scripts.

**Manifest Configuration**:
```json
"host_permissions": [
  "https://*/*",
  "http://*/*"
],
"content_scripts": [{
  "matches": ["<all_urls>", "https://*.cloudfront.net/*"],
  "match_about_blank": true,
  "js": [
    "services/packages/rbo.js",
    "services/packages/fastest-levenshtein.js",
    "services/packages/popper.min.js",
    "services/packages/tippy.umd.min.js",
    "services/channels-service.js",
    // ... 15+ more services
    "libs/jquery-3.7.0.min.js"
  ],
  "all_frames": true,
  "run_at": "document_end"
}]
```

**Dynamic Script Injection** (`background.js`):
```javascript
const injectScriptsTo = (tabId) => {
  chrome.scripting.executeScript({
    target: { tabId: tabId },
    files: [
      "services/packages/rbo.js",
      // ... 20+ script files
      "libs/jquery.js"
    ]
  });
};
```

**Scope**:
- Runs on ALL websites (not just target applications)
- Injects 20+ JavaScript files into every page
- Runs in all frames (including cross-origin iframes)
- Access to `about:blank` pages

**Verdict**: **MEDIUM RISK** - Extremely broad injection scope creates large attack surface. While necessary for ubiquitous help overlay, the extensive code injection on all sites poses risks if any injected library has vulnerabilities.

---

### 5. Cookie Access in Content Scripts
**Severity**: LOW
**Files**: `/services/step-service.js` (lines 617-619)

**Analysis**:
Content scripts access `document.cookie` to read cookies from visited pages.

**Code Evidence** (from dataFlowTraces):
```javascript
let rawCookies = document.cookie;  // SOURCE: document.cookie access
let rawCookiesList = rawCookies.split("; ");
```

**Context**:
The code appears in `step-service.js`, likely used for comparing page state between tutorial steps. The trace does NOT show transmission to external servers within the analyzed 200-line window.

**Verdict**: **LOW RISK** - Cookie access detected but no evidence of exfiltration. Likely used for page context matching in tutorials. However, the capability exists to read all cookies on visited pages.

---

### 6. Externally Connectable Configuration
**Severity**: LOW
**Files**: `/manifest.json` (lines 87-92)

**Analysis**:
The extension allows external websites to send messages to it.

**Manifest Configuration**:
```json
"externally_connectable": {
  "matches": [
    "*://*.amazonaws.com/*",
    "*://localhost/*"
  ]
}
```

**Implications**:
- Any AWS subdomain can communicate with the extension
- Localhost access enables local development
- Could be exploited if malicious scripts run on AWS-hosted sites

**Verdict**: **LOW RISK** - Overly broad AWS wildcard but necessary for the S3-hosted Angular app architecture. Localhost access is standard for development.

---

### 7. Remote Code Loading from S3/CloudFront
**Severity**: LOW (architectural, not currently malicious)
**Files**: `/background.js` (lines 587-606, 658-682)

**Analysis**:
The extension dynamically loads an Angular web application from CloudFront/S3 into iframes.

**Code Evidence**:
```javascript
async function injectingEassistant(source, mode="") {
  let EAssistantVersion = await chrome.storage.sync.get('EAssistantVersion');
  if (EAssistantVersion) {
    injectVersionedEassistant(EAssistantVersion.EAssistantVersion, source, mode);
  } else {
    const res = await getEAssistantVersion();
    if (res?.result?.result?.dependentComponentVersion) {
      await chrome.storage.sync.set({
        EAssistantVersion: res.result.result.dependentComponentVersion
      });
      injectVersionedEassistant(res.result.result.dependentComponentVersion, source, mode);
    }
  }
}

function injectVersionedEassistant(version, source, mode) {
  let url = `${S3BUCKETSIDEPANELURL.prodURL}${version}/index.html`;
  // https://d3smufgqxs08fd.cloudfront.net/{version}/index.html
  let data = {
    url: url,
    appId: chrome.runtime.id,
    drawInLeft: false,
    source: source,
    mode: mode
  };
  // Injects iframe with remote HTML from CloudFront
}
```

**S3 Bucket URLs**:
```javascript
var S3BUCKETSIDEPANELURL = {
  developmentURL: "https://d5qwn0cv5gtee.cloudfront.net/",
  prodURL: "https://d3smufgqxs08fd.cloudfront.net/",
  qaURL: "https://d1pf74k4aphxrb.cloudfront.net/",
  localURL: "http://localhost:4200",
  stageURL: "https://we-eassistant.test-opuseps.com/"
};
```

**Process**:
1. Extension fetches version number from company API
2. Constructs CloudFront URL using version: `https://d3smufgqxs08fd.cloudfront.net/{version}/index.html`
3. Injects iframe loading the remote Angular application
4. Remote app has microphone access and can communicate with extension

**Verdict**: **LOW RISK** (but concerning architecture) - While not actively malicious, this pattern allows the publisher to update functionality without CWS review. Changes to the CloudFront-hosted app could introduce new behaviors without triggering extension updates.

---

### 8. PostMessage Communication Without Origin Validation
**Severity**: LOW
**Files**: `/eassistant.js` (lines 197-214)

**Analysis**:
The extension listens for `postMessage` events with weak origin validation.

**Code Evidence**:
```javascript
var messageListenerEAssistant;
if (typeof messageListenerEAssistant == "undefined") {
  messageListenerEAssistant = function(event) {
    if (event.data && isJsonString(event.data)) {
      let request = JSON.parse(event.data);
      if (request.msg === CHROME_RUNTIME_MESSAGES.EIRemovePanel) {
        removeEassistant();
        chromeRuntimeSendMessage("fm-ea-mode-closed", null);
        return true;
      }
      if (request.msg === CHROME_RUNTIME_MESSAGES.EIResizePanel) {
        resizeScreen();
        return;
      }
    }
    // We only accept messages from ourselves
    // if (event.source != window) return;  ← COMMENTED OUT!
  };
  window.addEventListener("message", messageListenerEAssistant);
}
```

**Issues**:
1. Origin check is commented out: `// if (event.source != window) return;`
2. Only validates message format, not sender origin
3. Allows any page to send commands like "remove panel" or "resize screen"

**Prefill Flag**: `postmessage_no_origin`

**Verdict**: **LOW RISK** - The messages handled don't expose sensitive data or dangerous functionality (only UI manipulation). However, this is still a bad practice that could be exploited for UI confusion attacks.

---

## False Positive Patterns Identified

| Pattern | Location | Reason for FP | Actual Purpose |
|---------|----------|---------------|----------------|
| `eval()` detection | N/A | Regex-based scanners flag dynamic code | No actual eval() usage found |
| `Function()` detection | N/A | Regex-based scanners flag dynamic code | No actual Function() usage found |
| Cookie access | `services/step-service.js` | Could be mistaken for cookie theft | Page context comparison for tutorials |
| Tab URL access | `background.js` | Could be mistaken for general tracking | Conditional tracking of enterprise apps only |

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `api.internal.opuseps.com` | Help document retrieval, auth, categories | Auth tokens, user profile, document IDs | Continuous (when extension active) |
| `s2djscfihk.execute-api.us-west-2.amazonaws.com` | Analytics ingestion | Tab URLs, IP address, user/tenant IDs, timestamps | Every tab navigation on target apps |
| `api.ipify.org` | IP address lookup | None (response only) | Every tab navigation on target apps |
| `d3smufgqxs08fd.cloudfront.net` | Remote Angular app hosting | None (content download) | On extension activation |
| `d1pf74k4aphxrb.cloudfront.net` | QA environment app hosting | None (content download) | QA environment only |
| `d5qwn0cv5gtee.cloudfront.net` | Dev environment app hosting | None (content download) | Dev environment only |

### Data Flow Summary

**Data Collection**: EXTENSIVE
- Full URLs of visited pages (on target applications)
- User IP addresses
- User identity (ID, login name, tenant)
- Page titles and navigation timestamps
- Tutorial completion metrics
- Tab state and zoom levels
- Document interaction events

**User Data Transmitted**: HIGH VOLUME
- **To Company APIs**: User profiles, document access, completion events, authentication tokens
- **To AWS Analytics**: Full browsing history on target apps, IP addresses, user/tenant IDs, navigation patterns

**Tracking/Analytics**: COMPREHENSIVE
- Cross-session user tracking via user ID
- Geolocation via IP address
- Navigation pattern analysis
- Tutorial completion correlation with browsing behavior

**Third-Party Services**: AWS analytics endpoint (controlled by Opus EPS but external to main infrastructure)

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `tabs` | Required for tutorial overlay and navigation tracking | High (enables URL access) |
| `activeTab` | Access to current tab content | Medium (necessary for help overlay) |
| `scripting` | Dynamic content script injection | Medium (necessary but broad) |
| `storage` | Settings and auth token storage | Low (standard) |
| `management` | Extension management APIs | Low (no evidence of misuse) |
| `microphone` | **Audio recording/voice features** | **High (unclear necessity)** |
| `audioCapture` | **Audio capture** | **High (unclear necessity)** |
| `host_permissions: <all_urls>` | Help overlay on any website | High (necessary but extremely broad) |

**Assessment**: Permissions are overly broad for stated functionality. Microphone/audio permissions are particularly concerning given lack of user-facing audio features in documentation.

## Content Security Policy
```json
Manifest V3 default CSP applies (no custom CSP declared)
```
**Note**: MV3 extensions have strict CSP by default, preventing inline scripts and eval().

## Code Quality Observations

### Positive Indicators
1. No use of `eval()` or `Function()` for dynamic code execution
2. Proper error handling in async functions
3. Token-based authentication with renewal mechanism
4. Cache management (8-hour TTL for target URLs)

### Negative Indicators
1. **Commented-out security checks** (postMessage origin validation)
2. **Wildcard AWS domain** in externally_connectable
3. **Remote code loading** from CloudFront (updates bypass CWS review)
4. **Broad content script injection** (all websites, all frames)
5. **No data minimization** (collects full URLs, not just domains)
6. **Third-party analytics** (AWS endpoint, not just company servers)

### Obfuscation Level
**MEDIUM** - Code is minified and uses Angular/TypeScript compilation. The large extension size (timeout during static analysis) and webpack bundling make comprehensive analysis difficult. Main logic is readable but service implementations are complex.

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | `management` permission requested but no usage found |
| XHR/fetch hooking | ✗ No | No prototype modifications detected |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | No API interception patterns |
| Market intelligence SDKs | ✗ No | Custom analytics, not third-party SDK |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Remote config/kill switches | ⚠ Partial | Fetches "target application" list remotely |
| Cookie harvesting | ⚠ Partial | Reads cookies but no exfiltration detected |
| Hidden data exfiltration | **✓ Yes** | **Tab URLs, IP addresses sent to AWS** |
| User surveillance | **✓ Yes** | **Continuous navigation tracking on target apps** |

## Enterprise Context

**Important Note**: Opus Advisor appears to be an **enterprise software product** designed for corporate IT training and support. Key indicators:

1. **Multi-tenant architecture**: User profiles include `tenantId` and `tenant.tenancyName`
2. **Whitelisting system**: Only tracks URLs in "target applications" configured by tenant admins
3. **User activation control**: Checks `tenant.isAccessTargetApplication` before tracking
4. **Internal domains**: APIs hosted at `api.internal.opuseps.com`
5. **Enterprise features**: SSO login, admin tokens, role-based access

**Interpretation**:
In an **enterprise deployment context**, some HIGH-risk behaviors may be **expected and disclosed**:
- Employers may require employee activity monitoring on corporate applications
- Analytics help optimize training effectiveness
- IP addresses may be needed for security/compliance logging
- Microphone access may support voice-guided training features

**However**:
- The extension is publicly available on Chrome Web Store (200K users)
- Consumer users installing this extension would be subject to corporate surveillance
- No privacy policy visible in extension metadata
- Analytics sent to third-party AWS endpoint, not just company servers
- User consent mechanisms not evident in code

## Overall Risk Assessment

### Risk Level: **HIGH**

**Justification**:
1. **Active user surveillance** - Collects full browsing history on targeted applications
2. **Third-party data sharing** - Sends user data to AWS analytics endpoint, not just company APIs
3. **PII collection** - IP addresses, user IDs, login names, tenant information
4. **Unclear audio permissions** - Microphone access without evident necessity
5. **Broad attack surface** - All websites, all frames, 20+ injected scripts
6. **Remote code updates** - CloudFront-hosted app can change without extension updates
7. **Weak security practices** - Commented-out origin validation, wildcard external connections

**For Enterprise Users**:
- Risk is **MEDIUM-HIGH** if properly disclosed by IT department
- May be acceptable if covered by employment agreements
- Transparency with employees is critical

**For Consumer Users**:
- Risk is **HIGH** - Do not install unless you understand you're enrolling in enterprise monitoring
- All browsing on "target applications" is tracked and sent to company servers + AWS
- IP address and identity are transmitted with every navigation event

### Recommendations

**For General Users**:
- **Uninstall** unless you are an employee of a company using Opus EPS
- If required by employer, request privacy disclosure documentation
- Understand that browsing on corporate applications is monitored

**For IT Administrators**:
- Ensure employee consent for monitoring is obtained
- Review privacy impact assessment for GDPR/CCPA compliance
- Audit the list of "target applications" being tracked
- Consider restricting microphone permission if not needed
- Implement data retention policies for collected analytics
- Evaluate if AWS analytics endpoint meets data residency requirements

**For the Developer**:
- Add comprehensive privacy policy to extension listing
- Implement user consent flow before tracking activation
- Validate postMessage origins (uncomment security check)
- Restrict externally_connectable to specific AWS subdomains
- Minimize data collection (domains instead of full URLs)
- Remove microphone permissions if unused
- Add transparency dashboard showing what data is collected

### User Privacy Impact
**SEVERE** - The extension implements comprehensive user surveillance on targeted web applications:
- **Browsing history**: Full URLs of every page visited on target apps
- **Identity tracking**: User ID, login name, tenant affiliation
- **Geolocation**: IP address collected and transmitted
- **Behavioral profiling**: Navigation patterns, session durations, tutorial completions
- **Cross-session tracking**: Persistent user IDs enable long-term profiling
- **Third-party disclosure**: Data sent to AWS analytics endpoint

**Data Recipients**:
1. Opus EPS (company infrastructure)
2. AWS (analytics endpoint in us-west-2)
3. Potentially tenant administrators (likely have dashboard access)

## Technical Summary

**Lines of Code**: ~15,000+ (extension too large for static analyzer - TIMEOUT)
**External Dependencies**: jQuery 3.7.0, Popper.js, Tippy.js, Angular (remote), Fabric.js, 10+ other libraries
**Third-Party Libraries**: Extensive (jQuery, UI frameworks, date pickers, tree views, etc.)
**Remote Code Loading**: Yes (Angular app from CloudFront, version-controlled)
**Dynamic Code Execution**: None detected (no eval/Function)

## Conclusion

Opus Advisor is a **legitimate enterprise software product** with **HIGH privacy risks** due to extensive user surveillance and data collection capabilities. The extension collects comprehensive browsing analytics on targeted applications and transmits this data to both company-controlled APIs and third-party AWS infrastructure.

**Key Concerns**:
1. **Comprehensive tracking**: Full URL collection, IP addresses, user identity
2. **Third-party transmission**: AWS analytics endpoint (not just company servers)
3. **Unclear permissions**: Microphone access without evident necessity
4. **Weak security**: Commented-out origin validation, broad external connections
5. **Remote updates**: CloudFront-hosted app can change functionality without CWS review

**Final Verdict: HIGH RISK**

**For Enterprise Context**: May be acceptable with proper disclosure and consent
**For Consumer Users**: Do not install - this is surveillance software designed for corporate IT departments

**Recommendation**: The extension should be restricted to enterprise deployment via policy management, not publicly distributed on Chrome Web Store. If public distribution continues, comprehensive privacy disclosures and user consent mechanisms are mandatory.
