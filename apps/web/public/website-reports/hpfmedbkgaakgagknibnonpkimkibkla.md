# Copper CRM for Gmail and LinkedIn - Security Analysis Report

## Extension Metadata
- **Extension Name**: Copper CRM for Gmail and LinkedIn
- **Extension ID**: hpfmedbkgaakgagknibnonpkimkibkla
- **Version**: 2.0.427
- **User Count**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Copper CRM is a legitimate Customer Relationship Management extension designed to integrate with Gmail, Google Calendar, and LinkedIn. The extension provides email tracking, contact management, and CRM functionality directly within Google Workspace.

The security analysis reveals **LOW RISK** overall. The extension implements legitimate business functionality including email open tracking, analytics integration (Segment.io), and LinkedIn profile data extraction. While it collects significant user data (email content, recipients, LinkedIn profile information), this is necessary for CRM functionality and appears to be transmitted only to Copper's legitimate backend services (app.copper.com, api.copper.com).

**Key Findings:**
- Email tracking pixel functionality monitors when tracked emails are opened
- Analytics data sent to Segment.io for product telemetry
- LinkedIn profile scraping when users visit LinkedIn profiles
- Development artifact found (ngrok URL) - benign but should be removed
- No evidence of malicious behavior, data exfiltration, or ad injection
- Extensive permissions align with stated CRM functionality

## Vulnerability Details

### 1. Email Content Interception and Tracking
**Severity**: MEDIUM
**Files**: `background.js` (lines 488-652), `rulesets/email-tracker.json`
**Verdict**: EXPECTED FUNCTIONALITY

**Description:**
The extension intercepts outgoing Gmail messages using `chrome.webRequest.onBeforeRequest` to extract email content, subject, recipients, and insert tracking pixels.

**Code Evidence:**
```javascript
// background.js:645-651
function register() {
  chrome.webRequest.onBeforeRequest.addListener(request => {
    EmailTracker.beforeSendMailRequest(request)
  }, {
    urls: ["*://mail.google.com/sync/*"]
  }, ["requestBody"])
}

// background.js:510-540
static processSyncRequest(request) {
  const rawBuffers = request.requestBody.raw.map(rawPart => rawPart.bytes);
  const uint8ArrayBuffer = EmailTracker.toUint8ArrayBuffer(rawBuffers);
  const decodedRequest = EmailTracker.decodeUint8ArrayToText(uint8ArrayBuffer);
  const emailContents = EmailTracker.getEmailContentsFromRequest(decodedRequest);
  if (!emailContents) return;
  if (EmailTracker.isValidEmailForTracking(emailContents)) {
    const tracker_id = EmailTracker.extractTrackingPixelId(emailContents);
    const subject = EmailTracker.getEmailSubject(emailContents);
    const body = EmailTracker.getEmailBody(emailContents);
    const raw_recipients = EmailTracker.extractToAddresses(emailContents);
    // ...publishes tracked email data
  }
}
```

**Analysis:**
- Decodes Gmail sync requests to extract email metadata and body
- Searches for tracking pixel URL patterns to associate with tracking IDs
- Publishes tracking data including subject, body, and all recipients (To/CC/BCC)
- Blocks tracking pixel requests using declarativeNetRequest to prevent Gmail from loading them
- Data sent to Copper API at `{baseURL}api/v1/companies/{companyId}/email_open_tracking_api/create/`

**Privacy Impact**: High visibility into user email content, but necessary for CRM email tracking feature. Users likely opt-in to this functionality.

---

### 2. LinkedIn Profile Data Scraping
**Severity**: LOW
**Files**: `background.js` (lines 1208-1229), `content-scripts/hosts/linkedin/attempt-match.bundle.js`
**Verdict**: EXPECTED FUNCTIONALITY

**Description:**
Extension extracts LinkedIn profile information when users visit LinkedIn profile pages.

**Code Evidence:**
```javascript
// background.js:1214-1229
const readProperties = async () => {
  class LinkedInV1Reader {
    SELECTORS = {
      personName: ".inline.t-24.v-align-middle.break-words",
      profilePictureUrl: ".pv-top-card-profile-picture__container img",
      companyName: ".org-top-card-summary__title",
      about: "#about + div + div span",
      experience: "#experience + div + div",
      // ...additional selectors for work history
    };
```

**Analysis:**
- Uses DOM selectors to extract name, company, profile picture, about section, and work experience
- Triggered on LinkedIn profile pages (`https://www.linkedin.com/in/*`)
- Optional host permission - requires user consent
- Data used to populate CRM records with LinkedIn profile information

**Privacy Impact**: Scrapes publicly visible LinkedIn data only. Requires optional permission grant.

---

### 3. Third-Party Analytics Integration (Segment.io)
**Severity**: LOW
**Files**: `background.js` (lines 940-1052)
**Verdict**: LEGITIMATE TELEMETRY

**Description:**
Extension sends analytics events to Segment.io for product usage tracking.

**Code Evidence:**
```javascript
// background.js:954-969
class SegmentApiHelper {
  #apiPath = "https://api.segment.io/v1/";
  async #postSegmentApiRequest(url, requestData = {}, segmentWriteKey) {
    if (!segmentWriteKey) {
      throw new Error("No Segment writeKey available.")
    }
    const encodedWriteKey = btoa(`${segmentWriteKey}:`);
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${encodedWriteKey}`
      },
      body: JSON.stringify(requestData)
    });
    return response.json()
  }
```

**Analysis:**
- Standard Segment.io integration for product analytics
- Tracks user events, identifies users, and group properties
- Write key provided by content scripts (not hardcoded)
- Common practice for SaaS applications

**Privacy Impact**: Sends user behavior telemetry to third-party analytics platform. Standard SaaS practice.

---

### 4. Development Artifact - Ngrok URL
**Severity**: LOW
**Files**: `background.js` (line 2577)
**Verdict**: DEVELOPMENT LEFTOVER (BENIGN)

**Description:**
Hardcoded ngrok.io URL found in tracking pixel base URL function.

**Code Evidence:**
```javascript
// background.js:2572-2581
function isDevelopment(appRootUrl) {
  return appRootUrl.includes("copper.cool")
}

function trackingPixelBaseURL() {
  const trackingPixelBaselURL = "https://encrypted.ngrok.io/";
  const hosts = chrome.runtime.getManifest().host_permissions;
  const appRootUrl = hosts[0];
  return isDevelopment(appRootUrl) ? trackingPixelBaselURL : appRootUrl
}
```

**Analysis:**
- Ngrok URL only used when development domain (copper.cool) is detected
- Production builds use app.copper.com from manifest host_permissions
- Typo in variable name: "trackingPixelBaselURL" (should be "baseURL")
- No security risk in production deployments

**Recommendation**: Remove development artifacts before production releases.

---

### 5. Dynamic Content Script Injection
**Severity**: LOW
**Files**: `background.js` (lines 1154-1206)
**Verdict**: LEGITIMATE FUNCTIONALITY

**Description:**
Extension dynamically injects CSS and JavaScript into Gmail/Calendar pages after boot.

**Code Evidence:**
```javascript
// background.js:1168-1200
class HostBootReady extends _baseMessage.default {
  #commonCss = ["assets/vendor.css", "assets/chrome-ext.css", "assets/styles/fonts.css"];
  #commonJs = ["content-scripts/web-extension-tunnel.js", "assets/vendor.js",
               "assets/chrome-ext-chunk.app.js", "assets/chrome-ext.js"];

  async execute(actionArgs, sender) {
    // ...email blocklist check...
    const tabId = tab.id;
    const relevantCssFiles = [...this.#commonCss];
    const relevantJsFiles = [...this.#commonJs, this.#getHostJS(host)];
    return Promise.all([
      chrome.scripting.insertCSS({target: {tabId: tabId}, files: relevantCssFiles}),
      chrome.scripting.executeScript({target: {tabId: tabId}, files: relevantJsFiles})
    ])
  }
}
```

**Analysis:**
- Injects CRM UI components (Ember.js application) into Gmail/Calendar
- Files are bundled with extension (not remotely loaded)
- Triggered only after user email is detected and not blocklisted
- Uses chrome.scripting API (MV3) - safe

**Privacy Impact**: None - legitimate UI injection for CRM features.

---

## False Positive Analysis

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `setTimeout` with function | background.js:260, 1143 | Standard JavaScript timing - not eval |
| Chrome storage access | Multiple files | Legitimate settings/state persistence |
| Email/password regex | content-scripts/hosts/api/*.js | Gmail UI element detection, not keylogging |
| SVG innerHTML | assets/chrome-ext.js:28140+ | React icon rendering - sanitized |

## API Endpoints and Data Flow

### Primary Endpoints
| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://app.copper.com/api/v1/companies/{id}/email_open_tracking_api/create/` | Email tracking | Tracker ID, subject, body, recipients |
| `https://api.segment.io/v1/track` | Analytics events | Event name, user ID, properties |
| `https://api.segment.io/v1/identify` | User identification | User traits, context |
| `https://api.segment.io/v1/group` | Company grouping | Company ID, traits |
| `https://app.copper.com` | Main app backend | CRM data (contacts, opportunities, tasks) |
| `https://api.copper.com` | API backend | Data CRUD operations |

### Authentication
- Uses custom headers: `X-PW-AccessToken`, `X-PW-UserId`, `X-PW-ChromeExtension`
- API credentials stored in chrome.storage.local
- Separate storage keys for incognito mode

### Data Flow Summary
1. **Gmail**: User sends email → Extension intercepts via webRequest → Extracts content → Sends to Copper API → Tracking pixel added
2. **LinkedIn**: User visits profile → Content script scrapes DOM → Sends data to background → Syncs with Copper CRM
3. **Analytics**: User action → Event logged → Sent to Segment.io → Product telemetry
4. **CRM Operations**: User interacts with UI → API calls to app.copper.com/api.copper.com → Data persists in Copper backend

## Permissions Analysis

### Declared Permissions
| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `declarativeNetRequest` | Block tracking pixel loads | Low |
| `notifications` | Email open notifications | Low |
| `scripting` | Inject CRM UI into Gmail/Calendar | Medium |
| `sidePanel` | MV3 sidebar UI | Low |
| `storage` | Settings persistence | Low |
| `tabs` | Tab management for sidepanel | Low |
| `webRequest` | Intercept Gmail sync requests | **HIGH** |

### Host Permissions
- `https://app.copper.com/` - Main backend
- `https://mail.google.com/*` - Gmail integration (required)
- `https://calendar.google.com/*` - Calendar integration (required)
- `https://www.linkedin.com/*` - **Optional** - LinkedIn scraping

**Analysis**: All permissions have legitimate use cases for CRM functionality. The `webRequest` permission is sensitive but necessary for email tracking.

## Overall Risk Assessment

**RISK LEVEL: LOW**

### Rationale
1. **Legitimate Business Purpose**: Copper CRM is a well-known B2B SaaS product with documented CRM features
2. **No Malicious Indicators**: No evidence of:
   - Data exfiltration to unauthorized domains
   - Ad injection or coupon replacement
   - Extension enumeration/killing
   - Remote code execution
   - Keylogging or credential theft
   - Cryptocurrency mining
3. **Transparent Data Collection**: Email and LinkedIn data collection aligns with CRM functionality
4. **Secure Communications**: All API calls use HTTPS
5. **User Consent**: LinkedIn scraping requires optional permission grant

### Privacy Considerations
While technically "LOW RISK" from a malware perspective, users should be aware:
- Extension reads all email content for tracking purposes
- Email subjects, bodies, and recipient lists sent to Copper servers
- LinkedIn profile data extracted when visiting profiles
- Product usage telemetry sent to Segment.io

These are **expected behaviors** for a CRM extension, but users should trust Copper's privacy policy regarding data handling.

### Recommendations for Developers
1. Remove development artifacts (ngrok URL) from production code
2. Consider making email tracking opt-in rather than automatic
3. Add privacy disclosures in extension description about data collection
4. Implement CSP in sidepanel/popup HTML files to prevent XSS

## Conclusion

Copper CRM for Gmail and LinkedIn is a **legitimate enterprise CRM extension** with no malicious functionality detected. The extension implements expected features for CRM integrations including email tracking, contact management, and LinkedIn profile enrichment. Data collection practices, while extensive, are necessary for the stated functionality and appear limited to Copper's own backend services and standard analytics platforms.

**Final Verdict: CLEAN** (with privacy considerations typical of CRM software)
