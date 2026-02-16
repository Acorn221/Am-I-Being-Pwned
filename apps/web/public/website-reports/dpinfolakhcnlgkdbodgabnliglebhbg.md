# Vulnerability Report: Passport

## Metadata
- **Extension ID**: dpinfolakhcnlgkdbodgabnliglebhbg
- **Extension Name**: Passport
- **Version**: 6.2.9
- **Users**: ~90,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Passport is an educational engagement tracking extension designed for the GG4L (Global Grid 4 Learning) and StackUp platforms. The extension monitors user browsing activity to "Track, Measure, and Reward Online Reading." It collects detailed browsing data including visited URLs, time spent on each page, reading comprehension metrics, and article content, which are sent to external servers operated by GG4L. While this functionality is disclosed and intended for educational purposes (primarily in K-12 school environments where the extension is typically force-installed by administrators), the extensive data collection raises privacy concerns.

The extension tracks all HTTP/HTTPS sites, authenticates users via Google SSO or cookies, extracts page content using Readability.js, calculates reading grade levels, and sends this data to remote APIs every 60 seconds. The data collection appears to be for legitimate educational monitoring purposes, but the broad permissions and comprehensive tracking capabilities warrant a MEDIUM risk classification.

## Vulnerability Details

### 1. MEDIUM: Extensive Browsing Data Collection and Exfiltration

**Severity**: MEDIUM
**Files**: js/background/BrowsingData.js, js/page/timetracking_cs.js, js/page/getreadabilitystats.js
**CWE**: CWE-359 (Exposure of Private Personal Information)
**Description**: The extension collects comprehensive browsing data including full URLs (up to 900 characters), exact time spent per page (tracked in 15-minute buckets), domain names, reading grade levels, and article text (up to 8,000 characters). This data is transmitted to GG4L servers every 60 seconds.

**Evidence**:

Content script tracking user activity:
```javascript
// timetracking_cs.js
storeNewTime(secondsToAdd) {
    const now = new Date();
    console.log(`Sending time to background: from = ${this.currentHost} | seconds = ${secondsToAdd} | time = ${now.getHours()}:${now.getMinutes()}:${now.getSeconds()}`);
    chrome.runtime.sendMessage({ action: "storeNewTime", url: this.currentURL, domain: this.currentHost, newSeconds: secondsToAdd });
    this.lastTimeSent = now;
}
```

Data transmission to API:
```javascript
// BrowsingData.js
for (const [bucketId, bucketData] of Object.entries(buckets)) {
    const visit = {};
    visit.DomainName = domain;
    visit.Duration = bucketData.duration;
    visit.FullUrl = url.slice(0, 900); // limit the url length to max 900 chars
    visit.Grade = this.sitesData.getPageGrade(domain, url);
    visit.Metadata = this.sitesData.getPageMetadata(domain, url);
    visit.LocalAccruedDateTime = bucketData.bucketTime;
    visits.push(visit);
}
```

API endpoint construction:
```javascript
// PostBrowsingDataRequestBuilder.js
async buildURL() {
    const rootDomain = this.getRootDomain();
    const userId = await Helpers.getItemFromStorage(STORAGE_KEY_NAMES.STACKUP_USER_ID, STORAGE_TYPES.SYNC);
    this.request.setURL(`${rootDomain}/api/3.0/browsingdata/users/${userId}`);
}
```

**Verdict**: This is legitimate functionality for an educational monitoring tool, but the extensive scope of data collection (all HTTP/HTTPS sites) and granular tracking (down to seconds) makes this a privacy-significant feature. The extension is typically deployed in managed educational environments, which provides appropriate context, but individual users installing this would be subject to comprehensive monitoring.

### 2. MEDIUM: Article Content Extraction and Transmission

**Severity**: MEDIUM
**Files**: js/page/getreadabilitystats.js, js/background/SitesData.js
**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
**Description**: The extension extracts full article text (up to 8,000 characters) from visited pages, calculates reading comprehension statistics (Flesch-Kincaid grade level, word count), and sends this content to remote servers.

**Evidence**:

```javascript
// getreadabilitystats.js
storePageGradeAndArticleText((data) => {
    const title = data.title;
    let text = data.text;
    if (!text) {
        return;
    }
    text = text.trim();
    // We can send up to 8000 chars as article's text to the API
    text = text.substr(0, 8000);
    const lastSpaceInText = text.lastIndexOf(" ");
    text = text.substr(0, lastSpaceInText);
    // Check, whether we need to send the article text to the API or not
    chrome.runtime.sendMessage({ action: "sendScrapedText", domain: location.hostname, url: location.href, title, text, grade: data.grade });
});
```

Special handling for Google Docs:
```javascript
downloadDataFromDoc() {
    const BASE_URL = "https://docs.google.com/document/export?format=txt";
    const DOC_ID = `&id=${location.pathname.replace('/document/d/', '').replace(/\/.*/, '')}`;
    // ... fetches and exports Google Doc content as text
}
```

**Verdict**: The extraction and transmission of article content, particularly from Google Docs, is a privacy-sensitive operation. While intended to track educational reading progress, this could capture sensitive personal notes, private documents, or confidential information if used outside a controlled educational environment.

### 3. LOW: Cookie Access for Authentication

**Severity**: LOW
**Files**: js/background/auth/StackupAuthentication.js, js/background/Helpers.js
**CWE**: CWE-522 (Insufficiently Protected Credentials)
**Description**: The extension reads authentication cookies from StackUp and GG4L domains to authenticate users and maintain session state.

**Evidence**:

```javascript
// StackupAuthentication.js
authViaCookie(shallWeLog) {
    return new Promise((resolve, reject) => {
        chrome.cookies.get({ name: COOKIE_NAMES.STACKUP_API_TOKEN, url: Settings.getHostDomain() }, async (cookie) => {
            // ... extracts token from cookie
            const [apiToken, expirationTime] = arr;
            chrome.storage.sync.set({
                [STORAGE_KEY_NAMES.STACKUP_API_TOKEN]: apiToken,
                [STORAGE_KEY_NAMES.STACKUP_API_TOKEN_EXPIRATION]: Date.parse(expirationTime),
                [STORAGE_KEY_NAMES.STACKUP_USER_ID]: userId
            }, () => {
                Logger.logMessage(`Logged in via cookie`, shallWeLog);
                resolve(true);
            });
        });
    });
}
```

**Verdict**: Cookie access is limited to first-party authentication cookies for the extension's own service domains (engagement.gg4l.com and related subdomains). This is standard practice for maintaining authentication state and does not represent credential harvesting from arbitrary sites.

## False Positives Analysis

1. **Obfuscation Flag**: The static analyzer flagged the extension as "obfuscated," but examination reveals this is standard webpack bundling (vue/dist/js/chunk-vendors.js). The core functionality files are well-structured, readable JavaScript with clear variable names and comments.

2. **Permissions Scope**: The extension requests `http://*/*` and `https://*/*` permissions, which appears overly broad. However, this is necessary for the stated purpose of tracking reading activity across all educational websites. The extension does filter out specific sites (e.g., YouTube is blacklisted from grade calculation).

3. **Content Injection**: Content scripts run at `document_start` and `document_end` on all HTTP/HTTPS sites. This is required for accurate time tracking and page analysis, not for malicious code injection. The scripts only collect metrics and don't modify page content.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| engagement-api.gg4l.com/api/3.0/browsingdata/users/{userId} | POST browsing activity | URL, domain, duration, grade level, metadata, timestamps | Medium - detailed tracking data |
| engagement-api.gg4l.com/api/3.0/auth/users/{email} | GET authentication token via Google SSO | User email address | Low - standard OAuth flow |
| engagement-api.gg4l.com/api/3.0/icons | GET passport/service icons | Authentication headers only | Low - UI resources |
| docs.google.com/document/export?format=txt | GET Google Doc text content | Document ID and auth parameters | Medium - extracts private doc content |
| *.gg4l.com | Various API calls (annotations, metrics, notifications, webpage text) | User-generated content and behavioral data | Medium - comprehensive data collection |

All endpoints use HTTPS. The extension supports multiple environments (production, staging, demo, dev, local) with corresponding subdomains.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Passport is a legitimate educational technology tool designed for student engagement tracking in managed K-12 environments. The extension's data collection practices, while extensive, are appropriate for its stated purpose of monitoring and rewarding educational reading. However, several factors elevate this to MEDIUM risk:

1. **Scope of Data Collection**: The extension tracks all HTTP/HTTPS browsing, collects full URLs, precise time measurements, and article content up to 8,000 characters.

2. **Article Content Exfiltration**: Extraction of page text, including specialized handling for Google Docs, means private documents could be inadvertently captured and transmitted.

3. **Deployment Context**: While appropriate in a managed school environment where students/parents are informed and administrators control installation, individual users installing this extension would be subject to comprehensive monitoring without appropriate safeguards.

4. **Cookie Access**: Authentication via cookie extraction is functional but represents additional data collection beyond standard OAuth flows.

**Risk Mitigation Factors**:
- Legitimate educational purpose with known vendor (GG4L)
- Typically force-installed by school administrators (not malware distributed via Web Store)
- Uses HTTPS for all API communications
- Data sent to known educational platform endpoints
- Excludes incognito mode tracking
- Includes "DisabledDistrict" account type checks to prevent usage in disabled deployments

**Recommendation**: This extension is suitable for deployment in managed educational environments where students and parents are informed about the monitoring. It should NOT be installed by individual users unaware of its comprehensive tracking capabilities. The ~90,000 user count suggests widespread educational deployment, consistent with its intended use case.
