# Vulnerability Report: Passport

## Metadata
- **Extension ID**: jdnlcdkailpckmchjkgnphhdaoldgjgd
- **Extension Name**: Passport
- **Version**: 6.2.9
- **Users**: ~60,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Passport is an educational time-tracking extension designed for use in school environments, particularly integrated with GG4L (Global Grid 4 Learning) and StackUp platforms. The extension tracks student browsing activity including visited domains, full URLs, time spent on pages, and reading statistics (grade level, readability metrics), then transmits this data to educational platform servers at `engagement-api.gg4l.com` and related domains.

While the data collection is extensive and meets the technical definition of data exfiltration, this behavior is **disclosed and appropriate** for an enterprise educational monitoring tool. The extension is designed for admin-forced installation in educational settings where student activity tracking is an expected feature. However, the privacy implications are significant for end users, warranting a MEDIUM risk classification.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Browsing Activity Tracking and Transmission

**Severity**: MEDIUM
**Files**: js/background/BrowsingData.js, js/page/timetracking_cs.js, js/apis/BrowsingDataAPI.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**:

The extension implements comprehensive browsing activity tracking through content scripts injected on all HTTP/HTTPS pages. It monitors user interactions (mouse movements, scrolling, keyboard arrow keys) to determine "active time" spent on each webpage, then transmits this data along with full URLs and metadata to remote servers.

**Evidence**:

Content script tracking (timetracking_cs.js):
```javascript
// Report activity, when scrollbar is being moved
window.onscroll = async (e) => {
    await pageTracking.reportActivity(e);
}

// Report activity, when mouse is being moved
window.onmousemove = async (e) => {
    await pageTracking.reportActivity(e);
}

async reportActivity(event) {
    const isTabActive = await this.isTabActive();

    if (isTabActive) {
        this.status = "activated";
    }

    // Event is not trusted, when it was fired by some JS code
    if (!event.isTrusted || this.status !== "activated") {
        console.log('Not tracking time -- tab is either in the BG or event is not trusted!');
        return;
    }

    const now = Date.now();
    const secondsToAdd = Math.round((now - this.lastTimeSent) / 1000);

    // Store the new activity and set inactivity handler
    this.storeNewTime(secondsToAdd);
}
```

Data transmission structure (BrowsingData.js):
```javascript
for (const [domain, urls] of Object.entries(domains)) {
    for (const [url, urlData] of Object.entries(urls)) {
        if (!url.startsWith("http")) {
            continue;
        }

        const buckets = urlData.buckets;

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
    }
}

// Post all the time data
const newTimeSendTimeout = await this.postTrackedActivity(visits);
```

Data bucketing implementation:
```javascript
static getBucketID(date) {
    const mins = Math.floor(date.getUTCMinutes() / 15) * 15;
    return `${date.getUTCFullYear()}-${date.getUTCMonth() + 1}-${date.getUTCDate()}-${date.getUTCHours()}-${mins}`;
}

async storeNewTime(domain, url, newSeconds) {
    const userAccountType = await User.retrieveUserAccountType();
    if (userAccountType === ACCOUNT_TYPES.DisabledDistrict) {
        throw new ForbiddenFeatureError();
    }

    // ... stores activity data in chrome.storage.local with 15-minute buckets
}
```

API endpoint construction (PostBrowsingDataRequestBuilder.js):
```javascript
async buildURL() {
    const rootDomain = this.getRootDomain();
    const userId = await Helpers.getItemFromStorage(STORAGE_KEY_NAMES.STACKUP_USER_ID, STORAGE_TYPES.SYNC);

    this.request.setURL(`${rootDomain}/api/3.0/browsingdata/users/${userId}`);
}
```

**Verdict**:

This is a **disclosed educational monitoring tool** designed for enterprise deployment in schools. The data collection serves its stated purpose of tracking student reading time and engagement. Key mitigating factors:

1. **Admin-forced installation**: The extension checks for admin installation with `chrome.management.getSelf()` and `extensionInfo.installType === chrome.management.ExtensionInstallType.ADMIN`
2. **Incognito protection**: Tracking is disabled in incognito tabs: `if ((this.lastTimeSent && now - this.lastTimeSent < this.secondsBetweenSends * 1000) || this.isIncognitoTab) { return; }`
3. **Disabled districts**: The code includes checks for `ACCOUNT_TYPES.DisabledDistrict` that prevent data collection
4. **Legitimate use case**: Educational institutions require this functionality for curriculum assessment and student progress tracking

However, the privacy implications remain significant - full URLs are transmitted (up to 900 characters), creating a comprehensive browsing history. This is appropriately classified as MEDIUM risk due to the sensitive nature of browsing data, even though the collection is disclosed and fits the extension's purpose.

## False Positives Analysis

1. **Authentication Token Storage**: The extension stores `StackUpApiToken` and `passportApiToken` in chrome.storage, which could appear as credential harvesting. However, these are OAuth-style session tokens obtained through legitimate `chrome.identity.getProfileUserInfo()` API and cookie-based SSO, not stolen credentials.

2. **User Email Collection**: The extension retrieves user email via `chrome.identity.getProfileUserInfo()` which is a standard Chrome API for getting the logged-in user's profile. This is not keylogging or unauthorized credential theft.

3. **Cookie Access**: While the extension has `cookies` permission and reads cookies like `gg4l-pub_authzData`, this is for legitimate SSO integration with the educational platform, not cookie harvesting for malicious purposes.

4. **Webpack Bundled Code**: The analyzer flagged the code as "obfuscated", but upon inspection, the deobfuscated source shows clean, readable JavaScript with proper class structures and educational platform integrations. The bundling is from Vue.js webpack compilation, not intentional obfuscation.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| engagement-api.gg4l.com | Primary production API for browsing data | User ID, domain names, full URLs (900 char limit), duration per 15-min bucket, reading grade/metadata, timestamps | MEDIUM - Full browsing history |
| engagement.gg4l.com | Main web portal for dashboard/login | User authentication, session tokens | LOW - Standard auth flow |
| engagement-stgapi.gg4l.com | Staging environment API | Same as production | MEDIUM - Same data in test env |
| engagement-demoapi.gg4l.com | Demo environment API | Demo student browsing data | LOW - Demo data only |
| engagement-devapi.gg4l.com | Development environment API | Same as production | MEDIUM - Dev testing |
| *.mackinvia.com | Mackin e-book platform integration | Book metadata and reading progress | LOW - Limited to e-book context |

All endpoints use HTTPS. API requests include these headers:
- Authorization: Bearer token from StackUp authentication
- UTCOffset: User timezone offset
- ExtensionVersion: Current extension version
- ChromeStoreID: Extension ID

Data transmission occurs every 60 seconds (configurable via `browsingDataIntervalSeconds` in API response).

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Passport is a legitimate educational monitoring extension designed for K-12 school deployments. The browsing activity tracking (domains, full URLs, time spent, reading statistics) is **extensive and privacy-invasive**, but it serves the disclosed purpose of measuring student reading engagement for educational outcomes.

**Why MEDIUM instead of HIGH:**
1. **Transparent purpose**: Extension description states "Track, Measure, and Reward Online Reading"
2. **Enterprise context**: Designed for admin-forced installation in managed school environments
3. **Authentication required**: Only operates when student is logged into the educational platform
4. **Incognito protection**: Respects user privacy mode by disabling tracking
5. **Legitimate vendor**: GG4L is an established educational technology platform provider
6. **Account type controls**: Districts can disable functionality via account type settings

**Why MEDIUM instead of LOW:**
1. **Full URL collection**: Transmits complete URLs (up to 900 chars) including query parameters and paths, creating comprehensive browsing history
2. **Broad scope**: Tracks all HTTP/HTTPS pages, not limited to educational sites
3. **Detailed metadata**: Includes reading grade levels, article text analysis, and behavioral metrics
4. **Wide permissions**: `http://*/*` and `https://*/*` grant access to all websites
5. **User awareness**: Students may not fully understand the extent of monitoring

This extension represents the privacy tradeoff inherent in educational technology platforms. For school-managed deployments where students and parents are informed of monitoring policies, this is an appropriate tool. However, if installed on personal devices without clear consent, the privacy implications would be severe.
