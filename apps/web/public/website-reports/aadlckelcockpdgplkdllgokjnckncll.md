# AWAX Extension Security Analysis Report

## Metadata
- **Extension Name**: AWAX
- **Extension ID**: aadlckelcockpdgplkdllgokjnckncll
- **Version**: 1.3.31
- **User Count**: ~10,000 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

AWAX is a content blocking extension built on uBlock Origin Lite (uBOL) framework with additional custom features for ad/sponsored post filtering on Facebook and YouTube (via bundled SponsorBlock). The extension implements a **licensing/subscription model** with a 3-day trial that phones home to `awaxtech.com` to validate activation keys and track device registration.

**Overall Risk Assessment**: **MEDIUM**

The extension serves its stated purpose (ad blocking) but raises privacy concerns due to:
1. Device fingerprinting and user tracking sent to third-party server
2. Remote kill switch functionality that can disable the extension
3. Collection of email addresses via Chrome identity API
4. No clear privacy policy or disclosure of data collection practices

## Vulnerability Details

### 1. Device Fingerprinting and Phone-Home Behavior

**Severity**: MEDIUM
**Files**: `/js/background.js` (lines 1054-1061, 1133-1142, 1145-1161)
**Code**:
```javascript
addDevice: function () {
    apiReq('/firstOpen', {
        "deviceID": µb.awax.settings.did,
        "deviceName": "Chrome: " + navigator.userAgent + ", user_email:" + µb.awax.settings.email,
        "pushID": µb.awax.settings.email
    }, function (data) {
        µb.awax.loadNewFilters(data?.validation);
    });
}
```

**Verdict**: The extension generates a device ID (either from Chrome user email hash or MD5 of current date/time) and sends it along with the full user agent string and user email to `https://awaxtech.com/api` on first installation. This creates a persistent device fingerprint that can track users across sessions.

**API Endpoint**: `https://awaxtech.com/api/firstOpen` (POST)
**Data Sent**: Device ID, full user agent, email address

---

### 2. Email Address Collection via Identity API

**Severity**: MEDIUM
**Files**: `/js/background.js` (lines 1189-1191, 999)
**Code**:
```javascript
chrome.identity.getProfileUserInfo((userInfo) => {
    µBlock.awax.loadSettings(userInfo);
});

// Inside loadSettings:
email: (userInfo.email) ? userInfo.email : "undefined",
```

**Verdict**: The extension requests `identity.email` permission and collects the user's Chrome profile email address. This is stored locally and transmitted to the remote server during device registration and key validation checks. No clear consent or privacy disclosure is provided for this data collection.

---

### 3. Remote Kill Switch / Forced Disable

**Severity**: MEDIUM
**Files**: `/js/background.js` (lines 1106-1131)
**Code**:
```javascript
checkDate: function () {
    if (µb.awax.settings.timer < Date.now()) {
        if (µb.awax.settings.vk !== undefined) {
            µb.awax.timeCheckKey(µb.awax.settings.vk);
        }
        // ...
    }
    if ((µb.awax.settings.vd && µb.awax.settings.vd < Date.now()) ||
        (!µb.awax.settings.vd && (µb.awax.settings.lic !== '99999month') &&
         ((µb.awax.settings.sd + 1000 * 60 * 60 * 24 * 3) < Date.now()))) {
        µb.awax.disable();
        µb.awax.enableFb(false);
    }
}
```

**Verdict**: The extension implements a 3-day trial period (hardcoded as 72 hours from `settings.sd`). After expiration, it automatically disables itself unless a valid license key is entered. Daily checks to `awaxtech.com/api/web/checkKeyAndDevice` allow remote control over extension activation status. If the server returns `validation: false`, the extension immediately disables all filtering.

---

### 4. Excessive Permissions

**Severity**: LOW
**Files**: `manifest.json` (lines 271-283)
**Code**:
```json
"host_permissions": ["<all_urls>"],
"permissions": [
    "activeTab",
    "scripting",
    "storage",
    "unlimitedStorage",
    "declarativeNetRequest",
    "declarativeNetRequestFeedback",
    "identity",
    "identity.email"
]
```

**Verdict**: The extension requests `<all_urls>` host permissions and broad content blocking permissions. While these are necessary for an ad blocker, the `identity.email` permission is excessive and not clearly justified to users. The combination with phone-home behavior creates privacy concerns.

---

### 5. Facebook Sponsored Post Detection (Not Malicious)

**Severity**: CLEAN
**Files**: `/js/fb.js` (entire file)
**Code**:
```javascript
const faceN = {
    filters: {
        r: ["patrocinado", "sponsored", "sponsorisé", "sponsorizzata", ...],
        l: ["div[id^='feedsubtitle'] > :first-child", ...],
    }
};
```

**Verdict**: FALSE POSITIVE - The Facebook content script uses mutation observers to detect and hide sponsored posts by matching text strings in multiple languages. This is legitimate functionality for an ad blocker. No data exfiltration occurs in this module.

---

### 6. SponsorBlock Integration (Legitimate Third-Party)

**Severity**: CLEAN
**Files**: `/sb/content.js`, `/sb/vendor.js` (658KB total)
**Code**: Bundled SponsorBlock YouTube extension code

**Verdict**: FALSE POSITIVE - The extension includes a legitimate copy of the SponsorBlock extension (open-source GPL project) to skip sponsored segments in YouTube videos. Settings are synced via `chrome.storage.sync` with key `disableSkipping`. No malicious behavior detected in SponsorBlock components.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| Chrome identity API | background.js:1189 | Required for email collection feature (disclosed in permissions) |
| Storage sync operations | background.js:927, 958 | Normal extension settings persistence |
| User agent collection | background.js:1056 | Sent to server but standard practice for browser detection |
| Mutation observers | fb.js:119-139 | Used for detecting dynamic Facebook content changes |
| SponsorBlock network calls | sb/vendor.js | Legitimate API calls to SponsorBlock backend |

---

## API Endpoints

| Endpoint | Method | Data Sent | Purpose |
|----------|--------|-----------|---------|
| `awaxtech.com/api/firstOpen` | POST | deviceID, deviceName, pushID (email) | Initial device registration |
| `awaxtech.com/api/web/checkForUpdate` | GET | None | Check for filter list updates |
| `awaxtech.com/api/web/checkKeyAndDevice` | POST | deviceID, key | License key validation |
| `awaxtech.com/api/extendKey` | POST | deviceID, key, oldKey | License key renewal |

**Note**: All API calls use `mode: 'no-cors'` which prevents reading responses in some cases, but data is still transmitted.

---

## Data Flow Summary

1. **Installation**: Extension requests Chrome user email → Generates device ID → Sends to `awaxtech.com/api/firstOpen`
2. **Daily Check**: Every 24 hours, validates license key against remote server
3. **Trial Expiration**: After 3 days, disables all filtering unless valid key provided
4. **Facebook Filtering**: Detects sponsored posts locally, stores filter rules in `chrome.storage.local._awaxfilters`
5. **YouTube Filtering**: Uses bundled SponsorBlock to skip sponsor segments, communicates with SponsorBlock API independently

**External Data Transmission**:
- Device fingerprint (email hash + user agent) → `awaxtech.com`
- User email address → `awaxtech.com`
- License key validation requests → `awaxtech.com`

**Local Data Storage**:
- `chrome.storage.local.awax`: Settings (deviceID, email, timestamps, license status)
- `chrome.storage.local._awaxfilters`: Facebook ad filter rules
- `chrome.storage.sync`: SponsorBlock settings

---

## Overall Risk Assessment

**Risk Level**: **MEDIUM**

### Justification:
The extension performs its advertised functionality (ad/sponsored content blocking) effectively using legitimate open-source frameworks (uBlock Origin Lite + SponsorBlock). However, it implements invasive tracking and licensing mechanisms that are not clearly disclosed:

**Concerns**:
1. ✗ Collects and transmits personally identifiable information (email addresses)
2. ✗ Creates persistent device fingerprints without clear user consent
3. ✗ Implements remote kill switch that can disable functionality
4. ✗ Phones home daily with device validation checks
5. ✗ No visible privacy policy or data collection disclosure
6. ✗ Uses "no-cors" mode which suggests attempting to hide network activity from inspection

**Mitigating Factors**:
1. ✓ Core blocking functionality uses legitimate uBOL framework
2. ✓ No evidence of malicious payload injection
3. ✓ No DOM manipulation for ad injection or click hijacking
4. ✓ No cryptocurrency mining or residential proxy behavior
5. ✓ Declarative Net Request API (safe, sandboxed blocking)
6. ✓ SponsorBlock integration is legitimate and unchanged

### Recommendation:
Users should be informed that this extension collects email addresses and device information for licensing purposes. The extension would be classified as CLEAN if proper privacy disclosures were added and users explicitly consented to the data collection. As it stands, the lack of transparency warrants a MEDIUM risk classification for privacy violations.
