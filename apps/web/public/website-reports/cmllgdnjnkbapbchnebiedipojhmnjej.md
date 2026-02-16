# Vulnerability Report: Adaware AdBlock

## Metadata
- **Extension ID**: cmllgdnjnkbapbchnebiedipojhmnjej
- **Extension Name**: Adaware AdBlock
- **Version**: 4.2.1
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Adaware AdBlock is a rebadged version of the open-source uBlock Origin Lite ad blocker with proprietary telemetry code added by Lavasoft/Adaware. The extension collects and exfiltrates user metadata including install tracking parameters, browser fingerprinting data, extension activity metrics, and daily usage patterns to `flow.lavasoft.com`. While the core ad-blocking functionality derives from the legitimate uBlock Origin Lite project, the undisclosed data collection represents a privacy concern for users who expect a simple ad-blocking tool.

The telemetry tracks install attribution (partner IDs, campaign IDs, bundle IDs, offer IDs), browser environment fingerprinting (browser family/version, OS, locale, extension version), unique install identifiers (UUID), install dates, and periodic "daily activity" pings. This data collection is not prominently disclosed in the extension's description, which markets it as "A permission-less content blocker."

## Vulnerability Details

### 1. MEDIUM: Undisclosed Telemetry and User Tracking

**Severity**: MEDIUM
**Files**: `js/adaware-lib/adaware-telemetry.js`, `js/adaware-lib/adaware-ready.js`, `js/adaware-lib/adaware-config.js`, `js/adaware-lib/adaware-systemUtils.js`, `js/adaware-lib/adaware-trackingDataUtils.js`
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension collects and transmits user metadata to Lavasoft's servers without prominent disclosure. Three event types are sent to `https://flow.lavasoft.com/v1/event-stat`:

1. **CompleteInstall**: Sent 2 seconds after installation with full tracking payload
2. **CompleteUpdate**: Sent 2 seconds after each update with version migration data
3. **DailyActivity**: Sent every 24 hours with ongoing activity metrics

**Evidence**:

```javascript
// adaware-config.js
const POST_URL = "https://flow.lavasoft.com/v1/event-stat?";
let data = {
    "productId": "abe",
    "flowUrl": POST_URL,
    "extensionID": chrome.runtime.id,
    "externalData": {
        "PID": "",
        "CampaignID": "",
        "InstallSource": "",
        "BundleID": "",
        "OfferID": "",
        "TemplateID": ""
    }
};
```

```javascript
// adaware-telemetry.js - Data collection structure
const sendCompleteInstallEvent = () => {
    setTimeout(() => {
        adawareTrackingDataUtils.getInstallDate().then((date) => {
            adawareTrackingDataUtils.getInstallId().then((id) => {
                adawareStorageUtils.load('externalData', '', (ext) => {
                    let installDate = new Date(date.installDate).toISOString();
                    installDate = {installDate: installDate}
                    let installId = id;
                    let externalData = ext.externalData;
                    let browserEnvironment = new adawareSystemUtils.browserEnvironmentData();
                    let completeInstallEventData = adawareTrackingDataUtils.trackingData(
                        browserEnvironment, installDate, installId, externalData
                    );
                    sendEvent("CompleteInstall", completeInstallEventData);
                });
            });
        });
    }, 2000);
}
```

```javascript
// adaware-systemUtils.js - Browser fingerprinting
const browserEnvironmentData = function () {
    var browserInfo = getBrowserInfo();
    this.BrowserFamily = browserInfo.name;
    this.BrowserVersion = browserInfo.version;
    this.BrowserLocale = browserInfo.lang;
    this.Platform = getOSName();
    this.ExtensionVersion = manifest.version;
    this.ExtensionLocale = getUILanguage;
};
```

```javascript
// adaware-ready.js - Daily activity pings
const onAllReady = () => {
    lastPing = Date.now();
    setInterval(() => {
        sendDailyActivityData(lastPing);
        lastPing = Date.now();
    }, oneDay); // 24 hour interval
};
```

**Data Collected**:
- Unique install ID (generated UUID)
- Install timestamp
- Browser family and version
- Operating system
- Browser locale and extension locale
- Extension version
- Partner/campaign attribution parameters (extracted from Chrome Web Store URL query parameters)
- Daily activity timestamps
- Previous version on updates

**Verdict**: The telemetry is disclosed in Lavasoft's general privacy policy but not prominently in the extension listing. Users installing an "ad blocker" may not expect outbound telemetry, especially browser fingerprinting. This represents a moderate privacy concern as the data includes persistent identifiers and browser fingerprinting but does not access browsing history or page content.

### 2. MEDIUM: Attribution Parameter Extraction from Chrome Web Store

**Severity**: MEDIUM
**Files**: `js/adaware-lib/adaware-ready.js`
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: On first install, the extension queries all open Chrome Web Store tabs to extract tracking parameters from the URL, then exfiltrates this data to track attribution sources.

**Evidence**:

```javascript
// adaware-ready.js
const getParametersFromStore = () => {
    return new Promise((resolve, reject) => {
        try {
            chrome.tabs.query({
                url: "https://chrome.google.com/webstore/detail/adaware-ad-block/*"
            }, (tabs) => {
                if (tabs.length > 0) {
                    let url = tabs[0].url;
                    if ((url.split("?")).length > 1) {
                        externalData.PID = getUrlParameterFromString(url, "partnerId") ||
                                          adawareConfig.data.externalData.PID;
                        externalData.CampaignID = getUrlParameterFromString(url, "campaignId") || "";
                        externalData.InstallSource = getUrlParameterFromString(url, "sourceTraffic") || "";
                        externalData.BundleID = getUrlParameterFromString(url, "bundleId") || "";
                        externalData.OfferID = getUrlParameterFromString(url, "offerId") || "";
                    }
                    resolve(externalData);
                }
            });
        } catch (err) {
            resolve(externalData);
        }
    });
};
```

**Verdict**: This is a standard affiliate tracking mechanism, but the `tabs` permission enables reading all open Chrome Web Store URLs to extract attribution data. While the data is used for legitimate partner attribution, it demonstrates the extension's capability to query arbitrary tabs.

### 3. LOW: Pre-Whitelisted Lavasoft Domains

**Severity**: LOW
**Files**: `js/adaware-lib/adaware-ready.js`
**CWE**: CWE-284 (Improper Access Control)
**Description**: The extension automatically adds Lavasoft/Adaware domains to the ad-blocking whitelist, ensuring users cannot block the company's own tracking.

**Evidence**:

```javascript
// adaware-ready.js
const setWhitelistedSites = () => {
    const netWhitelistDefault = [
        // ... many Microsoft/Yahoo domains ...
        'jtracking.lulusoft.com',
        'adaware.com',
        'surveymonkey.com',
        'store.adaware.com',
        'pchelpsoft.com',
        'inpixio.com',
        'store.pchelpsoft.com',
        'avanquest.com',
    ];

    getTrustedSites().then(l => {
        const list = Array.from(l);
        if (list.length > 0) {
            setTrustedSites(netWhitelistDefault.concat(list));
        } else {
            setTrustedSites(netWhitelistDefault);
        }
    });
}
```

**Verdict**: This is a minor concern. While it's reasonable for vendors to whitelist their own properties, it reduces user control. The inclusion of `surveymonkey.com` (used for uninstall surveys) and tracking domains is self-serving but not a major security issue.

## False Positives Analysis

The ext-analyzer flagged the extension as "obfuscated" due to webpack bundling in some library files. This is a false positive - the core codebase is readable and matches the upstream uBlock Origin Lite project structure. The Adaware-specific modules (`adaware-lib/`) are clearly written and not obfuscated.

The `web_accessible_resources/` directory contains stub files (noop.js, empty files, etc.) used by the ad-blocking functionality to replace blocked resources. These are legitimate components from uBlock Origin Lite, not malicious payloads.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| flow.lavasoft.com/v1/event-stat | Telemetry collection | Browser fingerprint, install ID, attribution params, daily activity timestamps | MEDIUM - Undisclosed tracking |
| surveymonkey.com | Uninstall survey (via setUninstallURL) | Install metadata as URL parameters | LOW - Standard feedback mechanism |
| adaware.com/ad-block/thank-you | Post-install landing page | None (navigation only) | NONE |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Adaware AdBlock is a legitimate ad-blocking extension built on the open-source uBlock Origin Lite codebase. However, Lavasoft has added proprietary telemetry that collects and exfiltrates user metadata including browser fingerprinting, persistent install identifiers, and daily activity pings. While this data collection is likely disclosed in Lavasoft's privacy policy, it is not prominently advertised in the extension's marketing, which emphasizes it as a "permission-less content blocker."

The privacy concerns are moderate rather than high because:
1. The extension does NOT access browsing history or page content
2. The telemetry focuses on install attribution and browser environment, not user behavior
3. The core ad-blocking functionality is legitimate and derived from a trusted open-source project
4. No evidence of credential theft, malicious data exfiltration, or hidden functionality

However, users installing an ad blocker may reasonably expect privacy-focused behavior, and the undisclosed telemetry with browser fingerprinting and persistent tracking represents a trust violation. The extension would be rated LOW if the telemetry were more clearly disclosed in the extension description, or CLEAN if the telemetry were removed entirely (making it truly equivalent to upstream uBlock Origin Lite).

**Recommendation**: Users concerned about privacy should use the official uBlock Origin Lite extension instead, which provides identical ad-blocking functionality without the proprietary telemetry layer.
