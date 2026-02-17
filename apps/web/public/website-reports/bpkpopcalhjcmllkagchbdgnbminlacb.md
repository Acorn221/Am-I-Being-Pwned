# Vulnerability Report: MSN Homepage

## Metadata
- **Extension ID**: bpkpopcalhjcmllkagchbdgnbminlacb
- **Extension Name**: MSN Homepage
- **Version**: 1.0.0.7
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

MSN Homepage is a Microsoft-affiliated browser extension that sets MSN as the user's homepage and startup page. The extension implements comprehensive telemetry and tracking capabilities, sending user data including a unique machine ID, browser information, extension usage statistics, and partner/channel tracking codes to Microsoft endpoints. While the data collection is disclosed in the extension's purpose (setting MSN as homepage), the extent of tracking and the generation of persistent machine IDs raise privacy concerns. The extension also manipulates browser cookies and uses declarativeNetRequest to inject tracking parameters into MSN URLs.

The extension is from a reputable source (Microsoft) and serves its stated purpose legitimately, but the tracking infrastructure is more extensive than minimally necessary for providing homepage functionality.

## Vulnerability Details

### 1. MEDIUM: Persistent Machine ID Generation and Telemetry Collection

**Severity**: MEDIUM
**Files**: ping.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension generates a unique, persistent machine ID (GUID) and stores it in local storage. This ID is then sent to Microsoft's telemetry endpoints along with extensive browser and usage metadata every 24 hours and on install/update events.

**Evidence**:
```javascript
// Generates unique machine ID
function guid() {
    function s4() {
        return Math.floor((1 + Math.random()) * 0x10000)
            .toString(16)
            .substring(1);
    }
    var MachineGUID = s4() + s4() + s4() + s4() + s4() + s4() + s4() + s4();
    MachineGUID = MachineGUID.toLocaleUpperCase();
    chrome.storage.local.set({
        [MACHINE_ID]: MachineGUID
    });
    return MachineGUID;
}

// Telemetry ping function
function SendPingDetails(status) {
    var extensionVersion = manifestData.version;
    var OS = navigator.userAgent.substring(startIndex + 1, endIndex).replace(/\s/g, '');
    var browserVersion = navigator.userAgent.substr(navigator.userAgent.indexOf("Chrome")).split(" ")[0].replace("/", "");

    chrome.storage.local.get([PARTNER_CODE, CHANNEL, MACHINE_ID, DPC, MARKET], (items) => {
        var pingURL = 'https://go.microsoft.com/fwlink/?linkid=2243942&';
        var tVData = 'TV=is' + pc + '|pk' + extensionName + '|tm' + browserLanguage + '|bv' + browserVersion + '|ex' + extensionId + '|es' + status;
        if (items[CHANNEL])
            tVData = tVData + "|ch" + items[CHANNEL];
        if (items[DPC])
            tVData = tVData + "|dp" + items[DPC];
        var UD = 'MI=' + items[MACHINE_ID] + '&LV=' + extensionVersion + '&OS=' + OS + '&TE=37&' + tVData;
        UD = btoa(encodeURI(UD));
        pingURL = pingURL + 'UD=' + UD + '&ver=2';
        pingURL = encodeURI(pingURL);
        fetch(pingURL);
    });
}
```

**Verdict**: This is a medium-severity privacy concern. While Microsoft is a reputable company and the extension's purpose involves integration with Microsoft services, the generation of a persistent cross-session identifier enables long-term tracking of the user across extension reinstalls and browser sessions. The telemetry includes browser fingerprinting data (OS, browser version, language) combined with the unique ID.

### 2. MEDIUM: Cookie Manipulation and Cross-Domain Tracking

**Severity**: MEDIUM
**Files**: ping.js
**CWE**: CWE-565 (Reliance on Cookies without Validation and Integrity Checking)

**Description**: The extension sets tracking cookies on the .bing.com domain (_NTPC and _DPC) containing partner codes and distribution channel information. It also reads cookies from browserdefaults.microsoft.com and chrome.google.com to extract attribution/channel data.

**Evidence**:
```javascript
chrome.storage.local.get([MACHINE_ID, "ExtensionUpdated", "updatePingSent", DPC, PARTNER_CODE], (items) => {
    // Sets '_NTPC' session cookies in bing.com domain
    chrome.cookies.set({
        url: bingUrl,
        domain: '.bing.com',
        name: '_NTPC',
        value: !items[PARTNER_CODE]? defaultPC : items[PARTNER_CODE],
        sameSite: 'no_restriction',
        secure: true
    }, function (cookie) {});

    var _dpc = items[DPC] ?items[DPC] : "organic";
    if (_dpc != undefined && _dpc != "" && _dpc != null) {
        chrome.cookies.set({
            url: bingUrl,
            domain: '.bing.com',
            name: '_DPC',
            value: _dpc,
            sameSite: 'no_restriction',
            secure: true
        }, function (cookie) {});
    }
});

// Reads cookies from chrome.google.com to extract attribution
chrome.cookies.get({ url: chromeWS, name: '__utmz' }, function (cookie) {
    if (cookie) {
        var chromeWSChannel = getChromeWSChannel(cookie.value);
        if (chromeWSChannel != "") {
            details.channel = chromeWSChannel;
        }
        chrome.cookies.remove({ url: chromeWS, name: '__utmz' });
    }
});
```

**Verdict**: The extension uses broad cookie permissions to set tracking cookies across Microsoft domains and read attribution data from Chrome Web Store cookies. While this is part of Microsoft's legitimate attribution tracking for extension distribution, it represents cross-domain tracking capability that extends beyond basic homepage functionality.

### 3. LOW: DeclarativeNetRequest URL Parameter Injection

**Severity**: LOW
**Files**: ping.js
**CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)

**Description**: The extension uses declarativeNetRequest to intercept MSN homepage URLs and inject tracking parameters (pc and ocid) based on stored partner codes.

**Evidence**:
```javascript
function addHomepageRedirectRule(redirectRuleId, partnerCode, defaultPartnerCode, blockingURL) {
    var searchRedirectRule = {
        id: redirectRuleId,
        priority: 1,
        action: {
            type: "redirect",
            redirect: {
                transform: {
                    queryTransform: {
                        addOrReplaceParams: [
                            {
                                key: "ocid",
                                value: partnerCode  ? "MSNHP_" + partnerCode : "MSNHP_" + defaultPartnerCode
                            },
                            {
                                key: "pc",
                                value: partnerCode ? partnerCode : defaultPartnerCode
                            }
                        ],
                        removeParams: ["osmkt"]
                    }
                }
            }
        },
        condition: {
            urlFilter: blockingURL,
            resourceTypes: ["main_frame", "xmlhttprequest"]
        }
    };
}
```

**Verdict**: This is standard affiliate/attribution tracking for homepage extensions. The parameters are added to Microsoft's own MSN domain and serve legitimate business purposes for tracking extension distribution channels. Low severity as it's disclosed behavior and limited to Microsoft domains.

## False Positives Analysis

1. **Homepage Override**: The extension declares `chrome_settings_overrides` to set MSN as homepage - this is the stated purpose of the extension and is not malicious.

2. **Broad Host Permissions**: The extension requests `https://*/*` and `http://*/*` host permissions, but analysis of the code shows these are only used for cookie manipulation on specific Microsoft domains (bing.com, browserdefaults.microsoft.com) and Chrome Web Store. Not used for general web scraping.

3. **Static Analysis Exfiltration Flag**: ext-analyzer flagged `chrome.storage.local.get → fetch` as potential exfiltration. This is legitimate telemetry to Microsoft's own infrastructure for extension analytics.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://go.microsoft.com/fwlink/?linkid=2243942 | Telemetry ping | Machine ID, browser version, OS, extension version, partner code, channel, language | Medium - persistent identifier tracking |
| https://go.microsoft.com/fwlink/?linkid=2128904 | Install redirect | Extension ID, partner code, browser, market, channel, machine ID | Medium - attribution tracking |
| https://go.microsoft.com/fwlink/?linkid=2138838 | Uninstall feedback | Extension ID, market, machine ID, browser | Low - legitimate feedback |
| https://www.msn.com | Homepage | Query parameters with tracking codes | Low - expected behavior |
| https://www.bing.com | Cookie setting | Partner code cookies | Medium - cross-site tracking |
| https://browserdefaults.microsoft.com | Cookie reading | Reads installation attribution | Low - legitimate attribution |
| https://chrome.google.com | Cookie reading | Reads UTM parameters from Web Store | Low - legitimate attribution |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
This is a legitimate Microsoft extension that performs its stated function (setting MSN as homepage) but implements extensive tracking and telemetry infrastructure. The key privacy concerns are:

1. Generation of persistent machine IDs that enable long-term user tracking across sessions
2. Cross-domain cookie manipulation for attribution and tracking purposes
3. Daily telemetry pings with browser fingerprinting data

The extension comes from a reputable source (Microsoft) and the tracking serves legitimate business purposes (distribution channel attribution, usage analytics). However, the extent of data collection and the use of persistent identifiers go beyond what's minimally necessary for homepage functionality.

Users should be aware that installing this extension enables Microsoft to track their browser configuration and extension usage over time. The data is sent to Microsoft's own infrastructure, not third parties, which reduces risk compared to unknown actors.

**Rated MEDIUM** rather than HIGH because:
- The extension is from Microsoft, a reputable company with published privacy policies
- The tracking is limited to Microsoft's own services
- The core functionality (setting homepage) is disclosed and legitimate
- No evidence of credential theft, malicious code execution, or undisclosed third-party data sharing

Users concerned about privacy may want to avoid this extension and manually set their homepage instead.
