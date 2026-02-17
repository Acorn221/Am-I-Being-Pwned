# Vulnerability Report: Smart Searching Tab

## Metadata
- **Extension ID**: iacoifmgngnkjphlhpencjhenbngoheg
- **Extension Name**: Smart Searching Tab
- **Version**: 1.5.2
- **Users**: ~80,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Smart Searching Tab is a new tab replacement extension that redirects users to a search portal hosted at hsmartsearching.net. The extension collects tracking parameters via cookies and URL parameters, generates unique user identifiers, and sends telemetry data to remote servers. While the extension's primary behavior aligns with its stated purpose of providing "popular trending searches," it engages in undisclosed user tracking, automatically closes Chrome Web Store tabs during installation to prevent review/uninstallation, and implements aggressive window manipulation behavior for Yahoo search results.

The extension exhibits several privacy-concerning behaviors including persistent user tracking via generated GUIDs, beacon-style telemetry transmission without user notification, and automatic CWS tab closure to reduce uninstall likelihood. However, it does not appear to collect sensitive browsing data beyond the tracking context it establishes.

## Vulnerability Details

### 1. HIGH: Undisclosed User Tracking and Telemetry Collection

**Severity**: HIGH
**Files**: central.js, log.js, utility.js, config.js
**CWE**: CWE-359 (Exposure of Private Information)

**Description**: The extension implements comprehensive user tracking without clear disclosure in its description ("Smart Searching replaces your new tab page and provides you with popular trending searches!"). It generates persistent user identifiers, collects tracking parameters from cookies, and transmits telemetry to log.hsmartsearching.net on installation, updates, and sync events.

**Evidence**:

```javascript
// Generates persistent GUID for user tracking
generateID() {
    return this.GUID();
}

GUID() {
    try {
        function s4() {
            return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
        }
        return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
            s4() + '-' + s4() + s4() + s4();
    }
    catch (err) {
        return "00000000-0000-0000-0000-000000000000";
    }
}

// Telemetry transmission with user ID, source, traffic source, subids
send (event = '',optional = '',optional2 = '',optional3 = ''){
    this.store.getTracking(function(e){
        fetch(`https://log.hsmartsearching.net/log?event=${event}&user_id=${e.uid}&source=${e.source}&traffic_source=${e.ap}&subid=${e.uc}&implementation_id=searchmanager_${chrome.app.getDetails().version}&subid2=${chrome.app.getDetails().id}&page=${optional}&offer_id=${optional2}&referrer=${optional3}`)
        .then(function(){
                console.log('Success');
        }).catch(function(){
            console.log('Failure');
        });
    });
}
```

The extension collects tracking parameters from cookies on hsmartsearching.net domain:

```javascript
findCValue (value) {
    this.config.running++;
    let callback = this.setCVaule;
    let config = this.config;
    chrome.cookies.get({"name": value, "url": "https://hsmartsearching.net" }, function (cookieValue)
        {
            callback(cookieValue,config);
            return;
        }
    );
}
```

**Verdict**: This constitutes undisclosed tracking. The extension description does not mention user tracking, analytics, or data collection, yet it implements persistent user identification and transmits events to remote logging servers.

### 2. MEDIUM: Chrome Web Store Tab Closure During Installation

**Severity**: MEDIUM
**Files**: utility.js
**CWE**: CWE-506 (Embedded Malicious Code)

**Description**: During installation, the extension automatically searches for and closes any Chrome Web Store tabs containing the extension's ID. This prevents users from reading reviews, checking permissions, or easily uninstalling the extension immediately after installation.

**Evidence**:

```javascript
onInstall (typ){
    //TYP
    let check = this.isVailidCWS;
    chrome.tabs.create({ "url": typ + "&typ=true" });
    chrome.tabs.query({}, function (tabs) {
        for (let i = 0; i < tabs.length; i++) {
            if (check(tabs[i].url)) {
                chrome.tabs.remove(tabs[i].id);  // Closes CWS tab
            }
        }
    });
}

isVailidCWS (url){
    if(url != null && url.indexOf(chrome.app.getDetails().id) > 0 && url.indexOf("webstore") > 0){
        return true;
    }else {
        return false;
    }
}
```

**Verdict**: While not directly malicious, this is a dark pattern designed to reduce uninstall rates by making it harder for users to return to the CWS page. This behavior is adversarial to user agency.

### 3. MEDIUM: Aggressive Window Manipulation for Yahoo Search

**Severity**: MEDIUM
**Files**: search.js
**CWE**: CWE-451 (User Interface (UI) Misrepresentation of Critical Information)

**Description**: The extension monitors Yahoo search results and automatically creates new split windows (52% width) for new tabs opened from Yahoo search pages. This modifies expected browser behavior without user consent and could be disorienting.

**Evidence**:

```javascript
chrome.tabs.onCreated.addListener(function (clickedTab) {
    if (typeof clickedTab.openerTabId !== "undefined" && clickedTab.url == "") {
        chrome.tabs.get(clickedTab.openerTabId, function (serpTab) {
            if (serpTab.url.includes("search.yahoo.com/yhs") && (serpTab.url.includes("hspart=pty") || serpTab.url.includes("hspart=adk")) && serpTab.url.includes(_Config.getUserId())) {
                chrome.windows.getCurrent(function (winSize) {
                    if (typeof clickedTab.pendingUrl === 'undefined' || (typeof clickedTab.pendingUrl !== 'undefined' && clickedTab.pendingUrl.indexOf('chrome://') < 0)) {
                        var widthUsed = Math.ceil(winSize.width * 0.52);
                        var leftUsed = winSize.left + Math.abs(Math.ceil(winSize.width * 0.48));
                        var heightUsed = Math.ceil(winSize.height);
                        chrome.windows.create({
                            tabId: clickedTab.id, height: heightUsed, width: widthUsed, top: winSize.top, left: leftUsed, type: 'normal'
                        });
                    }
                });
            }
        });
    }
});
```

**Verdict**: This creates a split-screen window layout automatically when users click search results from Yahoo pages associated with this extension's affiliate tracking. While potentially monetization-related, it modifies browser UX without disclosure.

### 4. LOW: Remote Configuration Fetching

**Severity**: LOW
**Files**: utility.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)

**Description**: The extension fetches a "user class" identifier from a remote endpoint without HTTPS verification of response integrity.

**Evidence**:

```javascript
fetchUC () {
    this.config.running++;
    let callback = this.setCVaule;
    let config = this.config;
        fetch('https://hp.hsmartsearching.net/Userclass')
    .then(function(e){
        return e.json();
    })
    .then(function(e){
        if(e.length != 12){
            callback({"name": "uc", "value" : e},config)
        }else{
            callback({"name": "uc", "value" : "17000101"},config)
        }
        return;
    })
    .catch(function(e){
        return;
    })
}
```

**Verdict**: While the fetched value appears to be a classification identifier rather than executable code, this pattern could theoretically be used to change extension behavior based on remote server responses. The current implementation is benign but represents a remote configuration mechanism.

## False Positives Analysis

**Cookie Access**: The extension requests cookies permission and accesses cookies on hsmartsearching.net domain. While this could be used maliciously, in this case it's used only to retrieve tracking parameters that the extension itself (or related properties) set. It does not harvest cookies from arbitrary domains.

**New Tab Override**: Overriding the new tab page is the extension's stated purpose, so this is expected behavior.

**Tabs Permission**: Used for legitimate purposes (opening tabs on install, detecting Yahoo search tabs). No evidence of tab URL monitoring beyond the specific Yahoo search detection.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| log.hsmartsearching.net/log | Event tracking | user_id, source, traffic_source, subid, implementation_id (version), subid2 (extension ID), event type, optional page/offer/referrer | MEDIUM - Persistent user tracking |
| hp.hsmartsearching.net/Userclass | Fetch user classification | None (GET request) | LOW - Remote config |
| hp.hsmartsearching.net/ | New tab redirect | Multiple tracking params (ap, source, uc, uid, cid, page, i_id) | MEDIUM - User tracking via URL params |
| hp.hsmartsearching.net/uninstall | Uninstall page | user_id, source, ap, uc, iid, cid | LOW - Exit survey |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**: This extension engages in undisclosed user tracking with persistent identifier generation and telemetry transmission. The product description makes no mention of analytics, tracking, or data collection. Additionally, it implements adversarial patterns including automatic Chrome Web Store tab closure during installation (to prevent easy uninstallation) and aggressive window manipulation for Yahoo search results.

While the extension does not appear to exfiltrate sensitive browsing data or credentials, the combination of undisclosed tracking, persistent user identification, dark patterns to reduce uninstalls, and unexpected window manipulation behaviors warrant a HIGH risk rating. With 80,000 users, this represents significant privacy exposure.

The extension should either:
1. Clearly disclose tracking and data collection practices in its description and privacy policy
2. Remove the CWS tab closure mechanism
3. Make the Yahoo window manipulation optional or more transparent to users

Users concerned about privacy should avoid this extension in favor of alternatives that are more transparent about their data practices.
