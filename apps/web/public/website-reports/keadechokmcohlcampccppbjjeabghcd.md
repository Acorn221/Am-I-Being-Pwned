# Vulnerability Report: Quick Search Tool

## Metadata
- **Extension ID**: keadechokmcohlcampccppbjjeabghcd
- **Extension Name**: Quick Search Tool
- **Version**: 1.3
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Quick Search Tool is a search engine hijacker that overrides the user's default search provider with quicksearchtool.com. The extension exhibits several concerning behaviors including unauthorized tracking of user activity, cookie harvesting for tracking parameter extraction, automatic tab opening without user consent, and persistent user tracking across install/update/uninstall events. While the extension's stated purpose is to provide a "useful tool from the address bar," the implementation prioritizes monetization and tracking over user value, with multiple HIGH-severity privacy violations.

The extension uses Chrome Web Store cookie data to extract tracking parameters, generates unique user identifiers, sends installation/update/uninstall events to remote servers, and automatically opens new tabs upon installation and updates without user consent. This behavior is undisclosed and deceptive.

## Vulnerability Details

### 1. HIGH: Undisclosed User Tracking and Cookie Harvesting
**Severity**: HIGH
**Files**: background.js (lines 60-67)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension harvests cookies from the Chrome Web Store domain to extract tracking parameters (source, uid, ap) and stores them persistently. It also generates a unique user ID if none exists and tracks the user across install/update/uninstall events without disclosure.

**Evidence**:
```javascript
const qsCookie = await chrome.cookies.get({name: 'qs', url: `https://${extensionDomain}`});
const tracking = new URLSearchParams(qsCookie !== null ? qsCookie.value : '')
await chrome.storage.sync.set({
    src: tracking.get('source') ?? 'nocache',
    uid: tracking.get('uid') ?? `${s4()}${s4()}-${s4()}-${s4()}-${s4()}-${s4()}${s4()}${s4()}`,
    ap: tracking.get('ap') ?? 'appfocus1',
    uc: new Date().toISOString().split('T')[0].replace(/-/g, ''),
})
```

The extension sends tracking events:
```javascript
const sendLog = async (event, page = '', subId2 = '', referrer = '') => {
    const { src, uid, ap, uc } = await getTracking();
    await fetch(`https://log.${extensionDomain}/log?event=${event}&user_id=${uid}&source=${src}&traffic_source=${ap}&subid=${uc}&implementation_id=${extensionVertical}${extensionVersion}&subid2=${subId2}&page=${page}&offer_id=${extensionId}&referrer=${referrer}`)
}
```

**Verdict**: HIGH severity. The extension harvests cookies, generates persistent user identifiers, and tracks user behavior (install, update, uninstall events) without disclosure in the extension description. This constitutes undisclosed data collection.

### 2. HIGH: Automatic Tab Opening Without User Consent
**Severity**: HIGH
**Files**: background.js (lines 42-48, 78, 87)
**CWE**: CWE-610 (Externally Controlled Reference to a Resource)
**Description**: The extension automatically opens new tabs upon installation and update without user interaction or consent. This is a deceptive practice that forces users to visit the extension's monetization pages.

**Evidence**:
```javascript
const openNewTab = async (extraSource = '') => {
    const { src, uid, ap, uc } = await getTracking();
    chrome.tabs.create({
        active: true,
        url: `https://hp.${extensionDomain}?source=${src ?? ''}${extraSource}&uid=${uid ?? ''}&ap=${ap ?? ''}&uc=${uc ?? '17000101'}&i_id=${extensionVertical}${extensionVersion}&cid=${extensionId}&page=newtab`
    });
}
```

Called on install:
```javascript
await openNewTab('-firstopen');
```

Called on update:
```javascript
await sendLog('update');
await openNewTab('-updated')
```

**Verdict**: HIGH severity. Automatically opening tabs without user consent is a deceptive practice that violates user expectations and Chrome Web Store policies.

### 3. MEDIUM: Cookie-Based Remote Configuration
**Severity**: MEDIUM
**Files**: background.js (lines 69-80)
**CWE**: CWE-15 (External Control of System or Configuration Setting)
**Description**: The extension reads a 'ntp' cookie from the extension domain to determine whether to open a new tab on installation. This allows remote control of extension behavior without user knowledge.

**Evidence**:
```javascript
const ntpCookie = await chrome.cookies.get({name: 'ntp', url: `https://${extensionDomain}`});
if (ntpCookie !== null) {
    switch (parseInt(ntpCookie.value)) {
        case 0:
            break;
        case 1:
            chrome.tabs.create({selected: true});
            break;
        default:
            await openNewTab('-firstopen');
            break;
    }
}
```

**Verdict**: MEDIUM severity. While cookie-based configuration is not inherently malicious, using it to control deceptive behaviors (automatic tab opening) without user knowledge is problematic.

## False Positives Analysis

- **Search Engine Override**: The manifest declares `chrome_settings_overrides.search_provider`, which is the stated purpose of the extension. This is NOT a vulnerability in itself, though the extension is classified as a search hijacker.
- **declarativeNetRequest**: Used to append tracking parameters to search queries, which is expected for affiliate/monetization purposes.
- **Dynamic Tab Window Positioning** (lines 93-112): Creates a new window for tabs opened from Yahoo search results. This appears to be a monetization feature related to Yahoo search partnerships and is not a security vulnerability per se.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| log.quicksearchtool.com | Event tracking | event, user_id, source, traffic_source, subid, implementation_id, subid2, page, offer_id, referrer | HIGH - Persistent user tracking |
| query.quicksearchtool.com | Search queries | Search terms + tracking parameters (source, uid, ap, uc, i_id, cid) | MEDIUM - Search tracking |
| hp.quicksearchtool.com | Homepage/landing pages | source, uid, ap, uc, i_id, cid, page | MEDIUM - User tracking |
| search.quicksearchtool.com | Search suggestions | query | LOW - Standard autocomplete |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**: This extension is a search hijacker that employs multiple deceptive and privacy-invasive practices. Key concerns include:

1. **Undisclosed tracking**: The extension harvests cookies, generates persistent user IDs, and tracks user behavior across install/update/uninstall events without disclosure
2. **Automatic tab opening**: Forces users to visit monetization pages on install and update without consent
3. **Cookie harvesting**: Extracts tracking data from Chrome Web Store cookies for attribution tracking
4. **Remote configuration**: Uses cookies to control extension behavior remotely

While the extension's core functionality (search engine override) is disclosed in the manifest, the tracking, cookie harvesting, and automatic tab opening behaviors are NOT disclosed in the extension description ("Search the web using this useful tool from the address bar"). This constitutes undisclosed data collection and deceptive behavior.

The 200,000 user base makes this a significant privacy concern. The extension should be classified as HIGH risk due to undisclosed tracking and deceptive practices.
