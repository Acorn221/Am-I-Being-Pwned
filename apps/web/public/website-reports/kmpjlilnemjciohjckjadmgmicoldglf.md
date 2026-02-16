# Vulnerability Report: Dyknow Cloud

## Metadata
- **Extension ID**: kmpjlilnemjciohjckjadmgmicoldglf
- **Extension Name**: Dyknow Cloud
- **Version**: 7.11.06.64
- **Users**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Dyknow Cloud is a legitimate enterprise classroom monitoring extension designed for educational institutions to monitor and control student Chromebook devices during class sessions. The extension is designed for ChromeOS environments and implements comprehensive monitoring features including activity tracking, screen capture, tab control, URL filtering, and application blocking.

While the extension collects extensive student activity data and has powerful remote control capabilities, all functionality is consistent with its stated purpose as an educational monitoring tool. The data collection is disclosed and expected for classroom management software. The extension only operates on ChromeOS devices and communicates exclusively with official Dyknow infrastructure (api.dyknow.me, oauth.dyknow.me, satellite01.dydev.me).

## Vulnerability Details

### 1. LOW: Extensive Data Collection (Expected for Product Category)
**Severity**: LOW
**Files**: activityCollector.js, pal.js, logger.js, clients/satellite.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension collects comprehensive student activity data including browsing history, active applications, tab URLs, window titles, device information, and periodic screenshots of active browser tabs.

**Evidence**:
```javascript
// activityCollector.js tracks all user activity
activityCollector.subscribe = function (){
    activityCollector.pal.on("activity", activityCollector.onActivity);
```

```javascript
// pal.js monitors browser activity changes
this._processTabChangedEvent = function(tab) {
    activity = getActivity(ACTIVITY.NAME.BROWSER,ACTIVITY.IDENTIFIER.BROWSER, url, tab.title);
    if (tab.id){
        activity.tab_id = tab.id;
    }
    if (hasActivityChanged(activity)) {
        Logger.info("Navigation Changed", tab);
        changeActivity(activity);
    }
}
```

```javascript
// thumbnailActiveTab.js captures visible tab screenshots
safeChrome.tabs.captureVisibleTab( windowId, {}, function (dataUrl) {
    if (dataUrl) {
        thumbnailActiveTab.getImageBlob(dataUrl, width, height, resolve, reject);
    }
});
```

**Verdict**: This is standard functionality for classroom monitoring software. The Chrome Web Store description states "The Chromebook extension for Dyknow Cloud" and the software is marketed as a classroom management tool. Teachers need these capabilities to monitor student activity during class.

### 2. LOW: Remote Tab Control Capabilities
**Severity**: LOW
**Files**: directControl.js, cabra/helper/directControl.js
**CWE**: N/A (Expected Functionality)
**Description**: The extension can remotely close tabs, retrieve all open tabs with URLs and titles, and manage window focus. Teachers can view and close tabs on student devices.

**Evidence**:
```javascript
// directControl.js allows remote tab closure
closeTab: function (windowId, tabId){
    return new Promise(function(resolve, reject){
        safeChrome.tabs.get(tabId, function (origTab){
            safeChrome.tabs.remove(tabId, function () {
                // handles window cleanup after tab removal
            });
        });
    });
}
```

```javascript
// getTabs retrieves all browser tabs with metadata
getTabs: function (){
    chrome.windows.getAll({populate:true}, function(windows){
        var tabs = _.flatten(windows.map(function (w){
            return w.tabs.map(function (tab){
                return {
                    window_id: w.id,
                    tab_id: tab.id,
                    url: tab.url || tab.pendingUrl,
                    title: tab.title
                };
            });
        }));
        resolve(tabs);
    });
}
```

**Verdict**: This is expected classroom management functionality. Teachers need the ability to close distracting tabs and monitor student browsing during class sessions.

## False Positives Analysis

1. **Screen Capture**: The `desktopCapture` permission and `captureVisibleTab` usage are not malicious—they're core features for teachers to view student screens during class.

2. **Activity Tracking**: Comprehensive logging of URLs, titles, and application usage is the primary value proposition of classroom monitoring software.

3. **Remote Control**: The ability to close tabs, block applications, and filter URLs is standard for educational device management.

4. **System Permissions**: Permissions like `system.memory`, `system.display`, and `enterprise.deviceAttributes` are used for device information reporting, not exploitation.

5. **Chrome OS Restriction**: The extension explicitly checks for ChromeOS (`if (os === "Chrome OS" || isDebug.debug)`) and disables itself on other platforms, limiting its scope to managed educational environments.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://api.dyknow.me/ | Core API server | Student activity data, authentication tokens | Low - Official infrastructure |
| https://oauth.dyknow.me/ | OAuth authentication | Device tokens, user credentials | Low - OAuth flow |
| https://satellite01.dydev.me/ | Real-time command/control | Screen captures, tab data, activity logs | Low - Expected monitoring |
| https://accounts.google.com/* | Google OAuth | OAuth tokens | Low - Standard Google auth |
| https://www.googleapis.com/* | Google user info | Email address | Low - Identity verification |

All endpoints are official Dyknow/Google infrastructure. No third-party data exfiltration detected.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: Dyknow Cloud is a legitimate enterprise classroom monitoring tool that operates exactly as described in its marketing materials. While it has extensive monitoring and control capabilities, these are:

1. **Disclosed**: The product is marketed as classroom monitoring software
2. **Scoped**: Only works on ChromeOS devices in managed educational environments
3. **Authorized**: Typically deployed by school IT administrators with institutional policy
4. **Standard**: Features align with competitor products like GoGuardian, Securly, and LanSchool

The extension is not malware or spyware in the traditional sense—it's enterprise monitoring software used in educational settings. Privacy concerns are valid from a student perspective, but the functionality is intentional and disclosed, not a security vulnerability.

**Privacy Note**: Students and parents should be aware that when this extension is installed (typically by school administrators), it enables comprehensive monitoring of student device activity during school hours. This is common practice in K-12 education but raises legitimate privacy considerations.

Sources:
- [Dyknow Classroom Management Software](https://www.dyknow.com/)
- [Dyknow Cloud - Chrome Web Store](https://chromewebstore.google.com/detail/dyknow-cloud/kmpjlilnemjciohjckjadmgmicoldglf)
- [How monitoring works - Dyknow Support](https://support.securly.com/hc/en-us/articles/5393683323287-Dyknow-Classroom-How-monitoring-works-an-overview)
