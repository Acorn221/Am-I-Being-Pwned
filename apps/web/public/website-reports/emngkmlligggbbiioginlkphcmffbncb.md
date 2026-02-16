# Vulnerability Report: AdBlock on YouTube™

## Metadata
- **Extension ID**: emngkmlligggbbiioginlkphcmffbncb
- **Extension Name**: AdBlock on YouTube™
- **Version**: 1.7.0
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

AdBlock on YouTube™ is an ad-blocking extension that specifically targets YouTube advertisements. The extension implements standard ad-blocking functionality using webRequest blocking APIs and filter lists. It includes analytics telemetry that sends periodic pings to the developer's server (ping.getadblock.com) with usage statistics including user ID, version, OS, browser version, and ad block counts.

The extension's telemetry collection is consistent with standard analytics practices for free extensions. While the code contains commented-out sections for uninstall tracking URLs and installation welcome pages, these features are currently disabled in the deployed version. The extension operates exclusively on YouTube domains as stated in its manifest permissions.

## Vulnerability Details

### 1. LOW: Analytics Telemetry with User Tracking
**Severity**: LOW
**Files**: stats.js, servermessages.js, survey.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension generates a unique user ID on first install and periodically sends telemetry to ping.getadblock.com. The telemetry includes:
- Unique user ID (8 random characters + timestamp)
- Extension version
- Browser flavor (Chrome/Opera/Safari) and version
- Operating system and version
- Total ads blocked count
- Advanced options usage flag
- User language
- Total ping count
- Extension ID

**Evidence**:
```javascript
// stats.js lines 78-121
var checkUserId = function () {
  var userIDPromise = new Promise(function (resolve) {
    chrome.storage.local.get(STATS.userIDStorageKey, function (response) {
      var localuserid = storage_get(STATS.userIDStorageKey);
      if (!response[STATS.userIDStorageKey] && !localuserid) {
        STATS.firstRun = true;
        var time_suffix = (Date.now()) % 1e8;
        var alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
        var result = [];
        for (var i = 0; i < 8; i++) {
          var choice = Math.floor(Math.random() * alphabet.length);
          result.push(alphabet[choice]);
        }
        user_ID = result.join('') + time_suffix;
        // store in redundant locations
        chrome_storage_set(STATS.userIDStorageKey, user_ID);
        storage_set_stats(STATS.userIDStorageKey, user_ID);
      }
    });
  });
  return userIDPromise;
};

// stats.js lines 163-200
var pingNow = function () {
  getPingData(function (data) {
    if (!data.u) {
      return;
    }
    // attempt to stop users that are pinging us 'alot'
    if (data.pc > 5000) {
      if (data.pc > 5000 && data.pc < 100000 && ((data.pc % 5000) !== 0)) {
        return;
      }
      if (data.pc >= 100000 && ((data.pc % 50000) !== 0)) {
        return;
      }
    }
    data['cmd'] = 'ping';
    var ajaxOptions = {
      jsonp: false,
      type: 'POST',
      url: stats_url, // https://ping.getadblock.com/stats/
      data: data,
      success: handlePingResponse,
      error: function (e) {
        console.log('Ping returned error: ', e.status);
      },
    };
  });
};
```

**Verdict**: This is standard analytics telemetry for a free extension. The user ID is randomly generated (not tied to browser or user identity), and the data collected is reasonable for usage analytics. The extension does not appear to collect browsing history, page content, or other sensitive user data beyond what is disclosed. However, users should be aware that usage statistics are being tracked.

## False Positives Analysis

1. **Commented-out code**: The extension contains extensive commented-out code for features like uninstall tracking URLs and installation welcome pages (background.js lines 42-130). These are currently disabled and not executing, so they do not represent active privacy concerns.

2. **jQuery cookie plugin**: The extension includes a standard jQuery cookie plugin (options/cookie.js) which is a legitimate library used for managing extension settings, not for tracking user activity.

3. **webRequest blocking**: The use of webRequest and webRequestBlocking permissions is necessary for the extension's core ad-blocking functionality and is appropriately scoped to YouTube domains.

4. **Filter list updates**: The extension periodically checks for filter list updates (myfilters.js), which is standard behavior for ad blockers to stay effective against new ad formats.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| ping.getadblock.com/stats/ | Analytics telemetry | User ID, version, OS, browser version, ad count, language, ping count | LOW - Standard analytics |
| log.getadblock.com/v2/record_log.php | Error/status logging (commented out) | User ID, flavor, OS, language, event messages | LOW - Currently disabled |
| getadblock.com | Survey notifications, welcome pages (commented out) | None - features disabled | NONE - Inactive |
| www.googleapis.com | Unknown (detected by ext-analyzer) | Unknown | LOW - Likely benign API |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

AdBlock on YouTube™ is a legitimate ad-blocking extension with minimal privacy concerns. The primary finding is the analytics telemetry system that tracks usage statistics with a unique user ID. However, this telemetry:

1. Uses a randomly generated ID not tied to browser fingerprints or personal identity
2. Collects only usage metrics consistent with free extension analytics
3. Does not collect browsing history, page content, or sensitive user data
4. Operates exclusively on YouTube domains as disclosed in permissions
5. Includes rate limiting to prevent excessive pinging

The extension does not exhibit data exfiltration, malicious code execution, credential theft, or other high-risk behaviors. The commented-out code sections suggest the developers may have intentionally disabled certain tracking features. The extension's scope is appropriately limited to YouTube domains, and the webRequest blocking is necessary for its advertised functionality.

Users who are privacy-conscious should be aware that the extension sends periodic analytics pings, but this is standard practice for free browser extensions and the data collected appears reasonable and non-invasive.
