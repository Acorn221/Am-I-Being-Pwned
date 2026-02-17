# Vulnerability Report: Auto Quality for YouTube™

## Metadata
- **Extension ID**: iaddfgegjgjelgkanamleadckkpnjpjc
- **Extension Name**: Auto Quality for YouTube™
- **Version**: 2.1.3
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Auto Quality for YouTube™ is a browser extension that automatically sets video quality on YouTube. The extension uses content scripts running in both ISOLATED and MAIN world contexts to interact with the YouTube player API. It includes basic ad-blocking functionality via declarativeNetRequest rules and webRequest blocking of Google ad domains.

The extension has minimal security concerns. While it contains a remote configuration endpoint (api.megaxt.com/qualityList), this functionality is disabled via an early return statement in the code. The extension also redirects users to megaxt.com on install/uninstall events, which is transparent behavior. Overall, this is a legitimate utility extension with appropriate permissions for its stated purpose.

## Vulnerability Details

### 1. LOW: Disabled Remote Configuration Endpoint

**Severity**: LOW
**Files**: background/main.js, config.js
**CWE**: CWE-912 (Hidden Functionality)
**Description**: The extension contains code to periodically fetch configuration updates from a remote endpoint (https://api.megaxt.com/qualityList) every 360 minutes via an alarm. However, this functionality is effectively disabled by an early return statement at line 117 of background/main.js.

**Evidence**:
```javascript
const updateQualities = () => {
  return  // <-- Early return, function does nothing
  fetch(config.qualityListLocation)
    .then((response) => response.text())
    .then((responseText) => {
      console.log(responseText);
      chrome.tabs.query({}, (tabs) => {
        tabs.forEach((tab) => {
          chrome.tabs.sendMessage(
            tab.id,
            {
              action: "qualityListUpdated",
              data: responseText,
            },
            (response) => {
              if (chrome.runtime.lastError) {
                return;
              }
            }
          );
        });
      });
    })
    .catch((error) => { });
};
```

**Verdict**: While the presence of remote config code could be concerning, the early return statement makes this dead code. This appears to be leftover/commented-out functionality rather than active remote control capability. The quality list is hardcoded in config.js and cannot be changed remotely in the current implementation. No security risk in current state, but could become one if the return statement is removed in a future update.

## False Positives Analysis

1. **<all_urls> Permission**: Required for the extension to modify video quality on any page where YouTube videos might be embedded, not just youtube.com. This is appropriate for the stated functionality.

2. **MAIN World Content Script**: The extension injects a content script into the MAIN world context to access YouTube's player API, which is a standard and necessary approach for this type of functionality.

3. **webRequest Permission**: Used solely for blocking Google ad domains (tpc.googlesyndication.com), which is a documented feature of the extension.

4. **Post-Install Redirect**: The extension opens megaxt.com on install/uninstall, which is transparent marketing behavior common in legitimate extensions.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.megaxt.com/qualityList | Remote quality config (disabled) | None (dead code) | None |
| www.megaxt.com | Install/uninstall pages | Referrer params only | Low |
| yt.megaxt.com/rulelist | Rule list location (config only) | None | None |
| tpc.googlesyndication.com | Ad blocking target | None | None |
| googleads.g.doubleclick.net | Blocked via DNR | None | None |

## Network Behavior

The extension implements ad blocking through two mechanisms:
1. **webRequest blocking**: Cancels requests to tpc.googlesyndication.com
2. **declarativeNetRequest**: Blocks scripts from googleads.g.doubleclick.net

No user data is collected or transmitted. The only network activity is the post-install/uninstall page opens to megaxt.com with URL parameters indicating the referral context.

## Code Quality

- Clean, readable code with ES6+ syntax
- Proper error handling in most places
- No obfuscation detected
- Module-based architecture (MV3 service worker)
- Uses modern Chrome extension APIs appropriately

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This extension performs its stated function (auto-setting YouTube video quality) using legitimate techniques. The remote configuration endpoint is disabled, preventing any remote control concerns. The ad-blocking functionality is transparent and uses standard Chrome APIs. The only minor concern is the presence of dead code for remote configuration, which could theoretically be re-enabled in a future update. Users should be aware that the extension redirects to the developer's website on install/uninstall events.

**Recommendation**: Safe to use. Monitor for updates that might re-enable the remote configuration functionality.
