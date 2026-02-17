# Vulnerability Report: Omega Ad Blocker

## Metadata
- **Extension ID**: aoognjkkhapcjkfnakpddcciddcfbjcd
- **Extension Name**: Omega Ad Blocker
- **Version**: 2.0.3
- **Users**: ~300,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Omega Ad Blocker is a legitimate ad blocking extension that uses Chrome's declarativeNetRequest API for blocking ads. The extension employs remote configuration to fetch and update filter lists from omegadblocker.com. While this introduces a dependency on external servers, the behavior is transparent and appropriate for an ad blocker that needs to maintain up-to-date blocking rules.

The extension generates a unique identifier for installation tracking and communicates with its backend server for filter updates, installation confirmation, and uninstall tracking. These are standard telemetry practices for ad blocking extensions that need to manage filter lists and track usage statistics.

## Vulnerability Details

### 1. LOW: Remote Configuration Dependency

**Severity**: LOW
**Files**: extension.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension fetches blocking rules from omegadblocker.com without cryptographic verification. While this is common practice for ad blockers, it creates a potential risk if the server is compromised.

**Evidence**:
```javascript
async function updateRulesData() {
    const uniqueId = await getUniqueId();
    const {updateTime} = await chrome.storage.local.get(['updateTime']);
    const updatePeriodMs = 24 * 3600000;
    if (updateTime && (Date.now() - updateTime) < updatePeriodMs) {
        return;
    }

    const response = await fetch(endpointHostname+'/data/' + '?' + 'uniqueId=' + uniqueId);
    // ... fetches rule URLs and downloads rule data
    const ruleData = await (await fetch(rule.url + '?' + 'uniqueId=' + uniqueId)).json();
```

**Verdict**: This is expected behavior for an ad blocker. Filter lists need regular updates to remain effective. The extension checks for updates every 24 hours, which is reasonable. The risk is low because:
1. The extension uses HTTPS for all connections
2. Updates are rate-limited to once per 24 hours
3. The extension validates JSON structure before applying rules
4. This is standard practice in the ad blocking ecosystem

## False Positives Analysis

The following patterns appear in the code but are legitimate for an ad blocker:

1. **Dynamic Script Injection**: The extension injects anti-adblock circumvention scripts into web pages using `chrome.scripting.executeScript()`. This is a legitimate technique used by ad blockers to prevent websites from detecting and blocking the ad blocker itself.

2. **Content Script on All URLs**: The extension runs content scripts on `*://*/*` with `match_about_blank: true` and `all_frames: true`. This broad scope is necessary for comprehensive ad blocking across all websites and frames.

3. **Installation Tracking**: The extension calls `/init/` and `/installed/` endpoints to track installations. This is disclosed behavior for usage analytics and is not covert data collection.

4. **Web Accessible Resources**: The extension exposes filter static resources at `/filter/static/*` with `use_dynamic_url: true`. These are used for replacing blocked elements with placeholder content, which is standard ad blocker functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://omegadblocker.com/data/ | Fetch available filter list updates | uniqueId | LOW - Standard filter update mechanism |
| https://omegadblocker.com/init/ | Initialize new installation | None (generates uniqueId server-side) or existing uniqueId | LOW - Installation tracking |
| https://omegadblocker.com/installed/ | Confirm installation after delay | uniqueId | LOW - Installation confirmation |
| https://omegadblocker.com/bye.php | Uninstall tracking | uniqueId (via URL parameter) | LOW - Standard uninstall analytics |
| https://omegadblocker.com/success/ | Post-installation welcome page | None (opened in new tab) | LOW - User onboarding |
| (dynamic rule URLs) | Download filter list data | uniqueId | LOW - Filter list delivery |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

Omega Ad Blocker is a legitimate ad blocking extension that follows standard practices for this category of software. The extension:

1. Uses Chrome's official declarativeNetRequest API for blocking (Manifest V3 compliant)
2. Employs remote configuration for filter updates, which is necessary for maintaining effective ad blocking
3. Implements standard installation and usage tracking via a unique identifier
4. Does not collect browsing history, personal data, or sensitive information
5. Only contacts its own domain (omegadblocker.com) for legitimate purposes
6. Uses content scripts to inject cosmetic filters and anti-adblock bypass code, which is expected functionality

The primary finding is the remote configuration dependency, which is inherent to how modern ad blockers operate. The extension needs to fetch updated filter lists to block new ad networks and techniques. While this creates a trust dependency on omegadblocker.com, it is transparent and appropriate for the extension's stated purpose.

The extension shows no evidence of:
- Data exfiltration beyond basic installation tracking
- Credential theft
- Malicious code injection
- Hidden functionality
- Privacy violations beyond disclosed analytics

**Recommendation**: The extension is safe for use. Users should be aware that it contacts omegadblocker.com for filter updates and installation tracking, which is standard and necessary for ad blocking functionality.
