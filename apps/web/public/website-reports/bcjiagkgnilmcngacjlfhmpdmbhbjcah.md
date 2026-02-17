# Vulnerability Report: Adjust Page Brightness

## Metadata
- **Extension ID**: bcjiagkgnilmcngacjlfhmpdmbhbjcah
- **Extension Name**: Adjust Page Brightness
- **Version**: 0.3.8
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Adjust Page Brightness" is a legitimate browser extension designed to adjust screen brightness on web pages based on time schedules (day/night modes) or manual settings. The extension applies CSS filters or overlays to reduce page brightness, with support for dark mode detection and per-hostname customization.

The extension's codebase is clean, well-structured, and fully consistent with its advertised purpose. Static analysis revealed no suspicious data flows, no network exfiltration, and no dynamic code execution patterns. All permissions requested (`activeTab`, `scripting`, `storage`, `alarms`, `idle`, `<all_urls>`) are strictly necessary for the brightness adjustment functionality. The only minor issue identified is the opening of the developer's homepage on install/update, which is a standard practice but represents a low-severity privacy consideration.

## Vulnerability Details

### 1. LOW: Post-Install Homepage Navigation
**Severity**: LOW
**Files**: worker.js (lines 183-211)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension automatically opens the developer's homepage (`https://webextension.org/listing/screen-brightness.html`) when installed or updated (if more than 45 days have passed since the last update notification). This behavior tracks installation events and version updates via URL parameters.

**Evidence**:
```javascript
chrome.runtime.onInstalled.addListener(({reason, previousVersion}) => {
  chrome.management.getSelf(({installType}) => installType === 'normal' && chrome.storage.local.get({
    'faqs': true,
    'last-update': 0
  }, prefs => {
    if (reason === 'install' || (prefs.faqs && reason === 'update')) {
      const doUpdate = (Date.now() - prefs['last-update']) / 1000 / 60 / 60 / 24 > 45;
      if (doUpdate && previousVersion !== version) {
        chrome.tabs.create({
          url: page + '?version=' + version + (previousVersion ? '&p=' + previousVersion : '') + '&type=' + reason,
          active: reason === 'install',
          ...(tbs && tbs.length && {index: tbs[0].index + 1})
        });
```

**Verdict**: This is a common and relatively benign practice used by many legitimate extensions for user onboarding and displaying changelogs. The URL parameters disclose the extension version and installation reason, but no personally identifiable information is transmitted. Users can disable this behavior via the `faqs` preference in storage. This represents minimal privacy impact.

## False Positives Analysis

Several patterns that might appear suspicious in other contexts are legitimate for this extension:

1. **`<all_urls>` permission**: Required to inject brightness adjustment styles into all websites the user visits. This is the core functionality of the extension.

2. **Dynamic content script injection**: The extension uses `chrome.scripting.executeScript()` in the popup to manually inject styles when the content script hasn't loaded yet. This is a fallback mechanism, not an attack vector.

3. **CSS filter manipulation**: The extension modifies page styling via injected CSS (`filter: brightness()` or `rgba()` overlays). This is the intended functionality and does not pose XSS or code injection risks.

4. **Dark mode detection**: The extension creates a temporary `<span>` element to detect if the page uses a dark color scheme, then removes it. This is a legitimate feature to avoid over-darkening already-dark pages.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://webextension.org/listing/screen-brightness.html | Developer homepage (FAQs/support) | version, previousVersion, install type via URL params | LOW |
| https://clients2.google.com/service/update2/crx | Chrome Web Store update endpoint | None (browser-managed) | NONE |

No other external network requests are made. All functionality is local to the user's browser.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This extension is a legitimate utility with clean code and no security vulnerabilities beyond the standard post-install homepage navigation. The functionality exactly matches the advertised purpose, all permissions are justified, and there is no evidence of data exfiltration, tracking, or malicious behavior. The minor privacy consideration (homepage navigation with version parameters) is typical for legitimate extensions and can be disabled by the user. The extension deserves a LOW risk rating rather than CLEAN solely due to the homepage navigation behavior.
