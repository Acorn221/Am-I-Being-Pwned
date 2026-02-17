# Vulnerability Report: Adblock for YouTube™ — best adblocker

## Metadata
- **Extension ID**: ojigagjjcmnbplgdkggkkleckaohppok
- **Extension Name**: Adblock for YouTube™ — best adblocker
- **Version**: 1.6
- **Users**: ~90,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This is a legitimate YouTube ad blocking extension that functions as advertised. It uses Chrome's declarativeNetRequest API to block ad-related network requests and injects CSS/JavaScript to hide ad elements and manipulate YouTube's ad delivery mechanisms. While the extension performs its stated function without malicious behavior, it does employ promotional tactics including opening the developer's blog on installation and periodically requesting user reviews.

The extension does not collect or exfiltrate user data, does not access sensitive information, and operates transparently within its stated scope of blocking YouTube advertisements.

## Vulnerability Details

### 1. LOW: Promotional Behavior and User Engagement Tactics

**Severity**: LOW
**Files**: background.js (lines 40-41, 933-957), codehemu-content.js (lines 388-443)
**CWE**: CWE-506 (Embedded Malicious Code - Low Severity)
**Description**: The extension opens the developer's blog on installation/update and displays dialogs requesting reviews after users watch videos. While not malicious, this could be considered intrusive.

**Evidence**:
```javascript
// background.js lines 40-41
"webstore": `https://chromewebstore.google.com/detail/${API.runtime.id}`,
"homepage": "".concat("https://www.", "bloghemu.", "com/", randomy)

// background.js lines 933-945
case API.runtime.OnInstalledReason.INSTALL:
  API.tabs.create({
    url: config.homepage
  });
```

**Content script review dialog** (codehemu-content.js lines 407-441):
```javascript
if (settings[STORAGE_KEY_RATING] &&
  settings[STORAGE_KEY_RATING_NEXT] &&
  settings[STORAGE_KEY_VIDEO_COUNT] >
  settings[STORAGE_KEY_RATING_NEXT]) {
  const timeSaved = Math.ceil(settings[STORAGE_KEY_VIDEO_COUNT] *  0.5);
  createDialog({
    title: timeTitle,
    buttons: [{
        text: `❤️ ${API.i18n.getMessage("helpUsWithAReview")}`,
        onClick: () => {
          window.open(details.webstore, "_blank");
```

**Verdict**: This is standard promotional behavior for free extensions. Users can dismiss dialogs and the extension provides value (ad blocking) in exchange. No deceptive practices detected.

### 2. INFO: Code Injection Techniques

**Severity**: INFO (Not a vulnerability)
**Files**: background.js (lines 990-1017, 731-748)
**Description**: The extension injects JavaScript scriptlets into YouTube pages to interfere with ad delivery mechanisms. This is necessary functionality for an ad blocker.

**Evidence**:
```javascript
const inlineScriptsArray = [
  '(()=>{window.JSON.parse=new Proxy(JSON.parse,{apply(r,e,t){...',
  '(()=>{const t={apply:(t,o,n)=>{const e=n[0];return"function"==typeof e&&e.toString().includes("onAbnormalityDetected")...',
];
```

The extension uses `chrome.scripting.executeScript` with `world: 'MAIN'` to inject ad-blocking logic that:
- Proxies JSON.parse to filter ad data from API responses
- Manipulates video player state to skip ads
- Blocks ad detection callbacks

**Verdict**: This is legitimate ad blocking functionality. The code operates only on YouTube pages and serves the extension's stated purpose.

## False Positives Analysis

1. **Dynamic Code Execution**: The extension uses `injectfunction` to execute strings as code, which is flagged by static analysis. However, this is necessary for ad blocking scriptlets and the code is hardcoded within the extension (not fetched remotely).

2. **Proxy Manipulation**: The scriptlets create Proxy objects around native APIs (JSON.parse, Array.prototype.push, Promise.then). This is a standard technique for ad blockers to intercept and filter YouTube's ad delivery mechanisms.

3. **Trusted Types Policy**: The extension creates a TrustedTypes policy to inject scripts, which appears suspicious but is actually the secure way to inject content in modern Chrome extensions.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| bloghemu.com | Developer blog | None (navigation only) | Low - Promotional |
| chromewebstore.google.com | Review prompts | None (navigation only) | None - Legitimate |

No data collection endpoints identified. The extension does not make any HTTP requests for analytics, tracking, or data exfiltration.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This extension functions as a legitimate YouTube ad blocker without malicious behavior. The LOW risk rating is assigned due to promotional tactics (opening blog posts, review requests) that some users may find intrusive. However, these behaviors are:

1. **Transparent**: Documented in the extension's behavior
2. **Non-malicious**: No data theft or hidden functionality
3. **Standard practice**: Common in free extensions
4. **User-controllable**: Dialogs can be dismissed

The extension does not:
- Collect or exfiltrate user data
- Access sensitive information beyond its scope
- Communicate with third-party servers for data collection
- Modify content outside of YouTube
- Inject affiliate links or ads

The code injection and dynamic execution are necessary for ad blocking functionality and are implemented securely using Chrome's official APIs.

**Recommendation**: SAFE for use. Users seeking ad-free YouTube without data collection concerns can use this extension. Those who prefer no promotional interruptions should configure settings to disable review prompts.
