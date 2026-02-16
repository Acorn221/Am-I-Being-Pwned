# Vulnerability Report: Facebook Downloader

## Metadata
- **Extension ID**: hgknmjhmcbimcpdmmfeafjbdccaheaeg
- **Extension Name**: Facebook Downloader
- **Version**: 5.0.6
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension allows users to download videos from Facebook. The extension performs legitimate video downloading functionality but also sends analytics data to pbion.com and DOM-scraped content to www.facebook.com. The ext-analyzer flagged 3 exfiltration flows where document.querySelectorAll data reaches fetch() calls to www.facebook.com. While the extension's primary purpose is video downloading, the scraping and transmission of Facebook DOM content represents data exfiltration beyond the stated functionality. The obfuscated code flag indicates some level of code transformation, though much of it appears to be standard configuration data.

## Vulnerability Details

### 1. MEDIUM: DOM Scraping and Exfiltration to Facebook
**Severity**: MEDIUM
**Files**: background.js, popup.js, get.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension scrapes Facebook DOM content using document.querySelectorAll and sends it via fetch() to www.facebook.com. The ext-analyzer detected 3 HIGH-severity exfiltration flows where DOM data reaches network sinks.

**Evidence**:
```javascript
// background.js:424, popup.js:241, get.js:281
function pbion_get(u,f) {
    fetch(u).then(r => {
        return r.text();
    }).then(responseText => {
        f(responseText);
    }).catch(error => {});
}
```

The extension uses complex selectors targeting Facebook video elements:
```javascript
"selector": "#watch_feed>div>div>div>div>div>div>div>div>div>div>div>div,div[role='main'] div[role='feed'] div[role='article']>div,..."
```

**Verdict**: While this scraping is expected for a video downloader to extract video URLs, the volume of DOM querying and transmission to facebook.com raises concerns about what additional data may be collected beyond video metadata.

### 2. MEDIUM: Analytics Tracking to Third-Party Domain
**Severity**: MEDIUM
**Files**: popup.js, get.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension sends analytics data to pbion.com/report/ without clear disclosure in the manifest.

**Evidence**:
```javascript
// popup.js:506, get.js:129
var _ANALYTIC_ROOT = 'https://'+_config.domain+'/report/';

// popup.js:530, get.js:153
fetch(_ANALYTIC_ROOT+'?a='+m);
```

**Verdict**: Basic analytics tracking to the developer's domain. The content of the analytics payload (variable 'm') was not fully traced but appears to be usage metrics. This is common for extensions but should be disclosed to users.

## False Positives Analysis

The ext-analyzer flagged "obfuscated" code, but examination shows this is primarily:
- Multi-language translation strings (60+ languages in content.js)
- Standard webpack/bundling patterns
- Configuration objects with complex CSS selectors

The fetch() calls to www.facebook.com are partially legitimate - a Facebook video downloader must interact with Facebook's servers to retrieve video content. However, the extent of DOM scraping warrants the MEDIUM risk classification.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| pbion.com/report/ | Analytics tracking | Usage metrics (parameter 'a') | Medium |
| www.facebook.com | Video metadata extraction | DOM-scraped content via fetch() | Medium |
| suggestqueries.google.com | Search suggestions | Unknown | Low |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: The extension performs its stated function (downloading Facebook videos) but engages in DOM scraping and data transmission that may exceed user expectations. The 3 exfiltration flows detected by ext-analyzer show document.querySelectorAll data reaching fetch() calls to www.facebook.com. While this is partially expected for video extraction, the lack of transparency and the analytics tracking to pbion.com elevate the risk to MEDIUM. The extension does not appear to be malicious but collects and transmits user browsing data on Facebook without clear disclosure.

**Key Concerns**:
1. Extensive DOM scraping on Facebook pages
2. Analytics tracking to third-party domain (pbion.com)
3. Obfuscated/minified code makes full audit difficult
4. Message passing attack surface flagged by ext-analyzer

**Recommendation**: Users should be aware this extension monitors their Facebook browsing activity and sends data to external servers beyond just downloading videos.
