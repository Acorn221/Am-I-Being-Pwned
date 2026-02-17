# Vulnerability Report: Desktop For Instagram

## Metadata
- **Extension ID**: odlpjhnipdekfkdkadoecooboghijleh
- **Extension Name**: Desktop For Instagram
- **Version**: 1.1.3
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Desktop For Instagram is an extension that provides a mobile Instagram interface on desktop browsers by spoofing the User-Agent to appear as an iPhone and modifying Instagram's security headers. While its core functionality is legitimate, the extension exhibits several privacy and security concerns that are not disclosed to users.

The extension includes undisclosed third-party analytics (Google Analytics), fetches remote banner configurations from external servers, collects geolocation data without disclosure, and weakens Instagram's Content Security Policy by stripping CSP headers. These behaviors represent privacy violations and security concerns that users are not informed about in the extension's description or privacy policy links.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Third-Party Analytics Collection

**Severity**: MEDIUM
**Files**: background.js (lines 183-210)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension loads Google Analytics from an external CDN and sends usage data to Google without disclosure in the extension's description or prominent privacy notice.

**Evidence**:
```javascript
// background.js lines 184-199
async function background() {
  const ga = await new Promise((res, rej) => {
    window.GoogleAnalyticsObject = "_____private_ga____";
    const s = document.createElement("script");
    s.src = "https://www.google-analytics.com/analytics.js";
    s.async = true;
    s.addEventListener("load", function () {
      res(window._____private_ga____);
    });
    document.head.appendChild(s);
  });
  ga("create", "UA-101342128-8", "auto");
  ga("set", "checkProtocolTask", null);
  ga("send", "pageview", "extension_start");
```

The extension tracks:
- Extension start events
- Instagram page visits
- Usage patterns

**Verdict**: This violates Chrome Web Store policies requiring clear disclosure of data collection practices. Users are not informed that Google Analytics is integrated or what data is being collected.

### 2. MEDIUM: Remote Configuration with Geolocation Collection

**Severity**: MEDIUM
**Files**: app/index.js (lines 197-279)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension fetches remote banner configurations and collects user geolocation data without disclosure.

**Evidence**:
```javascript
// app/index.js lines 200-205
const [configuration, { countryIso2: iso }] = await Promise.all(
  [
    "https://dn0tkh0edij3c.cloudfront.net/banner_config.json",
    "https://prod-collection.joinupvoice.com/getGeoLocationCity?seed=desktop-for-instagram",
  ].map((url) => fetch(url).then((response) => response.json()))
);
```

The extension:
- Sends a request to `prod-collection.joinupvoice.com` to collect geolocation (country code)
- Fetches dynamic banner configurations from CloudFront
- Displays targeted banners based on user location
- No disclosure of this data collection in the privacy policy

**Verdict**: This represents undisclosed geolocation tracking and remote configuration loading. The joinupvoice.com domain suggests potential monetization through targeted advertising.

### 3. MEDIUM: Content Security Policy Weakening

**Severity**: MEDIUM
**Files**: background.js (lines 97-114)
**CWE**: CWE-693 (Protection Mechanism Failure)

**Description**: The extension strips Instagram's Content Security Policy headers to inject its own functionality, weakening the security posture of Instagram's website.

**Evidence**:
```javascript
// background.js lines 97-114
chrome.webRequest.onHeadersReceived.addListener(
  function (details) {
    const toBeRemoved = [
      "x-frame-options",
      "content-security-policy-report-only",
      "content-security-policy",
    ];
    const headers = details.responseHeaders.filter((header) => {
      return toBeRemoved.indexOf(header.name.toLowerCase()) === -1;
    });

    return {
      responseHeaders: headers,
    };
  },
  requestFilter,
  ["blocking", "responseHeaders"]
);
```

**Verdict**: While necessary for the extension's functionality (loading Instagram in an iframe), this strips important security headers including CSP and X-Frame-Options, potentially exposing users to clickjacking or XSS attacks if combined with other vulnerabilities.

### 4. LOW: User-Agent Spoofing

**Severity**: LOW
**Files**: background.js (lines 72-95), contentScripts/csHelper.js (lines 1-164)
**CWE**: CWE-471 (Modification of Assumed-Immutable Data)

**Description**: The extension modifies the User-Agent header to spoof an iPhone device and modifies navigator properties.

**Evidence**:
```javascript
// background.js lines 69-95
const iphoneUa = "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1";

chrome.webRequest.onBeforeSendHeaders.addListener(
  function (details) {
    if (details.tabId && (details.tabId === chromeTabId || details.tabId === -1)) {
      const { requestHeaders } = details;
      requestHeaders.forEach((header) => {
        if (header.name === "User-Agent") {
          header.value = iphoneUa;
        }
      });
      // Also removes referer header
      const headers = requestHeaders.filter((header) => {
        return header.name.toLowerCase() !== "referer";
      });
      return { requestHeaders: headers };
    }
  },
  requestFilter,
  ["blocking", "requestHeaders"]
);
```

**Verdict**: While this is the core functionality of the extension, it represents a modification of browser identity that could be used for fingerprinting evasion. The extension also strips the Referer header. This is disclosed through the extension's purpose but not explicitly stated.

## False Positives Analysis

The following patterns were examined but are not security issues:

1. **FileSaver.js library**: This is a legitimate, well-known open-source library for downloading files. The extension uses it to enable photo/video downloads from Instagram.

2. **Download functionality**: The extension adds download buttons to Instagram posts, which is a disclosed feature. The download mechanism itself is benign.

3. **CSP in manifest.json**: The extension declares `'unsafe-eval'` in its CSP, but this is for loading the analytics script and is scoped to the extension's own pages, not affecting user security on Instagram.

4. **Terms of Use popup**: The extension requires users to agree to terms before use, which is a legitimate mechanism.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.google-analytics.com | Usage analytics | Extension events, page views, potentially user ID | Medium - Undisclosed tracking |
| dn0tkh0edij3c.cloudfront.net/banner_config.json | Remote banner config | None (GET request) | Low - Dynamic content loading |
| prod-collection.joinupvoice.com/getGeoLocationCity | Geolocation collection | User's IP address (inferred geolocation) | Medium - Undisclosed location tracking |
| privacy.unimania.xyz | Privacy policy/terms | None (document hosting) | Low - Legitimate documentation |
| www.instagram.com | Core functionality | User credentials, session cookies | Low - Expected behavior |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: Desktop For Instagram provides legitimate functionality (mobile Instagram interface on desktop) but implements several undisclosed privacy-invasive practices. The extension collects analytics through Google Analytics, tracks user geolocation through a third-party service, and fetches remote configurations without user knowledge. These practices are not disclosed in the extension's description or privacy policy.

While the extension does not appear to be malicious, it violates Chrome Web Store policies regarding transparency and data collection disclosure. The weakening of Instagram's CSP also presents a security concern, though this is necessary for the extension's core functionality.

**Key Concerns**:
1. No disclosure of Google Analytics integration
2. Geolocation collection without user consent or disclosure
3. Remote configuration fetching from third-party domains
4. Security header stripping (CSP, X-Frame-Options)
5. Privacy policy links point to generic documents that may not cover actual practices

**Recommendation**: Users should be clearly informed about third-party analytics, geolocation tracking, and remote configuration loading. The extension should provide a detailed, accurate privacy policy before requesting user consent.
