# Vulnerability Report: שם זה זול יותר

## Metadata
- **Extension ID**: neigoggljhfnodeneidndcflnclldnpm
- **Extension Name**: שם זה זול יותר (Name: It's Cheaper)
- **Version**: 4.4.1
- **Users**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This is a price comparison extension for Israeli e-commerce sites that helps users find better deals by comparing prices across different retailers. The extension activates on HTTPS sites, displays price comparison modals, and allows users to submit new sites for comparison. While the extension provides legitimate shopping assistance functionality, it exhibits several privacy and security concerns. The extension collects browsing data including URLs and product information, transmits this data to multiple AWS API Gateway endpoints, uses postMessage without origin validation, and sets session storage access level to allow untrusted contexts. The extension also uses Google Analytics for telemetry and sends user-submitted site configuration data via EmailJS. These practices represent a MEDIUM risk level due to undisclosed data collection and security weaknesses.

## Vulnerability Details

### 1. MEDIUM: Browsing Data Collection and Exfiltration

**Severity**: MEDIUM
**Files**: content.js, google-analytics.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension collects and transmits extensive browsing data to remote servers without clear disclosure in the extension description. This includes:
- Full page URLs and titles via Google Analytics
- Product names and prices from e-commerce sites
- Site configuration data (DOM selectors, product titles, prices)
- User click patterns and interactions

**Evidence**:
```javascript
// content.js line 425-429
sendGAEvent('page_view', {
  page_title: document.title,
  page_location: document.location.href,
  domain: storedSiteData ? storedSiteData.domain : getDomainFromURL(window.location.href)
});

// content.js line 179
sendEmail(JSON.stringify(data), selectedProductData.title);

// content.js line 474
fetch(`https://o0rmue7xt0.execute-api.il-central-1.amazonaws.com/dev/sites?site=${websiteName}`)
```

The extension sends page view events to Google Analytics with full URLs (line 8806), transmits user-selected product data via EmailJS (lines 211-233), and fetches site configuration from AWS API Gateway endpoints. The extension description mentions "קבל קופונים והצעות מחיר מאתרים מקבילים בזמן אמת" (Get coupons and price quotes from parallel sites in real time) but does not explicitly disclose the collection and transmission of browsing data.

**Verdict**: This constitutes undisclosed data collection. While the data collection appears to be for legitimate price comparison functionality, users are not clearly informed that their browsing behavior, product searches, and page URLs are being transmitted to remote servers.

### 2. MEDIUM: postMessage Without Origin Validation

**Severity**: MEDIUM
**Files**: page.js, content.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension uses `window.postMessage()` with wildcard origin (`'*'`) to communicate between different script contexts, allowing any website to intercept or inject messages.

**Evidence**:
```javascript
// page.js line 32
window.postMessage({ type: 'FROM_PAGE', action: 'showClickProductTitle' }, '*');

// page.js line 40
window.postMessage({ type: 'TO_CONTENT', action: 'showMessage', message: "לחץ על כותרת המוצר" }, '*');

// content.js line 186
window.postMessage({ type: 'FROM_CONTENT', action: 'processCompleted' }, '*');
```

While the extension does filter messages by checking the `type` field (e.g., `event.data.type === 'FROM_PAGE'`), using wildcard origin allows malicious scripts on the same page to potentially spoof these messages.

**Verdict**: The use of wildcard origins in postMessage is a security weakness. While the impact is limited by message type checking, a malicious script could potentially trigger extension functionality or interfere with the user flow.

### 3. MEDIUM: Session Storage Access Level Configuration

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-266 (Incorrect Privilege Assignment)
**Description**: The extension configures session storage to be accessible from untrusted contexts (content scripts and web pages), potentially exposing session data.

**Evidence**:
```javascript
// background.js line 28
chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS' });
```

This setting allows content scripts running in web page contexts to access session storage data, including the Google Analytics session ID and client ID. While the extension stores limited data in session storage, this configuration increases the attack surface.

**Verdict**: This is a risky configuration that violates the principle of least privilege. Session data should be restricted to trusted extension contexts unless there is a specific need for web page access.

### 4. LOW: Multiple External API Dependencies

**Severity**: LOW
**Files**: content.js
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Description**: The extension relies on multiple AWS API Gateway endpoints and third-party services for core functionality, creating dependencies on external infrastructure.

**Evidence**:
The extension makes requests to:
- `o0rmue7xt0.execute-api.il-central-1.amazonaws.com` (site configuration, items, affiliate links)
- `djo93souk2.execute-api.il-central-1.amazonaws.com` (hotel searches)
- `2gxkd3dzwd.execute-api.il-central-1.amazonaws.com` (flight searches)
- `kufu51g8uk.execute-api.il-central-1.amazonaws.com` (product searches)
- `fhk2dp1otj.execute-api.il-central-1.amazonaws.com` (price alerts)
- `api.emailjs.com` (site configuration submissions)
- `yossidisk.github.io` (iframe content)

**Verdict**: While these dependencies are necessary for the extension's functionality, they create a large attack surface. If any of these endpoints are compromised, the extension could serve malicious content to users. The use of a personal GitHub Pages site (yossidisk.github.io) for iframe content is particularly concerning from a trust perspective.

## False Positives Analysis

1. **Google Analytics Integration**: The extension includes a Google Analytics implementation (google-analytics.js) that is based on the official Google Analytics Measurement Protocol for Chrome extensions. This is legitimate telemetry for the extension developer but should be disclosed to users.

2. **EmailJS for Site Submissions**: The `sendEmail` function uses EmailJS to notify the developer when users submit new site configurations. This appears to be a legitimate workflow for expanding the extension's supported sites, though the endpoint configuration (service_id: 'default_service', template_id: 'template_kbmvpfl') could be better documented.

3. **Price Comparison API Calls**: The numerous fetch calls to AWS endpoints are part of the core price comparison functionality. The extension searches for product prices across different retailers and displays comparison modals. This is the stated purpose of the extension.

4. **Content Script on All HTTPS Sites**: The manifest declares content scripts on `["https://*/*"]`, which is necessary for a price comparison extension that needs to work across multiple e-commerce sites. The extension does check for shopping-related keywords before activating (see `checkPageContentForKeywords` function).

5. **DOM Manipulation for Price Display**: The extension injects modals, buttons, and floating icons into web pages to display price comparisons. This is expected behavior for a shopping assistant extension.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| o0rmue7xt0.execute-api.il-central-1.amazonaws.com/dev/sites | Fetch site configuration | Website name | Low - read-only |
| o0rmue7xt0.execute-api.il-central-1.amazonaws.com/dev/items | Submit/search products | Product name, price, URL, site ID | Medium - collects user data |
| o0rmue7xt0.execute-api.il-central-1.amazonaws.com/dev/generateAliExpressLink | Generate affiliate links | Product URL | Low - likely affiliate monetization |
| djo93souk2.execute-api.il-central-1.amazonaws.com/default/HotelsByCity | Hotel price comparison | City, dates, guests, site name | Low - search functionality |
| 2gxkd3dzwd.execute-api.il-central-1.amazonaws.com/stag1/api/flights | Flight price comparison | Origin, destination, dates, site name | Low - search functionality |
| kufu51g8uk.execute-api.il-central-1.amazonaws.com/stag/search | Product search | Search query | Medium - tracks searches |
| fhk2dp1otj.execute-api.il-central-1.amazonaws.com/prod/price-alerts | Price drop alerts | Email, product data, URL | Medium - collects PII |
| api.emailjs.com/api/v1.0/email/send | Site configuration submission | Site config JSON, product title | Medium - developer notification |
| www.google-analytics.com/mp/collect | Analytics telemetry | Page URLs, titles, events, client ID | Medium - extensive tracking |
| yossidisk.github.io | Popup iframe content | Current tab URL (via query param) | Medium - external content injection |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
This extension provides legitimate price comparison functionality for Israeli e-commerce sites but exhibits several privacy and security concerns that elevate it to a MEDIUM risk level:

1. **Undisclosed Data Collection**: The extension collects extensive browsing data (page URLs, titles, product information, search queries) and transmits it to remote servers without clear disclosure in the extension description. Users installing this extension may not realize the extent of data collection occurring.

2. **Security Weaknesses**: The use of postMessage with wildcard origins and the configuration of session storage to be accessible from untrusted contexts represent security weaknesses that could be exploited by malicious scripts on compromised websites.

3. **Third-Party Dependencies**: The extension relies heavily on external infrastructure (AWS API Gateway endpoints, GitHub Pages) for core functionality. If any of these services are compromised, the extension could be leveraged to serve malicious content to 50,000 users.

4. **Analytics and Tracking**: The Google Analytics integration tracks page views, click events, and user interactions across all HTTPS websites visited by the user, creating a comprehensive browsing profile.

5. **Affiliate Monetization**: The extension includes affiliate link generation functionality (generateAliExpressLink), which is not disclosed in the extension description.

**Mitigating Factors**:
- The extension provides genuine utility (price comparison, coupon discovery)
- No evidence of credential theft or malicious code execution
- Uses minimal permissions (activeTab, storage)
- The data collection appears to be for legitimate functionality rather than pure surveillance
- Manifest V3 provides some security benefits

**Recommendation**: Users should be aware that this extension collects and transmits browsing data to remote servers. The developer should improve privacy disclosures and fix the identified security weaknesses (postMessage origin validation, session storage access level). Enterprise users may want to block this extension due to data exfiltration concerns.
