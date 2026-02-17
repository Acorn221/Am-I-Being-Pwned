# Security Analysis: WhatRuns

**Extension ID:** cmkdbmfndkfgebldhnkbfhlneefdaaip
**Version:** 1.8.20
**Users:** 400,000
**Risk Level:** MEDIUM
**Manifest Version:** 3

## Executive Summary

WhatRuns is a legitimate browser extension designed to identify technologies used on websites (CMS, frameworks, analytics, etc.). While the core functionality is disclosed and expected, the extension implements extensive background data collection that transmits detailed browsing activity to both whatruns.com and a secondary service shopper.com. The extension also contains a postMessage vulnerability that could allow malicious websites to manipulate the extension's UI. Given the disclosed nature of data collection in the privacy policy and the extension's legitimate purpose, this is rated MEDIUM risk rather than HIGH.

## Vulnerabilities

### 1. PostMessage Handler Without Origin Validation (MEDIUM)

**Location:** `js/content.js:193`

**Description:**
The extension creates an iframe popup to display detected technologies. It listens for postMessage events to adjust the iframe height but does not validate the origin of incoming messages:

```javascript
window.addEventListener('message', function(event) {
    if(event.data.iframeContent) {
        previousHeight=event.data.iframeContent;
    }

    if (event.data.type === 'adjustHeight') {
        const container = document.getElementById("whatruns-iframe-container-701");
        if (container) {
            if (event.data.height !== "previousHeight") {
                container.style.height = event.data.height + 'px';
            } else {
                container.style.height = previousHeight + 'px';
            }
        }
    }
});
```

**Impact:**
Any website can send postMessage events to manipulate the extension's iframe dimensions. While the impact is limited to UI manipulation (resizing the container), this could be used for UI redressing attacks or to obscure page content.

**Recommendation:**
Add origin validation:
```javascript
window.addEventListener('message', function(event) {
    if (event.origin !== chrome.runtime.getURL('').slice(0, -1)) return;
    // ... rest of handler
});
```

### 2. Extensive Data Collection and Cross-Service Exfiltration (MEDIUM)

**Locations:**
- `js/background.js` (lines 258-300, 305-353, 452-485)
- `js/data_sdk.js` (entire file)
- `js/ig_connect.js` (entire file)

**Description:**
The extension collects and transmits extensive browsing data to multiple endpoints across two different domains (whatruns.com and shopper.com):

#### Data Collection Categories:

**1. Basic Site Analysis Data (background.js)**
- Full URL of every visited page
- Page title
- Document HTML (up to 30KB, sanitized)
- Response headers
- Detected technologies and scripts
- User email and API key (if logged in, base64 encoded)

Transmitted to: `https://www.whatruns.com/api/v1/get_site_apps`

**2. SDK Data Collection (data_sdk.js)**
The extension implements a sophisticated DOM scraping SDK that:
- Matches pages against regex patterns received from the server
- Extracts data from specified DOM elements using XPath
- Collects form inputs and checkout data
- Monitors AI prompt inputs (ChatGPT, etc.) with debounced keylogging
- Generates persistent UUID for tracking

Data endpoints:
- `https://www.whatruns.com/api/v1/collect_data` (general page data)
- `https://www.whatruns.com/api/v1/collect_checkout_data` (e-commerce checkout flows)
- `https://www.whatruns.com/api/v1/collect_prompt_data` (AI prompt monitoring)

Example from `data_sdk.js:82-96`:
```javascript
processDataAndSendCaptify: async function() {
    try {
        const pagePath = window.location.href;
        const pageData = {
            url: pagePath,
            title: document ? document.title : "",
            referrer: document.referrer || "",
            uuid: await this.getUUID(), // persistent tracking UUID
            plugin_version: chrome.runtime.getManifest().version
        }
        var message = { id: SEND_DATA_SDK, data: pageData };
        this.sendMessageToChrome(message, response => { });
    }
}
```

**3. Product Image Grabber (ig_connect.js)**
On every page, the extension:
- Scrapes up to 15 product images from the page
- Checks if the domain is on a server-provided "store list"
- Queues product data to `shopper.com` (a separate service)
- Batches 10 pages before transmission or syncs every 30 minutes

Example from `ig_connect.js:16-62`:
```javascript
grabProductData: async function() {
    let CurrentUrl = window.location.href;
    let pageData = {
        title: $("title").text(),
        url: CurrentUrl,
        src_set: []
    }
    // Scrapes images from div backgrounds and img tags
    // ... pattern matching for JPG/JPEG/WEBP images ...

    BROWSER.runtime.sendMessage({
        id: IG_CHECK_STORES,
        data: pageData
    });
}
```

Transmitted to: `https://www.shopper.com/image_grabber/api/v1/ext/queue`

**4. Prompt Monitoring (data_sdk.js:173-196)**
The extension monitors AI chat interfaces:
```javascript
processPromptDataAndSend: async function(params) {
    // Finds input elements for ChatGPT, Claude, etc.
    let inputElement = this.getXpathElement(inputDom.xpath);
    if (inputElement) {
        self.debounceInputChange(inputElement, () => {
            self.collectPromptAndSend(params)  // Sends prompts to server
        });
    }
}
```

**Data Flow Trace (ext-analyzer output):**
```
chrome.storage.local.get → fetch (js/background.js)
```

This trace shows that stored user credentials (email, API key) are retrieved and sent with requests to the server.

**Disclosure Assessment:**
The WhatRuns privacy policy discloses data collection for "technology identification" and "product recommendations" but the extent and cross-service nature (shopper.com) may not be fully transparent to users. The AI prompt monitoring is particularly sensitive.

**Impact:**
- Complete browsing history transmitted to third parties
- Persistent user tracking via UUID
- E-commerce behavior profiling (checkout pages, product views)
- AI prompt data collection (potentially sensitive queries)
- Image scraping for unknown purposes (shopper.com integration)

**Mitigation:**
While disclosed, the collection is extensive. Users concerned with privacy should:
- Review the full privacy policy at whatruns.com
- Understand that browsing activity on all sites is transmitted
- Consider the shopper.com data sharing arrangement
- Be aware of prompt monitoring on AI chat sites

## Risk Assessment

**Overall Risk: MEDIUM**

**Breakdown:**
- **Critical Issues:** 0
- **High Issues:** 0
- **Medium Issues:** 2
  1. PostMessage origin validation vulnerability
  2. Extensive data collection and cross-service transmission

**Rationale for MEDIUM (not HIGH):**
1. The extension's data collection is disclosed in its privacy policy
2. The core functionality (identifying website technologies) requires access to page content
3. The extension has 400K users and is published by a known service (whatruns.com)
4. No evidence of credential theft or hidden malicious behavior
5. Users presumably install this knowing it will analyze websites they visit

However, the rating acknowledges:
- The extent of data collection goes beyond basic tech detection
- Cross-service data sharing with shopper.com may not be fully transparent
- AI prompt monitoring is particularly invasive
- PostMessage vulnerability creates attack surface

## Permissions Analysis

**Declared Permissions:**
- `tabs` - Access to tab information (URL, title)
- `activeTab` - Access to currently active tab
- `webRequest` - Monitor network requests for response headers
- `storage` - Store user credentials and tracking UUID
- `<all_urls>` - Access to all websites

**Assessment:**
All permissions are used as declared. The `<all_urls>` permission is necessary for the extension's stated purpose but enables the extensive data collection described above.

## Network Endpoints

### WhatRuns (whatruns.com) - Primary Service
1. `/api/v1/get_site_apps` - Retrieve detected technologies
2. `/api/v1/collect_data` - General page analytics
3. `/api/v1/collect_checkout_data` - E-commerce checkout tracking
4. `/api/v1/collect_prompt_data` - AI prompt monitoring
5. `/api/v1/analysite_site_data` - Site analysis upload
6. `/api/v1/analyse_bulk_site_data` - Batch site data (30 sites)
7. `/api/v1/analyse_emails` - Email extraction (commented out in current version)
8. `/api/v1/ext_review` - User review submission
9. `/api/v1/get_ig_stores` - Retrieve monitored store list

### Shopper (shopper.com) - Secondary Service
1. `/image_grabber/api/v1/ext/queue` - Product image and metadata upload

**External Communication Pattern:**
- Data transmitted on every page load (excluded domains: google.com, facebook.com, youtube.com, twitter.com, instagram.com, baidu.com, yahoo.com, whatsapp.com)
- Batching implemented for bulk site data (30 sites) and product images (10 items or 30 minutes)
- User credentials (email, API key) base64-encoded and sent with most requests

## Code Quality Observations

**Positive:**
- Manifest V3 compliance
- Content Security Policy implemented
- Proper error handling in most functions
- Excluded major domains from data collection (Google, Facebook, etc.)

**Concerns:**
- No origin validation on postMessage handlers
- Extensive client-side data collection capabilities
- Dynamic DOM scraping configuration received from server (XPath selectors)
- Persistent tracking UUID stored locally
- Commented-out email extraction code still present in codebase

## Recommendations

### For Extension Developer:
1. **Fix PostMessage Vulnerability:** Add origin validation to all message event listeners
2. **Enhanced Transparency:** Clearly disclose shopper.com integration and product image scraping in privacy policy
3. **Prompt Monitoring Opt-In:** Make AI prompt monitoring an explicit opt-in feature
4. **Minimize Data Retention:** Implement client-side aggregation and minimize raw data transmission
5. **Remove Dead Code:** Delete commented-out email extraction functionality

### For Users:
1. **Review Privacy Policy:** Understand the full extent of data collection at whatruns.com/privacy
2. **Selective Use:** Consider enabling only on sites where you want to identify technologies
3. **Be Aware:** Browsing history, product views, and AI prompts are transmitted to third parties
4. **Alternative:** If concerned about privacy, consider using the WhatRuns website directly (manual lookup) instead of the extension

## Conclusion

WhatRuns is a legitimate tool that performs its stated function of identifying website technologies. However, it implements extensive background data collection that goes significantly beyond basic technology detection, including e-commerce behavior tracking, AI prompt monitoring, and product image scraping for a secondary service (shopper.com). While this appears to be disclosed in the privacy policy, users should be aware of the comprehensive nature of data transmission. The postMessage vulnerability should be fixed but represents a lower risk compared to the data collection practices.

The MEDIUM risk rating reflects the disclosed-but-extensive nature of data collection, appropriate for an analytics/tracking extension that users knowingly install, but with concerns about the breadth of monitoring and cross-service data sharing.
