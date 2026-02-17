# Vulnerability Report: SellerAmp SAS - Amazon FBA Analysis Tool

## Metadata
- **Extension ID**: kidmffepbniamfbibhfgdakkggchipjl
- **Extension Name**: SellerAmp SAS - Amazon FBA Analysis Tool
- **Version**: 2.4.13
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

SellerAmp SAS is a legitimate Amazon FBA (Fulfillment by Amazon) arbitrage tool that helps sellers analyze products for online resale. The extension intercepts and manipulates Amazon requests to enable automated product research, including accessing product details, pricing history, and stock levels.

The extension operates as designed for its stated purpose - it manipulates Amazon session cookies and headers to enable automated browsing and data collection on Amazon sites. While this behavior involves significant request interception and cookie manipulation, it appears to be a legitimate commercial tool for Amazon sellers rather than malicious software. The extension uses `externally_connectable` to allow communication with its web dashboard and implements proper error tracking via Sentry.

## Vulnerability Details

### 1. LOW: Broad External Messaging Interface
**Severity**: LOW
**Files**: messageExternalHandler.js, background.js
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)
**Description**: The extension exposes an extensive external messaging API through `externally_connectable` that allows whitelisted domains (including localhost) to send commands such as GET_TAB_HTML, GET_TAB_URL, CREATE_SESSION, FETCH_WITHIN_SESSION, ADD_TO_CART, and REMOVE_FROM_CART.

**Evidence**:
```javascript
// manifest.json - externally_connectable
"externally_connectable": {
  "ids": [
    "kdjdiajopilediaadgkjijbcnegggpdd",
    "kidmffepbniamfbibhfgdakkggchipjl",
    "jiklpimhblckfpniaalmbkmkbaefndil",
    "gfkndgikhlecndckncfohdpblncbgffa"
  ],
  "matches": [
    "*://localhost/*",
    "*://sasend.localhost/*",
    "*://*.selleramp.com/*",
    "*://*.arbitragehero.com/*",
    "*://*.sellerampsas.com/*",
    "*://*.sellertoolkit.co.uk/*",
    "*://app.wamp.com/*",
    "*://uat.wamp.com/*"
  ]
}

// Supported commands include:
const SUPPORTED_COMMANDS = [
  GET_VERSION, GET_TAB_HTML, GET_TAB_URL, IS_TAB_ASIN,
  CREATE_SESSION, FETCH_WITHIN_SESSION, CLOSE_SESSION,
  ADD_TO_CART, REMOVE_FROM_CART, COMMAND_SHOW_SAS_EXT
];
```

**Verdict**: This is a standard pattern for commercial browser extensions that need to coordinate with their web dashboards. The domains are properly scoped to the vendor's infrastructure. The localhost inclusion is likely for development/testing. This is appropriate for the extension's stated purpose of Amazon seller automation.

## False Positives Analysis

The following patterns might appear concerning but are legitimate for this extension type:

1. **Cookie and Header Manipulation**: The extension extensively manipulates cookies and HTTP headers for Amazon requests. This is necessary for its core functionality of automating authenticated Amazon browsing sessions for product research.

2. **Session Management**: Complex session creation/management code that intercepts Amazon cookies (session-id, ubid-*, session-token). This enables the extension to maintain authenticated sessions for automated product lookups.

3. **Request Interception**: Uses declarativeNetRequest to modify headers on Amazon requests. This is required to add authorization headers for the extension's backend API and to manage Amazon session state.

4. **External Script Execution**: The extension can execute scripts to get page HTML (`executeScript`). This is a standard capability needed to extract product information from Amazon pages.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| sas.selleramp.com | Main backend API | Amazon product data, session info, user queries | Low - vendor's own infrastructure |
| o4505148813213696.ingest.sentry.io | Error tracking | Error reports, extension telemetry | Low - standard Sentry error monitoring |
| amazon.com/* (various) | Product data extraction | Modified headers/cookies for automation | Low - expected functionality |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This is a legitimate commercial tool for Amazon FBA sellers with appropriate permissions and behavior for its stated purpose. The extension:

1. **Operates as advertised**: All functionality relates to Amazon product research and arbitrage analysis
2. **Uses vendor infrastructure**: Primary communication is with selleramp.com domains
3. **Implements standard practices**: Sentry error tracking, proper manifest v3 structure
4. **Has transparent purpose**: Product description clearly states it's for Amazon FBA analysis
5. **Cookie manipulation is justified**: Required for automated Amazon session management

The only minor concern is the broad external messaging interface, but this is appropriately scoped to vendor domains and necessary for web dashboard integration. The localhost inclusion is likely for development environments.

**Recommendation**: Safe for use by Amazon sellers who understand they are granting the extension extensive permissions to automate Amazon browsing. Users should verify they trust SellerAmp as a vendor since the extension has deep access to Amazon sessions.
