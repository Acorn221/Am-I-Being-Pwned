# Vulnerability Report: CJDropshipping

## Metadata
- **Extension ID**: mbndljkgaoailfnpeodnlejigmkdpokb
- **Extension Name**: CJDropshipping
- **Version**: 3.2.3
- **Users**: Unknown (not available in manifest)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

CJDropshipping is a legitimate browser extension designed to facilitate dropshipping operations by allowing users to source products from various e-commerce platforms (AliExpress, 1688, Taobao, Tmall, eBay, DHgate, Shopify) and send sourcing/purchasing requests to CJDropshipping's platform. The extension injects UI elements into product listing and detail pages, provides currency conversion functionality, and manages authentication with the CJDropshipping service.

The extension follows appropriate security practices for a MV3 extension of this type. It uses proper authentication flows with token exchange, stores credentials securely in chrome.storage.sync, and communicates exclusively with its own backend services at cjdropshipping.com. The extension's functionality aligns with its stated purpose and does not exhibit malicious behavior. One minor concern is the use of `chrome.scripting.executeScript` with dynamic code strings in the background worker, which is a less secure pattern but appears to be used only for legitimate UI manipulation.

## Vulnerability Details

### 1. LOW: Dynamic Code Execution for UI Manipulation
**Severity**: LOW
**Files**: js/background.js (lines 117-119)
**CWE**: CWE-94 (Improper Control of Generation of Code)
**Description**: The extension uses `chrome.scripting.executeScript` with dynamically constructed code strings to manipulate the DOM on Shopify pages. Specifically, it shows/hides the extension's add button by executing inline code.

**Evidence**:
```javascript
function shopifyShowOrHide(display) {
  chrome.scripting.executeScript(id, {
    code: `document.querySelector("#sirui_add_button").style.display = "${display}"`
  })
}
```

The `display` parameter comes from controlled logic (hardcoded to "block" or "none"), so there's no direct injection risk, but this pattern is generally discouraged in favor of declarative content scripts or message passing.

**Verdict**: This is a low-severity issue because the dynamic values are controlled by the extension logic rather than user input. However, best practice would be to use message passing to content scripts rather than dynamic code execution.

## False Positives Analysis

The static analyzer flagged this extension as potentially obfuscated. However, upon manual review:

1. **Not Truly Obfuscated**: The code includes some minified libraries (jQuery, md5.min.js) which are standard practice. The extension's own code is deobfuscated and readable, containing Chinese comments indicating it's developed by or for a Chinese dropshipping company.

2. **Chrome Storage Usage**: The extension legitimately uses chrome.storage.sync to persist user authentication tokens and configuration (currency preferences, rate cache). This is appropriate for the extension's functionality.

3. **Token Exchange Pattern**: The extension implements a token swap mechanism where CJ website tokens are exchanged for plugin tokens via `exchangeToken` endpoint. This is a legitimate authentication pattern for integrating a web service with a browser extension.

4. **Content Script Injection**: The extension injects content scripts on `<all_urls>` but only to add a data attribute (`data-cjcrx='addYes'`) for fingerprinting its own presence. Other content scripts are properly scoped to specific e-commerce platforms.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| cjdropshipping.com/userCenterForeignWeb/foreign/swapToken | Exchange CJ web token for plugin token | CJ token (header) | Low - legitimate auth flow |
| cjdropshipping.com/quick-search-product-center/source/sourcing/addAccSource | Submit sourcing request | Product details (name, price, URL, image) | Low - stated functionality |
| cjdropshipping.com/app/externalPurchase/createPurchaseOrder | Create purchase order | Product details | Low - stated functionality |
| cjdropshipping.com/payment-center-web/paySupport/getAllRateExchange | Get currency exchange rates | None | Low - utility function |
| cjdropshipping.com/userCenterForeignWeb/erp/userAttribute/chaXunYongHuXinXi | Get user info and order counts | User token (header) | Low - user data retrieval |

All endpoints are on cjdropshipping.com or cjdropshipping.cn domains and use token-based authentication. No data is sent to third-party domains.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This is a legitimate business tool extension with appropriate permissions and security practices for its stated purpose. The extension:

1. **Proper Scoping**: Uses host_permissions limited to specific e-commerce platforms rather than broad access
2. **Secure Communication**: All API calls use HTTPS and token-based authentication
3. **No Data Exfiltration**: Product data is only sent to CJDropshipping's own backend when users explicitly trigger sourcing requests
4. **No Cookie Harvesting**: Does not access or transmit cookies
5. **Transparent Functionality**: The extension's behavior matches its description as a dropshipping tool
6. **MV3 Compliance**: Properly migrated to Manifest V3 with service worker architecture

The single low-severity finding (dynamic code execution) does not pose a significant security risk in the current implementation. Users should be aware that the extension sends product information to CJDropshipping when they use the sourcing feature, but this is the stated and expected functionality of the tool.
