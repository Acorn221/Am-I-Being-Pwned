# Vulnerability Report: PrettyMerch for Merch by Amazon™

## Metadata
- **Extension ID**: ahclfnpmodphlaiidnpjlkndabpnihea
- **Extension Name**: PrettyMerch for Merch by Amazon™
- **Version**: 7.92
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

PrettyMerch is a productivity dashboard for Amazon Merch sellers that monitors sales, product listings, and provides analytics. The extension fetches seller data from Amazon's Merch dashboard and sends it to the developer's API at `api.prettymerch.com` for processing and storage. While this behavior aligns with the extension's stated purpose of providing "a beautiful dashboard for Merch by Amazon," the extent of data collection and the use of minified/bundled code reduces transparency.

The extension collects comprehensive seller data including product listings, sales figures, customer IDs, account IDs, royalties, BSR rankings, and review data, then transmits this to external servers. The functionality is appropriate for a seller analytics tool, but users should be aware of the data being shared with a third-party service.

## Vulnerability Details

### 1. MEDIUM: Extensive Seller Data Collection and Transmission

**Severity**: MEDIUM  
**Files**: background.min.js, common.min.js  
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)  
**Description**: The extension collects detailed Amazon Merch seller data and transmits it to `api.prettymerch.com`. Data includes:
- Customer IDs and Account IDs (extracted via regex from dashboard HTML)
- Complete product listings with ASINs, titles, prices, status
- Sales data including dates, royalties, quantities
- Product metadata (BSR rankings, reviews, availability)
- User preferences and license keys

**Evidence**:
```javascript
// Extracting designer ID from dashboard
const e = /"accountId":"([A-Za-z0-9]*)"/g;
a = /"customerId":"([A-Za-z0-9]*)"/g.exec(t)[1], r = e.exec(t)[1], 
G_DESIGNER_ID.customerId = a, G_DESIGNER_ID.accountId = r

// Sending to external API
await fetch("https://api.prettymerch.com/research/search_product_v5xxxF.php", o)
fetch("https://api.prettymerch.com/trademark/search_tm_v5xxxF.php", {...})
fetch("https://api.prettymerch.com/validateLicence/validate_licence_Lrg6Ra.php", o)
```

**Verdict**: This is expected behavior for a third-party analytics dashboard. The extension's description states it provides "a beautiful dashboard for Merch by Amazon" which necessarily involves collecting and processing seller data. However, the extent of data sharing with external servers should be clearly disclosed to users. Risk is MEDIUM due to the sensitive nature of business data being transmitted to a third party.

### 2. LOW: Minified Code Reduces Transparency

**Severity**: LOW  
**Files**: background.min.js, content.min.js, common.min.js  
**CWE**: CWE-506 (Embedded Malicious Code)  
**Description**: All JavaScript files are minified with variable name obfuscation, making it difficult for users or researchers to audit the code's behavior. While deobfuscation reveals legitimate functionality, the minified distribution reduces transparency.

**Evidence**: Files use single-letter variable names and are bundled, though the code structure suggests webpack bundling rather than intentional obfuscation.

**Verdict**: Minification is common practice for production extensions to reduce file size, but it does make security auditing more difficult. Combined with the extensive permissions and data collection, this warrants noting but is not inherently malicious.

## False Positives Analysis

The static analyzer flagged several data flows as potential exfiltration:
- `chrome.storage.local.get → fetch(merch.amazon.com)` - This is the extension reading cached data and then making legitimate API calls to Amazon's Merch platform
- `chrome.storage.sync.get → fetch(merch.amazon.com)` - Same as above, using sync storage for user preferences
- `chrome.tabs.query → fetch(merch.amazon.com)` - Used to check if Merch dashboard tabs are open before making API calls

These are all legitimate operations for a dashboard extension that needs to interact with Amazon's Merch API. The extension does not access `merch.amazon.com` maliciously but rather uses Amazon's official API endpoints for fetching seller data.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| merch.amazon.com/dashboard | Fetch seller dashboard data | None (GET request) | Low - Official Amazon API |
| merch.amazon.com/api/* | Various seller data endpoints | None (GET requests) | Low - Official Amazon API |
| api.prettymerch.com/validateLicence/* | License validation | User ID, license key | Medium - Third party receives identifiers |
| api.prettymerch.com/research/search_product_v5xxxF.php | Product research | Search queries, marketplace, filters | Medium - Business analytics data |
| api.prettymerch.com/trademark/search_tm_v5xxxF.php | Trademark search | Keywords, marketplace | Low - Public data queries |
| gumroad.com | License purchase/validation | User credentials (license) | Low - Legitimate payment processor |
| images.amazon.com | Product images | ASINs | Low - Public product images |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: PrettyMerch is a legitimate productivity tool for Amazon Merch sellers that functions as described. The data collection and external transmission align with its stated purpose of providing analytics and enhanced dashboard functionality. However, the risk is elevated to MEDIUM because:

1. Sensitive business data (sales figures, account IDs, product performance) is transmitted to a third-party service
2. Users should be clearly informed about what data is shared with `api.prettymerch.com`
3. Minified code makes independent verification difficult
4. The extension requires broad host permissions across multiple Amazon domains

This is not malware or a scam - it's a functional tool that delivers its promised features. Users should evaluate whether they're comfortable sharing their Amazon Merch business data with the PrettyMerch service in exchange for enhanced analytics and dashboard features.
