# Vulnerability Report: GMB Everywhere - GBP Audit for Local SEO

## Metadata
- **Extension ID**: oibcaeeplepnjfjhokfcabnaafodppik
- **Extension Name**: GMB Everywhere - GBP Audit for Local SEO
- **Version**: 5.1.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

GMB Everywhere is a Local SEO audit tool that analyzes Google Business Profile (GBP) listings on Google Maps and Google Search. The extension scrapes business information from Google pages and transmits this data to external servers operated by gmbeverywhere.com for processing and analysis. While the extension's core functionality aligns with its stated purpose as a competitive SEO intelligence tool, it collects and exfiltrates significant amounts of business data along with user search queries.

The extension's data collection is disclosed through its description which explicitly mentions "spy, audit, and crush your GMB competitor," indicating competitive intelligence gathering. However, the extent of data collection—including business names, addresses, phone numbers, review counts, ratings, geographic coordinates, and user search terms—raises moderate privacy concerns. The extension operates only on Google domains and requires minimal permissions (storage only), which limits its attack surface.

## Vulnerability Details

### 1. MEDIUM: Business Data Exfiltration to Third-Party Servers

**Severity**: MEDIUM
**Files**: dist/content.bundle.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension systematically collects detailed business profile information from Google Maps and Google Search results pages, then transmits this data to external servers at `data.gmbeverywhere.com` and `app.gmbeverywhere.com`. The collected data includes:

- Business names and categories
- Street addresses
- Phone numbers
- Review counts and ratings
- Geographic coordinates (latitude/longitude)
- Place IDs and Knowledge Graph IDs
- Website URLs
- Business verification status
- Customer ID values
- Business profile IDs

**Evidence**:
```javascript
// Lines 360-374: Data structure being extracted
return {
  categories: o,
  phoneNumber: l,
  businessName: s,
  numberOfReviews: i,
  averageReviewRating: r,
  placeId: d,
  kgId: c,
  address: u,
  website: p,
  latlong: n,
  isBusinessVerified: h,
  cidValue: m,
  businessProfileId: g
}

// Lines 509-524: Data transmission to external server
const I = e => new Promise(((n, r) => {
  const i = t["audit-dashboard"]["send-data-api-url"], // https://data.gmbeverywhere.com/xano/save-temporary-data-to-store
    a = {
      url: e.url,
      rawData: e.windowArray
    };
  q(i, {
    unique_code: e.dataUniqueCode,
    data: JSON.stringify(a),
    feature_type: "basic-audit"
  })
```

**Verdict**: This data collection is disclosed in the extension's description, which explicitly markets it as a tool to "spy, audit, and crush your GMB competitor." The functionality is consistent with competitive SEO intelligence gathering. However, the collection of comprehensive business data including phone numbers and precise geographic coordinates represents a moderate privacy concern, especially since this data is sent to third-party servers. The data appears to be scraped from publicly visible Google pages, mitigating some concerns.

### 2. MEDIUM: User Search Query Collection

**Severity**: MEDIUM
**Files**: dist/content.bundle.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension captures user search queries from the Google search box and includes them in data transmitted to external servers. This reveals user search behavior and intent to third parties.

**Evidence**:
```javascript
// Lines 813-821: Search term collection and transmission
const u = {
  url: window.location.href,
  searchTerm: null === (i = document.querySelector("#searchboxinput")) || void 0 === i ? void 0 : i.value,
  rawData: r
};
q(s, {
  unique_code: a,
  data: JSON.stringify(u),
  feature_type: H
})
```

**Verdict**: The extension collects and transmits user search queries (e.g., "dentist nearby," "plumber in Chicago") along with business data. While this is likely used to provide context for the SEO analysis (understanding what search terms return which businesses), it represents user behavioral tracking. This is a moderate concern as search queries can reveal user location, interests, and business needs. There is no clear indication in the extension's privacy policy or description that user search queries are collected.

## False Positives Analysis

The static analyzer flagged this extension as "obfuscated," but this is a false positive. The code is webpack-bundled and minified using standard build tools (variables are shortened to single letters like `e`, `t`, `n`), which is normal for production JavaScript. The code structure is readable and follows typical patterns for modern web extensions.

The extension does not employ actual obfuscation techniques such as:
- String encoding or character escaping to hide URLs
- Control flow flattening
- Dead code injection
- Runtime code generation to hide functionality

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| data.gmbeverywhere.com/xano/save-temporary-data-to-store | Data storage API | Business profiles (name, address, phone, coordinates, reviews), user search queries, raw Google Maps state data | MEDIUM - Comprehensive business and user data collection |
| app.gmbeverywhere.com/release7/audit-dashboard.html | Audit dashboard | Dashboard rendering with business details | LOW - Display only |
| app.gmbeverywhere.com/release7/audits/basic-audit.html | Basic audit interface | Business details via URL parameters | LOW - Analysis interface |
| app.gmbeverywhere.com/release7/audits/review-audit.html | Review audit interface | Business details via URL parameters | LOW - Analysis interface |
| app.gmbeverywhere.com/release7/category-tool/category-finder.html | Category tool | Business categories | LOW - Category lookup |
| app.gmbeverywhere.com/release7/local-scan/local-scan.html | Local scan dashboard | Aggregated local business data | MEDIUM - Bulk competitor data |
| app.gmbeverywhere.com/release7/admin-pages/uninstall-page.html | Uninstall feedback | No data sent | NONE - Feedback page |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

GMB Everywhere operates as disclosed—a competitive intelligence tool for Local SEO analysis. The extension collects publicly available business information from Google Maps and Google Search, which aligns with its stated purpose of helping users "audit and spy on" competitors' Google Business Profiles.

The MEDIUM risk rating is assigned based on:

1. **Disclosed Functionality**: The extension description explicitly mentions its competitive intelligence purpose ("spy, audit, and crush your GMB competitor"), providing transparency about data collection.

2. **Extensive Data Collection**: The extension collects comprehensive business details including phone numbers, addresses, and precise geographic coordinates, which goes beyond basic SEO metrics.

3. **User Search Query Tracking**: Collection of user search terms represents behavioral tracking that may not be clearly disclosed to users.

4. **Third-Party Data Transmission**: All collected data is sent to external servers, creating privacy and data security dependencies on the vendor.

5. **Limited Permissions**: The extension only requests `storage` permission and operates exclusively on Google domains, which limits its ability to access sensitive user data or operate on other sites.

6. **No Credential Theft**: The extension does not attempt to access user credentials, cookies, or authentication tokens.

7. **Public Data Source**: The data being collected appears to be scraped from publicly visible Google Business Profile pages, not from private user accounts.

The extension is not malicious but represents a moderate privacy concern due to the volume and sensitivity of business data collected and the inclusion of user search behavior tracking. Users installing this extension should be aware that their search queries and the business data they view will be transmitted to gmbeverywhere.com servers.
