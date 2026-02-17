# Vulnerability Report: Email Finder-Kendo Sourcing Ninja

## Metadata
- **Extension ID**: kecadfolelkekbfmmfoifpfalfedeljo
- **Extension Name**: Email Finder-Kendo Sourcing Ninja
- **Version**: 6.702
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Email Finder-Kendo Sourcing Ninja is a recruiting/sourcing tool designed to extract contact information from LinkedIn, Crunchbase, and Google search results. The extension scrapes DOM content (company names, profile data) from these sites and sends it to the kendoemailapp.com backend for email discovery and lead management. The extension also integrates with various CRM systems (HubSpot, Zoho, Salesflare, etc.) to export discovered contacts.

All data collection and transmission is consistent with the extension's stated purpose as an email finder and recruiting tool. The extension operates transparently within its declared scope and does not exhibit malicious behavior beyond its intended functionality.

## Vulnerability Details

### 1. LOW: Data Collection Without Explicit User Consent Prompts
**Severity**: LOW
**Files**: contentScript.bundle.js, background.bundle.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension automatically scrapes DOM content from LinkedIn profiles, company pages, and search results without displaying explicit consent dialogs to the user. Profile information, company names, and URLs are extracted from the page and sent to kendoemailapp.com.

**Evidence**:
```javascript
// contentScript.bundle.js:28692-28723
var i = document.querySelector(".org-top-card__primary-content h1").textContent
// Scrapes company name from LinkedIn
chrome.runtime.sendMessage({
  contentScriptQuery: _e.setcompany,
  data: {
    comid: s,
    name: i,
    domain: l
  }
})

// background.bundle.js:34
fetch("https://kendoemailapp.com/kendoquery2?url=".concat(
  encodeURIComponent(t.url),
  "&id=", encodeURIComponent(t.id),
  "&cmp=", encodeURIComponent(t.cmp)
))
```

**Verdict**: This is expected behavior for a recruiting/sourcing tool. Users install this extension specifically to extract contact information from professional networking sites. The data collection is consistent with the extension's description and purpose.

## False Positives Analysis

The static analyzer flagged 6 exfiltration flows as HIGH severity, but these are all legitimate functionality for this extension type:

1. **Document scraping → fetch(kendoemailapp.com)**: This is the core functionality of the extension—extracting profile/company data from LinkedIn/Crunchbase and sending to the backend for email discovery.

2. **chrome.storage.local.get → fetch**: Retrieves user preferences (CRM metadata, saved lists) and includes them with API requests to maintain user session state.

3. **Flows through www.w3.org**: These appear to be false positives in the static analyzer, likely from React/webpack boilerplate or polyfills that don't actually transmit data externally.

The extension is a **legitimate business tool** similar to other recruiting software like Hunter.io or LinkedIn Sales Navigator. Data exfiltration is the primary purpose, not a security flaw.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| kendoemailapp.com/kendoquery2 | Retrieve email/contact info | URL, profile ID, company name, member ID | LOW - Expected |
| kendoemailapp.com/kendoquerysavecrm | Export contacts to CRM | Profile data, CRM metadata | LOW - Expected |
| kendoemailapp.com/kendoquerysavelist | Save leads to list | Lead list data | LOW - Expected |
| kendoemailapp.com/kendoquerycompany | Fetch company info | Company ID, name, domain | LOW - Expected |
| kendoemailapp.com/kendoqueryverify | Verify account/credits | User data with CRC checksum | LOW - Expected |
| kendoemailapp.com/kendoquerybatch | Batch process leads | Bulk lead data | LOW - Expected |
| kendoemailapp.com/kendoqueryhelp | Support request | User help request data | LOW - Expected |
| kendoemailapp.com/welcome | Onboarding | None (redirect only) | CLEAN |

All endpoints belong to the same vendor (kendoemailapp.com) and serve the extension's stated purpose.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This extension functions exactly as advertised—it's an email finder and recruiting sourcing tool. While it does exfiltrate DOM content from LinkedIn, Crunchbase, and Google search results, this is the entire purpose of the extension. Users who install this extension are explicitly seeking this functionality.

The extension:
- Only operates on sites listed in content_scripts matches (LinkedIn, Crunchbase, Google, kendoemailapp.com)
- Sends data exclusively to the vendor's domain (kendoemailapp.com)
- Uses appropriate CRC checksums for data integrity
- Implements standard CRM integrations (HubSpot, Zoho, etc.)
- Does not inject ads, modify page content maliciously, or access unrelated browsing data

The LOW rating reflects that while the extension does collect and transmit user-initiated profile data, this is disclosed behavior for a recruiting tool. There are no hidden data leaks, no credential theft, and no deceptive practices beyond the extension's stated scope.
