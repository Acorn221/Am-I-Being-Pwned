# Vulnerability Report: KDP Spy by Book Bolt

## Metadata
- **Extension ID**: eimimdbkklcfefabegnlclkfakkfdcpc
- **Extension Name**: KDP Spy by Book Bolt
- **Version**: 3.0.25
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

KDP Spy by Book Bolt is a legitimate browser extension designed for authors and publishers who use Amazon's Kindle Direct Publishing (KDP) platform. The extension analyzes Amazon book listings to extract metadata such as sales rankings, pricing, reviews, and estimated sales figures. This data is sent to the Book Bolt service (members.bookbolt.io) after user authentication, where it is presumably used for market research and competitive analysis in the self-publishing industry.

The extension requires users to authenticate with their Book Bolt account credentials before use. It scrapes publicly available Amazon product data, processes it client-side, and transmits structured information to the Book Bolt API. All network requests are made to the declared endpoint (members.bookbolt.io), and the extension only operates on Amazon domains as specified in its host permissions. The extension has been code-signed by Google's Web Store, indicating it passed their automated security checks.

## Vulnerability Details

### 1. LOW: Missing Origin Validation on Message Handlers

**Severity**: LOW
**Files**: scripts/content.min.js, scripts/background.min.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension uses chrome.runtime.onMessage listeners without explicit origin or sender validation. While the extension only operates on Amazon domains and communicates with its own background script, message handlers do not validate the source of incoming messages.

**Evidence**:
```javascript
// content.min.js line 56
chrome.runtime.onMessage.addListener(function(e, t, n) {
  if ("KDPSPY_GetCategories_Ok" === e.action && ...
```

```javascript
// background.min.js line 36
chrome.runtime.onMessage.addListener(function(e, t, r) {
  if ("KDPSPY_GetCategories" === e.action) {
```

**Verdict**: This is a low-severity issue. While message handlers should validate sender.id to ensure messages are from the extension itself, the impact is minimal because:
1. The extension only runs on Amazon domains (content script injection is limited by manifest)
2. Message actions are specific and unlikely to be exploited by malicious pages
3. Sensitive operations require API tokens stored in chrome.storage
4. MV3's service worker architecture provides additional isolation

## False Positives Analysis

The static analyzer flagged this extension with an "obfuscated" flag and detected exfiltration flows. However, these findings require contextualization:

**1. Obfuscation Flag**: The code is minified/bundled using standard build tools (appears to be Browserify based on the module wrapper pattern). This is standard practice for production extensions and not indicative of malicious obfuscation. Source maps are included (.js.map files), which malicious extensions typically omit.

**2. Exfiltration Flow (chrome.storage.local.get → fetch)**: This is the core functionality of the extension. The extension:
   - Stores the user's Book Bolt API token in chrome.storage after authentication
   - Uses this token to authenticate requests to members.bookbolt.io
   - Sends Amazon product data (ASIN, title, price, reviews, BSR) to the Book Bolt API

This is legitimate data collection for a market research tool, not covert exfiltration. The extension's purpose is to analyze Amazon listings and save them to the user's Book Bolt account.

**3. innerHTML Injection**: The extension uses innerHTML to render UI components (category chooser, product grid). While this could theoretically lead to XSS, the data sources are:
   - API responses from members.bookbolt.io (controlled by the extension vendor)
   - Amazon product data scraped from Amazon.com
   - User-controlled input (which is properly escaped in JSON.stringify calls)

The risk of XSS is low because the extension trusts its own API and doesn't inject untrusted third-party content.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| members.bookbolt.io/api/external/login | User authentication | Email, password | LOW - Standard login, uses HTTPS |
| members.bookbolt.io/api/external/get-user-categories | Fetch user's saved categories | API token | LOW - Authenticated request |
| members.bookbolt.io/api/external/save-favorite-product | Save Amazon products to Book Bolt | API token, product metadata (ASIN, title, price, reviews, BSR, author, publisher, etc.) | LOW - Expected functionality |
| members.bookbolt.io/api/external/save-favorite-keywords | Save keywords to Book Bolt | API token, keywords | LOW - Expected functionality |
| members.bookbolt.io/api/external/get-suggestions | Get keyword suggestions | API token, keywords | LOW - Expected functionality |
| www.amazon.com/* | Scrape product pages | None (GET requests via XMLHttpRequest) | LOW - Publicly available data |

All requests use HTTPS and include credentials (with `credentials: "include"` for fetch API calls), suggesting session-based authentication in addition to the API token.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This is a legitimate productivity tool for Kindle publishers with one minor security issue (missing message sender validation). The extension clearly states its purpose through its name and functionality. It requires user authentication, only collects publicly available Amazon data, sends data exclusively to the declared endpoint (members.bookbolt.io), and uses standard security practices (HTTPS, MV3, proper CSP). The "exfiltration" detected by static analysis is actually the extension's core feature - collecting Amazon book data for market research.

The low-severity vulnerability (missing origin validation) does not pose a significant risk in practice due to the extension's limited scope and permission model. Users who install this extension expect and consent to it analyzing Amazon listings and synchronizing data with their Book Bolt account.

**Recommendation**: The extension developer should add sender validation to message handlers (`if (sender.id !== chrome.runtime.id) return;`) as a security best practice, but this does not warrant a higher risk classification for the current version.
