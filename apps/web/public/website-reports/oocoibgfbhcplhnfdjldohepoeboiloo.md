# Vulnerability Report: KDSPY – Keyword Research for Authors

## Metadata
- **Extension ID**: oocoibgfbhcplhnfdjldohepoeboiloo
- **Extension Name**: KDSPY – Keyword Research for Authors
- **Version**: 5.13.55
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

KDSPY is a legitimate keyword research tool for authors selling books on Amazon. The extension requires user authentication with publishingaltitude.com and collects Amazon book ranking data, which is sent to the publisher's backend server. While the static analyzer flagged data exfiltration flows, these are disclosed and directly related to the extension's core functionality of tracking book sales rankings and providing keyword research insights.

The extension authenticates users via JWT tokens, scrapes book data from Amazon pages, and syncs tracked books to the publisher's backend. All data collection appears to be within the scope of the extension's stated purpose as a book research tool for authors.

## Vulnerability Details

### 1. LOW: User Authentication Data Collection
**Severity**: LOW
**Files**: libs/ui.js (line 408), background.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension collects user login credentials and sends them to publishingaltitude.com for authentication. After successful authentication, it retrieves user profile information via the WordPress REST API endpoint `/wp-json/wp/v2/users/me`.

**Evidence**:
```javascript
// libs/ui.js line 408
.then((e => e.json()))
.then((e => fetch("https://www.publishingaltitude.com/wp-json/wp/v2/users/me", {
    method: "GET",
    headers: {
        Authorization: "Bearer " + e.token,
        Accept: "application/json"
    }
})))
```

**Verdict**: This is expected behavior for a premium tool requiring user accounts. The authentication flow uses JWT tokens and appears to be standard WordPress authentication. No security vulnerability.

### 2. Amazon Book Data Collection (Not a Vulnerability)
**Files**: libs/other.js (trackData function), contentscripts/pageScript.js
**Description**: The extension scrapes book ranking data from Amazon pages, including:
- Book titles, authors, descriptions
- Sales ranks across different Amazon marketplaces
- Estimated sales figures
- Price information
- Review counts

This data is stored locally in chrome.storage and periodically synced via the `trackData()` function. The data collection is:
1. Limited to public Amazon product pages
2. Directly related to the extension's stated purpose (keyword research for authors)
3. User-initiated (users explicitly track books they're researching)

## False Positives Analysis

The static analyzer flagged three exfiltration flows:
1. `document.getElementById → fetch(www.publishingaltitude.com)` - This is the authentication/login flow
2. `chrome.storage.local.get → fetch` - This is syncing tracked book data to user's account
3. `chrome.tabs.query → fetch` - This is gathering data about Amazon tabs for book tracking

All three are legitimate behaviors for a book research tool that requires user accounts and cloud sync functionality. The extension does not access sensitive user data beyond what users explicitly track for research purposes.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| publishingaltitude.com/wp-json/jwt-auth/v1/token | User authentication | Username, password | Low - Standard auth |
| publishingaltitude.com/wp-json/wp/v2/users/me | User profile retrieval | JWT token | Low - Expected |
| chatgpt.com/chat | Optional ChatGPT integration | Book prompts/data | Low - User-initiated |

## Additional Features

### ChatGPT Integration
The extension includes an optional feature to send book research data to ChatGPT for AI-generated insights. This requires explicit user permission for the `https://chatgpt.com/*` origin and is clearly user-initiated through the UI.

### Address Spoofing
The extension can set the user's Amazon shipping address to a US zip code (90210) to ensure consistent pricing/availability data. This is standard for e-commerce research tools that need to normalize data across different user locations.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
KDSPY is a legitimate commercial tool for authors researching book keywords and sales data on Amazon. While it collects and transmits data to its backend server, this behavior is:
1. Disclosed in the extension's description and purpose
2. Necessary for the tool's core functionality
3. Limited to public Amazon product data that users explicitly track
4. Protected by user authentication

The extension does not exhibit malicious behaviors such as:
- Collecting sensitive user data (passwords, credit cards, browsing history)
- Injecting ads or affiliate links
- Operating covertly or without user knowledge
- Accessing data beyond its stated scope

The only minor concern is the use of webpack bundling which makes code review more difficult, but the deobfuscated code shows no evidence of malicious functionality. This is a standard commercial extension with appropriate data handling for its use case.
