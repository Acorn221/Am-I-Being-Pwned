# Vulnerability Report: Block Site

## Metadata
- **Extension ID**: lebiggkccaodkkmjeimmbogdedcpnmfb
- **Extension Name**: Block Site
- **Version**: 0.5.8
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Block Site is a legitimate website blocking extension that allows users to block or allow access to specific websites using Chrome's declarativeNetRequest API. The extension implements password protection for modifying block lists and includes scheduling features. The code is well-structured, uses modern Manifest V3 APIs, and shows no signs of malicious behavior. The only network request made is a benign fetch to retrieve blocked page titles for display purposes (with credentials omitted). The extension functions entirely as advertised with no privacy or security concerns beyond one minor issue.

## Vulnerability Details

### 1. LOW: Cross-Origin Fetch Without Origin Validation
**Severity**: LOW
**Files**: data/blocked/index.js (lines 87-92)
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension fetches the title of blocked pages using `fetch(href, {credentials: 'omit'})` without explicit origin validation. While credentials are properly omitted, this could theoretically be abused if a malicious page is set as a blocked URL.
**Evidence**:
```javascript
const title = () => fetch(href, {
  credentials: 'omit'
}).then(r => r.text()).then(content => {
  const dom = new DOMParser().parseFromString(content, 'text/html');
  document.getElementById('title').textContent = dom.title || 'Unknown';
}).catch(() => document.getElementById('title').textContent = 'Unknown');
```
**Verdict**: This is a very minor issue. The fetch properly omits credentials and the response is only used to extract the page title for display on the blocked page. No sensitive data is sent or exposed. This is a legitimate feature to show users what page they tried to access.

## False Positives Analysis

1. **Host Permissions (<all_urls>)**: Required for a site blocking extension to function. The extension needs to inspect URLs and apply blocking rules across all sites.

2. **Content Script on <all_urls>**: The content script (page-blocker.js) legitimately validates that pages loaded aren't in the blocked list and blocks them at document_start if needed. This is core functionality.

3. **External Fetch**: The single fetch call retrieves blocked page titles for user display only, with credentials properly omitted. Not exfiltration.

4. **Password Storage**: The extension stores SHA-256 hashed passwords in local storage for legitimate password protection of block list modifications. This is a security feature, not a vulnerability.

5. **Managed Storage**: The extension reads from managed storage (schema.json) to allow enterprise/admin configuration. This is a standard enterprise feature.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| webextension.org | Homepage URL in manifest | None (just manifest reference) | None |
| Blocked URLs | Fetch page title for display | None (credentials omitted) | Very Low |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: Block Site is a legitimate, well-designed website blocking extension that functions exactly as advertised. The extension:

- Uses modern Manifest V3 APIs (declarativeNetRequest) for blocking
- Implements proper password protection with SHA-256 hashing
- Makes only one network request (fetching blocked page titles) with credentials properly omitted
- Stores all data locally with no external transmission
- Includes enterprise management support via managed storage
- Has no obfuscation, no hidden functionality, no tracking, no analytics

The single LOW-severity finding is a minor design consideration around fetching titles of blocked pages, which is actually a user-facing feature. The extension is clean and poses no security or privacy risks to users.
