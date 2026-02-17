# Vulnerability Report: Who Unfollowed Me?

## Metadata
- **Extension ID**: fgeghoapchhdkpflicgicmiabmpeklkn
- **Extension Name**: Who Unfollowed Me?
- **Version**: 1.1.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Who Unfollowed Me?" is an Instagram follower tracking extension that compares follower lists over time to identify who has unfollowed the user. While the core functionality is legitimate, the extension collects and transmits user email addresses and potentially Instagram follower data to invertexto.com without clear disclosure in the extension's description. The extension implements a license verification system that requires users to purchase access through invertexto.com, with email addresses being sent to their server for validation. Additionally, the static analyzer detected data flows from chrome.storage to external endpoints, suggesting follower information may be exfiltrated beyond what is necessary for the stated functionality.

The extension is classified as MEDIUM risk due to undisclosed data collection practices and potential privacy concerns around user email and Instagram data being sent to third-party servers.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Email Collection and Transmission
**Severity**: MEDIUM
**Files**: license.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension collects user email addresses for license verification and transmits them to invertexto.com without clear disclosure in the extension description. Users enter their email to activate a paid license, which is sent to `https://www.invertexto.com/licenses/check.php?product=unfollowed&email=` for validation.
**Evidence**:
```javascript
// license.js lines 15-28
fetch("https://www.invertexto.com/licenses/check.php?product=unfollowed&email=" + a)
  .then(a => a.json())
  .then(b => {
    if ("ok" != b.status) return alert(b.status);
    const c = {
      email: a,
      expiration: b.expiration
    };
    chrome.storage.local.set({
      license: c
    }, () => {
      licenseDiv.innerHTML = activeLicenseHtml(c)
    })
  })
```
**Verdict**: While license verification is a legitimate business practice, the extension description ("Load your followers on different days to find out who unfollowed you during the period") does not mention email collection or transmission to external servers. This represents a disclosure gap.

### 2. MEDIUM: Potential Instagram Data Exfiltration
**Severity**: MEDIUM
**Files**: contentScript.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The static analyzer detected a data flow from `chrome.storage.local.get` to `fetch(www.instagram.com)`, suggesting that stored data (potentially including follower lists) may be transmitted. While the Instagram API calls appear to be for legitimate follower retrieval, the presence of chrome.storage data in these requests raises questions about what additional data might be included.
**Evidence**:
```
EXFILTRATION (3 flows):
  [HIGH] chrome.storage.local.get → fetch(www.invertexto.com)    license.js
  [HIGH] chrome.storage.local.get → fetch(www.instagram.com)    contentScript.js
```
**Verdict**: The extension stores follower data locally in chrome.storage and makes API calls to Instagram. While the code review shows the primary purpose is to fetch new follower data, the data flow pattern suggests stored data could potentially be included in requests. This requires clearer documentation about what data is transmitted and why.

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated," but upon review, the code appears to be standard minified JavaScript rather than intentionally obfuscated malware. The variable naming (single letters) and structure are consistent with typical minification tools used in production extensions.

The Instagram API calls themselves are legitimate and necessary for the extension's core functionality - it must query Instagram's GraphQL API to retrieve follower lists for comparison.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.instagram.com/api/v1/users/{id}/info/ | Retrieve user profile info including follower count | Instagram session headers (CSRF token, App ID) | Low - Standard Instagram API usage |
| www.instagram.com/graphql/query/ | Fetch paginated follower lists | Instagram session headers, user ID, pagination cursor | Low - Required for core functionality |
| www.invertexto.com/licenses/check.php | License validation | User email address in GET parameter | Medium - Email transmission not disclosed |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: The extension provides legitimate Instagram follower tracking functionality but engages in data collection practices (email addresses) that are not clearly disclosed in the extension description. While there is no evidence of malicious intent, the lack of transparency around data transmission to invertexto.com and the potential for follower data exfiltration elevates the privacy risk. The extension would be rated LOW if it included clear disclosures about email collection and data transmission in its description and privacy policy. Users should be aware that their email addresses are sent to invertexto.com servers and that the extension makes extensive API calls to Instagram to retrieve follower information.
