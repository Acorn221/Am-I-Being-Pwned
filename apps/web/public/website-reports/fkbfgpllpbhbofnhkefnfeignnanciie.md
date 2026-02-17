# Vulnerability Report: NetDocuments

## Metadata
- **Extension ID**: fkbfgpllpbhbofnhkefnfeignnanciie
- **Extension Name**: NetDocuments
- **Version**: 1.10.0.447
- **Users**: ~300,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

NetDocuments is a legitimate enterprise document management extension developed by NetDocuments Software Inc. The extension serves as a bridge between the NetDocuments cloud platform and a local companion application (ndOffice/ndClick) running on localhost ports 60500-60549. Its primary purpose is to enable users to send downloaded files to their NetDocuments account for cloud storage and management.

The extension requests broad permissions (all URLs, tabs, downloads, management, scripting) which are consistent with its functionality but present a theoretical attack surface. Analysis reveals the extension is primarily focused on legitimate document management workflows: it accesses user session data from NetDocuments domains, communicates with a localhost application for file operations, and queries tab information to determine context. One medium-severity concern is the content script's access to sensitive session tokens from NetDocuments pages on all frames without strict origin validation, which could be exploited in edge cases.

## Vulnerability Details

### 1. MEDIUM: Session Token Collection from All Frames
**Severity**: MEDIUM
**Files**: js/contentscript.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The content script runs on all frames (`"all_frames": true`) with pattern `*://*/*` and extracts sensitive authentication data from localStorage/sessionStorage on NetDocuments domains. It grabs membership information, eId, ndClickSessionValue, and ndClickSessionExpDate from page storage without additional frame origin validation.

**Evidence**:
```javascript
// contentscript.js lines 102-106
let membership = $.parseJSON(localStorage.getItem('membership'));
if (membership != undefined && membership.Value != undefined && membership.Value.UserInfo != undefined && sessionStorage.getItem('eIdExp') != null...) {
    let userInfo = membership.Value.UserInfo;
    userInfo.eId = sessionStorage.getItem('eId') == undefined || sessionStorage.getItem('eId') == "" ? "" : sessionStorage.getItem('eId');
    userInfo.ndClickSessionValue = sessionStorage.getItem('hugx')...
```

**Verdict**: MEDIUM severity because while the extension only processes this data on known NetDocuments domains (vault.netvoyage.com, eu.netdocuments.com, etc.), the all_frames injection means it runs in every iframe on those pages. If a NetDocuments page embeds untrusted third-party content in an iframe, the content script could theoretically be manipulated or exploited within that context. However, this is mitigated by the extension's legitimate need to access this data for authentication purposes and the fact that it only sends the data to the background script for local storage.

### 2. LOW: Active Tab URL Exposure to Localhost Application
**Severity**: LOW
**Files**: background.js
**CWE**: CWE-200 (Exposure of Sensitive Information)
**Description**: The extension queries active tab information and sends the domain to the localhost application in multiple request contexts.

**Evidence**:
```javascript
// background.js lines 132-161
chrome.tabs.query({ active: true }, function (tab) {
    let domain = extractHostname(tab[0].url);
    let request = {
        message: "post_request",
        requestId: uniqueId,
        domain: domain,
        data: { domain: domain, action: "apiVersion" },
        ...
    }
    Request(request, null, getVerResponse, "post", "", loginHostUrl, ndClickPort, ndClickSessionValue, eId, userLogin);
});
```

**Verdict**: LOW severity. The active tab URL is sent to https://localhost on a port range 60500-60549, which is the user's own machine running the ndOffice companion app. While this exposes browsing context to the local application, this is expected behavior for enterprise document management software that needs to understand which website context the user is operating in. The localhost communication is necessary for the extension's stated functionality.

## False Positives Analysis

**Static Analyzer Flag: Obfuscated Code**
The static analyzer flagged this extension as "obfuscated". However, examination of the deobfuscated code shows standard webpack-bundled JavaScript with no malicious obfuscation. The code includes readable function names, clear variable names, and standard enterprise software patterns. The bundling is typical for modern web extensions.

**Static Analyzer Flag: chrome.tabs.query → fetch Exfiltration Flow**
The analyzer detected a HIGH-severity flow from chrome.tabs.query to fetch. Investigation shows this is a false positive in the security context: the extension queries active tab information to extract the domain name, then sends requests to localhost (the user's own machine) or to legitimate NetDocuments API endpoints. The data sent is minimal (domain name, user authentication tokens for NetDocuments) and is necessary for the document management workflow. This is not data exfiltration but legitimate cloud service integration.

**Content Script on All URLs**
While the content script matches `*://*/*`, it only actively processes data on NetDocuments domains (vault.netvoyage.com, eu.netdocuments.com, etc.) and remains dormant on other sites. This is a common pattern for extensions that need to detect when users navigate to specific services.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://localhost:60500-60549 | Communication with ndOffice companion app | domain, userLogin, eId, session tokens, file data | Low - localhost only |
| vault.netvoyage.com | NetDocuments US cloud | User auth tokens, domain context | Low - legitimate service |
| eu.netdocuments.com | NetDocuments EU cloud | User auth tokens, domain context | Low - legitimate service |
| au.netdocuments.com | NetDocuments AU cloud | User auth tokens, domain context | Low - legitimate service |
| de.netdocuments.com | NetDocuments DE cloud | User auth tokens, domain context | Low - legitimate service |
| gov.netdocuments.us | NetDocuments US Gov cloud | User auth tokens, domain context | Low - legitimate service |
| can.netdocuments.com | NetDocuments Canada cloud | User auth tokens, domain context | Low - legitimate service |
| ducot.netdocuments.com | NetDocuments testing | User auth tokens, domain context | Low - legitimate service |
| preview.netdocuments.com | NetDocuments preview | User auth tokens, domain context | Low - legitimate service |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

NetDocuments is a legitimate enterprise document management extension from a known commercial vendor (NetDocuments Software Inc.) with 300,000 users and a 4.8 rating. The extension's behavior aligns with its stated purpose: managing downloads and integrating with the NetDocuments cloud platform via a localhost companion application.

The broad permissions (all URLs, tabs, downloads, management, scripting) are justified by the extension's functionality:
- All URLs: Content script needs to inject on NetDocuments domains
- Tabs: Required to query active tab context for document operations
- Downloads: Core functionality for managing downloaded files
- Management: Used to detect which extensions downloaded files
- Scripting: Dynamic content script injection (MV3 requirement)
- WebRequest: Monitor download requests

The one medium-severity issue (session token collection in all frames) is a minor implementation concern that could be hardened by restricting frame injection, but does not represent active malicious behavior. The extension does not perform credential theft, hidden data exfiltration to third parties, or any covert surveillance. All network communication is either to localhost or to the legitimate NetDocuments cloud infrastructure.

The extension would be more secure if it:
1. Restricted content script injection to top frames only (`"all_frames": false`)
2. Added explicit origin checks before accessing localStorage/sessionStorage
3. Narrowed host permissions to only NetDocuments domains rather than all URLs

However, these are defensive hardening recommendations rather than critical vulnerabilities. The extension is safe for use in enterprise environments where NetDocuments is an authorized service.
