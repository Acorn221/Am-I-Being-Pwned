# Vulnerability Report: Wildix Collaboration

## Metadata
- **Extension ID**: lobgohpoobpijgfegnlhdnppegdbomkn
- **Extension Name**: Wildix Collaboration
- **Version**: 2.0.3
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Wildix Collaboration is a legitimate enterprise VoIP/UC (Unified Communications) extension that provides click-to-call functionality and quick access to Wildix collaboration platforms. The extension integrates with Wildix PBX systems to enable users to make phone calls directly from web pages by clicking on phone numbers.

While the extension appears to be legitimate enterprise software from Wildix (a known VoIP provider), it requests several broad permissions that raise security concerns. The extension has access to the `management` API (which allows it to query and control other extensions), `scripting` permission with `<all_urls>` host permissions, and exposes an external messaging interface to wildixin.com domains. These permissions are excessive for its stated purpose and create a medium-risk attack surface.

## Vulnerability Details

### 1. MEDIUM: Excessive Permissions for Click-to-Call Functionality

**Severity**: MEDIUM
**Files**: manifest.json, background.js, js/app.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests overly broad permissions that exceed what's necessary for click-to-call functionality:

- `management` permission allows the extension to enumerate, disable, and interact with other extensions
- `scripting` permission with `http://*/*` and `https://*/*` host permissions allows injection into all websites
- Content scripts run on all HTTP/HTTPS URLs with `document_start` timing

**Evidence**:

```json
"permissions": [
    "tabs",
    "storage",
    "contextMenus",
    "notifications",
    "management",
    "scripting"
],
"host_permissions": [
    "http://*/*",
    "https://*/*"
]
```

The extension uses `management` API to check for and interact with a companion Wildix app:

```javascript
// app.js line 45
chrome.management.get(this.keyAppWil, (ext) => {
    if(!chrome.runtime.lastError && ext && ext.enabled == true){
        this.appWil = ext;
        this.setIcon('online');
        this.setTitle();
    }
});
```

**Verdict**: While the `management` permission is used for legitimate functionality (checking if a companion app is installed), this creates an attack surface. If the extension were compromised, it could manipulate other extensions. The broad host permissions are necessary for click-to-call on any website but still represent elevated privileges.

### 2. MEDIUM: Externally Connectable Messaging Interface

**Severity**: MEDIUM
**Files**: manifest.json, js/contentScriptCti.js
**CWE**: CWE-923 (Improper Restriction of Communication Channel to Intended Endpoints)
**Description**: The extension exposes a messaging interface to external websites under the `*.wildixin.com` domain via `externally_connectable`. This allows any page on wildixin.com to send messages to the extension.

**Evidence**:

```json
"externally_connectable": {
    "matches": ["*://*.wildixin.com/*"]
}
```

Content script accepts postMessage from window but validates origin:

```javascript
// contentScriptCti.js line 41
window.addEventListener('message', (event) => {
    if(event.origin && event.origin != window.location.origin){
        return;
    }
    // ... processes commands like 'appWindowFocus', 'connect', 'disconnect'
});
```

**Verdict**: The origin validation in the content script only checks that messages come from the same origin as the page, not that they come from wildixin.com. However, the content script only runs on cticonnect/collaboration URLs (which should be Wildix domains). The externally_connectable pattern allows external sites to communicate with the extension, which could be exploited if a wildixin.com subdomain were compromised.

### 3. LOW: Extension Enumeration via Management API

**Severity**: LOW
**Files**: js/app.js
**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
**Description**: The extension uses the `management` API to check for the presence of a specific Wildix application extension by its ID.

**Evidence**:

```javascript
// app.js line 14
keyAppWil: 'klaamdejgopombbjfpfhlebpjlmokgna',

// app.js line 45-55
chrome.management.get(this.keyAppWil, (ext) => {
    if(!chrome.runtime.lastError && ext && ext.enabled == true){
        this.appWil = ext;
        // ...
    }
});
```

**Verdict**: This is standard behavior for enterprise VoIP extensions that work in conjunction with desktop applications. Extension enumeration is used only to check for a companion app, not to fingerprint users or disable security extensions. This is LOW severity as it's limited to checking for one specific extension.

## False Positives Analysis

1. **Dynamic Script Injection**: The extension injects content scripts into all open tabs after installation/update (background.js lines 12-54). This appears suspicious but is a legitimate pattern to ensure the extension works on already-open tabs without requiring a reload.

2. **Network Requests to User-Configured Hosts**: The extension makes API calls to PBX hosts that users configure (e.g., `${host}/api/v1/Calls/`). This is expected behavior for an enterprise VoIP extension that connects to customer-specific infrastructure.

3. **Management API Usage**: While the `management` permission is powerful, it's only used to check if a companion Wildix app is installed and to launch it. This is legitimate for enterprise software that consists of multiple components.

4. **Backbone.js Library**: The extension uses Backbone.js and Underscore.js (legacy libraries), which might appear as "obfuscated" code in minified form but are standard legitimate frameworks.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| User-configured PBX host `/api/v1/Calls/` | Initiate phone calls | Phone number, device ID | LOW - requires user configuration, legitimate VoIP function |
| User-configured PBX host `/api/v1/Originate/Call` | Initiate calls (older PBX versions) | Phone number | LOW - legacy call initiation |
| User-configured PBX host `/api/v1/PBX/version/` | Get PBX version | None (header: UA: chromeExtension) | LOW - version check for compatibility |
| User-configured PBX host `/api/v1/PBX/candidates` | Get network addresses/failover hosts | None | LOW - discovers alternate PBX addresses |
| User-configured PBX host `/api/v1/PBX/ping/` | Health check PBX availability | None | LOW - connection testing |
| `*.wildixin.com` | External messaging (via externally_connectable) | Varies by command | MEDIUM - opens messaging channel |

All endpoints except wildixin.com are user-configured PBX hosts (typically enterprise-owned infrastructure). The wildixin.com domain is the legitimate domain of Wildix, a known VoIP provider.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This is a legitimate enterprise VoIP extension from Wildix, a recognized unified communications provider. The extension's core functionality (click-to-call, PBX integration, failover management) is consistent with its stated purpose.

However, the risk level is MEDIUM due to:

1. **Excessive Privileges**: The combination of `management`, `scripting`, and `<all_urls>` permissions creates a significant attack surface. If this extension were compromised (e.g., through a supply chain attack, malicious update, or XSS in the Wildix web app), an attacker could gain broad control over the browser.

2. **External Messaging Interface**: The `externally_connectable` configuration allows any subdomain of wildixin.com to message the extension. If a wildixin.com subdomain were compromised, it could potentially abuse this channel.

3. **Enterprise Deployment Context**: This extension is likely deployed in enterprise environments where users may not have manually reviewed permissions. The broad access could be leveraged by an attacker who compromises the extension.

The extension does NOT exhibit malicious behavior in its current form. All network communications go to user-configured PBX hosts (customer infrastructure) or Wildix's legitimate domains. There is no evidence of data exfiltration, credential theft, or hidden functionality.

**Recommendations**:
- Enterprise IT should review whether the `management` permission is necessary for their deployment
- The `externally_connectable` configuration should be restricted to specific subdomains rather than `*.wildixin.com`
- Content script scope could be limited to specific URL patterns where click-to-call is needed rather than all URLs
- Regular security audits should verify the extension hasn't been compromised
