# Vulnerability Report: RapidIdentity SnapApp

## Metadata
- **Extension ID**: nhcgblhkgldoffihfhknehpiclghkjom
- **Extension Name**: RapidIdentity SnapApp
- **Version**: 2024.2.0.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

RapidIdentity SnapApp is a legitimate enterprise Single Sign-On (SSO) extension developed by Identity Automation, LP. The extension provides form-fill SSO capabilities when used with the RapidIdentity product. It operates by communicating with a native host application (`identity.automation.snapapp.com`) via Chrome's native messaging API to retrieve and autofill login credentials on all websites.

While the extension serves a legitimate enterprise purpose, it presents medium-level security considerations due to its broad permissions and data handling practices. The extension has access to all websites via `<all_urls>` permissions and handles sensitive credential data by communicating with a native application. The static analyzer detected one exfiltration flow where tab information is sent to the native host application.

## Vulnerability Details

### 1. MEDIUM: Broad Credential Access via Native Messaging

**Severity**: MEDIUM
**Files**: js/background.js, js/content.js
**CWE**: CWE-257 (Storing Passwords in a Recoverable Format)
**Description**: The extension communicates with a native host application to retrieve and manage user credentials for all websites. While this is the intended functionality for an enterprise SSO tool, it creates a central point of credential exposure if the native application or extension is compromised.

**Evidence**:
```javascript
// background.js - Line 211-227
chrome.runtime.sendNativeMessage(o.HOST_NAME, {
  command: o.REQUEST_COMMAND.GET_CREDENTIALS,
  tabId: t,
  webRequest: {
    siteUrl: s
  }
}, i)
```

```javascript
// content.js - Lines 355-361
function P(e) {
  const {
    username: t,
    password: n,
    thirdField: r
  } = e.userDetails;
  p && D(p, t), // Fill username field
  l && (l.setAttribute("type", o.INPUT_TYPE.PASSWORD), D(l, n)), // Fill password field
  T && D(T, r), // Fill third field
}
```

**Verdict**: This is expected behavior for an enterprise SSO solution. The risk is medium because the extension requires a companion native application to function, which should be deployed and managed by enterprise IT administrators. However, if either component is compromised, credentials for all sites could be exposed.

### 2. MEDIUM: Tab and URL Information Sent to Native Host

**Severity**: MEDIUM
**Files**: js/background.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension sends tab information including URLs to the native host application for every website visited. This creates a browsing history log that is transmitted outside the browser.

**Evidence**:
```javascript
// background.js - Line 174
e.backgroundCommand === o.BACKGROUND_COMMAND.ADD_SITE_URL &&
  (e.webRequest.siteUrl = n.sender.tab.url)
```

The static analyzer flagged this flow:
```
EXFILTRATION (1 flow):
  [HIGH] chrome.tabs.get → chrome.runtime.sendNativeMessage    js/background.js
```

**Verdict**: This is expected behavior for the SSO functionality - the native application needs to know which site the user is visiting to provide the appropriate credentials. However, this means all browsing activity on sites where the extension activates is logged and transmitted to the native application, which could be a privacy concern in non-enterprise environments.

## False Positives Analysis

1. **Native Messaging to "External" Host**: The extension communicates with `identity.automation.snapapp.com` via native messaging. This is not actually an external network endpoint - it's the identifier for a locally installed native application. Native messaging in Chrome requires the host application to be installed locally and explicitly registered, so this is not unauthorized data exfiltration.

2. **Webpack Bundling**: The JavaScript files use webpack bundling (visible in the loader functions), which is standard practice and not obfuscation.

3. **Auto-Submit Behavior**: The extension automatically submits login forms when configured to do so. This is intentional functionality for SSO convenience, not malicious automation.

4. **Form Field Detection**: The extension actively searches for and manipulates password fields across all sites. This is necessary for its SSO function and not malicious behavior.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| identity.automation.snapapp.com | Native host identifier (local application, not network endpoint) | Tab URLs, site URLs, user-entered credentials, login success/failure status | MEDIUM - All browsing data and credentials on SSO-enabled sites are shared with native app |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

RapidIdentity SnapApp is a legitimate enterprise SSO tool that operates as designed. The medium risk rating is based on the following factors:

**Risk Factors:**
1. **Broad Permissions**: Requires `<all_urls>` host permissions and runs content scripts on all websites at `document_start`
2. **Credential Handling**: Retrieves, stores, and autofills sensitive credentials across all websites
3. **Browsing History Logging**: Sends URL information for all visited sites to the native application
4. **Powerful Permissions**: Has `nativeMessaging`, `tabs`, `webRequest`, and `webRequestAuthProvider` permissions
5. **HTTP Auth Interception**: Intercepts HTTP authentication requests and can automatically provide credentials

**Mitigating Factors:**
1. **Enterprise Context**: Designed for managed enterprise deployments with IT oversight
2. **Legitimate Publisher**: Developed by Identity Automation, LP, a known SSO provider
3. **Native App Required**: Cannot function without a separately installed native application, providing a layer of deployment control
4. **No External Network Communication**: All communication is with a locally installed native application, not external servers
5. **Manifest V3**: Uses the modern MV3 architecture with service workers
6. **Disclosed Functionality**: Extension description clearly states it provides "Form-Fill SSO capabilities when used with Identity Automation's RapidIdentity product"

**Recommendation**: This extension is safe for use in enterprise environments where RapidIdentity is the official SSO solution and the native application is deployed by IT administrators. It should not be installed by end users outside of an official enterprise deployment, as it would require the native application to function and provides very broad access to credentials and browsing data.
