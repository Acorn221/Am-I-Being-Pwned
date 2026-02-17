# Security Analysis Report: Netcraft Extension

## Extension Metadata

- **Extension ID**: bmejphbfclcpmpohkggcjeibfilpamia
- **Name**: Netcraft Extension
- **Version**: 2.1.2
- **Manifest Version**: 3
- **User Count**: ~70,000
- **Description**: Comprehensive site information and protection from phishing and malicious JavaScript when browsing the web

## Executive Summary

The Netcraft Extension is a **legitimate security tool** developed by Netcraft, a well-known cybersecurity company. This extension provides phishing protection, malicious JavaScript detection, and credential leak monitoring. While the extension collects and transmits browsing data to Netcraft's servers, this is consistent with its stated security functionality and is done for legitimate threat analysis purposes.

**Risk Level**: CLEAN

The extension exhibits the expected behavior of a security/anti-phishing tool and does not contain malicious code or backdoors.

## Key Functionality

### 1. Phishing Protection
- Monitors navigation events and checks visited URLs against Netcraft's threat database
- Fetches site reputation data from `mirror.toolbar.netcraft.com` and `www.netcraft.com`
- Blocks access to known phishing sites and displays warning pages
- Downloads encrypted blocklists of malicious resources (scripts, cryptominers, card skimmers)

### 2. Malicious JavaScript Detection
- Downloads pattern feeds for detecting:
  - Cryptocurrency miners (cryptojackers)
  - Shopping site skimmers (payment card theft scripts)
  - Web inject malware
- Intercepts script and XMLHttpRequest loads using `chrome.webRequest` API
- Blocks known malicious scripts before execution

### 3. Credential Leak Monitoring
- Content script monitors form inputs on websites
- Identifies "relevant" input fields (passwords, usernames, emails) using regex patterns
- When the background script requests input values, the content script sends:
  - Field IDs and names
  - Field values (actual user input)
  - Current frame URL
- This data is used to detect if credentials are being exfiltrated to unauthorized domains

### 4. User Reporting
- Allows users to report suspected phishing sites
- Submits URLs to `report.netcraft.com/api/v2/report/urls`
- Logs blocked visit statistics for analytics

## Data Collection and Transmission

### Information Sent to Netcraft Servers

#### Site Lookup Data (service_worker.js:11593-11596)
```javascript
const s = await chrome.tabs.get(o);
let r = (await chrome.webNavigation.getFrame({
  tabId: o,
  frameId: e
})).url;
```
The extension sends:
- Tab URLs being visited
- Frame URLs within tabs
- Request bodies from intercepted network requests

#### Credential Monitoring (content.js:454-458)
```javascript
type: "sendInputs",
data: {
  frame: location.href,
  inputs: t.relevantFilledInputs  // {id, name, value}
}
```
When credential leak detection is enabled, the extension sends:
- Form input field values (including passwords)
- Field IDs and names
- Page URLs where inputs were filled

#### Storage Data Syncing (service_worker.js:12198-12214)
```javascript
chrome.storage.sync.get(null, (e => {
  if (!0 === e.installed) {
    const a = Object.keys(e);
    for (const i of a) S[i] = e[i]
  }
}))
chrome.storage.local.get(null, (e => {
  const i = Object.keys(e);
  for (const a of i) S[a] = e[a];
}))
```
The extension accesses all stored settings and preferences.

#### Analytics/Telemetry (service_worker.js:11750-11763)
```javascript
const a = {
  block_reason: e.reason,
  block_type: e.type,
  extension_version: chrome.runtime.getManifest().version,
  forced: e.force,
  url: o
};
await fetch(f.Q.logBlockedVisit, {
  body: JSON.stringify(a),
  headers: {
    "Content-Type": "application/json;charset=utf-8"
  },
  method: "POST"
})
```
Logs blocked visits with:
- Blocked URL
- Block reason and type
- Extension version
- Whether user forced the visit

### Network Endpoints

All data is sent exclusively to Netcraft-owned domains:

1. **www.netcraft.com** - Main website, glossary links
2. **report.netcraft.com** - Phishing report submissions (`/api/v2/report/urls`)
3. **sitereport.netcraft.com** - Site reputation lookups
4. **toolbar.netcraft.com** - Threat feed updates (`/blocked_visit`, `/blockdb/`)
5. **mirror.toolbar.netcraft.com** - Mirror for threat feeds
6. **mirror2.extension.netcraft.com** - Secondary mirror
7. **trends.netcraft.com** - Top sites data

## Permissions Analysis

### Declared Permissions

```json
"permissions": [
  "storage",
  "tabs",
  "webRequest"
],
"host_permissions": [
  "<all_urls>"
]
```

### Permission Usage Justification

- **storage**: Used to cache threat databases, user preferences, and whitelisted sites
- **tabs**: Required to get tab information and determine which sites are being visited
- **webRequest**: Intercepts script/XHR requests to block malicious resources
- **host_permissions (<all_urls>)**: Necessary to monitor all sites for phishing/malware

All permissions are legitimately used for the extension's security functionality.

## Code Quality and Security Practices

### Positive Security Indicators

1. **Encryption of Threat Data**: Malicious resource patterns are encrypted with AES (service_worker.js:11881-11890):
```javascript
const t = atob(o),
  s = t.substring(0, f.Q.randomSaltLength),
  c = t.substring(f.Q.randomSaltLength),
  l = n()(f.Q.evilResourcesSalt + s + a),
  u = r().decrypt(c, l).toString(h()).split("\t"),
```

2. **No Arbitrary Code Execution**: No use of `eval()`, `Function()`, or `chrome.scripting.executeScript()` for dynamic code

3. **No Third-Party Analytics**: Uses Netcraft's own analytics endpoint, not Google Analytics or other third-party trackers

4. **Sanitization of URLs**: Strips credentials from URLs before logging (service_worker.js:11740-11742):
```javascript
const i = new URL(e.url);
i.username = "", i.password = "";
const o = i.toString();
```

5. **User Control**: Settings allow disabling individual features (credential leak monitoring, blocking, analytics)

6. **Legitimate Publisher**: Netcraft is a reputable cybersecurity company founded in 1995

### Potential Privacy Concerns (Not Vulnerabilities)

1. **Extensive Data Collection**: The extension can see all URLs visited and, when enabled, form input values including passwords
2. **Centralized Trust**: All data flows to Netcraft servers; users must trust Netcraft's data handling practices
3. **No Local-Only Mode**: Protection features require server connectivity; cannot operate fully offline

These are inherent to the extension's security mission rather than security flaws.

## Static Analysis Findings

The ext-analyzer identified 4 data exfiltration flows:

```
[HIGH] chrome.tabs.get → fetch(www.netcraft.com)
[HIGH] chrome.storage.local.get → fetch(www.netcraft.com)
[HIGH] chrome.webNavigation.getAllFrames → fetch(www.netcraft.com)
[HIGH] chrome.storage.sync.get → fetch(www.netcraft.com)
```

**Assessment**: These flows are expected behavior for a security extension. The data sent (visited URLs, storage contents) is necessary for threat lookup and synchronization with Netcraft's cloud-based threat intelligence.

54 additional benign flows were correctly filtered by the analyzer.

## Vulnerabilities

**None identified.**

This extension does not contain:
- Malicious data exfiltration (data collection is legitimate)
- Hardcoded secrets or credentials
- Remote code execution capabilities
- Insecure postMessage handlers
- Cryptomining or malvertising code
- Unauthorized third-party data sharing

## Final Verdict

**CLEAN - Legitimate Security Extension**

The Netcraft Extension is a well-designed, legitimate phishing and malware protection tool. While it collects significant browsing data, this is:

1. **Disclosed**: The description mentions "comprehensive site information and protection"
2. **Necessary**: URL checking and credential leak detection require this data
3. **Scoped**: Data only goes to Netcraft's servers, not third parties
4. **Controllable**: Users can disable credential leak monitoring and analytics

Users should install this extension with the understanding that it acts as a cloud-based security scanner, similar to Google Safe Browsing or Microsoft SmartScreen. Those who are comfortable with Netcraft analyzing their browsing activity in exchange for phishing protection will find this to be a useful security tool.

No security vulnerabilities were found during this analysis.

## Recommendations

For Users:
- Review the extension's privacy policy before installation
- Disable "credential-leaks" monitoring in settings if you're uncomfortable with password transmission
- Understand that all visited URLs are sent to Netcraft for threat analysis
- Whitelist trusted sites to reduce data collection on sensitive domains

For Developers:
- Consider adding a "local-only" mode for users who want protection without cloud connectivity
- Provide more granular controls over what data is sent to servers
- Add an option to review/audit data being sent before transmission
- Publish detailed privacy documentation explaining data handling practices
