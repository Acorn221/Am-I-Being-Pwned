# Vulnerability Report: Aternity Web Activity Creator 3.0

## Metadata
- **Extension ID**: ljanpepaipafblfikgiokdoccjbckfbf
- **Extension Name**: Aternity Web Activity Creator 3.0
- **Version**: 3.0.307
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Aternity Web Activity Creator 3.0 is an enterprise employee monitoring and analytics extension developed by Aternity (Riverbed Technology). The extension is designed for IT administrators to monitor end-user web activity and application performance. It collects extensive browsing data including page URLs, page titles, navigation timing, tab activity, and user interactions (clicks, keyboard events) and transmits this data to Aternity's server infrastructure at `wac.aternity.com`.

While this extension is a legitimate enterprise monitoring tool disclosed in its description, it represents significant privacy concerns for employees whose browsing activity is being tracked. The extension runs content scripts on all HTTP/HTTPS sites and has access to browsing history, tabs, and the ability to enumerate other extensions via the `management` permission.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Browsing Activity Collection and Transmission

**Severity**: MEDIUM
**Files**: content.js, main.js, 177.js, background.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension collects extensive user web activity data and transmits it to remote Aternity servers for enterprise monitoring purposes.

**Evidence**:

1. **Server Endpoint**: The extension communicates with `wac.aternity.com`:
```javascript
// main.js line 151-152
const h = "wac.aternity.com",
  ue = `https://${h}`;
console.log("WAC's server URL is: ", ue)
```

2. **Content Scripts on All URLs**: The manifest shows content scripts running on all HTTP/HTTPS pages:
```json
"content_scripts": [{
  "matches": ["https://*/*", "http://*/*"],
  "run_at": "document_start",
  "all_frames": true,
  "js": ["content.js"]
}]
```

3. **Browsing History Access**: Requests `history` permission to access user's browsing history.

4. **Page Activity Monitoring**: The extension tracks page URLs, titles, navigation events, and user interactions:
```javascript
// From 177.js - Activity event tracking
function M(u, T, g, d) {
  const S = {
    name: u.name,
    event: I.ib.fullName(T),
    literals: []
  },
  // Tracks various URL states
  k = w ? ["documentCommittedUrl"] : ["documentUrl", "documentCurrentUrl",
         "documentCommittedUrl", "frameUrl", "frameCommittedUrl", "frameCurrentUrl"];
```

5. **Tab Messaging**: Extension uses chrome.tabs.sendMessage to coordinate data collection across tabs:
```javascript
// main.js line 460
console.debug(`-> ${oe.browser}[${oe.tabId}][${oe.frameId}]:`, le, ve, Ke),
chrome.tabs.sendMessage(oe.tabId, Ke)
```

6. **Extension Enumeration**: Uses `management` permission to detect other extensions:
```javascript
// main.js line 473
chrome.management.get(oe, ({...}) => {...})
```

7. **Authentication with JWT**: Extension uses JWT tokens for authentication with the Aternity server and stores them in localStorage:
```javascript
// main.js lines 629, 639
localStorage.setItem(se.on, Ye)
// Clears tokens on logout
localStorage.removeItem(se.on), localStorage.removeItem(se.Ew),
localStorage.removeItem(se.Iu), localStorage.removeItem(_e)
```

**Verdict**: This is a disclosed enterprise monitoring tool, so the data collection is not covert or malicious. However, it does represent a privacy concern for employees. The MEDIUM risk rating reflects that while the functionality is disclosed and legitimate for enterprise use, the scope of data collection (all browsing activity) is significant. This is appropriate for an enterprise monitoring context where employees are aware they are being monitored.

## False Positives Analysis

1. **Webpack Bundling**: The extension uses Angular and webpack bundling, which creates minified code that appears obfuscated. The ext-analyzer correctly flagged this as "obfuscated" but this is standard for modern web applications, not deliberate code hiding.

2. **jQuery and Angular Libraries**: Large portions of content.js are standard jQuery (version 3.6.0) and Angular framework code, which is not suspicious.

3. **JWT Authentication**: The JWT token handling is standard authentication practice for enterprise SaaS applications.

4. **Extension Management Permission**: While the `management` permission allows extension enumeration, this may be used for detecting VPN extensions or other tools that could interfere with monitoring, which is standard behavior for enterprise monitoring tools.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| wac.aternity.com | Aternity Web Activity Creator server | User web activity data (page URLs, titles, navigation events, clicks, timing data, browsing history) | MEDIUM - Disclosed enterprise monitoring |
| help.aternity.com | Documentation/Help resources | None (outbound link only) | LOW - Help documentation |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This extension is a legitimate enterprise monitoring tool developed by Aternity (Riverbed Technology), a well-known enterprise software company. The extension's purpose is clearly disclosed in its name and description: "Aternity Web Activity Creator 3.0" for monitoring web activity.

The MEDIUM risk level is assigned because:

1. **Disclosed Purpose**: Unlike covert spyware, this is an openly disclosed employee monitoring tool
2. **Enterprise Context**: Designed for IT administrators to monitor employee productivity and application performance
3. **Extensive Data Collection**: Despite being disclosed, it collects comprehensive browsing data including history, URLs, page titles, and user interactions
4. **All-Sites Access**: Content scripts run on all HTTP/HTTPS pages with broad data collection capabilities
5. **Sensitive Permissions**: Uses `history`, `tabs`, and `management` permissions for extensive monitoring

The extension is not malicious, but represents a significant privacy concern. It is appropriate for enterprise environments where employees are informed about monitoring policies, but would be concerning if installed without user knowledge or consent. Organizations using this tool should ensure proper disclosure to employees in accordance with privacy regulations and employment policies.
