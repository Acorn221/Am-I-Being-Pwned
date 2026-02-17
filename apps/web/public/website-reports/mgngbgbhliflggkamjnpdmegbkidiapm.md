# Vulnerability Report: Remove YouTube Shorts

## Metadata
- **Extension ID**: mgngbgbhliflggkamjnpdmegbkidiapm
- **Extension Name**: Remove YouTube Shorts
- **Version**: 2.1.5
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"Remove YouTube Shorts" is a browser extension that removes YouTube Shorts from the interface and redirects shorts URLs to regular video format. While its core functionality is legitimate, the extension engages in undisclosed user tracking by collecting device fingerprinting data (user agent, platform, IP address, country) and exfiltrating this to third-party servers without disclosure in the Chrome Web Store listing or privacy policy. The extension generates a unique user ID from this data and transmits it to external analytics endpoints, constituting medium-risk privacy concerns.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Device Fingerprinting and User Tracking

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-359 (Exposure of Private Personal Information)
**Description**: On installation or update, the extension collects device fingerprinting data including `navigator.userAgent`, `navigator.platform`, IP address, and geolocation (country) from `api.country.is`. This data is hashed to create a unique user identifier and transmitted to `arktech-plugins.vercel.app/api/reciveInfo` after a randomized delay (1-21 seconds).

**Evidence**:
```javascript
// background.js lines 30-58
const e = navigator.userAgent,
  t = navigator.platform;
let o = "unknown_ip",
  n = "unknown_country";
try {
  const e = await fetch("https://api.country.is/");
  if (!e.ok) throw new Error("Failed to fetch information");
  const t = await e.json();
  o = t.ip || "unknown_ip", n = t.country || "unknown_country"
} catch (e) {}
return `${function(e){let t=0;for(let o=0;o<e.length;o++)t=(t<<5)-t+e.charCodeAt(o),t|=0;return t.toString(36)}(`
$ {
  e
}: $ {
  t
}: $ {
  o
}: $ {
  Date.now().toString()
}: $ {
  n
}
`).slice(0,30)}:${t}:${o}:${n}`
```

```javascript
// background.js lines 59-78
async function(e) {
  const t = Math.floor(21 * Math.random()) + 1;
  await new Promise((e => setTimeout(e, 1e3 * t)));
  const o = {
    UID: e
  };
  try {
    (await fetch("https://arktech-plugins.vercel.app/api/reciveInfo", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(o)
    })).ok ? (console.log("Popup info Updated Successfully"), chrome.storage.local.set({
      shortsRemoverUniqueUserId: e
    })) : console.error("Failed to update popup info")
  } catch (e) {
    console.error("Error updating popup info to server", e)
  }
}
```

**Verdict**: This constitutes undisclosed analytics/tracking. The Chrome Web Store listing does not mention any data collection, and there is no privacy policy disclosed. The random delay appears designed to evade detection or rate limiting. While the data collected is not highly sensitive (no browsing history or personal content), the lack of disclosure violates user privacy expectations.

### 2. LOW: postMessage Handler Without Origin Validation

**Severity**: LOW
**Files**: pageWorld.js
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
**Description**: The extension registers a `window.addEventListener("message")` handler without validating the message origin, potentially allowing malicious pages to send crafted messages.

**Evidence**:
```
ATTACK SURFACE:
  [HIGH] window.addEventListener("message") without origin check    pageWorld.js:2
  message data → fetch(api.country.is)    from: popup.js ⇒ background.js
```

**Verdict**: The static analyzer flagged this as HIGH severity, but upon code review, the actual risk is LOW. The pageWorld.js file appears to be part of a React developer tools or similar library that has minimal interaction with the extension's core functionality. The extension does not appear to expose sensitive functionality through this message handler, and it operates only on YouTube domains where cross-origin attacks would be limited by same-origin policy.

### 3. LOW: Broad Host Permissions

**Severity**: LOW
**CWE**: N/A
**Description**: The extension requests `*://*.youtube.com/*` host permissions, which grants access to all YouTube domains. While necessary for the extension's stated functionality, this is a broad permission surface.

**Verdict**: This permission is appropriate and necessary for the extension's legitimate purpose of modifying YouTube's interface to remove Shorts. Not overprivileged for its use case.

## False Positives Analysis

The static analyzer flagged several "HIGH" severity exfiltration flows that are false positives or low risk:

1. **chrome.tabs.query → *.src(reactjs.org)** - This appears to be popup.js loading React from CDN, a standard practice for UI development. No sensitive data exfiltration.

2. **chrome.tabs.query → fetch(api.country.is)** - While this is genuine data exfiltration, `chrome.tabs.query` is only used to get the active tab for messaging, not to extract tab data. The fetch to api.country.is is for IP geolocation, not tab content.

3. **chrome.storage.local.get → fetch(api.country.is)** - The storage.local.get only checks for the presence of a stored user ID; if absent, it triggers fingerprinting. This is tracking, but not extracting user-stored data.

4. **Obfuscated flag** - The code shows signs of minification/bundling (React, webpack), but not true obfuscation intended to hide malicious behavior. Variable renaming is standard for production builds.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.country.is | IP geolocation lookup | None (GET request, receives IP/country from server) | LOW - Public API for geolocation |
| arktech-plugins.vercel.app/api/reciveInfo | Analytics/tracking | Unique user ID (hash of UA, platform, IP, country, timestamp) | MEDIUM - Undisclosed tracking |
| reactjs.org | CDN for React library | None (script loading) | NONE - Legitimate CDN |
| mail.google.com | Unknown (flagged by analyzer) | Unknown | LOW - Likely false positive from popup UI |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: The extension's core functionality (removing YouTube Shorts from the UI) is legitimate and implemented without malicious intent. However, the undisclosed collection of device fingerprinting data and transmission to third-party analytics servers constitutes a privacy violation. Users are not informed of this data collection in the Chrome Web Store listing, and there is no privacy policy provided. The data collected (user agent, platform, IP geolocation) is not highly sensitive, but the lack of transparency and the use of randomized delays to obscure the tracking behavior elevates this to MEDIUM risk.

The extension does not exfiltrate browsing history, passwords, or other high-value data. It does not inject ads, modify page content maliciously, or engage in credential theft. The primary issue is privacy noncompliance rather than active malware behavior.

**Recommended Actions**:
- Extension should disclose data collection practices in its privacy policy
- Users should be given an opt-out mechanism for analytics
- Consider flagging for privacy policy review rather than removal
