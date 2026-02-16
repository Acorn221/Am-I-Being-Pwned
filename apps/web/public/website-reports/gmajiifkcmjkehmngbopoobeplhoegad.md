# Vulnerability Report: myfaveTT - download all TikToks you've loved

## Metadata
- **Extension ID**: gmajiifkcmjkehmngbopoobeplhoegad
- **Extension Name**: myfaveTT - download all TikToks you've loved
- **Version**: 1.12.51
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension is a TikTok downloader that allows users to export their liked, favorited, and followed content. The extension intercepts TikTok API calls and loads external UI components from `ui.myfavett.com` and `resync.myfavett.com` in iframes. The extension fetches TikTok data with user credentials included, which could pose a privacy concern if the external domains are compromised or become malicious. The extension also uses the File System Access API to store downloaded content locally. While the extension appears to function as advertised, the reliance on external frames that could access sensitive user data via postMessage warrants a MEDIUM risk classification.

## Vulnerability Details

### 1. MEDIUM: External Frame Loading Without Content Security Policy Validation

**Severity**: MEDIUM
**Files**: r.js, rl.html, c.js
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Description**: The extension loads external iframes from `https://ui.myfavett.com` and `https://resync.myfavett.com` within a sidebar injected into TikTok pages. These iframes receive messages containing user data and API responses via postMessage. While the origin checking uses hardcoded strings, if the external domains are compromised, they could receive sensitive user information.

**Evidence**:
```javascript
// r.js - Creates iframes loading external domains
const n = "https://ui.myfavett.com",
  e = document.createElement("iframe");
e.src = n, e.id = "ui", document.body.appendChild(e);
const o = "https://resync.myfavett.com",
  c = document.createElement("iframe");
c.src = o, c.id = "resync", document.body.appendChild(c);

// Message routing to external frames
window.onmessage = function(i) {
  const { origin: d, data: s } = i;
  if (d === t) switch (s.direction) {
    case 2:
      return void(null === (r = e.contentWindow) || void 0 === r || r.postMessage(s, n));
    case 6:
      return void(null === (a = c.contentWindow) || void 0 === a || a.postMessage(s, o))
  }
  // Routing messages back from external frames
  d === n && parent.postMessage({ direction: 3, ...s }, t);
  d === o && parent.postMessage({ direction: 7, ...s }, t)
};
```

**Verdict**: The extension's architecture creates a dependency on external domains that could intercept user data. If these domains are compromised or change ownership, they could become a vector for data exfiltration.

### 2. LOW: TikTok API Access with User Credentials

**Severity**: LOW
**Files**: s.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension makes multiple fetch requests to TikTok's API endpoints with `credentials: "include"`, sending the user's session cookies. While this is necessary for the extension's functionality, the data fetched (liked videos, following lists, user statistics) could be forwarded to the external UI frames.

**Evidence**:
```javascript
// s.js - Multiple credential-included fetches
const r = await fetch(o.X(), {
  credentials: "include"
}),

const i = await window.fetch(s.X(), {
  credentials: "include"
});

// Fetching user stats
const r = await fetch(o.X(), {
  credentials: "include"
}),
// Extracting diggCount (likes) and followingCount
Ae = null === (e = null === (t = null == s ? void 0 : s.userInfo) || void 0 === t ? void 0 : t.stats) || void 0 === e ? void 0 : e.diggCount
```

**Verdict**: This is expected behavior for a TikTok downloader, but combined with external frame loading, it creates a potential privacy risk. The extension's stated purpose matches this behavior, mitigating the severity.

## False Positives Analysis

The static analyzer flagged exfiltration flows from `document.getElementById` and `document.querySelectorAll` to `fetch(m.tiktok.com)`. These are legitimate operations where the extension reads TikTok's DOM to extract video metadata and then makes authenticated requests to TikTok's mobile API to fetch video details. This is core functionality for a TikTok downloader and not malicious exfiltration.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| ui.myfavett.com | External UI frame for extension sidebar | User data via postMessage | MEDIUM - External dependency |
| resync.myfavett.com | External "resync" functionality frame | Unknown data via postMessage | MEDIUM - External dependency |
| m.tiktok.com | TikTok mobile API | User credentials, API requests | LOW - Expected behavior |
| www.tiktok.com | TikTok web API | User credentials, API requests | LOW - Expected behavior |
| /node-webapp/api/common-app-context | TikTok app context API | User credentials | LOW - Expected behavior |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
The extension functions as advertised - a TikTok downloader that exports user's liked and followed content. However, the architectural decision to load external UI components from `ui.myfavett.com` and `resync.myfavett.com` creates a trust boundary issue. These frames receive data via postMessage and could potentially access sensitive user information if compromised.

The extension legitimately needs to:
1. Access TikTok's API with user credentials to fetch liked videos, following lists, and video metadata
2. Use the File System Access API to save downloaded content locally
3. Intercept TikTok API responses via webRequest to capture authentication headers

The MEDIUM risk stems from the external frame dependency rather than overtly malicious behavior. Users should be aware that this extension trusts third-party domains with their TikTok usage data. If the developer's infrastructure is compromised or the domains change hands, user privacy could be at risk.

**Recommendations**:
- Users should verify the legitimacy of ui.myfavett.com and resync.myfavett.com
- Consider using browser network monitoring to observe what data is sent to external domains
- Be aware that the extension has full access to TikTok session data and API responses
