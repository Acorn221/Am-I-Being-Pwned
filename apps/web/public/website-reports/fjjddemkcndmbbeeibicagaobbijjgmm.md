# Vulnerability Report: Alerte Bons Plans eBuyClub

## Metadata
- **Extension ID**: fjjddemkcndmbbeeibicagaobbijjgmm
- **Extension Name**: Alerte Bons Plans eBuyClub
- **Version**: 5.0.41
- **Users**: ~80,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Alerte Bons Plans eBuyClub is a French shopping cashback extension that alerts users to available cashback offers when they visit partner merchant websites. The extension collects browsing data, monitors all web requests, and harvests cookies from ebuyclub.com to authenticate users and track cashback-eligible purchases. While this data collection serves the extension's stated cashback functionality, the broad permissions and tracking scope raise privacy concerns. The extension uses affiliate link injection, tracks browsing history to partner sites, and sends user visit data to eBuyClub servers.

The extension's behavior is disclosed in its purpose (cashback tracking), but the combination of `webRequest` monitoring on `<all_urls>`, cookie harvesting, and browsing history tracking to remote servers justifies a MEDIUM risk rating due to the extensive data access required for its business model.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Web Request Monitoring and Browsing Tracking

**Severity**: MEDIUM
**Files**: background.js (lines 1509-1554)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension monitors all web requests across all URLs using `webRequest.onBeforeRequest` with `<all_urls>` and tracks user visits to detect partner merchant sites. It records which merchants users visit and sends this browsing history data to eBuyClub servers.

**Evidence**:
```javascript
// Line 1509-1516: Monitors ALL web requests
d.webRequest.onBeforeRequest.addListener(({
  tabId: e,
  url: s
}) => {
  t.then(() => this.cashbackEvents.saveEventsMatchingUrlAndCookiePatterns({
    tabId: e,
    url: s
  }))
}, {
  urls: ["<all_urls>"],
  types: ["main_frame"]
})

// Line 1058: LastVisited tracks browsing history to partner sites
url: w.LAST_VISITED_URL  // "https://www.ebuyclub.com/rest/json/membreTB_ws/tracking-history"

// Line 712: User browsing data sent to server
LAST_VISITED_URL: "https://www.ebuyclub.com/rest/json/membreTB_ws/tracking-history"
```

**Verdict**: This behavior is necessary for cashback functionality (detecting when users visit partner sites), but the broad monitoring of all web requests represents significant data collection. The extension tracks which partner merchants users visit and sends this history to eBuyClub servers. While disclosed in the extension's purpose, this constitutes extensive browsing surveillance.

### 2. MEDIUM: Cookie Harvesting from eBuyClub Domain

**Severity**: MEDIUM
**Files**: background.js (lines 904-908, 1608-1631)
**CWE**: CWE-522 (Insufficiently Protected Credentials)
**Description**: The extension harvests authentication cookies (`ebcAccess`, `ebcPseudo`) from the ebuyclub.com domain and uses them to authenticate API requests. These cookies are read and stored in extension storage, then used to make authenticated requests to eBuyClub servers.

**Evidence**:
```javascript
// Line 904-908: Function to extract cookies by name
z = async n => (await bt({
  url: "https://www.ebuyclub.com/toolbar/post-telechargement"
})).find(({
  name: s
}) => s === n)?.value

// Line 1612: Harvesting authentication cookies
const [e = "", s = ""] = await Promise.all([z("ebcAccess"), z("ebcPseudo")]);

// Line 1625-1626: Storing credentials in extension storage
this.userInfo ? await this.userInfo.init(t) : this.userInfo = new C(t),
await h({
  credentials: t
})
```

**Verdict**: Cookie harvesting is used for authentication to enable cashback tracking features. However, reading and storing authentication cookies from the parent domain is a sensitive operation that could be exploited if the extension were compromised. The cookies are legitimately used for the extension's stated purpose.

### 3. LOW: Overly Broad Host Permissions

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests `*://*/*` host permissions, granting access to all websites, when it technically only needs to access specific partner merchant domains and ebuyclub.com.

**Evidence**:
```json
"host_permissions": [
  "https://www.ebuyclub.com/toolbar/post-telechargement",
  "*://*/*"
]
```

**Verdict**: While overly broad, these permissions are necessary for the extension to monitor visits to any partner merchant site (which can be any e-commerce domain). The extension cannot pre-declare all possible partner merchants, so broad permissions are functionally required for its business model.

## False Positives Analysis

1. **Affiliate Link Pattern Suppression**: The extension contains extensive lists of affiliate network domains (linksynergy, shareasale, etc.) in lines 723-726. These are used to detect and suppress competing affiliate links, which is standard behavior for cashback extensions to ensure proper attribution.

2. **Google Analytics**: Standard analytics usage (lines 741-760) for product telemetry, not malicious tracking.

3. **Remote Configuration**: The extension fetches merchant lists and configuration from eBuyClub servers (lines 710-720), which is necessary for keeping cashback offers up-to-date.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.ebuyclub.com/rest/json/flux-tb/list | Fetch merchant list | User profile, browser info | Low - disclosed functionality |
| www.ebuyclub.com/rest/json/membreTB_ws/tracking-history | Submit browsing history | Partner merchant visits | Medium - privacy-sensitive |
| www.ebuyclub.com/rest/json/membreTB_ws/getUserInfos | Get user account info | Token, pseudo | Low - authenticated API |
| www.ebuyclub.com/rest/json/membreTB_ws/login | User authentication | Email, password | Low - legitimate auth |
| www.ebuyclub.com/rest/json/membreTB_ws/updateSettings | Update user preferences | User settings, token | Low - user-initiated |
| www.google-analytics.com/mp/collect | Analytics telemetry | Usage events | Low - standard analytics |
| images.ebuyclub.com/v8/toolbar/*.json | Fetch configs | None (GET) | Low - configuration data |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: This extension implements typical cashback extension functionality that inherently requires significant data access - monitoring web requests, tracking which merchant sites users visit, and reading authentication cookies. All these behaviors serve the extension's disclosed purpose of providing cashback alerts and tracking eligible purchases.

However, the combination of:
1. Monitoring all web requests across all URLs
2. Tracking and reporting user browsing history to partner sites
3. Harvesting authentication cookies from the parent domain
4. Having access to all websites via `*://*/*` permissions

represents a substantial collection of privacy-sensitive data. While this data collection is disclosed and necessary for cashback functionality, it creates significant privacy exposure for users who may not fully understand the extent of tracking involved.

The extension is legitimate and serves its stated purpose, but users should be aware that it monitors their browsing behavior across all websites to detect merchant visits for cashback tracking. The MEDIUM rating reflects the disclosed but extensive data collection inherent to the cashback business model.
