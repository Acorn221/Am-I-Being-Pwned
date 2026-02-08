# Vulnerability Report: Ad Blocker: Stands AdBlocker

## Metadata
- **Extension Name:** Ad Blocker: Stands AdBlocker
- **Extension ID:** lgblnfidahcdcjddiepkckcfdhpknnjh
- **Version:** 2.1.62
- **Manifest Version:** 3
- **User Count:** ~3,000,000
- **Analysis Date:** 2026-02-08

## Executive Summary

Stands AdBlocker is a legitimate ad-blocking extension with standard functionality: CSS-based element hiding, popup blocking via `window.open` interception, tracker iframe removal, cookie banner dismissal, and YouTube ad blocking via fetch/XHR response modification. The extension collects telemetry data (browsing URLs, navigation transitions, installed extensions list) and sends it to `prod.standsapp.org`, which is a **privacy concern** but is gated behind a data processing consent mechanism and is clearly part of the extension's intended analytics/reporting functionality. There is no evidence of malicious behavior, credential theft, proxy infrastructure, AI scraping, or remote code execution.

## Vulnerability Details

### 1. Browsing History Telemetry (MEDIUM)
- **Severity:** MEDIUM
- **Files:** `background/components/analysis-reporter.js`, `background/components/tab.js`
- **Code:**
  ```javascript
  // tab.js - onUpdated sends page URLs and navigation transitions
  await analysisReporter.addReportsBulk([{
    loadTime: new Date().getTime(),
    previousUrl: pageData.previousUrl,
    pageUrl: pageData.pageUrl,
    trt: tabData.transitions[tabId]?.[url]?.trt,
    trq: tabData.transitions[tabId]?.[url]?.trq
  }]);

  // analysis-reporter.js - sends to thepromise-event.standsapp.org
  const rows = reportData.map(r => ({
    nid, pid: '', sid: '', cc,
    ts: r.loadTime,
    rfu: encodeURIComponent(r.previousUrl),
    tu: encodeURIComponent(r.pageUrl),
    trt: r.trt || '', trq: r.trq?.join(',') || '',
    os, ver: getAppVersion(), blk: reportData.length
  }));
  ```
- **Verdict:** The extension collects every page URL visited along with referrer, navigation transition type, geo location, OS, and anonymous ID. Data is batched and sent to `thepromise-event.standsapp.org/convert`. This is a significant privacy concern but is gated behind `dataProcessingConsent.getConsent()` and represents typical analytics for ad-blocker effectiveness measurement. Not malicious.

### 2. Installed Extensions Enumeration (LOW)
- **Severity:** LOW
- **Files:** `background/components/server-logger.js`, `common/platform/management.js`
- **Code:**
  ```javascript
  // server-logger.js
  if (hasManagementPermissions) {
    extensions = await getAllExtensions();
  }
  const data = {
    privateUserId: user?.privateUserId,
    anonymousUserId,
    installedExtensions: extensions.map(({ id }) => id),
    // ...
  };
  ```
- **Verdict:** When the `management` optional permission is granted, the extension enumerates all installed extensions by ID and sends them to the server alongside event logs. The `management` permission is optional (not auto-granted), limiting impact. This could be used for competitive intelligence but is not inherently malicious.

### 3. XHR/Fetch Response Hooking (FALSE POSITIVE - Ad Blocker Scriptlet)
- **Severity:** N/A (Expected ad-blocker behavior)
- **Files:** `content/custom-scripts/dependencies/replace-xhr-response-content.js`, `content/custom-scripts/dependencies/json-prune-fetch-response.js`, `content/custom-scripts/dependencies/json-edit-fetch-request.js`
- **Verdict:** These are standard uBlock Origin-style scriptlets adapted for Stands. They intercept XHR and fetch responses to strip ad placement data (specifically YouTube ad slots). This is core ad-blocking functionality. The scripts are site-specific and clearly targeted at removing advertising JSON payloads.

### 4. window.open / document.createElement Interception (FALSE POSITIVE)
- **Severity:** N/A (Expected behavior)
- **Files:** `content/popups-script.js`
- **Verdict:** Overrides `window.open` and `document.createElement` to block popup ads. Uses known ad-network domain deny lists. Standard popup blocker functionality.

### 5. User Feedback Sent via Zapier Webhook (LOW)
- **Severity:** LOW
- **Files:** `background/messages/send-email.js`
- **Code:**
  ```javascript
  await serverApi.callUrl({
    url: `https://zapier.com/hooks/catch/b2t6v9/?type=${encodeURIComponent(type)}&Source=${encodeURIComponent(source)}&Content=${encodeURIComponent(content)}`
  });
  ```
- **Verdict:** User feedback and issue reports are sent via a Zapier webhook. The content includes geo, browser info, app version, and user-provided text. This is user-initiated (only triggered by the user submitting feedback) and not a security concern.

### 6. Remote CSS Rule Updates (LOW)
- **Severity:** LOW
- **Files:** `background/components/css-list-data.js`
- **Verdict:** The extension fetches CSS blocking rules from `static.standsapp.org` with incremental updates. Rules are CSS selectors for hiding ad elements. This is standard for ad blockers (equivalent to filter list updates in uBlock Origin). The hash verification mechanism prevents tampering during transit. No executable code is fetched.

## False Positive Table

| Pattern | File | Reason |
|---------|------|--------|
| XHR response replacement | `replace-xhr-response-content.js` | uBlock-style scriptlet for ad response stripping |
| Fetch proxy/interception | `json-prune-fetch-response.js`, `json-edit-fetch-request.js` | Ad-blocking fetch response modification |
| `window.open` override | `popups-script.js` | Popup ad blocker |
| `document.createElement` override | `popups-script.js` | Anchor tag popup detection |
| `abortCurrentScript` | `abort-current-script.js` | uBlock-style script abort scriptlet |
| `defineConstant` | YouTube `main.js` | Sets YouTube ad properties to undefined |
| `querySelector` in content scripts | `set-css.js`, `extended-rules.js` | CSS-based element hiding for ads |
| `innerHTML` in notification div | `popups-script.js` | UI notification for blocked popups |
| Shadow DOM traversal | `content/helpers.js`, `set-css.js` | Applies ad-hiding CSS to shadow DOM |

## API Endpoints Table

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `https://prod.standsapp.org/api/v2/events` | POST | Event logging | privateUserId, anonymousUserId, installed extensions (IDs), events |
| `https://prod.standsapp.org/api/v2/user` | POST | User creation | anonymousUserId |
| `https://prod.standsapp.org/user/heartbeat` | PUT | Heartbeat (hourly) | privateUserId |
| `https://prod.standsapp.org/geolookup` | GET | Geo lookup | None |
| `https://thepromise-event.standsapp.org/convert` | POST | Browsing analytics | Anonymous ID, page URLs, referrer URLs, transition type, geo, OS, version |
| `https://prod.standsapp.org/api/v2/user/notifications/` | GET | Fetch notifications | User ID |
| `https://prod.standsapp.org/lists_management/css-increments` | GET | CSS list management | Current list ID |
| `https://static.standsapp.org/lists/css-latest` | GET | Fetch latest CSS rules | Anonymous ID, app version |
| `https://static.standsapp.org/lists/css-increments/{id}` | GET | Fetch CSS increments | Anonymous ID, version |
| `https://static.standsapp.org/lists/trackers-list` | GET | Fetch trackers list | Anonymous ID, app version |
| `https://prod.standsapp.org/uninstall/{userId}/` | GET | Uninstall survey | User ID (via setUninstallURL) |
| `https://zapier.com/hooks/catch/b2t6v9/` | GET | User feedback | Type, source, feedback text, geo, browser info |

## Data Flow Summary

1. **On Install:** Creates anonymous UUID (`crypto.randomUUID()`), registers user with server, gets `privateUserId` back. Opens onboarding page on `standsapp.org`. Reports currently open tabs.
2. **On Navigation:** Records page URL, previous URL, transition type/qualifiers. Batches into groups of 10 and sends to `thepromise-event.standsapp.org/convert` with anonymous ID, geo, and OS.
3. **Hourly Heartbeat:** Sends `privateUserId` to heartbeat endpoint. Flushes pending logs and analytics reports.
4. **Event Logging:** Install, update, enable/disable, whitelist changes, notification interactions, URL filtering events are logged and batched to `prod.standsapp.org/api/v2/events`.
5. **Filter Lists:** CSS rules for hiding ads/cookie banners fetched from `static.standsapp.org` with incremental updates (hash-verified). Trackers list fetched every 90 days.
6. **Content Scripts:** Apply CSS hiding rules, block popups via `window.open` interception, remove tracker iframes, run site-specific ad-removal scriptlets (YouTube, Facebook, eBay, Bing, etc.).
7. **Consent Gating:** All telemetry is gated behind `dataProcessingConsent`. On Chrome this defaults to `true`; on Firefox it defaults to `false`. User can toggle it.

## Permissions Assessment

| Permission | Justification |
|------------|--------------|
| `storage`, `unlimitedStorage` | Store filter lists, user settings, statistics |
| `activeTab` | Access current tab for ad blocking |
| `scripting` | Inject content scripts into existing tabs on install/update |
| `contextMenus` | Right-click menu for blocking elements |
| `alarms` | Periodic jobs (heartbeat, cleanup, rule counting) |
| `notifications` | "Rate us" notification after blocking threshold |
| `tabs` | Track page navigation for analytics and per-tab blocking state |
| `webNavigation` | Track navigation transitions (referrer tracking) |
| `declarativeNetRequest`, `declarativeNetRequestFeedback` | Network-level ad/tracker blocking (MV3 standard) |
| `<all_urls>` (host) | Run content scripts on all pages for ad blocking |
| `management` (optional) | Enumerate installed extensions (for server logging) |

All permissions are justified by the extension's ad-blocking functionality, though `tabs` + `webNavigation` combined with the analytics reporting creates a browsing history collection pipeline.

## Overall Risk Assessment: **LOW**

The extension is a legitimate ad blocker with comprehensive ad-removal functionality (CSS hiding, popup blocking, YouTube ad stripping, cookie banner removal). The primary concern is the **browsing history telemetry** -- every page navigation is recorded and sent to Stands' servers with anonymous user ID, geo, and OS info. However, this telemetry is:

1. Gated behind a data processing consent mechanism
2. Uses anonymous IDs (not linked to personal identity by default)
3. Clearly part of the extension's analytics functionality (not covert)
4. Documented in their privacy policy URL included in the extension

The optional `management` permission for extension enumeration is a minor concern but requires explicit user grant. There is no evidence of: remote code execution, credential harvesting, keylogging, proxy infrastructure, search result hijacking, ad injection, or obfuscated malicious payloads. The XHR/fetch hooking is exclusively used for ad removal (YouTube, etc.) and follows standard uBlock Origin scriptlet patterns.
