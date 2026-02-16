# Security Analysis Report: Adblock for YouTube & Chrome - All Block

**Extension ID:** jajikjbellknnfcomfjjinfjokihcfoi
**Version:** 3.3.0
**Users:** 500,000
**Risk Level:** MEDIUM

## Executive Summary

This extension is a fork of uBlock Origin Lite (uBOL), a legitimate open-source ad blocker. While the core ad-blocking functionality appears benign, the developer has added a proprietary "link safety checker" feature that collects detailed browsing data and sends it to a third-party service (`service.allblock.app`). This introduces significant privacy concerns for users who expect a privacy-focused ad blocker.

## Vulnerability Findings

### MEDIUM: Invasive Link Scanning with Third-Party Data Exfiltration

**Location:** `rulesets/scripting/scriptlet/link-safety-checker.js`, `background.bundle.js`

**Description:**
The extension injects a content script on every page that extracts all hyperlinks, generates unique CSS selectors for each link, and sends this data to `https://service.allblock.app/check_links` via POST request.

**Data Collected:**
- Full URL of current page (`location.href`)
- Referrer URL (`document.referrer`)
- Array of all links on the page with:
  - Full link URL (after sanitizing auth tokens)
  - Unique CSS selector path for each link element
- Navigation events (route changes, pushState, replaceState)
- Page content type
- Extension version
- Unique user ID (UUID generated on install, persisted in storage)
- Timestamp
- Navigation type ("request", "route_change", "url_rewrite")

**Code Evidence:**
```javascript
// link-safety-checker.js lines 60-64
const t=d(n.getAttribute("href"));if(t){if(!e.has(t)){const a=k(n);e.set(t,{u:t,s:a})}

// background.bundle.js lines 342-344
const o={m:Oe,uid:await Be(),ev:c.getManifest().version,ct:e.ct,t:s,
nm:e.isDynamic||e.r?"url_rewrite":"request",nt:"foreground",u:e.u,r:e.r||"",links:n};

// background.bundle.js line 413
const s=await fetch("https://service.allblock.app/check_links",{method:"POST",
headers:{"Content-Type":"application/json"},body:JSON.stringify(e),signal:t})
```

**Privacy Impact:**
- Creates detailed browsing profile tied to persistent UUID
- CSS selectors reveal page structure and user interaction patterns
- Referrer tracking enables cross-site behavior correlation
- Data sent to closed-source third-party service (no privacy policy review possible)

**Risk:** MEDIUM
While the extension sanitizes authentication tokens from URLs (`email`, `token`, `auth`, `key`, etc.), it still leaks comprehensive browsing behavior to an external party. This is particularly concerning for an ad blocker where users expect enhanced privacy.

### MEDIUM: Undisclosed Analytics and User Tracking

**Location:** `background.bundle.js` lines 320-322, 464-468

**Description:**
The extension generates a persistent client UUID on installation and phones home to the developer's server on install/uninstall events.

**Code Evidence:**
```javascript
// Generate persistent UUID
async function Be(){let e=await f("clientId")
;return e||(e=self.crypto.randomUUID(),await h("clientId",e)),e}

// Install tracking
if("install"===e.reason){
const e=`https://allblock.app/en/welcome?uid=${t}&s=${Oe}&ev=${chrome.runtime.getManifest().version}`
;chrome.tabs.create({url:e})}
const s=`https://allblock.app/api/uninstall?uid=${t}`
;chrome.runtime.setUninstallURL(s)
```

**Risk:** MEDIUM
The UUID enables cross-session tracking and is sent with every link safety check request. Combined with the link scanning feature, this allows the operator to build long-term user profiles.

## Mitigating Factors

1. **Link Sanitization:** The extension removes sensitive query parameters (auth tokens, passwords, email) before sending URLs to the server
2. **User Control:** The link safety feature can be disabled via `linkSafetyEnabled` setting
3. **Core Blocking Legitimate:** The declarativeNetRequest rulesets appear to be genuine uBOL filter lists (EasyList, EasyPrivacy, URLhaus, etc.)
4. **No Credential Theft:** Does not access passwords, cookies (except localStorage for settings), or inject malicious scripts

## Architecture Notes

- Based on uBlock Origin Lite (MV3 declarativeNetRequest implementation)
- Uses legitimate filter lists: ublock-filters, easylist, easyprivacy, pgl, urlhaus-full
- Declarative net request rules are static JSON (not dynamically modified)
- Background service worker handles link queue batching (500 links per batch, 4s timeout)
- Queues link checks in localStorage with 100,000 item limit
- Retries failed checks with exponential backoff (30s → 300s max)

## Recommendations

**For Users:**
1. Disable the "link safety" feature in settings if privacy is a concern
2. Consider switching to official uBlock Origin Lite (no third-party data collection)
3. Review what data is shared at `https://allblock.app/privacy` (if available)

**For Developers:**
1. Disclose link scanning data collection in Chrome Web Store privacy policy
2. Make link safety opt-in instead of opt-out
3. Implement local link scanning using Safe Browsing API instead of third-party service
4. Open-source the backend or publish transparency reports

## Technical Details

**Permissions Analysis:**
- `activeTab` - Access to current tab (standard for ad blockers)
- `declarativeNetRequest` - Static rule blocking (MV3 requirement)
- `scripting` - Inject content scripts for cosmetic filtering
- `storage` - Persist settings and link check queue
- `<all_urls>` - Required for global ad blocking

**Network Endpoints:**
- `service.allblock.app/check_links` - Link safety checks (POST with browsing data)
- `allblock.app/en/welcome` - Opened on install with UUID tracking
- `allblock.app/api/uninstall` - Uninstall tracking URL

**Data Flow:**
1. Content script extracts links from page → generates CSS selectors
2. Batches links and sends to background script via `chrome.runtime.sendMessage`
3. Background script queues requests in localStorage
4. Periodic flush (1 minute alarm) sends batched data to `service.allblock.app`
5. Response marks links as "bad" (red badge) or "unknown" (yellow badge)
6. Content script applies visual badges to flagged links

## Conclusion

This extension is functionally a legitimate ad blocker but monetizes through privacy-invasive link scanning. The collection of detailed browsing patterns, persistent user tracking, and third-party data transmission are inappropriate for a tool marketed as privacy-enhancing. The MEDIUM risk rating reflects that while not overtly malicious, the undisclosed surveillance capabilities violate user expectations for an ad blocker.

**Tags:** `privacy:url_collection`, `privacy:third_party_analytics`, `feature:link_scanning`
