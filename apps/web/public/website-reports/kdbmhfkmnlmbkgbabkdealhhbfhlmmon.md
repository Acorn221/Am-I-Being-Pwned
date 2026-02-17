# Security Analysis: SteamDB Extension

**Extension ID:** kdbmhfkmnlmbkgbabkdealhhbfhlmmon
**Extension Name:** SteamDB
**Version:** 4.32
**Risk Level:** LOW
**User Count:** 500,000+

## Executive Summary

SteamDB is a legitimate browser extension that enhances the Steam Store and Steam Community websites with additional features including pricing data, player statistics, achievement tracking, and inventory management. The extension communicates with SteamDB's backend API (`extension.steamdb.info`) to provide enriched data about Steam games and user libraries.

**Key Finding:** While the extension exhibits 4 "exfiltration" flows flagged by static analysis (document.getElementById → fetch), these are **all legitimate** data enrichment operations that fetch Steam-related metadata from SteamDB's API. The extension does contain **one genuine vulnerability**: a postMessage handler without origin validation.

## Risk Assessment

**Overall Risk: LOW**

- **Critical:** 0
- **High:** 0
- **Medium:** 1 (postMessage without origin check)
- **Low:** 0

## Technical Analysis

### 1. Static Analysis Findings (ext-analyzer)

The ext-analyzer tool identified:
- **Risk Score:** 50
- **4 Exfiltration Flows:** document.getElementById → fetch
- **1 Message Handler:** window.addEventListener("message") without origin check
- **Obfuscation:** Minimal (jsbeautifier-processed code)

### 2. Detailed Code Review

#### A. "Exfiltration" Flows (False Positives)

All four flagged flows are **legitimate data enrichment operations**:

**Flow 1: explore.js (lines 12-21, 92-100)**
- **Source:** `document.getElementById('application_config')` - Steam's own config data
- **Data Extracted:** `accessToken`, `applicationConfig.COUNTRY`, `applicationConfig.WEBAPI_BASE_URL`
- **Sink:** `fetch()` to Steam's **official** API endpoint
- **Purpose:** Automated discovery queue generation
- **Endpoint:** `${applicationConfig.WEBAPI_BASE_URL}IStoreService/GetDiscoveryQueue/v1/`
- **Verdict:** LEGITIMATE - Uses user's Steam API token to call Steam's API (not exfiltration)

**Flow 2: app.js (lines 454-461, 567-633)**
- **Source:** `document.getElementById('application_config')` - Steam config
- **Data Extracted:** Country code, currency, app ID
- **Sink:** Background script message → `extension.steamdb.info/api/ExtensionAppPrice/`
- **Purpose:** Display historical lowest price data
- **Verdict:** LEGITIMATE - Fetches public pricing data from SteamDB API

**Flow 3: inventory.js (line 697, 259-278)**
- **Source:** `document.querySelector('#market_sell_buyercurrency_input')` - user-entered sell price
- **Sink:** `fetch('/market/itemordershistogram?...')` to **Steam's own domain**
- **Purpose:** Display market order book for quick-sell feature
- **Verdict:** LEGITIMATE - Calls Steam's market API

**Flow 4: achievements.js (lines 251-276, 1327-1360)**
- **Source:** `document.getElementById('application_config')` - Steam config
- **Data Extracted:** App ID, language, access token
- **Sink:** `fetch()` to Steam's API (`IPlayerService/GetGameAchievements/v1`, `IStoreBrowseService/GetItems/v1`)
- **Purpose:** Enhanced achievement display with grouping and DLC capsule images
- **Verdict:** LEGITIMATE - Calls Steam's official APIs

**Analysis:** None of these flows constitute data exfiltration. They either:
1. Call Steam's own APIs using Steam's provided credentials (normal OAuth flow)
2. Call SteamDB's API to fetch public metadata (pricing history, achievement groups)
3. Process data client-side without sending to third parties

#### B. Actual Vulnerability: postMessage Handler Without Origin Check

**Location:** `scripts/store/invalidate_cache.js:17-29`

```javascript
window.addEventListener('message', (request) => {
    if (request?.data && request.data.type === 'steamdb:extension-invalidate-cache') {
        WriteLog('Invalidating userdata cache');
        SendMessageToBackgroundScript({
            contentScriptQuery: 'InvalidateCache',
        }, () => {
            // noop
        });
    }
});
```

**Vulnerability:** Missing origin validation
**Severity:** MEDIUM
**Impact:** Any website can trigger cache invalidation by posting a message with `type: 'steamdb:extension-invalidate-cache'`. This forces the extension to refetch user data (owned games, wishlist, cart items) from Steam on the next page load.

**Exploitation Scenario:**
```javascript
// Malicious site could do:
window.postMessage({type: 'steamdb:extension-invalidate-cache'}, '*');
```

**Actual Impact:** Limited - invalidation only clears a cache; it doesn't leak data or perform destructive actions. Worst case: performance degradation from repeated cache invalidation.

**Remediation:**
```javascript
window.addEventListener('message', (request) => {
    // Add origin check
    if (request.origin !== 'https://store.steampowered.com') {
        return;
    }
    // ... rest of handler
});
```

### 3. Network Endpoints Analysis

**Legitimate Endpoints Used:**
- `store.steampowered.com` - Steam Store APIs (discovery queue, market data)
- `api.steampowered.com` - Steam Web API (achievements, user stats, family sharing)
- `steamcommunity.com` - Community APIs (inventory, badges, gifts)
- `extension.steamdb.info` - SteamDB backend API (pricing history, achievement groups)

All endpoints are documented, expected, and align with the extension's stated functionality.

### 4. Data Flow Analysis

**What Data is Collected:**
- Steam app IDs (from current page URL)
- User's currency/country (from Steam's `application_config`)
- Steam Web API tokens (from Steam's DOM, used only for Steam API calls)
- User's owned games, wishlist, cart (fetched from Steam's `/dynamicstore/userdata/`)

**Where Data Goes:**
- **To Steam APIs:** App IDs, tokens, user actions (follow/wishlist/ignore)
- **To SteamDB API:** App IDs, currency codes (to fetch pricing/achievement metadata)
- **Never sent to third parties:** User libraries, Steam tokens, personal data

**Background Script Security:**
- Validates `sender.tab` before processing messages (lines 43-46)
- Uses `Object.hasOwn()` for property checks (line 48)
- Rate-limits API requests (`nextAllowedRequest` variable)
- Caches user data locally to minimize requests

### 5. Permissions Analysis

**Declared Permissions:**
- `storage` - Used for user preferences and data caching (appropriate)
- Host permissions for `steamdb.info`, `steamcommunity.com`, `*.steampowered.com` - Required for content script injection (appropriate)

**No excessive permissions requested.**

### 6. Privacy Considerations

**Data Sent to SteamDB:**
- App IDs and currency codes (public data)
- User's country code (already public on Steam profile)
- No PII, no library contents, no Steam tokens

**SteamDB API Calls:**
- `GetApp` - Fetches public game metadata (player counts, update times)
- `GetAppPrice` - Fetches historical pricing data (public)
- `GetAchievementsGroups` - Fetches achievement group metadata (public)

All SteamDB API calls use anonymous public data; no user identification.

## Comparison to Similar Extensions

**Augmented Steam** (mentioned in code comments at line 1235) performs similar Steam enhancement functions. SteamDB's architecture is comparable and equally legitimate.

## Obfuscation Analysis

**Minimal obfuscation detected:**
- Code uses standard minification (jsbeautifier successfully deobfuscates)
- No packer/eval chains, no string concealment
- Readable variable names, comprehensive JSDoc comments
- Open development (references GitHub issues in comments)

## Functionality Review

**Documented Features (all verified in code):**
1. **Price Tracking:** Historical lowest prices from SteamDB API
2. **Player Stats:** Online counts, peak players from SteamDB/Steam APIs
3. **Achievement Enhancements:** Grouping by DLC, global unlock percentages
4. **Inventory Tools:** Quick-sell buttons, badge progress, gift identification
5. **Discovery Queue Auto-clear:** Automated queue processing using Steam's API
6. **Wishlist/Follow Management:** Calls Steam's official store endpoints

All features match the extension's public description and SteamDB.info's services.

## False Positive Analysis

**Why ext-analyzer flagged "exfiltration":**
1. **Pattern Matching Limitation:** Tool detects `document.getElementById → fetch` but cannot distinguish between:
   - Reading Steam's config to call Steam's API (legitimate)
   - Stealing tokens to send to attacker server (malicious)

2. **Legitimate OAuth Flow:** Extension reads Steam's access tokens from the DOM (Steam's design pattern) to make authenticated API calls on behalf of the user - this is the **intended usage** of those tokens.

3. **First-Party Data:** `application_config` element is created by Steam Store itself, not user-entered data. Extension uses it to determine API endpoints and user locale.

## Recommendations

### For Extension Developer (SteamDB)
1. **MEDIUM Priority:** Add origin validation to postMessage handler in `invalidate_cache.js`
2. **LOW Priority:** Consider using Content Security Policy meta tags in injected scripts

### For Users
- **Safe to Use:** Extension performs its documented functions without privacy violations
- **Risk:** Negligible - postMessage vulnerability has minimal exploitability
- **Trust Factor:** Maintained by SteamDB.info, a well-known Steam community resource since 2012

## Conclusion

SteamDB extension is a **legitimate Steam utility** with no malicious behavior. The static analysis "exfiltration" alerts are **false positives** stemming from:
1. Legitimate use of Steam's Web API OAuth flow
2. Fetching public metadata from SteamDB's API
3. Client-side data processing

**The only real vulnerability** is a missing origin check in a postMessage handler, which has limited exploitability (can only trigger cache invalidation, no data leakage).

**Verdict: LOW RISK** - Safe for installation with caveat about the postMessage vulnerability.

---

**Tags:** `legitimate`, `steam-enhancement`, `false-positive-exfil`
**Analyst Confidence:** High
**Date:** 2026-02-15
