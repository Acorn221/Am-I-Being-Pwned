# Security Analysis: Automatic Twitch: Drops, Moments and Points

**Extension ID:** kfhgpagdjjoieckminnmigmpeclkdmjm
**Version:** 1.6.3
**Users:** 300,000
**Risk Level:** MEDIUM
**Manifest Version:** 2

---

## Executive Summary

Automatic Twitch: Drops, Moments and Points is a Twitch automation extension that automatically claims channel points, drops, and moments for users. The extension's functionality matches its disclosed purpose, with all network activity aligning to stated features. Primary security concerns include two postMessage handlers without origin validation (allowing potential cross-origin messaging attacks) and embedded analytics credentials. The extension implements Twitch API automation, WebSocket proxying, and fetch/history interception but does not engage in undisclosed data collection.

**Risk Assessment:** MEDIUM - Disclosed automation functionality with postMessage vulnerabilities and embedded analytics secrets. No evidence of malicious behavior or undisclosed exfiltration.

---

## Permissions Analysis

### Declared Permissions
- `alarms` - Used for periodic checks (points every 4min, drops every 7min, notifications every ~3.5hrs)
- `storage` - Stores user settings, statistics, claim history
- `notifications` - Native browser notifications for claims and events
- `cookies` - Reads Twitch auth tokens and user session data

### Host Permissions
- `*://*.twitch.tv/*` - Full access to all Twitch pages
- `*://*.twitchcdn.net/*` - Access to Twitch CDN resources
- `*://*.ttvnw.net/*` - Access to Twitch video streams

**Assessment:** Permissions are appropriate for stated Twitch automation functionality. Cookie access enables authentication token extraction for GraphQL API calls.

---

## Network Activity Analysis

### Primary Endpoints

**Twitch GraphQL API (gql.twitch.tv)**
- **Operations Performed:**
  - `ChannelPointsContext` - Check for available point claims
  - `ClaimCommunityPoints` - Claim channel points
  - `Inventory` - Check for available drops
  - `DropsPage_ClaimDropRewards` - Claim drops
  - `CommunityMomentCallout_Claim` - Claim moments
  - `UseLive` - Check livestream status
  - `ChannelShell` - Get channel metadata
  - `PlaybackAccessToken` - Get video playback tokens

**Data Flow:** Extension extracts Twitch auth tokens from cookies (`twilight-user`, `auth-token`) and includes them in GraphQL requests. All operations are standard Twitch API calls for the disclosed automation features.

**WebSocket Proxy (wss://pubsub-edge.twitch.tv/v1)**
- Extension proxies the Twitch PubSub WebSocket to intercept real-time events
- Subscribed Topics:
  - `community-points-user-v1.{userId}` - Point claim notifications
  - `user-drop-events.{userId}` - Drop progress events
  - `onsite-notifications.{userId}` - General notifications
  - `community-moments-channel-v1.{channelId}` - Moment events
  - `predictions-channel-v1.{channelId}` - Prediction events
  - `predictions-user-v1.{userId}` - User prediction results

**Assessment:** WebSocket proxying enables real-time claim automation. No data exfiltration observed in WebSocket handling.

### Third-Party Endpoints

**Developer Notification API (api.ebnull.org)**
- `https://api.ebnull.org/automatic-twitch-channel-points-notifications` - Extension update notifications
- `https://api.ebnull.org/automatic-twitch-promotions` - Promotional content delivery

**Data Sent:** No user data. Requests are GET-only for notification retrieval.

**Google Analytics (www.google-analytics.com)**
```javascript
analyticsApi: "https://www.google-analytics.com/mp/collect?measurement_id=G-74NYF5V98T&api_secret=cGTT2cb5RXO4k92r8jq7-Q"
```
- **Events Tracked:**
  - Extension install/update/reset
  - Claim events (points, drops, moments)
  - Twitch events (raids, predictions)
  - Player events (reload button clicks)
  - Alert settings changes
  - Promotion opens
  - Extension errors

**Data Sent:**
- `client_id` - Random UUID stored in localStorage
- `user_id` - Random UUID stored in extension storage
- `extension_version` - "1.6.3"
- `language` - `navigator.language`
- `user_agent` - `navigator.userAgent`
- Event-specific parameters (claim counts, error messages, etc.)

**SECURITY CONCERN:** API secret is hardcoded in plaintext (`cGTT2cb5RXO4k92r8jq7-Q`). This allows anyone to send fake analytics data to the developer's Google Analytics account.

**BuyMeACoffee Tracking**
```javascript
linkBuymeacoffee: "https://www.buymeacoffee.com/ebnull"
```
Reference in code shows tracking when users open the donation page, but this is user-initiated navigation, not automatic exfiltration.

**Assessment:** Third-party API calls are for developer notifications and analytics only. No sensitive Twitch user data is sent to non-Twitch domains. Analytics secret exposure is a low-severity issue affecting analytics integrity, not user privacy.

---

## Code Behavior Analysis

### Content Script Injection (content.js)

**Fetch API Proxy**
```javascript
window.fetch = new Proxy(fetch, {
  apply: (target, thisArg, args) => {
    // Intercept GraphQL responses for ChannelPointsContext and DropCurrentSessionContext
    // Extract claim IDs and send via postMessage to extension context
  }
})
```
- Proxies `window.fetch` to intercept Twitch GraphQL responses
- Extracts `availableClaim` data from `ChannelPointsContext` operations
- Monitors drop progress from `DropCurrentSessionContext` operations
- Sends claim data via `window.postMessage()` with custom namespace `autoTwitchBrowserExtension`

**WebSocket Proxy**
```javascript
window.WebSocket = new Proxy(_originalWebSocket, {
  construct: (target, args) => {
    const ws = new target(...args);
    // Listen for Twitch PubSub messages
    // Extract claim/drop/moment/prediction data
    // Send to extension via postMessage
  }
})
```
- Proxies WebSocket constructor to intercept Twitch PubSub messages
- Automatically subscribes to claim-related PubSub topics using extracted auth tokens
- Parses incoming messages for claim-available events

**History API Proxy**
```javascript
window.history.pushState = new Proxy(_originalHistory.pushState, {
  apply: (target, thisArg, args) => {
    const result = target.apply(thisArg, args);
    window.postMessage({autoTwitchBrowserExtension: {historyUpdated: true}}, "*");
    return result;
  }
})
```
- Monitors SPA navigation to reinitialize on page changes

**Assessment:** API proxying is necessary for the extension's automation features. All intercepted data is used only for claim automation, not exfiltrated.

### Background Script Logic (background.js)

**Automatic Claiming Flow**
1. **Periodic Checks:**
   - Points: Every 4 minutes (GraphQL query for `ChannelPointsContext`)
   - Drops: Every 7 minutes (GraphQL query for `Inventory`)
   - Notifications: Every ~3.5 hours

2. **Real-time Claims:**
   - Listens for postMessages from content script with claim IDs
   - Immediately sends GraphQL mutation to claim points/drops/moments

3. **Statistics Tracking:**
   - Stores claim history in local storage (last 20 points, 10 drops, 10 moments, etc.)
   - Increments total counters (`statistics.totalPoints`, `totalDrops`, `totalMoments`)

**Auto-Reload Mechanism**
- Monitors player health every 10 seconds
- Reloads tab if playback errors exceed threshold (6 consecutive failures)
- Reloads if fetch failures exceed threshold (8 consecutive failures)
- Implements "integrity check" retry logic with cookie clearing

**Automation Features**
- Auto-start video playback by activating tabs and overriding `document.hidden`
- Auto-unmute by briefly setting volume to 0.011 then re-muting
- Auto-click player error buttons when detected
- Prevents tab discarding (`autoDiscardable = false`)

**Assessment:** Automation logic is aggressive but transparent. Features match the extension's disclosed purpose of automating Twitch engagement.

---

## Vulnerabilities Identified

### MEDIUM: Unvalidated postMessage Handlers (2 instances)

**Location:** `content.js:1`

**Issue:**
```javascript
window.addEventListener("message", n)
```
The extension registers two `window.addEventListener("message")` handlers without origin validation:

1. **Integrity Token Handler** (in injected script context):
```javascript
const n = i => {
  const r = i.data.autoTwitchBrowserExtensionIntegrity;
  i.source === window && (r ? /* fetch integrity token */ : ...)
};
window.addEventListener("message", n);
```

2. **Main Message Handler** (in content script context):
```javascript
function xe(e) {
  const t = e.data.autoTwitchBrowserExtension;
  e.source !== window || !t || setTimeout(() => {
    if (t.claimID) return Ue(t);
    if (t.drop) return Q();
    // ... more handlers
  }, ...)
}
window.addEventListener("message", xe);
```

Both handlers check `e.source === window` but do not validate `e.origin`. While checking `source === window` prevents cross-window attacks, malicious scripts running in the same page context (e.g., via DOM XSS or compromised third-party script) could:
- Trigger false claim attempts
- Trigger reloads by sending `{autoTwitchBrowserExtension: {fetchFailed: true}}`
- Manipulate prediction tracking
- Inject fake integrity tokens

**Impact:** An attacker with code execution in the Twitch page context could abuse extension functionality. Low exploitability (requires existing XSS on twitch.tv), but postMessage handlers should validate origin.

**Recommendation:** Add origin validation:
```javascript
if (e.source !== window || e.origin !== "https://www.twitch.tv") return;
```

---

### LOW: Hardcoded API Secret

**Location:** `background.js:1`

**Issue:**
```javascript
analyticsApi: "https://www.google-analytics.com/mp/collect?measurement_id=G-74NYF5V98T&api_secret=cGTT2cb5RXO4k92r8jq7-Q"
```

The Google Analytics Measurement Protocol API secret is embedded in plaintext. This allows anyone to:
- Send fake analytics events to the developer's property
- Pollute analytics data
- Potentially exhaust API quotas

**Impact:** Does not affect user security or privacy. Only impacts analytics data integrity.

**Recommendation:** API secrets should be server-side only. Consider using Google Analytics gtag.js client library instead of Measurement Protocol.

---

## Data Collection and Privacy

### Data Stored Locally
- User settings (automation toggles, alert preferences)
- Claim statistics (total points/drops/moments claimed)
- Claim history (last 20 points, 10 drops, 10 moments, etc.)
- UIDs (random UUIDs for analytics, not linked to Twitch identity)
- Twitch channel names/IDs from recent claims

### Data Sent Externally
**To Twitch (gql.twitch.tv):**
- User auth tokens (from cookies) - Required for API authentication
- Channel names/logins - Required for querying claim status
- Claim IDs - Required for claiming rewards

**To Google Analytics:**
- Random UUIDs (client_id, user_id)
- Browser metadata (language, user agent, extension version)
- Aggregated event counts (e.g., "claimed 5 drops")
- Non-sensitive error messages

**To Developer API (api.ebnull.org):**
- No user data sent (GET requests only)

**Assessment:** No Twitch user data (usernames, emails, watch history, etc.) is sent to third-party domains. Analytics collection is anonymized and limited to extension usage metrics.

---

## Obfuscation and Code Quality

**Obfuscation Level:** Medium
- Minified JavaScript with single-letter variable names
- No identifier renaming beyond standard minification
- Logic is traceable with deobfuscation

**Code Injection:**
The extension injects a `<script>` tag into the page DOM to run code in the Twitch page context (not isolated content script context). This is necessary to proxy native `fetch`, `WebSocket`, and `history` APIs but increases attack surface.

```javascript
function Ge(e) {
  const t = document.createElement("script");
  t.innerHTML = `(function () {${e.toString()...}})('${qe}');`;
  De.prepend(t);
}
```

**Assessment:** Code injection is required for API proxying but follows standard extension patterns. No malicious obfuscation detected.

---

## CSP Analysis

**Manifest CSP:**
```json
"content_security_policy": "script-src 'self' blob: filesystem: https://translate.google.com/ https://*.googleapis.com/ 'sha256-130H45A0e+tQTvO91CH/GKIfmF7stsYLFlf9oF0PhLo='; object-src 'self'"
```

- Allows scripts from `translate.google.com` and `googleapis.com` (for Google Translate integration mentioned in code)
- Includes a specific script hash (`sha256-130H45A0e+tQTvO91CH/GKIfmF7stsYLFlf9oF0PhLo=`)
- Allows `blob:` and `filesystem:` sources

**Assessment:** CSP is moderately permissive but justified for stated functionality. The script hash suggests inline script usage in extension pages.

---

## User Interaction and Disclosure

**Disclosure Quality:** Good
- Extension name clearly states "Automatic" functionality
- Description mentions "Drops, Moments and Points" automation
- Permissions align with described features

**User Control:**
- Settings allow toggling all automation features individually
- Users can disable point claiming, drop claiming, moment claiming separately
- Alert/notification preferences are configurable
- Extension can be fully disabled without uninstall

**Assessment:** Extension is transparent about automation. No evidence of hidden functionality.

---

## Comparison to Malware Patterns

### Patterns NOT Observed
- No undisclosed data exfiltration
- No credential theft beyond authorized Twitch API usage
- No cryptocurrency mining
- No ad injection
- No unauthorized purchases or transactions
- No browser hijacking
- No malicious redirects

### Patterns Observed
- Aggressive automation (auto-claiming, auto-reload, tab manipulation)
- API proxying (necessary for functionality)
- Analytics with embedded secrets (low severity)
- PostMessage handlers without origin validation (medium severity)

**Assessment:** Extension behavior matches disclosed automation features. Security issues are architectural vulnerabilities, not malicious intent.

---

## Recommendations

### For Users
1. **Understand Automation Risks:** This extension automates Twitch engagement, which may violate Twitch Terms of Service. Use at your own risk.
2. **Review Settings:** Disable features you don't need (e.g., auto-reload, auto-start).
3. **Monitor Tab Behavior:** Extension prevents tab discarding and manipulates video playback. This consumes system resources.

### For Developer
1. **Fix postMessage Handlers:** Add origin validation to all `window.addEventListener("message")` handlers.
2. **Remove Hardcoded Secrets:** Move Google Analytics API secret to server-side implementation.
3. **Add Update Mechanism:** Ensure integrity token handling doesn't fail on Twitch API changes.
4. **Document Third-Party APIs:** Clarify in privacy policy what data is sent to `api.ebnull.org` and Google Analytics.

---

## Conclusion

Automatic Twitch: Drops, Moments and Points is a **MEDIUM risk** extension that performs disclosed Twitch automation. The primary security concerns are:

1. **Two postMessage handlers without origin validation** - Could be exploited by malicious scripts in Twitch page context (medium severity, requires XSS on twitch.tv)
2. **Hardcoded Google Analytics API secret** - Affects analytics integrity, not user privacy (low severity)
3. **Aggressive automation** - May violate Twitch ToS, but is disclosed behavior

The extension does not engage in undisclosed data collection, credential theft, or malicious exfiltration. All network activity aligns with stated functionality. The buymeacoffee.com reference flagged by ext-analyzer is benign (developer donation link).

**Verdict:** Legitimate automation tool with architectural security issues. No evidence of malicious intent or undisclosed tracking. Users should be aware that Twitch automation may violate platform terms of service.
