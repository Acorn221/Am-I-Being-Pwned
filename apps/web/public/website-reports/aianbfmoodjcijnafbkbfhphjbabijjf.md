# Security Analysis Report: Steamlvlup Card Factory

## Extension Metadata

- **Extension Name**: Steamlvlup Card Factory
- **Extension ID**: aianbfmoodjcijnafbkbfhphjbabijjf
- **User Count**: ~40,000 users
- **Manifest Version**: 3
- **Version**: 2.1.4

## Executive Summary

Steamlvlup Card Factory is a legitimate Steam trading card automation tool that integrates with the steamlvlup.com service. The extension provides functionality for:
- Automated Steam trading card farming
- Badge creation assistance
- Booster pack profitability calculations
- Trade offer enhancements

While the extension has broad permissions and communicates with external servers, the analysis reveals it serves its intended purpose without clear malicious behavior. The extension requires Steam authentication tokens and access to sensitive trading data, but this is necessary for its advertised functionality.

## Vulnerability Analysis

### 1. Sensitive Data Collection - MEDIUM

**Severity**: MEDIUM
**Files**:
- `script/background.js` (lines 58-76)
- `script/cardFarm.js` (lines 58-73)
- `script/dropCards.js` (lines 1-121)
- `script/offscreen.js` (lines 1-73)

**Description**:
The extension collects and transmits sensitive Steam authentication data:

```javascript
// cardFarm.js - Line 58-73
getAccessToken() {
  return new Promise((e, t) => {
    fetch("https://steamcommunity.com/my/badges/", {
      method: "GET"
    }).then(e => e.text()).then(t => {
      let s = t.split('g_steamID = "')[1].split('";')[0],
          a = t.split('window.g_wapit="')[1].split('";')[0];
      e({
        steamid: s,
        token: a
      })
    })
  })
}
```

```javascript
// offscreen.js - Lines 23-28
socket = socketClusterClient.create({
  hostname: "extension.steamlvlup.com/",
  path: "socket",
  secure: !0
})
```

The extension extracts:
- Steam ID (g_steamID)
- Web API Token (g_wapit)
- Session IDs
- Trading card inventory data

This data is transmitted to:
- `extension.steamlvlup.com` (WebSocket)
- `api.steamlvlup.com` (HTTPS)
- `steamlvlup.com` (HTTPS)

**Verdict**: This is legitimate functionality for a trading card farming extension. Users must register on steamlvlup.com and the service requires authentication to manage card farming. However, users should understand they're trusting a third-party service with Steam credentials.

---

### 2. Broad Host Permissions - MEDIUM

**Severity**: MEDIUM
**Files**: `manifest.json` (lines 16-18)

**Description**:
```json
"host_permissions": [
  "*://steamcommunity.com/*",
  "*://*.steampowered.com/*",
  "*://api.steamlvlup.com/*",
  "*://steamlvlup.com/*",
  "*://extension.steamlvlup.com/*",
  "*://store.steampowered.com/app/*",
  "*://store.steampowered.com/*"
]
```

The extension requires access to all Steam domains and its own service domains.

**Verdict**: These permissions are necessary for the extension's core functionality (card farming, badge creation, trade offers, market price checking). All Steam-related permissions are justified.

---

### 3. External Service Dependency - MEDIUM

**Severity**: MEDIUM
**Files**:
- `script/offscreen.js` (WebSocket connection)
- `script/background.js` (API calls)

**Description**:
The extension relies on external infrastructure:

```javascript
// background.js - Lines 9-23
if ("checkNewTickets" == e.contentScriptQuery)
  return fetch("https://steamlvlup.com/support/tickets/load?type=open")

if ("updateSIH" == e.contentScriptQuery)
  return fetch("https://api.steamlvlup.com/v1/sih")

if ("updateGamePrice" == e.contentScriptQuery)
  return fetch("https://api.steamlvlup.com/v1/prices")

if ("checkBots" == e.contentScriptQuery)
  return fetch(`https://steamlvlup.com/api/check_bots?ids=${e.data}`)
```

**Verdict**: The extension is tightly coupled to steamlvlup.com services. If the backend is compromised, user data could be at risk. However, this is expected for a cloud-based service extension.

---

### 4. Offscreen Document with WebRTC - LOW

**Severity**: LOW
**Files**: `script/background.js` (lines 1-7), `offscreen.html`, `offscreen.js`

**Description**:
```javascript
async function createOffscreen() {
  await chrome.offscreen.hasDocument() || await chrome.offscreen.createDocument({
    url: "offscreen.html",
    reasons: ["WEB_RTC"],
    justification: "WebSocket connection to API server"
  })
}
```

The extension creates an offscreen document for WebSocket connections (not WebRTC as stated in the reason).

**Verdict**: This is a standard MV3 pattern for maintaining persistent connections. The justification text is misleading (says WebRTC but uses WebSocket), but the functionality is legitimate.

---

## False Positives

| Pattern | Location | Reason for False Positive |
|---------|----------|--------------------------|
| Dynamic script injection | `script/helper.js:51-55` | Legitimate injection of localization scripts from extension bundle |
| localStorage usage | Throughout | Standard extension settings storage, no sensitive data persisted |
| SHA-256 hashing | `script/helper.js:227-259` | Used for bonus code generation, not credential theft |
| Chrome runtime messaging | Multiple files | Standard extension communication patterns |
| Fetch API calls | Multiple files | All calls to legitimate Steam domains or declared extension API |

---

## API Endpoints Summary

| Endpoint | Purpose | Data Sent | Method |
|----------|---------|-----------|--------|
| `extension.steamlvlup.com/socket` | WebSocket for card drop events | steamid, token, session data | WebSocket |
| `api.steamlvlup.com/v1/sih` | Get Steam item price data | None | GET |
| `api.steamlvlup.com/v1/prices` | Get game price cache | None | GET |
| `steamlvlup.com/api/check_bots?ids=` | Check bot status | Bot IDs | GET |
| `steamlvlup.com/api/extension_token` | Get API token | Cookies (automatic) | GET |
| `steamlvlup.com/support/tickets/load` | Check support tickets | type=open | GET |
| `steamcommunity.com/my/badges/` | Extract Steam tokens | None (scrape HTML) | GET |
| `steamcommunity.com/market/*` | Get market prices | None | GET |
| `api.steampowered.com/IPlayerService/GetOwnedGames/v1/` | Get user's game library | access_token, steamid | GET |

---

## Data Flow Summary

1. **Authentication Flow**:
   - User visits Steam Community badges page
   - Extension scrapes Steam ID and Web API token from HTML
   - Credentials sent to steamlvlup.com for authentication
   - WebSocket connection established to extension.steamlvlup.com

2. **Card Farming Flow**:
   - Extension queries Steam API for owned games
   - Fetches game/card price data from api.steamlvlup.com
   - User selects games to farm
   - Extension sends play status to steamlvlup.com backend
   - Backend generates Steam protocol messages
   - Extension applies messages via Steam's chat interface
   - Card drop events monitored via Steam's client messaging

3. **Market Data Flow**:
   - Extension fetches booster pack prices from Steam Market
   - Fetches gem/card prices from api.steamlvlup.com
   - Calculates profitability locally
   - No market data sent to third parties

---

## Privacy Concerns

1. **Steam Credentials**: The extension transmits Steam Web API tokens to steamlvlup.com. While this is necessary for the service, users should trust the operator.

2. **Game Library**: The extension accesses and potentially transmits the user's complete game library to calculate farming opportunities.

3. **Trade Activity**: When enhancing trade offers, the extension processes all trade items and could transmit trade data to its servers.

4. **Persistent Connection**: The WebSocket maintains a persistent connection that could be used for tracking user activity.

---

## Overall Risk Assessment: **LOW**

### Justification:

**CLEAN with Transparency Concerns**

The extension is **functionally legitimate** and serves its advertised purpose as a Steam trading card automation tool. All observed behaviors are consistent with the features described in the Chrome Web Store listing:

✅ **No Clear Malicious Behavior Detected**:
- No credential stealing beyond what's required for functionality
- No unauthorized data exfiltration
- No ad injection or coupon manipulation
- No cryptocurrency mining
- No tracking pixels or analytics beyond service needs
- No extension enumeration or competitive interference

✅ **Appropriate Permission Usage**:
- All host permissions are used for stated features
- Storage used for legitimate settings
- Offscreen document justified for WebSocket
- No excessive or unnecessary permissions

⚠️ **Transparency Concerns**:
- Users must trust steamlvlup.com with Steam authentication tokens
- No clear privacy policy linked in extension
- Tight coupling to third-party infrastructure
- WebRTC reason stated but WebSocket used (minor inconsistency)

### Recommendation:

This extension is **CLEAN** but invasive by necessity. It requires significant trust in the steamlvlup.com service operator. The ~40,000 user base and years of operation suggest a legitimate service, but users should be aware they're sharing Steam credentials with a third party.

**Risk Level**: LOW - The extension works as advertised and serves a legitimate niche. Users should use it only if they trust the steamlvlup.com service.

---

## Security Recommendations

For Users:
1. Only install if you're willing to share Steam Web API tokens with steamlvlup.com
2. Register an account on steamlvlup.com first to understand the service
3. Review the service's terms and privacy policy
4. Consider using a dedicated Steam account if concerned about security
5. Monitor your Steam account for unauthorized activity

For Developers:
1. Add clear privacy policy disclosure in the extension description
2. Implement certificate pinning for API communications
3. Add rate limiting to prevent abuse
4. Provide transparency report on data collection
5. Consider open-sourcing the client-side code for security audits
6. Fix WebRTC/WebSocket justification mismatch in offscreen document

---

## Conclusion

Steamlvlup Card Factory is a **legitimate extension** that provides real value to Steam users interested in trading card automation. While it requires significant permissions and accesses sensitive Steam data, this is necessary for its functionality. The extension does not exhibit malicious behavior but does require users to trust a third-party service with their Steam authentication credentials.

**Overall Risk**: **LOW**
**Verdict**: **CLEAN** (with appropriate user awareness of third-party service dependency)
