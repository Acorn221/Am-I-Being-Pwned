# Security Analysis: CS2 Trader - Steam Trading Enhancer

## Extension Metadata
- **Extension ID**: kaibcgikagnkfgjnibflebpldakfhfih
- **Name**: CS2 Trader - Steam Trading Enhancer
- **Version**: 3.5.3
- **Users**: ~400,000
- **Developer**: cs2trader.app (gergelyszabo94)
- **Manifest Version**: 3

## Executive Summary

CS2 Trader is a legitimate Steam trading enhancement tool for Counter-Strike 2 (CS2) items with **MEDIUM risk** due to sensitive credential extraction practices. The extension provides genuine utility (price checking, float values, trade offer management) but implements **automatic Steam API key registration** and **access token scraping** that could be concerning from a security perspective. While the extension appears to use these credentials only for intended Steam API operations, the automatic extraction and storage of sensitive authentication tokens represents a security risk if the extension were ever compromised or modified maliciously.

**Key Concerns**:
1. Automatic Steam API key registration without explicit opt-in consent
2. Scraping Steam access tokens from HTML attributes via offscreen document
3. User-configurable Discord webhook integration (potential for abuse if compromised)
4. Limited eval() usage in injected page scripts (Steam market history)
5. Extensive permission scope across Steam Community domains

**No Evidence Found**:
- ✅ No third-party tracking/analytics SDKs
- ✅ No data exfiltration to non-Steam/non-csgotrader.app domains
- ✅ No XHR/fetch hooking or request interception
- ✅ No extension enumeration or disabling code
- ✅ No obfuscated malicious payloads
- ✅ No residential proxy infrastructure
- ✅ No remote kill switches or dynamic code loading

## Vulnerability Details

### 1. MEDIUM SEVERITY: Automatic Steam API Key Registration and Extraction

**Severity**: MEDIUM
**Files**:
- `js/contentScripts/steam/apiKey.bundle.js` (lines 1040-1058)
- `js/offScreen/offscreen.bundle.js` (lines 516-536)
- `js/backgroundScripts/background.bundle.js` (line 1712)

**Description**:
The extension automatically registers Steam API keys on behalf of users when they visit `steamcommunity.com/dev/apikey`. If `autoSetSteamAPIKey` setting is enabled (default: true), the extension:

1. Automatically fills in the domain field with `registered_{timestamp}`
2. Checks the "I agree to the terms" box
3. Submits the form automatically
4. Scrapes the generated API key from the resulting page via offscreen document
5. Validates and stores the key in chrome.storage.local

**Code Evidence**:
```javascript
// apiKey.bundle.js:1040-1044
if (e)
  if (document.getElementById("editForm").action.includes("registerkey"))
    document.getElementById("domain").value = `registered_${Date.now()}`,
    document.getElementById("agreeToTerms").checked = !0,
    document.querySelector("input[type=submit]").click();

// offscreen.bundle.js:517-526
const o = new Request("https://steamcommunity.com/dev/apikey");
fetch(o).then((e => {
  if (e.ok) return e.text();
  console.log(`Error code: ${e.status} Status: ${e.statusText}`), n(e.statusText)
})).then((o => {
  let r = null;
  try {
    const n = document.createElement("html");
    n.innerHTML = t().sanitize(o),
    r = n.querySelector("#bodyContents_ex").querySelector("p").innerText.split(": ")[1],
    e(r)
  }
```

**Verdict**: CONCERNING - While this functionality is disclosed and can be disabled, automatically registering API keys without explicit user interaction per registration is potentially risky. Steam API keys grant programmatic access to user accounts and should require explicit consent for each registration. The extension does display a warning message about API key security.

---

### 2. MEDIUM SEVERITY: Steam Access Token Scraping

**Severity**: MEDIUM
**Files**:
- `js/offScreen/offscreen.bundle.js` (lines 537-556)
- `js/backgroundScripts/background.bundle.js` (lines 12495-12507)

**Description**:
The extension scrapes Steam access tokens from the steamcommunity.com homepage HTML by parsing the `data-loyalty_webapi_token` attribute. This token is then used for Steam Web API calls to fetch trade offers.

**Code Evidence**:
```javascript
// offscreen.bundle.js:537-549
if ("scrapeAccessToken" in e) return new Promise(((e, t) => {
  const n = new Request("https://steamcommunity.com/");
  fetch(n).then((e => {
    if (e.ok) return e.text();
    console.log(`Error code: ${e.status} Status: ${e.statusText}`), t(e.statusText)
  })).then((n => {
    let o = null;
    try {
      o = n.split('data-loyalty_webapi_token="&quot;')[1].split('&quot;"')[0], e(o)
    } catch (e) {
      console.log(e), console.log(n), t(e)
    }
  }))

// Background script validates and stores token:
// background.bundle.js:12500-12503
i && chrome.storage.local.set({
  steamAcessToken: e,
  steamAcessTokenValid: !0
}, (() => {}))
```

**Usage**: Token is used for legitimate Steam API operations:
```javascript
// background.bundle.js:13603
const c = new Request(`https://api.steampowered.com/IEconService/GetTradeOffers/v1/?get_received_offers=${o}&get_sent_offers=${r}&active_only=${e}&historical_only${i}&get_descriptions=${t}&language=english&access_token=${s}`);
```

**Verdict**: CONCERNING - Access tokens provide authenticated API access. While used only for legitimate Steam API calls in the code reviewed, storing these tokens locally increases risk if the extension or user's system is compromised. This is standard practice for Steam extensions but represents inherent security risk.

---

### 3. LOW-MEDIUM SEVERITY: User-Configurable Discord Webhook Integration

**Severity**: LOW-MEDIUM
**Files**:
- `js/backgroundScripts/background.bundle.js` (lines 1879-1880, 13079-13101)

**Description**:
Extension allows users to configure Discord webhook URLs for notifications about trades, friend requests, and logout detection. While this is an opt-in feature controlled by the user, it could be abused if:
1. User is socially engineered to enter a malicious webhook
2. Extension is compromised in a future update

**Code Evidence**:
```javascript
// Default settings (disabled by default):
discordNotificationHook: "",
allowDiscordNotification: !1,

// Discord notification function:
fi = e => {
  chrome.storage.local.get(["allowDiscordNotification", "discordNotificationHook"], (({
    allowDiscordNotification: i,
    discordNotificationHook: t
  }) => {
    if (i && "" !== t) {
      const i = new Request(t, {
        method: "POST",
        body: JSON.stringify({
          embeds: [e],
          username: "CS2TRADER.APP",
          avatar_url: "https://csgotrader.app/cstlogo48.png"
        }),
        headers: {
          "Content-Type": "application/json"
        }
      });
      fetch(i).then((e => {
        e.ok || console.log(`Error code: ${e.status} Status: ${e.statusText}`)
      }))
    }
  }))
}
```

**Data Sent**: Trade notifications, friend request alerts, logout detection events

**Verdict**: ACCEPTABLE - User-configured, opt-in feature. Default disabled. Used only when explicitly configured by user. No hardcoded webhooks found.

---

### 4. LOW SEVERITY: eval() Usage in Market History Injection

**Severity**: LOW
**Files**:
- `js/injectToPage/LoadMarketHistory.js` (lines 30, 37)

**Description**:
Limited use of `eval()` to execute Steam-provided hover event code for market history items. This code is injected into the page context and evaluates response data from Steam's market API.

**Code Evidence**:
```javascript
// LoadMarketHistory.js:30
elMyHistoryContents.innerHTML = response.results_html,
MergeWithAssetArray(response.assets),
eval(response.hovers),  // ← Evaluates Steam's hover code
addItemInfoToElement(response.assets, response.hovers)

// LoadMarketHistory.js:37
g_oMyHistory.SetResponseHandler((function(response) {
  MergeWithAssetArray(response.assets),
  eval(response.hovers),  // ← Evaluates Steam's hover code
  addItemInfoToElement(response.assets, response.hovers)
}))
```

**Verdict**: LOW RISK - eval() is used on data from Steam's own servers (steamcommunity.com/market/myhistory), not arbitrary third-party sources. This is replicating Steam's native functionality. DOMPurify sanitization is applied to HTML content before insertion.

---

### 5. INFO: Extensive Credential Storage in Local Storage

**Severity**: INFO
**Files**:
- `js/backgroundScripts/background.bundle.js` (lines 1680-1809)

**Description**:
Extension stores multiple sensitive credentials in unencrypted chrome.storage.local:

**Stored Credentials**:
```javascript
steamAPIKey: "",           // Steam Web API key
apiKeyValid: !1,
steamAcessToken: "",       // Steam access token (OAuth-like)
steamAcessTokenValid: !1,
steamIDOfUser: "",         // User's Steam ID
steamSessionID: "",        // Session ID for CSRF protection
discordNotificationHook: "",  // User's Discord webhook (opt-in)
```

**Verdict**: STANDARD PRACTICE - Chrome extension local storage is isolated per-extension and encrypted at rest by the browser. This is standard for Steam trading extensions. However, malware with system access could potentially extract these values.

---

### 6. INFO: csgotraders.net Auto-Login Feature

**Severity**: INFO
**Files**:
- `js/contentScripts/tradersAutoLogin.bundle.js`

**Description**:
Optional feature that automatically clicks the Steam login button on csgotraders.net when enabled. Disabled by default.

**Code Evidence**:
```javascript
chrome.storage.local.get("csgotradersAutoLogin",(e=>{
  if(e.csgotradersAutoLogin){
    document.referrer.includes("steamcommunity.com/openid/login")&&
      (window.location.href="https://csgotraders.net/mytrades");
    const e=document.querySelector('a[href="/auth/steam"]');
    null!==e&&e.click()
  }
}));
```

**Verdict**: ACCEPTABLE - Opt-in convenience feature (default: false). Only automates clicking a link the user would normally click. Uses standard OpenID authentication flow.

---

## False Positives Identified

| Pattern | Location | Reason | Verdict |
|---------|----------|---------|---------|
| DOMPurify library | `background.bundle.js`, `apiKey.bundle.js`, etc. | Standard HTML sanitization library (v3.0.5) | FALSE POSITIVE |
| `proxy` keyword in context | Various bundle.js.map files | References to JS Proxy objects, not residential proxies | FALSE POSITIVE |
| `remote` keyword in context | `background.bundle.js:1879` | Refers to remote notification sounds (user URLs), not remote config | FALSE POSITIVE |
| `.innerHTML =` usage | Multiple content scripts | Used with DOMPurify.sanitize() wrapper | FALSE POSITIVE (sanitized) |
| fetch/XMLHttpRequest | All scripts | Standard API calls to Steam and csgotrader.app only | FALSE POSITIVE (legitimate) |

## API Endpoints & Data Flow

### Extension-Controlled Endpoints

| Domain | Purpose | Data Sent | Sensitive Data |
|--------|---------|-----------|----------------|
| `api.csgotrader.app` | Float value API | Inspect URLs, item data | Inspect links only |
| `prices.csgotrader.app` | Price data | None (GET only) | No |

**csgotrader.app endpoints**:
```javascript
// Float value retrieval:
https://api.csgotrader.app/float?url=${encodeURIComponent(inspectLink)}&price=${price}&currency=${currencyid}

// Batch float retrieval:
https://api.csgotrader.app/getFloats
POST body: {items, isOwn, ownerID, type}

// Price data (JSON):
https://prices.csgotrader.app/latest/${provider}.json
https://prices.csgotrader.app/latest/exchange_rates.json
```

### Steam Endpoints (First-Party)

| Domain | Purpose | Credentials Used |
|--------|---------|------------------|
| `api.steampowered.com` | Trade offers, player data, item class info | API Key, Access Token |
| `steamcommunity.com` | Inventory, market, profiles, friends | Session ID, cookies |
| `steamcommunity.com/dev/apikey` | API key management | Session cookies |

### Third-Party Endpoints (User-Configured)

| Domain | Purpose | User Control |
|--------|---------|--------------|
| Discord webhooks (user-provided) | Notifications | Opt-in, user supplies URL |
| Custom notification sounds (user URLs) | Audio playback | Opt-in, user supplies URL |

**No unauthorized third-party data exfiltration detected.**

## Data Flow Summary

```
User Action → Extension → Legitimate Destination
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

View inventory → Content script → Steam API (prices.csgotrader.app)
                               → Steam Community (item data)

Open trade offer → Background script → Steam API (GetTradeOffers with access token)
                                     → csgotrader.app (float values for items)

View market listing → Content script → Steam Market API
                                      → csgotrader.app (price history)

Visit /dev/apikey → Auto-register key → Store in chrome.storage.local
                                       → Validate via Steam API

Homepage load → Scrape access token → Store in chrome.storage.local
                                     → Use for trade API calls

Trade/friend events → (If enabled) → User's Discord webhook
                                    → Chrome notifications
```

**Local Storage Flow**:
```
Credentials extracted from Steam → chrome.storage.local (encrypted at rest)
                                 → Used for Steam API operations only
                                 → Not transmitted to third parties
```

## Chrome Extension Permissions Analysis

### Declared Permissions
```json
"permissions": [
  "storage",           // Store settings, credentials, cache
  "notifications",     // Desktop notifications for trades
  "alarms",           // Scheduled tasks (price updates, monitoring)
  "unlimitedStorage", // Large item/price databases
  "offscreen"         // DOM parsing for credential extraction
]

"optional_permissions": [
  "tabs"  // Tab management (opening trade pages)
]

"host_permissions": [
  "*://steamcommunity.com/*",      // All Steam Community pages
  "*://api.steampowered.com/*",    // Steam Web API
  "*://api.csgotrader.app/*",      // Extension backend (floats)
  "*://prices.csgotrader.app/*"    // Price data CDN
]

"optional_host_permissions": [
  "*://csgotraders.net/*",  // Third-party trading site integration
  "*://discord.com/*"       // Not actually used, likely legacy
]
```

### Permission Usage Assessment

| Permission | Usage | Risk Level | Justification |
|------------|-------|------------|---------------|
| `storage` | Credentials, settings, price cache | MEDIUM | Necessary but stores sensitive data |
| `notifications` | Trade alerts, friend requests | LOW | Standard notification feature |
| `alarms` | Price updates, offer monitoring | LOW | Scheduled background tasks |
| `unlimitedStorage` | Item database, float cache | LOW | Legitimate for large datasets |
| `offscreen` | DOM parsing for API key/token extraction | MEDIUM | Used for credential scraping |
| `tabs` (optional) | Opening trade pages | LOW | User-triggered convenience |
| `steamcommunity.com/*` | Full Steam integration | HIGH | Necessary for core functionality |
| `api.steampowered.com/*` | Trade API access | HIGH | Required for trade offers |

**Content Security Policy**:
```json
"extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';"
```
✅ Blocks inline scripts, allows only bundled scripts
✅ `wasm-unsafe-eval` likely for future features (no WASM currently used)

---

## Security Recommendations

### For Users:
1. **Review API Key Settings**: Disable "Auto Set Steam API Key" in extension options if you prefer manual key management
2. **Verify Discord Webhooks**: Only use trusted Discord webhooks if enabling notifications
3. **Monitor API Key Usage**: Periodically check `steamcommunity.com/dev/apikey` to ensure no unauthorized keys
4. **Review Permissions**: Understand that the extension requires broad Steam access to function

### For Developers:
1. **Explicit API Key Consent**: Consider requiring explicit per-registration consent before auto-registering API keys, not just a settings toggle
2. **Token Encryption**: Consider encrypting stored access tokens using a session-derived key
3. **Remove eval()**: Replace eval() in LoadMarketHistory.js with safer parsing (JSON.parse or DOM manipulation)
4. **Scope Reduction**: Consider moving from broad `*://steamcommunity.com/*` to specific page patterns where possible
5. **Security Audit Trail**: Add optional logging for credential access/usage for security-conscious users
6. **Code Signing**: Implement subresource integrity checks for any bundled libraries

### For Reviewers:
1. **Monitor Future Updates**: Watch for changes to credential handling code in updates
2. **Verify API Endpoints**: Ensure csgotrader.app endpoints continue to serve only stated functionality
3. **Check for Obfuscation**: Future versions should maintain current code transparency

---

## Overall Risk Assessment

**Risk Level**: **MEDIUM**

### Risk Factors:
- ✅ **Legitimate Purpose**: Genuine trading enhancement tool with extensive user base
- ✅ **Transparent Code**: Readable, non-obfuscated JavaScript
- ✅ **Known Developer**: Open-source project on GitHub (gergelyszabo94/csgo-trader-extension)
- ✅ **No Malicious Patterns**: No data exfiltration, tracking SDKs, or proxy infrastructure
- ⚠️ **Sensitive Credential Handling**: Auto-extracts API keys and access tokens
- ⚠️ **Broad Permissions**: Full access to Steam Community required for features
- ⚠️ **User-Configured Webhooks**: Potential for abuse if compromised

### Comparison to Known Threats:
- **Unlike malicious VPN extensions**: No XHR/fetch hooking, no browsing history collection, no market intelligence SDKs
- **Unlike ad injectors**: No DOM manipulation for advertising, no remote configs for behavior changes
- **Similar to legitimate Steam tools**: Comparable to Steam Inventory Helper, Enhanced Steam (now defunct)

### Trust Considerations:
- Extension source is available on GitHub: https://github.com/gergelyszabo94/csgo-trader-extension
- Active development and maintenance since 2017
- Large user base (~400K) with public reviews
- Legitimate use case: CS:GO/CS2 trading is complex and benefits from tooling

---

## Verdict: **LOW-MEDIUM RISK (Acceptable with Caveats)**

CS2 Trader is a **legitimate Steam trading enhancement tool** that provides genuine utility for CS2 traders. The extension does not exhibit malicious behavior, data exfiltration, or tracking characteristics found in malware-infected extensions.

**Primary concerns are security-related rather than malicious**:
1. Automatic credential extraction (API keys, access tokens) increases attack surface
2. Extensive permissions required for functionality create risk if extension is compromised
3. User-configurable webhooks could be exploited through social engineering

**Recommendation**: **ACCEPTABLE FOR USERS WHO UNDERSTAND THE RISKS**

This extension is appropriate for users who:
- Need advanced CS2 trading features (price checking, float values, offer management)
- Understand that it requires Steam API keys and access tokens to function
- Trust the developer and are comfortable with the permission scope
- Keep their system secure (malware could extract stored credentials)

**Not recommended for**:
- Security-sensitive accounts (pro traders with high-value inventories should use isolated accounts)
- Users uncomfortable with automatic credential extraction
- Users who don't need the advanced features (Steam native interface may suffice)

---

## Appendix: Code Sample References

### DOMPurify Usage (Sanitization)
```javascript
// All HTML insertion is sanitized:
document.getElementById("editForm").insertAdjacentHTML("afterend",
  i().sanitize('<div class="apiKeyAdded">...</div>'))
```

### Legitimate API Call Pattern
```javascript
// Typical csgotrader.app API call:
const g = new Request(`https://prices.csgotrader.app/latest/${provider}.json`, {
  method: "GET",
  headers: y,
  mode: "cors",
  cache: "default"
});
fetch(g).then((e => (e.ok || console.log(`Error code: ${e.status}`), e.json())))
```

### Steam Session Handling
```javascript
// Legitimate session ID usage for CSRF protection:
body: `sessionid=${sessionID}&steamid=${steamID}&ajax=1&action=${action}&steamids%5B%5D=${targetSteamID}`
```

---

**Report Generated**: 2026-02-06
**Analyst**: Claude (Anthropic)
**Extension Version Analyzed**: 3.5.3
**Analysis Confidence**: HIGH (Complete code review of deobfuscated sources)
