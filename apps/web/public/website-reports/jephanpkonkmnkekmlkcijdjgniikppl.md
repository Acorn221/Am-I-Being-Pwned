# Security Analysis: VK Next - функции для ВКонтакте (jephanpkonkmnkekmlkcijdjgniikppl)

## Extension Metadata
- **Name**: VK Next - функции для ВКонтакте
- **Extension ID**: jephanpkonkmnkekmlkcijdjgniikppl
- **Version**: 14.8.2
- **Manifest Version**: 3
- **Estimated Users**: ~50,000
- **Developer**: vknext.net
- **Analysis Date**: 2026-02-14

## Executive Summary
VK Next is a feature-rich enhancement extension for the Russian social network VKontakte (VK) with **MEDIUM** risk status. The extension provides legitimate functionality including UI improvements, theme customization, message templates, Telegram sticker integration, and various VK feature enhancements. Security analysis reveals privacy concerns around "spy" features that track user online/offline status and typing indicators, CORS bypass via header modification, and communication with developer-controlled API (api.vknext.net) for banner ads and authentication. The code is obfuscated and uses web-accessible resources exposed to all URLs. No evidence of malicious data exfiltration, credential theft, or cookie harvesting was found. The Telegram Bot API integration serves legitimate sticker download functionality. PostMessage handlers properly validate origin despite ext-analyzer flagging them.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. Privacy-Invasive "Spy" Features
**Severity**: MEDIUM
**Files**:
- `/scripts/847c90bc1.vknext.js` (lines 4726-4739)
- Multiple localization files with spy-related strings

**Analysis**:
The extension implements user activity tracking features marketed as "spying" functionality:

**Code Evidence** (`847c90bc1.vknext.js`):
```javascript
const r = async e => await n.storage.local.set({
  [s.No.SPYNING]: e
});
const _ = () => (l && (0, o.A)() - i <= 3 || (l = new Promise(async e => {
  e((await n.storage.local.get(s.No.SPYNING))[s.No.SPYNING] || {})
}), ...
```

**Tracked Events** (from localization files):
- Online/offline status: `"появился в сети"`, `"вышел из сети"`
- Typing indicators: `"печатает"`
- Voice message recording: `"записывает аудиосообщение"`
- Photo/video sending: `"отправляет фото"`, `"отправляет видео"`
- Message read status: `"прочитал сообщения"`
- Friend removal: `"удалил из друзей"`
- App-specific activity: `"появился в сети с {appName}"`

**Privacy Impact**:
- Enables detailed surveillance of VK contacts' activities
- Stores tracking data in local storage (`chrome.storage.local`)
- No evidence of transmission to external servers beyond VK itself
- Data appears confined to user's browser but enables invasive monitoring

**Verdict**: **PRIVACY CONCERN** - While not technically malicious data exfiltration, the spy features enable privacy-invasive monitoring of other users' activities. This is a gray-area feature common in VK enhancement extensions but raises ethical concerns.

---

### 2. CORS Bypass via Header Modification
**Severity**: MEDIUM
**Files**: `/scripts/847c90bc1.vknext.js` (lines 1170-1230)

**Analysis**:
The extension uses `declarativeNetRequest` to modify HTTP headers and bypass CORS restrictions.

**Code Evidence**:
```javascript
{
  id: (0, o.A)(),
  action: {
    type: "modifyHeaders",
    responseHeaders: [{
      value: "*",
      operation: "set",
      header: "Access-Control-Allow-Origin"
    }, {
      operation: "set",
      value: "*",
      header: "Access-Control-Allow-Methods"
    }, {
      value: "*",
      operation: "set",
      header: "Access-Control-Allow-Headers"
    }]
  },
  condition: {
    urlFilter: "https://api.telegram.org/",
    initiatorDomains: [r].concat(s.cV)
  }
}
```

**Modified Endpoints**:
1. `https://api.telegram.org/` - Sets wildcard CORS headers
2. `https://login.vk.com/?act=web_token` - Sets origin to "https://vk.com"
3. `https://oauth.vk.ru/*` - Sets wildcard CORS headers

**Purpose**:
- Enables cross-origin requests to Telegram Bot API for sticker downloads
- Facilitates VK OAuth token exchange
- Required for extension's Telegram sticker integration feature

**Risk Assessment**:
- Limited to specific VK and Telegram domains
- No evidence of abuse for malicious cross-origin data theft
- Necessary for advertised functionality (Telegram stickers in VK)
- Could potentially be exploited if extension is compromised

**Verdict**: **MEDIUM RISK** - CORS bypass is necessary for legitimate features but expands attack surface.

---

### 3. Communication with Developer-Controlled API
**Severity**: LOW
**Files**:
- `/scripts/80480b578.vknext.js` (line 156)
- `/scripts/8812f31ab.vknext.js` (lines 696-707)
- `/scripts/847c90bc1.vknext.js` (lines 3195-3265, 4698-4702)

**Analysis**:
The extension communicates with `https://api.vknext.net` for several purposes:

**Code Evidence** (`8812f31ab.vknext.js`):
```javascript
const r = await fetch("https://api.vknext.net/extension.getBannerInfo", {
  method: "POST",
  body: JSON.stringify(a),
  headers: {
    Accept: "application/json",
    "Content-Type": "application/json"
  }
}),
```

**API Endpoints**:
1. `extension.getBannerInfo` - Fetches banner/promo content
2. `internal.getAuthAppId` - Retrieves VK app ID for OAuth
3. `internal.getRawText` - Proxy for fetching text content

**Data Transmitted**:
```javascript
const a = {
  version: e.version,  // Extension version
  id: e.id             // Extension runtime ID
};
```

**Installation Tracking** (`847c90bc1.vknext.js`, line 4698):
```javascript
if ("install" === e) {
  const { version: e } = o.runtime.getManifest(),
        t = new URL("https://vknext.net/installed/vknext");
  t.searchParams.set("version", e),
  t.searchParams.set("id", o.runtime.id),
  await o.tabs.create({
    url: t.toString(),
    active: !0
  })
}
```

**Uninstall Tracking** (line 320):
```javascript
const t = new URL("https://vknext.net/uninstall");
if (e) t.searchParams.set("u", e.toString());  // User ID
const { version: a } = s.runtime.getManifest();
t.searchParams.set("v", a),
t.searchParams.set("id", s.runtime.id);
```

**Data Collected**:
- Extension version
- Extension runtime ID
- VK user ID (on uninstall)
- No browsing history, messages, or sensitive data

**Verdict**: **LOW RISK** - Basic telemetry for analytics and banner ads. No sensitive data exfiltration detected.

---

### 4. PostMessage Handlers (False Positive)
**Severity**: N/A (Not a Vulnerability)
**Files**:
- `/scripts/8f6ad9154.vknext.js` (lines 70-71)
- `/scripts/e42af5073.vknext.js` (line 3423)
- `/scripts/f0dd06f14.vknext.js` (line 40)

**Analysis**:
The ext-analyzer flagged 10 postMessage handlers as lacking origin validation. Manual code review reveals **this is a false positive**.

**Code Evidence** (`8f6ad9154.vknext.js`):
```javascript
this.messageHandler = async e => {
  if (e.origin !== window.origin) return;  // ✅ ORIGIN CHECK PRESENT
  const s = e.data;
  if (s?.source !== this.SOURCE_NAME) return;  // ✅ SOURCE VALIDATION
  // ... handler logic
}
```

**Security Measures**:
1. **Origin validation**: `e.origin !== window.origin` check prevents cross-origin messages
2. **Source identification**: Messages must include `source: "vkcom-vkn-13"` identifier
3. **Same-origin policy**: Only accepts messages from same window

**Message Types Handled**:
- `ON_UPDATE_STORAGE` - Storage synchronization
- `GET_MANIFEST` - Extension metadata retrieval
- `GET_STORAGE` - Local storage access
- `RELOAD_VKCOM` - Page reload trigger
- All handlers require both origin and source validation

**Verdict**: **NOT VULNERABLE** - PostMessage handlers properly validate origin. Ext-analyzer flag is incorrect.

---

### 5. Telegram Bot API Integration
**Severity**: N/A (Legitimate Functionality)
**Files**:
- `/scripts/aab1c04fe.vknext.js` (lines 10-39)
- `/scripts/847c90bc1.vknext.js` (lines 540-560)

**Analysis**:
The extension integrates with Telegram Bot API for sticker download functionality.

**Code Evidence** (`aab1c04fe.vknext.js`):
```javascript
const o = class {
  token;
  constructor(e) {
    this.token = e;
    // Methods: getMe, getFile, getStickerSet
  }
  async call(e, t) {
    const a = await (0, n.A)(`https://api.telegram.org/bot${this.token}/${e}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams(t)
    }),
    const r = await a.json();
    return r.ok, r
  }
  getFileUrl(e) {
    return `https://api.telegram.org/file/bot${this.token}/${e}`
  }
}
```

**Token Validation**:
```javascript
isValidToken() {
  if (!this.token) return !1;
  const e = this.token.split(":");
  return !(2 !== e.length || e[0].length < 4 || 35 !== e[1].length)
}
```

**API Methods Used**:
- `getMe` - Bot information
- `getFile` - Sticker file download
- `getStickerSet` - Sticker pack metadata

**Data Flow**:
1. User provides Telegram bot token (optional feature)
2. Extension uses token to call Telegram Bot API
3. Downloads sticker sets for use in VK
4. Token stored in `chrome.storage.local` (user-controlled)

**Security Indicators**:
- User must explicitly provide bot token
- Token validation before API calls
- Read-only API operations (no message sending)
- CORS bypass required but limited to Telegram domain
- No token transmission to vknext.net

**Verdict**: **LEGITIMATE FEATURE** - Telegram integration is optional, user-controlled, and serves advertised functionality (importing Telegram stickers to VK).

---

### 6. Web-Accessible Resources (All URLs)
**Severity**: LOW
**Manifest**: `manifest.json`

**Analysis**:
```json
"web_accessible_resources": [{
  "resources": ["*"],
  "matches": ["<all_urls>"]
}]
```

**Exposed Resources**:
- All extension assets (scripts, styles, images, icons)
- Accessible from any webpage via `chrome-extension://[id]/[path]`

**Risk Assessment**:
- Enables extension fingerprinting via resource timing attacks
- Could expose internal file structure
- No sensitive data in web-accessible files (verified via review)
- Common pattern in UI-modifying extensions

**Mitigation Factors**:
- Manifest V3 provides baseline CSP protections
- No credentials or API keys in exposed files
- Resources needed for dynamic injection into VK pages

**Verdict**: **LOW RISK** - Overly permissive but necessary for functionality. Enables fingerprinting but not data theft.

---

### 7. Obfuscated Code
**Severity**: LOW
**Files**: All scripts (webpack-bundled, minified)

**Analysis**:
The extension uses heavily minified and webpack-bundled code with short variable names:

**Obfuscation Characteristics**:
- Webpack module IDs (numeric)
- Minified variable names (`e`, `t`, `a`, `o`, `s`, `n`, `r`)
- String obfuscation in some areas (base64-encoded keys: `"udGltZS5p"`, `"cGlkb3I"`)
- Dynamic property access

**Example**:
```javascript
r = {
  version: await a.getVersion(),
  udGltZS5w: await a.getRuntimeId(),  // base64: "runtime.i"
  cGlkb3I: e,                          // base64: "pidor"
  // ... encrypted data structure
}
```

**Purpose Assessment**:
- Standard webpack production build minification
- Some deliberate obfuscation of API communication parameters
- No polymorphic or anti-analysis techniques detected
- Deobfuscation via jsbeautifier was successful

**Verdict**: **TRANSPARENCY CONCERN** - Minification is standard but base64 property names suggest intent to obscure API communication details.

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `api.vknext.net` | Banner ads, auth app ID | Extension version, runtime ID | Periodic (banner refresh) |
| `vknext.net` | Install/uninstall tracking, changelog, donate | Version, runtime ID, user ID (uninstall) | Install, update, uninstall |
| `static.vknext.net` | Static assets (images, videos) | None (asset downloads) | On-demand |
| `api.telegram.org` | Telegram sticker downloads | Bot token (user-provided), sticker IDs | User-initiated |
| `api.vk.com`, `oauth.vk.com`, `login.vk.com` | VK API calls, OAuth | VK access tokens, API requests | As needed for VK features |
| `api.genius.com` | Lyrics integration | Song metadata | User-initiated |

### Data Flow Summary

**Data Collection**: Extension version, runtime ID, VK user ID (uninstall only)
**User Data Transmitted**: None beyond VK API interactions
**Tracking/Analytics**: Basic install/uninstall tracking via vknext.net
**Third-Party Services**: Telegram Bot API (user-controlled), Genius API (lyrics)

**Critical Finding**: No evidence of VK message content, passwords, cookies, or browsing history being transmitted to external servers.

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `tabs` | Tab management, VK page injection | Low (functional) |
| `unlimitedStorage` | Storing themes, messages, deleted content | Low (local only) |
| `storage` | Settings, spy data, tokens | Medium (privacy data stored) |
| `declarativeNetRequest` | CORS bypass for Telegram/VK APIs | Medium (broad capability) |
| `scripting` | Content script injection into VK pages | Low (core feature) |
| `downloads` | Downloading stickers, media | Low (functional) |
| `alarms` | Scheduled tasks (polling, notifications) | Low (functional) |
| `notifications` | Desktop notifications for spy events | Low (functional) |
| `host_permissions: vk.com, vk.ru` | Access VK pages | Low (expected scope) |
| `host_permissions: vknext.net` | Communication with developer API | Medium (update mechanism) |
| `host_permissions: api.telegram.org` | Telegram sticker API | Low (optional feature) |
| `host_permissions: api.genius.com` | Lyrics lookup | Low (optional feature) |

**Assessment**: Permissions are justified for advertised functionality. The combination of `declarativeNetRequest` and broad host permissions is powerful but scoped to specific domains.

## Content Security Policy
```
Manifest V3 default CSP applies (no custom CSP declared)
```
**Default Protections**:
- `script-src 'self'` - Only extension scripts
- `object-src 'self'` - No external plugins
- No `unsafe-eval` or `unsafe-inline`

**Observations**: No CSP bypasses detected. Manifest V3 provides strong baseline protections.

## Code Quality Observations

### Positive Indicators
1. No dynamic code execution via `eval()` or `Function()`
2. No remote script loading
3. No XHR/fetch hooking or monkey-patching of native APIs
4. No extension enumeration or killing
5. No residential proxy infrastructure
6. No cryptocurrency mining
7. PostMessage handlers validate origin correctly
8. CORS bypass limited to specific domains
9. Telegram API access is opt-in (requires user token)

### Negative Indicators
1. Privacy-invasive "spy" features track user activities
2. Code obfuscation beyond standard minification
3. Web-accessible resources exposed to all URLs
4. Communication with developer API for ads/telemetry
5. CORS bypass expands attack surface
6. Base64-encoded API parameter names

### Obfuscation Level
**Medium** - Standard webpack minification plus deliberate obfuscation of some API communication details. No advanced anti-analysis techniques.

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | VK-only, no ChatGPT/Claude interception |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✗ No | Only injects VK UI enhancements |
| Remote config/kill switches | ✗ No | No remote code loading |
| Cookie harvesting | ✗ No | No `chrome.cookies` API usage |
| Credential theft | ✗ No | No password field monitoring |
| Hidden data exfiltration | ✗ No | All network calls are transparent |
| User activity surveillance | ✓ Yes | "Spy" features track VK contacts |

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Justification**:
1. **Privacy-invasive features** - "Spy" functionality tracks other users' online status, typing, and activities
2. **CORS bypass** - Header modification for Telegram/VK APIs expands attack surface
3. **Developer API communication** - Basic telemetry to vknext.net (version, runtime ID)
4. **Code obfuscation** - Beyond standard minification, suggests intent to obscure
5. **No malicious data theft** - No evidence of credential/cookie theft or unauthorized exfiltration
6. **Legitimate core features** - UI enhancements, themes, stickers are benign
7. **Limited scope** - Operates only within VK ecosystem

### Recommendations
- **For users**: Be aware that enabling "spy" features allows detailed tracking of contacts' activities. Review privacy implications before use.
- **For reviewers**: Monitor for future updates that might expand telemetry or add remote code loading.
- **For developers**: Increase transparency by providing unminified source code and clarifying data collection practices.

### User Privacy Impact
**MEDIUM** - The extension accesses:
- VK page content (for UI modifications)
- User online/offline status, typing indicators (spy features)
- Message content (for templates, deleted message recovery)
- Telegram bot token (user-provided, optional)
- Basic telemetry sent to vknext.net

**Critical**: No cross-site tracking, no credential theft, no cookie harvesting.

## Detailed Findings Summary

### MEDIUM Risk Findings (3)
1. **Privacy-invasive spy features** - Tracks VK contacts' online status, typing, message reads
2. **CORS bypass via header modification** - Expands attack surface for Telegram/VK API access
3. **Developer API communication** - Telemetry sent to vknext.net (version, ID, user ID on uninstall)

### LOW Risk Findings (2)
1. **Web-accessible resources exposed** - All extension files accessible via chrome-extension:// URLs
2. **Code obfuscation** - Base64-encoded parameter names, minified variables beyond webpack defaults

### Not Vulnerable (1)
1. **PostMessage origin validation** - False positive from ext-analyzer; origin checks are present

## Technical Summary

**Lines of Code**: ~10,000+ (deobfuscated across all scripts)
**External Dependencies**: None (bundled)
**Third-Party Libraries**: Webpack runtime, possibly React (inferred from component structure)
**Remote Code Loading**: None
**Dynamic Code Execution**: None

## Conclusion

VK Next is a **legitimate but privacy-concerning browser extension** that enhances VKontakte with UI improvements, themes, and messaging features. The primary risk stems from **"spy" functionality that enables detailed tracking of other VK users' activities**, raising ethical and privacy concerns. The extension communicates with developer-controlled API (vknext.net) for basic telemetry and banner ads but does not exfiltrate sensitive user data like messages, passwords, or cookies. CORS bypass via header modification is necessary for Telegram sticker integration but expands attack surface. Code obfuscation beyond standard minification reduces transparency. The postMessage origin validation finding from ext-analyzer is a false positive; handlers properly check `window.origin`.

**Final Verdict: MEDIUM RISK** - Safe for technical users who understand privacy implications of spy features. Users concerned about tracking should disable spy functionality or avoid this extension.

**Recommendation for Store**: Allow with privacy warning. Extension should clearly disclose tracking capabilities in description and require explicit opt-in for spy features.
