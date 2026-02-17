# Vulnerability Report: TTV NoAds

## Metadata
- **Extension ID**: efdkmejbldmccndljocbkmpankbjhaao
- **Extension Name**: TTV NoAds
- **Version**: 1.2.17
- **Users**: ~90,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

TTV NoAds is a Twitch ad-blocking extension that intercepts video stream requests and swaps ad-containing playlists with ad-free alternatives. The extension uses multiple fallback player types (embed, proxy, autoplay) and third-party proxy servers to obtain clean streams. While the static analyzer flagged two exfiltration flows, these are false positives related to the extension's legitimate donation/subscription verification system. The extension validates user-provided API keys by sending them to www.ttvadblock.com, which is the developer's own infrastructure for managing supporters who have donated. The extension does not collect or exfiltrate browsing history, user credentials, or other sensitive data beyond the optional API key validation.

The extension modifies HTTP headers (removes CSP, X-Frame-Options) and hooks the Worker constructor to inject ad-blocking logic into Twitch's video player. This is expected behavior for an ad-blocking extension and does not constitute a vulnerability. The extension is appropriately scoped to twitch.tv domains and operates transparently within its stated purpose.

## Vulnerability Details

### 1. LOW: Remote Configuration via API Endpoint
**Severity**: LOW
**Files**: js/bg.js, popup.js
**CWE**: N/A (Expected behavior for subscription-based features)
**Description**: The extension communicates with www.ttvadblock.com to validate API keys for users who have donated. When a user provides an API key (obtained after donating), the extension sends it to `https://www.ttvadblock.com/donate/api/subscription/check` to verify the subscription status.

**Evidence**:
```javascript
// js/bg.js lines 98-106
let t = await fetch("https://www.ttvadblock.com/donate/api/subscription/check", {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    api_key: e
  })
});
```

**Verdict**: This is not a security vulnerability. The API key is user-provided and only sent when the user explicitly enters it to verify their donation status. The extension stores the subscription status locally and uses it to hide donation prompts for supporters. No browsing data, cookies, or other sensitive information is transmitted.

## False Positives Analysis

The static analyzer flagged two "exfiltration" flows from `chrome.storage.local.get` to `fetch(www.ttvadblock.com)`. This is a false positive because:

1. **User-Initiated Action**: The data flow only occurs when a user explicitly enters an API key and clicks "Validate"
2. **Limited Scope**: Only the user-provided API key is sent, not browsing data or other storage contents
3. **Transparent Purpose**: The extension's popup clearly shows this is for donation verification
4. **No Silent Collection**: The extension does not silently collect or exfiltrate user data

The extension does read from `chrome.storage.local` to retrieve settings (ads enabled/disabled, message visibility, API key), but this is standard extension behavior for persisting user preferences.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.ttvadblock.com | Subscription verification, install/uninstall tracking | API key (user-provided), installation events | LOW - Legitimate developer infrastructure |
| gql.twitch.tv | Twitch GraphQL API (access tokens) | Channel name, player type, device ID | NONE - Required for ad-blocking functionality |
| usher.ttvnw.net | Twitch video stream API | Channel name, access tokens | NONE - Required for ad-blocking functionality |
| pxy.blocktwitchads.com | Third-party proxy for ad-free streams | Channel name | LOW - External dependency, privacy concern if not trusted |
| api.ttv.lol | Third-party proxy for ad-free streams | Channel name | LOW - External dependency, privacy concern if not trusted |

## Technical Analysis

### Ad-Blocking Mechanism
The extension uses sophisticated techniques to block Twitch ads:

1. **Worker Injection**: Hooks the `Worker` constructor to inject custom fetch handlers into Twitch's video player worker
2. **M3U8 Playlist Manipulation**: Intercepts video stream playlist requests and detects ad markers (`stitched`)
3. **Fallback Chain**: When ads are detected, tries multiple player types in sequence:
   - Embed player (iOS platform)
   - Proxy servers (blocktwitchads.com, ttv.lol)
   - Autoplay player (360p fallback)
4. **Header Modification**: Uses `declarativeNetRequest` to remove CSP and X-Frame-Options headers

### Privacy Considerations
- **On Install**: Opens www.ttvadblock.com/install (common for donation-supported extensions)
- **On Uninstall**: Sets uninstall URL to www.ttvadblock.com/uninstall (feedback collection)
- **Popup Display**: Shows periodic donation requests in-page (can be disabled by donating or closing)
- **Third-Party Proxies**: When ads are detected and local methods fail, sends current channel name to proxy services

### Code Quality
The code is webpack-bundled but not obfuscated. Variable names are minified but the logic is readable. The deobfuscated version shows standard ad-blocking patterns with no suspicious data collection.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
- The extension performs its stated function (ad-blocking on Twitch) without deceptive behavior
- The "exfiltration" flows are false positives related to optional donation verification
- API key transmission is user-initiated and limited to subscription validation
- No browsing data, cookies, credentials, or other sensitive information is collected
- The use of third-party proxies is a minor privacy concern but is necessary for the ad-blocking functionality
- The extension is appropriately scoped to twitch.tv domains
- Donation prompts may be annoying but are not malicious and can be disabled

The main concern is the reliance on external proxy services (pxy.blocktwitchads.com, api.ttv.lol) which receive channel names. Users who are privacy-conscious should be aware that their viewing activity (channel names) may be sent to these third parties when ads are detected. However, this is disclosed in the extension's functionality and is a tradeoff for free ad-blocking.

**Recommendation**: CLEAN for malware/malicious intent. The extension is legitimate. Users should be aware of the third-party proxy usage if they have strict privacy requirements.
