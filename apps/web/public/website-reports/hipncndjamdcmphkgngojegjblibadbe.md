# Security Analysis Report: Planet VPN

## Extension Metadata

- **Extension ID**: hipncndjamdcmphkgngojegjblibadbe
- **Name**: Free VPN Proxy and ad blocker - Planet VPN
- **Version**: 2.5.0
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

Planet VPN is a legitimate VPN service with extensive privacy features including ad blocking, tracker blocking, cookie blocking, and browsing history deletion. The extension requests highly invasive permissions appropriate for a VPN/privacy tool but uses them for their stated purpose. While the permission set is extensive, the extension operates transparently as a VPN service with optional privacy features.

**Overall Risk: CLEAN**

The extension implements standard VPN functionality with Firebase authentication, remote configuration, and privacy enhancement features. No malicious behavior, hidden data exfiltration, or exploitative code patterns were identified.

## Permissions Analysis

### High-Impact Permissions (Justified)

1. **proxy** - Required for VPN tunnel configuration
2. **webRequest + webRequestAuthProvider** - Handles proxy authentication
3. **<all_urls>** - Necessary for VPN routing and privacy feature application
4. **history** - Used for optional history deletion feature (user-controlled)
5. **privacy** - Manages third-party cookie blocking when enabled
6. **management** - Listed but NOT actually used in code
7. **declarativeNetRequest** - Powers ad/tracker blocking rulesets
8. **tabs** - Monitors active tabs for per-site privacy settings
9. **storage** - Stores user settings and server configurations
10. **scripting** - Listed but minimal usage detected
11. **offscreen** - Creates authentication worker for SSL certificate validation

### Permission Usage Verification

**✓ CLEAN**: All permissions align with advertised VPN and privacy protection functionality. No hidden misuse detected.

## Vulnerability Analysis

### 1. No Critical Vulnerabilities Detected

### 2. Privacy Features (By Design, User-Controlled)

**Severity**: N/A (Intentional Features)
**Affected Components**: Background service worker

**Findings**:
- **History Deletion**: Deletes browsing history when enabled (`historyOnVisited` listener)
- **Cookie Blocking**: Blocks third-party cookies via `chrome.privacy.websites` API
- **Ad Blocking**: Uses declarativeNetRequest rulesets (7.5MB+ of EasyList-style rules)
- **Tracker Blocking**: Separate ruleset for tracking scripts

**Files**:
- `background.js` lines 11680-11692 (history deletion)
- `background.js` lines 11661-11678 (cookie management)
- `rulesets/adblockerRuleset_1.json` (5MB)
- `rulesets/trackingRuleset.json` (3.5MB)

**Code Example**:
```javascript
historyOnVisited(e) {
  this.historyStatus && e.url && N.history.deleteUrl({
    url: e.url
  })
}
```

**Verdict**: CLEAN - These are opt-in privacy features clearly advertised in the extension name and description.

### 3. Firebase Integration

**Severity**: LOW (Standard Practice)
**Affected Components**: Push notifications, authentication

**Findings**:
- Firebase Cloud Messaging (FCM) for push notifications
- Firebase project ID: `b91829181723`
- API Key: `AIzaSyB7ccL3ifvf5Wz9jAbZ-DVE6MqHD3Jh49s` (public, non-sensitive)
- Device tokens sent to backend for notification delivery

**Files**: `background.js` lines 2184-2191, 4546-4592

**Verdict**: CLEAN - Standard Firebase SDK usage for push notifications.

### 4. Remote Configuration

**Severity**: LOW (Standard VPN Practice)
**Affected Components**: Server list, ad/tracker rulesets

**Findings**:
- Fetches VPN server list from `/v2/network/data/extensive`
- Downloads ad blocking rules from CDN (cdn.freevpnplanet.com)
- Uses Telegraph API for SSL certificate validation check

**Endpoints**:
- `https://cdn.freevpnplanet.com` or `https://s3.amazonaws.com/cdn.freevpnplanet.com` (Russia-specific)
- `https://api.telegra.ph/getPage/E-04-01-3` (config validation)

**Code**: `background.js` lines 1672-1690

**Verdict**: CLEAN - Standard remote configuration for VPN services.

### 5. X-Frame-Options Header Removal

**Severity**: LOW
**Affected Components**: declarativeNetRequest ruleset

**Findings**:
- Removes X-Frame-Options headers from `connect.freevpnplanet.com/*`
- Purpose: Allows embedding their own iframe for PIN modal/authentication
- Scope: Limited to extension's own domain only

**Files**: `rulesets/responseHeaders.json`

```json
{
  "action": {
    "type": "modifyHeaders",
    "responseHeaders": [
      {"header": "X-Frame-Options", "operation": "remove"}
    ]
  },
  "condition": {
    "urlFilter": "*://connect.freevpnplanet.com/*",
    "resourceTypes": ["sub_frame"]
  }
}
```

**Verdict**: CLEAN - Limited to extension's own authentication domain.

### 6. Offscreen Authentication Worker

**Severity**: LOW
**Affected Components**: SSL certificate validation

**Findings**:
- Creates offscreen document with Web Worker
- Fetches `api.telegra.ph` endpoint to trigger SSL authentication
- Purpose: Validates proxy authentication without interfering with browsing

**Files**:
- `scripts/offscreen.js`
- `scripts/offscreenWorker.js`

**Code**:
```javascript
onmessage=e=>{
  fetch(e.data).then(()=>{
    console.log("url fetched successfully")
  })
}
```

**Verdict**: CLEAN - Authentication helper for proxy credentials.

## False Positive Analysis

| Pattern | Location | False Positive | Reason |
|---------|----------|----------------|---------|
| `innerHTML` | N/A | N/A | Not detected in code |
| `eval()` | N/A | N/A | Not detected in code |
| Dynamic code execution | N/A | N/A | No eval/Function/Worker misuse |
| Firebase API key | background.js:2184 | ✓ YES | Public Firebase config (not sensitive) |
| History API usage | background.js:11689 | ✓ YES | Opt-in privacy feature (history deletion) |
| Cookie manipulation | background.js:11665 | ✓ YES | Opt-in privacy feature (3rd-party blocking) |
| Offscreen document | background.js:11701 | ✓ YES | Required for MV3 auth flow |

## Data Flow Summary

### Data Collection
1. **User Authentication** (optional)
   - Email/password sent to backend for premium accounts
   - JWT token stored locally
   - Bearer auth for API requests

2. **Analytics/Telemetry**
   - Firebase device token (for push notifications)
   - Browser type UUID (hardcoded per browser, not user-specific)
   - User's country code (for server selection)

3. **VPN Functionality**
   - Selected server configuration
   - Proxy authentication credentials (temporary, session-only)
   - Connection status

### Data Transmission Endpoints

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `freeplanetvpn.com/login` | User login | Email, password | Expected |
| `freeplanetvpn.com/v3/user` | Profile fetch | Auth token | Expected |
| `freeplanetvpn.com/v2/network/data/extensive` | Server list | Location, auth token | Expected |
| `firebaseinstallations.googleapis.com` | FCM registration | Device token | Standard |
| `api.telegra.ph` | SSL validation | None (GET request) | Benign |
| `cdn.freevpnplanet.com` | Ruleset updates | None (static files) | Benign |

### No Unauthorized Data Exfiltration
- ✓ No browsing history sent to servers
- ✓ No cookie harvesting beyond stated cookie blocking
- ✓ No keylogging or form interception
- ✓ No ad/coupon injection detected
- ✓ No market intelligence SDKs (Sensor Tower, etc.)
- ✓ No residential proxy reselling patterns

## API Endpoints Table

| Domain | Purpose | Authentication | Data Flow |
|--------|---------|----------------|-----------|
| freeplanetvpn.com | Primary API | Bearer token | Bidirectional |
| account.freeplanetvpn.com | User account portal | Session cookie | User-initiated |
| cdn.freevpnplanet.com | Static assets/rulesets | None | Download only |
| s3.amazonaws.com/cdn.freevpnplanet.com | Russia CDN fallback | None | Download only |
| api.telegra.ph | Config validation | None | GET only |
| firebase*.googleapis.com | Push notifications | Firebase token | FCM protocol |
| connect.freevpnplanet.com | Web authentication | None | iframe embed |

## Code Quality Observations

1. **Obfuscation**: Minimal variable minification, typical Webpack/Vite build output
2. **Libraries**: Firebase SDK v9+, Bowser (browser detection), Pinia (state management)
3. **Architecture**: Vue.js-based popup with background service worker
4. **No Suspicious Patterns**: No anti-debugging, no dynamic code loading, no hidden functionality

## Smart Filters & Ad Blocking

The extension includes comprehensive ad/tracker blocking:
- **7.5MB+** of EasyList-style rules across 3 rulesets
- Declarative Net Request API (MV3 compliant)
- Dynamic exception list (per-domain whitelist)
- Separate tracking and ad blocking rule categories

**Files**:
- `rulesets/adblockerRuleset_1.json` (5.0MB, ~100k rules)
- `rulesets/adblockerRuleset_2.json` (190KB)
- `rulesets/trackingRuleset.json` (3.5MB)
- CSS injection rules for element hiding

## Content Scripts

**Scope**: Limited to extension's own domains only

- **pinModal.js** (1,276 lines): Runs on `freeplanetvpn.com`, `planetvpnarab.com`, `freevpnplanet.net`
- **Purpose**: Shows extension pinning reminder modal on own website
- **Risk**: None - only injected on vendor's domains

## Recommendations

### For Users
✓ **Safe to Use**: Extension functions as advertised with no hidden malicious behavior.

**Privacy Considerations**:
- History deletion and cookie blocking are **opt-in** features
- VPN provider can see encrypted traffic metadata (inherent to VPN services)
- Free tier likely ad-supported or limited bandwidth
- Premium accounts require email registration

### For Security Researchers
- Extension demonstrates proper MV3 migration (offscreen documents, declarativeNetRequest)
- Firebase integration follows best practices (public config, device tokens only)
- No evidence of residential proxy reselling or traffic monetization beyond VPN service

## Conclusion

Planet VPN is a **legitimate VPN extension** with extensive privacy features. While the permission set is invasive, all permissions are justified by the advertised functionality. The extension does not exhibit malicious behavior patterns such as:

- ❌ Hidden data exfiltration
- ❌ Ad/coupon injection
- ❌ Keylogging or credential theft
- ❌ Extension enumeration/killing (beyond standard VPN conflict detection)
- ❌ Market intelligence SDKs
- ❌ Obfuscated malicious payloads

**Risk Assessment**: CLEAN

The extension operates transparently as a VPN service with optional ad blocking and privacy features. All data collection is consistent with providing VPN functionality and user account management.

---

**Analyst Notes**: This extension exemplifies why context matters in security analysis. Permissions like `history`, `privacy`, and `<all_urls>` appear invasive but are essential for the advertised privacy protection features. The key differentiator is **user control** - all privacy features are opt-in and clearly documented.
