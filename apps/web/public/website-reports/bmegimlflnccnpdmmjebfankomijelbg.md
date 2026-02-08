# Aurora VPN Security Analysis Report

## Extension Metadata

- **Extension ID**: bmegimlflnccnpdmmjebfankomijelbg
- **Name**: Aurora VPN — браузерный VPN
- **Version**: 2.1.5
- **Users**: ~0 (likely very low user count)
- **Language**: Primarily Russian
- **Permissions**: `proxy`, `storage`, `alarms`
- **Host Permissions**: `https://aurora-vpn.ru/*`, `http://ip-api.com/*`

## Executive Summary

Aurora VPN is a Russian-language browser VPN extension that provides SOCKS5 proxy tunneling through 9 regional servers. The extension implements a freemium model with 1 hour of free usage and paid premium servers. While the extension serves its stated purpose as a VPN service, it exhibits several concerning characteristics including obfuscated server credentials, anti-tampering mechanisms designed to detect and punish manipulation attempts, and unencrypted API communication that could expose user credentials and session tokens.

**Overall Risk Level: MEDIUM**

The extension is functional as a VPN service but implements security-hostile practices that create privacy and security risks for users.

---

## Vulnerability Details

### 1. MEDIUM: Credential Obfuscation via Character Offset Encoding

**Severity**: MEDIUM
**Category**: Security through obscurity
**Files**: `background.js` (lines 1-16)

**Description**:
Server IP addresses and ports are obfuscated using a simple character code offset (+7) to hide them from plaintext inspection.

**Evidence**:
```javascript
const OBFUSCATION_DELTA = 7;
function decodeFromOffsets(arr){
  return arr.map(n => String.fromCharCode(n - OBFUSCATION_DELTA)).join('');
}

const REGIONS = [
  { id: 'nl', name: 'Netherlands', host: [117,115,53,122,108,121,125,108,121,122,52,104,124,121,118,121,104,52,126,53,121,124], port: [56,55,60,57,56] },
  // Decodes to: nl.servers.aurora.ru:1234
```

Decoded server infrastructure:
- Netherlands: `nl.servers.aurora.ru:1234`
- Germany: `de.servers.aurora.ru:1235`
- Armenia: `am.servers.aurora.ru:1236`
- Sweden: `se.servers.aurora.ru:1237`
- Turkey: `tr.servers.aurora.ru:1238`
- USA: `us.servers.aurora.ru:1239`
- Estonia: `ee.servers.aurora.ru:1240`
- Switzerland: `ch.servers.aurora.ru:1241`
- Kazakhstan: `kz.servers.aurora.ru:1242`

**Verdict**: This is security theater. A trivial offset does not protect credentials. Any analyst can decode these values in seconds. This creates a false sense of security while not providing actual protection.

---

### 2. MEDIUM: Anti-Tampering with Account Termination

**Severity**: MEDIUM
**Category**: User-hostile security mechanism
**Files**: `background.js` (lines 179-223)

**Description**:
The extension implements anti-tampering logic that detects if users manipulate the `remainingMs` storage value to extend free trial time. If detected, the extension forcibly logs out the user, disconnects the VPN, and resets their free time to zero.

**Evidence**:
```javascript
// Lines 179-188 in restoreConnectionState()
if (remainingMs !== null && remainingMs > 3600100) {
  // Отключить VPN
  if (isConn) {
    await clearProxy();
  }
  // Выбросить из аккаунта
  await chrome.storage.local.remove([STORAGE_KEYS.loggedInUser,
    STORAGE_KEYS.subscriptionActive, STORAGE_KEYS.subscriptionExpires]);
  // Сбросить remainingMs до 0
  await chrome.storage.local.set({ [STORAGE_KEYS.remainingMs]: 0 });
}

// Lines 211-222 in getRemainingMs()
if (ms > 3600100) {
  ms = 0;
  await chrome.storage.local.set({ [STORAGE_KEYS.remainingMs]: ms });
  // Выбросить из аккаунта
  await chrome.storage.local.remove([STORAGE_KEYS.loggedInUser,
    STORAGE_KEYS.subscriptionActive, STORAGE_KEYS.subscriptionExpires]);
  // Отключить VPN напрямую
  if (connected) {
    await clearProxyDirect();
  }
}
```

**Verdict**: While preventing abuse is understandable, forcibly terminating user accounts without warning creates a hostile user experience. This mechanism could also trigger false positives if time synchronization issues or browser bugs cause the `remainingMs` value to become corrupted. Users should be warned rather than immediately punished.

---

### 3. MEDIUM: Insecure Authentication Flow

**Severity**: MEDIUM
**Category**: Credential transmission over insecure channel
**Files**: `background.js` (lines 749-809)

**Description**:
User credentials (username/password) are transmitted to `https://aurora-vpn.ru/services/` endpoints without additional encryption or security measures beyond HTTPS. Session tokens and device identifiers are transmitted in plaintext.

**Evidence**:
```javascript
// Login handler (lines 775-809)
chrome.runtime.sendMessage({ type, username, password }, (res) => {
  // ...
});

// Backend sends credentials
const resp = await fetch(`${API_BASE}/login.php`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username, password })
});
```

**Additional Concerns**:
1. No client-side password hashing before transmission
2. No CSRF protection tokens visible
3. Registration endpoint accepts passwords as short as 5 characters (line 755)
4. Username/password validation only checks minimum length, no complexity requirements

**Verdict**: While HTTPS provides transport encryption, the lack of additional security measures (hashing, strong password requirements, CSRF protection) creates vulnerability to credential stuffing, brute force, and session hijacking attacks if the server-side implementation is weak.

---

### 4. LOW: IP Whitelisting with Hardcoded Secret Token

**Severity**: LOW
**Category**: Weak secret management
**Files**: `background.js` (lines 28, 370-411)

**Description**:
The extension uses a hardcoded "secret token" for authenticating requests to the IP whitelisting endpoint. This token is visible in the source code.

**Evidence**:
```javascript
const AURORA_EXT_S_TOKEN = 'aurora-vpn-extension-secret-token';

// Used in API calls
const resp = await fetch(API_SET_ENDPOINT, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'aurora-ext-s': AURORA_EXT_S_TOKEN  // Line 374
  },
  body: JSON.stringify(requestBody),
  signal: ac.signal
});
```

**Verdict**: This appears to be a shared secret across all extension installations. While it may prevent casual abuse of the API endpoint, it provides minimal security since the token is embedded in every copy of the extension. An attacker could extract this token and make API calls directly.

---

### 5. LOW: DevTools Blocking in Popup

**Severity**: LOW
**Category**: Anti-debugging / User control restriction
**Files**: `popup.js` (lines 1350-1365)

**Description**:
The extension actively blocks developer tools access in the popup by preventing context menu, F12, and common DevTools shortcuts.

**Evidence**:
```javascript
// Security UX: disable context menu and common DevTools shortcuts within popup
try {
  window.addEventListener('contextmenu', (e) => e.preventDefault());
  window.addEventListener('keydown', (e) => {
    const ctrlOrMeta = e.ctrlKey || e.metaKey;
    const blocked = (
      e.key === 'F12' ||
      (ctrlOrMeta && e.shiftKey && ['I','J','C'].includes(e.key.toUpperCase())) ||
      (ctrlOrMeta && e.key.toUpperCase() === 'U')
    );
    if (blocked) {
      e.preventDefault();
      e.stopPropagation();
    }
  }, true);
} catch (_) {}
```

**Verdict**: While potentially intended to prevent users from accidentally breaking the UI, this is an anti-pattern that prevents legitimate debugging and inspection. It serves no real security purpose since the background page and manifest are still accessible, and sophisticated attackers can bypass these restrictions trivially.

---

### 6. LOW: Session Tracking and Device Fingerprinting

**Severity**: LOW
**Category**: Privacy concern
**Files**: `background.js` (lines 58-76, 846-878)

**Description**:
The extension generates persistent device IDs and uninstall tokens that are used to track sessions across browser restarts. User agent and IP addresses are collected and sent to the backend.

**Evidence**:
```javascript
async function getOrCreateDeviceId() {
  const data = await chrome.storage.local.get(STORAGE_KEYS.deviceId);
  let id = data[STORAGE_KEYS.deviceId];
  if (typeof id !== 'string' || id.length < 8) {
    id = crypto.randomUUID ? crypto.randomUUID() :
         'x' + Date.now().toString(36) + Math.random().toString(36).slice(2);
    await chrome.storage.local.set({ [STORAGE_KEYS.deviceId]: id });
  }
  return id;
}

// Session registration (lines 860-867)
body: JSON.stringify({
  username,
  device_id: deviceId,
  ip: ip || null,
  user_agent: user_agent || null,
  uninstall_token: uninstallToken
})
```

**Verdict**: This is standard practice for multi-device session management in modern applications. The extension transparently tracks devices for legitimate purposes (allowing users to see and terminate sessions on other devices). However, users should be aware that their device fingerprint, IP, and user agent are being collected and stored server-side.

---

### 7. LOW: Uninstall Tracking URL

**Severity**: LOW
**Category**: Tracking
**Files**: `background.js` (lines 53, 78-92)

**Description**:
When a user uninstalls the extension, they are redirected to a tracking URL that includes their uninstall token, allowing the backend to clean up sessions and potentially collect uninstall analytics.

**Evidence**:
```javascript
const UNINSTALL_PAGE_URL = 'https://aurora-vpn.ru/pleasewait';

function setUninstallUrlForSessionCleanup(uninstallToken) {
  try {
    const url = 'https://aurora-vpn.ru/services/api/sessions_uninstall.php?token=' +
                encodeURIComponent(uninstallToken);
    chrome.runtime.setUninstallURL(url);
  } catch (e) { /* ignore */ }
}
```

**Verdict**: This is a standard Chrome extension capability. The tracking allows the backend to clean up abandoned sessions, which is legitimate. However, users should be aware they are being tracked even during uninstallation.

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `fetch()` calls to `ip-api.com` | background.js:289, 353 | Legitimate geolocation lookup for displaying server location to user |
| Proxy configuration | background.js:413-469 | Core VPN functionality - configures SOCKS5 proxy via PAC script |
| Storage API usage | All files | Standard extension state management - no evidence of exfiltration |
| Content script on `aurora-vpn.ru` | content-script.js | Only injects user profile data into own domain for support widget integration |
| Chrome alarm API | background.js:24, 483, 992-998 | Used for free trial timer - legitimate time-based disconnection |

---

## API Endpoints Summary

### Primary Backend
- **Base**: `https://aurora-vpn.ru/services/`
- **Endpoints**:
  - `register.php` - User registration
  - `login.php` - User authentication
  - `subscription.php` - Check subscription status
  - `activate_license.php` - Activate premium license key
  - `api/set.php` - IP whitelisting (requires secret token)
  - `api/get_ip.php` - Fetch user's current IP
  - `api/sessions_register.php` - Register new device session
  - `api/sessions_list.php` - List all user sessions
  - `api/sessions_terminate.php` - Terminate specific session
  - `api/sessions_uninstall.php` - Cleanup on uninstall

### Third-party Services
- **ip-api.com** - Geolocation service (HTTP, not HTTPS)
- **aurora-vpn.ru/aurora_support_chat/api/security.php** - User existence check
- **aurora-vpn.ru/aurora_support_chat/proxy_monitor/api/proxy_servers_status.php** - Server health check
- **aurora-vpn.ru/aurora_support_chat/proxy_monitor/api/proxy_servers_best.php** - Auto-select fastest server

### SOCKS5 Proxy Servers
All on subdomain `servers.aurora.ru` ports 1234-1242:
- `nl.servers.aurora.ru:1234` (Netherlands)
- `de.servers.aurora.ru:1235` (Germany)
- `am.servers.aurora.ru:1236` (Armenia)
- `se.servers.aurora.ru:1237` (Sweden)
- `tr.servers.aurora.ru:1238` (Turkey)
- `us.servers.aurora.ru:1239` (USA)
- `ee.servers.aurora.ru:1240` (Estonia)
- `ch.servers.aurora.ru:1241` (Switzerland)
- `kz.servers.aurora.ru:1242` (Kazakhstan)

---

## Data Flow Summary

### On Installation/Update
1. Extension clears proxy settings and resets connection state
2. Generates persistent `deviceId` (UUID) and `uninstallToken` if not present
3. Sets uninstall redirect URL
4. Initializes free time (1 hour = 3,600,000 ms)
5. Auto-detects browser language (English vs Russian)

### On User Login
1. Frontend sends `{username, password}` to `/login.php`
2. Backend validates credentials and returns success/failure
3. If successful, extension fetches subscription status from `/subscription.php`
4. Extension registers device session with backend (sends deviceId, IP, user agent, uninstallToken)
5. Backend assigns session token for uninstall cleanup

### On VPN Connection
1. If subscription is inactive, check if free time remains (> 0 ms)
2. Extension fetches user's current IP from `ip-api.com` (HTTP)
3. Extension whitelists user's IP on all proxy servers via `/api/set.php` (requires secret token)
4. Extension decodes obfuscated server credentials for selected region
5. Extension configures browser proxy to SOCKS5 server via PAC script
6. Extension starts countdown timer if on free tier
7. Every minute, extension checks server health status

### On VPN Disconnection
1. Extension calculates elapsed time since `sessionStart`
2. If on free tier, deducts elapsed time from `remainingMs`
3. Extension updates `trafficUsed` and `totalActiveMs` statistics
4. Extension clears browser proxy settings
5. Extension persists state to `chrome.storage.local`

### On Uninstall
1. Browser redirects to `https://aurora-vpn.ru/services/api/sessions_uninstall.php?token={uninstallToken}`
2. Backend receives request and terminates associated session
3. User lands on feedback page `https://aurora-vpn.ru/pleasewait`

---

## Overall Risk Assessment

### Risk Level: MEDIUM

**Justification**:

**Positive Aspects**:
1. Extension performs its stated function as a VPN service
2. No evidence of ad injection, cookie theft, or keylogging
3. No dynamic code loading or remote script execution
4. Limited permissions (proxy, storage, alarms - appropriate for VPN)
5. Transparent session management with user-visible device list
6. Content script only runs on own domain for legitimate purpose

**Security Concerns**:
1. **Credential obfuscation** creates false sense of security
2. **Anti-tampering mechanism** is user-hostile and could cause false positives
3. **Weak authentication** requirements (5-char passwords, no hashing)
4. **Hardcoded secret token** provides minimal API protection
5. **DevTools blocking** prevents user inspection and debugging
6. **HTTP endpoint** for IP geolocation (ip-api.com) is unencrypted

**Privacy Concerns**:
1. Device fingerprinting via persistent UUID
2. Collection of IP addresses and user agents
3. Uninstall tracking
4. All user activity metadata sent to Russian-hosted backend

**Recommendations**:
1. Remove character offset obfuscation - it provides no security benefit
2. Replace account termination with warnings for suspected tampering
3. Implement client-side password hashing before transmission
4. Use dynamic API tokens instead of hardcoded shared secret
5. Remove DevTools blocking code
6. Migrate IP geolocation to HTTPS endpoint or use alternative service
7. Clearly disclose data collection practices in privacy policy
8. Consider implementing E2E encryption for sensitive user data

---

## Verdict

**MEDIUM RISK**

Aurora VPN is a **functional VPN extension** that serves its intended purpose without engaging in outright malicious behavior. However, it implements several **security-hostile and privacy-invasive practices** that create risk for users:

1. ✅ **No malware**: No evidence of keylogging, ad injection, cookie theft, or data exfiltration beyond expected VPN functionality
2. ⚠️ **Invasive but legitimate**: Device tracking, IP collection, and uninstall monitoring serve legitimate product purposes but raise privacy concerns
3. ❌ **Poor security practices**: Credential obfuscation theater, weak password requirements, hardcoded secrets, and anti-debugging measures
4. ⚠️ **User-hostile**: Anti-tampering that forcibly logs out users without warning

The extension would be rated **LOW** risk if the security practices were improved. As-is, the combination of weak authentication, obfuscation theater, and user-hostile anti-tampering justifies a **MEDIUM** rating.

Users concerned about privacy should note that all traffic metadata (IPs, device fingerprints, connection logs) are sent to a Russian-hosted backend, which may have different data protection standards than EU/US jurisdictions.
