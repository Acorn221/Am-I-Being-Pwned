# Security Analysis Report: VPNCity Chrome Extension

## Extension Metadata
- **Extension ID**: nnpnnpemnckcfdebeekibpiijlicmpom
- **Name**: VPNCity - Fast & Unlimited VPN | Unblocker
- **Version**: 2.2.2
- **Author**: Think Huge Ltd
- **User Count**: ~0 users
- **Description**: VPNCity - Fast, Secure & Unlimited VPN | Unblock Sites

## Executive Summary

**Overall Risk Level: CLEAN**

VPNCity is a legitimate VPN/proxy extension that provides HTTPS proxy routing through VPNCity-controlled servers. The extension implements standard VPN functionality including proxy configuration, authentication, IP checking, and location selection. While it requires broad permissions typical of VPN extensions and communicates extensively with its backend servers, the code is transparent, serves its stated purpose, and shows no evidence of malicious behavior or significant security vulnerabilities.

The extension has minimal user adoption (0 users) and appears to be either newly published or a test/development version. The code quality is reasonable with clear functionality boundaries.

## Detailed Findings

### 1. Manifest Analysis

**Permissions Requested:**
- `alarms` - Used for periodic timeout checking (free tier disconnection)
- `offscreen` - Creates offscreen document to trigger proxy authentication events
- `privacy` - Controls WebRTC IP leak prevention settings
- `proxy` - Core VPN functionality - configures browser proxy settings
- `storage` - Stores user credentials, settings, and preferences
- `webRequest` - Handles proxy authentication for outgoing requests
- `webRequestAuthProvider` - Provides credentials for authenticated proxy connections

**Host Permissions:**
- `https://www.vpncity.com/` - API communication
- `<all_urls>` - Required for proxy functionality to intercept all traffic

**Content Security Policy:** Not explicitly defined (uses default Manifest V3 CSP)

**Verdict:** Permissions are appropriate and necessary for VPN proxy functionality. The `<all_urls>` permission is required for proxy operation and is standard for VPN extensions.

---

### 2. Background Service Worker Analysis (`js/service_worker.js`)

**Key Functionality:**

#### Proxy Configuration
- Dynamically discovers available proxy ports (3129, 973, 1993, 5230, 16352, 28332) by testing connectivity
- Configures browser proxy using `chrome.proxy.settings.set()` with HTTPS scheme
- Validates proxy hosts against whitelist pattern: `/^[a-z0-9-]*\.vpncity\.com$/`
- Implements WebRTC leak protection via `chrome.privacy.network.webRTCIPHandlingPolicy`

#### Authentication Handling
- Listens to `chrome.webRequest.onAuthRequired` events to provide proxy credentials
- Retrieves stored credentials from `chrome.storage.sync`
- Uses offscreen document workaround for Chrome bug where `onAuthRequired` doesn't trigger for extension-originated requests

#### Connection Management
- Handles connect/disconnect messages from popup UI
- Implements timeout checking for free-tier users (10-minute sessions)
- Auto-disconnects free users after session expiry
- Updates extension badge and icon based on connection state

**Network Endpoints:**
- `https://*.vpncity.com:*` - Proxy server connections (port discovery)
- `https://www.vpncity.com/api/session/ipcheck` - IP address verification
- `https://proxy-logout.vpncity.com` - Logout signal endpoint
- `https://go.vpncity.com/chrome-extension-success-installation` - Post-install redirect
- `https://blog.vpncity.com/vpncity-and-the-cyberhaven-security-incident-*` - Security incident notification (v2.0.1 upgrade)

**Verdict: CLEAN** - Standard VPN proxy implementation. Host validation prevents proxy hijacking. Authentication handling is appropriate. No suspicious behavior detected.

---

### 3. Content Script Analysis (`js/warning.js`)

**Injection Scope:** `<all_urls>` (all websites)

**Functionality:**
- Injects a banner notification on web pages when using free-tier VPN connection
- Displays countdown timer showing remaining connection time
- Shows "Protected" or "Not Protected" status
- Includes "Unlimited Access" CTA button linking to upgrade page
- Banner only appears when: connected AND using free proxy AND not on vpncity.com

**DOM Manipulation:**
- Creates overlay banner with inline styles
- Appends to `document.body`
- User can dismiss banner (removes from DOM, clears interval)

**Data Access:**
- Reads from `chrome.storage.sync`: `disconnectAt`, `connected`, `free_proxy`
- No data exfiltration or keystroke monitoring
- No interaction with page content or form fields

**Verdict: CLEAN** - Simple notification banner for free users. Does not harvest data or interfere with page functionality. This is legitimate functionality to encourage upgrades.

---

### 4. Popup UI Analysis (`js/vpncity.js`)

**Functionality:**
- User authentication (login/signup) via VPNCity API
- Location selection from 60+ VPN server locations
- Connection/disconnection controls
- IP address verification display
- Account management (logout, upgrade checking)

**API Endpoints:**
```
POST https://www.vpncity.com/api/account/login
POST https://www.vpncity.com/api/account/register
GET  https://www.vpncity.com/api/locations
POST https://www.vpncity.com/api/account/checkupgrade
GET  https://www.vpncity.com/api/session/ipcheck (via offscreen worker)
```

**Data Handling:**
- Stores credentials as `username:token` in `chrome.storage.sync`
- Stores user ID, connection timeouts, location preferences
- Validates email format client-side
- Transmits login credentials over HTTPS
- Session management with connection time limits for free tier

**External Redirects:**
- Upgrade pages: `go.vpncity.com/chrome-extension-unlimited?userid=*`
- Referral program: `www.vpncity.com/page/refer-friend/*`
- Post-registration success: `go.vpncity.com/chrome-extension-success-registration`
- Uninstall feedback: `go.vpncity.com/chrome-extension-feedback`

**Verdict: CLEAN** - Standard account management and VPN control interface. Credentials transmitted securely over HTTPS. No suspicious data collection beyond what's necessary for service operation.

---

### 5. Offscreen Document & Worker Pattern

**Architecture:**
The extension uses a workaround for a Chrome limitation:
- Service worker creates offscreen document (`offscreen.html`)
- Offscreen document spawns web worker (`js/worker.js`)
- Service worker posts messages to offscreen document
- Offscreen document forwards to web worker
- Web worker makes fetch request (triggers `onAuthRequired` properly)
- Response bubbles back up the chain

**Purpose:** Ensures `webRequest.onAuthRequired` fires for extension-originated requests (Chrome bug workaround)

**Security Analysis:**
- Worker only accepts URL strings via `postMessage`
- Worker performs fetch to provided URL (potential SSRF risk, but controlled by service worker)
- Service worker only passes `https://www.vpncity.com/api/session/ipcheck`
- No arbitrary code execution or eval usage

**Verdict: CLEAN** - Legitimate workaround for Chrome API limitation. Input is controlled and hardcoded.

---

### 6. Dynamic Code Execution Analysis

**jQuery Library:**
- Uses jQuery 3.3.1 (minified)
- Contains standard jQuery `_evalUrl` function for loading external scripts via `$.getScript()`
- This function is NOT used anywhere in the extension code
- No dynamic script loading detected

**Eval/Function Usage:**
- No `eval()` calls found in custom code
- No `new Function()` usage
- No `setTimeout`/`setInterval` with string arguments
- All code is static

**Verdict: CLEAN** - No dynamic code execution. jQuery library present but eval functions unused.

---

## False Positive Analysis

| Pattern | Location | Context | Why It's Safe |
|---------|----------|---------|---------------|
| `fetch()` | Multiple files | API communication | All endpoints are legitimate VPNCity domains over HTTPS |
| `chrome.tabs.create()` | service_worker.js, vpncity.js | Post-install, upgrade, referral pages | Opens known VPNCity URLs for legitimate purposes |
| `postMessage` | offscreen.js, worker.js | Worker communication | Controlled internal messaging for IP check functionality |
| `innerHTML` | warning.js | Banner injection | Hardcoded HTML string for notification banner, no user input |
| `<all_urls>` permission | manifest.json | Content script & proxy | Required for VPN proxy operation, minimal content script usage |
| jQuery eval | jquery-3.3.1.min.js | Library function | Standard jQuery, `_evalUrl` not invoked by extension |

---

## Data Flow Summary

### Data Stored Locally:
- User credentials (`username:token`)
- User ID
- Current location selection
- Connection state and timeout values
- Location cache
- Favourite locations
- Free/premium tier status
- Upgrade check timestamps

### Data Transmitted to VPNCity Servers:
- User email and password (during login/registration)
- User ID in API requests
- Connection state (implicit via proxy usage)
- IP check requests

### Data Exposed via Proxy:
- **All browser HTTP/HTTPS traffic** when connected - routed through VPNCity proxy servers
- This is expected and documented VPN behavior

---

## API Endpoints Table

| Endpoint | Method | Purpose | Data Sent | Risk |
|----------|--------|---------|-----------|------|
| www.vpncity.com/api/account/login | POST | User authentication | email, password | Low - HTTPS encrypted |
| www.vpncity.com/api/account/register | POST | Account creation | email, password | Low - HTTPS encrypted |
| www.vpncity.com/api/locations | GET | Server list retrieval | None | Low - Public data |
| www.vpncity.com/api/session/ipcheck | GET | IP verification | None | Low - Anonymous |
| www.vpncity.com/api/account/checkupgrade | POST | Check upgrade status | username | Low - Non-sensitive |
| proxy-logout.vpncity.com | GET | Logout signal | None | Low - Anonymous |
| *.vpncity.com:* | CONNECT | Proxy connections | All traffic | Expected - VPN function |
| go.vpncity.com/* | GET (redirect) | Marketing pages | userid in URL | Low - User-initiated |

---

## Privacy Analysis

**What the extension collects:**
- Email address (for account management)
- Browsing traffic metadata (when connected via proxy)
- Connection duration and timing
- Selected VPN locations

**What it does NOT collect:**
- Keystrokes or form data
- Cookies from other sites
- Browsing history beyond active connections
- Credentials for other services
- Personal files or downloads

**User Transparency:**
- Privacy policy referenced in consent screen
- Clear indication of connection status
- Free tier time limits disclosed in UI
- Data collection limited to service operation

---

## Security Concerns & Mitigations

### Potential Concerns:

1. **Broad `<all_urls>` permission**
   - **Mitigation:** Required for proxy functionality. Content script only injects notification banner.

2. **Credentials stored in sync storage**
   - **Risk:** Credentials synced across devices in plaintext (Chrome encrypts sync data)
   - **Mitigation:** Uses authentication tokens, not raw passwords

3. **All traffic routed through third-party servers**
   - **Risk:** VPNCity can inspect all proxied traffic (standard VPN risk)
   - **Mitigation:** Inherent to VPN service model, disclosed in service terms

4. **Offscreen document SSRF potential**
   - **Risk:** Worker accepts URL via postMessage
   - **Mitigation:** Service worker only sends hardcoded VPNCity API URL

### No Critical Vulnerabilities Found

---

## Compliance Notes

**Cyberhaven Security Incident:**
The extension references a security incident in version 2.0.1 upgrade logic:
```javascript
if (object.previousVersion === '2.0.1') {
  chrome.tabs.create({
    url: 'https://blog.vpncity.com/vpncity-and-the-cyberhaven-security-incident-...'
  });
}
```

This indicates VPNCity proactively notified users about a security incident involving "Cyberhaven." This demonstrates responsible disclosure practices.

---

## Recommendations

**For Users:**
1. ✅ Extension is safe to use for its intended purpose
2. ⚠️ Understand that all traffic is routed through VPNCity servers when connected
3. ⚠️ Review VPNCity's privacy policy regarding traffic logging
4. ✅ Free tier has 10-minute session limits with cooldown periods

**For Developers:**
1. Consider encrypting stored credentials using Web Crypto API
2. Implement certificate pinning for API endpoints
3. Add CSP directive to manifest for defense in depth
4. Consider using `chrome.storage.local` with encryption instead of sync for credentials

---

## Comparison to Malicious VPN Patterns

| Malicious Pattern | VPNCity Behavior | Status |
|-------------------|------------------|--------|
| Extension enumeration/killing | Not present | ✅ Clean |
| XHR/fetch hooking | Not present | ✅ Clean |
| Residential proxy infrastructure | Uses owned proxy servers | ✅ Legitimate |
| Remote kill switches | Not present | ✅ Clean |
| Ad/coupon injection | Only own upgrade banner | ✅ Acceptable |
| Hidden data exfiltration | No hidden exfil detected | ✅ Clean |
| Keylogging | Not present | ✅ Clean |
| Cookie harvesting | Not present | ✅ Clean |
| Credential theft | Not present | ✅ Clean |

---

## Conclusion

**RISK LEVEL: CLEAN**

VPNCity is a legitimate, transparently-implemented VPN proxy extension that functions as advertised. The code is straightforward, well-structured, and shows no signs of malicious intent or hidden functionality. All network communication is with VPNCity-owned domains over HTTPS. Permissions are appropriate for VPN functionality. Data collection is limited to what's necessary for service operation.

The extension can be considered **safe for use**, with the standard caveats that apply to all VPN services: users should trust the VPN provider with their traffic, review privacy policies, and understand that all browser traffic is routed through third-party servers when connected.

The minimal user count (0 users) suggests this may be a development or test version, but the code itself is production-quality and secure.

---

**Analysis Date:** 2026-02-08
**Analyst:** Claude Sonnet 4.5
**Analysis Methodology:** Static code analysis, permission review, network endpoint enumeration, data flow mapping
