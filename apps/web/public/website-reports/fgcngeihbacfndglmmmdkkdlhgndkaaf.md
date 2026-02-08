# Windscribe VPN - Attack Surface Analysis

**Extension:** Windscribe - Free Proxy and Ad Blocker
**Version:** 4.2.4
**Manifest:** V3
**Users:** 2M+
**Rating:** 4.3
**Analysis Date:** 2026-02-04

---

## Executive Summary

**Risk Level: LOW-MEDIUM**

Windscribe is a **legitimate VPN extension** with integrated ad-blocking via uBlock Origin Lite. The extension has a large attack surface due to broad permissions but appears to operate transparently. No evidence of malicious behavior, P2P bandwidth sharing, or excessive data collection.

---

## Permission Analysis

### Granted Permissions
| Permission | Risk | Purpose |
|------------|------|---------|
| `proxy` | Medium | Core VPN functionality via PAC scripts |
| `webRequest` | Medium | Auth handling for proxy connections |
| `webRequestAuthProvider` | Low | Supplies proxy credentials |
| `declarativeNetRequestWithHostAccess` | Medium | Ad blocking via uBlock Origin Lite |
| `scripting` | Medium | Content script injection for anti-fingerprinting |
| `storage` / `unlimitedStorage` | Low | Session and settings persistence |
| `tabs` / `activeTab` | Low | Tab state for UI and allowlisting |
| `privacy` | Medium | WebRTC leak protection |
| `notifications` | Low | User alerts |
| `management` | Low | Extension conflict detection |
| `offscreen` | Low | Background processing |
| `alarms` | Low | Scheduled tasks |
| `contextMenus` | Low | Right-click menu |

### Host Permissions
```
<all_urls>
```
Required for VPN proxy to work on all sites.

### Optional Permissions
```
contentSettings
```
For additional browser settings control.

---

## Attack Surface Map

### 1. External Communication

#### API Endpoints
```javascript
// Primary domains
windscribe.com        // Main API
totallyacdn.com       // CDN/Fallback API
dynamic-api-host.windscribe.com  // DNS-resolved dynamic endpoint
```

#### DNS-over-HTTPS Fallback
```javascript
// Uses Cloudflare DoH for API resolution if primary fails
fetch(`https://1.1.1.1/dns-query?name=${_t}&type=TXT`, {
    headers: { Accept: "application/dns-json" }
})
```
**Assessment:** Legitimate fallback mechanism for censored regions.

#### API Request Authentication
```javascript
// Client auth hash with hardcoded salt
const hash = sha256(`952b4412f002315aa50751032fcaab03${timestamp}`);
// Parameters: platform=chrome, time=timestamp, client_auth_hash=hash
```
**Assessment:** Standard API authentication.

### 2. Proxy Implementation

#### PAC Script Generation
```javascript
function FindProxyForURL(url, host) {
    const userAllowlist = [...]
    const lanIps = /(^(127|10)\.\d{1,3}\.\d{1,3}\.\d{1,3}$)|.../
    const allowlist = [
        '*://api-staging.windscribe.com/*',
        '*://api.windscribe.com/*',
        '*://assets.windscribe.com/*',
        // ... Windscribe domains excluded from proxy
    ]

    // Direct connection for: LAN IPs, plain hostnames, allowlisted
    if (shouldNotProxy) return 'DIRECT'

    // Route through proxy
    return 'HTTPS hostname:443'
}
```
**Assessment:** Clean PAC script, excludes LAN and API traffic. No suspicious routing.

### 3. Message Handlers

#### onMessage (Internal)
Handles standard commands: CSS injection, toolbar icon, custom filters.
```javascript
casesToUse = ["insertCSS", "removeCSS", "toggleToolbarIcon",
              "injectCustomFilters", "applyRulesets", ...]
```

#### onMessageExternal
Present but **NOT exploitable** - no `externally_connectable` in manifest.
External websites cannot send messages to this extension.

### 4. Code Execution Vectors

#### eval/new Function Usage
Found in polyfills only (setImmediate, globalThis detection):
```javascript
// Polyfill for setImmediate
"function" != typeof e && (e = new Function("" + e))

// globalThis polyfill
return this || new Function("return this")()
```
**Assessment:** Standard polyfill patterns, not dangerous.

#### innerHTML Usage
Found in React rendering code (popup.bundle.js):
```javascript
// React internal: dangerouslySetInnerHTML handling
if (e.namespaceURI !== he || "innerHTML" in e) e.innerHTML = t;
```
**Assessment:** React framework internals, controlled by React's sanitization.

### 5. Content Script Injection

#### Anti-Fingerprinting Scripts
```javascript
fontAntiFingerprintingScript          // Font enumeration protection
screenResAntiFingerprintingScript     // Screen resolution spoofing
canvasAntiFingerprintingScript        // Canvas fingerprint protection
audioAntiFingerprintingScript         // Audio fingerprint protection
fingerprintjsAntiFingerprintingScript // FingerprintJS blocking
```
**Assessment:** Privacy-enhancing features.

#### Warp Scripts (Location Spoofing)
```javascript
languageWarpScript    // Spoof browser language
locationWarpScript    // Spoof geolocation
timeZoneWarpScript    // Spoof timezone
```
**Assessment:** Privacy features for matching VPN location.

### 6. Privacy Features

#### WebRTC Leak Protection
```javascript
chrome.privacy.network.webRTCIPHandlingPolicy.set({
    value: "disable_non_proxied_udp"
})
```
**Assessment:** Proper WebRTC leak prevention.

#### Split Personality
```javascript
splitPersonalityScript  // User-Agent spoofing
```
**Assessment:** Anti-tracking feature.

---

## Data Collection Analysis

### What IS Collected
1. **Session data**: Login credentials (for API auth), session_auth_hash
2. **Traffic usage**: Bandwidth consumed (for quota management)
3. **Server preferences**: Selected location, allowlist settings
4. **Debug logs**: Stored locally in IndexedDB (`WS_EXT_DB`)

### What is NOT Collected
- Browsing history
- URLs visited
- DNS queries
- Personal identifiable information beyond login

### Local Storage Schema
```javascript
WS_EXT_DB: IndexedDB database
WS_STATE: Extension state in chrome.storage.local
debugLog: Debug information (local only)
```

---

## Comparison with Other VPNs

| Feature | Windscribe | Hola VPN | NordVPN |
|---------|------------|----------|---------|
| P2P Exit Node | No | YES | No |
| URL Logging | No | YES | No |
| External Telemetry | No | YES | Minimal |
| uBlock Integration | YES | No | No |
| WebRTC Protection | YES | No | YES |
| Anti-Fingerprinting | YES | No | No |
| Open Source Parts | uBlock Lite | No | No |

---

## Security Findings

### Positive Findings
1. **No P2P/bandwidth sharing** - Unlike Hola, does not use users as exit nodes
2. **Clean PAC script** - No suspicious routing rules
3. **Local debug logging** - Logs stay on device, not sent to servers
4. **Modern architecture** - Manifest V3, proper API separation
5. **Privacy-enhancing features** - Anti-fingerprinting, WebRTC protection
6. **Transparent operation** - Uses well-known API domains

### Areas of Note
1. **Broad permissions** - `<all_urls>` and `scripting` required for functionality
2. **Hardcoded auth salt** - `952b4412f002315aa50751032fcaab03` (not a security issue, just implementation detail)
3. **DNS-over-HTTPS fallback** - Uses Cloudflare 1.1.1.1 (trusted provider)

### No Critical Vulnerabilities Found
- No command injection vectors
- No XSS sinks accepting untrusted input
- No remote code execution paths
- No data exfiltration mechanisms

---

## Verdict

**LEGITIMATE EXTENSION - LOW RISK**

Windscribe operates transparently as a VPN + ad-blocker. The codebase shows professional development practices:
- Clear separation of concerns
- Well-documented Redux state management
- Integration of trusted open-source components (uBlock Origin Lite)
- Privacy-first design with anti-fingerprinting features

**Recommended for users seeking**: VPN + ad-blocking + privacy protection in a single extension.

---

## Technical Details

### File Structure
```
windscribe/
├── manifest.json (Manifest V3)
├── background.bundle.js (1.4MB beautified - main VPN logic)
├── popup.bundle.js (1.8MB beautified - React UI)
├── js/
│   ├── background.js (uBlock Origin Lite integration)
│   ├── scripting/ (content scripts)
│   └── [uBlock modules]
└── rulesets/ (ad-blocking filter lists)
```

### Dependencies
- React (UI)
- Redux (state management)
- Dexie (IndexedDB wrapper)
- crypto-js (SHA256 for auth)
- uBlock Origin Lite (ad-blocking)

---

*Analysis performed by Claude Code - 2026-02-04*
