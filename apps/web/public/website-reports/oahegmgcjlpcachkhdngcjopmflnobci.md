# Security Analysis Report: IPchanger VPN

## Extension Metadata

- **Extension Name**: IPchanger VPN: IP Proxy for Privacy & Secure
- **Extension ID**: oahegmgcjlpcachkhdngcjopmflnobci
- **Version**: 0.0.4
- **User Count**: ~0 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

IPchanger VPN is a Chrome extension that serves as a thin browser-side companion to a mandatory Windows desktop application (`com.ipchanger.plugin`). The extension requires a paid subscription and does not function independently. While the core VPN functionality appears legitimate, the extension exhibits **CRITICAL security vulnerabilities** including:

1. **Content script injection on ALL websites (including file:///)** with jQuery library
2. **Insecure HTTP endpoint for behavior tracking** exposing user activity
3. **Excessive host permissions** requesting access to all HTTP/HTTPS sites
4. **Externally connectable to Google and Baidu domains** creating potential attack surface

**Overall Risk Level: CRITICAL**

The extension injects jQuery 1.8.3 (a library from 2012 with known vulnerabilities) into every website the user visits, creating significant security risks including XSS and potential hijacking opportunities.

---

## Vulnerability Details

### 1. CRITICAL: Universal Content Script Injection with Outdated jQuery

**Severity**: CRITICAL
**File**: `manifest.json` (lines 41-46)
**CWE**: CWE-94 (Improper Control of Generation of Code)

**Description**:
The extension injects jQuery 1.8.3 into **ALL websites** at document_start, including file:/// URLs:

```json
"content_scripts": [ {
  "all_frames": true,
  "js": ["minjs/jquery-1.8.3.js"],
  "matches": [ "http://*/*", "https://*/*","file://*/*"],
  "run_at": "document_start"
}]
```

**Security Impact**:
- jQuery 1.8.3 is from 2012 and contains **multiple known XSS vulnerabilities** (CVE-2012-6708, CVE-2015-9251)
- Injecting into `all_frames: true` means every iframe is affected
- `document_start` timing allows code execution before page security mechanisms initialize
- `file:///*` access is highly unusual and allows reading local files through browser
- Creates global `$` and `jQuery` objects that can be hijacked or exploited by malicious pages
- Any website can potentially exploit the outdated jQuery to compromise the extension context

**Verdict**: This is a critical vulnerability. There is no legitimate reason to inject jQuery into every website. The content script appears to serve no purpose (no other content script functionality detected), suggesting this may be leftover from development or intentionally malicious infrastructure.

---

### 2. HIGH: Insecure HTTP Endpoint for Behavior Tracking

**Severity**: HIGH
**Files**:
- `background.js` (line 67)
- `minjs/index.js` (line 28)

**Description**:
The extension tracks user behavior and sends it to an **unencrypted HTTP endpoint**:

```javascript
// background.js
let t = "http://rz.ipchanger.net/v1/user/behavior";

// minjs/index.js (different subdomain!)
let t = "http://rz.ipchanger.321174.com/v1/user/behavior";
```

**Tracked Behaviors** (from `setBehavarr` function calls):
- Behavior code 3: VPN connection initiated
- Behavior code 4: VPN connection successful
- Behavior code 5: VPN disconnection
- Behavior code 6: VPN disconnection (duplicate code)
- Behavior code 7: Email binding
- Behavior code 204-209: Location selection (Africa, Europe, Asia, Oceania, North America, South America)
- Behavior code 401: Unknown event

**Data Transmitted**:
```javascript
{
  ip: [user's IP address],
  create_time: [timestamp],
  behavior: [behavior code],
  desc: ""
}
```

**Headers Sent**:
- `zm-uid`: User ID
- `zm-username`: Username
- `zm-device`: Operating system
- `zm-platform`: "plugin"
- `zm-version`: Version number

**Security Impact**:
- **Man-in-the-middle vulnerability**: HTTP traffic can be intercepted and modified
- **IP address exposure**: User's real IP and connected VPN IPs are transmitted in clear text
- **User profiling**: Detailed usage patterns sent to remote server
- **Inconsistent endpoints**: Two different subdomains (`rz.ipchanger.net` vs `rz.ipchanger.321174.com`) suggests infrastructure issues or domain migration, increasing risk

**Verdict**: Unacceptable for a VPN/privacy product. All tracking should use HTTPS. The dual endpoint inconsistency is also suspicious.

---

### 3. MEDIUM: Externally Connectable to Public Domains

**Severity**: MEDIUM
**File**: `manifest.json` (lines 34-39)

**Description**:
```json
"externally_connectable":{
  "ids": ["oahegmgcjlpcachkhdngcjopmflnobci"],
  "matches": ["*://*.baidu.com/*","*://*.google.com/*"]
}
```

**Security Impact**:
- Allows ANY page on `*.baidu.com` or `*.google.com` to send messages to the extension via `chrome.runtime.sendMessage`
- These are extremely broad domains with user-generated content (Google Sites, Blogger, etc.)
- An attacker could host malicious content on these platforms to communicate with the extension
- Combined with the message handler in `background.js` (line 249), external messages are forwarded to the native messaging host

**Attack Scenario**:
1. Attacker creates page on Google Sites or Baidu Tieba
2. Page sends crafted message to extension ID
3. Extension forwards to native Windows application
4. Potential for native application exploitation

**Verdict**: Overly broad. No clear business justification for allowing entire Google/Baidu domains to communicate with extension.

---

### 4. MEDIUM: Native Messaging Dependency Creates Single Point of Failure

**Severity**: MEDIUM
**File**: `background.js` (entire file)

**Description**:
The extension is entirely dependent on a native Windows application (`com.ipchanger.plugin`) for all functionality:

```javascript
chromePort = chrome.runtime.connectNative("com.ipchanger.plugin")
```

The native app controls:
- User authentication (codes 1002, 1009, 1010)
- VPN connection establishment (code 1001)
- VPN disconnection (codes 1002, 1005, 1008)
- Proxy configuration (port number, IP address)

**Security Impact**:
- Extension has `proxy` permission but delegates all control to native binary
- No validation of native app responses before applying proxy settings
- If native app is compromised, extension provides full proxy control
- Native app could route traffic through malicious servers
- Extension automatically reconnects on disconnect (line 239-241), creating persistence

**Code Analysis**:
```javascript
// No validation - blindly trusts native app's proxy configuration
var n = {
  mode: "fixed_servers",
  rules: {
    singleProxy: {
      scheme: "socks5",
      host: "127.0.0.1",  // Hardcoded localhost
      port: e.content.port  // Port from native app
    },
    bypassList: o
  }
};
chrome.proxy.settings.set({value: n, scope: "regular"}, ...);
```

**Verdict**: While native messaging dependency is standard for VPN extensions, the lack of validation and automatic reconnection is concerning. The native app is a black box that could be malicious.

---

### 5. LOW: Optional Host Permissions for All Sites

**Severity**: LOW
**File**: `manifest.json` (lines 16-19)

**Description**:
```json
"optional_host_permissions": [
  "http://*/*",
  "https://*/*"
]
```

**Security Impact**:
- Extension CAN request access to all websites (though not granted by default)
- No evidence of usage in current code
- Could be used for future expansion into ad injection, cookie harvesting, etc.

**Verdict**: Standard for VPN extensions (needed for proxy bypass rules), but should be monitored for scope creep.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `eval()` in jQuery | `minjs/jquery-1.8.3.js` | Standard jQuery parseJSON functionality (though still risky due to jQuery age) |
| `Function()` in jQuery | `minjs/jquery-1.8.3.js` | Standard jQuery event handling |
| `atob()` | `minjs/common.js:15` | Base64 decode for API responses - legitimate use |
| `chrome.tabs.create/update` | `minjs/common.js:96-98` | Opening support/payment URLs - standard extension behavior |

---

## API Endpoints & Infrastructure

| Endpoint | Protocol | Purpose | Risk |
|----------|----------|---------|------|
| `http://rz.ipchanger.net/v1/user/behavior` | HTTP | Behavior tracking | **HIGH** (unencrypted) |
| `http://rz.ipchanger.321174.com/v1/user/behavior` | HTTP | Behavior tracking (alternative) | **HIGH** (unencrypted) |
| `https://papi.ipchanger.net/` | HTTPS | API base URL | LOW |
| `https://papi.ipchanger.net/api/server/srv_rand_line_list` | HTTPS | Random server selection | LOW |
| `https://papi.ipchanger.net/api/server/srv_plugin_list` | HTTPS | Server list retrieval | LOW |
| `https://papi.ipchanger.net/api/plugin/plugin_init` | HTTPS | Extension initialization | LOW |
| `http://g.myip.top/?lang=en` | HTTP | IP address lookup | MEDIUM (external 3rd party) |
| `https://chat.roxlabs.io/chatVisitorIndex` | HTTPS | Customer support chat | LOW |
| `https://www.ipchanger.net/service-updates/59.html` | HTTPS | Tutorial/help page | LOW |
| `*.baidu.com/*` | HTTPS/HTTP | Externally connectable | MEDIUM |
| `*.google.com/*` | HTTPS/HTTP | Externally connectable | MEDIUM |

**Infrastructure Concerns**:
- Mixed HTTP/HTTPS usage
- Inconsistent behavior tracking endpoints (two different subdomains)
- Third-party IP lookup service (`g.myip.top`) over HTTP
- Hardcoded session management with custom `zm-*` headers

---

## Data Flow Summary

### Outbound Data Collection

**To `rz.ipchanger.net/321174.com` (HTTP - INSECURE)**:
- User IP addresses (current and VPN IPs)
- Timestamps of all VPN connections/disconnections
- Geographic location selections
- User ID and username
- Operating system
- Behavior event codes

**To `papi.ipchanger.net` (HTTPS - Secure)**:
- Session ID
- User ID and username
- API requests for server lists
- Device and platform information

**To `g.myip.top` (HTTP - INSECURE)**:
- Browser makes GET request to determine external IP

**To Native Application** (`com.ipchanger.plugin`):
- All user commands (connect, disconnect, server selection)
- Ping/heartbeat every 1 minute
- Extension state information

### Inbound Data

**From Native Application**:
- User authentication status
- VPN connection status
- SOCKS5 proxy port configuration
- User account details (username, email, VIP expiration)
- Connection start time

**From API Servers**:
- Available VPN server list (IPs, locations, load percentages)
- Payment/download URLs
- Bypass list for proxy exclusions
- Remote configuration

---

## Chrome API Usage Analysis

| API | Permission | Usage | Risk |
|-----|-----------|-------|------|
| `chrome.runtime.connectNative` | nativeMessaging | Connect to Windows app | MEDIUM (trusts native binary) |
| `chrome.runtime.sendMessage` | - | Communication within extension | LOW |
| `chrome.runtime.onMessage` | - | Receive messages (including external) | MEDIUM (externally connectable) |
| `chrome.proxy.settings.set` | proxy | Configure SOCKS5 proxy | LOW (standard VPN function) |
| `chrome.storage.local` | storage | Store user data, config, behavior queue | LOW |
| `chrome.alarms` | alarms | 1-min heartbeat, 5-min behavior upload | LOW |
| `chrome.tabs.create/update` | - | Open support/payment URLs | LOW |

**Notable Patterns**:
- No content script communication detected (despite jQuery injection)
- No webRequest API usage (unusual for VPN)
- No declarativeNetRequest usage
- Proxy configuration hardcoded to `127.0.0.1` (localhost tunnel)

---

## Overall Assessment

### Risk Classification: CRITICAL

**Primary Concerns**:
1. **jQuery 1.8.3 injection into ALL websites** is unjustified and creates massive attack surface
2. **Unencrypted HTTP behavior tracking** violates basic security principles for privacy tools
3. **Externally connectable to Google/Baidu** without clear business need
4. **Zero users** suggests extension may be abandoned or test deployment

### Legitimate Functionality:
- Acts as browser companion to Windows VPN application
- Configures SOCKS5 proxy through native messaging
- Provides UI for server selection
- Tracks connection time and status
- Legitimate for users who have purchased the desktop application

### Malicious Indicators:
- ❌ **Universal jQuery injection** (no legitimate purpose detected)
- ❌ **HTTP tracking endpoints** (unacceptable for privacy product)
- ⚠️ **Inconsistent tracking domains** (infrastructure red flag)
- ⚠️ **Externally connectable to broad domains**

### Recommendations:
1. **REMOVE** content script injection entirely (no usage detected)
2. **UPGRADE** all HTTP endpoints to HTTPS immediately
3. **RESTRICT** externally_connectable to specific pages/paths (not entire domains)
4. **UPDATE** jQuery to modern version if content scripts are truly needed
5. **VALIDATE** native messaging responses before applying proxy settings
6. **DOCUMENT** why `file:///*` access is requested

---

## Verdict

**CRITICAL RISK** - The extension fails basic security hygiene for a privacy-focused VPN product. The universal jQuery injection vulnerability alone warrants immediate removal from the Chrome Web Store. The use of unencrypted HTTP for tracking user behavior in a VPN product is a severe privacy violation.

While the core proxy functionality appears legitimate (delegating to a native Windows application), the security vulnerabilities and questionable design choices suggest either severe incompetence or potentially malicious infrastructure.

**Recommendation**: DO NOT INSTALL. Users seeking VPN functionality should use established, audited VPN extensions.
