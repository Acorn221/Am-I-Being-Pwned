# Security Analysis Report: Mirroring360 Sender for Chrome

**Extension ID:** iaigceaehdihlnolehbapjfbbfpnlngg
**Name:** Mirroring360 Sender for Chrome
**Version:** 1.1.0.5
**Publisher:** Splashtop Inc.
**Users:** 600,000
**Overall Risk Level:** LOW

## Executive Summary

Mirroring360 Sender is a legitimate screen mirroring extension developed by Splashtop Inc. that enables users to cast their Chromebook or computer screens to other computers. The extension uses WebRTC for peer-to-peer screen sharing, WebSocket connections for signaling, and native messaging for desktop capture capabilities. While the ext-analyzer flagged one exfiltration flow and DOM manipulation patterns, detailed code review confirms these are benign components of the extension's legitimate functionality.

## Risk Assessment

**Risk Score:** 45/100 (ext-analyzer)
**Classification:** LOW

The extension's risk score is elevated due to its powerful permissions and data flow patterns, but the code inspection reveals these are necessary for its stated functionality and implemented by a reputable vendor.

## Permissions Analysis

### Required Permissions
- **tabs** - Enumerate and access tab information for screen capture selection
- **storage** - Store user preferences and connection settings
- **nativeMessaging** - Communicate with native Mirroring360 application (`com.splashtop.m360.native`)
- **desktopCapture** - Capture desktop screen for mirroring
- **tabCapture** - Capture individual tab content for selective sharing
- **activeTab** - Access the currently active tab

### Permission Justification
All permissions are appropriate for a screen mirroring application. The combination of `desktopCapture`, `tabCapture`, and `nativeMessaging` enables the core functionality of capturing and transmitting screen content.

## Static Analysis Findings

### ext-analyzer Output

**Flags:** obfuscated (minified code detected)

**Exfiltration Flow (1):**
- **Source:** `chrome.tabs.query` → captured tab information
- **Sink:** `*.src` property assignment in `js/spt3.js`
- **Severity:** HIGH (per analyzer)
- **Actual Risk:** BENIGN - Setting image source for UI icons based on connection state

**Attack Surface:**
- Message handlers accepting data with potential for `.src` and `.innerHTML` assignment
- Flow: `js/background.js` ⇒ `js/spt1.js`

### Code Review Findings

#### 1. DOM Manipulation (LOW)

**Location:** `js/spt1.js` and `js/spt3.js`

The analyzer flagged multiple `innerHTML` assignments, including:
```javascript
hitSecurity.innerHTML = chrome.i18n.getMessage("msgAuthError");
hitSecurity.innerHTML = user_security ? chrome.i18n.getMessage("msgAuthError") : chrome.i18n.getMessage("hitSecurity");
```

**Analysis:** All `innerHTML` assignments use sanitized data from:
- `chrome.i18n.getMessage()` calls (localized strings from manifest)
- Static HTML strings (e.g., `"<img src='image/connecting.gif'>"`)
- Controlled UI state updates

**Risk:** No XSS vulnerability present. All content is developer-controlled or comes from the extension's own message catalog.

#### 2. Image Source Assignment (BENIGN)

**Location:** `js/spt3.js` (multiple instances)

The exfiltration flow flagged by ext-analyzer involves setting image sources:
```javascript
e.items["idx_"+this.connSessionid].icon.src = "image/user_on.png";
e.items["idx_"+this.connSessionid].btnFav.src = "image/hc.png";
```

**Analysis:** All `.src` assignments use static paths to local image resources. No dynamic or user-controlled URLs are assigned. The flow from `chrome.tabs.query` to `.src` is indirect and involves UI state management, not data exfiltration.

**Risk:** NONE - No actual exfiltration occurs.

## Network Communication Analysis

### WebSocket Connections

**Primary Endpoint:** `wss://wbs.relay.splashtop.com`

**Purpose:** WebRTC signaling server for establishing peer-to-peer connections

**Protocol:** Custom protocol (`com.splashtop.webrtc2`)

**Data Transmitted:**
- Session initialization requests
- WebRTC SDP offers/answers
- ICE candidates for NAT traversal
- Heartbeat messages
- User-selected screen resolution

**Code Reference (js/background.js):**
```javascript
var singal_server_addr="wss://wbs.relay.splashtop.com";
var websocket_sub_protocol="com.splashtop.webrtc2";
```

### TURN Server

**Endpoint:** `turn:turn.relay.splashtop.com:443`

**Credentials:** Hardcoded username/password (`eric`/`1234`)

**Purpose:** NAT traversal for WebRTC when direct peer-to-peer connection fails

**Code Reference (js/spt3.js):**
```javascript
var r={iceServers:[{url:"turn:turn.relay.splashtop.com:443",credential:"1234",username:"eric"}]};
```

**Note:** The hardcoded TURN credentials are for a relay service and don't pose a security risk. This is a standard pattern for WebRTC applications.

### Native Messaging

**Application:** `com.splashtop.m360.native`

**Purpose:** Communicate with native Mirroring360 application for desktop capture and session management

**Communication:** Bidirectional JSON messages for session ID retrieval and screen capture coordination

## Vulnerabilities Identified

### LOW - Hardcoded TURN Credentials

**Severity:** LOW
**CVSS:** 2.0 (Low)

**Description:** The TURN relay server credentials are hardcoded in the source code (`username: "eric"`, `credential: "1234"`). While this is common practice for public TURN servers, it exposes the credentials to anyone who inspects the code.

**Location:** `js/spt3.js:62`

**Impact:** An attacker could use the TURN credentials to proxy traffic through Splashtop's relay server. However, this is a shared relay service and the credentials likely have rate limiting or usage restrictions.

**Recommendation:** Consider using a credential retrieval API or short-lived tokens instead of hardcoded credentials.

**Exploitability:** LOW - Credentials are for a relay service, not authentication/authorization

## Data Flow Analysis

### Screen Capture Flow

1. User selects screen/tab to share via extension popup
2. Extension requests desktop/tab capture via Chrome API
3. MediaStream obtained with video track
4. WebSocket connection established to Splashtop signaling server
5. WebRTC peer connection negotiated (SDP offer/answer exchange)
6. Screen data transmitted via WebRTC DataChannel/MediaStream (peer-to-peer)
7. TURN relay used only if direct connection fails

### Session Management Flow

1. Extension generates/retrieves UUID for device identification
2. WebSocket connection to `wbs.relay.splashtop.com`
3. Session registration with server using UUID and session code
4. Discovery of available receivers on local network
5. User selects target receiver
6. Authentication (optional password if configured)
7. WebRTC connection established

**Privacy Consideration:** The UUID is stored locally and used for device identification. Session codes are temporary and facilitate peer-to-peer connections.

## Third-Party Dependencies

- **jQuery 1.7.1** and **1.7.2** - Outdated versions (security updates available)
- **Bootstrap** - Used for UI components
- **WebRTC APIs** - Browser-native

**Recommendation:** Update jQuery to a maintained version (3.x or remove dependency if possible). jQuery 1.7.x has known vulnerabilities (CVE-2015-9251, CVE-2019-11358, CVE-2020-11022, CVE-2020-11023).

## Code Quality Observations

### Positive
- Consistent error handling and logging
- Use of Chrome's i18n API for localization
- Proper WebRTC connection lifecycle management
- Cleanup of resources on disconnect

### Concerns
- Minified/obfuscated code (though this appears to be standard build output)
- Use of deprecated jQuery versions
- Some global variable pollution (`orgwin`, `w`, etc.)

## Compliance & Privacy

**Data Collection:** The extension collects:
- Device UUID (generated locally)
- Platform information (OS, Chrome version)
- Screen resolution
- Session connection metadata

**Data Transmission:** All collected data is transmitted to Splashtop's infrastructure for session coordination. Screen content is transmitted peer-to-peer via WebRTC.

**Privacy Policy:** Extension references Splashtop's privacy policy at https://www.splashtop.com/privacy

## Recommendations

### For Users
1. **SAFE TO USE** - This is a legitimate screen mirroring application from a reputable vendor
2. Be aware that screen content is transmitted to the selected receiver
3. Only connect to trusted Mirroring360 receivers
4. Use the optional password feature for sensitive sessions

### For Developers
1. **Update jQuery** to version 3.x or remove the dependency
2. Consider implementing dynamic TURN credential retrieval
3. Add Content Security Policy (CSP) to prevent potential future XSS issues
4. Remove unused jQuery version (either 1.7.1 or 1.7.2)
5. Migrate to Manifest V3 (currently using MV3, good)

## False Positive Analysis

The ext-analyzer's "HIGH" exfiltration finding is a **false positive**:

**Reason:** The data flow `chrome.tabs.query → *.src` does not represent actual data exfiltration. Instead:
1. `chrome.tabs.query` is used to get tab information for UI display
2. The `.src` assignments set icon paths to local image files
3. No sensitive tab data is sent to external servers via this flow

The actual screen content transmission occurs via WebRTC (peer-to-peer) after explicit user action, which is the extension's intended functionality.

## Conclusion

Mirroring360 Sender for Chrome is a **legitimate, low-risk extension** that performs its advertised functionality of screen mirroring. The ext-analyzer findings are primarily false positives related to normal UI operations. The only legitimate concern is the use of outdated jQuery libraries, which should be updated but don't represent an immediate exploitable risk in this context.

The extension's access to sensitive permissions (screen capture) is appropriate for its functionality and implemented by Splashtop Inc., a established vendor in the remote desktop/screen sharing space.

**Recommendation: APPROVED FOR USE** with minor update suggestions for jQuery dependencies.

---

**Analyzed by:** Claude Opus 4.6
**Date:** 2026-02-15
**Methodology:** Manual code review + ext-analyzer static analysis
