# Security Analysis: PreMiD

**Extension ID**: agjnjboanicjcpenljmaaigopkgdnihi
**Name**: PreMiD
**Version**: 2.12.3
**Users**: 400,000
**Risk Level**: MEDIUM
**Date Analyzed**: 2026-02-15

---

## Executive Summary

PreMiD is a Discord Rich Presence extension that displays user activity from various websites (YouTube, Netflix, Disney+, etc.) on their Discord profile. The extension contains **2 medium-severity vulnerabilities** and **1 low-severity issue** primarily related to insecure message handler implementations and developer mode features. While the extension serves a legitimate disclosed purpose, the presence of WASM code, missing origin validation in message handlers, and a developer-mode WebSocket backdoor create potential attack surfaces.

**Overall Risk Assessment**: MEDIUM - Legitimate functionality with security implementation flaws.

---

## Vulnerability Summary

| Severity | Count | Categories |
|----------|-------|------------|
| CRITICAL | 0 | - |
| HIGH | 0 | - |
| MEDIUM | 2 | postMessage without origin check, developer backdoor |
| LOW | 1 | Analytics telemetry |

---

## Detailed Findings

### MEDIUM: Insecure postMessage Handlers

**Location**:
- `chunks/initSentry-C26_pGTm.js:34` (Sentry integration)
- `presences/Disney+/presence.js:1`

**Description**:
Two instances of `window.addEventListener("message")` are implemented without origin validation. This allows any webpage to send arbitrary messages to these handlers.

**Code Evidence**:
```javascript
// Disney+ presence handler
window.addEventListener("message", n => {
    n.data.type === "pmd-receive-image-id" && ({ imageId: u } = n.data)
});
```

**Risk**:
An attacker-controlled page could send crafted messages to manipulate extension behavior, particularly:
- Override image IDs for Disney+ presence display
- Potentially interfere with Sentry error reporting mechanisms

**Likelihood**: MEDIUM - Requires user to visit malicious page while extension is active
**Impact**: MEDIUM - Could cause display corruption or interfere with error reporting

**Recommendation**: Implement origin validation:
```javascript
window.addEventListener("message", n => {
    if (n.origin !== "expected-origin.com") return;
    // process message
});
```

---

### MEDIUM: Developer Mode WebSocket Backdoor

**Location**: `background.js` - `ActivityDevManager` class

**Description**:
The extension includes developer mode functionality that creates a WebSocket connection to `ws://localhost:3021` for live-reloading presence definitions. While this is a legitimate development feature, it remains in production code and creates potential security concerns.

**Code Evidence**:
```javascript
class Ri extends fe {
    connect() {
        try {
            this.ws = new WebSocket("ws://localhost:3021"),
            this.setupWebSocketHandlers()
        } catch(e) {
            this.log("Failed to create WebSocket connection:", e),
            this.startReconnection()
        }
    }

    async handleLocalActivity(e) {
        // Loads arbitrary presence code from WebSocket
        await this.activityController.loadLocalPresence(i, r, a, !1, c)
    }
}
```

**Risk**:
- If malware runs on the user's machine and listens on port 3021, it could inject arbitrary presence code
- The extension auto-reconnects every 5 seconds when devMode is enabled
- No authentication/validation of WebSocket messages beyond format checking

**Likelihood**: LOW - Requires devMode to be enabled AND malicious localhost service
**Impact**: MEDIUM - Could inject arbitrary code execution within extension context

**Recommendation**:
- Remove developer mode from production builds
- Implement cryptographic signing/verification of development payloads
- Add authentication tokens for local development server

---

### LOW: Analytics and Telemetry

**Endpoints**:
- `pd.premid.app` (main API)
- `premid.app` (website)

**Description**:
The extension collects analytics via heartbeat requests every 5 minutes including:
- Active services/websites being tracked
- Extension enabled status
- Premium subscription status
- User language
- Platform information (OS, architecture, user agent)
- Unique analytics ID

**Code Evidence**:
```javascript
async getHeartbeatData() {
    return {
        identifier: this.analyticsId,
        activities: i,
        activeActivity: e,
        extension: {
            enabled: c?.enabled ?? !0,
            userscripts: n ?? !1,
            premium: d?.billingInterval ?? void 0,
            language: u,
            version: v.runtime.getManifest().version,
            connected: o
        },
        platform: {
            agent: navigator.userAgent,
            os: r.os,
            arch: r.arch
        }
    }
}
```

**Risk**:
Telemetry collection appears disclosed in the extension's core functionality (Discord Rich Presence requires server communication). However, detailed browsing patterns are shared with the service.

**Likelihood**: HIGH - Analytics active for all users
**Impact**: LOW - Expected behavior for Discord integration, though privacy-sensitive

**Recommendation**: Ensure privacy policy clearly discloses all data collection practices.

---

## Technical Architecture

### Core Functionality

PreMiD operates as a bridge between websites and Discord:

1. **Content Scripts** inject into all websites (`<all_urls>`)
2. **Presence Definitions** (bundled for YouTube, Netflix, Disney+, Twitch, SoundCloud) monitor page activity
3. **Background Service** aggregates presence data and communicates with Discord
4. **WebSocket/API Communication** with Discord servers via headless sessions

### Permission Analysis

| Permission | Justification | Risk |
|------------|---------------|------|
| `tabs` | Track active tabs for presence | Expected |
| `storage`, `unlimitedStorage` | Store presence configs, settings | Expected |
| `scripting` | Inject presence code into pages | Expected |
| `idle` | Pause presence when idle | Expected |
| `userScripts` | Isolated execution (MV3) | Expected |
| `*://*/*` (host) | Monitor all websites | **Broad but necessary** |

**Host Permission Scope**: The `*://*/*` permission is required for the extension's core purpose (detecting activity on arbitrary websites), making it expected but inherently powerful.

---

## WASM Analysis

**Finding**: Extension contains WebAssembly code (detected by ext-analyzer)

**Context**: WASM presence is confirmed but specific usage not immediately clear from deobfuscated code. Likely related to:
- Image processing for presence thumbnails
- Compression/decompression utilities (extension includes zip/deflate functions)
- Performance-critical data parsing

**Risk**: MEDIUM - WASM can obscure malicious logic, but given extension's open-source nature (references to GitHub in code) and large user base, likely benign compression/processing code.

---

## Web Accessible Resources

The extension exposes the following resources to all websites:

- `presences/*/presence.js` (Disney+, Netflix, YouTube, Twitch, SoundCloud)
- `presences/*/metadata.json`
- `variableGetterDependencies.js`
- `content-scripts/notification/*`
- `icons/PreMiD.png`

**Risk**: LOW - These are intentionally exposed for presence injection and not sensitive.

---

## Data Flow Analysis

### Sensitive Data Handling

1. **Discord Credentials**: Extension accesses Discord session via headless connections
2. **Browsing Activity**: Current tab URL/title sent to Discord for Rich Presence
3. **Analytics ID**: Persistent user identifier stored and transmitted
4. **Custom Status**: User-configured Discord status messages

**Storage**:
- Local storage for preferences
- Sync storage for cross-device settings
- IndexedDB for presence definitions

**Network Transmission**:
- All data transmitted to `pd.premid.app` API endpoints
- Discord WebSocket connections for real-time presence updates

---

## Code Quality Observations

### Positive
- Uses modern Chrome extension APIs (Manifest V3)
- Implements userScripts for better isolation
- Includes Sentry error reporting for reliability
- Modular architecture with presence definitions
- Idle detection respects user privacy (pauses when idle)

### Negative
- Missing origin validation on message handlers
- Developer mode in production builds
- Large codebase with complex minified chunks
- WASM without clear documentation in deobfuscated source

---

## Recommendations

### Immediate (Critical/High)
*None - no critical or high-severity findings*

### Short-term (Medium)
1. **Add origin validation** to all `window.addEventListener("message")` handlers
2. **Remove developer mode** from production builds or implement proper authentication
3. **Document WASM usage** for transparency

### Long-term (Low)
4. **Enhance privacy controls** - Allow users to disable analytics/telemetry
5. **Implement CSP reporting** to detect injection attempts
6. **Code audit** of WASM modules for transparency

---

## Conclusion

PreMiD is a **legitimate Discord Rich Presence extension** with a **MEDIUM risk rating** due to implementation flaws rather than malicious intent. The primary concerns are:

1. Insecure message handler implementations creating XSS-adjacent attack vectors
2. Developer backdoor functionality in production code
3. Broad host permissions (necessary for functionality)

The extension appears to operate as disclosed - showing user activity on Discord. However, the security vulnerabilities identified should be addressed to protect the 400,000+ user base from potential exploitation by malicious third parties.

**Recommended Actions for Users**:
- Extension is safe to use for its intended purpose
- Be aware that browsing activity is shared with Discord and PreMiD servers
- Consider disabling when not actively using Discord

**Recommended Actions for Developers**:
- Patch postMessage handlers with origin validation
- Strip developer mode from release builds
- Publish security audit results and WASM source code for transparency
