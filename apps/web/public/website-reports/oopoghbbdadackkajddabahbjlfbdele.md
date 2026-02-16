# Vulnerability Report: InstaShare 2

## Metadata
- **Extension ID**: oopoghbbdadackkajddabahbjlfbdele
- **Extension Name**: InstaShare 2
- **Version**: 1.9.0.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

InstaShare 2 is a legitimate wireless presentation and collaboration extension designed for BenQ Board devices. The extension facilitates screen sharing, camera streaming, and file sharing to BenQ display devices via WebRTC/WebSocket connections. The extension collects user email addresses and system information (OS, CPU specifications, Chrome version) for collaboration features, but this data collection is appropriate for its stated functionality.

The extension connects to BenQ-owned signaling servers (benqcloud.com) to establish WebRTC connections for screen mirroring and collaboration. While it uses sensitive permissions including `identity.email`, `system.cpu`, and `management`, these are properly scoped to the extension's legitimate purpose of wireless presentation. The code appears to be professionally developed (Vite/Vue bundled) with no evidence of malicious behavior.

## Vulnerability Details

### 1. LOW: Broad Permission Scope for Enterprise Collaboration Tool

**Severity**: LOW
**Files**: manifest.json, service-worker.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**: The extension requests `identity.email`, `system.cpu`, `management`, and `power` permissions which are broader than typical extensions. However, these are all justified for its wireless presentation functionality:
- `identity.email` - Used to identify users in collaborative sessions
- `system.cpu` - Used to optimize video encoding/streaming based on device capabilities
- `management` - Used to check extension installation type (dev vs production environment)
- `power` - Used to prevent system sleep during active presentations
- `tabs` - Required for screen sharing functionality

**Evidence**:
```javascript
// service-worker.js - Collects user email and system info
async function Oe() {
  const E = await chrome.identity.getProfileUserInfo(),
    e = await chrome.runtime.getPlatformInfo(),
    t = await chrome.system.cpu.getInfo();
  return Promise.all([E, e, t])
}

// Extracts username from email for display in collaboration UI
function Re(E) {
  let e = "",
    t = "";
  return E === "" ? (e = "", t = a.TIMESTAMP) : (e = E.substring(0, E.indexOf("@")), t = a.EMAIL), [e, t]
}

// Checks CPU model to determine if common Intel processor
function le(E) {
  const e = E.toLowerCase(),
    t = ["i3", "i5", "i7", "i9"];
  return e.includes("intel") ? t.some(T => e.includes(T)) : !0
}

// Power management to keep display awake during presentation
function de() {
  chrome.power.requestKeepAwake("display")
}
```

**Verdict**: While the permissions are broad, they are all appropriately used for the extension's stated purpose of wireless presentation and collaboration. The data collected (email, CPU model, OS type, Chrome version) is shared via BroadcastChannel to the main application for session management and device capability detection, not exfiltrated externally.

## False Positives Analysis

The static analyzer flagged:
- **WASM flag**: No actual WASM files were found in the extension directory, likely a false positive
- **Obfuscated flag**: The code is minified by Vite (modern bundler), not maliciously obfuscated
- **message data → fetch/innerHTML/src flows**: These are benign message passing patterns in the collaboration UI, not exploitable

The extension uses WebSocket connections to BenQ's signaling servers, which is standard for WebRTC-based screen sharing applications. The signaling server URLs are hardcoded to benqcloud.com domains across dev/stage/prod environments.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| wss://signaling-server-dev.benqcloud.com | WebSocket signaling (dev) | User ID, room ID, heartbeat messages | Low - legitimate signaling |
| wss://signaling-server-stage.benqcloud.com | WebSocket signaling (staging) | User ID, room ID, heartbeat messages | Low - legitimate signaling |
| wss://signaling-server.benqcloud.com | WebSocket signaling (prod) | User ID, room ID, heartbeat messages | Low - legitimate signaling |
| chromewebstore.google.com | Extension store URL | None (just a reference URL) | None - informational only |

The WebSocket connections implement standard heartbeat/ACK patterns with timeout handling. Messages include user identifiers and room IDs for multi-user collaboration sessions, which is expected functionality for a wireless presentation tool.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: InstaShare 2 is a legitimate enterprise collaboration tool from BenQ with appropriate data collection for its stated purpose. While it requests sensitive permissions (`identity.email`, `system.cpu`, `management`, `power`), all are properly utilized for wireless presentation features:

1. User email is extracted (local part only) for display names in collaborative sessions
2. CPU and OS information is used to optimize video streaming performance
3. Management API checks installation type to determine environment (dev/stage/prod)
4. Power API prevents display sleep during active presentations

The extension only communicates with BenQ's own infrastructure (benqcloud.com signaling servers) for WebRTC connection establishment. No evidence of unauthorized data collection, tracking, or malicious behavior was found. The code is professionally developed using modern frameworks (Vite/Vue) and follows standard patterns for WebRTC-based collaboration tools.

The only minor concern is the breadth of permissions, which could be seen as slightly excessive, but all permissions have clear, legitimate uses within the extension's documented functionality.
