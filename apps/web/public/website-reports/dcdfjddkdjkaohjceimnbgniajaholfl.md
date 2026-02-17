# Vulnerability Report: ActivCast Sender

## Metadata
- **Extension ID**: dcdfjddkdjkaohjceimnbgniajaholfl
- **Extension Name**: ActivCast Sender
- **Version**: 0.0.4.2
- **Users**: ~300,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

ActivCast Sender is a legitimate screen sharing/mirroring extension developed by Promethean Limited for their ActivCast educational technology platform. The extension enables users to cast their desktop or browser tab to ActivCast receiver devices via WebRTC, using Splashtop's relay infrastructure. The extension requests powerful permissions (desktopCapture, tabCapture, nativeMessaging) that are appropriate for its stated screen sharing functionality.

The static analysis identified weak origin validation on message handlers that could allow malicious web pages to trigger unintended behavior. However, the actual security impact is limited as the most sensitive operations require user interaction (screen sharing permission prompt) or are protected by Chrome's security model. The extension communicates exclusively with legitimate Splashtop/Promethean infrastructure over secure WebSocket connections.

## Vulnerability Details

### 1. LOW: Weak Origin Validation on Message Handlers
**Severity**: LOW
**Files**: js/bg.js (deobfuscated), js/spt1.js (deobfuscated)
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension's message handlers in the background script process messages from any source without validating the sender's origin. The static analyzer flagged flows where message data reaches `.innerHTML` and `.src` properties without origin checks.

**Evidence**:
```javascript
// js/bg.js - chrome.runtime.onMessage.addListener
chrome.runtime.onMessage.addListener(function(a,b,c){
  log&&log.debug("Get the command: "+JSON.stringify(a));
  if(a)switch(a.id){
    case "getlist":
    case "getsessionid":
    case "shareTo":
    // ... many message handlers without origin validation
  }
});
```

The static analyzer detected:
```
ATTACK SURFACE:
  message data → *.src    from: js/bg.js ⇒ js/spt1.js
  message data → *.innerHTML    from: js/bg.js ⇒ js/spt1.js
```

**Verdict**: While the message handlers lack origin validation, the actual risk is LOW because:
1. The extension only processes messages with specific command IDs (getlist, shareTo, etc.)
2. Sensitive operations like screen capture require explicit user permission via Chrome's desktopCapture API
3. The innerHTML assignments in spt1.js only use localized messages from `chrome.i18n.getMessage()`, not raw message data
4. The extension is designed for Chrome Apps (chrome.app.window API), which has a different security model than regular extensions

## False Positives Analysis

1. **Obfuscated Code Flag**: The static analyzer flagged the code as "obfuscated" due to variable renaming and minification. However, this appears to be standard build-time minification rather than malicious obfuscation. The deobfuscated code reveals straightforward WebRTC screen sharing logic with Splashtop infrastructure.

2. **DOM Manipulation Flows**: The flows to `.innerHTML` and `.src` are primarily for legitimate UI updates (displaying connection status messages, error messages, loading images) rather than XSS vulnerabilities. The actual content sources are either:
   - Localized strings from manifest: `chrome.i18n.getMessage()`
   - Internal state variables (session codes, connection status)
   - Base64-encoded parameters from trusted sources

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| wss://promethean-wbs.relay.splashtop.com | WebRTC signaling server (Promethean-branded) | Session metadata, platform info, UUID, WebRTC SDP/ICE candidates | Low - Legitimate infrastructure |
| wss://wbs.relay.splashtop.com:443 | Fallback WebRTC signaling server | Same as above | Low - Legitimate Splashtop service |
| turn:turn.relay.splashtop.com:443 | TURN relay for NAT traversal | WebRTC media streams (screen capture) | Low - Standard WebRTC relay |

**Data Flow**: The extension sends platform information (OS version, Chrome version), a locally-generated UUID, session codes, and WebRTC negotiation data. Screen capture streams are transmitted via WebRTC peer connections. No browsing history, cookies, or personal data beyond what's necessary for screen sharing is collected.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
- ActivCast Sender is a legitimate enterprise/education screen sharing tool from Promethean Limited
- The permissions (desktopCapture, tabCapture, nativeMessaging) are appropriate for screen mirroring functionality
- The extension connects only to legitimate Splashtop relay infrastructure over secure WebSocket connections
- While message handlers lack strict origin validation, the practical attack surface is minimal due to Chrome's permission model and the extension's internal logic
- The obfuscation is standard minification, not malicious code hiding
- The extension has been available since at least 2016 with ~300K users and no public reports of abuse
- The low 3.1 star rating appears to be related to connectivity/usability issues rather than security concerns

**Recommendation**: Users should only install this extension if they specifically need to connect to Promethean ActivCast hardware. The minor origin validation weakness could be addressed by adding sender validation to the chrome.runtime.onMessage listener, but the current implementation poses minimal real-world risk.
