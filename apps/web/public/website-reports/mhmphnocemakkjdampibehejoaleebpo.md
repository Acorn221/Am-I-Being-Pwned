# Security Analysis Report: SuperNova SWF Enabler

**Extension ID**: mhmphnocemakkjdampibehejoaleebpo
**Version**: 0.93
**User Count**: 500,000
**Risk Level**: MEDIUM
**Manifest Version**: 3

## Executive Summary

SuperNova SWF Enabler is a legitimate browser extension that enables playing Flash/SWF content using the Ruffle WASM emulator. While the core functionality appears benign, the extension has **medium-severity security vulnerabilities** related to insecure message handling and privacy concerns around usage tracking.

The extension tracks user gaming activity and exfiltrates stored identifiers (gamerguid, partnerid) to getsupernova.com endpoints. It also contains three postMessage handlers without proper origin validation, creating potential XSS attack vectors.

## Risk Assessment

**Overall Risk: MEDIUM**

- **Critical**: 0
- **High**: 0
- **Medium**: 3
- **Low**: 1

## Vulnerabilities

### MEDIUM: Insecure postMessage Handlers (3 instances)

**Location**:
- `scripts/afterpage.js:330`
- `scripts/notifications.js:10715`
- `scripts/enabler.js:10808`

**Description**: Three window message event listeners accept postMessage events without validating the message origin, enabling potential cross-site scripting (XSS) attacks.

**Evidence**:

```javascript
// scripts/afterpage.js:330
window.addEventListener("message", function( event ) {
    if (
        event &&
        event.data &&
        event.data.who == "afterpage"
    ) {
        switch( event.data.command ) {
            case "waitForEnabler":
                if ($("#enablerIf").length) {
                    enabler.ready({ function: waitForEnabler, options: event.data.data })
                } else {
                    renderNotification( event.data.data );
                }
                break;
```

```javascript
// scripts/notifications.js:10715
window.addEventListener("message", function (event) {
    switch (event.data.command) {
        case "notify":
            self.waitForEnabler(event.data.data);
            break;
        case "renderNotification":
            self.notify(event.data.data);
            break;
```

```javascript
// scripts/enabler.js:10808
window.addEventListener("message", function (event) {
    if (event.data.who == "enabler") {
        switch (event.data.command) {
            case "waitForEnabler":
                self.waiting = {
                    status: true,
                    data: event.data.data
                };
                break;
```

**Impact**: Malicious websites could send crafted postMessage events to trigger unintended extension behavior or potentially inject content into notification displays.

**Recommendation**: Add origin validation:
```javascript
window.addEventListener("message", function(event) {
    // Validate origin
    if (event.origin !== window.location.origin) return;
    // Process message...
});
```

### MEDIUM: User Identifier Exfiltration

**Location**: `background.js:143-152, 609, 668-676`

**Description**: The extension stores unique user identifiers (gamerguid, partnerid) and transmits them to getsupernova.com endpoints for usage tracking.

**Evidence**:

```javascript
// background.js:143-152 - Sends gamerguid and partnerid to server
async function persistGamerStatus() {
  chrome.storage.sync.get([ "partnerid", "gamerguid" ], function( response ) {
    post( getsupernovaurl + "/www/jsbin/gamerstatus", {
      "data": {
        i: response.gamerguid,
        lc: { pi: response.partnerid, ts: new Date(), url: "" }
      }
    });
  });
}

// background.js:609 - Fetches poolid using partnerid
fetch( getsupernovaurl + '/www/jsbin/getpoolid?publisherid=' + publisherid)

// background.js:668-676 - On install, receives and stores tracking IDs
fetch( getsupernovaurl + "/www/jsbin/install.js?type=extension", { method: "POST" }).then(function (res) {
  return res.json();
}).then(function (body) {
  let guid = body.data.gamerguid;
  if (guid) chrome.storage.sync.set({ gamerguid: guid });
  let poolid = body.data.poolid;
  if (poolid) chrome.storage.sync.set({ poolid: poolid });
  let publisherid = body.data.publisherid;
  if (publisherid) chrome.storage.sync.set({ partnerid: publisherid });
```

**Impact**: User gaming behavior is tracked and associated with persistent identifiers across sessions. This enables profiling of user activity without explicit opt-in consent.

**Privacy Concern**: The extension does not clearly disclose this tracking in a user-facing privacy policy visible in the code.

### LOW: Native Messaging to Unverified Application

**Location**: `background.js:184-194, 204-218`

**Description**: The extension uses Chrome's native messaging API to communicate with a local application named 'com.tacticstechnology.superstarter'.

**Evidence**:

```javascript
// background.js:184-194
chrome.runtime.sendNativeMessage('com.tacticstechnology.superstarter',
  { text: play },
  function (response) {
    if (response == null) {
      log("Superstarter failed to launch - running check on status");
      checkSuperStarterStatus();
    } else {
      log("Received " + JSON.stringify(response));
    }
  });
```

**Impact**: Low risk if the native application is properly signed and distributed through official channels. However, if compromised, the native application could execute arbitrary code with user privileges.

**Note**: This is standard functionality for Flash player alternatives that need to launch standalone players.

## Code Analysis

### Legitimate Functionality

The extension's core purpose is to enable Flash/SWF content playback using Ruffle, an open-source Flash Player emulator written in Rust and compiled to WebAssembly:

1. **WASM Emulator**: Loads Ruffle WASM modules (`ruffle_web_bg.wasm`, `ruffle_web-wasm_extensions_bg.wasm`)
2. **Flash Detection**: Detects Flash objects on pages (`DOM_hasFlashObject()`)
3. **Game Bookmarking**: Allows users to bookmark and replay Flash games
4. **UI Components**: Provides popup UI and settings pages

### Network Endpoints

All network requests target getsupernova.com infrastructure:

| Endpoint | Purpose |
|----------|---------|
| `https://getsupernova.com/www/jsbin/gamerstatus` | POST gamer status updates |
| `https://getsupernova.com/www/jsbin/usage` | POST usage analytics |
| `https://getsupernova.com/www/jsbin/getpoolid` | GET poolid for user |
| `https://getsupernova.com/www/jsbin/install.js` | POST on install, receives tracking IDs |
| `https://getsupernova.com/update/iogames.json` | GET list of .io games |
| `https://fun.getsupernova.com/fbrcguukCoskepBvNjiupwfkdlxyydgxngyqmehvc` | GET country info |

### Data Flow

**Sensitive Data Sources**:
- `chrome.storage.sync`: gamerguid, partnerid, poolid, playedgames
- User's browsing context (URLs of Flash content)

**Data Sinks**:
- `fetch()` requests to getsupernova.com
- Native messaging to SuperStarter application
- postMessage to embedded iframes

### Permissions Analysis

| Permission | Justification | Risk |
|------------|---------------|------|
| `storage` | Store game bookmarks, settings | Low - standard usage |
| `activeTab` | Inject content scripts to detect Flash | Low - user-initiated |
| `tabs` | Query tabs, send messages | Low - needed for functionality |
| `nativeMessaging` | Communicate with SuperStarter app | Medium - requires trust in native app |
| `offscreen` | Create offscreen document for messaging | Low - MV3 standard practice |
| `https://*.getsupernova.com/` | API communication | Medium - enables tracking |

## Obfuscation Analysis

**WASM**: Yes - Ruffle emulator compiled to WebAssembly (legitimate use case)
**Code Obfuscation**: Minimal - Code is webpacked but not heavily obfuscated
**Deobfuscation**: Successfully deobfuscated with jsbeautifier

## Tags

- `vuln:postmessage_no_origin` - Missing origin validation on message handlers
- `privacy:usage_tracking` - Tracks user gaming activity with persistent identifiers
- `native_messaging` - Uses native messaging to communicate with local application

## Recommendations

### For Users

1. **Awareness**: Understand that your Flash gaming activity is tracked and sent to getsupernova.com
2. **Alternatives**: Consider other Flash emulator extensions with better privacy practices
3. **Native App**: Verify the SuperStarter native application is from a trusted source if installed

### For Developers

1. **Immediate**: Add origin validation to all postMessage handlers
2. **High Priority**: Implement user consent for usage tracking with clear privacy disclosure
3. **Best Practice**: Minimize data collection and provide opt-out mechanisms
4. **Code Quality**: Add input validation and sanitization for message data before processing

## Conclusion

SuperNova SWF Enabler provides legitimate Flash emulation functionality using the reputable Ruffle project. However, the extension has **medium-severity security issues** that should be addressed:

1. Three insecure postMessage handlers create XSS attack surface
2. Persistent user tracking without clear disclosure raises privacy concerns
3. Native messaging dependency requires trust in external application

**Recommendation**: **MEDIUM RISK** - Address postMessage origin validation and improve privacy transparency before widespread deployment. The tracking behavior should be clearly disclosed and made opt-in.
