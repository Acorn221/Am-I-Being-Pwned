# Vulnerability Report: Szafir SDK Web

## Metadata
- **Extension ID**: gjalhnomhafafofonpdihihjnbafkipc
- **Extension Name**: Szafir SDK Web
- **Version**: 0.0.17.2
- **Users**: ~900,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Szafir SDK Web is a legitimate browser extension developed by Krajowa Izba Rozliczeniowa (Polish National Clearing House) that provides qualified electronic signature functionality for Polish users as an alternative to Java applets. The extension bridges web applications with a native host application (SzafirHost) to enable cryptographic operations using smart cards.

While the extension serves a legitimate purpose, it contains a medium-severity vulnerability in its content script's message handler. The extension listens for postMessage events from all origins without proper validation, potentially allowing malicious websites to send commands to the native messaging host. However, the actual security impact is limited by the architecture: commands are relayed through Chrome's extension messaging system and require the native host to be installed and connected.

## Vulnerability Details

### 1. MEDIUM: postMessage Listener Without Origin Validation

**Severity**: MEDIUM
**Files**: content.js:193
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)

**Description**:
The content script registers a window message event listener without validating the origin of incoming messages. While there is a check that `e.source === window`, this only prevents messages from iframes/other windows, but does not validate the origin of the web page that could call `window.postMessage()`.

**Evidence**:
```javascript
// content.js lines 42-72
function handleWindowMessages(e) {
    // We only accept messages from ourselves
    if (e.source != window) {
        return;
    }

    const data = _parseMessageData(e.data);
    if (data && data.type == "SZAFIR_EXT_MSG") {
        debugLog("CNT.js : HANDLE WINDOW MESSAGE: ", data);

        switch (data.params.command) {
            case _commands.load:
                HWND_loadSzafir(data.params);
                break;
            case _commands.unload:
                HWND_unloadSzafir();
                break;
            default:
                HWND_SzafirCommand(data.params);
                break;
        }
    }
}

// Line 193
window.addEventListener("message", handleWindowMessages);
```

The content script is injected on all URLs (`matches: ["*://*/*"]`) and accepts commands from any web page. An attacker could craft a malicious page that sends messages with type `SZAFIR_EXT_MSG` to attempt to interact with the extension.

**Attack Vector**:
A malicious website could execute:
```javascript
window.postMessage(JSON.stringify({
    type: "SZAFIR_EXT_MSG",
    params: {
        command: "load",
        config: { ... }
    }
}));
```

**Mitigating Factors**:
1. **Native Host Required**: The extension only performs meaningful operations when connected to the native SzafirHost application, which must be explicitly installed by the user.
2. **User Interaction**: Loading Szafir requires the native host to be running and the user to have configured it.
3. **Limited Attack Surface**: Commands are processed through the background script and native messaging interface, which provides some isolation.
4. **Legitimate Use Case**: The extension is designed to be called from authorized banking/e-signature websites, so some level of cross-origin communication is intentional.

**Verdict**:
This is a real vulnerability but the practical exploitation risk is limited. An attacker could potentially trigger unwanted native messaging connections or execute Szafir SDK commands if they can convince a user to visit a malicious page while having the native host installed and running. The impact is primarily availability/DoS rather than data exfiltration, as the commands are cryptographic operations that require physical smart card presence.

**Recommendation**:
Implement origin checking against an allowlist of authorized domains that should be permitted to use the Szafir SDK functionality.

## False Positives Analysis

1. **Native Messaging on All Sites**: The content script runs on `*://*/*` and uses `nativeMessaging` permission. This appears overly broad but is necessary for the extension's legitimate function - Polish government and banking sites need to be able to invoke the e-signature SDK from various domains.

2. **Chrome Extension Message Passing**: The extensive use of `chrome.runtime.sendMessage()` and message listeners is standard architectural pattern for extensions that bridge content scripts with background/native components.

3. **Tab Activation**: The code includes `chrome.tabs.update(this._tabId, {active: true})` when receiving native messages (background.js:107). This is intentional UX to bring focus to the tab performing cryptographic operations.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.elektronicznypodpis.pl/gfx/elektronicznypodpis/pl/defaultstronaopisowa/146/1/1/szafirhost.msi | Native host installer download link (Windows) | None (hardcoded URL) | CLEAN |
| www.elektronicznypodpis.pl/gfx/elektronicznypodpis/pl/defaultstronaopisowa/146/1/1/szafirhost-install.jar | Native host installer download link (Linux/macOS) | None (hardcoded URL) | CLEAN |

**Analysis**: No external API calls are made. The URLs are hardcoded references for users to download the required native host application. No user data is transmitted to external servers.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
Szafir SDK Web is a legitimate enterprise tool with 900,000 users in Poland for qualified electronic signatures. The extension's core functionality - bridging web pages with native cryptographic hardware - is implemented correctly using Chrome's native messaging API.

The primary security concern is the lack of origin validation in the postMessage handler, which could allow unauthorized websites to send commands to the extension. However, this vulnerability's impact is limited by:
- Requirement for native host installation and active connection
- Commands require physical smart card presence
- No sensitive data exfiltration vectors identified
- Well-structured code with proper separation of concerns

The MEDIUM rating reflects that while a vulnerability exists, the actual exploitability and impact are constrained by the architecture. This is not malware or a privacy violation - it's a legitimate tool with a coding oversight that should be fixed but doesn't pose immediate critical risk to users.

**Tags**:
- vuln:postmessage-no-origin
- behavior:native-messaging
- behavior:cryptographic-operations
