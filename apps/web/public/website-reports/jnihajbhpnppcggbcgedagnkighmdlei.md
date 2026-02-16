# Vulnerability Report: LiveReload

## Metadata
- **Extension ID**: jnihajbhpnppcggbcgedagnkighmdlei
- **Extension Name**: LiveReload
- **Version**: 2.1.0
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

LiveReload is a legitimate browser extension designed for web developers. It connects to a local LiveReload server running on the developer's machine (127.0.0.1:35729) and automatically refreshes web pages when source files are modified. This extension is part of the standard LiveReload development workflow and poses no security or privacy risks to users.

The extension only communicates with localhost, uses standard WebSocket connections for development purposes, and does not collect, transmit, or exfiltrate any user data. All network communication is strictly limited to the local development server.

## Vulnerability Details

No vulnerabilities identified.

## False Positives Analysis

### 1. Localhost-only Communication
The extension connects to `ws://127.0.0.1:35729` and `http://127.0.0.1:35729`, which are localhost addresses. This is the expected and documented behavior for a development tool that needs to communicate with a local LiveReload server.

**Evidence**:
```javascript
// global.js lines 169-170
this.host = '127.0.0.1';
return this.port = 35729;
```

**Verdict**: Not a security concern - localhost communication for development purposes.

### 2. Message Passing Without Origin Check
The extension uses `chrome.runtime.onMessage.addListener` to receive messages from content scripts. While there's no explicit origin check, this is safe because:
- Messages only come from content scripts injected by the extension itself
- The extension only accepts specific commands: 'status', 'resourceAdded', 'resourceUpdated'
- No sensitive operations are performed based on message content

**Evidence**:
```javascript
// global.js lines 55-65
chrome.runtime.onMessage.addListener(function(_arg, sender, sendResponse) {
  var data, eventName;
  eventName = _arg[0], data = _arg[1];
  switch (eventName) {
    case 'status':
      LiveReloadGlobal.updateStatus(sender.tab.id, data);
      return ToggleCommand.update(sender.tab.id);
    default:
      return LiveReloadGlobal.received(eventName, data);
  }
});
```

**Verdict**: Safe - limited command set, no dangerous operations.

### 3. Dynamic Script Injection
The content script dynamically injects the `livereload.js` script into pages. This is the core functionality of the extension and is necessary for the LiveReload protocol to work.

**Evidence**:
```javascript
// injected.js lines 140-142
element = this.document.createElement('script');
element.src = url;
return this.document.body.appendChild(element);
```

The script URL is either:
- From the local LiveReload server: `http://127.0.0.1:35729/livereload.js`
- From the extension bundle: `chrome.runtime.getURL('livereload.js')`

**Verdict**: Safe - scripts are loaded from trusted sources (localhost or extension itself).

### 4. Broad Permissions
The extension requests `<all_urls>` permission, which appears excessive but is required because:
- Developers need to reload any page they're working on
- The extension must inject content scripts into all pages during development
- This is standard for development tools

**Verdict**: Appropriate for the extension's legitimate development purpose.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| ws://127.0.0.1:35729/livereload | WebSocket connection to local LiveReload server | Extension version, protocol info, page URL | None (localhost only) |
| http://127.0.0.1:35729/livereload.js | Download LiveReload client script | None (HTTP GET) | None (localhost only) |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
LiveReload is a well-known, open-source development tool with legitimate functionality. The code analysis confirms:

1. **No Data Exfiltration**: All network communication is restricted to localhost (127.0.0.1:35729)
2. **No Privacy Concerns**: Extension does not collect, store, or transmit user data
3. **No Malicious Behavior**: All functionality aligns with documented LiveReload protocol
4. **Appropriate Permissions**: While permissions are broad, they're necessary for the extension's development tool purpose
5. **No Code Execution Risks**: Dynamic script injection is limited to trusted sources (localhost server or extension bundle)
6. **No Hidden Functionality**: Code is straightforward browserify-bundled JavaScript with no obfuscation

This extension is safe for developers to use and poses no security or privacy risks to end users.
