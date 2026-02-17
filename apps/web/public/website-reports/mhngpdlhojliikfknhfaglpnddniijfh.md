# Vulnerability Report: WorkingVPN - The VPN that just works

## Metadata
- **Extension ID**: mhngpdlhojliikfknhfaglpnddniijfh
- **Extension Name**: WorkingVPN - The VPN that just works
- **Version**: 0.4.7
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

WorkingVPN is a VPN browser extension that provides proxy functionality to route browser traffic through remote servers. The extension includes features like WebRTC disabling, geolocation spoofing, and local IP bypass. The extension exhibits two concerning behaviors: (1) it automatically detects and disables competing VPN/proxy extensions using the `management` permission, and (2) it retrieves fallback API endpoints from a GitHub repository when primary servers are unreachable. While these behaviors may be considered standard for VPN extensions trying to maintain exclusive control, the automatic disabling of other extensions without explicit user consent represents extension enumeration and anti-competitive behavior.

The extension's core VPN functionality appears legitimate for its stated purpose, with proxy authentication, connection management, and privacy features like WebRTC blocking and geolocation spoofing. However, the automatic disabling of competing extensions and remote configuration fetching introduce additional attack surface.

## Vulnerability Details

### 1. MEDIUM: Extension Enumeration and Automatic Disabling
**Severity**: MEDIUM
**Files**: assets/entry.background.js-DYqHYnAf.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension uses the `management` permission to enumerate all installed extensions and automatically disables any extension with `proxy` permissions (except itself). This occurs during the connection process.

**Evidence**:
```javascript
ue = u(function(t = function() {}) {
  return a(this, null, function*() {
    const e = yield chrome.management.getAll();
    var s = !1,
      o = [];
    if (this.browserType === "chrome")
      for (const r of e) r.id != n.runtime.id && r.enabled == !0 && r.name.toLowerCase().indexOf("download manager") === -1 && r.name.toLowerCase().indexOf("idm") === -1 && (r.permissions.includes("proxy") && (s = !0, o && !o.some(h => h.id === r.id) && o.push(r)), o.length > 0);
    (s != this.storage.extensionConflict || o.toString() != C(this.storage.conflictingExtensions).toString()) && (this.storage.extensionConflict = s, this.storage.conflictingExtensions = o, yield this.saveStorage(), yield this.updatePopupState())
  })
})

fe = u(function(t = () => {}) {
  return a(this, null, function*() {
    if (this.browserType === "chrome") {
      const e = yield chrome.management.getAll();
      for (const s of e) s.id != n.runtime.id && s.enabled != 0 && s.permissions.includes("proxy") && (yield n.management.setEnabled(s.id, !1), this.storage.extensionConflict = !1, this.storage.conflictingExtensions = []);
      yield this.saveStorage(), yield this.updatePopupState()
    }
  })
})
```

**Verdict**: While VPN extensions commonly check for conflicts, automatically disabling other extensions is aggressive behavior. This is standard for VPN/proxy extensions trying to ensure exclusive control of proxy settings, but it crosses into anti-competitive territory. The extension does exclude "download manager" and "IDM" extensions, showing some consideration. This is flagged as MEDIUM severity because it's expected behavior for VPN extensions, though it represents extension enumeration.

### 2. LOW: Remote Configuration from GitHub
**Severity**: LOW
**Files**: assets/entry.background.js-DYqHYnAf.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: When primary API servers fail, the extension fetches fallback API hostnames from a public GitHub repository without integrity verification.

**Evidence**:
```javascript
let b = "https://github.com/lovingthat/peanutbutter/raw/refs/heads/jelly/rules.json";
// ...
try {
  let y = yield fetch(b.toString(), {
    method: "GET",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    cache: "no-store"
  });
  if (y.ok) {
    let E = yield y.json();
    if (E != null && E.apis && E.apis.constructor === Array)
      return e = E.apis, this.storage.fallbackApis = e,
        yield this.saveStorage(), yield this.apiRequest(t, e);
    throw new Error("Fallback API hostnames are not an array")
  }
} catch (y) {}
```

**Verdict**: The extension fetches configuration from a GitHub repository when primary servers are unreachable. While this provides resilience, it introduces a dependency on GitHub availability and the security of that repository. However, the fetched data is only API hostnames (not executable code), and the extension validates that the response is a JSON array. This is a LOW severity issue because it's configuration data rather than code, though it does create an additional attack surface.

## False Positives Analysis

1. **Extension Disabling is Standard VPN Behavior**: While flagged as extension enumeration, disabling competing VPN/proxy extensions is standard behavior for VPN extensions that need exclusive control of browser proxy settings. Most VPN extensions perform similar conflict detection.

2. **Proxy Authentication**: The extension performs proxy authentication by fetching from `healthcheck.workingvpn` and `login.workingvpn`. This is legitimate VPN functionality, not credential theft.

3. **Sentry Integration**: The extension includes Sentry error tracking with DSN `https://8264e0771d0a4c90a4f5a1eb87603634@o40735.ingest.sentry.io/5274901`. This is standard error monitoring, not data exfiltration.

4. **WebRTC Blocking and Geolocation Spoofing**: These are privacy-enhancing features expected in VPN extensions to prevent IP leaks.

5. **`<all_urls>` Permission**: Required for the VPN to intercept and proxy all web requests, which is the core purpose of a VPN extension.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| workingvpn.com | Primary API server | Extension UID, extension ID (headers) | Low - Standard API authentication |
| 000000555.xyz | Backup API server | Extension UID, extension ID (headers) | Low - Fallback endpoint |
| healthcheck.workingvpn | Proxy authentication test | None | Low - Connection verification |
| login.workingvpn | Proxy login | Authentication token | Low - Expected VPN functionality |
| logout.workingvpn | Proxy logout | None | Low - Session cleanup |
| github.com/lovingthat/peanutbutter | Fallback API list | None | Low - Configuration fetch only |
| sentry.io | Error reporting | Error telemetry | Low - Standard crash reporting |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: WorkingVPN is a functional VPN extension that provides legitimate proxy services. The primary concerns are:

1. **Extension Enumeration and Auto-Disable**: The extension automatically detects and disables competing VPN extensions. While this is standard behavior for VPN extensions ensuring exclusive proxy control, it represents anti-competitive behavior and use of the `management` permission for extension enumeration.

2. **Remote Configuration**: Fetching fallback API endpoints from GitHub introduces an additional attack surface, though the risk is limited since only configuration data (not code) is fetched.

The extension's core VPN functionality (proxy management, WebRTC blocking, geolocation spoofing, local IP bypass) appears legitimate and expected for a VPN service. The extension uses proper authentication, handles connection failures gracefully, and implements privacy features.

The MEDIUM risk level reflects that while the concerning behaviors exist, they are largely standard for the VPN extension category. Users installing a VPN extension should expect it to take exclusive control of proxy settings, which necessitates detecting and potentially disabling competing extensions. The remote configuration from GitHub is a resilience feature with limited security impact.

**Recommendations for Users**:
- Be aware that this extension will automatically disable other VPN/proxy extensions
- The extension sends a unique identifier (UID) to its API servers for authentication
- Extension includes error reporting to Sentry which may send crash telemetry
