# Vulnerability Report: VPN Наоборот – ВПН с российским IP

## Metadata
- **Extension ID**: mbhjnocfbpfanolafndokifmlmlhdnon
- **Extension Name**: VPN Наоборот – ВПН с российским IP
- **Version**: 4.0.9
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This is a legitimate Russian VPN service extension (VPN Naoborot - "VPN Reversed") that provides users with Russian IP addresses for accessing region-locked Russian services such as Gosuslugi, Kinopoisk, and tax services. The extension operates as a paid subscription service, dynamically fetching proxy server configurations from its backend API and routing user traffic through those proxies.

The extension follows standard VPN implementation patterns with transparent user authentication, clear privacy policy disclosures, and legitimate commercial operation. There are no indicators of malicious activity, hidden data exfiltration, or deceptive practices.

## Vulnerability Details

No vulnerabilities identified. This section documents the extension's legitimate functionality.

### Legitimate Functionality Analysis

**Files**: background.js, chunks/popup-zDxv81_g.js

**Description**: The extension implements a standard commercial VPN service with the following architecture:

1. **User Authentication**: Users authenticate via email through the service's website (www.vpn-naoborot.com), receiving a `publicRequestId` token
2. **Proxy Configuration**: The extension fetches proxy server details from `naoborot-api.naoinfrastructure.com` API endpoint (`get_proxy`)
3. **PAC Script Deployment**: Configures Chrome's proxy settings using PAC (Proxy Auto-Configuration) scripts
4. **Connection Management**: Handles proxy authentication and maintains connection state

**Evidence**:

Key API endpoint (background.js, line 4754):
```javascript
i = await Mr.post("get_proxy", {
  json: o
});
```

Proxy configuration (background.js, lines 4762-4772):
```javascript
function wc(e, t = []) {
  const n = [...new Set([...e.map(o => `${o.host}:${o.port}`), ...t.map(o => `${o.host}:${o.port}`)]).values()].map(o => `PROXY ${o}`).join("; ");
  return `
  function FindProxyForURL(url, host) {
    // Direct connection for API requests
    if (host.includes('${jr}')) {
      return "DIRECT";
    }
    // All other traffic goes through proxy
    return "${n}";
  }
 `
}
```

Connectivity check (background.js, line 4775):
```javascript
await G.isConnected() && await fetch("https://www.google.com/generate_204")
```

**Verdict**: This is expected and necessary functionality for a VPN service. The extension transparently performs its stated purpose.

## False Positives Analysis

### Static Analyzer Flag: Exfiltration Flow

The static analyzer flagged a potential exfiltration flow: `document.querySelectorAll → fetch(react.dev)`. This is a false positive. The reference to `react.dev` appears in error handling messages within the React framework bundle (used for the popup UI), not as an actual data exfiltration endpoint.

Example from popup-zDxv81_g.js (line 698):
```javascript
var m = "https://react.dev/errors/" + h;
```

This is part of React's development error messaging system and does not result in actual network requests to react.dev in the production build.

### Device IP Collection

The extension collects the user's device IP address from `api.ipify.org` (background.js, line 4677). This is a legitimate function for VPN services to:
- Provide users with information about their current IP
- Send device metadata to the backend for service provisioning
- Track device identity across sessions

This is disclosed in the service's functionality and is standard practice for VPN applications.

### Window.open Calls

The extension contains `window.open()` calls to open:
- Chrome Web Store page for leaving reviews (line 31989)
- External feedback form (line 31996)
- Subscription payment page (line 31832)

These are user-initiated actions from the popup UI, not malicious redirects.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| naoborot-api.naoinfrastructure.com | Primary API for proxy configuration and user data | Device ID, Device IP, Public Request ID | LOW - Standard VPN backend |
| api.ipify.org | IP address lookup | None | LOW - Public IP detection service |
| www.google.com/generate_204 | Connectivity check | None | NONE - Standard captive portal detection |
| www.vpn-naoborot.com | Service website | User email (for subscription) | LOW - Legitimate commercial site |
| react.dev | Error reference URLs (not called) | None | NONE - Framework documentation |

### API Resilience

The extension implements a fallback mechanism across 10+ backup API subdomains (0.naoborot-api..., 1.naoborot-api..., etc.) to ensure service availability. This is a legitimate availability design pattern, not infrastructure for malicious C2 operations.

## Privacy Considerations

As a VPN service, this extension necessarily:
1. Routes all user traffic through its proxy servers (`<all_urls>` permission)
2. Collects device identifiers and IP addresses
3. Requires user authentication

These are inherent to VPN functionality and are disclosed through:
- The extension's description mentioning it's a VPN for Russian sites
- The subscription/payment flow indicating it's a commercial service
- Standard Chrome permission warnings for `<all_urls>` and `proxy` permissions

Users opting to use a VPN service understand their traffic is routed through third-party servers.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

This extension is a legitimate commercial VPN service operating transparently within its stated purpose. The analysis found:

1. **No deceptive practices**: The extension clearly identifies itself as a VPN service
2. **No hidden data collection**: All data flows are necessary for VPN operation
3. **Standard VPN architecture**: Proxy configuration, authentication, and traffic routing follow industry standards
4. **Transparent business model**: Paid subscription service with clear payment flows
5. **No malware indicators**: No code obfuscation (webpack bundling is not obfuscation), no eval usage, no credential theft
6. **User consent**: VPN services inherently require routing traffic through their servers, which users explicitly consent to by installing and activating the service

The extension's functionality aligns completely with its description: providing Russian IP addresses for accessing region-restricted Russian online services. This is a legitimate use case for users outside Russia who need to access government services, banking, or media content restricted to Russian IP addresses.

**Recommendation**: CLEAN - No security or privacy concerns beyond what is inherent and disclosed in any VPN service.
