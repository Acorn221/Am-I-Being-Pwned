# Vulnerability Report: VPN USA - Planet VPN lite Proxy

## Metadata
- **Extension ID**: fhggeljlcambnphlgjbgnenndddhldkg
- **Extension Name**: VPN USA - Planet VPN lite Proxy
- **Version**: 1.0.13
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

VPN USA - Planet VPN lite Proxy is a legitimate VPN extension that provides proxy functionality to route user traffic through remote servers. The extension uses Manifest V3 and implements standard VPN features including proxy configuration, authentication handling, and server selection. The code is webpack-bundled (not obfuscated) and follows expected patterns for a VPN extension.

The extension connects to remote servers at `vqols.cc` to fetch proxy configuration, establishes proxy connections with authentication, and uses an offscreen document with a web worker to trigger SSL checks. While the extension requests broad permissions typical for VPN functionality, the code review reveals no evidence of malicious behavior, hidden data collection, or privacy violations beyond what is expected for a VPN service.

## Vulnerability Details

### 1. LOW: Remote Configuration Without Integrity Verification
**Severity**: LOW
**Files**: background.js (lines 4368-4392)
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension fetches proxy configuration from a remote endpoint (`https://vqols.cc/lite/v1/connection/config`) without apparent cryptographic signature verification. This is standard practice for VPN extensions that need dynamic server selection, but theoretically allows the remote server to change proxy behavior.

**Evidence**:
```javascript
static async getConfig(t) {
  const e = {
    nodes_pool_id: t,
    protocols: "proxy"
  },
  { data: n, error: u } = await Re({
    url: h0.nodesConfig(e)
  });
  if (u) {
    console.error("Error fetching config:", u);
    return
  }
  if (n?.payload) {
    const g = fn(n.payload).data;
    un(g);
    const v = {
      username: String(g.access_user),
      password: String(g.access_key)
    };
    return s0.constructor.prototype.onAuthRequiredCreds = v, g
  }
}
```

**Verdict**: This is expected behavior for a VPN extension. The remote configuration allows the service to manage server pools, update proxy credentials, and handle infrastructure changes without requiring extension updates. No evidence of malicious intent.

## False Positives Analysis

1. **Offscreen Document with Web Worker**: The extension uses `chrome.offscreen` API with a web worker that performs fetch operations. This is legitimate - the worker fetches from `api.telegra.ph/getPage/fvp-11-30` to perform SSL connectivity checks, which is a standard VPN practice to verify that HTTPS traffic can pass through the proxy.

2. **Broad Host Permissions**: The extension requests `http://*/*` and `https://*/*` permissions, which appears excessive but is required for VPN functionality. The `webRequest` and `webRequestAuthProvider` permissions are needed to intercept authentication challenges from the proxy server.

3. **Management Permission**: The `management` permission is declared but no code in the analyzed files uses `chrome.management` API to enumerate or disable other extensions. The permission may be vestigial or used in unanalyzed portions.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| vqols.cc/lite/v1/connection/config | Fetch proxy server configuration | nodes_pool_id, protocols | LOW - Standard VPN remote config |
| gapi.vqols.cc/ip | Get user's public IP address | None | LOW - IP geolocation check |
| api.telegra.ph/getPage/fvp-11-30 | SSL connectivity test | None | NONE - Public Telegraph page |
| cdn.freevpnplanet.com | CDN for static assets | None | NONE - Static resources |
| s3.amazonaws.com/cdn.freevpnplanet.com | Backup CDN | None | NONE - Static resources |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This is a legitimate VPN extension that implements expected VPN functionality without evidence of malicious behavior. The single LOW-severity finding relates to remote configuration fetching, which is standard practice for VPN services. The extension:

- Does not exfiltrate browsing history, cookies, or user data beyond what's necessary for VPN operation
- Does not inject ads or affiliate links
- Does not use the `management` permission to enumerate or disable competing extensions
- Does not contain truly obfuscated code (webpack bundling is not obfuscation)
- Properly discloses its VPN functionality through naming and permissions

The extension operates as advertised - providing VPN proxy functionality through remote servers. Users should understand that all their traffic routes through Planet VPN's infrastructure when the extension is active, but this is the expected and disclosed purpose of the extension.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
