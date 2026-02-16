# Vulnerability Report: Netskope Chrome Extension

## Metadata
- **Extension ID**: pjfbgcbklnoeejjipoabcfnijajgikpb
- **Extension Name**: Netskope Chrome Extension
- **Version**: 132.2.0
- **Users**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

The Netskope Chrome Extension is a legitimate enterprise cloud security solution designed to enforce explicit proxy routing for web traffic. The extension redirects all HTTP/HTTPS/WebSocket traffic through Netskope's cloud proxy infrastructure (eproxy-{tenant}.goskope.com:8081) and injects authentication tokens (X-NS-PATOKEN) into request headers. While this is expected behavior for an enterprise security tool, the extension's broad permissions and traffic interception capabilities represent a MEDIUM privacy risk when evaluated independently of its intended enterprise deployment context.

The extension is designed to be deployed via enterprise managed policies (Chrome Enterprise), where administrators configure tenant names, bypass lists, and authentication settings. However, it can also be manually configured by end users through local storage, which could lead to unintended privacy implications if installed outside of an enterprise context.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Traffic Interception and Header Injection

**Severity**: MEDIUM
**Files**: background.js, proxy-utils.js
**CWE**: CWE-319 (Cleartext Transmission of Sensitive Information)
**Description**: The extension requests `*://*/*` host permissions and configures system-wide proxy settings to route all HTTP/HTTPS/WebSocket traffic through Netskope's infrastructure. Additionally, it injects an `X-NS-PATOKEN` authentication header into virtually all web requests using `declarativeNetRequest`, excluding only domains in the `header_skip_list` and `goskope.com`.

**Evidence**:
```javascript
// background.js lines 197-218
chrome.proxy.settings.set({
  value: {
    mode: 'fixed_servers',
    rules: {
      proxyForHttp: {
        scheme: 'http',
        host: 'eproxy-' + tenant,
        port: 8081
      },
      proxyForHttps: {
        scheme: 'http',
        host: 'eproxy-' + tenant,
        port: 8081
      },
      bypassList: bypass_list
    }
  },
  scope: 'regular'
}
```

```javascript
// proxy-utils.js lines 74-107
chrome.declarativeNetRequest.updateDynamicRules({
  addRules: [{
    id: 1,
    condition: {
      excludedRequestDomains: headerSkipList.concat(['goskope.com']),
      resourceTypes: ['main_frame', 'sub_frame', 'stylesheet', 'script',
                      'image', 'font', 'object', 'xmlhttprequest', 'ping',
                      'csp_report', 'media', 'websocket', 'other']
    },
    action: {
      type: 'modifyHeaders',
      requestHeaders: [{
        header: 'X-NS-PATOKEN',
        operation: 'set',
        value: nsPaToken
      }]
    }
  }]
})
```

**Verdict**: This is EXPECTED behavior for an enterprise cloud access security broker (CASB) solution. Netskope's business model involves inspecting and securing enterprise web traffic. The extension properly supports bypass lists and PAC scripts for granular control. However, rated MEDIUM because:
1. All user web traffic is routed through third-party servers
2. Authentication tokens are injected into headers, allowing Netskope to correlate user activity
3. If installed by individual users (not via enterprise policy), they may not fully understand the privacy implications
4. The proxy uses HTTP (not HTTPS) for the proxy connection itself, though this is standard for explicit proxies

## False Positives Analysis

The following patterns appear in the code but are NOT security concerns:

1. **Cookie Access** - The extension monitors and manages `nspatoken` and `nsauth_session` cookies, but these are authentication cookies for the Netskope service itself, not user cookie harvesting.

2. **Notification Pulling** - The extension makes long-polling requests to `achecker-{tenant}` endpoints for user notifications. This is standard enterprise notification infrastructure, not data exfiltration.

3. **Managed Storage** - The extension uses Chrome's managed storage API to receive enterprise policies. This is the correct way to deploy enterprise extensions.

4. **Dynamic Code** - No use of `eval()`, `Function()`, or other dynamic code execution was detected.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| eproxy-{tenant}:8081 | Proxy server for all web traffic | All HTTP/HTTPS/WS traffic with X-NS-PATOKEN header | MEDIUM - Expected for CASB but represents full traffic visibility |
| authservice.goskope.com | Authentication service (content script targets) | User credentials during authentication flow | LOW - Standard authentication |
| authservice.eu.goskope.com | European authentication service | User credentials during authentication flow | LOW - Standard authentication |
| authservice.au.goskope.com | Australian authentication service | User credentials during authentication flow | LOW - Standard authentication |
| authservice.de.goskope.com | German authentication service | User credentials during authentication flow | LOW - Standard authentication |
| achecker-{tenant} | Notification long-polling endpoint | X-NS-PATOKEN header, receives notifications | LOW - Standard notification system |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
This is a legitimate enterprise security product from Netskope, a well-known cloud access security broker (CASB) vendor. All traffic interception and header injection behavior is disclosed and expected for this type of security tool. The extension is properly designed for enterprise deployment via Chrome's managed policies.

The MEDIUM risk rating reflects:
1. **Privacy Impact**: All user web traffic is routed through Netskope's infrastructure with authentication headers, providing complete visibility into browsing activity
2. **Deployment Context**: While appropriate for enterprise environments with informed users, individual users installing this extension may not fully understand the privacy implications
3. **No Technical Vulnerabilities**: The code is well-written with no obvious security flaws, XSS vulnerabilities, or credential theft mechanisms
4. **Transparent Operation**: The extension clearly identifies itself as "Netskope Chrome Extension" and provides UI controls for configuration

This extension is **NOT malicious** but represents a typical enterprise monitoring/security tool. The risk level is MEDIUM rather than HIGH or CLEAN because:
- It's CLEAN from a technical security perspective (no vulnerabilities)
- It's MEDIUM from a privacy perspective (comprehensive traffic monitoring)
- The rating accounts for potential misuse if installed outside enterprise context

**Recommendation**: This extension should only be installed in enterprise environments where users are informed about traffic monitoring policies. Individual users should not install this extension unless required by their organization.
