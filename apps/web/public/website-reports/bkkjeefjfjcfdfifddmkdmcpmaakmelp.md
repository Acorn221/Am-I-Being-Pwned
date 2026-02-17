# Vulnerability Report: Truffle

## Metadata
- **Extension ID**: bkkjeefjfjcfdfifddmkdmcpmaakmelp
- **Extension Name**: Truffle
- **Version**: 4.7.1
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Truffle is a livestream enhancement extension that provides additional features for streaming platforms (YouTube, Twitch, Patreon). The extension collects cookies from streaming platforms, modifies HTTP request/response headers, and communicates extensively with Truffle's backend infrastructure. While the extension appears to be a legitimate service for enhancing livestream experiences, it exhibits several security concerns including insufficient origin validation in postMessage handlers, privileged cookie access, and header manipulation capabilities that could be exploited if the extension were compromised.

The extension uses broad permissions (`<all_urls>`) and accesses sensitive data from streaming platforms, but these capabilities appear justified for its stated functionality. The primary concern is the postMessage handler without origin checks, which creates an attack surface for cross-frame exploitation.

## Vulnerability Details

### 1. MEDIUM: postMessage Handler Without Origin Check

**Severity**: MEDIUM
**Files**: chunks/create-6466ba3c.js
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)

**Description**: The extension implements window.addEventListener("message") handlers without proper origin validation in the transframe communication layer. This allows any webpage to send messages to the extension's frames, potentially triggering unintended behavior.

**Evidence**:
```javascript
// chunks/create-6466ba3c.js (deobfuscated)
window.addEventListener("message", this._messageHandlerWrapper)
this._messageHandlerWrapper = e => {
  this._options?.allowedOrigins && !this._options.allowedOrigins.includes(e.origin) || this._messageHandler(e.data);
}
```

The handler checks allowedOrigins but uses inclusive logic that could allow messages through if allowedOrigins is undefined or empty. The ext-analyzer flagged this pattern at chunks/create-6466ba3c.js:3.

**Verdict**: While the extension attempts origin validation, the logic structure creates risk. However, impact is limited because the communication protocol uses a specific namespace and message format that would be difficult to exploit without knowledge of internal APIs.

### 2. MEDIUM: Cookie Harvesting from Streaming Platforms

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-359 (Exposure of Private Information)

**Description**: The extension collects all cookies from YouTube and related domains through a privileged background API. While this appears necessary for the extension's functionality (accessing authenticated streaming APIs), it represents significant access to user credentials.

**Evidence**:
```javascript
// background.js
getCookies: async (e$1, o) => {
  if (!["youtube.com", "studio.youtube.com", "www.youtube.com"].some((e => o.includes(e))))
    throw console.error("Domain not whitelisted", o), new Error(`Domain not whitelisted: ${o}`);
  return await e.exports.cookies.getAll({
    url: o
  })
}
```

The extension whitelists only specific streaming domains, which is good practice. The cookies are used to make authenticated requests to YouTube/Twitch APIs on behalf of the user.

**Verdict**: This is expected behavior for a livestream enhancement tool that needs to interact with authenticated streaming platform APIs. The domain whitelisting mitigates risk, but this represents a high-privilege operation that could be abused if the extension or its infrastructure were compromised.

### 3. MEDIUM: HTTP Header Manipulation

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-693 (Protection Mechanism Failure)

**Description**: The extension uses declarativeNetRequest and webRequest APIs to remove HTTP headers (including security headers) from requests to streaming platforms.

**Evidence**:
```javascript
// background.js
removeHeaders: async (e, {headers: t, ttlMs: o}) => {
  try {
    let e;
    e = l ? await d(t) : await m(t),
    o && setTimeout((() => {
      e();
    }), o);
  } catch (e) {
    console.error("Error removing headers", e);
  }
}

// Removes headers like 'origin', 'x-frame-options', 'content-security-policy'
const MODIFIED_FETCH_DOMAINS = ["youtube.com", "twitch.tv", "patreon.com"];
```

The extension removes headers including `origin`, `x-frame-options`, and `content-security-policy` to enable cross-origin requests and embedding. This is scoped to specific domains but represents a significant security capability.

**Verdict**: This functionality appears necessary for the extension to embed and interact with streaming platform content. The removal is limited to specific whitelisted domains and is temporary (with TTL). However, this capability could weaken security protections if misused.

### 4. LOW: Externally Connectable Configuration

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The extension allows external connections from truffle.vip domains and one other extension ID.

**Evidence**:
```json
"externally_connectable": {
  "ids": ["pmnmpgjfacmjcnfigcmgfipemjpggmeg"],
  "matches": ["*://*.truffle.vip/*"]
}
```

**Verdict**: This is legitimate configuration allowing the extension to communicate with Truffle's web infrastructure and potentially another Truffle extension. The domain restriction limits attack surface.

## False Positives Analysis

1. **Obfuscation Flag**: The ext-analyzer flagged the extension as "obfuscated". However, upon inspection, this appears to be webpack/bundler minification rather than malicious obfuscation. The code structure is consistent with React/modern JavaScript build tools.

2. **Broad Permissions**: The extension requests `<all_urls>` permissions, which could be seen as excessive. However, for a livestream enhancement tool that works across multiple streaming platforms, this is justified. The extension explicitly limits its active operations to specific streaming domains.

3. **Remote Configuration**: The extension fetches configuration and embed definitions from `mothertree.truffle.vip/graphql`. This is standard practice for a SaaS extension that provides dynamic content. The queries are read-only and scoped to user's organization context.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| mothertree.truffle.vip/graphql | Fetch embed configurations and channel data | orgId, entity references, access tokens | MEDIUM - authenticated queries with user context |
| app.truffle.vip | Embed iframe hosting, onboarding flow | Navigation, user interaction events | LOW - legitimate web app integration |
| platform-chat-api.truffle.vip | Chat integration API | Video IDs, channel IDs | LOW - read-only platform data queries |
| gql.twitch.tv/gql | Twitch GraphQL API | Twitch queries (proxied) | LOW - standard Twitch API usage |
| youtube.com, twitch.tv, patreon.com | Streaming platform APIs | Cookies, authenticated requests | MEDIUM - uses user credentials |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: Truffle appears to be a legitimate livestream enhancement extension with expected functionality for its category. The extension collects cookies, modifies headers, and communicates with external infrastructure, but these capabilities align with its stated purpose of enhancing livestream viewing experiences.

The primary security concerns are:

1. **Attack Surface**: The postMessage handler without robust origin checking creates potential for cross-frame attacks
2. **Privileged Access**: Cookie harvesting and header manipulation represent high-privilege operations that could be abused
3. **Dependency on External Infrastructure**: Significant reliance on Truffle backend services means user security depends on Truffle's infrastructure security

These risks are mitigated by:
- Domain whitelisting for sensitive operations
- Scoped permissions to streaming platforms
- Legitimate business model (enhancing streaming experiences)
- No evidence of undisclosed data collection

**Recommendation**: MEDIUM risk is appropriate. Users should trust Truffle's infrastructure security. The extension should improve postMessage origin validation and consider more restrictive permissions where possible. For a streaming enhancement tool of this type, the current permission set is within expected norms.
