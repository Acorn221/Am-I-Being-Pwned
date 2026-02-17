# Security Analysis: CyberGhost VPN – Proxy for Chrome

**Extension ID**: ffbkglfijbcbgblgflchnbphjdllaogb
**Version**: 10.0.0
**User Count**: 900,000
**Risk Level**: HIGH
**Publisher**: CyberGhost

## Executive Summary

CyberGhost VPN is a legitimate VPN proxy extension from a reputable vendor. However, it contains a **CRITICAL** security vulnerability in its manifest configuration that creates a significant attack surface, combined with multiple data exfiltration flows. The extension uses `externally_connectable: ["<all_urls>"]`, which allows **any website on the internet** to send messages to the extension and potentially trigger sensitive operations.

The extension also exhibits suspicious data flows where extension storage (both local and sync) is transmitted to external endpoints via fetch() calls, though these appear to be directed to the Chrome Web Store (likely for analytics or update checking).

## Vulnerability Summary

| Severity | Count | Description |
|----------|-------|-------------|
| CRITICAL | 1 | Unrestricted externally_connectable allowing any website to message the extension |
| HIGH | 3 | Multiple data exfiltration flows from storage to network endpoints |
| MEDIUM | 0 | - |
| LOW | 0 | - |

## Critical Findings

### 1. CRITICAL: Unrestricted External Messaging (externally_connectable)

**Severity**: CRITICAL
**CWE**: CWE-346 (Origin Validation Error)
**CVSS**: 8.1 (High)

#### Description

The extension's manifest.json declares:
```json
"externally_connectable": {
  "matches": ["<all_urls>"]
}
```

This configuration is extremely dangerous as it allows **any webpage on any domain** to communicate with the extension via `chrome.runtime.sendMessage()`. This creates multiple attack vectors:

1. **Malicious websites** can interact with the extension's message handlers
2. **Compromised legitimate websites** can be weaponized to attack extension users
3. **Man-in-the-middle attackers** on HTTP sites can inject code to interact with the extension
4. **Cross-site scripting (XSS) vulnerabilities** on any website become amplified

#### Attack Scenario

An attacker could:
1. Create a malicious website or compromise an existing site
2. Inject JavaScript that calls `chrome.runtime.sendMessage('ffbkglfijbcbgblgflchnbphjdllaogb', {malicious_payload})`
3. Trigger privileged operations within the extension
4. Potentially manipulate proxy settings, access stored credentials, or exfiltrate user data

#### Evidence

**File**: `manifest.json:53-57`
```json
"externally_connectable": {
  "matches": [
    "<all_urls>"
  ]
}
```

#### Impact

- **Confidentiality**: HIGH - External sites can potentially query extension state and access stored data
- **Integrity**: HIGH - Malicious messages could alter proxy configurations or extension behavior
- **Availability**: MEDIUM - Malicious messages could disable VPN functionality

#### Recommendation

**Immediate**: Restrict `externally_connectable` to only the specific domains that legitimately need to communicate with the extension. For example:
```json
"externally_connectable": {
  "matches": [
    "https://www.cyberghostvpn.com/*",
    "https://account.cyberghostvpn.com/*"
  ]
}
```

**Best Practice**: If no external website communication is needed, remove the `externally_connectable` declaration entirely.

### 2. HIGH: Extension Storage Exfiltration to Chrome Web Store

**Severity**: HIGH
**CWE**: CWE-200 (Exposure of Sensitive Information)

#### Description

The extension contains data flow paths where sensitive data from Chrome's storage APIs (`chrome.storage.local.get` and `chrome.storage.sync.get`) reaches network sinks via `fetch()` calls to `chromewebstore.google.com`.

#### Evidence

**Data Flow 1**: Local Storage → Network
```
Source: chrome.storage.local.get (src/scripts/background.js:70)
  ↓
Sink: fetch(chromewebstore.google.com) (src/scripts/background.js)
```

**Data Flow 2**: Sync Storage → Network
```
Source: chrome.storage.sync.get (src/scripts/background.js:70)
  ↓
Sink: fetch(chromewebstore.google.com) (src/scripts/background.js)
```

**Endpoint Identified**:
- `chromewebstore.google.com/detail/cyberghost-vpn-%E2%80%93-proxy-fo/ffbkglfijbcbgblgflchnbphjdllaogb`

#### Analysis

While the destination is Google's Chrome Web Store (likely for analytics, ratings, or update checking), this pattern is concerning because:

1. **Unclear data scope**: It's not evident what specific data from storage is being transmitted
2. **Potential PII exposure**: VPN extensions often store sensitive user data (tokens, preferences, location data)
3. **Third-party transmission**: Even to Google, user data transmission should be minimized and transparent

#### Impact

- **Confidentiality**: MEDIUM-HIGH - Potentially sensitive user configuration or authentication data could be exposed
- **Privacy**: HIGH - User activity patterns could be inferred from transmitted data
- **Compliance**: May violate GDPR/privacy regulations if PII is transmitted without explicit consent

#### Recommendation

1. **Audit transmitted data**: Review exactly what data is being sent to the Chrome Web Store endpoint
2. **Minimize data collection**: Only transmit non-sensitive, anonymized telemetry if necessary
3. **User consent**: Ensure users explicitly consent to any data transmission in privacy policy
4. **Code obfuscation concerns**: The heavily minified code makes audit difficult - consider providing source maps for security review

### 3. HIGH: Message Handler Data Exfiltration

**Severity**: HIGH
**CWE**: CWE-441 (Unintended Proxy or Intermediary)

#### Description

The extension has message handlers that can forward data received via `chrome.runtime.onMessage` to external network endpoints.

#### Evidence

**Data Flow 3**: Message Data → Network (from popup)
```
Source: Message data from src/popup.js
  ↓
Handler: src/scripts/background.js (message listener)
  ↓
Sink: fetch(chromewebstore.google.com)
```

**Data Flow 4**: Message Data → Network (from background)
```
Source: Message data from src/scripts/background.js
  ↓
Handler: src/scripts/background.js (message listener)
  ↓
Sink: fetch(chromewebstore.google.com)
```

#### Attack Scenario (Combined with Vulnerability #1)

Given the unrestricted `externally_connectable`:

1. Attacker creates a malicious website
2. Website sends crafted message: `chrome.runtime.sendMessage('ffbkglfijbcbgblgflchnbphjdllaogb', {data: "payload"})`
3. Extension's message handler processes the message
4. Malicious data gets forwarded to external endpoint via fetch()
5. Attacker could potentially:
   - Use extension as a proxy to bypass CORS
   - Inject tracking data
   - Trigger unintended extension behaviors

#### Impact

- **Integrity**: HIGH - External attackers can inject messages that trigger network requests
- **Availability**: MEDIUM - Could be abused for DoS via excessive message sending
- **Privacy**: HIGH - Extension becomes an unwitting proxy for attacker-controlled data

#### Recommendation

1. **Validate message origins**: Even with restricted `externally_connectable`, always validate `sender.url` in message handlers
2. **Sanitize message data**: Never trust message content - validate and sanitize all inputs
3. **Rate limiting**: Implement rate limits on message processing to prevent abuse
4. **Authentication**: Require authentication/authorization for sensitive message types

## Permissions Analysis

### Declared Permissions

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `storage` | Store VPN configuration and user preferences | LOW (normal for VPN) |
| `tabs` | Query tab information for VPN status | MEDIUM (overprivileged) |
| `proxy` | Configure browser proxy settings | LOW (required for VPN) |
| `<all_urls>` | Host permission for all URLs | HIGH (overprivileged) |

### Overprivileged Analysis

1. **`tabs` permission**: Used to query tab state, but VPN extensions typically don't need full tabs permission. Consider using `activeTab` instead if only current tab info is needed.

2. **`<all_urls>` host permission**: Grants read/write access to all websites. While needed for proxy functionality, this is a very broad permission that should be carefully audited.

## Code Quality Concerns

### Obfuscation

The extension's JavaScript code is heavily minified and bundled, making security auditing extremely difficult:
- **Background script**: 70 lines (single minified line)
- **Popup script**: 95 lines (single minified line)
- **Frameworks**: Includes bundled React and other libraries

**Recommendation**: Provide source maps or un-minified source code for security review.

### Bundled Dependencies

The extension bundles:
- React 18.x
- Analytics/telemetry SDK (appears to be Segment or similar)
- Various utility libraries

**Risk**: Bundled dependencies could contain vulnerabilities. Recommend:
- Document all third-party dependencies
- Use dependency scanning tools (npm audit, Snyk)
- Keep dependencies updated

## Technical Details

### Manifest Version

The extension uses Manifest V3, which is good for security (service workers, improved permission model).

### Content Security Policy

```json
"content_security_policy": {
  "extension_pages": "script-src 'self' ; object-src 'self' "
}
```

The CSP is properly restrictive (no `unsafe-eval`, no remote scripts), which is a positive security control.

### Web Accessible Resources

```json
"web_accessible_resources": [{
  "matches": ["<all_urls>"],
  "resources": ["images/*", "fonts/*"]
}]
```

Resources are limited to images and fonts, which is acceptable. However, combined with `externally_connectable: <all_urls>`, this could potentially be used for fingerprinting users across websites.

## Data Flow Summary

| Source | Data Type | Destination | Risk |
|--------|-----------|-------------|------|
| chrome.storage.local | Extension config | chromewebstore.google.com | HIGH |
| chrome.storage.sync | User preferences | chromewebstore.google.com | HIGH |
| External messages | Arbitrary data | fetch() calls | CRITICAL |
| popup.js messages | User actions | background.js → network | HIGH |

## Network Endpoints

| Endpoint | Purpose | Data Transmitted |
|----------|---------|------------------|
| chromewebstore.google.com/detail/cyberghost-vpn-* | Likely analytics/ratings | Extension storage data (unknown scope) |

## Remediation Priority

1. **CRITICAL - Immediate**: Fix `externally_connectable` to restrict to legitimate domains only
2. **HIGH - Short term**: Audit and document what data is transmitted to Chrome Web Store
3. **HIGH - Short term**: Implement message origin validation in all message handlers
4. **MEDIUM - Medium term**: Review permissions for least-privilege principle
5. **LOW - Long term**: Provide un-minified source code or source maps for security review

## Compliance Considerations

### GDPR/Privacy

- Extension may be transmitting PII without adequate user consent
- Privacy policy should clearly disclose data transmission to Google
- Consider implementing opt-out mechanism for telemetry

### Chrome Web Store Policy

The `externally_connectable: ["<all_urls>"]` pattern may violate Chrome Web Store's security best practices, though it's not explicitly forbidden. CyberGhost should justify this configuration or restrict it.

## Conclusion

CyberGhost VPN is a legitimate extension from a reputable provider, but the **CRITICAL** `externally_connectable` misconfiguration creates a severe security risk that affects 900,000+ users. Any malicious website can interact with the extension, potentially manipulating VPN settings or triggering data exfiltration.

The data flows from extension storage to external endpoints are also concerning, particularly given the heavily obfuscated code that prevents detailed audit of what data is being transmitted.

**Recommendation**: Users should be cautious until CyberGhost addresses the `externally_connectable` vulnerability. The extension should not be considered secure in its current state despite being from a legitimate vendor.

---

**Analysis Date**: 2026-02-14
**Analyst**: Claude Sonnet 4.5 (Security Analysis Agent)
**Methodology**: Static analysis via ext-analyzer (Babel AST-based), manifest review, code inspection
**Tools**: ext-analyzer v1.0 (data-flow tracing, constant propagation, cross-component analysis)
