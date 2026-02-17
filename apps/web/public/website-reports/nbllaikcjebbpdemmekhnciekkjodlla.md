# Security Analysis: SkrivaText

**Extension ID:** nbllaikcjebbpdemmekhnciekkjodlla
**Version:** 1.2.10
**Users:** 400,000
**Risk Level:** MEDIUM
**Developer:** Texthelp (Oribi)

## Executive Summary

SkrivaText is a legitimate writing assistance tool developed by Texthelp for Swedish and English spelling/grammar checking. The extension is primarily targeted at users with reading and writing difficulties and integrates with Google Docs and Microsoft Word Online. While the extension serves its stated purpose from a reputable developer, the security analysis identified **14 medium-severity postMessage vulnerabilities** and authentication token transmission patterns that may not be fully disclosed to users.

The extension uses OAuth2/OpenID Connect for authentication via `idp.texthelp.com` and transmits storage data (likely including access tokens) to the identity provider. Additionally, multiple UI components (toolbar, sidebar, options, etc.) implement message handlers without proper origin validation, creating potential attack vectors for malicious web pages to manipulate extension behavior.

## Risk Assessment

**Overall Risk: MEDIUM**

### Vulnerability Breakdown
- **Critical:** 0
- **High:** 0
- **Medium:** 14 (postMessage handlers without origin checks)
- **Low:** 1 (obfuscated code patterns)

### Key Concerns
1. **PostMessage Vulnerabilities** - 14 extension UI pages listen for window messages without validating sender origin
2. **Authentication Token Handling** - Storage data flows to authentication endpoints (likely OAuth tokens)
3. **Code Obfuscation** - Minified/bundled code makes security review difficult
4. **Broad Content Script Injection** - Runs on Google Docs, Office 365, and assessment platforms

## Detailed Findings

### MEDIUM: PostMessage Handlers Without Origin Validation (14 instances)

**Severity:** Medium
**CWE:** CWE-940 (Improper Verification of Source of a Communication Channel)

#### Description
The extension injects multiple UI components (toolbar, sidebar, options panel, login pages, etc.) into web pages as iframes. These components listen for `window.addEventListener("message")` events but do not validate the `event.origin` property before processing messages. This allows any malicious script running on the same page to send arbitrary commands to the extension UI.

#### Affected Files
- `views/toolbar.js` (2 handlers)
- `views/sidebar.js` (3 handlers)
- `views/options.js` (2 handlers)
- `views/lookup.js` (2 handlers)
- `views/login.js` (1 handler)
- `views/login-auth-callback.js` (1 handler)
- `views/improve.js` (1 handler)
- `views/correct.js` (1 handler)
- `views/action-popup.js` (1 handler)

#### Technical Details
The ext-analyzer detected the following pattern across all UI files:

```javascript
window.addEventListener("message", (event) => {
  // Process event.data without checking event.origin
  // Could allow malicious pages to manipulate extension UI
});
```

#### Exploitation Scenario
1. User visits a malicious website while using SkrivaText on Google Docs in another tab
2. Attacker page detects the presence of SkrivaText via web-accessible resources
3. Attacker sends crafted postMessage to extension iframe
4. Extension UI component processes the message without origin validation
5. Potential outcomes:
   - UI state manipulation
   - Triggering unintended extension actions
   - Information disclosure through response messages
   - Confusion attacks (displaying fake prompts/errors)

#### Impact
While the extension's architecture may include secondary validation layers, the lack of origin checking at the window.message level creates an unnecessary attack surface. Given that SkrivaText runs on sensitive contexts (Google Docs with user documents, Office 365), any UI manipulation could lead to phishing attacks or data disclosure.

#### Recommendation
Add origin validation to all postMessage handlers:

```javascript
window.addEventListener("message", (event) => {
  // Validate origin before processing
  const allowedOrigins = [
    chrome.runtime.getURL(""),
    "https://docs.google.com",
    // other trusted origins
  ];

  if (!allowedOrigins.some(origin => event.origin.startsWith(origin))) {
    console.warn("Rejected message from untrusted origin:", event.origin);
    return;
  }

  // Process event.data
});
```

### LOW: Authentication Token Transmission

**Severity:** Low
**CWE:** CWE-359 (Exposure of Private Information)

#### Description
Static analysis detected a data flow where `chrome.storage.local.get()` is called and the retrieved data reaches a `fetch()` call to `idp.texthelp.com`. This pattern is consistent with OAuth2/OpenID Connect token refresh flows.

#### Technical Details
The extension implements OpenID Connect authentication:
- Discovery endpoint: `https://idp.texthelp.com/.well-known/openid-configuration`
- Supports authorization_code grant type with PKCE
- Stores tokens in `chrome.storage.local`
- Implements automatic token refresh

The detected flow:
```
chrome.storage.local.get → fetch(https://idp.texthelp.com/*)
```

This is standard behavior for OAuth-based extensions, where refresh tokens stored locally are sent to the identity provider to obtain new access tokens.

#### Privacy Considerations
The extension's privacy policy should clearly disclose:
- Authentication tokens are stored locally
- Tokens are transmitted to Texthelp's identity provider
- User authentication state is synced with Texthelp's backend services

#### Risk Level: Low
This is expected behavior for a subscription-based SaaS tool requiring user authentication. However, users should be aware that:
1. The extension authenticates users via Texthelp's OAuth service
2. Access tokens grant the extension permission to access Texthelp's backend APIs
3. Token transmission occurs over HTTPS to `idp.texthelp.com`

#### Recommendation
Ensure privacy policy explicitly states:
- "SkrivaText requires user authentication via Texthelp account"
- "Authentication tokens are stored locally and transmitted securely to Texthelp servers"
- Include data retention policies for authentication state

### Positive Security Observations

1. **Manifest V3 Adoption** - Uses modern manifest version with improved security model
2. **Scoped Host Permissions** - Only requests access to specific Texthelp/Oribi domains
3. **Content Security Policy** - Implements CSP for extension pages: `script-src 'self'; object-src 'self'`
4. **No Externally Connectable** - Does not expose APIs to external websites
5. **Minimal Permissions** - Only requests `storage` and `identity` permissions
6. **HTTPS-Only APIs** - All backend communication over HTTPS
7. **Legitimate Developer** - Texthelp is an established assistive technology company
8. **Targeted Content Scripts** - Only injects into Google Docs, Office 365, and specific assessment platforms

## Permissions Analysis

### Declared Permissions
- `storage` - Store user preferences, authentication tokens
- `identity` - OAuth2/OpenID Connect authentication flows

### Host Permissions
- `https://idp.texthelp.com/*` - Identity provider (authentication)
- `https://skrivatext.texthelp.com/*` - Main API backend
- `https://dictionary.oribi.se/*` - Dictionary/translation services

### Content Script Injection
The extension injects content scripts into:
- Google Docs (`*://docs.google.com/document/*`)
- Office 365 Word Online (`*://*.officeapps.live.com/we/wordeditorframe.aspx*`)
- Trelson assessment platform (`*://assessment.trelson.com/*`, `*://app.trelson.dev/*`)

### Web Accessible Resources
The following resources are exposed to all websites:
- `views/action-popup.html`
- `views/correct.html`
- `views/improve.html`
- `views/login-auth-callback.html`
- `views/login.html`
- `views/lookup.html`
- `views/options.html`
- `views/sidebar.html`
- `views/toolbar.html`

These are used for iframe-based UI injection and could be used for extension fingerprinting.

## Network Endpoints

### Authentication & Identity
- `https://idp.texthelp.com/.well-known/openid-configuration` - OpenID Connect discovery
- Token, authorization, userinfo, revocation endpoints (discovered dynamically)

### Application APIs
- `https://skrivatext.texthelp.com/*` - Main backend API (spelling/grammar checking)
- `https://dictionary.oribi.se/*` - Dictionary lookups and translations

## Threat Model

### Attack Vectors
1. **Malicious Web Page → PostMessage Injection** - Moderate likelihood, medium impact
2. **Man-in-the-Middle (HTTPS)** - Low likelihood (all traffic uses HTTPS)
3. **Extension Fingerprinting** - High likelihood (web-accessible resources), low impact
4. **Token Theft via Storage Access** - Low likelihood (requires extension compromise or malicious co-extension)

### Mitigations
- Add origin validation to all postMessage handlers
- Consider using chrome.runtime.connect for trusted cross-frame communication
- Implement message nonce/signature verification for sensitive operations
- Regular security audits of bundled dependencies

## Code Quality Observations

### Obfuscation/Minification
The extension uses webpack/bundler minification, which:
- Makes static analysis difficult
- Obscures actual code behavior
- Is common for TypeScript/React projects but reduces transparency
- Could hide malicious code in supply chain attacks

### Dependencies
Analysis detected the following bundled libraries:
- React (UI framework)
- Classnames (CSS utility)
- Base64 encoding/decoding utilities
- OpenID Connect client library
- Zod (schema validation)

## Recommendations

### For Developer (Texthelp)
1. **High Priority**: Implement origin validation on all `window.addEventListener("message")` handlers
2. **Medium Priority**: Consider migrating to `chrome.runtime.connect()` for trusted extension frame communication
3. **Low Priority**: Publish unminified source code or source maps for transparency
4. **Documentation**: Ensure privacy policy clearly describes authentication token handling

### For Users
1. **Risk Level**: Medium - Safe to use with caution
2. **Suitability**: Appropriate for educational/accessibility purposes from reputable developer
3. **Privacy Awareness**: Understand that the extension authenticates via Texthelp servers and processes document content
4. **Sensitive Data**: Exercise caution when using on highly confidential documents (though this is inherent to any cloud-based writing assistant)

### For Enterprise IT
1. Review Texthelp's data processing agreement and privacy policy
2. Verify compliance with organizational data handling policies
3. Consider network monitoring for traffic to `*.texthelp.com` and `*.oribi.se`
4. Evaluate whether postMessage vulnerabilities pose acceptable risk for organizational use
5. Monitor for extension updates addressing security concerns

## Conclusion

SkrivaText is a **MEDIUM risk** extension from a legitimate developer (Texthelp) providing assistive technology for writing. The primary security concerns are:

1. **14 postMessage handlers without origin validation** - Creates attack surface for malicious web pages
2. **OAuth token transmission** - Standard behavior but should be clearly disclosed

The extension does not exhibit characteristics of malware, data exfiltration, or malicious intent. However, the postMessage vulnerabilities represent a real security gap that should be addressed. Organizations and users should weigh the accessibility benefits against the identified security risks.

**Recommended Action**: Safe to use for intended purpose (writing assistance), but users should be aware of postMessage attack surface. Texthelp should prioritize fixing the origin validation issues in a future update.

---

**Analysis Date:** 2026-02-15
**Analyzer:** ext-analyzer v1.0 + Manual Review
**Methodology:** AST-based static analysis, data flow tracing, manifest review, OSINT research
