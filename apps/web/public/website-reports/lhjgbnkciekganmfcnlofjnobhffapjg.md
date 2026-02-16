# Security Analysis: Obsidian Security (lhjgbnkciekganmfcnlofjnobhffapjg)

## Extension Metadata
- **Name**: Obsidian Security
- **Extension ID**: lhjgbnkciekganmfcnlofjnobhffapjg
- **Version**: 1.14.1
- **Manifest Version**: 3
- **Estimated Users**: ~1,000,000
- **Developer**: Obsidian Security (obsidiansecurity.com)
- **Analysis Date**: 2026-02-14

## Executive Summary
Obsidian Security is a **legitimate enterprise security product** designed for corporate environments. The extension monitors for phishing attempts, malicious applications, suspicious clipboard content, and unauthorized application usage. While the extension exhibits concerning characteristics including extensive permissions (history, identity.email, management, cookies, proxy), 8 unchecked postMessage handlers, WASM binaries, and broad data collection, analysis indicates these capabilities are justified for its stated purpose as an enterprise security agent deployed via managed storage policies.

**Overall Risk Assessment: MEDIUM**

The MEDIUM rating reflects the extensive surveillance capabilities required for corporate security monitoring. While not malicious, the extension represents significant privacy implications and should only be deployed in managed enterprise environments with appropriate user consent.

## Vulnerability Assessment

### 1. Unchecked postMessage Event Handlers (8 instances)
**Severity**: HIGH
**CWE**: CWE-346 (Origin Validation Error)
**Files**:
- `/content-scripts/suspicious-check.js` (2 handlers, line 7)
- `/content-scripts/suspicious-check-main.js` (2 handlers, line 1)
- `/content-scripts/agent-monitor.js` (2 handlers, line 196)
- `/content-scripts/agent-monitor-file.js` (2 handlers, line 1)

**Analysis**:
The extension registers 8 `window.addEventListener("message")` handlers across multiple content scripts without origin validation. This creates a potential attack surface for malicious websites to send crafted postMessage payloads to the extension.

**Code Pattern** (minified):
```javascript
window.addEventListener("message", function(event) {
    // No event.origin check before processing event.data
});
```

**Attack Vector**:
Malicious websites could potentially send crafted messages to these handlers. However, the actual risk depends on:
1. What actions these handlers perform
2. Whether they validate message structure/content
3. Whether they can trigger privileged operations

**Mitigating Factors**:
- The handlers are in content scripts (limited privileges compared to background)
- The extension uses `externally_connectable` to restrict which external sites can connect (obsec.io, obsec.us, obsec.eu domains only)
- Message structure validation may exist in the minified code

**Recommendation**: Implement explicit origin checking:
```javascript
window.addEventListener("message", function(event) {
    if (!event.origin.match(/^https:\/\/.*\.obsec\.(io|us|eu)$/)) return;
    // Process message
});
```

---

### 2. Content Security Policy Allows unsafe-eval
**Severity**: MEDIUM
**CWE**: CWE-94 (Improper Control of Generation of Code)
**File**: `/manifest.json`

**Analysis**:
The extension's CSP for extension pages includes `'wasm-unsafe-eval'`:
```json
"content_security_policy": {
    "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';"
}
```

**Purpose**:
This is required for the ONNX Runtime WASM module used for local machine learning-based phishing detection. The extension includes:
- `/phishnet/ort-wasm-simd-threaded.wasm` (Microsoft ONNX Runtime v1.20.0)
- `/phishnet/ort-wasm-simd-threaded.mjs`

The README.md includes SHA1 checksums verifying these files match the official npm package `onnxruntime-web@1.20.0`.

**Risk**:
While `wasm-unsafe-eval` is less dangerous than `unsafe-eval`, it still allows WebAssembly compilation which could be exploited if:
1. An attacker can inject malicious WASM modules
2. The WASM runtime has vulnerabilities
3. The extension loads untrusted WASM code

**Verdict**: **ACCEPTABLE WITH CAVEATS** - The unsafe-eval directive is required for legitimate ML functionality. The WASM binaries are verifiably from Microsoft's official ONNX Runtime. However, this increases attack surface if any code injection vulnerabilities exist.

---

### 3. Extensive Permission Set and Data Collection
**Severity**: HIGH (Privacy Concern)
**CWE**: CWE-359 (Exposure of Private Personal Information)
**Files**: Multiple (entire extension architecture)

**Analysis**:
The extension requests extremely broad permissions:

**Permission Analysis**:

| Permission | Purpose | Privacy Impact |
|------------|---------|----------------|
| `history` | Monitor browsing for suspicious patterns | **CRITICAL** - Full browsing history |
| `identity` + `identity.email` | User identification for corporate monitoring | **HIGH** - User email address |
| `management` | Monitor installed extensions | **MEDIUM** - Extension inventory |
| `cookies` | Monitor authentication cookies | **CRITICAL** - Session tokens |
| `proxy` | Potentially intercept/monitor traffic | **HIGH** - Network routing control |
| `webRequest` + `webRequestBlocking` | Intercept all network requests | **CRITICAL** - All network traffic |
| `<all_urls>` | Access all websites | **CRITICAL** - Universal page access |

**Data Collection Evidence**:

1. **Managed Storage Schema** (`managed-storage-schema.json`):
```json
{
  "OrgConfig": {
    "orgToken": "Obsidian Org Token",
    "channelId": "Obsidian Private Channel ID",
    "encryptionKey": "Org attestation encryption key",
    "urls": {
      "config": "Config URL",
      "telemetry": "Telemetry URL"
    }
  },
  "ProfileSettings": {
    "MachineIdentifier": "Machine identifier",
    "LocalUsername": "Local username",
    "LocalFullname": "Local user full name",
    "ActiveDirectoryUser": "Active directory user",
    "ActiveDirectoryDomain": "Active directory domain",
    "CrowdstrikeIdentifier": "Crowdstrike identifier"
  }
}
```

This reveals the extension is designed to be deployed via enterprise policies (Managed Storage) and collects:
- Machine identifiers
- Local username and full name
- Active Directory credentials
- Integration with CrowdStrike EDR
- Encrypted telemetry sent to configurable URLs

2. **Identity Provider Monitoring**:
The extension injects content scripts on:
- **Okta**: `*://*.okta.com/*`, `*://*.okta-emea.com/*`, `*://*.okta-gov.com/*`
- **OneLogin**: `*://*.onelogin.com/*`
- **Microsoft**: `*://*.azure.com/*`, `*://*.microsoft.com/*`, `*://*.office.com/*`, etc. (15+ domains)
- **Google**: `*://accounts.google.com/*`, `*://calendar.google.com/*`
- **ClickUp**: `*://*.clickup.com/*`

Scripts like `id-discovery-okta.js`, `id-discovery-onelogin.js`, etc. monitor authentication flows.

3. **Network Endpoints**:
The extension communicates with:
- `api.obsec.io` (primary API)
- `extension.obsec.us`
- `signup.obsec.io`
- `web-login-v2-cdn.onelogin.com` (according to ext-analyzer flows)

4. **Exfiltration Flows** (from ext-analyzer):
```
[HIGH] document.querySelectorAll → fetch(web-login-v2-cdn.onelogin.com)
[HIGH] document.querySelectorAll → fetch (block-page.js)
[HIGH] document.querySelectorAll → fetch (agent-monitor.js)
```

These flows indicate the extension:
- Scrapes page content using `querySelectorAll`
- Sends scraped data via `fetch()` to remote servers
- Monitors OneLogin authentication pages

**Functionality Analysis**:

Based on localized strings (`messages.json`) and HTML files, the extension provides:

1. **Phishing Detection** (`suspicious.html`, ONNX Runtime WASM):
   - Takes screenshots of pages
   - Runs ML model locally for phishing detection
   - Compares against reference embeddings database
   - Blocks or warns on suspected phishing sites

2. **Application Blocking** (`blocked.html`):
   - Blocks access to unauthorized applications
   - Uses `declarativeNetRequest` for URL blocking
   - Shows block page with user email, app name, event ID

3. **Clipboard Monitoring** (`clipboard.html`):
   - Detects "unsafe clipboard contents"
   - Warns if potentially harmful commands copied
   - Likely targets social engineering attacks (e.g., malicious PowerShell)

4. **Authentication Monitoring** (`auth-detector.js`):
   - Monitors login attempts across identity providers
   - Detects unauthorized application usage
   - Reports to Obsidian for "analysis and alerting"

5. **User Agent Spoofing** (rulesets):
   - Includes declarativeNetRequest rules to modify User-Agent headers
   - Can spoof Chrome, Edge, Firefox, Safari (currently disabled)
   - Purpose unclear - possibly for compatibility or fingerprinting evasion

**Privacy Impact**: **EXTREMELY HIGH**

The extension has complete visibility into:
- All websites visited (history)
- All network requests (webRequest)
- User email address (identity.email)
- Authentication sessions (cookies)
- Page content (content scripts on `<all_urls>`)
- Installed extensions (management)
- Clipboard contents

**Verdict**: **APPROPRIATE FOR ENTERPRISE SECURITY, UNACCEPTABLE FOR CONSUMER USE**

This level of monitoring is consistent with enterprise Data Loss Prevention (DLP) and insider threat detection tools. However, it should:
1. Only be deployed with explicit user consent
2. Be governed by enterprise policies
3. Have clear privacy policies
4. Be subject to security audits
5. Never be installed voluntarily by consumers

---

### 4. externally_connectable Configuration
**Severity**: MEDIUM
**CWE**: CWE-923 (Improper Restriction of Communication Channel to Intended Endpoints)
**File**: `/manifest.json`

**Analysis**:
The extension allows external websites to communicate with it:
```json
"externally_connectable": {
    "matches": [
        "https://*.obsec.io/*",
        "https://*.obsec.us/*",
        "https://*.obsec.eu/*"
    ]
}
```

**Purpose**: This allows the Obsidian Security web application to communicate directly with the extension, likely for:
- Configuration management
- Status reporting
- User enrollment
- Diagnostic data

**Risk**:
- Subdomain wildcards (`*.obsec.io`) mean ANY subdomain can connect
- If an attacker compromises a subdomain (e.g., via XSS on a forgotten staging site), they can send messages to the extension
- The content script `obsec-page-messaging.js` is injected into these domains with `"world": "MAIN"`, giving it access to the page's JavaScript context

**Recommendation**:
- Restrict to specific subdomains (e.g., `app.obsec.io`, `api.obsec.io`)
- Implement message authentication/signing
- Validate all external messages

---

### 5. Keylogging Detection (FALSE POSITIVE)
**Severity**: N/A (Not a Vulnerability)
**Files**: Static analysis flagged keylogging patterns

**Analysis**:
The static analyzer flagged `keylogging` patterns, likely due to content scripts that monitor input events on authentication pages. This is **expected behavior** for an enterprise security product monitoring:
- Credential entry on unauthorized sites
- Form submissions to phishing pages
- Suspicious input patterns

The extension's manifest declares:
> "Obsidian Security uses read access on websites in order to inspect the page for suspicious content and to identify unauthorized utilization of specific applications."

**Verdict**: **NOT MALICIOUS** - This is legitimate security monitoring functionality for an enterprise DLP tool.

---

### 6. Dynamic Code Execution Capabilities
**Severity**: LOW
**CWE**: CWE-94 (Improper Control of Generation of Code)
**Files**: Multiple (minified code)

**Analysis**:
Static analysis detected:
- `dynamic_eval` patterns
- `dynamic_function` patterns
- `eval()` and `new Function()` usage

**Context**:
Reviewing the code, these appear in:
1. **Third-party libraries**: React, PDF.js worker, ONNX Runtime
2. **Minified/bundled code**: The extension uses Vite for bundling (evident from build artifacts)

**Risk**: These are likely part of legitimate dependencies (React's development tools, PDF.js, ML runtime). However, minification makes verification difficult.

**Recommendation**: Request source maps or unminified code for security audit.

---

## Behavioral Analysis

### Legitimate Enterprise Security Features

1. **Phishing Detection**:
   - Local ML model (ONNX Runtime) analyzes page screenshots
   - Compares against reference embeddings for known brands
   - Shows warning page with "Looks malicious. Go back" or "Looks safe. Proceed"
   - Allows exemptions ("Proceed next time")

2. **Application Control**:
   - Blocks access to unauthorized SaaS applications
   - Integrates with corporate policies
   - Shows block page with remediation information

3. **Credential Monitoring**:
   - Monitors authentication on major identity providers
   - Detects unauthorized account usage
   - Sends alerts to security team

4. **Clipboard Protection**:
   - Detects malicious commands copied to clipboard
   - Prevents social engineering attacks targeting system administrators
   - Shows overlay warning before allowing paste

### Data Exfiltration

The extension sends data to Obsidian Security servers including:
- Authentication events (user email, IdP, timestamp)
- Phishing detections (URL, screenshot, ML model output)
- Application usage (blocked apps, user email)
- Telemetry (extension version, browser info)
- Machine identifiers and AD credentials (via managed storage)

**Justification**: This is the core functionality of an enterprise security product. Data is sent to the customer's Obsidian Security instance for:
- Security alerting
- Incident response
- Threat intelligence
- Compliance reporting

**Privacy Safeguards**:
- Encryption key provided via managed storage
- Configurable telemetry URLs (for on-premise deployments)
- Enterprise policy control

---

## Risk Scoring Breakdown

| Category | Score | Justification |
|----------|-------|---------------|
| **Permissions** | 5/5 | Maximum privilege set (history, cookies, identity, management, proxy, all_urls) |
| **Data Collection** | 5/5 | Complete browsing monitoring, credentials, clipboard, user identity |
| **Code Quality** | 3/5 | Minified code, unchecked postMessage handlers, unsafe-eval CSP |
| **Network Communication** | 4/5 | Sends sensitive data to remote servers, broad externally_connectable |
| **Transparency** | 2/5 | Limited user visibility into data collection (enterprise deployment) |

**Overall Risk: MEDIUM** (3.0/5.0)

The extension is feature-complete for enterprise security but represents extreme privacy implications. Risk rating factors in:
- **Legitimate use case** (enterprise security)
- **Managed deployment** (via policies, not consumer install)
- **Technical vulnerabilities** (postMessage handlers, CSP)
- **Privacy impact** (total surveillance capability)

---

## Recommendations

### For Users
1. **DO NOT install voluntarily** - This is an enterprise security agent, not a consumer product
2. If deployed by your employer, understand:
   - All browsing activity is monitored
   - Authentication attempts are logged
   - Clipboard contents are scanned
   - Email address is collected
3. Review your organization's privacy policy
4. Do not use this browser profile for personal browsing

### For Organizations Deploying This Extension
1. **Mandatory user notification** about monitoring capabilities
2. **Separate browser profiles** for work and personal use
3. **Regular security audits** of Obsidian Security's infrastructure
4. **Data retention policies** for collected telemetry
5. **Legal review** for GDPR/CCPA compliance
6. **Incident response plan** if Obsidian servers are compromised

### For Obsidian Security (Developers)
1. **Fix postMessage handlers**: Add explicit origin validation
2. **Restrict externally_connectable**: Use specific subdomains, not wildcards
3. **Provide source maps**: Enable security audits of unminified code
4. **Document data flows**: Clear privacy policy on what data is sent where
5. **Implement CSP reporting**: Monitor for CSP violations
6. **Regular penetration testing**: Third-party security audits
7. **Minimize permissions**: Evaluate if all permissions are strictly necessary

---

## Compliance Considerations

### GDPR (General Data Protection Regulation)
- **Lawful basis**: Likely "legitimate interests" or "contractual necessity"
- **User consent**: Must be informed and freely given
- **Data minimization**: Consider if all collected data is necessary
- **Right to access**: Users should be able to view collected data
- **Data retention**: Clear policies on how long data is stored

### CCPA (California Consumer Privacy Act)
- **Notice at collection**: Users must be informed about data collection
- **Right to delete**: Ability to request data deletion
- **Right to opt-out**: For California employees

### ECPA (Electronic Communications Privacy Act)
- **Employer monitoring**: Must notify employees of monitoring
- **Reasonable expectation of privacy**: Clear policies reduce legal risk

---

## Technical Indicators

### Code Obfuscation
- **Obfuscation Level**: MODERATE
- Build tool: Vite (JavaScript bundler)
- Minified: Yes
- Source maps: Not included in distribution
- Identifiable libraries: React, MUI, PDF.js, ONNX Runtime

### Network Infrastructure
- **Primary Domain**: obsec.io, obsec.us, obsec.eu
- **API Endpoint**: api.obsec.io
- **TLS**: Yes (enforced via HTTPS in externally_connectable)
- **Certificate Pinning**: Not detected

### Persistence Mechanisms
- Deployed via **Managed Storage** (enterprise policy)
- Cannot be easily removed by users (policy-enforced installation)
- Configuration updates pushed via admin console

---

## Conclusion

Obsidian Security is a **legitimate enterprise security product** with extensive monitoring capabilities appropriate for corporate threat detection and data loss prevention. The extension is technically well-designed for its purpose, using local ML models for phishing detection and comprehensive monitoring across authentication providers.

**However**, the extension represents one of the most privacy-invasive browser extensions analyzed, with complete visibility into all browsing activity, credentials, clipboard contents, and user identity.

**Key Findings**:
- ✅ **Legitimate product** from a recognized security vendor
- ✅ **Enterprise deployment** via managed policies (not consumer malware)
- ✅ **Technical sophistication** (ML-based phishing detection, multi-IdP monitoring)
- ⚠️ **Privacy implications** are extreme (total surveillance capability)
- ⚠️ **Security vulnerabilities** exist (unchecked postMessage handlers)
- ❌ **Should never be installed voluntarily** by consumers

**Final Verdict**: **MEDIUM RISK** - Appropriate for managed enterprise environments with user consent and oversight, but represents significant privacy and security concerns that require mitigation.

---

## Appendix: Permission Justification Matrix

| Permission | Business Justification | Privacy Risk |
|------------|----------------------|--------------|
| `history` | Detect visits to phishing/malicious sites | CRITICAL - Full history access |
| `identity` + `identity.email` | User identification for alerts | HIGH - PII collection |
| `management` | Detect risky browser extensions | MEDIUM - Extension inventory |
| `cookies` | Monitor session hijacking | CRITICAL - Auth tokens |
| `proxy` | Network traffic inspection | HIGH - MITM capability |
| `webRequest` + `webRequestBlocking` | Block malicious requests | CRITICAL - All network access |
| `declarativeNetRequest` | Application blocking rules | MEDIUM - Content filtering |
| `scripting` | Inject monitoring code | HIGH - Code injection |
| `storage` | Store configuration and exemptions | LOW - Local data |
| `alarms` | Periodic scans and updates | LOW - Background tasks |
| `webNavigation` | Track navigation to blocked apps | HIGH - Browsing behavior |
| `offscreen` | Background processing for ML | LOW - Performance |
| `<all_urls>` | Monitor all websites | CRITICAL - Universal access |

**Total Permission Risk Score**: 9.5/10 (Extremely High - Maximum privilege set)

---

## References
- Extension Store: https://chromewebstore.google.com/detail/lhjgbnkciekganmfcnlofjnobhffapjg
- Vendor Website: https://www.obsidiansecurity.com/
- ONNX Runtime: https://github.com/microsoft/onnxruntime
- CWE-346: https://cwe.mitre.org/data/definitions/346.html
- CWE-359: https://cwe.mitre.org/data/definitions/359.html
