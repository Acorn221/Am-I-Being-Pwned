# Vulnerability Report: AI Sidebar with Deepseek, ChatGPT, Claude and more.

## Metadata
- **Extension ID**: inhcgfpbfdjbjogdfjbclgolkmhnooop
- **Extension Name**: AI Sidebar with Deepseek, ChatGPT, Claude and more.
- **Version**: 1.6.5
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension provides an AI chat sidebar interface powered by aitopia.ai, offering access to multiple AI models including DeepSeek, ChatGPT, and Claude. While the extension's core functionality appears legitimate, static analysis reveals two medium-severity security vulnerabilities and one low-severity issue.

The primary concern is a window.addEventListener("message") handler that accepts messages without origin validation (line 1810 of 1c25847c7fc02d4653adfd0d76358356.js). Combined with static analysis findings showing message data flows to innerHTML sinks, this creates a cross-site scripting (XSS) attack surface. Additionally, the extension declares externally_connectable permissions for two domains (aitopia.ai and chatgptextension.ai), which appears justified for the service's functionality but expands the attack surface.

## Vulnerability Details

### 1. MEDIUM: PostMessage Handler Without Origin Validation
**Severity**: MEDIUM
**Files**: aitopia/assets/1c25847c7fc02d4653adfd0d76358356.js (line 1810)
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The extension registers a window message event listener without validating the origin of incoming messages:

**Evidence**:
```javascript
window.addEventListener(
  "message",
  (s) => (
    console.log("MESSAGE"),
    y.sendMessageListener(s.data, null, null, !0)
  ),
  !1
)
```

This handler accepts messages from any origin and passes the data to `sendMessageListener` without verification. While the code is minified/obfuscated making full flow analysis difficult, the lack of origin checking (e.g., `if (event.origin !== 'https://trusted-domain.com')`) is a security anti-pattern.

**Verdict**: This vulnerability could allow malicious websites to send crafted messages to the extension's content script. The actual exploitability depends on what `sendMessageListener` does with untrusted data, but accepting arbitrary cross-origin messages creates unnecessary risk.

### 2. MEDIUM: Message Data to innerHTML Sink
**Severity**: MEDIUM
**Files**: aitopia/assets/5b6d41c8f3d086816edf7147d0e5be66.js → aitopia/assets/1c25847c7fc02d4653adfd0d76358356.js
**CWE**: CWE-79 (Cross-site Scripting)

**Description**: Static analysis detected data flows where message data reaches innerHTML sinks:

**Evidence** (from ext-analyzer):
```
ATTACK SURFACE:
  [HIGH] window.addEventListener("message") without origin check
    aitopia/assets/1c25847c7fc02d4653adfd0d76358356.js:1810
  message data → *.innerHTML
    from: aitopia/assets/5b6d41c8f3d086816edf7147d0e5be66.js
    ⇒ aitopia/assets/1c25847c7fc02d4653adfd0d76358356.js
```

The analyzer found 20 instances of innerHTML usage in 1c25847c7fc02d4653adfd0d76358356.js, and at least one data flow path from postMessage to innerHTML.

**Verdict**: Combined with the unvalidated postMessage handler, this creates a potential XSS vector where malicious websites could inject HTML/JavaScript into the extension's UI. The extension operates on `<all_urls>`, making this particularly concerning as any website could attempt exploitation.

### 3. LOW: Externally Connectable Domains
**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-668 (Exposure of Resource to Wrong Sphere)

**Description**: The extension declares `externally_connectable` for two wildcard domains:

**Evidence**:
```json
"externally_connectable": {
  "matches": [
    "*://*.aitopia.ai/*",
    "*://*.chatgptextension.ai/*"
  ]
}
```

**Verdict**: This allows any website on these domains (including subdomains) to communicate with the extension via chrome.runtime.sendMessage. This appears to be intentional for the service's backend communication (the partner.json confirms "Powered by aitopia.ai"). However, it expands the attack surface - if either domain is compromised or allows user-generated content on a subdomain, attackers could interact with the extension. This is marked LOW severity as it appears to be a necessary design choice for the extension's functionality.

## False Positives Analysis

**Obfuscation Flag**: The static analyzer flagged the code as "obfuscated," but upon inspection, this appears to be standard webpack/Vite bundling with minified variable names (e.g., `y`, `q`, `H`). This is normal for production JavaScript bundles and not inherently malicious. The code structure shows typical Vue.js/React patterns with ES6 imports.

**Exfiltration Flows**: The analyzer detected 4 "exfiltration" flows showing DOM data (querySelectorAll, getElementById, chrome.storage) reaching fetch() calls. Reviewing the context, these appear to be legitimate flows where the extension:
1. Extracts page content for AI context (expected for an AI assistant)
2. Sends user queries to the aitopia.ai backend
3. Reads storage for user preferences/settings

These patterns are consistent with the extension's stated purpose and do not represent covert data theft.

**Google Endpoint**: The analyzer detected www.google.com as an endpoint. This is likely for scraping Google search results to provide context to AI models, which aligns with AI assistant functionality.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| chat.deepseek.com | DeepSeek AI chat interface | User queries, conversation context | LOW - Official DeepSeek endpoint |
| aitopia.ai | Backend service provider | User data, page content, settings | MEDIUM - Third-party service, see externally_connectable concern |
| chatgptextension.ai | Alternative backend domain | Similar to aitopia.ai | MEDIUM - Secondary domain for same service |
| www.google.com | Search result scraping (inferred) | Likely none (scraping only) | LOW - Read-only scraping |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

The extension has legitimate functionality as an AI chat sidebar but contains two medium-severity vulnerabilities that create unnecessary security risks:

1. The postMessage handler without origin validation violates secure messaging best practices
2. The message-data-to-innerHTML flow creates a potential XSS attack surface
3. The combination of these issues on `<all_urls>` means any website a user visits could attempt to exploit these weaknesses

The extension does NOT exhibit signs of malicious intent - the observed data collection appears consistent with providing AI assistant functionality. However, the security weaknesses could be exploited by malicious third parties to:
- Inject malicious content into the extension's UI
- Potentially access extension storage or capabilities via crafted messages
- Compromise user trust in the extension

**Recommendation**: The developers should:
1. Add strict origin validation to the postMessage handler (whitelist only aitopia.ai/chatgptextension.ai)
2. Sanitize all message data before using innerHTML (use textContent or DOMPurify)
3. Consider using chrome.runtime messaging instead of window.postMessage where possible
4. Implement Content Security Policy restrictions to limit inline script execution

The extension is suitable for use by privacy-conscious users who trust aitopia.ai with their browsing context, but the security vulnerabilities should be addressed to prevent potential exploitation.
