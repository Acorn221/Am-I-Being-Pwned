# Security Analysis: 金山收藏助手 (Kingsoft Bookmark Helper)

**Extension ID:** lanhpcaapacdmofkjpkahckmlkljcdhh
**Version:** 2.0.7
**Users:** 1,000,000+
**Publisher:** Kingsoft/WPS
**Risk Level:** MEDIUM

## Executive Summary

Kingsoft Bookmark Helper is a legitimate web clipper extension from WPS/Kingsoft that allows users to save web pages to their Kingsoft Docs (金山文档) account. While the extension appears to serve its stated purpose without malicious intent, it contains **two high-severity postMessage vulnerabilities** that could allow malicious websites to exploit the extension's privileged capabilities. The extension also uses broad host permissions (`*://*/*`) and cookies access, though these appear limited to legitimate functionality within the Kingsoft ecosystem.

## Vulnerability Analysis

### 1. PostMessage Origin Validation Bypass (HIGH)

**Locations:**
- `kdocs/contentScripts/index.global.js:5911`
- `kdocs/assets/content-script-1b827b1e.js:2935`

**Details:**

Both content scripts register `window.addEventListener("message")` handlers without origin validation. The code implements a MessageChannel-based communication system for cross-context messaging:

```javascript
window.addEventListener("message", s), e === "window" ? setTimeout(o, 0) : o();
```

The handler processes `webext-port-offer` commands from any origin (`"*"`):

```javascript
window.postMessage({
  cmd: "webext-port-offer",
  scope: t,
  context: e
}, "*", [i.port2]);
```

While the code does check that `c !== e` (context doesn't match sender), it does **not validate the message origin**. A malicious website could:

1. Send crafted `webext-port-offer` messages to the content script
2. Establish a MessageChannel port with the extension
3. Potentially trigger extension functionality or exfiltrate data through the established communication channel

**Attack Scenario:**

A malicious page could inject messages matching the expected format to establish unauthorized communication with the extension's privileged context, potentially triggering bookmark saves to attacker-controlled accounts or extracting page content.

**CVSS 3.1:** 7.4 (High)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N

### 2. Cookie Manipulation for CSRF Protection (MEDIUM)

**Location:** `kdocs/contentScripts/index.global.js:7920-7947`

**Details:**

The extension programmatically sets CSRF tokens in cookies for `.kdocs.cn` domain:

```javascript
Le.cookies.set({
  url: zi,
  name: "csrf",
  value: n,
  domain: ".kdocs.cn",
  path: "/",
  secure: !1,      // Not HTTPS-only
  storeId: "0",
  httpOnly: !1     // JavaScript accessible
})
```

Issues:
- CSRF token set with `secure: false` (works over HTTP)
- `httpOnly: false` makes it readable by JavaScript
- Cookie domain is broad (`.kdocs.cn`)

While this appears to be legitimate CSRF protection for API requests, the non-secure, non-httpOnly configuration weakens the security model.

**CVSS 3.1:** 4.3 (Medium)
**Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N

## Permissions Analysis

### High-Risk Permissions

1. **`host_permissions: ["*://*/*"]`**
   - **Risk:** Full access to all websites
   - **Usage:** Content scripts injected on all pages to enable bookmark capture
   - **Justification:** Required for web clipper functionality
   - **Verdict:** Legitimate but overly broad

2. **`cookies`**
   - **Risk:** Can read/write cookies for any site
   - **Usage:** Manages CSRF tokens for kdocs.cn API authentication
   - **Scope:** Observed usage limited to `.kdocs.cn` domain
   - **Verdict:** Legitimate but powerful

3. **`scripting`**
   - **Risk:** Can inject scripts dynamically
   - **Usage:** Likely for content extraction when saving pages
   - **Verdict:** Standard for web clippers

### Standard Permissions
- `contextMenus` - Right-click menu integration
- `tabs` - Tab metadata access
- `storage` - Extension settings
- `activeTab` - Current tab access

## Data Flow Analysis

### Endpoints Contacted

All network activity targets legitimate Kingsoft/WPS infrastructure:

1. **Primary Domain:** `https://www.kdocs.cn`
2. **API Endpoint:** `https://vas-api.kdocs.cn`
3. **Account Service:** `https://account.kdocs.cn`
4. **WPS Account:** `https://account.wps.cn`
5. **File Service:** `https://f.kdocs.cn`
6. **Public Links:** `https://p.kdocs.cn`

### Data Collection

The extension collects:
- **Page Content:** HTML, text, selected fragments (for bookmarking)
- **Page Metadata:** Title, URL (standard for web clipper)
- **User Session:** Cookies/auth tokens for kdocs.cn
- **No PII Exfiltration:** No evidence of harvesting cross-site cookies or sensitive data

### Blacklist Configuration

Extension actively avoids injecting on competitor sites:

```javascript
Yi = ["https://www.wps.cn", "https://kdocs.cn", "https://www.kdocs.cn",
      "https://docs.qq.com", "https://feishu.cn", "https://shimo.im",
      "https://pan.baidu.com", "https://www.weiyun.com", "https://account.wps.cn"]
```

This blacklist prevents the extension from activating on its own domains and major Chinese document/cloud platforms.

## Code Quality Issues

1. **Obfuscation:** Extension uses heavily minified/obfuscated code (marked by ext-analyzer)
2. **Large Bundle Size:** Background script is 3 lines, each 100KB+ (webpack bundling)
3. **Framework Overhead:** Includes full Vue.js, Axios, Element Plus UI library

## Privacy Assessment

### Privacy Policy
- Links to: `https://privacy.wps.cn/policies/privacy/kdocs`
- Chinese language privacy policy for Kingsoft Docs

### Data Handling
- **First-Party Only:** All data sent to Kingsoft/WPS infrastructure
- **No Third-Party Analytics:** No evidence of Google Analytics, tracking pixels, etc.
- **Session Cookies:** Uses `withCredentials: true` for authenticated API calls
- **User Consent:** Displays permission dialog on first use

## Legitimate Functionality Confirmed

The extension's core purpose is genuine:
- Saves web pages/selections to user's Kingsoft Docs account
- Integrates with WPS Office ecosystem (popular in China)
- Provides keyboard shortcut (Alt+R) for quick bookmarking
- Shows UI overlays for folder selection and login

## Risk Mitigation Recommendations

### For Developer (Kingsoft)

1. **Fix PostMessage Vulnerability (Critical):**
   ```javascript
   // Add origin validation
   window.addEventListener("message", function(event) {
     if (event.origin !== "chrome-extension://" + chrome.runtime.id) return;
     // ... process message
   });
   ```

2. **Harden CSRF Cookie:**
   ```javascript
   chrome.cookies.set({
     // ...
     secure: true,    // HTTPS only
     httpOnly: true,  // No JS access
     sameSite: "strict"
   });
   ```

3. **Reduce Host Permissions:** Consider `activeTab` + explicit match patterns for better security model

4. **Remove Obfuscation:** Use source maps for debugging, don't ship minified code to users

### For Users

1. **Low Risk for Current Users:** Extension appears safe for its stated purpose
2. **Trust Required:** Must trust Kingsoft/WPS with bookmarked content
3. **Avoid Sensitive Sites:** Don't use on banking/medical sites due to broad permissions
4. **Update Promptly:** Ensure vulnerabilities are patched when fixed

## Comparison with Industry Standards

**Similar Extensions:**
- Evernote Web Clipper
- Notion Web Clipper
- Pocket

All web clippers require broad permissions, but best-in-class examples:
- Use `activeTab` instead of `*://*/*` where possible
- Implement strict CSP policies
- Validate all cross-context messages
- Minimize cookie access scope

## Conclusion

Kingsoft Bookmark Helper is a **legitimate extension with security vulnerabilities**. The postMessage flaws represent real attack surface that could be exploited by malicious websites to abuse the extension's privileges. However, there is **no evidence of malicious intent** - the extension performs its documented function without data exfiltration or tracking.

**Recommendation:** MEDIUM risk. Safe for general use by Chinese users who trust the WPS ecosystem, but vulnerabilities should be patched. Western users should evaluate whether they need Kingsoft Docs integration.

## Technical Indicators

| Indicator | Value | Risk |
|-----------|-------|------|
| Obfuscated Code | Yes | ⚠️ Medium |
| Broad Permissions | `*://*/*` | ⚠️ Medium |
| Cookie Access | `.kdocs.cn` only | ✓ Low |
| PostMessage Validation | Missing | ⚠️ High |
| Third-Party Endpoints | None | ✓ Clean |
| Known Publisher | Kingsoft/WPS | ✓ Trusted |
| User Base | 1M+ | ✓ Established |

## References

- **webextension-polyfill:** Extension uses Mozilla's WebExtension API polyfill
- **Element Plus UI:** Uses official Vue 3 component library
- **Axios HTTP Client:** Standard HTTP library (no modifications detected)
- **WPS Office:** Legitimate Chinese productivity suite by Kingsoft

---

**Analyst Notes:** Extension represents a typical "powerful but legitimate" web clipper from a major software vendor. The postMessage vulnerabilities are likely developer oversight rather than intentional backdoors. Recommend disclosure to Kingsoft security team and 90-day patch timeline before public disclosure.
