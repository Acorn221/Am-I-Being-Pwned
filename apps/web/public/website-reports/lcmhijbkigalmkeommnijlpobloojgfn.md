# Vulnerability Report: Tampermonkey

## Metadata
- **Extension ID**: lcmhijbkigalmkeommnijlpobloojgfn
- **Extension Name**: Tampermonkey
- **Version**: 5.1.1
- **Users**: ~10,000,000+
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Tampermonkey is a legitimate and widely-used userscript manager extension that allows users to install and run custom JavaScript on web pages. With over 10 million users, it is one of the most popular browser extensions. The extension requires extensive permissions (<all_urls>, webRequest, webRequestBlocking, cookies, tabs, etc.) which are necessary for its core functionality of running user-provided scripts on arbitrary websites.

While Tampermonkey is not malicious, its security model contains a medium-severity vulnerability in its postMessage handling. The extension listens for window messages without properly validating the message origin, which could allow malicious websites to inject content into frames controlled by Tampermonkey. Additionally, by design, Tampermonkey executes arbitrary user-provided JavaScript code with elevated privileges (eval, Function constructor), which is an intentional feature but presents inherent security risks if users install malicious scripts.

## Vulnerability Details

### 1. MEDIUM: PostMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: extension.js:9851
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The extension sets up a window message event listener without validating the origin of incoming messages. This allows any website to send messages to Tampermonkey's frames, potentially injecting content into the DOM.

**Evidence**:
```javascript
// extension.js:9851
window.addEventListener("message", (e => {
  let t;
  const i = e.data.clicked || e.data.type,
    s = e.data.amount,
    o = e.data.currency,
    a = e.data.redirect_url;
  if (i)
    if (a && f(a, !0), e.data.success) {
      t = pt(".contrib_iframe");
      const n = t.data("oheight");
      if (!n || n < 0 || n > 1e3) return;
      t.animate({
        height: n
      }, 1e3), X("contributed", i, {
        id: e.data.id
      })
    } else e.data.clicked && (X("clicked", i, {
        amount: s || "?",
        currency: o || "?"
      }), pt(".contrib_button").remove(), n.append(pt('<button class="contrib_button">').text(ot("Ok")).on("click", (() => {
        r()
```

The handler accepts data from any origin and can:
- Set `innerHTML` on elements (from lint.js flows to extension.js)
- Set `src` attributes on elements
- Trigger redirects via `redirect_url`
- Manipulate iframe heights

**Verdict**:
While Tampermonkey has some basic validation (checking height bounds, etc.), the lack of origin checking means a malicious website could craft messages to manipulate the contribution/donation UI or potentially inject content. The impact is limited by the specific context (appears to be donation-related UI), but it represents a security weakness.

### 2. Expected Behavior: Dynamic Code Execution

**Severity**: N/A (By Design)
**Files**: background.js, extension.js, content.js
**CWE**: N/A

**Description**:
Tampermonkey extensively uses `eval()`, `Function()` constructor, and dynamic script injection - this is the core purpose of the extension. It allows users to install and execute arbitrary JavaScript code ("userscripts") on web pages they visit.

**Evidence**:
- Multiple template strings in background.js showing userscript templates with `eval(c.code)` for Babel compilation
- Content script injection mechanisms throughout the codebase
- Dynamic function execution for userscript sandboxing

**Verdict**:
This is not a vulnerability but rather the intended functionality. The security model relies on users only installing scripts from trusted sources. Tampermonkey is a tool - like a text editor or command line - that can be used safely or dangerously depending on what the user chooses to run.

## False Positives Analysis

1. **Obfuscation Flag**: The ext-analyzer flagged the code as "obfuscated". However, this appears to be webpack-bundled/minified code rather than intentional obfuscation for malicious purposes. This is standard for production browser extensions.

2. **eval() Usage**: While the extension uses `eval()` extensively (52 occurrences), this is the core feature of Tampermonkey - it compiles and executes userscripts. This is not malicious behavior.

3. **Extensive Permissions**: Permissions like `<all_urls>`, `webRequest`, `webRequestBlocking`, `cookies`, `tabs` are all necessary for Tampermonkey to:
   - Inject userscripts into any page
   - Intercept and modify web requests (for GM_xmlhttpRequest)
   - Access page cookies for userscript APIs
   - Manage tabs for userscript functionality

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| userscript.zone | Script search/discovery service | Tab URLs for script search (opt-in) | Low - legitimate service |
| tampermonkey.net | Official homepage/updates | Version info, update checks | Low - official domain |

Both domains are legitimate and owned by the Tampermonkey project. The extension appears to use userscript.zone for helping users find scripts for specific websites, and tampermonkey.net for documentation and updates.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
Tampermonkey is a legitimate and well-established browser extension with over 10 million users. It is not malware and serves its stated purpose as a userscript manager. However, it receives a MEDIUM risk rating due to:

1. **PostMessage Vulnerability**: The lack of origin validation in the message handler (extension.js:9851) represents a real security weakness that could be exploited by malicious websites to manipulate the extension's UI or inject content.

2. **Inherent Security Model**: By design, Tampermonkey grants users the ability to run arbitrary JavaScript with elevated permissions. While this is the intended functionality, it means that if users install malicious userscripts, those scripts can:
   - Access all website data
   - Steal cookies and credentials
   - Perform actions on behalf of the user
   - Exfiltrate sensitive information

The MEDIUM rating reflects that while the extension itself is trustworthy, the postMessage vulnerability should be fixed, and users must understand that the security of their browsing depends on only installing userscripts from trusted sources.

**Recommendations**:
1. Add origin validation to all postMessage event listeners
2. Consider implementing Content Security Policy restrictions
3. Users should only install scripts from trusted sources like Greasy Fork or OpenUserJS
