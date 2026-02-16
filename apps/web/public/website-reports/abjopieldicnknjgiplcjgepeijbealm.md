# Vulnerability Report: Single Sign-on Assistant

## Metadata
- **Extension ID**: abjopieldicnknjgiplcjgepeijbealm
- **Extension Name**: Single Sign-on Assistant
- **Version**: 3.5.1
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Single Sign-on Assistant is a legitimate enterprise authentication extension developed by Micro Focus (now Open Text) for Access Manager, CloudAccess, and SecureLogin products. The extension provides automated single sign-on capabilities for corporate environments by managing credentials through a native host application and enterprise identity provider servers. While the extension has broad permissions (including `<all_urls>` and `nativeMessaging`), these are justified by its enterprise SSO functionality. The extension exhibits two minor security issues: a CSP configuration that allows `wasm-unsafe-eval` and postMessage handlers without strict origin validation. These pose minimal risk in the intended enterprise deployment context.

The extension's architecture relies on native messaging to communicate with a local SecureLogin/Access Manager client, which handles actual credential storage and policy enforcement. Web-accessible resources are properly scoped, and the extension only operates when connected to configured enterprise identity providers.

## Vulnerability Details

### 1. LOW: Content Security Policy Allows WASM Unsafe Eval

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-749 (Exposed Dangerous Method or Function)
**Description**: The extension's CSP includes `wasm-unsafe-eval` which allows WebAssembly compilation without requiring `unsafe-eval` for general JavaScript evaluation.

**Evidence**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
}
```

**Verdict**: This is a minor configuration issue. The CSP still blocks inline scripts and eval() for JavaScript. The `wasm-unsafe-eval` directive is more permissive than necessary but does not enable arbitrary code execution in the extension's current codebase, which does not use WebAssembly. This would only be exploitable if combined with another vulnerability that allows injection of malicious WASM modules.

### 2. LOW: PostMessage Handler Without Strict Origin Validation

**Severity**: LOW
**Files**: Content.min.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension listens for postMessage events in the credential prompt dialog functionality without strict origin validation.

**Evidence**:
```javascript
window.addEventListener("message",function(a){
  if(a.source==window&&a.data&&"ssoa"==a.data.id)
    switch(a.data.message){
      case "ssoa-cancel-button":k.removeCredentialPromptDialog();break;
      case "ssoa-save-button":
        a=document.getElementById("ssoa-username-field").value;
        const b=document.getElementById("ssoa-password-field").value;
        a&&b?k.bSSOSaveCredentials(a,b):window.location.reload()
    }
})
```

**Verdict**: The handler only processes messages where `a.source==window`, meaning messages must originate from the same window object, not external frames or origins. While best practice would include explicit origin checking, this same-window restriction significantly limits the attack surface. The messages only trigger UI actions (dialog removal) or credential save flows that still require user input from DOM elements. Not a significant security risk in practice.

## False Positives Analysis

### Native Messaging Communication
The extension makes extensive use of `chrome.runtime.connectNative("com.netiq.slchromehost")` to communicate with a native application. This is **not** malicious data exfiltration but rather the core architectural pattern for enterprise SSO. The native host handles credential storage, policy enforcement, and script execution according to administrator configuration.

### Broad Permissions
Permissions like `<all_urls>`, `webRequest`, and `tabs` are **necessary and appropriate** for an enterprise SSO solution that needs to:
- Intercept HTTP Basic Auth challenges on any domain
- Inject content scripts to detect and fill login forms
- Communicate with enterprise IDP servers

### Remote Endpoints
The extension communicates with enterprise identity provider endpoints configured by administrators:
- `/nidp/basicsso/formfill/metadata` (Access Manager)
- `/osp/a/t1/auth/app/formfill/form/` (CloudAccess)

These are **not** unauthorized data exfiltration endpoints but legitimate API calls to retrieve form-fill metadata and credential policies from the user's corporate SSO server.

### Dynamic Code Patterns
The extension's sandbox functionality (`sandbox.getScript`) retrieves and executes automation scripts from the native host. This is **expected behavior** for an enterprise scripting platform like SecureLogin and is protected by the requirement that scripts must be approved by enterprise administrators and stored in the native credential vault.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| clients2.google.com/service/update2/crx | Chrome extension auto-update | Extension ID, version | None - Standard Chrome update mechanism |
| www.netiq.com/solutions/identity-access-management/ | Homepage link in manifest | None | None - Documentation link only |
| [Admin-configured IDP]/nidp/basicsso/formfill/* | Access Manager SSO metadata/credentials | Session cookies, credential requests | Low - Enterprise authenticated endpoints |
| [Admin-configured IDP]/osp/a/t1/auth/app/formfill/* | CloudAccess SSO metadata/credentials | Session cookies, credential requests | Low - Enterprise authenticated endpoints |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This is a legitimate enterprise identity and access management extension from a well-known vendor (Micro Focus/Open Text). The extension's broad permissions and native messaging capabilities are appropriate and necessary for its stated purpose of providing automated single sign-on in corporate environments.

The two identified vulnerabilities are minor:
1. The CSP could be stricter by removing `wasm-unsafe-eval`, but this doesn't create immediate exploitability
2. PostMessage handlers could add explicit origin checks, but the same-window restriction provides adequate protection

The extension is designed for managed enterprise deployments where administrators control:
- Which applications receive SSO configuration
- What credentials are stored in the native vault
- Which automation scripts can execute
- IDP server endpoints

For enterprises using Micro Focus/Open Text Access Manager, CloudAccess, or SecureLogin products, this extension provides legitimate value. It should only be installed in environments where the corresponding native host application is properly configured and managed by IT administrators.

**Recommendation**: CLEAN for enterprise users with proper deployment. Individual consumers should not install this extension as it requires enterprise infrastructure to function.
