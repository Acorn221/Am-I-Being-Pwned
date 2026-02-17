# Vulnerability Report: SmartOn ID Pass Extension

## Metadata
- **Extension ID**: mogcjkdkjaljhkbkhdkcmjioeingjndl
- **Extension Name**: SmartOn ID Pass Extension
- **Version**: 1.0.3.1
- **Users**: Unknown (Enterprise deployment)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

SmartOn ID Pass Extension is a legitimate enterprise Single Sign-On (SSO) and password management solution developed by Soliton Systems K.K., a Japanese enterprise security company. The extension uses native messaging to communicate with a local desktop application for secure credential storage and retrieval.

The extension has broad permissions (nativeMessaging, webRequest, host permissions for all URLs, scripting) appropriate for its enterprise SSO functionality. All credential handling is encrypted using AES encryption before transmission to the native application. The extension does not exfiltrate data to remote servers and operates entirely through local native messaging. This is a clean, well-architected enterprise security tool with one minor issue related to Content Security Policy configuration.

## Vulnerability Details

### 1. LOW: Encrypted Native Messaging Without CSP Protection

**Severity**: LOW
**Files**: background.js, ssopass.js
**CWE**: CWE-693 (Protection Mechanism Failure)
**Description**: The extension uses AES encryption for all native messaging communication but does not implement Content Security Policy protections. While the encryption is properly implemented with a hardcoded key, the lack of CSP means the extension could potentially be vulnerable to injection attacks if a malicious website could inject code into the extension context.

**Evidence**:
```javascript
// background.js lines 226-244
function F(a) {
  "string" !== typeof a && (a = JSON.stringify(a));
  g || (g = z());
  return CryptoJS.AES.decrypt(a, g, {
    format: formatter
  }).toString(CryptoJS.enc.Utf8)
}

function I(a) {
  "string" !== typeof a && (a = JSON.stringify(a));
  g || (g = z());
  return CryptoJS.AES.encrypt(a, g, {
    format: formatter
  }).toString()
}

function z() {
  return CryptoJS.enc.Base64.parse("X08qTW5VZyNzdEQlJnI9WFYmYi0/M2pYelZ2eHZ5Wi8=").toString(CryptoJS.enc.Utf8)
}
```

The encryption key is hardcoded in Base64 format. While this is necessary for the extension to function, the manifest does not specify a Content Security Policy to prevent script injection.

**Verdict**: This is a minor issue in the context of an enterprise deployment where the extension is distributed through managed Chrome installations. The risk is low because:
1. The extension uses proper encryption for all native messaging
2. Enterprise deployments typically have additional security controls
3. No remote code execution or dynamic script loading is present
4. The extension does not communicate with external servers

## False Positives Analysis

Several patterns that might appear suspicious are actually legitimate for an enterprise SSO tool:

1. **All URLs host permissions**: Required to inject credentials into any website the user visits for SSO functionality
2. **webRequest and webRequestAuthProvider**: Required to intercept HTTP Basic Authentication prompts and automatically fill credentials
3. **Content script on all frames**: Required to detect login forms across all websites and iframes
4. **Native messaging**: Core functionality for communicating with the local desktop credential vault
5. **Scripting permission**: Required to inject form-filling logic into web pages

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native messaging (jp.co.soliton.smarton.id.pass) | Local desktop app communication | Encrypted SSO requests, URL, tab info | None (local only) |

No remote API endpoints detected. All communication is between the browser extension and the local native application.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This is a legitimate enterprise SSO and password management extension from a reputable Japanese security vendor (Soliton Systems K.K.). The extension:

1. **Proper Architecture**: Uses native messaging for secure credential storage rather than storing credentials in the extension itself
2. **Encryption**: All native messaging communication is encrypted using AES
3. **No Data Exfiltration**: Does not send any data to remote servers
4. **Appropriate Permissions**: All permissions are justified for its SSO functionality
5. **Enterprise Context**: Designed for managed enterprise deployments with homepage pointing to official vendor website (soliton.co.jp)

The only security consideration is the lack of Content Security Policy, which is a minor issue given the enterprise deployment context and absence of dynamic code loading or remote script execution.

**Recommendation**: This extension is safe for enterprise deployment. Organizations using this extension should ensure it is deployed through managed Chrome policies and that the native application component is properly secured.
