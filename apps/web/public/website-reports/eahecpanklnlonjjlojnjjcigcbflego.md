# Vulnerability Report: ČSOB Electronic Signature

## Metadata
- **Extension ID**: eahecpanklnlonjjlojnjjcigcbflego
- **Extension Name**: ČSOB Electronic Signature
- **Version**: 2.1.5.0
- **Users**: Unknown (Enterprise deployment)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

ČSOB Electronic Signature is a legitimate enterprise browser extension developed for ČSOB bank (Československá obchodní banka) customers in Czech Republic and Slovakia. The extension provides PKI (Public Key Infrastructure) functionality for electronic signing operations using smart cards or other hardware security modules. It serves as a bridge between web-based banking applications and native PKI services through Chrome's native messaging API.

The extension exhibits standard enterprise banking security practices with properly scoped permissions limited to banking domains (*.csob.cz, *.csob.sk, *.ica.cz). The code is clean, well-structured, and implements legitimate banking functionality. One minor security consideration is the broad externally_connectable configuration, which is assessed as low risk given the enterprise context and specific domain restrictions.

## Vulnerability Details

### 1. LOW: Broad externally_connectable Configuration

**Severity**: LOW
**Files**: manifest.json, background.js
**CWE**: CWE-923 (Improper Restriction of Communication Channel to Intended Endpoints)
**Description**: The extension declares an externally_connectable section in manifest.json that allows external websites to communicate with the extension. While this is necessary for the extension's legitimate banking functionality, the configuration includes multiple domains and wildcards.

**Evidence**:
```json
"externally_connectable": {
   "matches": [
      "*://localhost/*",
      "https://*.csob.cz/*",
      "https://*.csob.sk/*",
      "*://*.capgemini.com/*",
      "*://*.ica.cz/*",
      "https://csob--c.vf.force.com/*",
      "https://sf--csobuat--c.sandbox.vf.force.com/*"
   ]
}
```

The background.js implements proper connection handling:
```javascript
if(isFirefox) {
    chrome.runtime.onConnect.addListener(connected);
} else {
    chrome.runtime.onConnectExternal.addListener(connected);
}
```

**Verdict**: This is standard practice for enterprise banking extensions that need to interact with multiple banking and infrastructure domains. The domains are all legitimate and related to ČSOB banking infrastructure (including Capgemini as IT service provider and Salesforce instances for CRM). The extension properly validates connections and implements message authentication. This represents minimal risk given the enterprise deployment context.

## False Positives Analysis

Several patterns might appear suspicious on initial review but are legitimate for this extension type:

1. **Native Messaging**: The extension uses nativeMessaging permission and connects to a host named "cz.ica.icapkiservice.host". This is the expected and proper way to communicate with PKI hardware (smart cards) for electronic signatures.

2. **Cookie Access**: The extension accesses cookies via chrome.cookies.get() API, but only to attach banking session cookies to PKI signing requests. This is necessary for authenticating the signing operation with the banking backend. The code shows proper cookie handling:
   ```javascript
   if(m.purpose == PURPOSE_COOKIE) {
       messageRegister[m.id] = tabId;
       lastMessageSourcePage = tabId;
       addCookieAndSend(m);
   }
   ```

3. **Base64 Encoding**: The code uses base64 encoding for message content, which might look like obfuscation but is standard practice for binary data transmission in JSON messages between the extension and native PKI service.

4. **Obfuscation Flag**: The static analyzer flagged the code as "obfuscated", but inspection of the deobfuscated code shows clean, readable JavaScript with proper variable names and comments. The original code was likely minified for distribution, not intentionally obfuscated.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| clients2.google.com/service/update2/crx | Chrome extension update endpoint | Extension metadata | None - Standard Chrome update |
| *.csob.cz | ČSOB Czech banking domains | PKI signatures, cookies, banking data | Low - Legitimate banking |
| *.csob.sk | ČSOB Slovak banking domains | PKI signatures, cookies, banking data | Low - Legitimate banking |
| *.ica.cz | I.CA PKI service provider | PKI operations, certificate data | Low - Legitimate PKI provider |
| *.capgemini.com | IT infrastructure provider | Technical integration data | Low - Enterprise IT partner |
| *.proebiz.com | Business banking platform | Banking operations data | Low - Legitimate banking platform |
| csob--c.vf.force.com | Salesforce production instance | CRM data | Low - Enterprise CRM |
| sf--csobuat--c.sandbox.vf.force.com | Salesforce UAT instance | Test CRM data | Low - Enterprise testing |
| localhost | Local development/testing | Development data | Low - Local only |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This is a legitimate enterprise banking extension with no significant security or privacy concerns. The extension:

1. **Purpose-appropriate permissions**: All permissions (nativeMessaging, activeTab, storage, cookies) are necessary and properly used for PKI signing operations
2. **Proper scope limitation**: Host permissions are restricted to specific banking and infrastructure domains
3. **Clean implementation**: Code is well-structured with proper error handling and logging controls
4. **Enterprise security practices**: Implements timeout mechanisms, connection management, and proper message routing
5. **No data exfiltration**: All data flows are between legitimate banking services and the local PKI hardware
6. **Transparent functionality**: Extension description accurately represents its PKI signing capabilities
7. **Professional development**: Includes localization (Czech, English), options UI, and proper lifecycle management

The only identified issue is the broad externally_connectable configuration, which is assessed as low risk given:
- All domains are legitimate and related to ČSOB banking operations
- Extension properly validates incoming connections
- This is standard practice for enterprise banking integrations
- The extension is intended for enterprise deployment, not general public use

This extension represents best practices for enterprise PKI extensions and poses minimal security or privacy risk to users within its intended ČSOB banking customer base.
