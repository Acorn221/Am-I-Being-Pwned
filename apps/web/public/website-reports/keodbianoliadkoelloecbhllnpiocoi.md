# Vulnerability Report: My IP Hider VPN

## Metadata
- **Extension ID**: keodbianoliadkoelloecbhllnpiocoi
- **Extension Name**: My IP Hider VPN
- **Version**: 12.1.1
- **Users**: Unknown (not in metadata)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

My IP Hider VPN is a VPN/proxy service extension that provides legitimate VPN functionality but contains concerning security behaviors. The extension automatically disables competing proxy extensions without explicit user consent (lines 565-573 of index.js), which constitutes aggressive anti-competitive behavior. Additionally, it collects and stores user credentials (email/password) for remote authentication with the my-safe-net.com service, transmitting these credentials over the network in POST requests. While VPN extensions commonly disable other VPN extensions to avoid proxy conflicts, this extension does so silently without user notification, and the credential handling presents potential privacy and security risks.

The extension requires broad permissions including `management` (to enumerate and disable other extensions), `scripting` (to inject authentication forms), and host access to all URLs. The static analyzer flagged the extension as obfuscated, though examination of the deobfuscated code suggests this is primarily webpack bundling rather than malicious obfuscation.

## Vulnerability Details

### 1. HIGH: Automatic Extension Disabling Without User Consent
**Severity**: HIGH
**Files**: deobfuscated/index.js (lines 565-573)
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension automatically enumerates all installed extensions and disables any that have the `proxy` permission, without informing the user or requesting consent.

**Evidence**:
```javascript
chrome.management.getAll(function(apps) {
  apps.forEach (function(extension) {
    if (extension.id == chrome.runtime.id || extension.enabled == false) return;
    extension.permissions.forEach(function(permission) {
      if (permission == 'proxy')
        chrome.management.setEnabled(extension.id, false);
    });
  });
});
```

**Verdict**: While VPN/proxy extensions commonly need to disable competing proxy extensions to avoid configuration conflicts, this implementation is aggressive and lacks user transparency. The extension disables ALL other proxy extensions immediately on installation without any user notification, consent dialog, or explanation. This behavior goes beyond legitimate conflict prevention and constitutes anti-competitive practice. A more ethical implementation would notify users about conflicts and allow them to choose which extension to use.

### 2. HIGH: User Credential Collection and Remote Transmission
**Severity**: HIGH
**Files**: deobfuscated/lib/ServerAPI.js (lines 181-202, 205-224), deobfuscated/index.js (lines 250-276)
**CWE**: CWE-256 (Plaintext Storage of a Password), CWE-319 (Cleartext Transmission of Sensitive Information)
**Description**: The extension collects user email addresses and passwords, stores them in chrome.storage, and transmits them to my-safe-net.com for authentication. Credentials are stored in plaintext in local storage and sent via POST requests.

**Evidence**:
```javascript
// Authentication with email/password
ServerAPI.Authenticate(
  message.email,
  message.pass,
  function(valid, total, invoice) {
    Preferences.profile.email = message.email;
    Preferences.profile.pass = message.pass;
    // ... stored in chrome.storage.local
  }
)

// ServerAPI Request method transmits credentials
this.Request({
  url: this.serviceUrl,
  content: {
    'op': 'check',
    'email': email,
    'password': pass
  }
})
```

**Verdict**: While credential collection is expected for a paid VPN service, the implementation stores passwords in plaintext in chrome.storage.local rather than using more secure token-based authentication. The extension transmits credentials to `https://my-safe-net.com/misc/proxylistpro/action` (HTTPS is used, mitigating some risk). This is standard practice for commercial VPN extensions, but the plaintext storage presents a privacy risk if the user's device is compromised. Modern best practices would use OAuth tokens or session cookies rather than storing actual passwords.

### 3. LOW: Aggressive User Agent Spoofing
**Severity**: LOW
**Files**: deobfuscated/lib/UserAgentList.js (entire file)
**CWE**: CWE-358 (Improperly Implemented Security Check for Standard)
**Description**: The extension includes a hardcoded list of 300+ user agent strings and can modify the User-Agent header for all requests using declarativeNetRequest, potentially for fingerprinting evasion but also enabling deceptive practices.

**Evidence**:
```javascript
if (isFakeBrowser)
  requestHeaders.push({
    operation: chrome.declarativeNetRequest.HeaderOperation.SET,
    header: 'User-Agent',
    value: userAgent,
  });
```

**Verdict**: User agent spoofing is a standard feature of privacy-focused VPN/proxy extensions and is not inherently malicious. It's actually listed in the extension's settings as "Fake browser name" (line 189 of messages.json), so users are aware of this capability. This is a legitimate privacy feature, though it can be abused for deceptive purposes. Rating this as LOW severity because it's disclosed and optional.

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated," but examining the deobfuscated code shows relatively clean, readable JavaScript. The original extracted files use webpack/bundling patterns typical of modern JavaScript applications, which may have triggered the obfuscation flag. The code structure suggests this is a commercial VPN product rather than malware.

The extension's use of the `management` permission to disable other proxy extensions, while aggressive, is technically justified for VPN applications to avoid proxy configuration conflicts. However, the lack of user consent or notification elevates this from a technical necessity to an ethical concern.

The extension does NOT exhibit typical malware patterns such as:
- Hidden data exfiltration beyond its stated VPN service
- Cryptocurrency mining
- Ad injection or affiliate hijacking
- Keylogging or credential theft (credentials are collected with user knowledge for the service)

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| my-safe-net.com/misc/proxylistpro/action | Primary API for auth, proxy lists, geo data | email, password, operation codes | MEDIUM - Credentials transmitted (HTTPS mitigates) |
| myiphider.com/page/install | Installation thank-you page | Extension ID (via URL param) | LOW - Standard analytics |
| myiphider.com/page/uninstall | Uninstall survey | Extension ID | LOW - Standard analytics |
| myiphider.com/login | User login portal | None (external page) | LOW - User-initiated |
| myiphider.com/thanks?id= | Payment confirmation | Invoice ID | LOW - Transaction tracking |
| chrome.google.com/webstore/detail/.../reviews | Rating prompt | None (external page) | CLEAN - Standard rating request |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

The extension combines two concerning behaviors that elevate it to HIGH risk:

1. **Automatic Extension Disabling**: Silently disabling competing extensions without user consent is anti-competitive and violates user autonomy. While VPN extensions may legitimately need to prevent proxy conflicts, this should be done transparently with user notification.

2. **Credential Storage Practices**: Storing user passwords in plaintext in chrome.storage.local presents a security risk. Modern authentication should use token-based systems or at minimum hash/encrypt stored credentials.

The extension provides legitimate VPN functionality and does not exhibit traditional malware characteristics (no hidden exfiltration, no code execution, no ad injection). However, the combination of aggressive extension management and suboptimal credential handling justifies a HIGH risk rating rather than MEDIUM.

**Mitigation Recommendations**:
- Notify users when disabling competing extensions and allow them to choose
- Implement token-based authentication instead of storing plaintext passwords
- Add user consent dialogs for invasive permissions like `management`
- Provide transparency about what data is collected and transmitted

**For Users**:
- Be aware this extension will automatically disable other VPN/proxy extensions
- Understand that your login credentials are stored on your device
- Review the extension's privacy policy regarding credential handling
- Consider using VPN services that use certificate-based or token-based authentication
