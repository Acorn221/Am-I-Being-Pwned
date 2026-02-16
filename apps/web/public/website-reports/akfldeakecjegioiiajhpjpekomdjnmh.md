# Vulnerability Report: Web Signer for Barclays

## Metadata
- **Extension ID**: akfldeakecjegioiiajhpjpekomdjnmh
- **Extension Name**: Web Signer for Barclays
- **Version**: 2.3.1.6
- **Users**: ~100,000+
- **Manifest Version**: 3
- **Developer**: Thales Group
- **Analysis Date**: 2026-02-15

## Executive Summary

Web Signer for Barclays is a legitimate enterprise banking security extension developed by Thales Group (formerly Gemalto). The extension provides digital signature functionality for Barclays corporate banking services, integrating with hardware smart card readers via native messaging. The extension operates exclusively on Barclays banking domains and related payment service providers.

This is a clean, purpose-built security tool with no privacy or security concerns. All privileged permissions are justified for its cryptographic signing operations and multi-monitor display handling. The extension does not exfiltrate data, inject ads, or perform any unauthorized operations.

## Vulnerability Details

### No Vulnerabilities Found

After comprehensive static analysis and code review, no security or privacy vulnerabilities were identified. All behaviors are legitimate and appropriate for a banking authentication extension.

## False Positives Analysis

Several patterns that might appear suspicious in other contexts are completely legitimate here:

1. **Native Messaging (`nativeMessaging` permission)**
   - **Purpose**: Communication with local cryptographic signing software (`com.gemalto.esignerwe`)
   - **Legitimate**: Essential for hardware security module (HSM) and smart card reader integration
   - **Evidence**: The extension bridges web-based banking interfaces with physical signing devices

2. **Host Permissions `<all_urls>`**
   - **Scope Limited**: Content scripts only inject on specific Barclays banking domains and authorized payment processors
   - **Justification**: Required for web_accessible_resources and display.system APIs
   - **Evidence**: Manifest line 10-34 restricts actual execution to 24 whitelisted banking domains

3. **System Display API (`system.display` permission)**
   - **Purpose**: Multi-monitor DPI/zoom detection for precise GUI rendering
   - **Legitimate**: Required for WYSIWYS (What You See Is What You Sign) verification
   - **Evidence**: Lines 654-863 in background.js handle screen resolution calculations for signature dialog positioning

4. **Remote Configuration (`software.barclayscorporate.com/check-version`)**
   - **Purpose**: Version checking and security update notifications
   - **Non-invasive**: Only fetches configuration data, does not execute remote code
   - **Evidence**: custom.js line 30, content.js lines 1458-2052 show read-only version checking

5. **Data Sanitization in Logs**
   - **Privacy Protection**: Function `sanitizeMessage()` (background.js lines 102-114) explicitly redacts PINs and sensitive signature data from logs
   - **Best Practice**: Demonstrates security-conscious development

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| software.barclayscorporate.com/check-version | Version checking and update notifications | Extension version, timestamp | CLEAN |

## Code Quality Observations

**Positive Security Practices:**
- PIN redaction in error messages (background.js lines 626-648)
- Message sanitization before logging (background.js lines 102-114)
- Transaction ID validation to prevent message replay
- DOMPurify library included for HTML sanitization
- Proper origin validation for native messaging port

**Architecture:**
- **Background Script**: Acts as relay between content scripts and native application (PKCS#11 cryptographic library)
- **Content Scripts**: Inject signing UI only on whitelisted banking domains
- **Native Host**: `com.gemalto.esignerwe` - local cryptographic signing service

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This is a legitimate enterprise security extension developed by Thales Group, a global leader in digital security and cryptography. All permissions and behaviors are appropriate for a banking authentication tool that integrates with hardware security modules. The extension:

- Only operates on explicitly whitelisted Barclays banking domains
- Uses native messaging exclusively for local cryptographic operations
- Does not exfiltrate user data to third parties
- Implements proper security practices (PIN redaction, message sanitization)
- Has a clear, documented purpose matching its actual behavior
- Is developed by a reputable security company under contract with Barclays

The 100,000+ user base consists of Barclays corporate banking customers who require this extension for secure transaction signing. No security or privacy concerns were identified.

## Recommendations

None. The extension operates as designed with no security issues detected.

## Technical Details

**Static Analysis Results:**
- No suspicious data exfiltration flows detected
- No eval() or dynamic code execution patterns (beyond legitimate jQuery/library code)
- No cookie harvesting or credential theft behaviors
- No malicious network activity
- Obfuscation flag triggered by webpack bundling (not malicious obfuscation)

**Key Files Reviewed:**
- `background.js` - Native messaging relay and transaction management
- `content.js` - DOM integration and signature UI
- `barclays/custom.js` - Barclays-specific configuration
- `manifest.json` - Permissions and content script declarations
