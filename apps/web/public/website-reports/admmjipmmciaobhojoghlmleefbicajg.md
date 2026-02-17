# Norton Password Manager - Security Analysis Report

## Extension Metadata

- **Extension Name**: Norton Password Manager
- **Extension ID**: admmjipmmciaobhojoghlmleefbicajg
- **Version**: 8.2.5.1175
- **User Count**: ~5,000,000
- **Developer**: Symantec Corporation
- **Manifest Version**: 3

## Executive Summary

Norton Password Manager is a legitimate password management extension from a reputable security vendor (Symantec/NortonLifeLock). The extension requires extensive permissions as part of its intended functionality to manage passwords across all websites. After comprehensive analysis, **no malicious behavior or critical vulnerabilities were identified**. The extension follows security best practices for a password manager, including proper encryption, secure communication with backend services, and use of legitimate AWS infrastructure.

**Overall Risk Assessment**: **CLEAN**

The extension is invasive by design (password managers must access credentials on all sites), but serves its intended purpose without malicious behavior.

## Manifest Analysis

### Permissions
- **contextMenus**: For right-click password fill options
- **notifications**: User notifications for password alerts
- **storage**: Store encrypted vault metadata
- **tabs**: Access to tab information for password autofill
- **webNavigation**: Detect page loads for form detection
- **webRequest**: Monitor requests (likely for secure form detection)
- **alarms**: Scheduled tasks (sync, security checks)
- **clipboardWrite**: Copy passwords to clipboard
- **scripting**: Inject content scripts dynamically
- **host_permissions**: `<all_urls>` - Required for password autofill on any site

### Content Security Policy
- Default CSP (secure)
- No unsafe-eval or unsafe-inline detected

### Content Scripts
1. **Global content script** (`content/cs.js`): Runs on `<all_urls>` for form detection and autofill
2. **Site-specific scripts**: Custom form handlers for 30+ websites (Amazon, Citi, Bank of America, etc.)
3. **Norton domain listeners**: `cctListener.js` and `nslListener.js` for Norton SSO integration

**Verdict**: Permissions are appropriate for a password manager. `<all_urls>` access is necessary for the core functionality.

## Vulnerability Analysis

### 1. No Dynamic Code Execution
**Severity**: N/A
**Status**: PASS

**Finding**: No use of `eval()`, `new Function()`, or other dynamic code execution detected.

**Verdict**: Clean - No code injection vectors identified.

---

### 2. Secure Network Communication
**Severity**: N/A
**Status**: PASS

**API Endpoints**:
| Endpoint | Purpose | Security |
|----------|---------|----------|
| `https://gz0s1l0bj0.execute-api.us-east-1.amazonaws.com/PROD` | AWS API Gateway for vault operations | HTTPS + AWS SigV4 auth |
| `https://login.norton.com/sso/oidc1/token` | OIDC authentication | HTTPS |
| `https://cloudconnect2.norton.com/*` | Cloud sync service | HTTPS |
| `https://identitysafe.norton.com/*` | Vault portal | HTTPS |
| `https://accesstoken.idsafe.norton.com/` | Token service | HTTPS |

**Finding**: All network communication uses HTTPS. AWS API Gateway endpoints are authenticated with AWS Signature Version 4 (SigV4). Authentication uses OIDC standard with proper token management.

**Code Evidence** (`apiGateway/apigClient.js`):
```javascript
var t="https://gz0s1l0bj0.execute-api.us-east-1.amazonaws.com/PROD"
// ... SigV4 authentication implementation
serviceName:"execute-api",region:e.region,endpoint:r
```

**Verdict**: Clean - Secure backend infrastructure with proper authentication.

---

### 3. Encryption Implementation
**Severity**: N/A
**Status**: PASS

**Finding**: Extension uses node-forge library for AES encryption with proper cipher modes (CBC, GCM, CTR). VaultSDK.worker.js implements secure cryptographic operations in a Web Worker for isolation.

**Technologies**:
- AES-128/256-CBC encryption
- HMAC-SHA256 for authentication
- AWS Cognito identity pool for key management (`us-east-1:bf6139ac-7ae1-4a8f-8ef5-1e4aeeca8d06`)
- TLS 1.0+ with proper cipher suites

**Verdict**: Clean - Industry-standard encryption properly implemented.

---

### 4. Site-Specific Form Handlers
**Severity**: N/A
**Status**: PASS

**Finding**: Extension includes 30+ site-specific scripts (Amazon, Citi, Bank of America, etc.) that handle non-standard login forms. These scripts use `WAXUtils.js` utility for form detection.

**Code Evidence** (`content/formdata/sitescripts/WAXUtils.js`):
```javascript
addLoginInput:function(e){
    void 0!==e&&null!=e&&(null==l&&(l=[]),l.push(e),
    e.addEventListener("keydown",WAXUtils.onLoginKeyDown,!1),
    WAXUtils.isTextInput(e)||e.addEventListener("mousedown",WAXUtils.onLoginClick,!1))
}
```

**Analysis**: Scripts only monitor form submissions for autofill purposes. No evidence of credential exfiltration to non-Norton domains.

**Verdict**: Clean - Legitimate autofill functionality for complex login flows.

---

### 5. Firebase Cloud Messaging
**Severity**: N/A
**Status**: PASS

**Finding**: Extension uses Firebase Cloud Messaging (FCM) for push notifications.

**Configuration** (from `background.js`):
```javascript
FIREBASE_CONFIGURATION:{
    apiKey:"AIzaSyB6GZuteRcGoegx-IDxK37dLpz7ekivMt4",
    authDomain:"ncs-spoc.firebaseapp.com",
    projectId:"ncs-spoc",
    messagingSenderId:"9988494302"
}
```

**Verdict**: Clean - Standard FCM integration for legitimate notification delivery.

---

### 6. Analytics & Telemetry
**Severity**: LOW
**Status**: INFORMATIONAL

**Finding**: Extension includes Google Analytics and Mixpanel for usage tracking.

**Trackers**:
- Google Analytics: `UA-80690213-1`
- Mixpanel: `eac88aea8bc59a05574a3964bb81c0ba` (standard)
- Mixpanel: `4e18d018329f05750593852f303687ff` (anonymized)

**Verdict**: Informational - Standard product analytics, not malicious. Users should be aware of telemetry.

---

### 7. Extension Enumeration / Killing
**Severity**: N/A
**Status**: PASS

**Finding**: No chrome.management API usage detected. No extension enumeration or killing behavior.

**Verdict**: Clean

---

### 8. XHR/Fetch Hooking
**Severity**: N/A
**Status**: PASS

**Finding**: No prototype pollution or hooking of XMLHttpRequest/fetch APIs detected.

**Verdict**: Clean

---

### 9. Residential Proxy / P2P Infrastructure
**Severity**: N/A
**Status**: PASS

**Finding**: No peer-to-peer networking, proxy infrastructure, or WebRTC data channels detected.

**Verdict**: Clean

---

### 10. Market Intelligence SDKs
**Severity**: N/A
**Status**: PASS

**Finding**: No Sensor Tower, Pathmatics, or similar SDKs detected.

**Verdict**: Clean

---

## False Positives

| Pattern | File | Reason |
|---------|------|--------|
| `postMessage` usage | `background.js` | Legitimate inter-component messaging for service worker communication |
| Firebase public keys | `background.js` | Standard FCM configuration, not a credential leak |
| AWS endpoint hardcoded | `apigClient.js` | Legitimate backend API endpoint for Norton services |
| Site-specific scripts | `content/formdata/sitescripts/*` | Autofill helpers for complex login forms, not malicious injection |
| Google Analytics | Various | Standard product analytics |

## Data Flow Summary

1. **User credentials**: Captured on forms → Encrypted locally with user master password → Sent to AWS API Gateway (`gz0s1l0bj0.execute-api.us-east-1.amazonaws.com`) with SigV4 auth → Stored in Norton vault
2. **Authentication**: OIDC flow via `login.norton.com` → AWS Cognito identity pool → Temporary credentials
3. **Sync**: Encrypted vault metadata synced via `cloudconnect2.norton.com`
4. **Notifications**: FCM push notifications from `ncs-spoc.firebaseapp.com`
5. **Telemetry**: Usage metrics sent to Google Analytics and Mixpanel (anonymized option available)

**Security Controls**:
- All data transmitted over HTTPS
- Passwords encrypted client-side before transmission
- AWS SigV4 request signing for API authentication
- Web Worker isolation for cryptographic operations
- No third-party data sharing outside Norton/Symantec infrastructure

## API Endpoints Table

| Endpoint | Method | Purpose | Authentication |
|----------|--------|---------|----------------|
| `https://gz0s1l0bj0.execute-api.us-east-1.amazonaws.com/PROD/device` | GET/PUT/DELETE | Device registration | AWS SigV4 |
| `https://gz0s1l0bj0.execute-api.us-east-1.amazonaws.com/PROD/unlock-request` | POST | Vault unlock requests | AWS SigV4 |
| `https://gz0s1l0bj0.execute-api.us-east-1.amazonaws.com/PROD/unlock-response` | POST | Vault unlock responses | AWS SigV4 |
| `https://login.norton.com/sso/oidc1/token` | POST | OIDC token exchange | OAuth 2.0 |
| `https://cloudconnect2.norton.com/*` | Various | Cloud sync | Bearer token |
| `https://identitysafe.norton.com/*` | Various | Vault portal | Session |
| `https://fcmregistrations.googleapis.com/v1` | POST | FCM registration | FCM auth |

## Overall Risk Assessment

**Risk Level**: **CLEAN**

### Justification

Norton Password Manager is a legitimate security product from a reputable vendor. While the extension requires extensive permissions and has broad access to user data (inherent to password managers), it:

1. **Uses proper encryption**: Industry-standard AES encryption with secure key management via AWS Cognito
2. **Secure communication**: All network traffic over HTTPS with proper authentication (SigV4, OIDC)
3. **No malicious patterns**: No extension killing, XHR hooking, proxy infrastructure, or credential theft
4. **Legitimate backend**: Uses official Norton/Symantec infrastructure (AWS, Firebase)
5. **No obfuscation**: Code is minified but not maliciously obfuscated
6. **Follows best practices**: Web Worker isolation for crypto, CSP headers, MV3 service worker

### Privacy Considerations

While not malicious, users should be aware:
- Extension has `<all_urls>` access (required for password management)
- Sends usage telemetry to Google Analytics and Mixpanel
- Syncs encrypted vault to Norton cloud servers
- Captures form data on all websites for autofill (encrypted before storage)

These are **expected behaviors** for a cloud-based password manager and are disclosed in Norton's privacy policy.

## Recommendations

1. **For Users**: Safe to use. This is a legitimate password manager from a trusted security vendor.
2. **For Researchers**: No security issues identified. Extension follows security best practices for password management.
3. **For Norton/Symantec**: Consider adding more transparency around telemetry collection and providing opt-out options in-extension.

## Conclusion

Norton Password Manager is a **CLEAN** extension that serves its intended purpose without malicious behavior. The extensive permissions are necessary for password management functionality across all websites. The extension uses industry-standard encryption, secure backend infrastructure, and proper authentication mechanisms. No vulnerabilities or malicious patterns were identified during this analysis.
