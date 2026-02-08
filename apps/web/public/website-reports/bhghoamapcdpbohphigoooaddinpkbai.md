# Vulnerability Report: Authenticator Extension

## Metadata
- **Extension ID**: bhghoamapcdpbohphigoooaddinpkbai
- **Extension Name**: Authenticator
- **Version**: 8.0.1
- **User Count**: ~8,000,000
- **Analysis Date**: 2026-02-08
- **Manifest Version**: 3

## Executive Summary

Authenticator is a legitimate two-factor authentication (2FA) code generator extension with ~8 million users. The extension provides TOTP/HOTP authentication code generation, QR code scanning, and optional cloud backup integration (Google Drive, Dropbox, OneDrive).

**Primary Finding**: This extension is **CLEAN** with no malicious behavior detected. The extensive permissions and cloud integrations are fully justified by the extension's intended functionality as a 2FA authenticator with backup capabilities. All network calls are limited to documented OAuth flows and cloud storage APIs.

## Vulnerability Details

### 1. No Critical Vulnerabilities Found
**Severity**: N/A
**Status**: CLEAN

The extension implements standard 2FA functionality with proper security practices:
- Local encryption using AES (crypto-js library)
- Sandboxed password hashing (argon.html with unsafe-eval only in sandbox)
- Proper CSP policies restricting script sources
- OAuth 2.0 flows for cloud provider authentication

### 2. OAuth Redirect Domains
**Severity**: LOW (Informational)
**Files**: `dist/background.js`
**Code Evidence**:
```javascript
r=-1!==navigator.userAgent.indexOf("Edg")?
  encodeURIComponent("https://authenticator.cc/oauth-edge"):
  U?encodeURIComponent(chrome.identity.getRedirectURL()):
  encodeURIComponent("https://authenticator.cc/oauth")
```

**Analysis**: The extension uses `authenticator.cc/oauth` and `authenticator.cc/oauth-edge` as OAuth redirect URIs for Google Drive integration (non-Edge browsers require external redirect). This is a standard pattern for OAuth flows in extensions that cannot use chrome.identity on all platforms.

**Verdict**: **NOT VULNERABLE** - Legitimate OAuth redirect handling for cross-browser compatibility.

### 3. Feedback URL Redirect
**Severity**: LOW (Informational)
**Files**: `dist/background.js`
**Code Evidence**:
```javascript
return O&&(t="https://otp.ee/chromeissues"),t&&chrome.tabs.create({url:t,active:!0}),!0
```

**Analysis**: The extension opens `https://otp.ee/chromeissues` for user feedback/issue reporting. Domain appears to be affiliated with the extension developers.

**Verdict**: **NOT VULNERABLE** - Standard feedback mechanism, user-initiated only.

### 4. Enterprise Management Schema
**Severity**: LOW (Informational)
**Files**: `schema.json`
**Configuration Options**:
- `disableInstallHelp`: Disable help page on install
- `disableBackup`: Hide 3rd party backup options
- `disableExport`: Hide export buttons
- `storageArea`: Force sync or local storage
- `enforcePassword`: Require password protection
- `enforceAutolock`: Force auto-lock timeout
- `passwordPolicy`: Regex-based password requirements

**Analysis**: Robust enterprise policy support for managed deployments. All settings are restrictive (increase security) rather than permissive.

**Verdict**: **NOT VULNERABLE** - Proper enterprise configuration support.

## False Positives

| Pattern | Location | Reason for False Positive |
|---------|----------|--------------------------|
| `innerHTML` usage | `dist/popup.js`, `dist/options.js`, `dist/import.js` | Standard DOM manipulation in UI scripts, no user-controlled content injection detected |
| `eval` in CSP | `manifest.json` (sandbox) | Restricted to sandboxed page (`view/argon.html`) for Argon2 password hashing, properly isolated |
| OAuth client secrets | `dist/background.js` | Public OAuth client IDs/secrets for Google Drive/Dropbox/OneDrive - standard for client-side apps |
| Crypto libraries | All dist files | Legitimate use of crypto-js (AES, SHA-256, PBKDF2) and GOST cryptography for encryption |

## API Endpoints

| Endpoint | Purpose | Data Sent | Justification |
|----------|---------|-----------|---------------|
| `https://accounts.google.com/o/oauth2/v2/auth` | Google OAuth | OAuth authorization code | Google Drive backup authentication |
| `https://www.googleapis.com/oauth2/v4/token` | Google OAuth | Client ID/secret, auth code | Exchange auth code for access token |
| `https://www.googleapis.com/drive/v3/files` | Google Drive API | Encrypted backup data | Upload/download backups to Google Drive |
| `https://www.dropbox.com/oauth2/authorize` | Dropbox OAuth | OAuth authorization | Dropbox backup authentication |
| `https://api.dropboxapi.com/2/users/get_current_account` | Dropbox API | Access token | Verify Dropbox account |
| `https://content.dropboxapi.com/2/files/upload` | Dropbox API | Encrypted backup data | Upload backups to Dropbox |
| `https://login.microsoftonline.com/common/oauth2/v2.0/authorize` | OneDrive OAuth | OAuth authorization | OneDrive backup authentication |
| `https://graph.microsoft.com/v1.0/me/drive/special/approot` | OneDrive API | Encrypted backup data | Upload/download backups to OneDrive |
| `https://www.google.com/` | Clock sync | Timestamp request | Sync local clock for TOTP accuracy |
| `https://authenticator.cc/oauth` | OAuth redirect | OAuth callback data | Non-Edge browser OAuth redirect URI |
| `https://otp.ee/chromeissues` | Feedback | User-initiated navigation | Issue reporting link |

## Data Flow Summary

### Local Data Storage
1. **2FA Secrets**: Stored in `chrome.storage.sync` or `chrome.storage.local` (user configurable)
2. **Encryption**: Secrets encrypted with AES using user password (optional but recommended)
3. **Password Hashing**: Argon2id via sandboxed page (`view/argon.html`)

### Cloud Backup Flow (Optional)
1. User enables backup → OAuth flow initiated
2. Extension receives access token via OAuth redirect
3. Encrypted backup file uploaded to cloud storage
4. **Important**: Backups are unencrypted unless user sets password (warning shown in UI)

### Content Script Functionality
- **QR Code Scanning**: Injects script to capture visible QR codes on active tab
- **Autofill**: Optional feature to inject TOTP codes into forms
- **No Cookie Harvesting**: No cookie access detected
- **No Keylogging**: Keyboard listeners only in extension UI, not content scripts

### Permissions Justification
- `activeTab`: Required for QR code scanning
- `storage`: Store 2FA secrets and settings
- `identity`: OAuth flows for cloud backup
- `alarms`: Auto-lock timer functionality
- `scripting`: QR code scanning and autofill
- `clipboardWrite` (optional): Copy codes to clipboard
- `contextMenus` (optional): Right-click menu integration

## Overall Risk Assessment

**RISK LEVEL**: **CLEAN**

### Justification
This extension is a well-designed, legitimate 2FA authenticator with the following characteristics:

**Positive Security Indicators**:
1. **Open Source**: Licensed under MIT, source code available
2. **Proper Encryption**: Uses industry-standard AES encryption with Argon2 password hashing
3. **Minimal Attack Surface**: No XHR/fetch hooking, no analytics, no ad injection
4. **Transparent Cloud Integration**: All OAuth flows are standard, documented patterns
5. **Strong CSP**: Restrictive Content Security Policy with sandboxing for eval usage
6. **Enterprise Ready**: Managed schema for policy-based configuration
7. **User Control**: All invasive features (backup, autofill) are opt-in

**No Malicious Indicators**:
- ❌ No extension enumeration/killing
- ❌ No residential proxy infrastructure
- ❌ No remote config or kill switches
- ❌ No market intelligence SDKs
- ❌ No data exfiltration beyond documented cloud backups
- ❌ No credential harvesting
- ❌ No ad/coupon injection
- ❌ No obfuscation (webpack bundling only)

**Why Extensive Permissions Are Justified**:
The extension requires broad permissions because it must:
1. Scan QR codes from any webpage (activeTab + scripting)
2. Optionally autofill codes into forms (scripting)
3. Sync encrypted data across devices (storage + optional cloud)
4. Maintain time-based code accuracy (google.com clock sync)

All data transmission is limited to:
- User-initiated OAuth flows with Google/Dropbox/Microsoft
- Encrypted backup uploads to user's own cloud storage
- Clock synchronization for TOTP accuracy

**Recommendation**: This extension is safe for use. The ~8 million user base and open-source nature provide additional trust signals. Users should enable password encryption and understand that cloud backups are unencrypted by default (per extension warnings).
