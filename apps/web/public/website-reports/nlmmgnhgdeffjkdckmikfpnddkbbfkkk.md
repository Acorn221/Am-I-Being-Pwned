# Vulnerability Report: Lightning Autofill

## Metadata
- **Extension ID**: nlmmgnhgdeffjkdckmikfpnddkbbfkkk
- **Extension Name**: Lightning Autofill
- **Version**: 14.24.3
- **Users**: ~600,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Lightning Autofill is a legitimate form-filling productivity tool with 600,000 users that has been operating since 2010. The extension uses powerful permissions (`<all_urls>`, `scripting`, `userScripts`) to perform its core function of automatically filling web forms. While the static analyzer flagged the code as obfuscated, this appears to be standard webpack/bundler minification rather than deliberate obfuscation. The extension integrates with Google Drive for cloud sync and offers a premium subscription model. After thorough analysis, the extension demonstrates appropriate use of its permissions for its stated purpose and follows security best practices. No malicious behavior was detected.

## Vulnerability Details

### 1. LOW: Broad Host Permissions with Form Manipulation Capabilities
**Severity**: LOW
**Files**: manifest.json, autofill.js, eventPage.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests `<all_urls>` host permissions and uses `scripting`, `userScripts`, and content scripts on all URLs. While this is necessary for a form autofill tool to function on any website, it represents a broad attack surface.

**Evidence**:
```json
"host_permissions": ["<all_urls>"],
"content_scripts": [
  {
    "matches": ["<all_urls>"],
    "js": ["js/autofill.js"],
    "all_frames": true,
    "match_about_blank": true,
    "run_at": "document_end"
  }
]
```

**Verdict**: ACCEPTABLE - This permission scope is essential for an autofill extension that needs to work across all websites. The extension provides an "Exceptions" feature allowing users to exclude specific sites, which is a good privacy control. The use of `userScripts` API for dynamic rule injection is appropriate for the use case.

### 2. LOW: OAuth2 Integration with Google Services
**Severity**: LOW
**Files**: manifest.json, eventPage.js
**CWE**: CWE-522 (Insufficiently Protected Credentials)
**Description**: The extension uses OAuth2 to access Google Drive and user email for cloud synchronization features. This involves handling sensitive tokens.

**Evidence**:
```json
"oauth2": {
  "client_id": "171872051662-m3bdmb4v1cl3og24ager32vsn6gp1dma.apps.googleusercontent.com",
  "scopes": [
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/userinfo.email"
  ]
}
```

Static analyzer detected endpoints:
- www.googleapis.com
- accounts.google.com

**Verdict**: ACCEPTABLE - The OAuth2 scopes are appropriately limited to `drive.file` (only files created by the app) rather than full Drive access. The integration is used for legitimate cloud backup functionality. Token revocation functionality is present in the code.

### 3. LOW: Remote Configuration from lightningautofill.com
**Severity**: LOW
**Files**: eventPage.js, common-60e5e246.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension communicates with `ai.lightningautofill.com` and fetches configuration/subscription data from the vendor's server.

**Evidence**:
Static analyzer reported endpoint: `ai.lightningautofill.com`

**Verdict**: ACCEPTABLE - This communication is for subscription verification and premium feature management. The domain is legitimately owned by the extension vendor (Tohodo LLC). No evidence of code download or execution of remotely-fetched scripts was found.

## False Positives Analysis

### Obfuscation Flag
The static analyzer flagged the code as "obfuscated." Investigation reveals this is webpack/Rollup bundling with minification, not malicious obfuscation:
- Import statements use shorthand variable names (standard webpack output)
- The deobfuscated files are only 1-7 lines because they're ES6 module imports
- The actual code is in bundled chunks like `common-60e5e246.js`
- Copyright headers and clear documentation URLs are present
- Localization strings in `messages.json` are fully readable

### Dynamic Code Execution
While the extension uses `chrome.scripting.executeScript` and the `userScripts` API, this is for its core functionality:
- Injecting autofill logic into web pages
- Supporting user-defined JavaScript variables (premium feature)
- All code execution is user-controlled through the options interface

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.googleapis.com | Google OAuth & Drive API | OAuth tokens, spreadsheet data | Low - Standard Google API |
| accounts.google.com | Google authentication | OAuth flow | Low - Standard Google Auth |
| ai.lightningautofill.com | Premium features/AI | Subscription data, form metadata | Low - Vendor-controlled |
| cdn.jsdelivr.net | CDN preconnect | None (preconnect only) | Minimal - CDN resource hint |
| docs.lightningautofill.com | Documentation | None (user navigation) | Minimal - Help system |

## Privacy Considerations

**Data Collection**: The extension accesses form data on all websites to perform autofilling. Users configure what data to fill through the options page.

**Cloud Sync**: Optional Google Sheets integration stores user's autofill profiles in their own Google Drive (not vendor servers).

**Local Storage**: Form templates and autofill rules are stored locally. No evidence of unauthorized data exfiltration was found.

**Subscription Model**: The extension offers Free/Plus/Pro tiers with premium features (JavaScript rules, captcha solving, etc.). Subscription verification occurs via `lightningautofill.com`.

## Security Strengths

1. **Manifest V3 Migration**: Extension uses modern MV3 APIs with service worker
2. **Limited OAuth Scopes**: Only requests `drive.file` not full Drive access
3. **User Control**: Exceptions list allows users to disable on specific sites
4. **Token Management**: Includes OAuth token revocation functionality
5. **No Eval in Main World**: User scripts run in isolated world with CSP

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: Lightning Autofill is a legitimate productivity tool that has been in operation since 2010 with 600,000 users. While it requires broad permissions to function across all websites, these permissions are appropriate for an autofill extension and are used only for their stated purpose. The extension:

- Uses permissions appropriately for form autofill functionality
- Implements OAuth2 with minimal necessary scopes
- Provides user controls (exceptions, manual mode)
- Maintains transparent communication with vendor services for subscriptions
- Shows no evidence of malicious data exfiltration
- Has proper privacy controls and optional cloud sync

The primary privacy consideration is that the extension has access to all form data on all websites, which is inherent to its functionality. Users should be aware of this when installing any autofill extension and should use the exceptions list for sensitive sites. The code quality and permission usage indicate a professionally maintained extension.
