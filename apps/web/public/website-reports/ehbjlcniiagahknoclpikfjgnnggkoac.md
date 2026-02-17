# Vulnerability Report: Followers Exporter

## Metadata
- **Extension ID**: ehbjlcniiagahknoclpikfjgnnggkoac
- **Extension Name**: Followers Exporter
- **Version**: 3.2.5
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Followers Exporter is an Instagram data export tool that allows users to export their follower and following lists to CSV format. The extension uses OAuth 2.0 authentication via Google Identity API to associate users with a backend service at getwebooster.com, which appears to be a legitimate SaaS platform for Instagram analytics.

The extension has appropriate permissions for its stated functionality (cookies, storage, identity) and host permissions limited to Instagram and its own backend domain. Static analysis revealed no suspicious data exfiltration flows, no code execution vulnerabilities, and no evidence of malicious behavior. The codebase is webpack-bundled (not obfuscated) and uses standard libraries including Parse SDK, MSAL (Microsoft Authentication Library), and jQuery.

The primary security concern is the broad cookie permission combined with Instagram host access, which theoretically allows reading Instagram session cookies, but this appears to be necessary for the extension's legitimate functionality of accessing Instagram data.

## Vulnerability Details

### 1. LOW: Broad Cookie Permission Scope

**Severity**: LOW
**Files**: manifest.json, background.js
**CWE**: CWE-269 (Improper Privilege Management)

**Description**: The extension requests the "cookies" permission along with host permissions for `*://*.instagram.com/*`. This combination technically allows the extension to read Instagram session cookies, which could be used to hijack user sessions if the extension were malicious.

**Evidence**:
```json
"permissions": ["cookies", "storage", "identity"],
"host_permissions": ["*://*.instagram.com/*", "*://*.getwebooster.com/*"]
```

However, analysis of the codebase shows no evidence of cookie theft or unauthorized session access. The extension appears to use standard Instagram GraphQL and REST APIs for fetching follower/following data, which is consistent with its stated purpose.

**Verdict**: This is a theoretical risk rather than an actual vulnerability. The permission is likely required for the extension to maintain authenticated sessions with Instagram while fetching user data. No malicious cookie access patterns were detected in the code.

## False Positives Analysis

**Webpack Bundling vs Obfuscation**: The extension's JavaScript files are webpack-bundled with minified code, which the static analyzer flagged as "obfuscated". However, this is standard build tooling, not intentional code obfuscation. The code structure is typical of React/Vue applications with clearly identifiable libraries (Parse SDK, MSAL, jQuery, Moment.js).

**Third-Party Libraries**: The extension includes Microsoft Authentication Library (MSAL) and Parse SDK, which contain references to various authentication endpoints. These are legitimate authentication flows and not indicators of malicious behavior.

**Instagram API Access**: The extension makes requests to Instagram's GraphQL and REST API endpoints to fetch follower/following data. This is the core functionality of the extension and is clearly disclosed in the extension's description.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| igexport.getwebooster.com | Backend service for export processing | User email (via OAuth), Instagram follower data | LOW - Legitimate backend for paid service |
| www.googleapis.com/oauth2/v2/userinfo | Google OAuth user info | OAuth access token | LOW - Standard OAuth flow |
| accounts.google.com/o/oauth2/auth | Google OAuth authorization | OAuth credentials | LOW - Standard OAuth flow |
| www.instagram.com/graphql/query/ | Instagram GraphQL API | User queries for followers/following | LOW - Legitimate Instagram API usage |
| i.instagram.com/api/v1/users/ | Instagram REST API | User profile requests | LOW - Legitimate Instagram API usage |

## Payment Integration

The extension integrates with payment processors (Paddle and Stripe) via the getwebooster.com backend:
- getwebooster.com/paddle
- getwebooster.com/stripe

This indicates the extension is part of a paid/freemium service model, which is consistent with its business model as an Instagram analytics tool.

## Privacy Considerations

The extension collects:
1. **User email address** - via Google OAuth (chrome.identity API)
2. **Instagram follower/following data** - this is the core functionality
3. **Usage analytics** - likely sent to getwebooster.com backend

This data collection appears to be disclosed and necessary for the service to function. Users authenticate via Google OAuth, which provides transparency about what data is shared.

## Static Analysis Results

**ext-analyzer findings**:
- No exfiltration flows detected (0 flows)
- No code execution vulnerabilities (0 flows)
- No WASM usage
- No open message handlers
- Manifest risk score: 30/100 (due to cookie + broad host permissions)
- Overall risk: CLEAN (beyond stated functionality)

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
Followers Exporter is a legitimate Instagram analytics tool with no evidence of malicious behavior. The extension:
- Uses standard OAuth 2.0 authentication (Google Identity API)
- Limits host permissions to only required domains (Instagram and own backend)
- Has no suspicious data exfiltration patterns
- Uses a legitimate backend service (getwebooster.com) with payment integration
- Employs standard web development libraries without malicious code injection

The only minor concern is the broad cookie permission, but this appears necessary for maintaining authenticated Instagram sessions while fetching follower data. The extension's behavior aligns with its stated purpose of exporting Instagram follower/following lists.

**Recommendation**: The extension is safe for users who want to export their Instagram follower data and are comfortable sharing their Instagram data with the getwebooster.com service. Users should review the extension's privacy policy to understand how their data is used and stored.
