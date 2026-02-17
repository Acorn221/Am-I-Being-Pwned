# Vulnerability Report: Rewardsweb

## Metadata
- **Extension ID**: okembgocccnjoiaafmdedmhodcoalbgg
- **Extension Name**: Rewardsweb
- **Version**: 13.18.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Rewardsweb is a legitimate rewards and cashback browser extension targeting the Latin American market, particularly users of LATAM Airlines loyalty program. The extension operates as a shopping rewards platform that tracks user purchases at participating stores and provides cashback/points rewards. It uses standard OAuth 2.0 authentication flow via chrome.identity API for user login, integrates with legitimate services (rewardsweb.com, LATAM Airlines API), and includes Google Analytics for usage tracking. The extension's permissions and behavior are appropriate for its stated functionality as a rewards tracking service.

The code is built with modern web frameworks (React, Redux) and uses standard browser extension patterns. While it does use broad host permissions (*://*/*) and cookies permission for tracking store visits, this is necessary for its core functionality. No evidence of malicious behavior, credential theft, or undisclosed data collection was found.

## Vulnerability Details

### 1. LOW: CSP Sandbox Unsafe Policies
**Severity**: LOW
**Files**: manifest.json (lines 36-38)
**CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers or Frames)
**Description**: The Content Security Policy for the sandbox includes 'unsafe-eval' and 'unsafe-inline', which weaken security protections. The CSP configuration is:
```json
"sandbox": "sandbox allow-scripts; script-src 'self' 'unsafe-inline' 'unsafe-eval'; child-src 'self'; script-src-elem 'self' 'unsafe-inline' https://test.api.latam-pass.latam.com https://api.latam-pass.latam.com; frame-src https://loyaltyprogram.latamairlines.com https://test.api.latam-pass.latam.com https://api.latam-pass.latam.com"
```

**Evidence**: The manifest defines a sandbox page (fraudSandbox.html) with relaxed CSP policies allowing eval and inline scripts.

**Verdict**: This is a minor security concern but not a critical vulnerability. The 'unsafe-eval' and 'unsafe-inline' directives reduce defense-in-depth protections against potential XSS or code injection, but the sandbox page appears to be used for specific functionality related to fraud detection/prevention. This configuration is intentional for the extension's legitimate operation and does not pose immediate risk.

## False Positives Analysis

1. **Broad Host Permissions**: The extension requests `*://*/*` host permissions, which could appear excessive. However, this is necessary for a rewards/cashback extension that needs to detect when users visit any participating store website.

2. **Cookies Permission**: The extension uses `chrome.cookies` API, which could be flagged as privacy-invasive. However, this is required for the extension to track authenticated sessions with participating stores and verify purchases for reward allocation.

3. **Identity Permission**: Uses `chrome.identity.launchWebAuthFlow` for OAuth authentication. This is the standard, secure method for extension authentication and integrates with the Rewardsweb backend API for user login.

4. **externally_connectable**: The manifest declares `externally_connectable` for localhost and *.rewardsweb.com domains. This is appropriate for allowing the extension to communicate with the Rewardsweb web application.

5. **Google Analytics**: The extension includes GA4 tracking (measurement ID: G-846Q94XRLG). This is disclosed functionality for a commercial extension and is standard practice for product analytics.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| ext.rewardsweb.com | Main API backend | User authentication, store tracking, rewards data | Low - HTTPS, legitimate service |
| chrextasscf.rewardsweb.com | CDN for assets | Static resources (images, fonts) | Low - CDN only |
| app.rewardsweb.com | Web application | User redirects, OAuth callbacks | Low - Legitimate web app |
| help.rewardsweb.com | Help/support | Documentation access | Low - Static content |
| api.latam-pass.latam.com | LATAM Airlines API | Loyalty program integration | Low - Official LATAM API |
| test.api.latam-pass.latam.com | LATAM test environment | Testing/staging data | Low - Official test API |
| loyaltyprogram.latamairlines.com | LATAM loyalty program | Program information | Low - Official LATAM site |
| www.google-analytics.com | Analytics | Usage statistics, events | Low - Standard analytics |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

Rewardsweb is a legitimate commercial browser extension providing rewards/cashback services for the Latin American market with an official partnership with LATAM Airlines. The extension's permissions, API integrations, and data flows are all appropriate for its stated functionality. Key factors supporting this assessment:

1. **Legitimate Business Model**: Clear commercial purpose as a rewards platform with partnerships with major companies (LATAM Airlines).

2. **Standard Authentication**: Uses OAuth 2.0 via chrome.identity API (the recommended secure method) for user authentication.

3. **Appropriate Permissions**: While broad, the permissions are necessary for tracking store visits and purchase verification across multiple e-commerce sites.

4. **Professional Development**: Code is well-structured using modern frameworks (React, Redux, LaunchDarkly feature flags), indicating professional development practices.

5. **Transparent Infrastructure**: All API endpoints are clearly associated with the Rewardsweb service or official LATAM Airlines domains.

6. **No Malicious Patterns**: No evidence of credential theft, hidden data exfiltration, keylogging, or other malicious behavior patterns.

The only minor concern is the relaxed CSP for the sandbox environment, but this appears to be an intentional design decision for specific functionality and does not constitute a security vulnerability in the context of the extension's operation.
