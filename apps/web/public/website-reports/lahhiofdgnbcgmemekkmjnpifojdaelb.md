# Vulnerability Report: Vercel

## Metadata
- **Extension ID**: lahhiofdgnbcgmemekkmjnpifojdaelb
- **Extension Name**: Vercel
- **Version**: 1.4.1
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

The Vercel extension is an official browser extension developed by Vercel to enable the Vercel Toolbar on production deployments. The extension implements postMessage communication between content scripts and the Vercel website. While the extension uses origin validation, the implementation has weaknesses that could theoretically allow attacks from malicious subdomains. However, given the restricted scope of operations (limited to Vercel's own infrastructure) and the lack of sensitive data handling, the overall security risk is LOW.

This extension is a legitimate development tool that facilitates communication between deployed Vercel sites and the Vercel platform. The permissions requested (alarms, storage, webRequest, and host permissions) are appropriate for its stated functionality.

## Vulnerability Details

### 1. LOW: Weak postMessage Origin Validation
**Severity**: LOW
**Files**: src/content/toolbar.js
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
**Description**: The extension's content script listens for postMessage events with origin validation that checks against specific allowed origins (localhost:3000, vercel.live, canary-vercel.live, and *.vercel.sh domains). However, the validation logic uses a regex pattern that could potentially be exploited by crafted subdomain names.

**Evidence**:
```javascript
window.addEventListener("message", async e => {
  const g = e.origin;
  if (!(g !== "http://localhost:3000" && g !== "https://vercel.live" && g !== "https://canary-vercel.live" && !(g.endsWith(".vercel.sh") && /^https:\/\/[^.]*vercel-live[^.]*\.vercel\.sh$/.test(g)))) {
    // Process message actions
  }
});
```

The regex pattern `/^https:\/\/[^.]*vercel-live[^.]*\.vercel\.sh$/` allows any subdomain containing "vercel-live" anywhere in the subdomain portion. For example, `https://malicious-vercel-live-attack.vercel.sh` would pass validation.

**Verdict**: While this is a weakness in origin validation, the practical security impact is LOW because:
1. An attacker would need to deploy a site on Vercel infrastructure (*.vercel.sh)
2. The extension's functionality is limited to Vercel platform features (proxy-fetch, user settings, screenshot, Pusher subscriptions)
3. No sensitive user data is collected or transmitted outside of Vercel's ecosystem
4. The extension only accepts specific message action types with limited functionality

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated" - this is a false positive. The code is webpack-bundled with standard minification, which is normal for production browser extensions. The code structure is consistent with legitimate build tools, not deliberate obfuscation.

The `webRequest` permission might seem excessive, but examining the code shows it's not actually used in the current version - likely a legacy permission that hasn't been removed from the manifest.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://vercel.com/api/extension-auth | Extension authentication | Auth token | Low - authenticated communication with Vercel backend |
| https://vercel.com/api/live/check-domain-owner | Domain ownership verification | Domain name | Low - legitimate verification |
| https://vercel.com/api/v2/teams | Fetch user teams | None (GET) | Low - user's own team data |
| https://vercel.com/api/live/production-domains | Fetch production domains | Team ID | Low - user's deployment domains |
| https://vercel.com/api/feedback/auth/extension-validate | Validate feedback auth | Auth token | Low - feedback feature auth |
| {origin}/api/pusher/auth | Pusher WebSocket authentication | Channel/credentials | Low - real-time updates via Pusher |

All endpoints are within Vercel's own infrastructure and serve legitimate purposes for the toolbar functionality.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
The Vercel extension is a legitimate developer tool from Vercel with appropriate functionality for its stated purpose. The weak origin validation in the postMessage handler represents a minor vulnerability that could theoretically be exploited by an attacker who controls a *.vercel.sh subdomain. However, the limited scope of available actions (proxying fetch requests to Vercel APIs, managing user settings, taking screenshots) combined with the requirement that an attacker would need access to Vercel's deployment infrastructure significantly reduces the practical risk.

The extension does not:
- Collect sensitive user data beyond what's necessary for Vercel platform features
- Exfiltrate data to third-party domains
- Use dynamic code execution (eval, Function constructor)
- Modify web content in unexpected ways
- Access cookies or credentials outside the Vercel ecosystem

**Recommendations**:
1. Strengthen the origin validation regex to use an exact subdomain match pattern
2. Consider implementing CSP with stricter policies
3. Remove unused permissions (webRequest appears unused)
4. Add sendResponse validation to ensure messages come from trusted sources
