# Vulnerability Report: 데이터랩툴즈 헬퍼

## Metadata
- **Extension ID**: ldoknfkedngbdfgdkeicojmhnojgpdcb
- **Extension Name**: 데이터랩툴즈 헬퍼 (Datalab Tools Helper)
- **Version**: 1.0.9
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This is a Korean marketing analytics browser extension that provides enhanced functionality for Datalab Tools on Naver.com. The extension loads external scripts from app.datalab.tools and implements a message-passing architecture between content scripts, foreground scripts, and background service workers. While the extension does fetch remote code, this appears to be legitimate functionality for a marketing analytics tool. The extension scope is limited to naver.com and datalab.tools domains, minimizing potential attack surface. The main security concern is the loading of external JavaScript from a remote server without additional verification, though this is within the extension's stated purpose.

## Vulnerability Details

### 1. LOW: Remote Script Loading without Integrity Verification

**Severity**: LOW
**Files**: foreground.bundle.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension dynamically loads JavaScript from `https://app.datalab.tools/loader.js` without verifying script integrity using Subresource Integrity (SRI) hashes or other cryptographic verification.

**Evidence**:
```javascript
// foreground.bundle.js:4617-4638
function Vr() {
  if (!new URL(location.href).hostname) {
    Nt.debug("🔍 로컬 환경이므로 외부 로더 스크립트를 로드하지 않습니다.");
    return
  }
  const v = {
      hostname: "app.datalab.tools",
      scriptId: "__datalab_tools_extension_loader__",
      scriptPath: "/loader.js"
    },
    L = Br(),
    r = `https://${v.hostname}${v.scriptPath}?v=${L}`;
  if (Pr(v.scriptId)) {
    Nt.info("ℹ️ Datalab 로더 스크립트가 이미 로드되어 있습니다.");
    return
  }
  Hr();
  const R = Gr(r, v.scriptId),
    N = document.documentElement || document.body || document.head;
  Nt.info(`🚀 Datalab 로더 스크립트를 주입합니다: ${r}`), N.appendChild(R)
}
```

**Verdict**: This is a common pattern for analytics and marketing tools that need to update functionality without requiring extension updates. While it creates a dependency on the remote server's security, it is disclosed through the extension's purpose and permissions. The risk is mitigated by:
- Limited scope (only runs on naver.com and datalab.tools domains)
- HTTPS enforcement
- Extension only loads from a specific, controlled domain (app.datalab.tools)

## False Positives Analysis

**1. ext-analyzer EXFILTRATION findings**: The static analyzer flagged three "exfiltration" flows involving `document.querySelectorAll → fetch`. However, these are legitimate data flows for a marketing analytics tool:
- The extension queries DOM elements on Naver pages to extract marketing data
- Fetches are made to the extension's own datalab.tools backend
- This is the expected behavior for a marketing analytics tool

**2. Message Handler innerHTML assignments**: The ext-analyzer flagged "message data → *.innerHTML" patterns. Review shows:
- The extension uses DOMPurify library (visible in foreground.bundle.js)
- innerHTML usage is within React/Preact framework code (bundled libraries)
- No evidence of unsanitized user input being written to innerHTML in application code

**3. Obfuscation flag**: The code is webpack-bundled with minification, which is standard for production web applications, not malicious obfuscation.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| app.datalab.tools | Analytics backend | DOM data from Naver pages, likely marketing metrics | LOW - Disclosed functionality for marketing tool |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This extension is a legitimate Korean marketing analytics tool with a clear, disclosed purpose. The remote script loading is consistent with its function as a dynamic analytics platform. Key risk mitigations include:

1. **Limited Scope**: Only operates on naver.com and datalab.tools domains
2. **No Sensitive Permissions**: Uses declarativeNetRequest for header modification (likely for API access), but lacks access to cookies, browsing history, or other sensitive APIs
3. **Transparent Behavior**: The code includes debug logging showing its operations
4. **Professional Development**: Uses modern libraries (React/Preact, DOMPurify) and MV3 architecture

The main concern is the trust dependency on app.datalab.tools. If that domain were compromised, malicious code could be delivered to extension users. However, this is an inherent risk of any cloud-connected analytics tool and appears to be the intended architecture.

**Recommendation**: Users should only install this if they actively use Datalab Tools for marketing analytics on Naver. The remote code execution capability means users must trust the extension publisher's infrastructure security.
