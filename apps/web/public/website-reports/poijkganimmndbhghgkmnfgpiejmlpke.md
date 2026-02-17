# Vulnerability Report: Share Your Cookies

## Metadata
- **Extension ID**: poijkganimmndbhghgkmnfgpiejmlpke
- **Extension Name**: Share Your Cookies
- **Version**: 1.0.3
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Share Your Cookies is a browser extension that enables users to export and import authentication cookies between different browser sessions or users. While marketed as a convenient account-sharing tool that avoids revealing passwords, this functionality creates severe security risks. The extension allows complete session hijacking by exporting all cookies for a domain (including authentication tokens, CSRF tokens, and session identifiers) as a base64-encoded string that can be imported into any other browser instance. This effectively enables account takeover without requiring passwords, bypassing multi-factor authentication, and can facilitate unauthorized access to sensitive accounts.

The extension has approximately 100,000 users and requests broad permissions (cookies access to all HTTP/HTTPS sites, active tab access). While the code itself does not exfiltrate data to remote servers, the core functionality is inherently dangerous as it deliberately extracts and allows transfer of authentication credentials.

## Vulnerability Details

### 1. HIGH: Session Hijacking via Cookie Export/Import

**Severity**: HIGH
**Files**: popup.js
**CWE**: CWE-294 (Authentication Bypass by Capture-replay)
**Description**: The extension's primary function allows users to export all cookies for the current domain as a base64-encoded string and import them into another browser session. This enables complete session hijacking and account takeover.

**Evidence**:

Export functionality (lines 70-76):
```javascript
const l = o => {
  chrome.cookies.getAll({
    url: o.origin
  }, o => {
    const r = o.reduce((e, t, n) => (e += JSON.stringify(t), n < o.length - 1 && (e += ";"), e), "");
    e.value = btoa(r), t.disabled = !0, n.disabled = !0, i.style.display = "none"
  })
}
```

Import functionality (lines 78-119):
```javascript
const a = e => {
  chrome.cookies.getAll({
    url: e.origin
  }, t => {
    let n = 0;
    t.forEach(o => {
      chrome.cookies.remove({
        url: e.origin,
        name: o.name
      }, () => {
        n++, n === t.length && c(e)
      })
    })
  })
},
c = t => {
  const n = atob(e.value).split(";");
  let o = 0;
  n.forEach(e => {
    e = JSON.parse(e), chrome.cookies.set({
      url: t.origin,
      name: e.name,
      value: e.value,
      domain: e.domain,
      path: e.path,
      secure: e.secure,
      httpOnly: e.httponly,
      sameSite: e.sameSite,
      expirationDate: e.expirationDate,
      storeId: e.storeId
    }, () => {
      o++, o === n.length && (chrome.tabs.query({
        active: !0,
        currentWindow: !0
      }, e => {
        chrome.tabs.update(e[0].id, {
          url: t.origin
        })
      }), window.close())
    })
  })
}
```

**Verdict**: This is a HIGH risk vulnerability. The extension deliberately extracts all cookies including:
- Session tokens
- Authentication cookies
- CSRF tokens
- Remember-me tokens
- Any other sensitive cookie data

The import function only performs minimal validation (checking domain similarity on line 64), but this is easily bypassed. Once cookies are exported, they can be:
- Shared with malicious actors
- Used to hijack active sessions
- Used to bypass multi-factor authentication (since session is already authenticated)
- Transferred across machines to impersonate users
- Stored insecurely and stolen

While the extension's stated purpose is "sharing accounts without revealing passwords," this approach is fundamentally insecure and violates the security model of web authentication. Session tokens are security-critical credentials that should never be exported or transferred.

## False Positives Analysis

None. The extension does exactly what it claims - extract and import cookies. However, this functionality itself is the security risk. There are no false positives in this analysis.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | No external network requests | N/A | N/A |

The extension does not send data to external servers. However, the exported cookie data (base64-encoded) is displayed in the UI and can be manually copied by users to share via any channel (email, messaging, etc.).

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

This extension receives a HIGH risk rating for the following reasons:

1. **Session Hijacking Capability**: The core functionality enables complete session hijacking by extracting all authentication cookies. This is not a bug or vulnerability in the traditional sense - it's the intended feature, which makes it particularly dangerous.

2. **Broad Attack Surface**: With 100,000 users and permissions for all HTTP/HTTPS sites, this extension creates significant risk. Any user who exports their cookies and shares them (even with trusted parties) is vulnerable to account takeover.

3. **Bypasses Security Controls**: Cookie export bypasses:
   - Password-based authentication
   - Multi-factor authentication (MFA)
   - Account security questions
   - IP-based restrictions (partially)

4. **User Misunderstanding**: Users may not understand that sharing cookies is equivalent to sharing complete account access, including to sensitive accounts (banking, email, social media, corporate systems).

5. **No Data Exfiltration But Manual Risk**: While the extension doesn't automatically exfiltrate data, it provides tools for users to manually extract and transfer security-critical credentials.

**Mitigating Factors**:
- No automatic exfiltration to remote servers
- Users must intentionally use the export function
- Code is relatively simple and transparent (Webpack-bundled but not obfuscated)

**Risk Classification**: The extension is not malware, but it provides dangerous functionality that can enable account takeover attacks. It should be flagged as HIGH risk due to session hijacking capabilities.
