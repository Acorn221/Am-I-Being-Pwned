# Vulnerability Report: 电脑管家上网防护

## Metadata
- **Extension ID**: ibgigpdnkkdnicediiebbfnednhmlpab
- **Extension Name**: 电脑管家上网防护 (QQ PC Manager Web Protection)
- **Version**: 1.1.2
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension is a web protection component from Tencent's QQ PC Manager (电脑管家). It functions as a browser-based URL filtering system that communicates with a native Windows application via the nativeMessaging API. The extension monitors all tab navigation, sends URLs to the native component for security checks, and can redirect users to warning pages or block malicious sites based on the native application's response.

The extension operates as designed for its stated purpose (web protection). However, it exhibits significant privacy concerns due to its comprehensive browsing activity monitoring and transmission to a native application controlled by Tencent. All visited URLs are sent to the native host for classification, which represents complete browsing surveillance when the native application is installed.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Browsing Activity Monitoring
**Severity**: MEDIUM
**Files**: js/background.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension monitors all tab navigation events and sends every visited URL to the native host application (com.qq.qqpcmgr) for security classification. This creates a complete record of user browsing activity accessible to Tencent's PC Manager software.

**Evidence**:
```javascript
chrome.tabs.onUpdated.addListener((function(t, n, o) {
    if ("loading" == n.status) {
        if (!o.url) return;
        e.checkUrlFW(o.id, o.url, 2)
    }
}))

checkUrlFW: function(t, n, o) {
    var s = {
        CMD: "QueryUrlFW"
    };
    s.URL = n, s.ID = t,
    null != e.hPort && e.hPort.postMessage(JSON.stringify(s))
}
```

**Verdict**: This behavior is disclosed through the extension's name and description (web protection filter), and is necessary for the URL filtering functionality. However, the comprehensive nature of the monitoring represents a significant privacy consideration for users. The extension requires the separate installation of QQ PC Manager native application to function, which provides some user awareness. The data remains local to the native application rather than being sent to remote servers from the extension itself.

### 2. LOW: URL Redirection Based on External Classification
**Severity**: LOW
**Files**: js/background.js
**CWE**: CWE-601 (URL Redirection to Untrusted Site)
**Description**: The extension can redirect users to alternative URLs (DFDURL) provided by the native host when a site is classified as malicious.

**Evidence**:
```javascript
"" != s && "2" == n.URLTP && "" != n.DFDURL ? (
    chrome.tabs.update(parseInt(n.ID), {
        url: n.DFDURL
    }),
    chrome.action.setIcon({
        path: "../images/Danger.png",
        tabId: parseInt(n.ID)
    })
)
```

**Verdict**: This is standard behavior for web protection software and serves the extension's legitimate purpose. The redirection is controlled by the native Tencent application rather than arbitrary external sources. The extension does update the icon to indicate danger, providing user feedback.

### 3. LOW: Storage of Remote Configuration URL
**Severity**: LOW
**Files**: js/background.js
**CWE**: CWE-15 (External Control of System or Configuration Setting)
**Description**: The extension receives and stores a "safe URL" from the native host that appears to be used for configuration purposes.

**Evidence**:
```javascript
e.extPoctInfo.bExtPoctSwitch = "true" == n.EXTPOCTSWITCH,
e.extPoctInfo.bTrayRunning = "true" == n.TRAYRUNNING,
e.extPoctInfo.bPCMgrInstall = "true" == n.QQPCMGRINST,
n.SAFEURL && (e.safeUrl = n.SAFEURL),
chrome.storage.sync.set({
    safeUrl: e.safeUrl
}, (() => console.log("**********safeUrl:************", e.safeUrl)))
```

Default safe URL: `https://sdi.3g.qq.com/v/2022092615014911838`

**Verdict**: The remote configuration capability could theoretically be used to change extension behavior, but it appears limited to updating the safe URL reference. The configuration is only accepted from the local native host application, not directly from internet sources. This represents standard update mechanisms for security software.

## False Positives Analysis

The ext-analyzer flagged the code as "obfuscated," which is accurate for the minified production build. However, after deobfuscation, the code logic is straightforward:

1. **Webpack bundling**: The assets/index.js is a standard Vite/Vue build for the popup UI - not malicious obfuscation
2. **URL monitoring**: While comprehensive, this is the core functionality of a web protection filter
3. **Native messaging**: Communication with QQ PC Manager is the extension's stated purpose
4. **No hidden exfiltration**: The extension does not directly communicate with remote servers; all URL data is sent only to the local native application

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://sdi.3g.qq.com/v/2022092615014911838 | Default "safe URL" reference | None from extension | LOW - Configuration reference only |
| https://guanjia.qq.com/ | Homepage URL (QQ PC Manager) | None | CLEAN - Static reference |
| https://urlsec.qq.com/report.html | Report URL feature in popup | User-initiated | CLEAN - Legitimate reporting |
| https://urlsec.qq.com/complain.html | Complaint URL feature in popup | User-initiated | CLEAN - Legitimate feedback |
| Native Host: com.qq.qqpcmgr | Local native messaging | All visited URLs, tab IDs, statistics requests | MEDIUM - Privacy concern |

**Note**: The extension itself does not make HTTP requests to remote servers. All network communication would occur within the native QQ PC Manager application, which is outside the scope of this extension analysis.

## Privacy Considerations

**Browsing History Exposure**: Every URL visited is sent to the native application, creating comprehensive browsing surveillance. Users should be aware that:
- Complete browsing history is accessible to Tencent QQ PC Manager
- The native application could potentially log or transmit this data (beyond extension scope)
- This represents complete web activity monitoring while the native app is running

**User Consent**: The extension's Chinese name and description indicate it is a web protection filter, which provides some disclosure of monitoring functionality. However, the comprehensive nature of the monitoring may not be immediately apparent to users.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
This extension functions as designed for web protection filtering, similar to enterprise security products or parental control software. The core concern is the comprehensive monitoring of all browsing activity sent to Tencent's native application. While this is necessary for the URL filtering functionality and disclosed through the extension's purpose, it represents significant privacy exposure.

The extension is not malicious in the traditional sense - it does not hide its affiliation with Tencent QQ PC Manager, does not inject ads or affiliates, and requires deliberate installation of both the extension and native application. However, users should be fully aware that installing this extension grants Tencent's PC Manager complete visibility into their browsing activity.

The MEDIUM risk rating reflects:
- **Privacy concern**: Complete URL monitoring sent to Tencent's native application
- **Legitimate purpose**: Functions as disclosed for web protection
- **User choice**: Requires deliberate installation of native application
- **No hidden behavior**: No undisclosed data exfiltration or malicious features
- **Large user base**: 1M+ users suggests established software from major vendor

Users who are comfortable with Tencent monitoring their browsing activity for security purposes may find this acceptable. Privacy-conscious users should avoid this extension.
