# Security Analysis Report: Streak Email Tracking for Gmail

## Extension Metadata
- **Name**: Streak Email Tracking for Gmail
- **Extension ID**: jcgpgjhaendighananonflfmjjefjjlp
- **User Count**: ~70,000
- **Version**: 7.56
- **Manifest Version**: 3
- **Developer**: Streak (www.streak.com)

## Executive Summary

Streak Email Tracking is a legitimate email tracking and CRM extension developed by a well-funded venture-backed company (YCombinator, Battery Ventures, Redpoint Ventures). The extension is designed to add email tracking and CRM capabilities to Gmail.

**Overall Risk Level: CLEAN**

The extension exhibits security-conscious development practices with legitimate business functionality. No malicious behavior, proxy infrastructure, market intelligence SDKs, or unauthorized data exfiltration was detected. The extension uses standard Gmail integration patterns and communicates only with its own backend infrastructure at streak.com and mailfoogae.appspot.com.

## Vulnerability Analysis

### 1. Extension Enumeration via chrome.management API

**Severity**: LOW
**Status**: FALSE POSITIVE (Benign Use Case)

**Files**:
- `/background-mv3.js` (lines 317-326)
- `/clientjs/clientjs.chunk.2733.a7db76272bbbcf24e450.js` (lines 30-99)

**Code Reference**:
```javascript
// background-mv3.js line 317-326
extensionListRequest: {
  legacyResponseName: 'extensionListResponse',
  handler() {
    if (chrome.management?.getAll) {
      return chrome.management.getAll();
    } else {
      // Safari doesn't support chrome.management currently
      return [];
    }
  },
}
```

**Functionality**:
The extension requests a list of all installed extensions via `chrome.management.getAll()`. This is used to detect **incompatible extensions** that may conflict with Streak's functionality.

**Detected Incompatible Extensions**:
The extension checks for 18 known incompatible CRM/Gmail extensions including:
- Signal (demimoohidhmolhbphaklnmokjhjgjlf)
- Cirrus Insight (fmdomiplhgolgpibfdjjhgbcbkdcfkmk)
- Gmelius (dheionainndbbpoacpnopgmnihkcmnkl)
- Yesware (gkjnkapjmjfpipfcccnjbjcbgdnahpjp)
- Hiver (fcinnggknmdfkilogcndkgpojpfojeem)
- And 13 others

**User Impact**:
When a conflicting extension is detected, Streak displays a warning modal informing the user of the conflict. The extension does NOT disable or kill competing extensions - it only warns the user. Users can dismiss the warning with "Don't show again."

**Verdict**: This is a **legitimate compatibility check** to prevent conflicts with competing CRM extensions. The extension does not attempt to disable, uninstall, or interfere with other extensions. This is a standard practice for extensions that modify Gmail's UI extensively.

### 2. Email Tracking via Image Blocking

**Severity**: INFORMATIONAL
**Status**: LEGITIMATE FEATURE

**Files**:
- `/background-mv3.js` (lines 188-312)

**Code Reference**:
```javascript
// Image URL filtering to prevent email tracking
const mapUrlFilterToRedirectRule = urlFilter => {
  return {
    priority: 1,
    action: {
      redirect: {url: EMPTY_IMAGE_URL},
      type: 'redirect',
    },
    condition: {
      requestDomains: ['googleusercontent.com', 'mailfoogae.appspot.com'],
      resourceTypes: ['image'],
      urlFilter: urlFilter,
      isUrlFilterCaseSensitive: false,
    },
  };
};
```

**Functionality**:
Streak implements email tracking using tracking pixels (invisible images embedded in emails). The extension:
1. Uses `declarativeNetRequest` API to block tracking pixel loads
2. Blocks images from `googleusercontent.com` and `mailfoogae.appspot.com` domains
3. Replaces blocked images with empty 1x1 transparent GIFs

**Mechanism**:
- **Global blocking**: Blocks tracking pixels for all Gmail accounts in the browser
- **Tab-specific allowlisting**: Allows pixels for emails not related to the current Gmail account

This prevents tracking notifications from firing when the user reloads a tab with their own sent tracked email.

**Verdict**: This is the **core legitimate functionality** of the extension - email tracking. The implementation is transparent and documented in the code comments.

### 3. Network Communication Domains

**Severity**: INFORMATIONAL
**Status**: LEGITIMATE

**Authorized Domains** (from manifest.json):
- `mail.google.com` - Gmail integration
- `mailfoogae.appspot.com` - Streak backend (Google App Engine)
- `*.mailfoogae.appspot.com` - Streak subdomains
- `*.googleusercontent.com` - Google's CDN for user content
- `*.google.com` - Google services
- `*.streak.com` - Streak website and assets

**API Endpoints Observed**:
- `https://www.streak.com/*` - Main website
- `https://support.streak.com/*` - Support documentation
- `https://assets.streak.com/clientjs-static/*` - Static assets
- `https://mail.google.com/sync/*/i/fd` - Gmail sync API (InboxSDK)

**Verdict**: All network communication is directed to legitimate Streak infrastructure and Google services. No third-party analytics, ad networks, or suspicious endpoints detected.

### 4. Permissions Analysis

**Declared Permissions**:
- `storage` - Local settings and configuration storage
- `scripting` - Content script injection (for Gmail integration)
- `declarativeNetRequestWithHostAccess` - Image blocking for tracking
- `management` - Extension compatibility checking

**Host Permissions**:
- Gmail and Google services (necessary for CRM functionality)
- Streak's own domains (backend communication)

**Verdict**: All permissions are **justified and necessary** for the stated functionality. No excessive or suspicious permissions requested.

### 5. Content Security Policy

**Manifest CSP**: Not explicitly defined (uses default MV3 CSP)

The extension uses Manifest V3 which enforces strict CSP by default:
- No remote code execution
- No `eval()` or inline scripts in extension context
- All code bundled with the extension

**Verdict**: CSP is appropriate for MV3 extension.

### 6. Code Injection Analysis

**Injection Mechanism**:
The extension uses `chrome.scripting.executeScript()` to inject scripts into Gmail pages. This is done through:
- Content scripts defined in manifest (`app-mv3.js`, `app-common-gmail-main-world.js`)
- Dynamic injection via InboxSDK (`pageWorld.js` injection)

**Injected Scripts**:
- `pageWorld.js` (568 KB) - InboxSDK library for Gmail integration
- `app-mv3.js` (4.9 KB) - Content script loader
- `clientjs/*` (55 MB total) - Webpack-bundled application code

**Verdict**: Code injection is limited to Gmail pages and uses the legitimate InboxSDK framework. No malicious injection detected.

### 7. Third-Party Dependencies

**Identified Libraries**:
- **InboxSDK** - Gmail integration framework (open source)
- **React 18.3.1** - UI framework
- **Kefir.js** - Reactive programming library
- **Lodash** - Utility library
- **Monaco Editor** - Code editor (Microsoft VSCode's editor)
- **Userflow** - User onboarding/tutorial system
- **Phoenix** - WebSocket library (Elixir channels client)

**Verdict**: All dependencies are **legitimate open-source libraries**. No suspicious or obfuscated third-party code detected.

### 8. Dynamic Code Execution

**Analysis**: Searched for `eval()`, `Function()`, `setTimeout()` with string arguments - **none found** in the main extension scripts.

The webpack-bundled code uses standard module loading without dynamic code generation.

**Verdict**: No dynamic code execution vulnerabilities detected.

### 9. Keylogging & Form Harvesting

**Analysis**: Searched for keyboard event listeners and value extraction patterns in Gmail context.

No evidence of:
- Unauthorized keylogging
- Password harvesting
- Credit card capture
- Cookie stealing

The extension does track user interactions for legitimate CRM purposes (email opens, link clicks) but this is the **stated functionality**.

**Verdict**: No malicious data harvesting detected.

### 10. XHR/Fetch Hooking

**Analysis**: The extension uses InboxSDK's XHR wrapping functionality:

```javascript
// pageWorld.js - InboxSDK's XHR proxy
mainFrame.XMLHttpRequest = XHRProxyFactory(main_originalXHR, main_wrappers, {
  logError,
});
```

This is used to intercept Gmail's AJAX requests to provide CRM features like:
- Detecting when emails are sent
- Tracking email opens
- Syncing with Streak backend

**Verdict**: XHR hooking is **limited to Gmail's APIs** and is part of InboxSDK's documented functionality. This is not malicious hooking.

## False Positive Analysis

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `chrome.management.getAll()` | background-mv3.js:320 | Legitimate compatibility checking for conflicting extensions |
| XMLHttpRequest hooking | pageWorld.js:2193 | InboxSDK framework for Gmail API interception (documented) |
| Image blocking | background-mv3.js:188-312 | Core email tracking feature (legitimate) |
| postMessage usage | iframe.js:16-50 | iframe bridge for Gmail integration (secure) |
| Extension enumeration | clientjs.chunk.2733:74 | Conflict detection, not extension killing |

## API Endpoints Table

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `mailfoogae.appspot.com` | Streak backend API | User email, CRM data, tracking events |
| `mail.google.com/sync/*/i/fd` | Gmail sync API | Gmail metadata (via InboxSDK) |
| `assets.streak.com/clientjs-static` | Static assets | None (CDN) |
| `support.streak.com` | Documentation | None (opens in new tab) |
| `www.streak.com/addusertoplan` | Billing/team management | User email, team key |

## Data Flow Summary

**Collected Data**:
1. **User Email**: Gmail address of the user
2. **Email Metadata**: Subject lines, recipients, timestamps
3. **Tracking Events**: Email opens, link clicks (core feature)
4. **CRM Data**: Pipelines, contacts, notes entered by user
5. **Extension List**: Names of installed extensions (base64 encoded, for debugging)

**Data Transmission**:
- All data sent to Streak's backend (`mailfoogae.appspot.com`)
- HTTPS encrypted
- No third-party sharing detected in code

**Data Storage**:
- `chrome.storage` API for local settings
- No sensitive data stored locally without encryption indication

**Privacy Considerations**:
The extension inherently requires access to email content to provide CRM and tracking features. Users should be aware that:
- Streak can access all Gmail data
- Email tracking data is sent to Streak's servers
- Extension usage analytics are collected

This is **disclosed in the extension description** and is the core functionality users install the extension for.

## Security Strengths

1. **Manifest V3 Compliance**: Uses latest security standards
2. **No Remote Code**: All code bundled with extension
3. **Legitimate Company**: Well-funded, transparent company with public team
4. **Open Documentation**: Feature behavior documented in code comments
5. **Standard Permissions**: Only requests necessary permissions
6. **InboxSDK Framework**: Uses documented, open-source Gmail integration
7. **No Extension Killing**: Only warns about conflicts, doesn't disable extensions
8. **No Malicious SDKs**: No Sensor Tower, Pathmatics, or similar detected
9. **No Proxy Infrastructure**: No residential proxy or VPN functionality
10. **No Ad Injection**: No coupon or ad injection detected

## Recommendations

**For Users**:
- This extension is **safe to use** for its intended purpose
- Be aware it has full access to Gmail data (required for functionality)
- Understand that email tracking data is sent to Streak's servers
- Review Streak's privacy policy at streak.com

**For Developers**:
- Consider making the extension list collection opt-in
- Add more transparency about what data is sent to backend
- Document the XHR hooking behavior in user-facing docs

## Conclusion

Streak Email Tracking for Gmail is a **legitimate, professionally developed extension** with no malicious behavior. It implements its stated functionality (email tracking and CRM) in a straightforward manner using standard Chrome extension APIs and the well-documented InboxSDK framework.

The extension enumeration feature, while potentially concerning in isolation, is used only for compatibility warnings and not for competitive sabotage. The extension does not kill, disable, or interfere with other extensions.

All network communication is limited to Streak's own infrastructure and Google services. No unauthorized data exfiltration, market intelligence SDKs, residential proxy infrastructure, or malicious code was detected.

**Final Verdict**: CLEAN

---

**Report Generated**: 2026-02-07
**Analyzed Version**: 7.56
**Analysis Method**: Static code analysis of deobfuscated extension code
