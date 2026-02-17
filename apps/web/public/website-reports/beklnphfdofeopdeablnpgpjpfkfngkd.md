# Vulnerability Report: Hide My History - A Private History Engine

## Metadata
- **Extension ID**: beklnphfdofeopdeablnpgpjpfkfngkd
- **Extension Name**: Hide My History - A Private History Engine
- **Version**: 2.0.1.1
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

"Hide My History" is a search engine hijacker that sets itself as the default search provider and intercepts all web requests to redirect search queries from major search engines (Google, Bing, etc.) to hidemyhistory.co. The extension uses powerful webRequest blocking permissions on all URLs and implements remote configuration through dynamically fetched regex patterns that control which URLs to redirect. While the stated purpose is privacy-focused search, the implementation reveals extensive tracking capabilities and remote control over user browsing behavior.

The extension fetches redirect rules from a remote server (e.hidemyhistory.co/Update/Regex) that can be updated at any time to change which search queries are intercepted. It also sends the extension ID and potentially search queries to remote servers, creating privacy concerns despite the "privacy-focused" branding. The use of webRequest blocking on all URLs combined with remote configuration represents a security risk as the server could be updated to redirect or block arbitrary websites.

## Vulnerability Details

### 1. HIGH: Search Engine Hijacking with Remote Configuration

**Severity**: HIGH
**Files**: lib/bg.js (lines 8605-8620, 8831, 9735)
**CWE**: CWE-912 (Hidden Functionality)

**Description**: The extension hijacks search engine queries by using webRequest blocking listeners on `<all_urls>` and redirecting matching requests to hidemyhistory.co. The redirect patterns are controlled by regex rules fetched from a remote server at `https://e.hidemyhistory.co/Update/Regex`, allowing the operator to dynamically change which URLs are intercepted without user consent or extension updates.

**Evidence**:
```javascript
// Sets up webRequest blocking on ALL URLs
webRequest.onBeforeRequest.addListener(self.onBeforeRequestHandler,
    { urls: ['<all_urls>'] }, ['blocking', 'requestBody']);

webRequest.onBeforeSendHeaders.addListener(self.allowOrRedirectRequest,
    { urls: ['<all_urls>'] }, ['blocking', 'requestHeaders', 'extraHeaders']);

// Fetches redirect patterns from remote server
webRequest.makeJsonRequest(`${settings.updateDomain}Update/Regex`, (err, result, resultData) => {
    self.setRegexes(resultData);
    storage.set({ regexes: resultData }, 'local');
    self.emit('update-match-regex', self.regexMatches);
});

// Redirects matching search queries
let q = query[1];
result = {
    redirectUrl: self.getQueryUrl(q),
};
```

**Verdict**: This represents undisclosed behavior modification capabilities. While search engine redirection is the stated purpose, the remote configuration mechanism allows arbitrary URL patterns to be matched and redirected without user knowledge. The regex patterns could theoretically be updated to intercept banking sites, webmail, or other sensitive destinations.

### 2. MEDIUM: Extension ID Leakage to Remote Server

**Severity**: MEDIUM
**Files**: lib/bg.js (line 7294)
**CWE**: CWE-359 (Exposure of Private Information)

**Description**: The extension sends the Chrome extension ID to the remote server during installation requests, creating a unique identifier that could be used for tracking.

**Evidence**:
```javascript
newInstallRequest() {
    let installUrl = this.getInstallRequestUrl();
    let result = fetch(installUrl, { headers: { 'Active_Id': (webext.runtime.id) } })
        .then((res) => res.json());
    return result;
}
```

**Verdict**: Sending the extension ID in the `Active_Id` header to `https://e.hidemyhistory.co/Update/Install` allows the server to track individual installations and potentially correlate user behavior across sessions. This contradicts the "privacy-focused" branding.

### 3. MEDIUM: Encrypted Query Parameters Without Key Verification

**Severity**: MEDIUM
**Files**: lib/bg.js (lines 9754-9799)
**CWE**: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)

**Description**: The extension claims to "encrypt" search queries but the implementation appears to use a simple client-side hash that is fetched from the server. The encryption key and method are controlled remotely, and there's no verification that the encryption is actually secure.

**Evidence**:
```javascript
self.getQueryUrl = function getQueryUrl(query) {
    if (self.hash) {
        query = self.encryptQuery(query);
        return self.getEncryptedQueryUrl(query);
    }
    return self.getUnencryptedQueryUrl(query);
};

self.getEncryptedQueryUrl = function getEncryptedQueryUrl(q) {
    return `${settings.searchDomain}search?eq=${encodeURIComponent(q)}`;
};

// Fetches encryption token from remote
webext.webRequest.makeJsonRequest(`${self.getExtSettings().updateDomain}Update/EncToken`, ...);
```

**Verdict**: The "encryption" is client-side only and controlled by server-provided keys, meaning the server can decrypt all queries. This provides no real privacy protection from the hidemyhistory.co operator while potentially giving users a false sense of security.

### 4. MEDIUM: Content Script on All URLs for Tooltip Injection

**Severity**: MEDIUM
**Files**: lib/page-protection.js (lines 1934-1961), manifest.json
**CWE**: CWE-94 (Improper Control of Generation of Code)

**Description**: The extension injects a content script on all HTTP/HTTPS URLs that can inject arbitrary HTML and CSS into pages for "tooltip" functionality. While the current implementation appears benign (showing informational tooltips), the infrastructure could be repurposed.

**Evidence**:
```javascript
self.appendStylesToPage = function appendStylesToPage(styles) {
    let style = document.createElement('style');
    style.type = 'text/css';
    style.appendChild(document.createTextNode(styles));
    document.getElementsByTagName('head')[0].appendChild(style);
    return style;
};

self.messageHandler = function messageHandler(message) {
    self.showTooltips(message.tooltipSelector, message.additionalCss);
};
```

Manifest declares:
```json
"content_scripts": [{
    "run_at": "document_end",
    "matches": ["http://*/*", "https://*/*"],
    "js": ["lib/page-protection.js"],
    "css": ["css/tooltip.css"]
}]
```

**Verdict**: While currently used for legitimate tooltips, this content script could receive updated CSS/selector instructions from the background page to inject different content. Combined with the remote configuration vulnerability, this creates a potential avenue for future malicious behavior.

## False Positives Analysis

The extension uses broad permissions (`webRequest`, `webRequestBlocking`, `<all_urls>`) that are technically necessary for its stated purpose of redirecting search queries. The `chrome_settings_overrides` to set the default search provider is also disclosed functionality. However, the remote configuration mechanism goes beyond what's necessary for a privacy-focused search tool and represents a legitimate security concern rather than a false positive.

The use of webpack bundling is standard and not obfuscation. The code structure follows typical patterns for browser extensions.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.hidemyhistory.co/encsearch | Search queries (encrypted) | Search terms (client-side "encrypted") | MEDIUM - Server can decrypt |
| www.hidemyhistory.co/encsuggest | Search suggestions | Partial search terms | MEDIUM - Tracking potential |
| e.hidemyhistory.co/Update/Regex | Fetch redirect patterns | None (GET request) | HIGH - Remote behavior control |
| e.hidemyhistory.co/Update/Install | Installation tracking | Extension ID in header | MEDIUM - Installation tracking |
| e.hidemyhistory.co/Update/EncToken | Fetch encryption key | Unknown | MEDIUM - Controlled encryption |
| e.hidemyhistory.co/Update/secureformrules | Fetch form protection rules | Unknown | MEDIUM - Remote config |
| e.hidemyhistory.co/Update/whitelistregex | Fetch whitelist patterns | Unknown | MEDIUM - Remote config |
| www.hidemyhistory.co/update/reset | Settings reset notification | None | LOW |
| e.hidemyhistory.co/update/uninstall | Uninstall tracking | Extension key/hash | MEDIUM - User tracking |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: This extension is a search engine hijacker with legitimate disclosure of its primary function (redirecting to hidemyhistory.co search), but implements concerning remote configuration capabilities that go beyond reasonable operational needs. The operator has the ability to:

1. Dynamically update which URLs are intercepted via remote regex patterns
2. Track individual installations via extension ID
3. Potentially access all search queries despite "encryption" claims
4. Inject content into all web pages

While the current behavior appears limited to search redirection, the remote configuration mechanism (regex patterns fetched from e.hidemyhistory.co) could be weaponized to redirect banking sites, intercept credentials, or inject malicious content without requiring an extension update. The "privacy-focused" branding is misleading given the tracking capabilities.

The extension does not rise to HIGH or CRITICAL because:
- The search hijacking is disclosed (via chrome_settings_overrides)
- No evidence of current malicious payload delivery
- No credential theft or financial fraud detected
- No evidence of selling user data (though tracking infrastructure exists)

However, it exceeds LOW risk due to:
- Remote configuration control over URL interception
- Extension ID tracking contradicting privacy claims
- Misleading "encryption" that provides false security
- Overly broad permissions combined with remote config
