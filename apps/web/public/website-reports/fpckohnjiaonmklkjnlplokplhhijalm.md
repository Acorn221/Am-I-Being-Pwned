# Vulnerability Report: Family Search

## Metadata
- **Extension ID**: fpckohnjiaonmklkjnlplokplhhijalm
- **Extension Name**: Family Search
- **Version**: 3.0.6
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Family Search is a browser hijacker extension that overrides the user's default search engine to privatesearch.online. The extension presents itself as a family-friendly tool that provides separate search profiles for parents and children, using different search engines (Yahoo/Google/Bing for parents, Kiddle/Kidrex for kids). While the stated functionality is benign, the extension modifies critical browser settings and includes affiliate tracking parameters in all search queries.

The extension does not contain malicious code execution, data exfiltration, or credential theft. However, it monetizes user search behavior through affiliate tracking (yid=c5pr parameter) and redirects all search activity through privatesearch.online servers. The implementation is straightforward with no obfuscation, and the code quality is clean.

## Vulnerability Details

### 1. LOW: Browser Search Hijacking with Affiliate Tracking

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-506 (Embedded Malicious Code - though more accurately search hijacking for monetization)
**Description**: The extension modifies Chrome's default search engine settings to redirect all searches through privatesearch.online with affiliate tracking parameter "yid=c5pr". This is disclosed in the extension's description but represents unwanted modification of browser settings for commercial gain.

**Evidence**:
```json
"chrome_settings_overrides": {
  "search_provider": {
    "encoding": "UTF-8",
    "favicon_url": "https://search.privatesearch.online/favicon.ico",
    "is_default": true,
    "name": "Family",
    "keyword": "Family Search",
    "search_url": "https://search.privatesearch.online/search/?category=web&yid=c5pr&vert=private&q={searchTerms}",
    "suggest_url": "https://sug.privatesearch.online/v1/sug/?yid=c5pr&vert=private&q={searchTerms}"
  }
}
```

The `yid=c5pr` parameter appears in all search URLs, indicating affiliate tracking. The homepage also includes this parameter:
```json
"homepage_url": "https://search.privatesearch.online/wim/ds/gotohub?yid=c5pr"
```

**Verdict**: This is a typical search hijacker/browser modifier extension. While the family safety angle may be legitimate, the primary business model is affiliate revenue from search traffic. The extension is upfront about changing the search engine, but users may not realize all searches are tracked via the yid parameter.

### 2. LOW: Cookie Manipulation for Search Engine Preference

**Severity**: LOW
**Files**: utills/helpers.js, popup/popup.js
**CWE**: CWE-565 (Reliance on Cookies without Validation and Integrity Checking)
**Description**: The extension sets cookies on the privatesearch.online domain to track which search engine profile is active (parent vs. kid). While this is functionally necessary for the extension's stated purpose, it demonstrates how the extension maintains state with the remote search provider.

**Evidence**:
```javascript
export function setCookie(key, value){
    chrome.cookies.set({
        url: 'https://privatesearch.online/',
        domain: '.privatesearch.online',
        name: key,
        value: value,
        secure: true,
        sameSite: 'no_restriction'
    })
}
```

Called from popup.js when changing profiles:
```javascript
changeCurrentUser('parent')
setCookie('se', parentSearchEngine)
```

**Verdict**: The cookie manipulation is consistent with the extension's functionality and does not represent a security vulnerability per se. However, it does create a persistent tracking mechanism with the remote search provider.

## False Positives Analysis

1. **Content Script on privatesearch.online**: The content script only adds a CSS class to detect installation - this is benign:
   ```javascript
   document.body.className += ' c5pr';
   ```

2. **localStorage Usage**: The extension stores user preferences (profile names, avatars, passwords, search engine choices) in localStorage. This is encoded with base64 (not encryption, just obfuscation) but is appropriate for local settings storage:
   ```javascript
   export function setSettings(settings = defaultSettings){
       localStorage.setItem('settings', btoa(JSON.stringify(settings)));
   }
   ```

3. **Password Protection**: The "password" feature is a 4-digit PIN stored locally to restrict access to the parent profile. This is not a security vulnerability - it's a parental control feature. The PIN is stored in plaintext in localStorage, which is acceptable for this use case since it's protecting profile settings, not sensitive data.

4. **Post-Install Tab**: Opening a "thank you" page on install is standard behavior for extensions:
   ```javascript
   if (data['reason'] === 'install') {
       chrome.tabs.create({ url: `https://search.privatesearch.online/wim/thank_you?yid=c5pr` });
   }
   ```

5. **Uninstall URL Tracking**: Setting an uninstall URL is common practice for gathering user feedback:
   ```javascript
   chrome.runtime.setUninstallURL('https://www.websafety.live/removed');
   ```

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| search.privatesearch.online | Primary search queries | Search terms, affiliate ID (yid=c5pr) | LOW - Standard search hijacker revenue model |
| sug.privatesearch.online | Search suggestions | Partial search terms, affiliate ID | LOW - Standard autocomplete functionality |
| www.websafety.live | Marketing/support site | None (just links) | MINIMAL - Static pages for privacy policy, FAQ, contact |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This extension is a browser search hijacker that monetizes user search queries through affiliate tracking. While this behavior is undesirable, it falls into the "LOW" category rather than "MEDIUM" or higher for the following reasons:

1. **No Data Exfiltration**: The extension does not collect or transmit browsing history, form data, cookies, or any sensitive information beyond search queries (which are inherently sent to search engines).

2. **No Code Execution Vulnerabilities**: There is no use of eval(), no dynamic script loading, no XSS vulnerabilities, and proper CSP is in place.

3. **Disclosed Functionality**: The extension description states it "provides two search profiles to keep the family's search activities separated on shared devices" and shows search.privatesearch.online in the manifest, so the search engine override is not hidden.

4. **Limited Permissions**: The extension only requests `contextMenus` and `cookies` permissions, plus host permissions for its own domain. No broad permissions like `<all_urls>`, `webRequest`, or `tabs` beyond what's needed.

5. **Clean Implementation**: The code is straightforward, non-obfuscated, and the family profile switching functionality works as described.

**Why Not CLEAN**: The extension modifies browser settings for commercial gain (affiliate revenue) and redirects all search traffic through a third-party provider. This represents unwanted behavior even if disclosed.

**Why Not MEDIUM**: There is no evidence of undisclosed data collection, no security vulnerabilities that could be exploited, and the functionality matches the description. Users who install this extension get what they signed up for (albeit with affiliate tracking they may not have noticed).

The primary concern is that users may install this thinking they're getting a family safety tool, when the real purpose is search traffic monetization. However, the actual search functionality could still provide value for families wanting separate kid/parent search experiences.
