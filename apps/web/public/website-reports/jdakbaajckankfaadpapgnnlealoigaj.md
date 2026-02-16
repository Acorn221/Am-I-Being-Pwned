# Vulnerability Report: Movie Finder

## Metadata
- **Extension ID**: jdakbaajckankfaadpapgnnlealoigaj
- **Extension Name**: Movie Finder
- **Version**: 3.0.1
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Movie Finder is a search hijacking extension that overrides the user's default search engine to redirect all searches through moviefindersearch.com. While marketed as a movie search utility with omnibox shortcuts (@nf, @imdb, etc.), the extension's primary function is to capture all default search queries and monetize them through a third-party search provider. The extension employs deceptive tactics including forced search engine override (with `"is_default": true`), undisclosed cookie manipulation to track user preferences across the moviefindersearch.com domain, and content script injection on Yahoo.com to manipulate the user interface and discourage search engine changes.

The extension's behavior constitutes a violation of user privacy and consent principles. Users installing a "Movie Finder" extension would not reasonably expect their entire default search experience to be hijacked and monetized, with their search queries routed through a third-party tracking infrastructure.

## Vulnerability Details

### 1. HIGH: Search Hijacking via Forced Default Search Provider Override

**Severity**: HIGH
**Files**: manifest.json, bg/background.js, config.js
**CWE**: CWE-506 (Embedded Malicious Code)
**Description**: The extension forcibly overrides Chrome's default search engine and sets itself as the default with `"is_default": true`. This hijacks all searches performed from the omnibox, redirecting them through moviefindersearch.com with tracking parameters.

**Evidence**:
```json
"chrome_settings_overrides": {
  "search_provider": {
    "encoding": "UTF-8",
    "favicon_url": "https://www.moviefindersearch.com/favicon.ico",
    "is_default": true,
    "name": "Movie Finder",
    "keyword": "Movie Finder",
    "search_url": "https://www.moviefindersearch.com/search/?category=web&s=dkds&vert=movie&q={searchTerms}",
    "suggest_url": "https://sug.moviefindersearch.com/v1/sug/?s=dkds&vert=movie&q={searchTerms}"
  }
}
```

All search queries are routed through this infrastructure with tracking parameters:
- `s=dkds` - affiliate/partner identifier
- `vert=movie` - vertical category
- `category=web` - search category

The uninstall URL also includes these tracking parameters:
```javascript
uninstall: `${url.origin}/wim/uninstall?s=${params['s']}&vert=${params['vert']}`
```

**Verdict**: This is a clear case of search hijacking. The extension's stated purpose is to provide movie search shortcuts (e.g., "@nf Titanic"), but forcing itself as the default search provider means ALL user searches are intercepted, not just movie-related queries. This is undisclosed functionality that violates user consent.

### 2. HIGH: Undisclosed Third-Party Cookie Manipulation and User Tracking

**Severity**: HIGH
**Files**: bg/background.js, config.js
**CWE**: CWE-359 (Exposure of Private Personal Information)
**Description**: The extension uses the `cookies` permission to read and write cookies on moviefindersearch.com domain to track user configuration and behavior. This creates a persistent tracking mechanism across the third-party domain without clear disclosure.

**Evidence**:
```javascript
function writeCookie(cookieName, cookieValue) {
    let date= new Date().getTime() / 1000;
    date=date+60*60*24*365;
    chrome.cookies.set({
        url: `https://${config.domain}`,
        name: cookieName,
        value: cookieValue,
        domain: `.${config.domain}`,
        secure: true,
        sameSite: 'no_restriction',
        expirationDate:date
    });
}
```

Cookies written:
1. `use_ac` - autocomplete preference tracking
2. `services` - base64-encoded JSON of user's selected movie services
3. `se` - selected search engine preference
4. `keep_changes` - tracks whether the user has seen the "keep changes" prompt

The extension sets these cookies with:
- 1-year expiration
- `sameSite: 'no_restriction'` - allows cross-site tracking
- Domain-level scope (`.moviefindersearch.com`) - accessible across all subdomains

Additionally, the extension reads the `keep_changes` cookie to determine whether to show UI manipulation prompts:
```javascript
chrome.cookies.get({url: `https://${config.domain}`, name: 'keep_changes'}, (cookie) => {
    if (cookie) {
        chrome.storage.local.set({'show_keep_changes': 'false'})
    }
    resolve(cookie);
});
```

**Verdict**: The extension creates a persistent tracking infrastructure on a third-party domain. User preferences are synced to cookies that can be read by the moviefindersearch.com website, enabling cross-context tracking. The privacy policy link in the extension (`${url.origin}/wim/privacy?s=${params['s']}`) is dynamically generated, and the actual disclosure of this tracking behavior is unclear.

## False Positives Analysis

1. **jQuery Usage**: The extension includes a standard jQuery 3.x library (3242 lines). The presence of `XMLHttpRequest` and `eval` within jQuery is expected library functionality, not malicious behavior.

2. **Management API for Uninstall**: The extension uses `chrome.management.uninstallSelf()` to allow users to uninstall via the context menu. This is a legitimate feature, though the implementation could be used for remote-triggered uninstall if the extension accepted external messages (it does not currently).

3. **Content Script on Yahoo.com**: The extension injects scripts on `*://*.yahoo.com/*` to display a "keep changes" overlay prompting users to maintain Movie Finder as their default search. While this is manipulative UI behavior, it's not technically exploiting a vulnerability - it's using web_accessible_resources to inject an overlay.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| moviefindersearch.com/search/ | Search query routing | `category=web`, `s=dkds`, `vert=movie`, `q={searchTerms}` | HIGH - All user searches tracked with affiliate ID |
| sug.moviefindersearch.com/v1/sug/ | Search suggestions | `s=dkds`, `vert=movie`, `q={searchTerms}` | MEDIUM - User search terms sent before query completion |
| moviefindersearch.com/wim/gotohub | Homepage redirect | `s=dkds` | LOW - Partner identifier only |
| moviefindersearch.com/wim/uninstall | Uninstall tracking | `s=dkds`, `vert=movie` | MEDIUM - Tracks uninstall events with affiliate ID |
| moviefindersearch.com/wim/rate | Rating link | `id={extension_id}`, `s=dkds`, `a=LikeLink` | LOW - Optional user action |
| moviefindersearch.com/wim/survey | Dislike/survey | `yid={s}`, `vert={vert}`, `extid={extension_id}`, `name={extensionName}` | MEDIUM - Links extension ID to partner ID |
| moviefindersearch.com/wim/help | Help page | `s=dkds` | LOW - Static page with partner ID |
| moviefindersearch.com/wim/contact | Contact page | `s=dkds` | LOW - Static page with partner ID |
| moviefindersearch.com/wim/privacy | Privacy policy | `s=dkds` | LOW - Static page with partner ID |
| moviefindersearch.com/wim/eula | Terms of service | `s=dkds` | LOW - Static page with partner ID |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**: Movie Finder is a search hijacker that employs deceptive practices to monetize user search queries through a third-party tracking infrastructure. While not containing outright malware or credential theft, the extension:

1. **Hijacks default search**: Forces all omnibox searches through moviefindersearch.com with affiliate tracking, far exceeding the stated purpose of providing movie search shortcuts.

2. **Undisclosed tracking**: Implements a cookie-based tracking system on a third-party domain without clear disclosure, syncing user preferences to enable cross-context tracking.

3. **UI manipulation**: Injects content scripts on Yahoo.com specifically to display overlays encouraging users to keep the hijacked search settings.

4. **Monetization infrastructure**: The `s=dkds` parameter appears throughout all API calls, indicating this is part of a partner/affiliate monetization scheme where user searches generate revenue.

The extension's name ("Movie Finder") and description ("quick commands from your browser's address bar to search on popular movie sites") are misleading - the primary functionality is search engine replacement, not movie search shortcuts. Users would not reasonably consent to having their entire default search experience hijacked when installing what appears to be a specialized movie search tool.

**Tags**:
- `behavior:search_hijacking`
- `privacy:third_party_tracking`
- `behavior:deceptive_functionality`
- `privacy:cookie_manipulation`
