# Vulnerability Report: Start New Search

## Metadata
- **Extension ID**: hinehnlkkmckjblijjpbpamhljokoohh
- **Extension Name**: Start New Search
- **Version**: 3.3
- **Users**: ~200,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

"Start New Search" is a search hijacking extension that overrides the user's default search provider and redirects all search queries to Yahoo search with affiliate tracking parameters. The extension sets itself as the default search provider via `chrome_settings_overrides` and uses `webRequest` blocking to intercept searches directed at its declared URL (start-new-search.com), redirecting them to Yahoo with hardcoded affiliate parameters (`hspart=rotz`, `hsimp=yhs-001`) that generate revenue for the publisher.

While the extension claims to provide "Yahoo powered search," it does not disclose that it's monetizing user searches through affiliate tracking, and the suspicious behavior of closing and recreating tabs during the first 3 searches suggests attempts to evade detection or ensure proper tracking initialization. With 200,000 users and a 1.0 rating (likely artificially inflated or based on minimal reviews), this represents a significant search hijacking operation.

## Vulnerability Details

### 1. HIGH: Search Hijacking with Undisclosed Affiliate Tracking

**Severity**: HIGH
**Files**: bg.js, manifest.json
**CWE**: CWE-506 (Embedded Malicious Code)
**Description**: The extension overrides the browser's default search provider and redirects all search queries to Yahoo with affiliate tracking parameters, generating revenue without clear disclosure.

**Evidence**:

Manifest declares search provider override:
```json
"chrome_settings_overrides": {
  "search_provider": {
    "keyword": "Start New Search",
    "name": "Start New Search",
    "encoding": "UTF-8",
    "is_default": true,
    "search_url": "http://start-new-search.com/?q={searchTerms}"
  }
}
```

Background script intercepts and redirects searches:
```javascript
function DefaultSearchController() {
    var pa = {
        'lc': 'us',
        'id': 'mdru8e8c16596d07d9e88716',
        'args': 'ArFaIWJoNqArQGMVB7sby78oQGR7xTVoN9IgB7seAT0bQGR7BHFaIT8pxo0aCaZdCaZd'
    },
    url_full = 'https://{%lc%}.search.yahoo.com/yhs/search?p={searchTerms}&hspart=rotz&hsimp=yhs-001&type={%id%}&param2=&param3=&param4=&param1={%args%}';
    // Redirects to Yahoo with affiliate parameters
}

chrome.webRequest.onBeforeRequest.addListener(function(details) {
    var red_url = new DefaultSearchController()
        .get_search_url(details.url.substring(catch_url.length));
    return { redirectUrl: red_url };
}, { urls: [catch_url + "*"] }, ["blocking"]);
```

The affiliate parameters reveal:
- `hspart=rotz` - Yahoo affiliate partner ID
- `hsimp=yhs-001` - Yahoo implementation tracking
- `type=mdru8e8c16596d07d9e88716` - Campaign/product identifier
- `param1=ArFaIWJoNqArQGMVB7sby78oQGR7xTVoN9IgB7seAT0bQGR7BHFaIT8pxo0aCaZdCaZd` - Encoded tracking data

**Verdict**: This is search hijacking with undisclosed monetization. The extension description says "Search now with the powerful Yahoo provided search" but doesn't disclose that every search generates affiliate revenue for the publisher.

### 2. HIGH: Suspicious Tab Manipulation During Initial Searches

**Severity**: HIGH
**Files**: bg.js
**CWE**: CWE-506 (Embedded Malicious Code)
**Description**: During the first 3 searches after installation (or after localStorage is cleared), the extension closes the original tab and creates a new one, likely to evade detection or ensure tracking parameters are properly initialized.

**Evidence**:
```javascript
if (localStorage['PLI']) {
    localStorage['counter'] = 3  // Skip tab manipulation if PLI flag set
} else {
    localStorage['counter'] = 0  // Enable tab manipulation for first 3 searches
}

chrome.webRequest.onBeforeRequest.addListener(function(details) {
    var red_url = new DefaultSearchController()
        .get_search_url(details.url.substring(catch_url.length));
    if (
        (parseInt(localStorage['counter'] || 0) < 3) && localStorage['id']
    ) {
        // First 3 searches: close original tab and open new one
        chrome.tabs.query({
            active: true,
            lastFocusedWindow: true
        }, function(t) {
            tabid = t[0].id;
            chrome.tabs.create({ url: red_url });
            chrome.tabs.remove(tabid);  // Close original tab
            localStorage['counter'] = parseInt(localStorage['counter'] || 0) + 1
        });
    } else return {
        redirectUrl: red_url  // After 3 searches: just redirect
    };
}, { urls: [catch_url + "*"] }, ["blocking"]);
```

**Verdict**: The tab closing/recreating behavior during the first 3 searches is highly suspicious and serves no legitimate user purpose. This appears designed to ensure affiliate tracking parameters are properly registered with Yahoo's systems or to evade browser anti-hijacking protections that might detect redirect patterns.

## False Positives Analysis

None. While some browser extensions legitimately offer alternative search providers, they typically:
1. Clearly disclose affiliate relationships in the description/privacy policy
2. Don't use deceptive domain names (start-new-search.com that immediately redirects)
3. Don't manipulate tabs to ensure tracking
4. Provide actual search functionality rather than pure redirection

This extension provides no value beyond monetizing user searches.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| search.yahoo.com | Search redirection target | Search queries + affiliate parameters (hspart, hsimp, type, param1) | HIGH - All user searches monetized |
| ff.search.yahoo.com | Search suggestions | Search query fragments | MEDIUM - Real-time query tracking |
| start-new-search.com | Dummy search URL (intercepted) | None (never reached) | LOW - Just a placeholder for manifest |
| docs.google.com | Privacy policy | None | CLEAN - Static document |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**: This is a classic search hijacking extension that monetizes user searches through undisclosed affiliate tracking. Key risk factors:

1. **Undisclosed Monetization**: The extension description mentions "Yahoo powered search" but doesn't disclose affiliate revenue generation
2. **Search Query Exfiltration**: Every search query is sent to Yahoo with tracking parameters
3. **Suspicious Tab Manipulation**: The first 3 searches involve closing and recreating tabs, suggesting evasion tactics
4. **Large User Base**: 200,000 users are affected, representing a significant privacy impact
5. **Remote Configuration**: The extension accepts localStorage values for `lc`, `id`, and `args` parameters, allowing remote modification of tracking parameters

The extension provides no legitimate value to users beyond what they could achieve by manually setting Yahoo as their search engine. Its sole purpose is to generate affiliate revenue by hijacking the default search provider setting. The tab manipulation behavior and lack of transparency about monetization elevate this from a typical "annoyware" browser hijacker to a HIGH risk security concern.

**Recommended Action**: Users should immediately uninstall this extension and manually reset their default search provider in Chrome settings.
