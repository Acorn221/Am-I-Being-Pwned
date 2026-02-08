# Speed Dial Extension - Security Analysis Report

## Extension Metadata
- **Extension ID**: ejbjamhkdedinncaeiackcdehpccoejm
- **Extension Name**: Speed Dial
- **Version**: 1.1.9
- **User Count**: ~200,000
- **Author**: Alexander
- **Manifest Version**: 3

---

## Executive Summary

Speed Dial is a **CLEAN** new tab replacement extension with **LOW** overall risk. The extension functions as a bookmark/speed dial manager with customizable layouts and backgrounds. While it collects user browsing patterns through bookmark URLs sent to external APIs and uses Google Analytics, these data collection practices are typical for new tab extensions providing logo/styling services. The extension lacks malicious patterns such as extension enumeration, residential proxy infrastructure, remote kill switches, XHR/fetch hooking, or market intelligence SDKs.

**Risk Level**: **LOW**
**Classification**: **CLEAN**

---

## Manifest Analysis

### Permissions Requested
```json
"permissions": [
  "tabs",
  "unlimitedStorage",
  "contextMenus",
  "storage",
  "favicon"
],
"host_permissions": [
  "<all_urls>"
]
```

### Permission Justification
- **tabs**: Used for creating new tabs with bookmarks and managing tab navigation
- **unlimitedStorage**: Stores user bookmarks, favicons, background images, and settings locally
- **contextMenus**: Right-click context menu to add bookmarks from any page
- **storage**: Stores extension configuration and bookmark data via `chrome.storage.local`
- **favicon**: Uses Chrome's built-in favicon API to fetch site icons
- **host_permissions (all_urls)**: Provides favicon access and allows adding bookmarks from any website

### Content Security Policy
- No explicit CSP defined (uses Manifest V3 defaults)
- No dynamic code execution observed (eval, Function, etc. only in minified libraries)

### Chrome URL Overrides
```json
"chrome_url_overrides": {
  "newtab": "pages/newtab.html"
}
```
- Replaces the new tab page with a custom speed dial interface (legitimate extension purpose)

---

## Vulnerability Assessment

### 1. Bookmark URL Exfiltration to External API
**Severity**: MEDIUM
**Status**: PRIVACY CONCERN
**Files**: `js/tabs.js` (lines 1321, 1349, 1743, 1784, 2114)

**Description**:
When users add or edit bookmarks, the extension sends the full bookmark URL to external APIs hosted at `speed-dial.net`:

1. **Tab Style API**: `http://speed-dial.net/api/tab_style/`
   - Sends: `site` (domain), `full_link` (full URL)
   - Purpose: Retrieves logo/color styling for bookmarks

2. **Page Title API**: `http://speed-dial.net/api/page_title/index_page_title.php`
   - Sends: `site` (domain), `full_link` (full URL)
   - Purpose: Fetches page title metadata

3. **OpenGraph Parser API**: `https://speed-dial.net/api/og_parser/`
   - Sends: `site` (full URL)
   - Purpose: Extracts OpenGraph images for bookmark thumbnails

**Code Examples**:
```javascript
// From tabs.js:1743
$.ajax({
    url: 'https://speed-dial.net/api/tab_style/',
    data: {
        site: _.getDomain($('#page_url').val()),
        full_link: encodeURIComponent($('#page_url').val())
    },
    dataType: 'json',
    method: 'GET'
});

// From tabs.js:1784
$.ajax({
    url: 'https://speed-dial.net/api/og_parser/',
    data: {site: $('#page_url').val()},
    dataType: 'json',
    method: 'GET'
});
```

**Impact**:
- User bookmark URLs are transmitted to third-party servers
- Reveals user browsing interests and frequently visited sites
- Data sent over HTTP in some cases (not HTTPS), vulnerable to interception

**Verdict**: **PRIVACY CONCERN** - While this is a common pattern for extensions providing logo/styling services, users should be aware that their bookmark URLs are shared with `speed-dial.net`. This is disclosed in the extension's purpose but may not be obvious to all users.

---

### 2. Google Analytics Tracking
**Severity**: LOW
**Status**: STANDARD PRACTICE
**Files**: `js/ga.js` (lines 1-9)

**Description**:
The extension includes Google Analytics tracking with account ID `UA-64305484-4`:

```javascript
var _gaq = _gaq || [];
_gaq.push(['_setAccount', 'UA-64305484-4']);
_gaq.push(['_trackPageview']);

(function() {
    var ga = document.createElement('script');
    ga.type = 'text/javascript';
    ga.async = true;
    ga.src = 'https://ssl.google-analytics.com/ga.js';
    var s = document.getElementsByTagName('script')[0];
    s.parentNode.insertBefore(ga, s);
})();
```

**Additional tracking hooks** (commented out but present):
```javascript
// From bg.js:5
// _gaq.push(['_trackEvent', 'extensions', 'install']);

// From bg.js:194
// _gaq.push(['_trackEvent', 'extensions', 'open_share_window']);
```

**Impact**:
- Tracks page views within the extension
- Standard analytics practice for developers to monitor usage

**Verdict**: **ACCEPTABLE** - Standard analytics implementation, not excessive.

---

### 3. Uninstall Survey with User Metrics
**Severity**: LOW
**Status**: STANDARD PRACTICE
**Files**: `js/bg.js` (lines 168-176)

**Description**:
The extension sets an uninstall URL that includes usage metrics:

```javascript
if(chrome.i18n.getMessage('@@ui_locale') == 'ru') {
    if(chrome.runtime.setUninstallURL) {
        const appOpenings = 99;
        const ab = 99;
        chrome.runtime.setUninstallURL(
            'https://speed-dial.net/uninstall/?count='+appOpenings+'&hl='+
            chrome.i18n.getMessage('@@ui_locale')+'&ab_bg='+ab
        );
    }
}
```

**Note**: The code has hardcoded values (`99`) instead of actual localStorage reads, suggesting this feature was disabled or is non-functional.

**Verdict**: **ACCEPTABLE** - Standard uninstall survey pattern, only for Russian users.

---

### 4. Hidden Window Screenshot Capture
**Severity**: MEDIUM
**Status**: LEGITIMATE FEATURE
**Files**: `js/bg.js` (lines 201-278)

**Description**:
The extension can create hidden popup windows to capture screenshots of websites for bookmark thumbnails:

```javascript
function hiddenCapture(link, callback) {
    var windowParam = {
        url: link,
        focused: false,
        left: 1e5,      // Off-screen positioning
        top: 1e5,
        width: 100,
        height: 100,
        type: "popup"
    };

    chrome.windows.create(windowParam, function(w) {
        // ... resize window, wait for page load
        chrome.tabs.captureVisibleTab(w.id, function(dataUrl) {
            callback({
                capture: dataUrl,
                title: tabInfo.title
            });
            chrome.windows.remove(w.id);
        });
    });
}
```

**Impact**:
- Creates off-screen windows to load websites and capture screenshots
- Only triggered when user manually adds a bookmark and selects screenshot option
- Screenshots stored locally, not transmitted externally
- Window auto-closes after 12 seconds timeout

**Verdict**: **LEGITIMATE** - This is a standard bookmark thumbnail capture feature. User-initiated and screenshots are stored locally.

---

### 5. Affiliate Link Replacement
**Severity**: LOW
**Status**: MONETIZATION PATTERN
**Files**: `js/bg.js` (lines 67-89), `js/options.js` (lines 470-492)

**Description**:
The extension replaces broken affiliate links with updated versions:

```javascript
const fixBrokenLinks = (links) => {
    const fixLinks = [{
        broken: "https://alitems.com/g/1e8d11449421a60bd21c16525dc3e8/",
        fixed: "https://aliexpress.ru/#no_ads"
    }, {
        broken: "https://ad.admitad.com/g/tekzyq4q2i21a60bd21cf7c2d5eccb/",
        fixed: "https://worldoftanks.eu/ru/"
    }, {
        broken: "https://ad.admitad.com/g/40f3crspww21a60bd21c9dc87d04ab/",
        fixed: "https://worldofwarships.eu/ru/"
    }, {
        broken: "https://ad.admitad.com/g/1d9ed345dd21a60bd21cdc28f2033d/",
        fixed: "https://www.wildberries.ru/"
    }];

    return links.map(link => {
        const findInBrokens = fixLinks.findIndex(v => v.broken === link.url);
        if(findInBrokens !== -1) {
            link.url = fixLinks[findInBrokens].fixed;
        }
        return link;
    });
}
```

**Impact**:
- Previously installed bookmarks with old Admitad affiliate links are replaced
- Removes affiliate tracking from bookmarks (surprisingly user-friendly)
- Only affects pre-installed bookmarks on fresh install

**Verdict**: **ACCEPTABLE** - Actually removes affiliate links rather than injecting them. No active monetization through link manipulation.

---

## False Positives Identified

### 1. jQuery Library
**File**: `js/jqmini.js`
**Description**: Minified jQuery v1.10.2 library (3,364 lines). Contains `eval()` and DOM manipulation but is a standard, legitimate library.

### 2. Bootstrap/jQuery UI Libraries
**Files**: `js/libs/bootstrap.min.js`, `js/libs/jquery-ui.min.js`, `js/libs/bootstrap-colorpicker.min.js`
**Description**: Standard UI libraries with minified code containing event listeners and DOM manipulation patterns.

### 3. XMLHttpRequest Usage
**Description**: All XMLHttpRequest usage is for legitimate API calls to fetch bookmark styling data or search suggestions from Google/Yandex. No evidence of XHR/fetch hooking or interception.

---

## API Endpoints & External Connections

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `speed-dial.net/api/tab_style/` | Fetch bookmark logo/colors | Domain, full URL | Medium (Privacy) |
| `speed-dial.net/api/page_title/` | Fetch page title metadata | Domain, full URL | Medium (Privacy) |
| `speed-dial.net/api/og_parser/` | Parse OpenGraph images | Full URL | Medium (Privacy) |
| `cdn.speed-dial.net/images/` | Default background images | None (static assets) | Low |
| `cdn.speed-dial.net/logos/` | Bookmark logo assets | None (static assets) | Low |
| `speed-dial.net/uninstall/` | Uninstall survey | Usage count, locale | Low |
| `ssl.google-analytics.com/ga.js` | Analytics tracking | Pageviews | Low |
| `www.google.com/complete/search` | Search suggestions | Search query | Low |
| `suggest.yandex.ru/suggest-ya.cgi` | Search suggestions | Search query | Low |

---

## Data Flow Summary

### Data Collected
1. **Bookmark URLs** - Sent to speed-dial.net APIs for styling/metadata
2. **Page views** - Sent to Google Analytics
3. **Search queries** - Sent to Google/Yandex for autocomplete
4. **Uninstall metrics** - Extension usage count, locale (Russian users only)

### Data Stored Locally
1. **User bookmarks** - URLs, titles, favicons, screenshots
2. **Extension settings** - Layout preferences, background images
3. **Bookmark categories** - User-defined groups/folders
4. **File system storage** - Up to 200MB for favicon/screenshot images

### Data NOT Collected
- Browsing history (outside of manually added bookmarks)
- Cookies or login credentials
- Keyboard input (no keyloggers)
- Extension inventory (no chrome.management API usage)
- Cross-site requests/responses (no XHR/fetch hooking)

---

## Comparison to Known Malicious Patterns

| Pattern | Present | Details |
|---------|---------|---------|
| Extension enumeration/killing | ❌ No | No `chrome.management` API usage |
| XHR/fetch hooking | ❌ No | No network interception code |
| Residential proxy infrastructure | ❌ No | No proxy configuration |
| Remote config/kill switches | ❌ No | No remote code execution |
| Market intelligence SDKs | ❌ No | No Sensor Tower, Pathmatics, etc. |
| AI conversation scraping | ❌ No | No content script injection |
| Ad/coupon injection | ❌ No | Actually removes affiliate links |
| Dynamic code execution | ❌ No | Only in standard libraries |
| Content script injection | ❌ No | No content_scripts in manifest |

---

## Overall Risk Assessment

**Risk Level**: **LOW**
**Classification**: **CLEAN**

### Summary
Speed Dial is a legitimate new tab replacement extension that provides bookmark management with visual customization. While it does send bookmark URLs to external APIs for logo/styling services and uses Google Analytics, these practices are standard for this category of extension and align with the extension's stated functionality.

### Key Strengths
- ✅ No malicious code patterns detected
- ✅ No extension enumeration or killing
- ✅ No XHR/fetch interception
- ✅ No remote kill switches or dynamic code loading
- ✅ No market intelligence SDKs
- ✅ No ad injection or affiliate link injection
- ✅ Local-first data storage (bookmarks stored in chrome.storage.local)
- ✅ Manifest V3 compliant
- ✅ No content scripts (doesn't inject code into websites)

### Privacy Considerations
- ⚠️ Bookmark URLs sent to speed-dial.net APIs (disclosed functionality)
- ⚠️ Google Analytics tracking (standard practice)
- ⚠️ Some API calls over HTTP instead of HTTPS

### Recommendations
1. **For Users**: Be aware that bookmark URLs you add are sent to speed-dial.net for styling/logo retrieval. If you bookmark sensitive URLs (internal tools, private sites), this data will be shared.

2. **For Developer**:
   - Migrate all API calls to HTTPS
   - Consider local-only mode for privacy-conscious users
   - Add privacy policy disclosure in extension description

---

## Conclusion

Speed Dial is a **CLEAN** extension with **LOW** security risk. It functions as advertised and does not exhibit malicious behavior patterns seen in VPN/productivity extensions like Sensor Tower's StayFree/StayFocusd, Urban VPN, or VeePN. The extension's data collection is limited to what's necessary for its bookmark styling features, with no evidence of surveillance, data harvesting beyond stated functionality, or deceptive practices.

**Final Verdict**: **CLEAN / LOW RISK**
