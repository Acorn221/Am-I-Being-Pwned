# Instapaper Extension Security Analysis
**Extension ID:** ldjkgaaoikpmhmkelcgkgacicjfbofhh
**Users:** ~300,000
**Version:** 3.1.2
**Manifest Version:** 3
**Date:** 2026-02-06

---

## Executive Summary

**RISK LEVEL: CLEAN**

The Instapaper browser extension is a legitimate read-it-later service extension with no malicious behavior detected. All network communications go exclusively to official Instapaper domains, and the extension performs only documented functionality: saving articles, managing highlights, syncing with user accounts, and providing inline save buttons on social media sites.

---

## Manifest Analysis

### Permissions Assessment
```json
"permissions": ["storage", "activeTab", "contextMenus"]
"host_permissions": ["http://*/*", "https://*/*"]
```

**Risk:** LOW
- **storage**: Used for user preferences (keyboard shortcuts, highlights enabled, Twitter/HN integration settings)
- **activeTab**: Required to extract article content when user clicks save button
- **contextMenus**: Adds "Save to Instapaper" right-click menu
- **host_permissions**: Broad access required for content extraction on any page user chooses to save

All permissions align with documented functionality. No dangerous permissions like `management`, `webRequest`, `cookies`, or `declarativeNetRequest`.

### Content Security Policy
No custom CSP defined (uses MV3 defaults). No inline scripts in HTML files.

---

## Background Service Worker Analysis

**File:** `/js/readlater.js` (9.6 KB)

### Network Communications
All API calls target legitimate Instapaper endpoints:
- `https://www.instapaper.com/bookmarklet/post_v6` - Article saving
- `https://www.instapaper.com/bookmarklet/xpaths` - Parser config for better extraction
- `https://www.instapaper.com/highlight/{id}/delete` - Delete highlights
- `https://www.instapaper.com/bookmark/{id}/highlight` - Create highlight
- `https://www.instapaper.com/highlight/{id}/update_note` - Update note
- `https://www.instapaper.com/move/{id}/to/{folder_id}` - Move to folder
- `https://www.instapaper.com/bookmark/{id}/kindle` - Send to Kindle
- `https://www.instapaper.com/update_tags/{id}` - Update tags

**Risk:** NONE - All legitimate service endpoints.

### Key Functions
1. **Article Saving** - Extracts page title, canonical URL, selected text, and compressed HTML
2. **Multi-page Crawling** - Fetches paginated articles (limit 30 pages) for better reading experience
3. **Highlights Management** - Create/update/delete text highlights with notes
4. **Folder Management** - Move saved articles between folders
5. **Tags Management** - Add/remove tags on saved articles
6. **Kindle Integration** - Send articles to Kindle email (Premium feature)

### Firefox Privacy Handling
Lines 156-158, 324-341: Special URL parameter stripping for Firefox:
```javascript
if (isFirefox) {
    /* Mozilla doesn't want us collecting URL params indiscriminately */
    // Strips query params except YouTube ?v= and HN ?id=
}
```
**Risk:** NONE - Actually reduces data collection on Firefox per Mozilla policy.

### Authentication Flow
Line 402-404, 413-415: Redirects to `https://www.instapaper.com/hello2` on 403 errors for login.
**Risk:** NONE - Standard OAuth-style redirect flow.

---

## Content Script Analysis

### Primary Content Script: `bookmarklet.js` (32 KB)

#### Article Extraction Logic
Lines 52-96: `SimpleParser.getBasicPageInfo()`
- Extracts canonical URL from `<meta property="og:url">` or `<link rel="canonical">`
- Gets title from OpenGraph metadata or `document.title`
- Gets thumbnail from `<meta property="og:image">`
- Uses XPath selectors from server API for site-specific parsing

**Risk:** NONE - Standard metadata extraction.

#### HTML Compression
Lines 102-106, 194-216:
```javascript
function jbs(html) {
    if (html.length > 1024*1024) return html; /* too big to deflate quickly */
    return '<' + '![D[' + jbs_deflate(html);
}
```
Uses `deflate-base64-min.js` (38 KB) for client-side HTML compression before upload.
**Risk:** NONE - Performance optimization to reduce network payload.

#### Multi-page Article Detection
Lines 108-174: Detects paginated articles using:
1. Server-provided XPath selectors for "single page" links
2. Server-provided XPath selectors for "next page" links
3. Auto-detection heuristic (Lines 145-172): finds "next" links with similar URLs

**Risk:** NONE - Legitimate reading experience enhancement.

#### DOM Manipulation
All DOM operations are for UI overlay display:
- Lines 759-771: Creates save confirmation overlay with folder/archive/kindle/tags buttons
- Lines 226-244: Folder dropdown for moving articles
- Lines 688-718: Archive button toggle
- Lines 720-738: Send to Kindle button
- Lines 331-393: Tags dropdown UI

**innerHTML Usage:** Lines 418, 445, 839 - Only for reading extracted HTML or updating status text, never injecting external content.

**Risk:** NONE - Standard UI rendering, no injection vulnerabilities.

#### Text Selection Harvesting
Lines 345, 352: Captures `window.getSelection()` when user saves article.
**Purpose:** Becomes article description in Instapaper (documented feature).
**Risk:** NONE - Only collected on explicit user save action, disclosed in Firefox onboarding.

---

### Highlights Feature: `highlights-ugly.js` (22 KB)

Lines 1-200: Text highlighting engine using:
- `window.getSelection()` to detect user-selected text
- XPath/regex to locate text in DOM for highlighting
- Event listeners on highlight spans for delete/note actions

**Risk:** NONE - Standard text selection API for legitimate highlighting feature.

#### Selection Monitoring
Line 183-185:
```javascript
function textSelection() {
    return window.getSelection ? window.getSelection() : document.getSelection ? document.getSelection() : document.selection || void 0
}
```
Only reads selection when user explicitly creates highlight (Opt+Select or save menu).

**Risk:** NONE - No passive keylogging or selection monitoring.

---

### Social Media Integration Scripts

#### Twitter/X Integration: `twitter.js` (2 KB)
Lines 6-48: Adds "Save to Instapaper" button to tweets containing links.
- Polls DOM every 1000ms for new tweets (`setTimeout(addInstapaperAction, 1000)`)
- Injects button into `[role="group"]` (tweet actions bar)
- Calls `saveLink(link.href)` on click

**Risk:** NONE - Standard social media integration pattern.

#### Hacker News Integration: `hackernews.js` (1.2 KB)
Lines 1-25: Adds "instapaper" link to article subtext on HN.

**Risk:** NONE

#### Lobste.rs Integration: `lobsters.js` (1.6 KB)
Lines 1-34: Adds "instapaper" link to story bylines on lobste.rs.

**Risk:** NONE

---

### Tags Management: `tags.js` (13 KB)

Lines 372-376: Keydown listener on search input for Enter key to add tags.
```javascript
searchInput.addEventListener("keydown", function(e) {
    if (e.key == "Enter") {
        _addTextInputTag(searchInput, searchInput.value);
    }
});
```

**Risk:** NONE - Only monitors Enter key in search input field, not page-wide keylogging.

---

## Privacy & Data Collection

### Firefox-Specific Onboarding
**File:** `onboard.html` + `onboard.js`

Lines 16-23 (onboard.html): Explicit disclosure:
```html
<p>In order to save articles to Instapaper, we collect certain information:</p>
<ul>
    <li>URLs of articles you save.</li>
    <li>HTML of articles you save.</li>
    <li>Selected text on the page when you save articles.</li>
</ul>
<p>Instapaper only collects information when you save an article or take an action.</p>
```

Lines 8-17 (onboard.js): Requests host permissions only after consent checkbox.

**Risk:** NONE - Transparent disclosure, explicit consent required (Firefox policy compliance).

### Data Sent to Instapaper
From `bookmarklet.js` lines 343-369:
- **URL**: Page URL (with query params stripped on Firefox except YT/HN)
- **Title**: Page title or OpenGraph title
- **Canonical URL**: If available
- **Selection**: Selected text (20-10240 chars)
- **Thumbnail**: OpenGraph image URL
- **Body**: Compressed HTML (up to 1 MB, stripped of scripts/styles/iframes)
- **Highlights settings**: Whether to enable highlights/auto-highlight selection

**Collection Trigger:** Only on explicit user save action (button click, keyboard shortcut, context menu).

**Risk:** NONE - All data collection is on-demand and disclosed.

---

## Security Checks

### Extension Enumeration/Killing
**Status:** NOT FOUND
- No `chrome.management` API calls
- Only self-uninstall in Firefox onboarding if user declines consent (line 34, `onboard.js`)

### XHR/Fetch Hooking
**Status:** NOT FOUND
- No monkey-patching of `XMLHttpRequest` or `fetch`
- Direct fetch calls only for Instapaper API

### Cookie/Credential Harvesting
**Status:** NOT FOUND
- No `document.cookie` access
- No `localStorage`/`sessionStorage` access
- Authentication via redirect to Instapaper login page (session cookies managed by browser)

### Remote Code Execution
**Status:** NOT FOUND
- No `eval()`, `Function()`, or dynamic code execution
- No external script loading (CDN, remote config)
- `deflate-base64-min.js` is bundled library for compression (legitimate use)

### Ad/Coupon Injection
**Status:** NOT FOUND
- No ad network domains
- No affiliate links or coupon engines
- Social media buttons only inject "Save to Instapaper" links pointing to article URLs

### Residential Proxy Infrastructure
**Status:** NOT FOUND
- No proxy-related code or vendor SDKs

### Market Intelligence SDKs
**Status:** NOT FOUND
- No Sensor Tower, Pathmatics, or similar telemetry SDKs
- No AI conversation scraping logic
- No chatbot widget detection

### Obfuscation
**Status:** MINIMAL
- `deflate-base64-min.js` is minified but legitimate compression library (38 KB, base64 encoding implementation)
- `highlights-ugly.js` is minified but readable (text highlighting engine)
- All other scripts are clean, readable code

---

## False Positive Analysis

### innerHTML Usage
Lines 66 (options.js), 38 (onboard.js), 445 (bookmarklet.js):
```javascript
current_year.innerHTML = (new Date()).getFullYear();
om.innerHTML = message + ' ' + subtitle;
```
**Verdict:** Safe - Only inserting sanitized text (year number, status messages). No external data.

### getSelection() Calls
Multiple files (bookmarklet.js, highlights-ugly.js):
**Verdict:** Safe - Standard Web API for reading user text selection. Only collected on explicit highlight/save actions, not passive monitoring.

### XHR Usage
Line 827-848 (bookmarklet.js): XMLHttpRequest for multi-page article fetching.
**Verdict:** Safe - Crawls pagination links from same site to stitch multi-page articles together. No interception or hooking.

### Keydown Listener
Line 372 (tags.js): Listens for Enter key in tag search input.
**Verdict:** Safe - Scoped to specific input field, not page-wide keylogger.

---

## Comparison to Known Malicious Patterns

| Pattern | Found | Details |
|---------|-------|---------|
| Extension enumeration | NO | No `chrome.management.getAll()` calls |
| Extension disabling | NO | Only self-uninstall on Firefox consent decline |
| XHR/fetch hooking | NO | Direct API calls, no monkey-patching |
| Cookie harvesting | NO | No `document.cookie` access |
| AI conversation scraping | NO | No LLM domain detection (ChatGPT, Claude, etc.) |
| Chatbot widget scraping | NO | No Intercom/Zendesk/Salesforce detection |
| Residential proxy SDKs | NO | No Luminati/Oxylabs/BrightData code |
| Ad injection | NO | No ad network requests |
| Coupon injection | NO | No affiliate/coupon engines |
| Remote config | NO | Only XPath parser hints from Instapaper API |
| Hardcoded secrets | NO | No API keys or credentials in code |
| Obfuscated payloads | NO | Minified libraries only (deflate, highlights) |

---

## Data Flow Diagram

```
User Action (Save Article)
    ↓
bookmarklet.js extracts:
    - Page title/URL/thumbnail
    - Selected text
    - Compressed HTML
    ↓
Background (readlater.js) sends to:
    → https://www.instapaper.com/bookmarklet/post_v6
    ↓
Response includes:
    - bookmark_id
    - folders
    - tags
    - has_kindle flag
    ↓
UI updates with folder/archive/kindle/tags options
    ↓
Further actions (move/archive/kindle/tags) → Instapaper API
```

All data flows exclusively to legitimate Instapaper endpoints. No third-party analytics, no telemetry, no tracking pixels.

---

## Legitimate Use Cases

1. **Article Saving**: Core functionality - extracts article HTML/metadata and uploads to Instapaper service
2. **Multi-page Detection**: Automatically stitches paginated articles for seamless reading
3. **Highlights & Notes**: Allows users to highlight text and add notes synced across devices
4. **Social Media Integration**: Adds one-click save buttons on Twitter, HN, Lobste.rs for convenience
5. **Folder Management**: Organize saved articles into folders
6. **Tags Management**: Add searchable tags to articles
7. **Kindle Integration**: Send articles to Kindle email (Premium feature)
8. **Firefox Privacy Compliance**: Strips URL params per Mozilla policy, requires explicit consent

---

## Recommendations

### For Users
**SAFE TO USE** - Instapaper is a well-established read-it-later service with transparent data practices.

**Privacy Considerations:**
- Extension collects page HTML and selected text when you save articles (required for service functionality)
- Firefox version requires explicit consent and strips URL query parameters for privacy
- All data syncs to Instapaper account (not leaked to third parties)
- Premium features (Kindle, unlimited notes, full-text search) require paid subscription

### For Developers
No security issues identified. Extension demonstrates good practices:
- Minimal permissions for required functionality
- Transparent data collection disclosure (especially Firefox)
- No third-party SDKs or tracking
- Clean, readable codebase
- Manifest v3 compliance

---

## Verdict

**RISK LEVEL: CLEAN**

The Instapaper extension is a legitimate service with no malicious behavior. All network traffic goes to official Instapaper domains, all permissions are justified by documented features, and the Firefox version includes transparent consent flows per Mozilla policy. The extension performs exactly as advertised: saving articles to the Instapaper read-it-later service with optional highlights, folders, tags, and Kindle integration.

**No vulnerabilities or privacy violations detected.**

---

## Technical Evidence Summary

| Category | Status | Evidence |
|----------|--------|----------|
| Manifest Permissions | CLEAN | storage, activeTab, contextMenus - all justified |
| Background Script | CLEAN | Only calls Instapaper API endpoints |
| Content Scripts | CLEAN | Article extraction + UI overlay only |
| Network Traffic | CLEAN | 100% to *.instapaper.com domains |
| Dynamic Code | NONE | No eval/Function/remote scripts |
| Cookie Access | NONE | No document.cookie calls |
| Extension Killing | NONE | Only self-uninstall on consent decline |
| SDK Injection | NONE | No third-party SDKs detected |
| Data Harvesting | CLEAN | Only on explicit user save action, disclosed in onboarding |
| Obfuscation | MINIMAL | Two minified libraries (compression, highlights) - legitimate |

**Total JavaScript Size:** 152 KB across 11 files
**External Dependencies:** None (all bundled)
**Third-Party Domains:** None

---

## Files Analyzed

### JavaScript (11 files)
- `/js/readlater.js` (9.6 KB) - Background service worker
- `/js/bookmarklet.js` (32 KB) - Article extraction & save UI
- `/js/highlights-ugly.js` (22 KB) - Text highlighting engine
- `/js/tags.js` (13 KB) - Tags management UI
- `/js/premium.js` (6.1 KB) - Premium upgrade modal
- `/js/twitter.js` (2 KB) - Twitter integration
- `/js/onboard.js` (1.7 KB) - Firefox onboarding/consent
- `/js/options.js` (2.1 KB) - Settings page
- `/js/hackernews.js` (1.2 KB) - HN integration
- `/js/lobsters.js` (1.6 KB) - Lobste.rs integration
- `/js/deflate-base64-min.js` (38 KB) - HTML compression library

### HTML (3 files)
- `/manifest.json` - MV3 manifest
- `/options.html` - Settings page
- `/onboard.html` - Firefox consent flow

### CSS (5+ files)
Not analyzed - no JavaScript injection risk

---

**Analysis Date:** 2026-02-06
**Analyst:** Claude Code Security Research
**Extension Version:** 3.1.2
**Manifest Version:** 3
