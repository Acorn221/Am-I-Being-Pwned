# Vulnerability Report: PDF Tab - PDF Converter in a New Tab

## Metadata
- **Extension ID**: dheegnmioobjiclbacdpbgkhgieekfkg
- **Extension Name**: PDF Tab - PDF Converter in a New Tab
- **Version**: 1.0.2
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

PDF Tab is a new tab replacement extension that provides search functionality and PDF file conversion features. The extension sends user search queries to a third-party suggestion service (suggest.finditnowonline.com) without explicit disclosure and uploads user files to an external PDF conversion service (smartpdf.org). While the PDF conversion functionality appears to be the stated purpose, the search query exfiltration to a non-Google/Bing/standard search provider API represents undisclosed data collection.

The extension also fetches preview images for bookmarks from api.tabrr.com. The code shows minimal obfuscation (webpack bundling only) and no evidence of truly malicious intent, but the data flows to third-party services raise privacy concerns that may not be adequately disclosed to users.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Search Query Exfiltration

**Severity**: MEDIUM
**Files**: newtab.bundle.js (line 11442)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension implements search autocomplete functionality by sending every keystroke in the search box to suggest.finditnowonline.com. This third-party suggestion API receives all user search queries as they are typed, representing a form of user behavior tracking that may not be adequately disclosed.

**Evidence**:
```javascript
getSuggestions = e => {
  let t = this,
    n = [];
  e.trim().toLowerCase().length;
  fetch("https://suggest.finditnowonline.com/SuggestionFeed/Suggestion?format=json&q=" + e).then((function(e) {
    return e.json().then((function(e) {
      n = e[1], t.setState({
        suggestions: n
      })
    }))
  }))
};
```

**Verdict**: While search suggestion services are common, this implementation sends data to a non-standard third-party API rather than using official APIs from Google/Bing/DuckDuckGo. The privacy policy and extension description should clearly disclose this behavior. The extension allows users to choose their search engine (Google, Bing, Yahoo, DuckDuckGo) for final searches, but the suggestion service always uses finditnowonline.com regardless of user preference.

### 2. MEDIUM: File Upload to Third-Party Service

**Severity**: MEDIUM
**Files**: newtab.bundle.js (lines 13036-13056)
**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

**Description**: The extension uploads user files (Word documents, Excel spreadsheets, images, PowerPoint presentations) to smartpdf.org for PDF conversion. While this is the stated functionality, users uploading sensitive documents should be aware that files are transmitted to and processed by a third-party service.

**Evidence**:
```javascript
t.append("source", e[0]), t.append("origin", "file-upload"), fetch("https://smartpdf.org/api/tasks/", {
  method: "post",
  headers: {
    host: "smartpdf.org"
  },
  body: t
}).then((e => e.json())).then((function(e) {
  if (e.id) {
    a(3);
    const t = window.setInterval((() => ((e, t) => {
      fetch("https://smartpdf.org/api/tasks/" + e, {
        method: "get",
        headers: {
          origin: "smartpdf.org"
        }
      })
```

**Verdict**: This functionality aligns with the extension's stated purpose ("Simply convert files to PDF directly in a new tab"). However, users should be clearly informed that their files are uploaded to a third-party service. There's no evidence of malicious behavior, but confidential documents uploaded through this feature would be exposed to the smartpdf.org service.

### 3. LOW: Bookmark Preview Image Fetching

**Severity**: LOW
**Files**: background.bundle.js (line 73)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension fetches preview images for user bookmarks from api.tabrr.com, which discloses the domains users have bookmarked to this third-party service.

**Evidence**:
```javascript
function r(t, e, o, r) {
  fetch("https://api.tabrr.com/?url=" + t).then((function(t) {
    return t.text().then((function(t) {
      if (t.length > 50 && t.includes("png")) {
        let l = i(o, e);
        "data:image" === t.substring(0, 10) && (l.previewImage = t, l.url = r.url, l.title = r.title, chrome.storage.local.set({
          userBookmarks: e
        }, (function() {})))
      }
```

**Verdict**: This is a convenience feature to provide visual previews of bookmarked sites. The extension only sends domain names (not full URLs with paths), and the API appears to return site favicons/previews. This is relatively low risk but represents another data flow to a third-party service.

## False Positives Analysis

1. **Webpack Bundling**: The code shows webpack bundling artifacts and React framework code, which is NOT obfuscation. The ext-analyzer flagged the code as "obfuscated" but this is standard JavaScript minification and module bundling.

2. **Search Engine Selection**: The extension provides legitimate functionality allowing users to choose between Google, Bing, Yahoo, and DuckDuckGo as their default search provider. The search forms correctly submit to these official services.

3. **Storage API Usage**: The extension reads from chrome.storage.local for legitimate purposes (theme preferences, user bookmarks, search engine selection). The static analyzer flagged these as potential exfiltration flows, but they are false positives - the data is used locally for UI rendering.

4. **YouTube Flows**: The ext-analyzer flagged flows to youtube.com, but examination shows this is just the default bookmark to YouTube created on installation, not actual data exfiltration.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| suggest.finditnowonline.com | Search autocomplete suggestions | User keystrokes in search box | MEDIUM - user behavior tracking |
| smartpdf.org | PDF conversion service | User-uploaded files (documents, images) | MEDIUM - potentially sensitive files |
| api.tabrr.com | Bookmark preview images | Bookmark domain names | LOW - metadata leakage |
| google.com/search | Search submission | Final search queries (only if Google selected) | LOW - expected behavior |
| bing.com/search | Search submission | Final search queries (only if Bing selected) | LOW - expected behavior |
| yahoo.com/search | Search submission | Final search queries (only if Yahoo selected) | LOW - expected behavior |
| duckduckgo.com | Search submission | Final search queries (only if DDG selected) | LOW - expected behavior |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

The extension performs its stated function (PDF conversion and new tab replacement) but engages in undisclosed data collection through the search suggestion API. The primary concerns are:

1. All search queries typed into the search box are sent to suggest.finditnowonline.com regardless of the user's selected search engine preference
2. User files are uploaded to a third-party PDF conversion service, which may not be adequately disclosed for users handling sensitive documents
3. Bookmark domain names are shared with api.tabrr.com for preview image fetching

The extension does NOT exhibit malicious behavior such as credential theft, hidden data exfiltration, or code injection. However, the privacy implications of sending search queries to a non-standard third-party API warrant a MEDIUM risk classification. Users should be clearly informed about these data flows in the privacy policy and extension description.

The extension would be classified as LOW risk if:
- The search suggestion service used standard APIs from the major search providers instead of a third-party service
- The privacy policy clearly disclosed all external service integrations
- Users were given the option to disable suggestion fetching or use their selected search engine's native suggestion API

The code quality is reasonable with standard webpack bundling and React framework usage. No evidence of intentional obfuscation or anti-analysis techniques was found.
