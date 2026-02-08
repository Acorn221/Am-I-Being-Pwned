# Vulnerability Report: nightTab

## Extension Metadata

- **Extension Name**: nightTab
- **Extension ID**: hdpcadigjkbcpnlcpbcohpafiaefanki
- **User Count**: ~100,000
- **Version**: 7.5.0
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

nightTab is a **clean, legitimate new tab customization extension** with no malicious behavior detected. The extension operates entirely offline using localStorage for data persistence, requests zero permissions beyond the new tab override, and contains no network communication, tracking, or data exfiltration capabilities. All code is transparent, well-structured, and focused solely on providing a customizable new tab experience with bookmarks, theming, and widget functionality.

**Overall Risk Level**: CLEAN

## Vulnerability Analysis

### Critical Severity Issues
**None detected.**

### High Severity Issues
**None detected.**

### Medium Severity Issues
**None detected.**

### Low Severity Issues

#### 1. Third-Party Font Loading (INFORMATIONAL)
**Severity**: LOW
**Files**: `index.aa4ffa86a9dab33eb643.js` (lines 13631, 13652, 13763, 13789)
**Description**: Extension includes Web Font Loader library supporting external font APIs.

**Code Evidence**:
```javascript
// Google Fonts API
var $ = "https://fonts.googleapis.com/css";

// Fonts.net API
b(this.c, (a.a.api || "https://fast.fonts.net/jsapi") + "/" + r + ".js" + ...)

// Typekit API
b(this.c, (this.a.api || "https://use.typekit.net") + "/" + t + ".js", ...)

// Fontdeck API
b(this.c, (this.f.api || "https://f.fontdeck.com/s/css/js/") + ...)
```

**Verdict**: BENIGN - Standard Web Font Loader library for loading custom fonts. Only activates if user manually configures external fonts. Default behavior uses local fonts only. No privacy/security risk as this is user-initiated and limited to font stylesheets.

#### 2. innerHTML Usage
**Severity**: LOW
**Files**: `index.aa4ffa86a9dab33eb643.js` (lines 14944, 14964, 14970, 15302, 32871, 38980, etc.)
**Description**: Multiple uses of innerHTML for rendering UI elements.

**Code Evidence**:
```javascript
r && "" != r && (o.innerHTML = r);
t.innerHTML = e, o.appendChild(t.firstChild)
this.element.hour.innerHTML = this.string.hour()
this.element.text.innerHTML = t
```

**Verdict**: SAFE - All innerHTML usage is for rendering sanitized user settings (time/date strings, theme names, bookmark titles) stored in localStorage. No external input or untrusted data is rendered. Standard practice for new tab UI rendering.

#### 3. Background Script with localStorage Access
**Severity**: LOW
**Files**: `initialBackground.js`
**Description**: Minimal background script reads nightTabStyle from localStorage.

**Code Evidence**:
```javascript
if(localStorage.getItem("nightTabStyle")){
  const e=document.createElement("style");
  switch(localStorage.getItem("nightTabStyle")){
    case"light": e.innerHTML="html, body {background-color: rgb(255, 255, 255);}"; break;
    case"dark": e.innerHTML="html, body {background-color: rgb(0, 0, 0);}";
  }
  document.querySelector("head").appendChild(e)
}
```

**Verdict**: SAFE - Benign performance optimization to set background color during page load to prevent flash of default styling. Only reads whitelisted values ("light"/"dark"), no security risk.

## False Positives

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| `navigator.userAgent` | Lines 13496, 13556, 14917, 39337 | Web Font Loader library uses UA detection for browser-specific font rendering bugs. Standard legitimate practice. |
| `navigator.clipboard` | Lines 38214, 45009 | User-initiated clipboard operations for backup/restore functionality. Requires user click on export/import buttons. |
| `innerHTML` | Multiple locations | Rendering user's own settings data (time, date, greetings, bookmark names) from localStorage. No external/untrusted input. |
| `btoa` | Line 13231 | Standard webpack sourcemap encoding. Development artifact, not malicious. |
| GitHub URLs | Lines 24359-38303 | Hardcoded example/preset background images hosted on developer's own GitHub repository. User can customize/remove. |
| `keydown` listeners | Lines 32745, 32792, 40892 | Keyboard shortcuts for menu navigation (Ctrl+Alt+M, Esc, Tab focus loops). Standard accessibility features. |

## API Endpoints & External Connections

| Domain/URL | Purpose | Risk | Notes |
|------------|---------|------|-------|
| `fonts.googleapis.com` | Google Fonts CSS | None | Only if user manually configures Google Fonts |
| `fast.fonts.net` | Fonts.com API | None | Only if user manually configures Fonts.com fonts |
| `use.typekit.net` | Adobe Typekit | None | Only if user manually configures Typekit fonts |
| `f.fontdeck.com` | Fontdeck API | None | Only if user manually configures Fontdeck fonts |
| `github.com/zombieFox/nightTabAssets` | Example preset images | None | Hardcoded example backgrounds, user can replace |
| `github.com/zombieFox/nightTab` | Help/support links | None | Documentation links only |
| `buymeacoffee.com/zombieFox` | Donation link | None | Optional UI element for donations |

**Note**: All font API connections are **conditional** - they only load if the user explicitly configures custom fonts in settings. Default installation makes **zero network requests**.

## Data Flow Analysis

### Data Collection
- **None**. Extension collects no user data, telemetry, or analytics.

### Data Storage
- **localStorage**: All user settings (theme, bookmarks, widgets, layout) stored locally.
- **Format**: JSON backup/export available via user-initiated clipboard copy.
- **Scope**: Data never leaves browser, fully offline.

### Data Transmission
- **None**. No network requests in default configuration.
- Optional font loading only if user manually configures external fonts.
- No tracking pixels, beacons, or analytics.

### Third-Party Integrations
- **Web Font Loader**: Standard open-source library for loading web fonts (Google, Typekit, etc.)
- **Activation**: Only when user manually configures custom fonts
- **Data Shared**: None beyond CSS/font file requests to selected font provider

## Security Assessment

### Permissions Analysis
```json
{
  "chrome_url_overrides": {
    "newtab": "index.html"
  }
}
```
- **Only permission**: New tab override
- **No host permissions**: Cannot access any websites
- **No content scripts**: Cannot inject into pages
- **No background service worker**: Minimal background script only for styling
- **No webRequest/cookies/tabs permissions**: Cannot monitor browsing

### Content Security Policy
- No CSP specified (default Manifest V3 CSP applies)
- No inline scripts in HTML
- No eval() or Function() constructor usage
- No remote code loading

### Code Characteristics
- **Transparency**: Open source project (github.com/zombieFox/nightTab)
- **Build**: Standard webpack bundle with readable deobfuscated code
- **Dependencies**: Moment.js (date/time), Web Font Loader, standard DOM utilities
- **Obfuscation**: None (standard webpack minification only)

### Attack Surface
- **Minimal**: Only processes user's own input (bookmark URLs, theme settings)
- **XSS Risk**: None (no reflection of external data)
- **CSRF Risk**: None (no authenticated operations)
- **Data Exfiltration Risk**: None (no network capability)

## Positive Security Features

1. **Zero Default Network Access**: No external requests in default configuration
2. **Minimal Permissions**: Only requests new tab override
3. **Open Source**: Transparent development on GitHub
4. **Local-First**: All data stored in localStorage, no cloud sync
5. **User Control**: All external resources (backgrounds, fonts) are user-configured
6. **No Tracking**: No analytics, telemetry, or user behavior monitoring
7. **Export/Import**: Full user control over data via JSON backup

## Recommendations

1. **For Users**: Extension is safe to use. Consider reviewing configured external fonts if privacy is a concern.
2. **For Developer**: Consider adding explicit CSP to manifest for defense-in-depth.
3. **For Reviewers**: No security concerns. Extension follows best practices.

## Conclusion

nightTab is a **completely safe, privacy-respecting new tab extension** with zero malicious characteristics. It operates entirely offline by default, collects no data, requires minimal permissions, and provides full transparency through open-source development. The extension is an excellent example of a well-designed, user-focused browser extension that respects privacy and security.

All external resource loading (fonts, preset images) is either user-initiated or clearly documented as optional presets. The codebase shows professional development practices with no red flags.

## Overall Risk Rating

**CLEAN** - No vulnerabilities, tracking, or malicious behavior detected. Safe for installation.

---

**Analysis Completed**: 2026-02-07
**Analyst**: Claude Sonnet 4.5
**Confidence Level**: High
