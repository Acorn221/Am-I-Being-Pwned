# Vulnerability Report: ghiblify - new tab

## Extension Metadata
- **Extension ID**: kdaipjfpbngmcginhhahacjkkkpbaefh
- **Extension Name**: ghiblify - new tab
- **Version**: 1.1.6
- **Users**: ~40,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

Ghiblify is a Studio Ghibli-themed new tab replacement extension that provides a calming interface with time/date widgets, weather, to-do lists, quick links, pomodoro timer, music player (YouTube embeds), and customizable backgrounds. The extension is **CLEAN** with no malicious behavior detected. It serves its intended purpose of providing an aesthetic new tab experience with productivity widgets.

The extension uses minimal permissions (storage, geolocation) appropriate for its functionality. All data is stored locally using chrome.storage.local and localStorage. The only external network call is to OpenWeatherMap API for weather data using a hardcoded API key.

## Vulnerability Details

### 1. Hardcoded OpenWeatherMap API Key
**Severity**: LOW
**Location**: `/scripts/weather.js:9`
**Code**:
```javascript
let api = "https://api.openweathermap.org/data/2.5/weather";
let apiKey = "f146799a557e8ab658304c1b30cc3cfd";
```

**Description**: The extension contains a hardcoded OpenWeatherMap API key that is publicly visible in the source code. This API key is used to fetch weather data based on user geolocation.

**Impact**:
- The API key can be extracted and used by others, potentially exhausting the developer's API quota
- The key could be revoked by OpenWeatherMap if abuse is detected
- No direct security risk to users, only to the extension's functionality if the key is disabled

**Verdict**: Low risk - This is a developer operational issue rather than a user security vulnerability. The extension would stop showing weather if the key is revoked.

---

### 2. YouTube Embed Embedded Content
**Severity**: LOW
**Location**: `/index.html:446-474`
**Code**:
```html
<iframe width="100%" src="https://www.youtube.com/embed/jfKfPfyJRdk?&" title="Lofi girl"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"></iframe>
```

**Description**: The extension embeds multiple YouTube iframes with various permissions (autoplay, clipboard-write, gyroscope, etc.) for lo-fi music streaming.

**Impact**:
- YouTube iframes have access to autoplay, clipboard-write, and other browser features
- These are standard YouTube embed permissions and not exploitable
- YouTube content is from trusted channels (Lofi Girl, etc.)

**Verdict**: Low risk - Standard YouTube embed functionality, appropriate for a music player feature.

---

### 3. Missing CSP for script-src in HTML head
**Severity**: LOW
**Location**: `/index.html:10`
**Code**:
```html
<meta http-equiv="Content-Security-Policy" content="script-src 'self' https://ajax.googleapis.com">
```

**Description**: The CSP allows scripts from ajax.googleapis.com, though this domain is not actually used in the loaded scripts. All scripts are loaded from local sources.

**Impact**:
- Allows loading scripts from Google's CDN, which could be a vector if the extension were compromised
- However, no scripts are actually loaded from this domain in current version
- All actual scripts are local files (jQuery, Bootstrap, custom scripts)

**Verdict**: Low risk - Overly permissive but not actively exploited. CSP could be tightened to only 'self'.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `fetch()` calls | `index.js:1341, 1394, 1404` | Loading local JSON config files using `chrome.runtime.getURL()` - safe |
| `fetch()` calls | `weather.js:53` | Legitimate API call to OpenWeatherMap for weather data |
| Service Worker syntax | `index.js:9-55` | Dead/unused code - Service Worker event listeners that don't function in extension context |
| `chrome.storage.sync` | `cursor.js:20,28,50,60` | Standard Chrome sync storage for cursor preferences - legitimate |
| `eval/Function` in jQuery | `jquery-3.6.0.min.js, jquery.min.js` | Standard jQuery library behavior - safe |
| `atob/btoa` in libraries | Various minified libs | Standard base64 encoding in legitimate libraries |
| YouTube iframes | `index.html:446-474` | Music player feature - intended functionality |
| Google Forms embed | `background_en.json:12` | Bug report form URL - legitimate developer support mechanism |

## API Endpoints

| Endpoint | Purpose | Data Sent | Data Received |
|----------|---------|-----------|---------------|
| `https://api.openweathermap.org/data/2.5/weather` | Weather data | Latitude, Longitude, API Key | Temperature, weather description, location name |
| `https://www.youtube.com/embed/*` | Music streaming | None (iframe embed) | Video content |
| `https://fonts.googleapis.com/*` | Font loading | None | Font files |
| `https://www.ghibli.jp/gallery/*.jpg` | Background images | None | Studio Ghibli images |

## Data Flow Summary

### Data Collection
- **Geolocation**: Collected via `navigator.geolocation.getCurrentPosition()` for weather widget
- **User Preferences**: Time format, widget visibility, background filters, cursor size
- **User Content**: To-do list items, notes, quick links
- **Background State**: Last shown background, favorites list, removed backgrounds

### Data Storage
- **localStorage**: Quick links, notes, music selection, avatar selection, weather unit preference, cached geolocation
- **chrome.storage.local**: Widget positions, visibility toggles, time format, background preferences, filters, to-do list data, favorite/removed backgrounds
- **chrome.storage.sync**: Cursor size and cursor image path (synced across devices)

### Data Transmission
- **Outbound**: Only geolocation coordinates sent to OpenWeatherMap API
- **No tracking**: No analytics, no user behavior tracking, no third-party data collection
- **No sensitive data leakage**: User's to-do items, notes, and links remain local

### Privacy Analysis
- Extension does NOT send user-generated content to any server
- Geolocation is used only for weather and stored locally for caching
- No cookies, no tracking pixels, no analytics scripts
- No postMessage to external origins
- All user data stays on the device

## Overall Risk Assessment

**Risk Level**: CLEAN

### Justification
Ghiblify is a legitimate new tab extension with no malicious behavior or significant security vulnerabilities. The extension:

1. **Appropriate Permissions**: Uses only `storage` and `geolocation` permissions, both necessary for its advertised features (saving preferences, weather widget)

2. **Local Data Storage**: All user data (to-do lists, notes, quick links, preferences) is stored locally using chrome.storage.local/sync and localStorage. No exfiltration detected.

3. **Minimal Network Activity**: The only external API call is to OpenWeatherMap for weather data, which is clearly part of the intended functionality.

4. **Open Source Attribution**: Extension credits original developer (suitangi's Minimal-Newtab) and provides links to source repositories.

5. **No Obfuscation**: Code is readable and straightforward, using standard libraries (jQuery, Bootstrap, Moment.js) without suspicious minification beyond normal library builds.

6. **No Malicious Patterns**:
   - No extension enumeration or fingerprinting
   - No XHR/fetch hooking
   - No dynamic code injection
   - No hidden iframes or tracking pixels
   - No ad/coupon injection
   - No cookie harvesting
   - No keylogging
   - No clipboard access abuse

7. **Transparent Functionality**: All features (time, date, search, weather, to-do, music, backgrounds) work exactly as advertised.

### Minor Issues (Non-Critical)
- Hardcoded API key (developer operational issue)
- Slightly permissive CSP (could be tightened)
- Dead service worker code (doesn't execute)
- Missing script files referenced in HTML (backgroundpref.js, prefImg.js) - likely removed in update but not cleaned from HTML

These issues do not constitute malicious behavior or pose security risks to users. The extension fulfills its stated purpose without invasive data collection or hidden functionality.

---

**Verdict**: CLEAN - Safe for use. Extension provides aesthetic new tab experience with productivity tools using minimal, appropriate permissions with no malicious behavior detected.
