# Vulnerability Assessment Report: Google Input Tools

## Extension Metadata
- **Extension Name**: Google Input Tools
- **Extension ID**: mclkkofklkfljcocdinagocijmpgbhab
- **User Count**: ~4,000,000
- **Version**: 11.4.0.0
- **Manifest Version**: 3
- **Publisher**: Google (Official)

## Executive Summary

Google Input Tools is an official Google extension that provides virtual keyboards, handwriting input, and input method editors (IMEs) for over 90 languages. The extension has been analyzed for security vulnerabilities and malicious behavior.

**Overall Risk Assessment: CLEAN**

This is a legitimate Google-developed extension that serves its intended purpose of providing multilingual input capabilities. While the extension requires extensive permissions due to its functionality, the code follows Google's security best practices, uses the SafeValues library for XSS protection, and only communicates with official Google domains for legitimate language processing services.

## Key Findings

### Permissions Analysis
The extension declares the following permissions:
- `offscreen` - For local storage migration
- `tabs` - To inject input tools into active tabs
- `storage` - To persist user settings and language preferences
- `scripting` - To inject content scripts dynamically
- `host_permissions: ["http://*/*", "https://*/*"]` - To provide input tools on all websites

**Verdict**: All permissions are necessary for the extension's core functionality of providing input assistance across all web pages.

### Content Security Policy
No custom CSP is defined in the manifest, using Chrome's default Manifest V3 CSP which is secure.

## Vulnerability Details

### 1. Network Communications - CLEAN
**Severity**: N/A
**Location**: `chext_backgroundpage.js:58`

**Details**:
The extension makes network requests to two official Google API endpoints:
```javascript
var Fb = Cb`https://inputtools.google.com/request`
var Gb = Cb`https://inputtools.google.com/predict`
```

These requests are made via the `Hb` function using the Fetch API:
```javascript
Hb = function(a,b,c,d,e,g){
    b=Eb(b==="/request"?Fb:Gb,c);
    a.g=new AbortController;
    fetch(b.toString(),{
        signal:a.g.signal,
        method:"POST",
        headers:e||{},
        body:JSON.stringify(g)
    })
}
```

**Verdict**: CLEAN - These are legitimate Google Input Tools API endpoints used for:
- Language transliteration requests
- Text prediction/autocomplete
- Handwriting recognition

The URLs are constructed using Google's SafeValues library (the `Cb` template tag) which prevents URL injection attacks.

### 2. Chrome API Usage - CLEAN
**Severity**: N/A
**Location**: `chext_backgroundpage.js` (multiple locations)

**Details**:
The extension uses Chrome APIs appropriately:

- **chrome.storage.local**: Used for persisting user preferences and settings (lines 52-53)
- **chrome.tabs**: Used to query tabs and inject scripts (line 54)
- **chrome.scripting.executeScript**: Dynamically injects language-specific keyboard layouts and IME configs (lines 54-55)
- **chrome.runtime.onInstalled**: Re-injects scripts on extension install/update (line 54)
- **chrome.action.setIcon**: Updates the extension icon based on active language (line 57)
- **chrome.offscreen**: Creates offscreen documents for local storage migration (line 55)

**Verdict**: CLEAN - All Chrome API usage is legitimate and necessary for the extension's functionality.

### 3. Content Script Behavior - CLEAN
**Severity**: N/A
**Location**: `chext_loader.js`, `chext_driver.js`

**Details**:
The extension injects two content scripts on all pages:
1. `chext_loader.js` - Runs in all frames to detect input fields
2. `chext_driver.js` - Main content script that manages input tools UI

The content scripts:
- Listen for keyboard events (keydown, keypress, keyup) to provide input assistance
- Monitor focus changes to activate/deactivate input tools
- Use postMessage for communication between frames and background
- Inject virtual keyboard and handwriting recognition UI when activated

**Keyboard Event Monitoring**:
```javascript
// Lines 121-123 in chext_driver.js
Jl(this.A,q,this.rc,void 0,this);     // keydown
Jl(this.A,t,this.zc,void 0,this);     // keypress
Jl(this.A,Ie,this.tc,void 0,this);    // keyup
```

**Verdict**: CLEAN - Keyboard monitoring is essential for an input method editor. The extension only processes keyboard events when explicitly activated by the user. No evidence of keylogging or data exfiltration of sensitive information.

### 4. XSS/Code Injection Protection - CLEAN
**Severity**: N/A
**Location**: Multiple files

**Details**:
The extension uses Google's SafeValues library throughout the codebase to prevent XSS:

- **Safe HTML Construction**: Uses safevalues sanitization (lines 65-71 in chext_driver.js)
- **Trusted Types Support**: Checks for `trustedTypes` API (line 69 in chext_popup.js)
- **Safe URL Construction**: URLs are created using template literals with validation
- **innerHTML Protection**: Multiple guards against unsafe innerHTML usage

Example from `chext_driver.js:71`:
```javascript
if(c.nodeType===1&&(e=c.tagName,/^(script|style)$/i.test(e)))
    throw d=e.toLowerCase()==="script"?
        "Use setScriptTextContent with a SafeScript.":
        "Use setStyleTextContent with a SafeStyleSheet.",
        Error(d);
c.innerHTML=tm(f);
```

**Verdict**: CLEAN - The extension follows security best practices with comprehensive XSS protections.

### 5. Data Collection - CLEAN
**Severity**: N/A
**Location**: `chext_backgroundpage.js`

**Details**:
Data sent to Google's Input Tools API includes:
- Text being typed (for transliteration/prediction)
- Writing guide data (for handwriting recognition)
- Language preferences
- Pre-context (last 20 characters for better predictions)

No sensitive data is collected. The extension does NOT:
- Access or transmit cookies
- Access or transmit passwords
- Monitor browsing history
- Track user activity across sites
- Send data to third-party domains

**Verdict**: CLEAN - Data collection is limited to what's necessary for input assistance and only sent to official Google APIs.

### 6. Dynamic Script Loading - CLEAN
**Severity**: N/A
**Location**: `chext_backgroundpage.js:54-55`, `chext_driver.js:534`

**Details**:
The extension dynamically loads language-specific files:

```javascript
// Loading keyboard layouts
chrome.scripting.executeScript({
    target:{tabId:c.tab.id},
    files:["layouts/"+b.gl+".js"]
});

// Loading IME configs
chrome.scripting.executeScript({
    target:{tabId:c.tab.id},
    files:["imeconfigs/"+b.gi+".js"]
});
```

The extension includes 165 keyboard layouts and 52 IME configurations for different languages. All files are bundled with the extension (not fetched from remote sources).

**Verdict**: CLEAN - Dynamic script loading is used to load language-specific resources on-demand, improving performance. All scripts are local to the extension package.

### 7. Extension Communication - CLEAN
**Severity**: N/A
**Location**: Multiple files

**Details**:
The extension uses standard Chrome messaging APIs:
- `chrome.runtime.sendMessage` / `onMessage` - For background-content script communication
- `postMessage` - For iframe communication in virtual keyboard
- `chrome.tabs.connect` - For persistent port connections

All communication is internal to the extension or with user-activated UI components.

**Verdict**: CLEAN - No evidence of unauthorized communication with other extensions or external entities.

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| innerHTML usage | chext_driver.js:71, chext_options.js:33 | Protected by SafeValues library checks |
| Keyboard event listeners | chext_driver.js:121-123 | Essential for IME functionality, only active when user enables |
| fetch() calls | chext_backgroundpage.js:21 | Legitimate API calls to inputtools.google.com |
| Dynamic script injection | chext_backgroundpage.js:54-55 | Loading bundled language packs on-demand |
| Google SafeValues error messages | Multiple files | Security library validation messages, not actual errors |

## API Endpoints

| Endpoint | Purpose | Method | Data Sent |
|----------|---------|--------|-----------|
| https://inputtools.google.com/request | Transliteration/prediction | POST | Language code, text input, configuration |
| https://inputtools.google.com/predict | Autocomplete suggestions | POST | Language code, partial text, context |
| https://ssl.gstatic.com/inputtools/images/* | Static assets | GET | None (image resources) |
| https://ssl.gstatic.com/inputtools/js/ime/2/*.js | IME modules | GET | None (script resources) |
| https://ssl.gstatic.com/inputtools/js/config/*.js | Configuration files | GET | None (config resources) |

All endpoints are official Google infrastructure. No third-party or suspicious endpoints detected.

## Data Flow Summary

1. **User activates input tool** → Extension icon clicked or keyboard shortcut used
2. **Content script injected** → Virtual keyboard or handwriting UI displayed
3. **User input captured** → Keyboard events or handwriting strokes
4. **Local processing** → Text formatting, candidate generation
5. **API request (if needed)** → Send to inputtools.google.com for complex transliteration
6. **Response received** → Display suggestions to user
7. **User selection** → Commit text to active input field
8. **Settings persistence** → Save preferences to chrome.storage.local

All data processing is transparent and user-initiated. No background tracking or silent data collection.

## Security Features

1. **Manifest V3 Compliance**: Uses service workers, declarative APIs
2. **SafeValues Library**: Comprehensive XSS protection throughout
3. **Trusted Types**: Support for browser's Trusted Types API
4. **Content Security Policy**: Adheres to Chrome's strict MV3 CSP
5. **HTTPS Only**: All network requests use HTTPS
6. **Input Validation**: Template literal validation for URLs
7. **Official Publisher**: Developed and maintained by Google

## Overall Risk Assessment

**Risk Level: CLEAN**

### Justification:
Google Input Tools is a legitimate, well-maintained extension from Google that provides valuable multilingual input functionality. The extensive permissions and broad web access are necessary for its core purpose of providing input assistance across all websites.

**Why CLEAN despite invasive permissions:**
1. **Official Google Product**: Developed by Google with transparency
2. **Clear Purpose**: All functionality directly supports stated purpose
3. **Security Best Practices**: Uses SafeValues, Trusted Types, and secure coding patterns
4. **No Malicious Behavior**: No evidence of data theft, ad injection, or unauthorized tracking
5. **Legitimate API Usage**: Only communicates with official Google Input Tools APIs
6. **User Control**: All input assistance is user-activated, not automatic
7. **Privacy Respecting**: Minimal data collection, no cross-site tracking
8. **Large User Base**: 4M+ users without reported security incidents

**Recommendation**: This extension is safe to use. Users who need multilingual input capabilities can install it with confidence. The extensive permissions are justified by the extension's functionality and are used appropriately without abuse.
