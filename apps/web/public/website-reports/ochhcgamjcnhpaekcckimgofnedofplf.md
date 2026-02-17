# Security Analysis: Zoom Video - UltraWide Video

**Extension ID:** ochhcgamjcnhpaekcckimgofnedofplf
**Version:** 1.1.6
**Users:** 400,000
**Risk Level:** CLEAN
**Analysis Date:** 2026-02-15

## Executive Summary

Zoom Video - UltraWide Video is a legitimate browser extension that provides video zoom and aspect ratio controls for ultrawide monitors. The extension injects custom UI controls into popular streaming platforms (Netflix, YouTube, Prime Video, Disney+, HBO Max) allowing users to adjust video scaling and aspect ratios (16:9, 18:9, 21:9, 32:9).

Static analysis flagged one potential data exfiltration flow (risk_score=45, 1 exfil flow), but detailed examination reveals this is a **false positive** caused by Vite's modulepreload polyfill in the React build output. The extension performs no data collection, has no network activity, and operates entirely client-side using chrome.storage.local for user preferences.

## Technical Architecture

### Manifest v3 Components

**Permissions:**
- `storage` - Stores user zoom preferences and settings
- `activeTab` - Required for tab interaction
- `<all_urls>` host permissions - Required for content script injection on streaming sites

**Components:**
- **Background Service Worker** (`src/js/serviceWorker.js`): Handles keyboard shortcuts and message passing
- **Content Script** (`src/js/contentScript.js`): Injects zoom UI controls into streaming sites
- **Popup UI** (`src/layouts/popup.html` + `src/js/popup.js`): React-based settings interface

### Build Stack

The extension uses modern web development tools:
- **React 18** - UI framework
- **Vite** - Build tool and bundler
- **ES Modules** - Module system with dynamic imports

All JavaScript is minified production builds. The popup.js file (257KB) contains the entire React + React-DOM bundle plus the settings UI.

## Functional Behavior

### Core Features

1. **Video Zoom Controls**: CSS scale transforms applied to `<video>` elements
2. **Aspect Ratio Presets**: 16:9, 18:9, 21:9, 32:9, and auto-detect
3. **Keyboard Shortcuts**:
   - Ctrl/Cmd+Up/Down for zoom in/out
   - Dedicated shortcuts for each aspect ratio
4. **Persistent Settings**: Zoom mode (off/session), transition speed, default ratio

### Content Script Injection

The content script targets specific streaming platforms by checking `window.location.href`:
- `youtube.com` - Injects zoom button into YouTube player controls
- `netflix.com` - Adds zoom controls with left-top transform origin
- `primevideo.com` - Custom button placement in Prime Video UI
- `disneyplus.com` - Disney+ player integration
- `play.hbomax.com` - HBO Max controls

The script uses `document.querySelector()` to find platform-specific control containers and injects custom SVG buttons. User interactions trigger `chrome.storage.local` updates and apply CSS transforms to video elements.

### Data Storage

All data stored in `chrome.storage.local`:
- `zoom_{tabId}` - Per-tab zoom state (scale, videoWidth, videoHeight, screenWidth, screenHeight)
- `settings` - Global settings object:
  - `persistentZoomMode`: "off" or "session"
  - `playerButtonDefaultRatio`: "off", "auto", "16x9", "18x9", "21x9", "32x9"
  - `zoomTransitionSpeed`: "0ms", "150ms", "300ms", "600ms", "1000ms"
  - Custom keyboard shortcuts

No data leaves the user's browser.

## Static Analysis Findings

### False Positive: Modulepreload Polyfill

**ext-analyzer Detection:**
```
EXFILTRATION (1 flow):
  [HIGH] document.querySelectorAll → fetch    src/js/popup.js
```

**Analysis:**
The flagged flow occurs in line 1 of `popup.js`:

```javascript
(function(){
  const t=document.createElement("link").relList;
  if(t&&t.supports&&t.supports("modulepreload"))return;
  for(const o of document.querySelectorAll('link[rel="modulepreload"]'))r(o);
  new MutationObserver(o=>{
    for(const i of o)if(i.type==="childList")
      for(const l of i.addedNodes)
        l.tagName==="LINK"&&l.rel==="modulepreload"&&r(l)
  }).observe(document,{childList:!0,subtree:!0});

  function r(o){
    if(o.ep)return;
    o.ep=!0;
    const i=n(o);
    fetch(o.href,i)  // ← Detected as "exfiltration sink"
  }
})();
```

This is **Vite's built-in modulepreload polyfill** that prefetches ES module dependencies for better performance. The `querySelectorAll` finds `<link rel="modulepreload">` tags in the popup.html, and `fetch()` preloads the linked modules (like `getScaleByResolution.js`).

**The fetch targets are local extension resources**, not external URLs. This is standard behavior in modern JavaScript bundlers and poses zero security risk.

### Permission Analysis

**<all_urls> Host Permission:**
While broad, this permission is **necessary and properly scoped**:
- Extension only activates on popular streaming platforms (5 hardcoded domains)
- Content script checks `window.location.href` before injecting UI
- No wildcard domain matching or user data access
- Purely UI manipulation via CSS transforms

**No Network Activity:**
Comprehensive analysis of all JavaScript files confirms:
- Zero `XMLHttpRequest` usage
- Zero `fetch()` calls to external domains
- No WebSocket connections
- No third-party analytics or tracking
- No remote code loading

## Privacy Assessment

### Data Collection: NONE

The extension collects and stores zero user data. All state is ephemeral (tab-specific zoom levels) or user-configured (aspect ratio preferences).

### Third-Party Integrations: NONE

No external services, APIs, CDNs, or tracking pixels.

### Network Requests: NONE

The only network activity is Vite's modulepreload polyfill fetching local extension resources from `chrome-extension://` URLs.

## Security Posture

### Strengths

1. **Minimal Attack Surface**: Pure client-side logic with no server component
2. **Content Security Policy**: `script-src 'self'; object-src 'self'` prevents inline scripts
3. **Isolated Storage**: Per-tab zoom state prevents cross-tab contamination
4. **No Eval/Function**: No dynamic code execution
5. **Modern Build**: Uses TypeScript, ES modules, and React best practices

### Weaknesses

**None identified.** The extension follows security best practices for a UI manipulation tool.

## Verdict

**Risk Level: CLEAN**

Zoom Video - UltraWide Video is a well-engineered, privacy-respecting browser extension with a singular purpose: improving video viewing experience on ultrawide monitors. The static analysis false positive highlights the challenge of automated analysis with minified React bundles and modern build tools.

**Recommendation:** Safe for use. No security concerns identified.

---

## Technical Details

### Files Analyzed
- `manifest.json` (40 lines)
- `src/js/serviceWorker.js` (1 line, 1.6KB minified)
- `src/js/contentScript.js` (78 lines, 153KB minified)
- `src/js/popup.js` (94 lines, 257KB minified React bundle)
- `src/js/getScaleByResolution.js` (2 lines, 1.7KB minified)

### Code Quality
- Production-ready React 18 build
- Proper error handling in async/await patterns
- Clean separation of concerns (background/content/popup)
- TypeScript compilation artifacts visible in minified code

### Permissions Justification
- ✅ `storage` - Required for user preferences
- ✅ `activeTab` - Required for tab messaging
- ✅ `<all_urls>` - Required for content script injection (scoped to 5 streaming sites in practice)

### Update Mechanism
Standard Chrome Web Store auto-update via `https://clients2.google.com/service/update2/crx`
