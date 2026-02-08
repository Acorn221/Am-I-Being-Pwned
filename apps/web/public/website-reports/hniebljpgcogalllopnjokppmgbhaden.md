# Screen Recorder (hniebljpgcogalllopnjokppmgbhaden) - Vulnerability Report

## Extension Metadata
- **ID:** hniebljpgcogalllopnjokppmgbhaden
- **Version:** 3.3.1
- **Users:** ~2,000,000
- **Manifest Version:** 3
- **Permissions:** desktopCapture
- **Developer Domain:** scre.io
- **Minimum Chrome Version:** 88

## Executive Summary

Screen Recorder by Scre.io is a minimal, privacy-respecting screen and camera recording extension built as a React single-page application. Three independent analysis agents examined the manifest/permissions, background service worker/network behavior, and content script injection surface. All three agents unanimously rated this extension as **LOW RISK / CLEAN**.

The extension requests only a single permission (`desktopCapture`), which is the minimum required for its core screen recording functionality. It declares no host permissions, no content scripts, no web-accessible resources, and no optional permissions. The content security policy is strict (`script-src 'self'; object-src 'self'`), blocking all inline scripts, eval, and external script loading. The background service worker is 23 lines of code that opens the popup window, handles a recording-stopped notification, and disables auto-update -- nothing else.

No external API calls, analytics SDKs, telemetry endpoints, or data exfiltration vectors were identified anywhere in the codebase. The only network-related references are navigation links to the developer's documentation site (scre.io, support.scre.io) and a Google Fonts import. All user preferences (camera position, device IDs, language) are stored locally in `localStorage` and never transmitted. Recorded video data is stored in local IndexedDB. This extension does not interact with visited web pages in any capacity.

## Vulnerability Details

**No true positive vulnerabilities were identified.**

All three analysis agents conducted thorough searches for the following attack patterns and found none:

- XHR/fetch hooking or monkey-patching
- Credential harvesting or form field interception
- Keylogging or keystroke exfiltration
- Browsing history access or page content scraping
- Extension enumeration or ad-blocker killing
- Cookie theft or session hijacking
- Dynamic code execution (eval, new Function, remote script loading)
- Analytics/tracking SDK injection (GA, Mixpanel, Segment, Sentry, etc.)
- Market intelligence SDKs (Sensor Tower Pathmatics, etc.)
- AI conversation scraping
- Ad injection or search hijacking
- Cross-origin postMessage exploitation
- Remote configuration servers or server-controlled behavior

## False Positive Analysis

| Flag | File | Assessment |
|------|------|------------|
| `ga()` function reference | `static/js/main.ff9ff9e3.js:8244` | React internal function (`ga` is a minified variable name), NOT Google Analytics |
| `http://www.w3.org/` namespace URIs | `static/js/main.ff9ff9e3.js` (multiple lines) | Standard XML/SVG/MathML namespace declarations in React DOM rendering |
| `document.createElement("script")` | `static/js/main.ff9ff9e3.js` (Webpack runtime) | Webpack chunk loader for internal code splitting (`/static/js/1.adf9a35a.chunk.js`), loads only bundled extension code |
| `String.fromCharCode()` / `charCodeAt()` | `static/js/main.ff9ff9e3.js` | ts-ebml library for Matroska/EBML video format parsing, standard codec operations |
| `dangerouslySetInnerHTML` | `static/js/main.ff9ff9e3.js` | React framework property for SVG namespace rendering, no user input passed through |
| `keydown` / `keypress` / `keyup` events | `static/js/main.ff9ff9e3.js` | React synthetic event system for extension UI form controls, scoped to popup only |
| `PerformanceObserver` / Web Vitals | `static/js/1.adf9a35a.chunk.js` | CLS/FCP/FID/LCP/TTFB metrics calculated locally but never transmitted (no beacon endpoint) |
| `indexedDB.open()` | `static/js/main.ff9ff9e3.js` | Local video recording storage, no external sync or exfiltration |
| `chrome.runtime.onUpdateAvailable` (update disabled) | `background.js:20` | Prevents mid-recording auto-update interruption; CWS still controls distribution |

## API Endpoints & Domains

| Domain | Protocol | Purpose | Risk |
|--------|----------|---------|------|
| `scre.io` | HTTPS | Navigation links to homepage and privacy policy | NONE -- user-facing links only, not API calls |
| `support.scre.io` | HTTPS | Navigation links to help/support articles | NONE -- user-facing links only, not API calls |
| `fonts.googleapis.com` | HTTPS | Google Fonts (Inter font family) via CSS link | NONE -- standard font CDN |
| `twitter.com/scre_io` | HTTPS | Social media link in footer | NONE -- navigation link |
| `youtube.com` | HTTPS | YouTube channel link in footer | NONE -- navigation link |
| `reactjs.org` | HTTPS | React error decoder URLs (development error messages) | NONE -- never called in production |
| `github.com/legokichi/ts-ebml` | HTTPS | Library metadata (issues/readme URLs in package) | NONE -- never called at runtime |

## Data Flow Summary

- **Collected locally:** Camera/microphone device IDs, UI preferences (camera position, size, shape, zoom, mirror), language selection, video optimization toggle, cookie consent timestamp, recorded video chunks (IndexedDB)
- **Sent to server:** Nothing. Zero external API calls. Zero telemetry. Zero analytics.
- **Not sent:** All locally stored data remains in the browser. No cloud sync, no remote backup, no usage statistics, no crash reporting.

## Chrome API Usage

| API | Location | Purpose |
|-----|----------|---------|
| `chrome.desktopCapture.chooseDesktopMedia()` | `main.ff9ff9e3.js:21056` | Prompts user to select screen/window/tab for recording |
| `chrome.runtime.onMessage.addListener()` | `background.js:1` | Listens for `RECORDING_STOPPED` message from popup |
| `chrome.runtime.sendMessage()` | `main.ff9ff9e3.js:14386` | Sends `RECORDING_STOPPED` signal when recording ends |
| `chrome.runtime.getURL()` | `background.js:13` | Gets extension-internal URL for popup HTML |
| `chrome.windows.create()` | `background.js:12` | Opens 800x690 popup window for recording UI |
| `chrome.windows.update()` | `background.js:5` | Refocuses browser window after recording stops |
| `chrome.action.onClicked` | `background.js:9` | Handles extension icon click to open popup |
| `chrome.runtime.onUpdateAvailable` | `background.js:20` | Suppresses auto-update (prevents recording interruption) |

## Technology Stack

- **Framework:** React 17 (production build)
- **Build Tool:** Webpack with code splitting
- **Video Processing:** ts-ebml (Matroska/EBML format library)
- **Styling:** styled-components with polished helpers
- **Internationalization:** i18next (56 locales)
- **Media Capture:** Native `navigator.mediaDevices.getUserMedia()` + Chrome `desktopCapture` API

## Overall Risk Assessment

**Risk Level: CLEAN**

Screen Recorder is one of the most minimal and well-scoped extensions analyzed in this research project. With only a single permission (`desktopCapture`), no content scripts, no host permissions, a strict CSP, and zero external network communication, the attack surface is effectively nonexistent beyond the intended screen recording functionality.

The extension does not interact with visited web pages, does not collect browsing data, does not include any analytics or telemetry infrastructure, and does not communicate with external servers for any purpose. All data remains local to the user's browser. The codebase is a straightforward React application with standard Webpack bundling and no obfuscation beyond standard minification.

Compared to other extensions analyzed in this research (VeePN, Urban VPN, Troywell, StayFree/StayFocusd, YouBoost, Flash Copilot), which exhibited patterns like extension enumeration, XHR/fetch hooking, AI conversation scraping, and data exfiltration to remote servers, Screen Recorder demonstrates what a well-behaved Chrome extension looks like: minimal permissions, no unnecessary data collection, and transparent functionality.

---

*Report generated: 2026-02-06*
*Analysis: 3-agent parallel review (Manifest/Permissions, Background/Network, Content Scripts/Injection)*
*All agents: unanimous CLEAN rating*
