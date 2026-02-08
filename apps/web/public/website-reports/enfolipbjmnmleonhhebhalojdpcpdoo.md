# Vulnerability Report: Screenshot reader (enfolipbjmnmleonhhebhalojdpcpdoo)

## Metadata
| Field | Value |
|---|---|
| Extension Name | Screenshot reader |
| Extension ID | enfolipbjmnmleonhhebhalojdpcpdoo |
| Version | 2.0.14 |
| Manifest Version | 3 |
| User Count | ~8,000,000 |
| Developer | Texthelp (companion to Read&Write for Google Chrome) |

## Executive Summary

Screenshot reader is a legitimate accessibility tool by Texthelp, designed as a companion extension to "Read&Write for Google Chrome." It captures a user-selected screen area, performs OCR via a bundled Tesseract.js engine, and reads the extracted text aloud using Texthelp's SpeechStream text-to-speech service or ElevenLabs TTS. The extension uses broad permissions (`<all_urls>` host permissions and content scripts injected into all frames) which are justified by its core functionality: it needs to capture any visible tab and overlay its selection UI on any page. No malicious behavior, data exfiltration, proxy infrastructure, SDK injection, or remote code execution was found. The code is minified but not obfuscated, and all network activity is clearly tied to legitimate TTS functionality.

## Vulnerability Details

### LOW-001: Hardcoded ElevenLabs API Key
- **Severity:** LOW
- **File:** `features/speech/iframe/speech-iframe.js` (line ~4819)
- **Code:** `apiKey: "D1dHmXy4WxpngFmg4vam"`
- **Verdict:** A hardcoded ElevenLabs API key is present in the speech iframe script. The server is `tts-elevenlabs-streaming-1-us-east-1.texthelp.com` (a Texthelp-owned proxy), not the direct ElevenLabs API. This is a minor credential exposure issue -- if extracted, the key could be abused for unauthorized TTS usage against Texthelp's account. This is not a user-facing security risk but a developer hygiene issue.

### LOW-002: Hardcoded SpeechStream Username
- **Severity:** LOW
- **File:** `scripts/main.js` (beautified lines ~4416-4428)
- **Code:** `userName: "rwforgdocs4"`, `speechServer: "https://speech.speechstream.net/"`
- **Verdict:** The Texthelp SpeechStream username is hardcoded. Similar to LOW-001, this is a minor credential/configuration exposure, not a user data risk.

### INFO-001: Broad Permissions Justified by Functionality
- **Severity:** INFORMATIONAL
- **File:** `manifest.json`
- **Details:** The extension requests `<all_urls>` host permissions and injects content scripts into `<all_urls>` with `all_frames: true`. Additionally, `web_accessible_resources` exposes scripts and OCR page to all URLs.
- **Verdict:** These permissions are necessary for the extension's core functionality: it must capture any visible tab (`chrome.tabs.captureVisibleTab`) and inject its screen capture overlay UI on any page. The content script only listens for specific extension commands (DOSCREENSHOTREAD, doExternalOCR) and does not scrape or exfiltrate page data. **Not a vulnerability.**

### INFO-002: Service Worker Fetch Intercept Modifies CSP Headers
- **Severity:** INFORMATIONAL
- **File:** `scripts/serviceworker.js`
- **Code:** The service worker intercepts all GET requests to its own origin and rewrites the CSP header to `script-src 'self' 'wasm-unsafe-eval'; object-src 'none'`
- **Verdict:** This is done to enable Tesseract WASM execution within the extension's own pages. The `wasm-unsafe-eval` directive is necessary for WebAssembly-based OCR. The intercept only applies to the extension's own resources (service worker scope), not to web pages. The CSP set is actually quite restrictive (no unsafe-inline, no external scripts). **Not a vulnerability.**

### INFO-003: Externally Connectable to Sibling Texthelp Extensions
- **Severity:** INFORMATIONAL
- **File:** `manifest.json` (lines 67-86)
- **Details:** The extension accepts external messages from 10 specific extension IDs (all Texthelp products like Read&Write) and from `*.texthelp.com` domains. Commands accepted: `startScreenShotReader`, `TH_externalOCR_SSR`, `externalOCR`.
- **Verdict:** This is a standard pattern for companion extensions from the same vendor. The accepted commands are narrowly scoped (trigger screenshot read, perform OCR on a provided image). No arbitrary code execution or data exfiltration is possible via these channels.

### INFO-004: Microsoft Teams Trusted Types Override
- **Severity:** INFORMATIONAL
- **File:** `scripts/init.js`
- **Code:** `["teams.microsoft.com","sway.cloud.microsoft"].includes(window.location.hostname)&&window.trustedTypes&&(window.refTrustedTypes=window.trustedTypes,delete window.trustedTypes);`
- **Verdict:** This removes the Trusted Types policy on Microsoft Teams and Sway pages. This is a compatibility workaround, as Trusted Types can interfere with DOM manipulation needed for the overlay UI. It only affects these two specific Microsoft domains, and the original reference is preserved. Minimal security impact as it weakens CSP enforcement on those sites only.

## False Positive Table

| Pattern | Location | Reason Not Malicious |
|---|---|---|
| Custom Elements polyfill (innerHTML, DOM manipulation) | main.js lines 1-667 | Standard @webcomponents/custom-elements polyfill for Lit framework |
| btoa/atob usage | serviceworker.js, main.js | Binary-to-base64 conversion for audio data (speech TTS responses) |
| fetch interception in service worker | serviceworker.js | Only intercepts extension's own resources to add WASM-compatible CSP headers |
| WebSocket connection | speech-iframe.js | Connects to Texthelp's ElevenLabs proxy for streaming TTS audio |
| `<all_urls>` content script injection | manifest.json | Required for screenshot capture overlay UI on any page |
| postMessage usage | main.js, ocr.js | Internal communication between content script and OCR iframe |
| document.execCommand("copy") | main.js | Clipboard copy of OCR-extracted text (user-initiated action) |
| `screenshotreader-analytics` CustomEvents | main.js | Local DOM events consumed by sibling Read&Write extension, not sent to any server |

## API Endpoints Table

| Endpoint | Purpose | Data Sent |
|---|---|---|
| `https://speech.speechstream.net/Generator/voice/{voice}` | Texthelp SpeechStream TTS | SSML text to synthesize, username, speed settings |
| `https://{cacheServer}/SpeechCache/{path}/{hash}.mp3` | Cached TTS audio retrieval | Cache path (username/voice/speed hash) |
| `wss://tts-elevenlabs-streaming-1-us-east-1.texthelp.com/api/{voiceId}` | ElevenLabs streaming TTS via Texthelp proxy | Text to synthesize, voice settings |

## Data Flow Summary

1. **User clicks extension icon** -> service worker sends DOSCREENSHOTREAD command to active tab's content script
2. **Content script** creates a full-page overlay (`th-ssr-container` custom element) for area selection
3. **Service worker** captures visible tab screenshot via `chrome.tabs.captureVisibleTab`
4. **Content script** crops screenshot to selected area, converts to grayscale
5. **OCR iframe** (`pages/ocr.html`) receives cropped image, runs Tesseract.js OCR locally (no network)
6. **OCR results** returned to content script via postMessage
7. **Text-to-speech**: extracted words sent to Texthelp's SpeechStream server or ElevenLabs proxy for audio synthesis
8. **Audio playback**: received audio played back with word highlighting synchronized to playback timing
9. **Copy function**: user can copy OCR text to clipboard via document.execCommand

All OCR processing happens locally. Only TTS synthesis requires network access to Texthelp servers. No page content, browsing data, cookies, or user information is collected or transmitted.

## Overall Risk Assessment

**CLEAN**

This is a legitimate accessibility extension by Texthelp, a well-known assistive technology company. Despite the broad permissions (`<all_urls>`, all-frames content script injection), the extension uses them strictly for its intended purpose: screenshot-based OCR and text-to-speech. There is no evidence of data exfiltration, tracking, ad injection, proxy infrastructure, extension enumeration, or any malicious behavior. The only minor findings are hardcoded API credentials (ElevenLabs key and SpeechStream username), which represent a developer hygiene issue rather than a user security concern.
