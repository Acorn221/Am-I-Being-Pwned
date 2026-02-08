# Vulnerability Report: Secure Exam Proctor (Proctorio)

## Metadata
- **Extension ID:** fpmapakogndmenjcfoajifaaonnkpkei
- **Name:** Secure Exam Proctor (Proctorio)
- **Version:** 1.5.25325.55
- **Users:** ~4,000,000
- **Manifest Version:** 3
- **Analysis Date:** 2026-02-08

## Executive Summary

Secure Exam Proctor (branded as Proctorio) is an exam proctoring extension used by educational institutions. It is an extremely invasive extension that requests nearly every available Chrome permission, including screen capture, webcam/microphone access, desktop capture, tab capture, proxy control, browsing data deletion, management of other extensions, privacy settings control, system hardware info, and `<all_urls>` host access. The extension actively disables other extensions, closes DevTools windows, monitors screen contents via pixel-level analysis, captures screenshots, blocks AI/cheating websites, and sends telemetry to `telemetry.proctorcollect.com`.

While extremely invasive, **all observed behaviors are consistent with exam proctoring functionality**. The extension is a well-known, widely-deployed commercial product used by universities. No evidence of residential proxy infrastructure, market intelligence SDKs, ad injection, cryptocurrency mining, credential theft, or data exfiltration beyond its intended proctoring purpose was found.

## Vulnerability Details

### 1. Extension Enumeration and Disabling (MEDIUM)
- **Severity:** MEDIUM
- **Files:** `assets/Js2Q.js` (service worker)
- **Code:**
  ```javascript
  // Enumerates all extensions and disables those on a blacklist (Ih list)
  n.map(e=>{const n=F(e);t.Ih.includes(n)&&(Ps.send(["_trackEvent","rEvE","y42Y",e]),t.ft.zu.setEnabled(e,!1,uh))})

  // Also disables duplicate Proctorio instances
  Qh(t){const e=t.filter(t=>this._h[F(t)]);if(e.length>1){...this.ft.zu.setEnabled(e,!1,uh)}}

  // Generic disable by message command
  case"disable":pn[1]&&xo.zu.setEnabled(pn[1],!1,Ie)
  ```
- **Verdict:** Expected for exam proctoring - disabling screen sharing, VPN, and AI assistant extensions during exams. Uses `chrome.management.getAll()` and `chrome.management.setEnabled()` to enumerate and disable extensions with matching hashes stored in `Ih` and `_h` lists.

### 2. DevTools Detection and Forced Self-Disable (MEDIUM)
- **Severity:** MEDIUM
- **Files:** `assets/Js2Q.js`
- **Code:**
  ```javascript
  // Detects DevTools windows and self-disables / interrupts exam
  xo.Vu.getCurrent({populate:!0,windowTypes:["devtools"]},t=>{
    t&&t.tabs&&"DevTools"===t.tabs[0].title&&(N=2,setTimeout(()=>{
      xo.zu.get(xo.wt.id,function(t){t.enabled&&(Ye(!1),xo.zu.setEnabled(xo.wt.id,!1))})
    },2e3))
  })

  // Also closes DevTools popup windows
  xo.Vu.remove(t[e].id).catch(t=>{})
  ```
- **Verdict:** Anti-tampering measure for exam integrity. Detects `chrome-devtools://` URLs and DevTools windows, interrupts the exam session, and sends tracking events (`rEvE/8znf`, `rEvE/Dgxw`).

### 3. Privacy Settings Modification (MEDIUM)
- **Severity:** MEDIUM
- **Files:** `assets/Js2Q.js`, multiple helper scripts
- **Code:**
  ```javascript
  // Controls third-party cookie and password saving settings
  chrome.privacy.websites.thirdPartyCookiesAllowed.set(...)
  chrome.privacy.services.passwordSavingEnabled.set(...)
  ```
- **Verdict:** Expected for exam lockdown - prevents password autofill during exams and manages cookie settings for LMS integration.

### 4. Proxy Settings Control (LOW)
- **Severity:** LOW
- **Files:** `assets/Js2Q.js`
- **Code:**
  ```javascript
  chrome.proxy.settings.set(...)
  chrome.proxy.settings.get(...)
  chrome.proxy.settings.clear(...)
  ```
- **Verdict:** Used to prevent VPN/proxy bypass during exams. No evidence of routing traffic through third-party proxies for residential proxy purposes.

### 5. Screen Capture and Recording (MEDIUM)
- **Severity:** MEDIUM
- **Files:** `assets/offscr.js` (offscreen document)
- **Code:**
  ```javascript
  // Uses navigator.mediaDevices.getDisplayMedia for screen capture
  this.v=await navigator.mediaDevices.getDisplayMedia(this.screenConstraints)
  // Pixel-level monitoring via canvas for tampering detection
  screenContextTransfer.getImageData(...)
  // Screenshot capture via tabs API
  chrome.tabs.captureVisibleTab(e,{format:"jpeg",quality:20})
  ```
- **Verdict:** Core proctoring functionality. Captures screen to detect cheating. The `yt` class implements pixel-level "hitbox" monitoring that detects if the exam content area has been altered or overlaid (anti-screen-sharing detection).

### 6. Telemetry Collection (LOW)
- **Severity:** LOW
- **Files:** `assets/Js2Q.js`
- **Code:**
  ```javascript
  // Sends telemetry events to Proctorio servers
  const Ms=new class{
    constructor(t="https://telemetry.proctorcollect.com/c",e=5e3,n=1){...}
    async el(t,e,n,r="event",...){
      // POSTs binary telemetry data
    }
  }
  // Various tracking events: rEvE (extension events), DBZw (UI events), comp (companion)
  Ps.send(["_trackEvent","rEvE","y42Y",e])
  ```
- **Verdict:** First-party analytics for exam session monitoring. All data goes to Proctorio-owned domains (`telemetry.proctorcollect.com`). No third-party SDK injection.

### 7. AI/Cheating Website Blocklist (INFO)
- **Severity:** INFO
- **Files:** `assets/helpers/cd43b.js`, `assets/helpers/qq3e.js`
- **Code (decoded from Uint8Array):**
  ```
  chegg.com|openai.com|chatgpt.com|jasper.ai|rytr.me|hoppycopy.co|writesonic.com|
  gemini.google.com|claude.ai|x.ai|writer.com|ai-writer.com|anyword.com|articleforge.com|
  copy.ai|copysmith.ai|frase.io|kafkai.com|narrativa.com|peppercontent.io|scalenut.com|
  shortlyai.com|wordtune.com|otter.ai|sembly.ai|krisp.ai|fireflies.ai|perplexity.ai|grok.com

  // Voice assistant keywords
  google|siri|alexa|gpt|lynda|linda|copilot|cortana|bixby|meta
  ```
- **Verdict:** Blocklist of AI/cheating tools used during exam lockdown. Standard exam integrity measure.

### 8. Virtual Camera/Device Detection (INFO)
- **Severity:** INFO
- **Files:** `assets/Js2Q.js`
- **Code:**
  ```javascript
  // Long list of virtual camera/capture software to detect during exams
  ke=["virtual camera","virtual webcam","virtual device","virtual driver","webcammax capture",
  "fake webcam","openni","sparkocam","ispy","vlc capture","ucanvcam","manycam","magiccamera",
  "splitcam","ip camera","mjpeg camera"..."droidcam source"..."snap camera"...]
  ```
- **Verdict:** Detects virtual webcam software to prevent webcam spoofing during exams.

### 9. String Obfuscation via Uint8Array Encoding (LOW)
- **Severity:** LOW
- **Files:** Multiple (cd43b.js, qq3e.js, and others)
- **Code:**
  ```javascript
  function Ge(e){const t=new Uint8Array(e);return(new TextDecoder).decode(t)}
  // Domains encoded as byte arrays rather than plaintext strings
  Ge([104,116,116,112,115,58,47,47...]) // "https://getproctorio.com"
  ```
- **Verdict:** Mild obfuscation of domain strings and configuration values. While this is an anti-analysis pattern, it is common in commercial software to prevent string-based static analysis tools from flagging domain names. All decoded strings point to legitimate Proctorio infrastructure.

### 10. Browsing Data Removal (LOW)
- **Severity:** LOW
- **Files:** `assets/Js2Q.js`
- **Code:**
  ```javascript
  chrome.browsingData.remove(...)
  ```
- **Verdict:** Used to clear exam session data after exam completion. Standard for exam lockdown browsers.

### 11. Development Install Self-Uninstall (LOW)
- **Severity:** LOW
- **Files:** `assets/Js2Q.js`
- **Code:**
  ```javascript
  // Detects sideloaded/development installs and forces uninstall
  xo.zu.get(xo.wt.id,function(t){
    if(t&&"development"==t.installType){
      Ps.send(["_trackEvent","rEvE","8Yhf",JSON.stringify(t)]);
      xo.qu.create({url:`${e?ia():ta()}?code=4704&type=corrupted`});
      setTimeout(function(){xo.zu.uninstallSelf()},2e3);
    }
  })
  ```
- **Verdict:** Anti-tampering measure - prevents modified/sideloaded versions from being used during exams.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| DOMPurify innerHTML sanitizer | helpers/cd43b.js, a200s.js, a186s.js | DOMPurify v3.2.5 HTML sanitization library - standard XSS prevention |
| `createElement("script")` via Olark | helpers/a200s.js | Olark live chat widget injection for live proctoring support |
| `eval`-like patterns in DOMPurify | Multiple helper files | Part of DOMPurify's sanitization engine |
| WebSocket to `*.proctor.io` | Js2Q.js | Real-time communication with proctoring servers during exam sessions |
| `chrome.cookies` access | Multiple files | LMS session management for LTI integration |
| `postMessage` handler in qq3e.js | helpers/qq3e.js | Communication bridge between web page and extension for Proctorio exam pages only (origin-checked against secureexamproctor.com) |

## API Endpoints Table

| Endpoint | Purpose | Method |
|----------|---------|--------|
| `https://telemetry.proctorcollect.com/c` | Telemetry/analytics collection | POST |
| `https://getproctorio.com` | Main Proctorio landing/API | GET |
| `https://cdn.proctorauth.com/assets/...` | CDN for assets/icons | GET |
| `https://az545770vo.azureedge.net/configs/` | Configuration data (Azure CDN) | GET |
| `https://az545770.vo.msecnd.net/lti/exam` | LTI exam launch | GET |
| `wss://*.proctor.io/` | WebSocket for real-time proctoring | WebSocket |
| `https://cdn.proctordata.com/` | Proctoring data CDN | GET |
| `https://live.proctoring.com` | Live proctoring service | GET |
| `https://www.secureexamproctor.com` | Main exam proctor site | GET |
| `https://staging.secureexamproctor.com` | Staging environment | GET |
| `https://gbl.proctorauth.com` | Authentication service | GET |
| `https://checkout.stripe.com/c/pay` | Payment processing | GET |
| `http://3v.to/...` | URL shortener (diagnostics) | GET |
| `https://proctorio.zendesk.com/` | Support/help center | GET |
| `https://eucentral.questionmark.com/delivery/` | QuestionMark LMS integration | GET |
| Olark chat (2442-113-10-2938) | Live proctor chat support | JS embed |

## Data Flow Summary

1. **Exam Activation:** Instructor embeds Proctorio link in LMS (Moodle, Canvas, D2L, Blackboard). Content scripts detect the Proctorio embed and communicate with background service worker.
2. **Lockdown:** Extension disables other extensions (from hash-based blocklist), blocks AI/cheating websites via declarativeNetRequest, closes DevTools, modifies privacy/proxy settings.
3. **Monitoring:** Screen recording via `getDisplayMedia`, periodic screenshots via `captureVisibleTab`, webcam monitoring via offscreen document, system info collection (CPU, memory, display, storage).
4. **Telemetry:** Events (extension disable, DevTools detection, exam state changes) are sent to `telemetry.proctorcollect.com` via POST.
5. **Communication:** Real-time WebSocket connection to `*.proctor.io` for live proctoring. Olark chat widget injected for live proctor support.
6. **Cleanup:** Browsing data cleared, extensions re-enabled, privacy settings restored after exam completion.

## Overall Risk Assessment

**CLEAN**

This extension is Proctorio, a well-known commercial exam proctoring solution used by thousands of educational institutions worldwide. While it is one of the most invasive extensions in the Chrome Web Store (requesting 24+ permissions including screen capture, webcam access, extension management, proxy control, and `<all_urls>`), every invasive behavior observed serves a clear exam integrity purpose:

- Extension disabling prevents cheating tools
- DevTools detection prevents code inspection/tampering
- Screen capture and pixel-level monitoring detect screen sharing
- AI/cheating website blocking prevents unauthorized assistance
- Virtual camera detection prevents webcam spoofing
- Privacy settings control prevents session leakage
- Telemetry goes exclusively to first-party Proctorio infrastructure

No evidence of: malware, residential proxy infrastructure, market intelligence SDKs, cryptocurrency mining, credential harvesting, ad/coupon injection, or data exfiltration to unauthorized third parties. The Uint8Array string encoding is mild obfuscation common in commercial software and all decoded values point to legitimate Proctorio-owned domains.
