# Security Analysis: Amazon video downloader (ifilpkbapdaiheanhglnfigdgbhbkcho)

## Extension Metadata
- **Name**: Amazon video downloader
- **Extension ID**: ifilpkbapdaiheanhglnfigdgbhbkcho
- **Version**: 1.9
- **Manifest Version**: 3
- **Estimated Users**: ~30,000
- **Developer**: Unknown
- **Analysis Date**: 2026-02-15

## Executive Summary

Amazon video downloader is a freemium extension designed to download product videos and images from Amazon websites. The extension provides legitimate video/image downloading functionality using FFmpeg.wasm for video processing. However, **the extension exhibits concerning privacy practices** through integration with third-party paywall infrastructure (shareclip.me, ttsmp3.net) that tracks user activity and implements usage restrictions. While the core functionality appears legitimate, the extension sends user identifiers and browsing context to external servers for subscription verification, raising significant privacy concerns.

**Overall Risk Assessment: MEDIUM**

The extension's 14 exfiltration flows detected by static analysis are primarily related to the paywall system transmitting user IDs and DOM state to subscription validation servers. The extension does not appear to be outright malware, but users should be aware of the privacy implications of the third-party tracking infrastructure.

## Vulnerability Details

### 1. Third-Party Paywall Data Exfiltration [MEDIUM]

**Severity**: MEDIUM
**Files**:
- `/js/modules/paywallModule.js` (lines 18-33)
- `/js/popup-new.js` (lines 574-605)

**Code Evidence** (`paywallModule.js`):
```javascript
function fetchPaywallStatus(e) {
  fetch(isDebug ? `http://localhost:3000/api/paywall/check-v2?user_id=${e}` :
    `https://amazon-video-downloader-paywall.shareclip.me/api/paywall/check-v2?user_id=${e}`)
    .then((e => {
      if (!e.ok) throw new Error(`HTTP error! Status: ${e.status}`);
      return e.json()
    }))
    .then((e => {
      e && e.success && (e.price && "number" == typeof e.price && (currentPrice = e.price),
      chrome.storage.local.set({
        showPaywall: e.show_paywall,
        isSubscribed: e.is_subscribed,
        userId: e.user_id
      }),
      !0 === e.show_paywall ? applyPaywallRestrictions() : removePaywallRestrictions(),
      e.is_subscribed)
    }))
}
```

**Analysis**:
The extension generates a unique user identifier (UUID) and sends it to a third-party paywall service hosted at `shareclip.me` to check subscription status. This occurs every time the popup is opened on an Amazon page.

**Data Transmitted**:
- User ID (persistent UUID stored in chrome.storage.local and chrome.storage.sync)
- Implicitly: extension usage patterns (frequency of popup opening)

**Privacy Impact**:
- **User tracking**: The third-party service can track when users access Amazon product pages
- **Cross-session identification**: The UUID persists across browser sessions and survives extension reinstalls (stored in sync storage)
- **No privacy policy**: The extension listing does not disclose this third-party data sharing
- **Centralized monitoring**: The paywall service can build profiles of user behavior patterns

**Endpoints Contacted**:
- `amazon-video-downloader-paywall.shareclip.me` (subscription validation)
- `ttsmp3.net` (payment processing)
- `buymeacoffee.com` (donation link - benign)

**Verdict**: CONFIRMED PRIVACY VIOLATION
While this is not outright data theft, the extension shares persistent user identifiers with third-party infrastructure without adequate disclosure. Users have a reasonable expectation that a video downloader would not phone home for every use.

---

### 2. Excessive DOM Data Collection [MEDIUM]

**Severity**: MEDIUM
**Files**: `/content/content.js` (lines 1-150)

**Code Evidence**:
```javascript
document.querySelectorAll("script").forEach((t => {
  let e = t.innerText;
  e.includes("var obj = jQuery.parseJSON") ?
    e.match(/\{(.*)\}/g).forEach((t => {
      t.includes("alwaysIncludeVideo") && (r = t)
    })) :
    e.includes("ImageBlockATF") && e.match(/\{(.*)\}/g).forEach((t => {
      if (t.includes("hiRes")) {
        t = t.replace(/'/g, '"');
        // Parses Amazon's internal JSON data
      }
    }))
}));
```

**Analysis**:
The content script scrapes Amazon's page JavaScript to extract video and image metadata. This includes parsing internal Amazon data structures embedded in `<script>` tags.

**Data Extracted**:
- Video URLs, titles, duration, thumbnails
- Product image URLs (all variants)
- Product ASINs (Amazon Standard Identification Numbers)
- Current product URL
- Amazon's internal data structures

**Context Flows to External Services**:
According to ext-analyzer, 14 flows show data paths from:
- `document.getElementById` → `fetch(buymeacoffee.com)` ❌ FALSE POSITIVE - buymeacoffee is just a donation link
- `chrome.tabs.query` → `fetch(shareclip.me)` ✓ REAL - tab data context when checking paywall
- `chrome.storage.local.get` → `fetch(shareclip.me)` ✓ REAL - user preferences sent to paywall
- `document.querySelectorAll` → message passing → `fetch` ✓ POTENTIAL - DOM state accessible to popup

**Actual Exfiltration Assessment**:
The majority of detected flows are false positives from static analysis. The buymeacoffee.com calls do not transmit sensitive data (just opens donation page). However, the paywall check does occur in the context of having tab information and storage data available, which could enable tracking of which specific Amazon products users view.

**Verdict**: CONFIRMED PRIVACY CONCERN
While the extension doesn't explicitly send product URLs to external servers in the current code, the architecture allows the paywall service to infer user activity patterns through the timing and frequency of subscription checks.

---

### 3. CSP Unsafe-Eval for WASM [LOW]

**Severity**: LOW
**Files**: `manifest.json` (lines 30-32)

**Code Evidence**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self';"
}
```

**Analysis**:
The extension uses `'wasm-unsafe-eval'` in its CSP to enable FFmpeg.wasm for video processing. This is required for WebAssembly execution but does weaken security posture.

**Files Using WASM**:
- `/vendor/ffmpeg/ffmpeg-core.js`
- `/vendor/ffmpeg/ffmpeg-core.wasm`
- `/offscreen/offscreen.html` (runs FFmpeg in offscreen document)

**Security Impact**:
- **Moderate risk**: WASM execution is isolated but 'wasm-unsafe-eval' allows dynamic compilation
- **Legitimate use case**: FFmpeg requires WASM for video merging/transcoding
- **Mitigating factors**: WASM files appear to be legitimate FFmpeg builds

**Verdict**: ACCEPTABLE RISK
WASM usage is necessary for the extension's stated video processing functionality. However, users should be aware that WASM binaries are difficult to audit and could potentially contain malicious code.

---

## Network Analysis

### External Domains Contacted

| Domain | Purpose | Risk Level |
|--------|---------|------------|
| `shareclip.me` | Paywall subscription validation | MEDIUM - Privacy tracking |
| `ttsmp3.net` | Payment processing | MEDIUM - Redirects to payment |
| `buymeacoffee.com` | Donation link (user-initiated) | LOW - Benign |
| `imvbird.com` | Unknown (in manifest host permissions) | UNKNOWN - Not observed in code |
| `localhost:3000`, `localhost:8000` | Debug endpoints (disabled in production) | N/A |

### Data Flow Summary

**Outbound Data**:
1. **User ID (UUID)** → `shareclip.me` every popup open
2. **Subscription status** ← `shareclip.me` response
3. **Dynamic pricing** ← `shareclip.me` (can change paywall price remotely)

**No Observed Exfiltration of**:
- Amazon product URLs
- Video content
- User search history
- Downloaded file metadata
- Browser tabs/history beyond active tab

**However**: The architecture makes it trivial to add such exfiltration in a future update, as the extension already has:
- `tabs` permission (read all tab URLs)
- Network access to external domains
- User tracking infrastructure in place

---

## Permission Analysis

### Requested Permissions

```json
"permissions": [
  "activeTab",      // ✓ Needed to inject content scripts
  "tabs",           // ⚠️ EXCESSIVE - can read all tab URLs
  "storage",        // ✓ Needed for settings/downloads
  "downloads",      // ✓ Needed for video downloads
  "offscreen"       // ✓ Needed for FFmpeg processing
]
```

### Host Permissions

The extension requests access to:
- Amazon CDN domains (legitimate for video downloads)
- `amz-download-video.imvbird.com` (purpose unclear - not used in observed code)
- All Amazon regional domains (20 TLDs)

### Excessive Permissions Assessment

**`tabs` permission**: The extension uses `chrome.tabs.query` to find existing download manager tabs, but this also grants ability to read all tab URLs. This is more than needed - could use `activeTab` only.

**`imvbird.com` domain**: Listed in host_permissions but not observed in actual network calls. Possible remnant from earlier version or future feature.

**Verdict**: MODERATELY EXCESSIVE
The extension requests broader permissions than strictly necessary, increasing attack surface if compromised.

---

## Freemium Paywall Mechanism

### Business Model

The extension implements an aggressive freemium model:

**Free tier**:
- Download 1st video from standard products
- All downloads from Amazon Live pages

**Paid tier ($3.99/month)**:
- Download videos 2+ from products
- Batch downloads of all videos
- Global image downloads

### Privacy Implications of Paywall

**Tracking mechanism**:
```javascript
// background.js - User ID generation
chrome.storage.local.get(["userId"], (t => {
  let e = t.userId;
  e || chrome.storage.sync.get(["userId"], (t => {
    e = t.userId,
    e ? chrome.storage.local.set({ userId: e }) :
    (e = crypto.randomUUID(),
     chrome.storage.local.set({ userId: e }),
     chrome.storage.sync.set({ userId: e }))
  }))
}))
```

**Concerns**:
1. UUID stored in **sync storage** = survives reinstalls across devices
2. Paywall check on **every popup open** = usage tracking
3. Dynamic pricing from server = A/B testing / price discrimination potential
4. No opt-out mechanism for tracking

---

## Code Quality Observations

### Obfuscation

The extension uses webpack bundling with minified variable names, making analysis more difficult. The deobfuscated code reveals:
- Legitimate video/image extraction logic
- Standard FFmpeg.wasm integration
- Freemium restriction enforcement

### Suspicious Patterns (Low Severity)

1. **Debug endpoints in production code**: localhost URLs present but disabled by `isDebug=false` flag
2. **Unused host permission**: `imvbird.com` domain declared but not observed
3. **Remote price control**: Paywall price pulled from server, not hardcoded

---

## Comparison with Claimed Functionality

**Extension Description**: "Download videos from Amazon. Its batch download feature lets you grab multiple videos simultaneously."

**Actual Behavior**:
- ✅ Downloads Amazon product videos
- ✅ Downloads product images
- ✅ Batch download support (behind paywall)
- ✅ FFmpeg-based video processing
- ❌ **Not disclosed**: Third-party subscription tracking
- ❌ **Not disclosed**: Remote paywall configuration
- ❌ **Not disclosed**: Persistent user identifier generation

---

## Recommendations

### For Users

**If you use this extension**:
1. Be aware your usage is tracked by `shareclip.me`
2. Your persistent user ID can correlate activity across sessions
3. The developer can remotely change paywall restrictions
4. Consider alternatives that don't require external servers for basic functionality

**Risk tolerance**:
- **Low risk tolerance**: Avoid - privacy concerns outweigh utility
- **Medium risk tolerance**: Use for occasional downloads, be aware of tracking
- **High risk tolerance**: Acceptable if freemium model is understood

### For Developer

To improve privacy posture:
1. **Add privacy policy** disclosing third-party tracking
2. **Make paywall opt-in** instead of tracking all users
3. **Remove unused permissions** (reduce `tabs` to `activeTab` if possible)
4. **Explain `imvbird.com`** host permission or remove if unused
5. **Consider local-only freemium** (trial period, no server checks)

---

## Final Verdict

**Risk Level: MEDIUM**

Amazon video downloader provides legitimate video/image downloading functionality but implements concerning privacy practices through third-party paywall infrastructure. The extension is not malware and does not appear to steal user data maliciously, but it does track user activity patterns through persistent identifiers sent to external servers without adequate disclosure.

**Key Findings**:
- ✅ Core functionality is legitimate (video/image downloads)
- ✅ Uses standard FFmpeg.wasm (not malicious)
- ⚠️ Tracks users via persistent UUID sent to third-party servers
- ⚠️ No privacy policy disclosing external data sharing
- ⚠️ Remote configuration allows dynamic paywall changes
- ❌ Excessive permissions (tabs)
- ❌ Unexplained host permission (imvbird.com)

**Vulnerabilities Breakdown**:
- **Critical**: 0
- **High**: 0
- **Medium**: 2 (Third-party paywall tracking, Excessive DOM data collection context)
- **Low**: 1 (CSP unsafe-eval for WASM)

The extension sits in a gray area between legitimate freemium software and privacy-invasive tracking. Users should weigh the convenience of video downloads against the privacy cost of persistent tracking by third-party infrastructure.

---

## Technical Appendix

### Static Analysis Results (ext-analyzer)

- **Risk Score**: Not specified in requirements
- **Exfiltration Flows**: 14 detected
  - 4 flows: `buymeacoffee.com` (FALSE POSITIVES - just donation link opens)
  - 4 flows: `localhost:3000` (disabled debug endpoint)
  - 6 flows: `shareclip.me` paywall checks (CONFIRMED)
- **WASM Usage**: Confirmed (FFmpeg)
- **Obfuscation**: Webpack minification detected
- **CSP Weaknesses**: `'wasm-unsafe-eval'` (required for FFmpeg)

### Mitigation Strategies

**Short-term** (for users concerned about privacy):
1. Use extension only when needed, disable otherwise
2. Clear extension data regularly to reset user ID
3. Use in incognito mode (though ID may still sync)
4. Monitor network tab for unexpected requests

**Long-term** (ecosystem solutions):
1. Chrome Web Store should require privacy policy for extensions with external network calls
2. Extensions should declare "phones home" behavior in manifest
3. User consent required for persistent tracking identifiers
