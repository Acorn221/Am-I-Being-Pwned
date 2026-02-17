# Security Analysis: Voice Control for ChatGPT

**Extension ID:** eollffkcakegifhacjnlnegohfdlidhn
**Version:** 4.3.1
**Users:** 400,000
**Risk Level:** LOW
**Manifest Version:** 3

## Executive Summary

Voice Control for ChatGPT is a legitimate browser extension that adds voice control functionality to ChatGPT and Claude AI. The extension implements standard Google Analytics tracking to monitor usage patterns but lacks transparent disclosure of this data collection in its Chrome Web Store privacy documentation. While the analytics implementation is benign (tracking events and sessions only), the absence of clear privacy policy disclosure represents a minor compliance issue.

## Permissions Analysis

### Declared Permissions
- `storage`: Used for storing extension settings, client ID, and session data

### Optional Permissions
- `tabs`: Requested for new tab replacement feature
- `scripting`: Requested for Claude AI integration
- `https://*/*`: Optional host permissions for Claude AI functionality

### Host Permissions
The extension operates on:
- `https://chat.openai.com/*`
- `https://chatgpt.com/*`
- `https://claude.ai/*` (when user grants optional permission)

All permissions align with the extension's stated voice control functionality.

## Data Flow Analysis

### Google Analytics Integration

The extension implements Google Analytics 4 Measurement Protocol tracking in `/src/pages/background/index.js`:

**Configuration:**
- Endpoint: `https://www.google-analytics.com/mp/collect`
- Measurement ID: `G-67EVHBE3DC`
- API Secret: `bXxiMdAmTDOHvtvFKxxjRg` (hardcoded)

**Data Collected:**
1. **Client ID**: UUID generated on install, stored in `chrome.storage.local`
2. **Session ID**: Timestamp-based session identifier (30-minute expiry)
3. **Event Names**: User interaction events (e.g., feature usage, errors)
4. **Engagement Time**: Fixed 100ms engagement metric

**Data Flow:**
```
Content Script → localStorage check (vc-settings)
    ↓
chrome.runtime.sendMessage({gaEvent: eventData})
    ↓
Background Script → Enriches with client_id, session_id
    ↓
Batch Queue (2-second delay, max 100 events)
    ↓
fetch() → Google Analytics MP endpoint
```

**Source Code Evidence:**
```javascript
// Background script (src/pages/background/index.js)
const w="https://www.google-analytics.com/mp/collect"
const b="G-67EVHBE3DC"  // Measurement ID
const I="bXxiMdAmTDOHvtvFKxxjRg"  // API Secret

async function l(){
  let t=(await chrome.storage.local.get("clientId")).clientId;
  return t||(t=self.crypto.randomUUID(),
    await chrome.storage.local.set({clientId:t})),t
}

await fetch(`${w}?measurement_id=${b}&api_secret=${I}`,{
  method:"POST",
  body:JSON.stringify({client_id:t,events:[e]})
})
```

### Privacy Opt-Out Mechanism

The extension includes a user-controlled opt-out via localStorage:

```javascript
// ga-track-event.c7cbcd22.js
const e=window.localStorage.getItem("vc-settings");
if(e){
  const{showExtension:n}=JSON.parse(e);
  if(!n)return  // Blocks analytics if showExtension=false
}
chrome.runtime.sendMessage({gaEvent:t})
```

Users can disable tracking through extension settings by toggling the "showExtension" flag.

## Network Endpoints

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://www.google-analytics.com/mp/collect` | Usage analytics | Client ID, session ID, event names, engagement time |
| `https://voicecontrol.chat/feedback/offboarding` | Uninstall survey | Extension ID (via URL parameter) |
| `https://chatgpt.com` | Core functionality | None (content script injection) |
| `https://claude.ai` | Optional integration | None (content script injection) |

## Security Findings

### LOW: Undisclosed Analytics Collection

**Severity:** Low
**CWE:** CWE-359 (Exposure of Private Information)

**Description:**
The extension collects usage analytics (client ID, session ID, event names) via Google Analytics 4 without explicit disclosure in the Chrome Web Store privacy policy section. While the data collected is non-sensitive and limited to usage patterns, Google's Developer Program Policies require clear disclosure of data collection practices.

**Evidence:**
1. Background script implements GA4 tracking (confirmed in deobfuscated code)
2. Chrome Web Store listing lacks privacy policy link or analytics disclosure
3. Developer website (voicecontrol.chat) has privacy link but not readily accessible from CWS

**Impact:**
Users are not informed that their usage patterns are being tracked, even though the tracking is anonymous and benign. This violates user transparency expectations and may conflict with Chrome Web Store disclosure requirements.

**User Data Collected:**
- Anonymous client UUID (locally generated)
- Session timestamps
- Feature usage event names (no PII)
- Engagement duration (synthetic 100ms value)

**No Sensitive Data:**
- Does NOT collect browsing history
- Does NOT collect ChatGPT/Claude conversations
- Does NOT collect authentication tokens
- Does NOT access clipboard or screen content

**Recommendation:**
Add privacy policy link to Chrome Web Store listing explicitly stating:
- Usage analytics are collected via Google Analytics
- Client ID generation and purpose
- User opt-out mechanism (showExtension setting)
- Data retention policy

## Code Quality Observations

### Positive Security Practices
1. **Minimal Permissions**: Only requests `storage` by default; other permissions are optional and user-controlled
2. **User Opt-Out**: Respects localStorage `showExtension` flag to disable analytics
3. **Session Management**: 30-minute session timeout prevents indefinite tracking
4. **No Sensitive Data**: Does not access or transmit conversation content
5. **Manifest V3**: Uses modern service worker architecture

### Areas of Concern
1. **Hardcoded API Secret**: Google Analytics API secret is embedded in code (standard practice for GA4 MP but exposes measurement stream to spoofing)
2. **Obfuscation**: Minified code makes auditing difficult (though legitimate for build optimization)
3. **Web Accessible Resources**: Exposes `manifest.json` and assets to all sites via `matches: ["*://*/*"]` (fingerprintability concern but not a vulnerability)

## Functionality Verification

The extension's core features align with its description:
- Voice input for ChatGPT/Claude via Web Speech API
- Text-to-speech for responses
- Optional new tab page replacement
- Optional Claude AI integration
- Settings stored in chrome.storage.local

No hidden functionality or malicious behavior detected.

## Risk Assessment

**Overall Risk: LOW**

The extension is functionally legitimate and does not exhibit malicious behavior. The analytics tracking is standard industry practice, though the lack of transparent disclosure is a minor compliance issue. The data collected is non-sensitive and limited to usage metrics.

### Risk Factors:
- **No credential theft**
- **No hidden data exfiltration**
- **No command-and-control infrastructure**
- **No code execution vulnerabilities**
- **Privacy disclosure gap** (analytics not mentioned in CWS listing)

### Comparison to Risk Framework:
- CRITICAL: Not applicable (no credential theft/hidden exfil/C2)
- HIGH: Not applicable (no undisclosed user data exfiltration)
- **MEDIUM**: Not applicable (analytics is disclosed via opt-out mechanism, just not in CWS policy)
- **LOW**: Applicable (minor privacy disclosure gap for analytics tracking)
- CLEAN: Not applicable due to analytics disclosure issue

## Recommendations

### For Users
1. **Safe to Use**: Extension is legitimate and safe for its intended purpose
2. **Disable Analytics**: Set `showExtension: false` in extension settings to opt out of analytics
3. **Review Permissions**: Only grant optional permissions (tabs, scripting, claude.ai) if you use those features

### For Developer
1. **Add Privacy Policy Link**: Include prominent privacy policy link in Chrome Web Store listing
2. **Disclose Analytics**: Explicitly state Google Analytics usage in privacy documentation
3. **Document Opt-Out**: Make the `showExtension` analytics toggle more discoverable in UI
4. **Secure API Secret**: Consider server-side proxy for GA4 to avoid exposing API secret in client code
5. **Reduce WAR Scope**: Limit web_accessible_resources to specific origins instead of `*://*/*`

## Static Analyzer Findings

**ext-analyzer Results:**
- **Risk Score:** 20 (low)
- **Exfiltration Flows:** 1 (chrome.storage → fetch to google-analytics.com)
- **Code Execution Flows:** 0
- **Attack Surface:** Open message handlers for analytics events (expected behavior)
- **Obfuscation Flag:** True (minified production build)
- **WASM:** False

The analyzer correctly identified the Google Analytics data flow as the sole exfiltration pattern. The risk score appropriately reflects the benign nature of this tracking.

## Conclusion

Voice Control for ChatGPT is a **legitimate extension** with a **minor privacy disclosure gap**. The analytics implementation is standard and non-invasive, collecting only anonymous usage metrics. With the addition of a clear privacy policy on the Chrome Web Store listing, this extension would be fully compliant. Users concerned about analytics can safely disable tracking via the extension's settings.

**Verdict:** LOW risk - Safe to use with awareness of analytics tracking.
