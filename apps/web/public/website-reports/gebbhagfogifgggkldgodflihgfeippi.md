# Return YouTube Dislike - Security Analysis Report

## Extension Metadata
- **Extension Name**: Return YouTube Dislike
- **Extension ID**: gebbhagfogifgggkldgodflihgfeippi
- **User Count**: ~6,000,000
- **Version**: 4.0.2
- **Manifest Version**: 3

## Executive Summary

Return YouTube Dislike is a browser extension that restores the dislike count on YouTube videos. The extension operates by fetching dislike statistics from a third-party API (returnyoutubedislikeapi.com) and displaying them alongside YouTube's native interface. While the extension has extensive permissions and processes user data, the functionality aligns with its stated purpose. The code quality is good, with proper error handling and no evidence of malicious behavior.

**Overall Risk Assessment: CLEAN**

The extension requires invasive permissions and collects video viewing data, but these capabilities serve the extension's core functionality. There are no indicators of malware, data exfiltration beyond stated features, ad injection, or other malicious patterns.

## Vulnerability Analysis

### 1. Remote Configuration Loading - LOW (FALSE POSITIVE)
**Severity**: INFORMATIONAL
**File**: `ryd.content-script.js` (line 110227)
**Description**: The extension fetches UI selector configurations from the remote API endpoint `/configs/selectors`.

**Code**:
```javascript
let result = await fetch(getApiEndpoint("/configs/selectors"), {
  method: "GET",
  headers: {
    Accept: "application/json",
  },
})
```

**Verdict**: FALSE POSITIVE - This is a legitimate design pattern to handle YouTube's frequent UI changes without requiring extension updates. The selectors are used for DOM manipulation to inject the dislike counter, not for executing arbitrary code.

---

### 2. User Tracking via Video IDs - LOW
**Severity**: PRIVACY CONCERN (EXPECTED BEHAVIOR)
**File**: `ryd.background.js` (lines 222-236)
**Description**: The extension batches and sends video IDs to the API server.

**Code**:
```javascript
else if (request.message == "send_links") {
  toSend = toSend.concat(request.videoIds.filter((x) => !sentIds.has(x)));
  if (toSend.length >= 20) {
    fetch(getApiEndpoint("/votes"), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(toSend),
    });
    for (const toSendUrl of toSend) {
      sentIds.add(toSendUrl);
    }
    toSend = [];
  }
}
```

**Verdict**: EXPECTED - This behavior is necessary for the extension's core functionality. Video IDs are sent to aggregate dislike statistics. The extension batches requests efficiently and tracks sent IDs to avoid duplicates.

---

### 3. Persistent User ID Generation - LOW
**Severity**: PRIVACY CONCERN (EXPECTED BEHAVIOR)
**File**: `ryd.background.js` (lines 625-641)
**Description**: The extension generates and stores a persistent user ID.

**Code**:
```javascript
function generateUserID(length = 36) {
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  if (crypto && crypto.getRandomValues) {
    const values = new Uint32Array(length);
    crypto.getRandomValues(values);
    for (let i = 0; i < length; i++) {
      result += charset[values[i] % charset.length];
    }
    return result;
  } else {
    for (let i = 0; i < length; i++) {
      result += charset[Math.floor(Math.random() * charset.length)];
    }
    return result;
  }
}
```

**Verdict**: ACCEPTABLE - User IDs are required for vote submission and anti-spam measures. The ID is cryptographically random and not linked to any PII. This is standard practice for API authentication.

---

### 4. Proof-of-Work Puzzle System - INFORMATIONAL
**Severity**: INFORMATIONAL
**File**: `ryd.background.js` (lines 602-623)
**Description**: The extension implements a proof-of-work puzzle solver for vote submissions.

**Code**:
```javascript
async function solvePuzzle(puzzle) {
  let challenge = Uint8Array.from(atob(puzzle.challenge), (c) => c.charCodeAt(0));
  let buffer = new ArrayBuffer(20);
  let uInt8View = new Uint8Array(buffer);
  let uInt32View = new Uint32Array(buffer);
  let maxCount = Math.pow(2, puzzle.difficulty) * 3;
  for (let i = 4; i < 20; i++) {
    uInt8View[i] = challenge[i - 4];
  }

  for (let i = 0; i < maxCount; i++) {
    uInt32View[0] = i;
    let hash = await crypto.subtle.digest("SHA-512", buffer);
    let hashUint8 = new Uint8Array(hash);
    if (countLeadingZeroes(hashUint8) >= puzzle.difficulty) {
      return {
        solution: btoa(String.fromCharCode.apply(null, uInt8View.slice(0, 4))),
      };
    }
  }
  return {};
}
```

**Verdict**: LEGITIMATE - This is an anti-spam mechanism. The extension solves computational puzzles to prove legitimacy before submitting votes. Uses `atob/btoa` for base64 encoding, not code execution.

---

### 5. Patreon OAuth Integration - INFORMATIONAL
**Severity**: INFORMATIONAL
**File**: `popup.js`, `ryd.background.js`
**Description**: The extension includes optional Patreon authentication for premium features.

**Code**:
```javascript
chrome.runtime.sendMessage({ message: "patreon_oauth_login" }, (resp) => {
  if (chrome.runtime && chrome.runtime.lastError) {
    console.error("Login failed:", chrome.runtime.lastError.message);
    alert(chrome.i18n.getMessage("patreonLoginStartFailed"));
    return;
  }
  if (resp && resp.success) {
    const user = resp.user;
    showLoggedInView(user);
  }
});
```

**Verdict**: LEGITIMATE - Uses standard OAuth flow with chrome.identity API for optional premium features. Properly handles authentication tokens and session verification. No credential theft detected.

---

## False Positive Analysis

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| `innerHTML` usage | Multiple locations in content script | Used for injecting UI elements (dislike counter, tooltips). No user-controlled input. Content is sanitized or template-based. |
| `atob`/`btoa` | `ryd.background.js:603,618` | Used for base64 encoding in proof-of-work puzzle system, not for deobfuscation or code execution. |
| Remote config fetch | `ryd.content-script.js:110227` | Fetches CSS selectors for YouTube UI compatibility, not executable code. |
| Large bundled library | `ryd.content-script.js` (10.8MB) | Contains ECharts visualization library for Patreon premium analytics features. Legitimate data visualization, not malware. |

## API Endpoints

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `GET /votes?videoId={id}&likeCount={count}` | Fetch dislike counts | Video ID, like count |
| `POST /votes` | Batch send video IDs | Array of video IDs (max 20) |
| `POST /interact/vote` | Submit user vote | userId, videoId, vote value |
| `POST /interact/confirmVote` | Confirm vote with puzzle solution | userId, videoId, puzzle solution |
| `GET /puzzle/registration?userId={id}` | Register new user | userId |
| `POST /puzzle/registration?userId={id}` | Confirm registration | userId, puzzle solution |
| `POST /api/auth/oauth/exchange` | Patreon OAuth token exchange | OAuth code, state, redirectUri |
| `POST /api/auth/verify` | Verify Patreon session | sessionToken |
| `GET /configs/selectors` | Fetch UI selectors | None |

All endpoints target: `https://returnyoutubedislikeapi.com`

## Data Flow Summary

1. **User Visits YouTube Video**:
   - Content script extracts video ID from URL
   - Fetches dislike count from API with video ID and like count
   - Injects dislike counter into YouTube UI

2. **User Votes**:
   - Vote sent to background script
   - Background script submits vote with userId
   - Server responds with proof-of-work challenge
   - Extension solves puzzle and confirms vote

3. **Batch Video Tracking**:
   - Content script sends lists of viewed video IDs
   - Background script batches 20 IDs before sending
   - Sent to API for aggregate statistics

4. **Optional Patreon Integration**:
   - User initiates OAuth flow in popup
   - Background script handles OAuth via chrome.identity API
   - Session token stored in chrome.storage.sync
   - Token verified on popup open

## Permissions Analysis

### Declared Permissions
- `storage` - Used for: user preferences, userId, registration status, Patreon auth
- `optional_permissions: ["identity"]` - Used for: Patreon OAuth (opt-in only)

### Host Permissions
- `*://*.youtube.com/*` - Required for: injecting dislike counter into YouTube pages

**Assessment**: Permissions are minimal and appropriate for functionality. No excessive or suspicious permissions.

## Manifest Security

- **Manifest Version**: 3 (modern, more secure)
- **Content Security Policy**: Not explicitly defined (uses MV3 defaults)
- **Externally Connectable**: Limited to `*://*.youtube.com/*` (appropriate)
- **Web Accessible Resources**: `ryd.script.js`, `menu-fixer.js` (for YouTube page injection)

**Assessment**: Manifest configuration follows security best practices.

## Code Quality Observations

**Positive Indicators**:
- Clean, readable code with proper error handling
- No obfuscation or suspicious patterns
- Uses standard APIs (fetch, crypto.subtle, chrome.storage)
- Open-source project on GitHub (https://github.com/Anarios/return-youtube-dislike)
- Proper separation of concerns (background, content, popup scripts)
- Defensive programming with null checks and try-catch blocks

**No Malicious Patterns Detected**:
- ❌ No eval() or Function() constructor
- ❌ No XHR/fetch prototype hooking
- ❌ No keylogger or input monitoring
- ❌ No cookie theft
- ❌ No extension enumeration/fingerprinting
- ❌ No ad injection or content manipulation beyond stated purpose
- ❌ No residential proxy or P2P networking
- ❌ No market intelligence SDKs (Sensor Tower, Pathmatics, etc.)
- ❌ No AI conversation scraping
- ❌ No dynamic code execution

## Overall Risk Assessment: CLEAN

**Justification**:
Return YouTube Dislike is a legitimate extension that performs exactly as advertised. While it requires host permissions for YouTube and sends video viewing data to a third-party API, this behavior is necessary for its core functionality and transparently disclosed. The extension:

1. **Serves its intended purpose**: Restores YouTube dislike counts
2. **No hidden malicious behavior**: All network calls are to the stated API
3. **Appropriate permissions**: Only requests what's needed for functionality
4. **Good code quality**: Well-structured, maintainable code with no obfuscation
5. **Open source**: Code is publicly auditable on GitHub
6. **Privacy considerations**: While it tracks video views, this is essential for the service and not excessive

The extension collects viewing data (video IDs visited), which some users may consider a privacy trade-off, but this is clearly part of the service's functionality and is not used maliciously.

## Recommendations

**For Users**:
- This extension is safe to use if you want YouTube dislike counts restored
- Be aware that video IDs you view are sent to the API (necessary for functionality)
- Patreon integration is optional and uses secure OAuth

**For Developers**:
- Consider adding a privacy policy link in the extension
- Document data collection practices in user-facing documentation
- Consider implementing local-only mode for privacy-conscious users (though this would limit accuracy)

---

**Analysis Date**: 2026-02-08
**Analyst**: Claude Sonnet 4.5 (Automated Security Analysis)
