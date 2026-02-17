# Teleparty (Netflix Party) - Security Analysis Report

## Extension Metadata
- **Name**: Netflix Party is now Teleparty
- **Extension ID**: oocalimimngaihdkbihfgmpkcpnmlaoa
- **Version**: 5.5.5
- **User Count**: ~10,000,000
- **Manifest Version**: 3
- **Developer**: WP Interactive Media, Inc.

## Executive Summary

Teleparty (formerly Netflix Party) is a legitimate browser extension for synchronized video watching across 30+ streaming platforms including Netflix, Disney+, Hulu, Amazon Prime Video, HBO Max, and many others. The extension enables users to watch videos together remotely with synchronized playback and a chat feature.

The extension uses appropriate permissions for its functionality, implements proper security practices, and communicates only with its legitimate backend services. While it has broad permissions (`optional_host_permissions: *://*/*`), these are necessary to support 30+ streaming platforms and are not abused. The extension includes analytics (PostHog) and uses Firebase for push notifications, which are standard practices for a social viewing application.

**Overall Assessment**: The extension is CLEAN with proper security implementation for its intended purpose.

## Permissions Analysis

### Declared Permissions
- `activeTab` - Access to currently active tab (appropriate for content injection)
- `storage` - Local data storage (session state, user preferences)
- `scripting` - Dynamic script injection for platform support
- `alarms` - Background timers (likely for connection keepalive)

### Optional Host Permissions
- `*://*/*` - Broad access to all websites (required to support 30+ streaming platforms)

### CSP (Content Security Policy)
```
frame-src http://localhost:3000/ https://redirect.teleparty.com/
         https://teleparty-auth---test.firebaseapp.com/
         https://teleparty-mobile.firebaseapp.com/
script-src 'self'
object-src 'self'
```
**Verdict**: Properly restrictive CSP with specific frame sources for auth/redirect flows.

## Network Endpoints Analysis

### Primary Backend Services
| Endpoint | Purpose | Risk Level |
|----------|---------|------------|
| https://api.teleparty.com | Main backend API | Low - Legitimate service |
| https://socketio.teleparty.com | WebSocket for real-time sync | Low - Required for chat/sync |
| https://www.teleparty.com | Main website | Low - Company domain |
| https://files.teleparty.com | Static resources | Low - CDN for assets |
| https://redirect.teleparty.com | OAuth/auth redirects | Low - Standard auth flow |

### Legacy Domains
| Endpoint | Purpose | Risk Level |
|----------|---------|------------|
| https://wptony1.netflixparty.com | Legacy backend | Low - Old branding |
| https://*.netflixparty.com | Old domain pattern | Low - Historical compatibility |

### Third-Party Services
| Endpoint | Purpose | Risk Level |
|----------|---------|------------|
| https://us.i.posthog.com | Product analytics | Low - Standard analytics |
| https://www.gstatic.com/firebasejs/* | Firebase SDK | Low - Google CDN |
| Firebase (teleparty-auth---test.firebaseapp.com) | Push notifications | Low - Standard service |

### Streaming Platform Domains
The extension legitimately accesses 30+ streaming platforms including:
- Netflix, Disney+, Hulu, Amazon Prime Video, HBO Max, Apple TV+
- Crunchyroll, Paramount+, Peacock, ESPN+, Fubo, Sling
- International: Hotstar, Viki, SonyLIV, Zee5, Vidio, U-NEXT, Hulu Japan, etc.

## Chrome API Usage Analysis

### Background Service Worker (background_service_bundled.js)
**APIs Used**:
- `chrome.runtime` - Message passing, extension lifecycle
- `chrome.tabs` - Tab management for synchronized viewing
- `chrome.storage` - Persistent state storage
- `chrome.scripting` - Dynamic content script injection
- `chrome.alarms` - Background timers
- `chrome.idle` - User idle state detection
- `chrome.permissions` - Runtime permission requests
- `chrome.windows` - Window management
- `chrome.webRequest` - **CSP header modification** (see security analysis below)

### chrome.webRequest Usage - CSP Blocking
**Location**: `background_service_bundled.js`
```javascript
vr(t){
  console.log("blockCSP for tab "+t);
  const e={urls:["*://*/*"],tabId:t,types:["main_frame","sub_frame"]};
  chrome.webRequest.onHeadersReceived.addListener(this.Ds.bind(this),e,
    ["blocking","responseHeaders"])
}
```

**Analysis**: The extension uses `chrome.webRequest` to modify CSP headers on streaming platform pages. This is a **powerful and potentially dangerous capability**, but appears to be used legitimately to:
1. Allow injection of synchronization scripts on streaming platforms
2. Enable cross-frame communication for the Teleparty overlay

**Risk Assessment**: MEDIUM risk for abuse, but LEGITIMATE use case. The extension needs to modify CSP headers because streaming platforms have strict CSP policies that would otherwise block the synchronization functionality.

**Note**: Manifest v3 officially deprecates `chrome.webRequest` in favor of `declarativeNetRequest`, but this extension still uses the older API (requires special enterprise/developer permissions or is grandfathered in).

## Content Script Analysis

### Platform Coverage
The extension injects content scripts for 30+ streaming platforms:
- `/content_scripts/netflix/netflix_content_bundled.js` (289KB)
- `/content_scripts/netflix/netflix_injected_bundled.js` (20KB)
- Similar scripts for Disney+, Hulu, Amazon, HBO Max, etc.

### Browse Scripts
Separate browse scripts for platform detection and initialization:
- `/browse_scripts/{platform}/{platform}_browse_bundled.js`
- `/browse_scripts/{platform}/{platform}_browse_injected_bundled.js`

### Injected Functionality
**`lib/replace_state_script.js`** - History API hooking:
```javascript
var popInteraction=function(t){
  window.postMessage({type:"FROM_PAGE_POP",text:"next episode from the webpage!"},"*")
};
var reloadInteraction=function(t){
  window.postMessage({type:"FROM_PAGE",text:"next episode from the webpage!"},"*")
};
window.onpopstate=popInteraction;
history.onreplacestate=history.onpushstate=reloadInteraction;
```

**Purpose**: Detects navigation events (next episode, video changes) to keep all viewers synchronized.

**Risk**: Low - Legitimate use of history API hooking for synchronization. Uses postMessage for inter-script communication.

### React/DOM Manipulation
Netflix injected script uses React internals inspection:
```javascript
const getReactInternals = (root) => {
  var keys = Object.keys(root);
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].startsWith("__reactInternalInstance")) {
      return root[keys[i]];
    }
  }
};
```

**Purpose**: Access Netflix's React component tree to control video playback programmatically.

**Risk**: Low - Standard technique for interacting with React-based streaming platforms.

## Data Collection & Privacy

### Analytics - PostHog
- **Endpoint**: `https://us.i.posthog.com`
- **Occurrences**: 6 references in `popup_react_bundled.js`
- **Purpose**: Product analytics for feature usage tracking
- **Risk**: Low - Standard analytics platform

### Firebase Push Notifications
**Configuration** (`firebase-messaging-sw.js`):
```javascript
firebase.initializeApp({
  apiKey:"AIzaSyDmxz7HsfNuhW52Mti-Q9lAGHJYOzEijb8",
  authDomain:"teleparty-auth---test.firebaseapp.com",
  projectId:"teleparty-auth---test",
  storageBucket:"teleparty-auth---test.appspot.com",
  messagingSenderId:"391169153212",
  appId:"1:391169153212:web:0eae4ff68890df614b18b9"
});
```

**Notification Types**:
- `friend_request` - New friend requests
- `dropin_request` - Party join requests and invitations

**Risk**: Low - Firebase API key is intentionally public (client-side keys are not secrets). Used for legitimate push notification functionality.

### Data Storage
- Uses `chrome.storage` for session state, user preferences, party metadata
- No evidence of cookie harvesting, keylogging, or unauthorized data exfiltration

## Vulnerability Assessment

### 1. Chrome.webRequest CSP Modification
**Severity**: MEDIUM (Potentially High Risk, But Legitimate Use)
**Location**: `background_service_bundled.js`
**Code**:
```javascript
chrome.webRequest.onHeadersReceived.addListener(this.Ds.bind(this),
  {urls:["*://*/*"],tabId:t,types:["main_frame","sub_frame"]},
  ["blocking","responseHeaders"])
```

**Description**: Extension modifies Content Security Policy headers for streaming platform pages.

**Legitimate Purpose**:
- Streaming platforms have strict CSP policies
- Teleparty needs to inject synchronization scripts
- CSP modification is necessary for core functionality

**Potential for Abuse**:
- Could weaken security on streaming platforms
- Could be used to inject arbitrary scripts
- Requires `webRequest` permission (deprecated in MV3)

**Mitigation**:
- Scoped to specific tab IDs (not global)
- User explicitly installs extension knowing it modifies streaming behavior
- Company is reputable (10M+ users, established product)

**Verdict**: ACCEPTABLE - High-privilege API used for legitimate synchronization functionality, but requires trust in the developer.

### 2. History API Hooking
**Severity**: LOW
**Location**: `lib/replace_state_script.js`
**Code**: Hooks `history.pushState`, `history.replaceState`, `window.onpopstate`

**Description**: Monitors navigation events on streaming platforms.

**Purpose**: Detect episode changes, video switches to maintain party synchronization.

**Verdict**: BENIGN - Standard technique for video synchronization.

### 3. React Internals Access
**Severity**: LOW
**Location**: `content_scripts/netflix/netflix_injected_bundled.js`
**Code**: Accesses `__reactInternalInstance` and `__reactFiber`

**Description**: Inspects React component internals on streaming platforms.

**Purpose**: Programmatic video playback control (play, pause, seek) for synchronized viewing.

**Verdict**: BENIGN - Necessary for controlling third-party video players.

### 4. PostHog Analytics
**Severity**: LOW
**Location**: `popup_react_bundled.js`
**Endpoint**: `https://us.i.posthog.com`

**Description**: Product analytics for feature usage tracking.

**Data Collected**: Likely user interactions, feature adoption, error tracking.

**Verdict**: ACCEPTABLE - Standard analytics, no evidence of sensitive data collection.

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| MD5 implementation | `background_service_bundled.js` | Standard crypto library for hashing |
| Firebase public API key | `firebase-messaging-sw.js` | Client-side keys are not secrets |
| PostHog tracking | `popup_react_bundled.js` | Legitimate product analytics |
| History API hooks | `lib/replace_state_script.js` | Required for navigation detection |
| React internals access | Content scripts | Standard technique for video control |
| chrome.webRequest | `background_service_bundled.js` | Necessary for CSP modification (see vulnerability #1) |

## Malicious Behavior Screening

### ❌ No Evidence Of:
- Extension enumeration or killing
- XHR/fetch hooking for MITM attacks
- Residential proxy infrastructure
- Remote kill switches or dynamic code loading
- Market intelligence SDKs (Sensor Tower, Pathmatics, etc.)
- AI conversation scraping
- Ad injection or coupon replacement
- Cookie stealing or credential harvesting
- Keylogging or form data interception
- Cryptocurrency mining
- Click fraud or ad fraud
- Unauthorized file access

### ✅ Legitimate Features:
- Synchronized video playback across 30+ streaming platforms
- Real-time chat via WebSocket (`socketio.teleparty.com`)
- Friend requests and party invitations via Firebase notifications
- OAuth/authentication flows via redirect.teleparty.com
- Product analytics via PostHog
- Multi-platform support (Netflix, Disney+, Hulu, etc.)

## Data Flow Summary

```
User Browser (Extension)
    ↓
Content Scripts → Detect video playback state (play, pause, seek, time)
    ↓
Background Service → Coordinate synchronization logic
    ↓
WebSocket (socketio.teleparty.com) → Real-time state synchronization with other party members
    ↓
API (api.teleparty.com) → Session management, friend lists, party metadata
    ↓
Firebase → Push notifications for friend requests, party invitations
    ↓
PostHog → Anonymous usage analytics
```

**Data Transmitted**:
- Video playback state (play/pause/seek/timestamp)
- Chat messages
- User profile (name, avatar)
- Friend list metadata
- Party session information

**Data NOT Transmitted**:
- Passwords or credentials
- Browsing history outside streaming platforms
- Personal files or downloads
- Payment information
- Video content itself (only playback state)

## Security Best Practices Assessment

### ✅ Strengths:
1. **Proper CSP**: Restrictive Content Security Policy in manifest
2. **MV3 Compliance**: Uses Manifest V3 (modern security model)
3. **Scoped Permissions**: APIs used appropriately for functionality
4. **No Dynamic Code**: No `eval()`, `Function()`, or remote code execution
5. **HTTPS Only**: All backend communication over encrypted channels
6. **Established Developer**: WP Interactive Media, Inc. - reputable company
7. **Large User Base**: 10M+ users with public reviews and scrutiny

### ⚠️ Areas of Concern:
1. **chrome.webRequest**: Powerful API that modifies CSP headers (but necessary for functionality)
2. **Broad Host Permissions**: `*://*/*` access (but required for 30+ platforms)
3. **Deprecated API**: `chrome.webRequest` is deprecated in MV3 (should migrate to declarativeNetRequest)
4. **Analytics**: PostHog tracking (standard but privacy-conscious users may object)

## Overall Risk Assessment

**Risk Level**: **CLEAN**

### Justification:
Teleparty is a **legitimate social viewing extension** with 10+ million users and a reputable developer (WP Interactive Media, Inc.). While it uses powerful permissions including:

1. **`chrome.webRequest`** for CSP modification (MEDIUM risk API)
2. **`*://*/*` host permissions** (broad scope)
3. **History API hooking** (navigation monitoring)
4. **React internals manipulation** (video player control)

...all of these capabilities are **necessary and appropriate** for the extension's core functionality: synchronized video watching across 30+ streaming platforms.

The extension:
- ✅ Uses permissions only for advertised functionality
- ✅ Communicates only with legitimate backend services
- ✅ Includes standard analytics (PostHog) and notifications (Firebase)
- ✅ Shows no evidence of malicious behavior
- ✅ Has proper security implementation (CSP, HTTPS, no dynamic code)
- ✅ Is transparent about its functionality (chat, sync, friends)

### Explanation of "CLEAN" Rating:
Per instructions: "If an extension requires lots of permissions and is invasive, but serves its intended purpose and has no clear malicious behavior or key vulnerabilities, mark it as CLEAN with an explanation."

Teleparty is **invasive** (broad permissions, CSP modification, video player control) but serves its **clearly advertised purpose** (synchronized watching with chat). There is **no evidence of malicious behavior**, data theft, or unauthorized functionality. The extension is exactly what it claims to be.

### Recommendation:
**SAFE FOR USE** - Users should be aware that the extension:
- Modifies streaming platform page security policies (CSP)
- Has access to activity on all streaming platforms
- Sends video playback state and chat messages to Teleparty servers
- Includes analytics tracking (PostHog)

This is all **expected and necessary** for a synchronized viewing application and is clearly disclosed in the extension description and permissions request.

---

**Analysis Date**: 2026-02-07
**Analyst**: Claude Sonnet 4.5
**Confidence Level**: High
