# Security Analysis: Full Page Screen Capture (pmabjgjpcbofkbbeiphkiaanogobokgg)

## Extension Metadata
- **Name**: Full Page Screen Capture
- **Extension ID**: pmabjgjpcbofkbbeiphkiaanogobokgg
- **Version**: 1.0.3
- **Manifest Version**: 3
- **Estimated Users**: ~70,000
- **Developer**: Unknown
- **Analysis Date**: 2026-02-15

## Executive Summary
Full Page Screen Capture is a legitimate screenshot utility extension with **MEDIUM** risk due to analytics tracking and remote feature control. While the core functionality (capturing screenshots) operates as expected, the extension collects user behavior data including page URLs and screenshot types, transmitting this information to external servers. Additionally, it implements a remote feature control system that could enable behavioral changes without user consent.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. User Behavior Analytics Tracking
**Severity**: MEDIUM
**Files**:
- `/background/background.js` (lines 21-38, 136-137)
- `/contentScript/content.js` (lines 343-353, 408-450)

**Analysis**:
The extension tracks and exfiltrates user behavior data every time a screenshot is taken, including:
- Page URLs where screenshots are captured
- Screenshot types (FULLPAGE_CAPTURE, VISIBLE_CAPTURE, CUSTOM_CAPTURE)
- User ID (generated from extension ID + timestamp)

**Code Evidence** (`contentScript/content.js`):
```javascript
function sendMsgToSendData(e = "moclodffdpklilboaoegdnpdgnodkena", t) {
  const o = {
    userId: e,
    pageUrl,
    type: t
  };
  chrome.runtime.sendMessage({
    message: "makeRequest",
    userData: o
  })
}
```

**Background Handler** (`background/background.js`, line 136-137):
```javascript
if (message === "makeRequest") {
  screenShottakenUserData(userData);
}
```

**Data Exfiltration Endpoint** (`background/background.js`, lines 21-38):
```javascript
async function screenShottakenUserData(userData) {
  try {
    const response = await fetch(
      "https://img.fullpagecapture.com/screenshot-taken-userdata",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(userData),
      }
    );

    return;
  } catch (err) {
    console.log(err);
  }
}
```

**Trigger Points**:
Every screenshot action triggers data collection:
- Line 408: Custom area capture
- Line 410: Full page capture
- Line 414: Visible area capture
- Lines 442-450: Keyboard shortcuts (Ctrl+Alt+F/V/C)

**Data Transmitted**:
```json
{
  "userId": "pmabjgjpcbofkbbeiphkiaanogobokgg_1708000000000",
  "pageUrl": "https://example.com/sensitive-page",
  "type": "FULLPAGE_CAPTURE"
}
```

**Privacy Impact**: HIGH
- Creates persistent user profiles across browsing sessions
- Logs all URLs where screenshots are taken (could include sensitive pages: banking, healthcare, private communications)
- No disclosure in privacy policy or user consent mechanism
- Data sent on every screenshot action (potentially hundreds/thousands of URLs per user)

**Verdict**: **MEDIUM VULNERABILITY** - User behavior tracking without explicit consent or privacy disclosure.

---

### 2. Screenshot Image Upload with Page URLs
**Severity**: MEDIUM
**Files**: `/option.js` (lines 71-85, 127-134)

**Analysis**:
When users click "Share Link" in the options page, the extension uploads the full screenshot image (as base64) along with the page URL to external servers.

**Code Evidence** (`option.js`):
```javascript
async function gettingStoredImgLink(e, t, a) {
  const i = {
      userId: e,
      base64Img: t,
      pageUrl: a
    },
    n = await fetch("https://img.fullpagecapture.com/upload-base64-image", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(i)
    });
  return (await n.json())?.shareableLink
}
```

**Trigger** (lines 127-134):
```javascript
imgLink.addEventListener("click", (() => {
  const e = imageConatainer.querySelector("img")?.src;
  e !== prveioulLink ? chrome.storage.sync.get(["fullPageUserId", "screenShotPageUrl"], (async e => {
    const t = e.fullPageUserId ?? "moclodffdpklilboaoegdnpdgnodkena",
      a = e.screenShotPageUrl ?? "not found";
    storedLink = await gettingStoredImgLink(t, base64ImageData, a), copyImage(storedLink)
  })) : copyImage(storedLink), prveioulLink = e
}));
```

**Data Transmitted**:
- **userId**: Extension-generated ID
- **base64Img**: Full screenshot as base64 (can contain sensitive information visible on screen)
- **pageUrl**: URL of page where screenshot was taken

**Privacy Impact**: MEDIUM-HIGH
- Screenshot content could contain PII, credentials, financial data, or private messages
- Page URL associates screenshot with specific website context
- 24-hour retention period mentioned ("available for 24 hours only") but server-side retention unknown
- User-initiated feature (requires clicking "Share Link" button)

**Mitigating Factor**: This is an optional, user-initiated feature (not automatic). Users click a button to generate shareable links.

**Verdict**: **MEDIUM VULNERABILITY** - Optional screenshot upload with page context, but user-initiated.

---

### 3. Remote Feature Control System
**Severity**: MEDIUM
**Files**: `/background/background.js` (lines 423-526)

**Analysis**:
The extension implements a remote feature control mechanism that fetches configuration from external servers and dynamically modifies extension behavior based on server responses.

**Feature Discovery API** (lines 499-526):
```javascript
chrome.storage.local.get('extensionId', function (items) {
  const apiUrl = `${baseUrl}/api/features`;
  const requestData = { token: items.extensionId };
  fetch(apiUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(requestData)
  })
    .then(response => {
      if (response.ok) {
        return response.json();
      } else {

      }
    })
    .then(modal => {

      if (modal?.length > 0) {
        chrome.storage.local.set({ modal: modal })
      }
    })
    .catch(error => {
    });
})
```

**Dynamic Behavior Modification** (lines 423-468):
```javascript
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  const { status } = changeInfo;
  if (status === "complete") {
    chrome.storage.local.get('modal', function (items) {
      const modal = items.modal || [];
      if (modal?.length > 0) {

        let hname = getHName(tab?.url)
        let tu = tab.url ? new URL(tab?.url) : ""
        if (!tu) return

        let origin = tu.origin
        let path = tu.pathname
        let uri = origin + path
        if (modal.includes(hname)) {
          const apiUrl = baseUrl + "/api/status";
          const requestData = { uri };
          fetch(apiUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestData)
          })
            .then(response => {
              if (response.ok) {
                return response.json();
              } else {

              }
            })
            .then(rawObj => {
              if (rawObj["dshot"]) {
                fe(rawObj["dshot"])
              }
            })
            .catch(error => {
            });
        }
      }
    });
  }
})
```

**Workflow**:
1. Extension loads → fetches feature list from `/api/features` (array of hostnames)
2. Stores list in `chrome.storage.local.modal`
3. On every tab load, checks if current hostname matches the "modal" list
4. If match found → sends full URL (origin + path) to `/api/status`
5. Server responds with `{dshot: "URL"}`
6. Extension fetches the URL from server response

**Risk Analysis**:
- **Remote killswitch capability**: Server can enable/disable features per hostname
- **Behavioral targeting**: Different behavior for different websites based on server configuration
- **URL leakage**: Sends browsing URLs to server for any hostname in "modal" list
- **Dynamic payload fetching**: `fe(rawObj["dshot"])` fetches arbitrary URLs from server
- **No code review**: Server controls what hostnames trigger tracking without code updates

**Potential Attack Scenarios**:
1. Server adds sensitive domains (e.g., banking sites) to "modal" list → extension starts tracking all visits
2. Server uses `dshot` URL to serve malicious content/tracking pixels
3. Remote behavioral changes without user consent or extension updates

**Verdict**: **MEDIUM VULNERABILITY** - Remote configuration control enables server-side behavioral modifications.

---

### 4. Extension ID as Tracking Token
**Severity**: LOW
**Files**: `/background/background.js` (lines 331-398)

**Analysis**:
The extension generates a persistent tracking ID based on `chrome.runtime.id` + timestamp and registers it with the external server on install/update.

**Code Evidence** (lines 340-368):
```javascript
chrome.runtime.onInstalled.addListener(function (details) {
  const extensionId = guidGenerator()

  if (details.reason == "install") {

    chrome.storage.local.set({ extensionId: extensionId }).then(() => {

      chrome.storage.local.get("extensionId", function (res) {
        const apiUrl = `${baseUrl}/api/screenshot`
        const requestData = { token: res.extensionId };
        fetch(apiUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(requestData)
        })
          .then(response => {
            if (response.ok) {
            } else {
            }
          })

          .catch(error => {
          });

      })
    })
  }
```

**GUID Generation** (lines 331-336):
```javascript
function guidGenerator() {
  var S4 = function () {
    return (((1 + Math.random()) * 0x10000) | 0).toString(16).substring(1);
  };
  return (S4() + S4() + "-" + S4() + "-" + S4() + "-" + S4() + "-" + S4() + S4() + S4());
}
```

**User ID in option.js** (line 130):
```javascript
const t = e.fullPageUserId ?? "moclodffdpklilboaoegdnpdgnodkena"
```

**Privacy Impact**: LOW-MEDIUM
- Creates persistent identifier for user tracking across sessions
- Registered with server on install/update
- Used in all analytics tracking calls
- Enables cross-session user profiling

**Verdict**: **LOW VULNERABILITY** - Standard analytics pattern, but no user disclosure.

---

## Network Activity Analysis

### External Endpoints

| Endpoint | Purpose | Data Transmitted | Frequency |
|----------|---------|------------------|-----------|
| `img.fullpagecapture.com/screenshot-taken-userdata` | Analytics tracking | userId, pageUrl, screenshot type | Every screenshot |
| `img.fullpagecapture.com/upload-base64-image` | Image upload for sharing | userId, base64 image, pageUrl | User-initiated (share link) |
| `img.fullpagecapture.com/api/screenshot` | User registration | Generated GUID token | Install/update |
| `img.fullpagecapture.com/api/features` | Remote feature config | Extension ID token | On startup |
| `img.fullpagecapture.com/api/status` | Dynamic behavior check | Current page URL (origin+path) | Every page load (if hostname in "modal" list) |
| `fullpagecapture.com/#how-to-install` | Onboarding page | None (tab open) | Install |
| `fullpagecapture.com/#features` | Update page | None (tab open) | Update |
| `fullpagecapture.com/feedback/` | Uninstall survey | None (tab open) | Uninstall |

### Data Flow Summary

**Automatic Data Collection**:
- Extension ID registration (install/update)
- Feature configuration fetch (startup)
- Screenshot analytics (every screenshot: URL + type)
- Dynamic behavior checks (conditional on hostname matching)

**User-Initiated Data Collection**:
- Screenshot image upload with URL (when clicking "Share Link" button)

**Tracking Capability**: HIGH
- Persistent user IDs across sessions
- Complete screenshot usage tracking (what, where, when)
- Browsing patterns for targeted hostnames
- Server-controlled feature toggling

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `tabs` | Required for screenshot capture API | Low (core feature) |
| `storage` | Settings, user IDs, feature config | Medium (tracks behavior) |
| `downloads` | Save screenshots locally | Low (core feature) |
| `scripting` | Inject content scripts for capture | Low (core feature) |
| `notifications` | User notifications | Low (standard UX) |
| `gcm` | Google Cloud Messaging (push notifications) | Medium (unused in code?) |
| `host_permissions: <all_urls>` | Capture screenshots on any site | High (broad access) |

**Assessment**: Most permissions justified for screenshot functionality, but combined with tracking creates privacy risk.

## Content Security Policy
```json
No CSP declared in manifest.json (Manifest V3 default applies)
```
**Note**: Manifest V3 extensions have built-in CSP protections preventing inline script execution and eval().

## Code Quality Observations

### Positive Indicators
1. No dynamic code execution (`eval()`, `Function()`)
2. No external script loading
3. No XHR/fetch hooking or monkey-patching
4. No extension enumeration or killing
5. No residential proxy infrastructure
6. Clean screenshot capture implementation
7. Local image storage using IndexedDB (not automatic upload)

### Concerning Indicators
1. **Heavy analytics tracking** without disclosure
2. **Remote feature control** system
3. **Obfuscated variable names** (standard minification)
4. **No privacy policy** link in manifest
5. **GCM permission** declared but not clearly used in visible code
6. **Silent URL transmission** to external servers

### Obfuscation Level
**MEDIUM** - Variable names are minified/obfuscated (e.g., `e`, `t`, `o`, `a`), making reverse engineering harder. Ext-analyzer flagged as "obfuscated". Likely result of build process rather than deliberate malice.

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | No API interception |
| Market intelligence SDKs | ✗ No | No third-party analytics frameworks |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Remote config/kill switches | ✓ **YES** | `/api/features` + dynamic hostname targeting |
| Cookie harvesting | ✗ No | No cookie access |
| GA/analytics proxy bypass | ✗ No | No analytics manipulation |
| Hidden data exfiltration | ✓ **YES** | Screenshot analytics + URL tracking |
| User behavior tracking | ✓ **YES** | Every screenshot logs URL + type |

## Ext-Analyzer Output Analysis

**Flags**: `obfuscated`

**EXFILTRATION (4 flows)**:
1. `document.getElementById → fetch(img.fullpagecapture.com)` - option.js
2. `chrome.storage.local.get → fetch(img.fullpagecapture.com)` - option.js
3. `chrome.storage.sync.get → fetch(img.fullpagecapture.com)` - option.js
4. `chrome.storage.local.get → fetch(img.fullpagecapture.com)` - background.js

**Analysis**: All 4 flows are legitimate data exfiltration:
- Flows 1-3: Share link feature (user-initiated screenshot upload with URL)
- Flow 4: Analytics tracking or feature config fetch

**ATTACK SURFACE**:
- `message data → *.src(chromewebstore.google.com)` - Likely the "Rate Us" button (line 119-124 in option.js), benign

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Justification**:
1. **Analytics tracking without disclosure** - Collects URLs of all pages where screenshots are taken
2. **Remote feature control** - Server can modify extension behavior by targeting specific hostnames
3. **Screenshot upload includes URLs** - Optional but associates images with browsing context
4. **No privacy policy** - Users unaware of data collection practices
5. **Legitimate core functionality** - Screenshot capture works as expected
6. **No malicious payload** - No code execution, proxy, or extension killing

**Risk Breakdown**:
- **Privacy Risk**: HIGH (comprehensive tracking)
- **Security Risk**: MEDIUM (remote config control)
- **Malware Risk**: LOW (no malicious payload detected)
- **Combined Risk**: MEDIUM

### Recommendations
**For Users**:
- **Be aware** this extension tracks every URL where you take screenshots
- **Avoid** taking screenshots of sensitive pages (banking, healthcare, private messages)
- **Do not use** share link feature for screenshots containing PII or secrets
- **Consider alternatives** with better privacy practices

**For Developer**:
- Add privacy policy disclosure
- Make analytics opt-in instead of automatic
- Provide clear consent mechanism for URL tracking
- Disclose remote feature control in privacy policy
- Consider removing remote config system or limiting scope

### User Privacy Impact
**MEDIUM-HIGH** - The extension tracks:
- All URLs where screenshots are taken (automatic)
- Screenshot types and frequency (usage patterns)
- User IDs for cross-session profiling
- Optional: Full screenshot images with URLs (share feature)

No evidence of cross-site tracking beyond screenshot contexts, but comprehensive usage monitoring creates privacy risk.

## Technical Summary

**Lines of Code**: ~2,700 (deobfuscated, excluding libraries)
**External Dependencies**: jQuery, jsPDF, Cropper.js
**Third-Party Libraries**: All included locally (no CDN loading)
**Remote Code Loading**: None
**Dynamic Code Execution**: None

## Conclusion

Full Page Screen Capture is a **functional screenshot extension with problematic privacy practices**. The core functionality works as advertised, but the extension implements comprehensive user behavior tracking (URLs + screenshot types) and a remote feature control system that could enable dynamic behavioral changes. While no malicious payload or data theft mechanism was detected, the lack of privacy disclosure and automatic URL tracking constitute a medium-risk privacy concern.

**Final Verdict: MEDIUM** - Functional extension with privacy concerns. Not malware, but users should be aware of analytics tracking.
