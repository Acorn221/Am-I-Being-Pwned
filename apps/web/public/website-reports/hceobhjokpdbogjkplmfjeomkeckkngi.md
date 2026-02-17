# Security Analysis: New Bing Anywhere (hceobhjokpdbogjkplmfjeomkeckkngi)

## Extension Metadata
- **Name**: New Bing Anywhere
- **Extension ID**: hceobhjokpdbogjkplmfjeomkeckkngi
- **Version**: 2.7.2
- **Manifest Version**: 3
- **Estimated Users**: ~40,000
- **Developer**: ha0z1 (github.com/ha0z1/New-Bing-Anywhere)
- **Analysis Date**: 2026-02-15

## Executive Summary
New Bing Anywhere is a browser extension that enables access to Microsoft Bing Chat (Copilot) from any search engine page, including Google, Yandex, and other search providers. The extension injects a Bing Chat interface sidebar on search result pages and performs user-agent spoofing to enable Bing Chat features. Analysis identified **LOW** overall risk with three security concerns: an unvalidated postMessage listener, user-agent manipulation, and cookie modification. The extension is **legitimate and open-source** with no data exfiltration or malicious behavior detected.

**Overall Risk Assessment: LOW**

## Vulnerability Assessment

### 1. Unvalidated postMessage Listener (MEDIUM Risk)
**Severity**: Medium
**Files**: `/content_script.js` (line 3553)

**Analysis**:
The extension registers a `window.addEventListener("message")` handler without origin validation, creating a potential attack surface for malicious web pages to send crafted messages.

**Code Evidence** (`content_script.js`):
```javascript
window.addEventListener("message", ne => {
  let {
    type: N,
    data: E
  } = ne.data;
  if (N === "nba-ready" && oe.css("visibility", "visible"), N === "nba-resize") {
    let {
      height: De
    } = E;
    oe.css({
      height: Math.floor(De) + 1
    })
  }
})
```

**Attack Surface**:
- Any web page can post messages with `type: "nba-ready"` or `type: "nba-resize"`
- The `nba-resize` handler accepts arbitrary height values from untrusted sources
- Could potentially be used to manipulate the injected UI dimensions

**Mitigation Factors**:
- Limited impact: only controls CSS visibility and height of injected iframe
- No sensitive data handling in the message handler
- No cross-origin data leakage
- The injected iframe itself has proper origin isolation

**Risk Assessment**: **MEDIUM** - Should validate `event.origin` to prevent UI manipulation by malicious pages.

**Recommendation**: Add origin check:
```javascript
if (ne.origin !== chrome.runtime.getURL('').replace(/\/$/, '')) return;
```

---

### 2. User-Agent Spoofing (LOW Risk)
**Severity**: Low
**Files**: `/inject.js` (lines 17-36)

**Analysis**:
The extension overwrites `navigator.userAgent` and `navigator.userAgentData` to impersonate Microsoft Edge, likely to bypass Bing Chat browser restrictions.

**Code Evidence** (`inject.js`):
```javascript
let e = i(); // Generates Edge user-agent string
Object.defineProperty(navigator, "userAgent", {
  get: () => e
});
// ...
Object.defineProperty(navigator, "userAgentData", {
  get: () => ({
    brands: [{
      brand: "Not A(Brand",
      version: "99"
    }, {
      brand: "Microsoft Edge",
      version: "121"
    }, {
      brand: "Chromium",
      version: "121"
    }],
    mobile: !1,
    platform: "Windows"
  })
})
```

**Spoofed User-Agent**:
- Macintosh: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ... Edg/121.0.2277.106`
- Windows: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Edg/121.0.2277.106`

**Purpose**:
- Enables Bing Chat features that Microsoft restricts to Edge browser
- Grants access to Bing's AI conversation features on non-Edge browsers

**Privacy Implications**:
- Websites may receive incorrect browser fingerprinting data
- Analytics and telemetry will show Edge usage instead of actual browser
- Could bypass browser-specific security policies

**Legitimacy Check**:
- This is the **core functionality** of the extension (enabling Bing Chat outside Edge)
- Transparent in the extension's GitHub repository and name ("New Bing Anywhere")
- No deceptive intent - users install specifically for this purpose

**Risk Assessment**: **LOW** - While technically user-agent spoofing, it's the declared purpose of the extension with no malicious intent.

---

### 3. Cookie Manipulation (LOW Risk)
**Severity**: Low
**Files**: `/background.js` (lines 285-341)

**Analysis**:
The extension modifies Bing cookies (`_EDGE_S`, `_RwBf`, `ANON`) to enable Bing Chat features and bypass regional restrictions.

**Code Evidence** (`background.js`):
```javascript
chrome.webRequest.onBeforeRequest.addListener(() => {
  chrome.cookies.get({
    name: "_EDGE_S",
    url: c // "https://www.bing.com/"
  }, e => {
    let t = y(o), // Parse cookie value
        n = t.get("mkt")?.toLowerCase() ?? "";
    // If market is restricted (zh-CN, ru, ru-ru):
    I.map(s => s.toLowerCase()).includes(n) && (
      n === "zh-cn" ?
        (t.set("mkt", "zh-HK"), t.set("ui", "zh-hans")) :
        t.delete("mkt"),
      p({ url: c, name: e.name, value: t.toString() }, e)
    )
  })
  // ... similar for _RwBf cookie (sets wls=2)
  // ... and ANON cookie (deletes "A" parameter)
})
```

**Modified Cookies**:
1. **`_EDGE_S`**: Changes market code from `zh-CN` (China) to `zh-HK` (Hong Kong)
2. **`_RwBf`**: Sets `wls=2` parameter (likely enables web language settings)
3. **`ANON`**: Removes the `A` parameter (unknown purpose)

**Purpose**:
- Bypasses regional restrictions for Bing Chat access
- Enables features that may be disabled in certain countries (e.g., China, Russia)

**Security Implications**:
- Only modifies first-party Bing.com cookies
- No third-party cookie access
- No cross-site cookie injection
- Changes are limited to Bing domains

**Privacy Implications**:
- May circumvent Microsoft's geographic restrictions
- Could violate Microsoft's Terms of Service (user responsibility)
- No data exfiltration - modifications stay within Bing ecosystem

**Risk Assessment**: **LOW** - Cookie modifications are scoped to Bing.com and serve the extension's core purpose.

---

### 4. Dynamic Redirect Rule (INFO)
**Severity**: Informational
**Files**: `/background.js` (lines 343-368), `/rules.json`

**Analysis**:
The extension creates a dynamic redirect rule for Chinese users to add an invite code parameter to `chat.aiplus.lol` URLs.

**Code Evidence**:
```javascript
var N = [k && [{  // k = isChinese
  action: {
    type: V, // "redirect"
    redirect: {
      url: `${x}?invite_code=b90e84b5`  // x = "https://chat.aiplus.lol/login"
    }
  },
  condition: {
    requestDomains: ["chat.aiplus.lol"],
    urlFilter: x,
    isUrlFilterCaseSensitive: !1,
    resourceTypes: A
  }
}]].flat().filter(Boolean)
```

**Behavior**:
- **Only active for Chinese language users** (`k && ...`)
- Redirects `https://chat.aiplus.lol/login` → `https://chat.aiplus.lol/login?invite_code=b90e84b5`
- Adds affiliate/referral code `b90e84b5`

**Purpose**:
- `aiplus.lol` appears to be a third-party ChatGPT/AI service
- Likely a referral partnership to monetize Chinese users
- Invite code may grant premium features or referral credits

**Concerns**:
- Not disclosed prominently (hidden in code)
- Monetization via affiliate link
- Only affects Chinese users (language targeting)
- Unknown service (aiplus.lol) - potential privacy implications

**Risk Assessment**: **INFORMATIONAL** - Transparent affiliate redirect for specific user segment. Not malicious but should be disclosed.

---

## Legitimate Functionality Analysis

### Core Features (As Designed)

#### 1. Bing Chat Sidebar Injection
**Files**: `content_script.js` (lines 3400-3600)

The extension injects a Bing Chat sidebar on Google, Yandex, and other search pages using an iframe:

```javascript
let oe = (0, qe.default)('<div id="nba-sidebar" />').css({
  position: "fixed",
  right: "0px",
  top: "0px",
  width: "400px",
  height: "100vh",
  // ... styling
});
```

**Purpose**: Displays Bing AI chat interface alongside search results.

#### 2. Search Query Passthrough
**Files**: `background.js` (lines 233-257)

Opens Bing/Google tabs with search queries from context menu or user actions:

```javascript
H = async ({ url: e } = {}) => {
  let t = g(e), // Parse URL
      r = t.searchParams.get("q") ?? ""; // Extract search query
  // Open/update tab with search query
  await chrome.tabs.update(n.id, { url: s })
}
```

**Purpose**: Allows switching between search engines while preserving queries.

#### 3. Context Menu Items
**Files**: `background.js` (lines 129-189)

Adds helpful shortcuts to extension icon menu:

- Open Copilot
- Open New Bing Chat
- Open Bing Image Creator
- Like it (Chrome Web Store review page)
- Report issues (GitHub issues with auto-filled environment data)

#### 4. Notification System
**Files**: `background.js` (lines 202-232)

Fetches announcements from GitHub issue #24 and displays notifications:

```javascript
Y = async () => {
  e = await fetch("https://api.github.com/repos/ha0z1/New-Bing-Anywhere/issues/24")
    .then(async o => await o.json())
}
```

**Data Transmitted**: None (only fetches public GitHub data)
**Purpose**: Shows extension updates/announcements to users

---

## False Positive Analysis

### Ext-Analyzer Findings Review

The static analyzer flagged **5 "exfiltration" flows** in `app/assets/index.js`:

| Flow | Assessment | Explanation |
|------|------------|-------------|
| `document.querySelectorAll → fetch` | **FALSE POSITIVE** | React framework code (preload links), not data exfiltration |
| `chrome.storage.local.get → fetch` | **FALSE POSITIVE** | React Router fetcher abstraction, no actual network call |
| `chrome.tabs.query → fetch` | **FALSE POSITIVE** | React code path in popup UI, not data exfiltration |
| `chrome.tabs.query → *.src(www.w3.org)` | **FALSE POSITIVE** | Likely SVG/icon loading in React UI |
| `document.getElementById → fetch` | **FALSE POSITIVE** | React root mounting (`document.getElementById("root")`) |

**Actual Network Calls**:
1. `fetch("https://www.bing.com/turing/conversation/create")` - Legitimate Bing Chat API call
2. `fetch("https://api.github.com/repos/ha0z1/New-Bing-Anywhere/issues/24")` - Notification fetch

**Conclusion**: The analyzer correctly detected network-capable code paths but failed to distinguish between:
- **React framework abstractions** (fetcher API, router, component lifecycle)
- **Actual data exfiltration** (sending user data to external servers)

**Verdict**: **NO DATA EXFILTRATION DETECTED**

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `api.github.com` | Fetch announcements | None (public API) | On extension load (cached 1hr) |
| `www.bing.com/turing/*` | Bing Chat API | Conversation messages (user-initiated) | Per chat interaction |
| `github.com/ha0z1/*` | Documentation links | None (navigation only) | User-triggered |
| `chat.aiplus.lol` | ChatGPT alternative (CN users) | Redirect with invite code | On navigation (CN users only) |

### Data Flow Summary

**Data Collection**: None (no telemetry, analytics, or tracking)
**User Data Transmitted**: Only to Bing Chat API (expected behavior)
**Tracking/Analytics**: None
**Third-Party Services**: Bing Chat (Microsoft), GitHub API (public)

**Privacy Assessment**: The extension does not collect or exfiltrate user data beyond the intended Bing Chat interactions.

---

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `storage` | Settings and configuration storage | Low (local only) |
| `cookies` | Modify Bing cookies to enable chat features | Low (Bing domain only) |
| `webRequest` | Intercept Bing requests to modify cookies | Medium (broad permission) |
| `contextMenus` | Add extension shortcuts to menu | Low (UI only) |
| `declarativeNetRequest` | Redirect aiplus.lol URLs (CN users) | Low (scoped to one domain) |
| `host_permissions: <all search engines>` | Inject chat sidebar on search pages | Medium (necessary but broad) |
| `optional_permissions: https://*/*` | Allow chat on any HTTPS page | High (user must grant) |

**Assessment**: Permissions are appropriately scoped for declared functionality. The `webRequest` permission is the highest risk but limited to Bing.com URLs.

---

## Content Security Policy
```json
Default Manifest V3 CSP applies (no custom CSP)
```
**Evaluation**: Standard MV3 protections prevent inline scripts and `eval()`. No weakening of CSP detected.

---

## Code Quality Observations

### Positive Indicators
1. **Open-source** (GitHub: ha0z1/New-Bing-Anywhere)
2. **Active development** with version 2.7.2 and regular updates
3. **No dynamic code execution** (`eval()`, `Function()`)
4. **No remote code loading** (all resources bundled)
5. **Clean React application architecture** (popup UI)
6. **Minimal network activity** (only Bing Chat and GitHub)
7. **Transparent cookie modifications** (documented in code)
8. **Community engagement** (GitHub issues, user support)

### Negative Indicators
1. **Obfuscated code** in `app/assets/index.js` (React production build)
2. **Missing origin validation** on postMessage listener
3. **Undisclosed affiliate redirect** (aiplus.lol for CN users)
4. **User-agent spoofing** (expected but technically deceptive)
5. **Cookie manipulation** (may violate Microsoft ToS)

### Obfuscation Level
**Medium** - React production build with minified variable names. Background/content scripts are readable with standard beautification. No deliberate malicious obfuscation.

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | Extension creates conversations, doesn't intercept |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Remote config/kill switches | ✗ No | Configuration fetched from GitHub (public) |
| Cookie harvesting | ✗ No | Only modifies Bing cookies (functional) |
| Data exfiltration | ✗ No | All network calls are functional/transparent |
| Keylogging | ✗ No | No keyboard event capture |

---

## Overall Risk Assessment

### Risk Level: **LOW**

**Justification**:
1. **Legitimate purpose** - Enables Bing Chat on non-Edge browsers (as advertised)
2. **Open-source transparency** - Code available on GitHub for review
3. **Minimal data collection** - No telemetry, analytics, or user tracking
4. **Scoped modifications** - Cookie/UA changes limited to Bing functionality
5. **Active maintenance** - Regular updates and community support
6. **No malicious patterns** - Clean codebase with no data exfiltration

**Vulnerabilities Identified**:
- 1 Medium (unvalidated postMessage listener)
- 2 Low (user-agent spoofing, cookie manipulation)

**Mitigating Factors**:
- Vulnerabilities are functional side effects, not malicious intent
- Limited attack surface (message handler only controls UI dimensions)
- Cookie modifications scoped to Bing domains
- User-agent spoofing is transparent and expected behavior

---

### Security Recommendations

#### For Developer (ha0z1)
1. **Add origin validation** to postMessage listener:
   ```javascript
   window.addEventListener("message", ne => {
     if (ne.origin !== chrome.runtime.getURL('').replace(/\/$/, '')) return;
     // ... existing code
   })
   ```

2. **Disclose affiliate relationship** for `chat.aiplus.lol` redirect in:
   - Extension description
   - Privacy policy
   - GitHub README

3. **Consider CSP headers** to further harden the extension

#### For Users
- **Understand the risks**: User-agent spoofing may violate Microsoft's ToS
- **Review permissions**: Extension requires broad access to search engine pages
- **Monitor behavior**: Extension is open-source and can be audited
- **Optional permissions**: Only grant `https://*/*` if you want chat on all pages

---

### User Privacy Impact
**LOW** - The extension:
- Does not track browsing history
- Does not collect personal data
- Only sends user messages to Bing Chat (expected behavior)
- Modifies cookies exclusively for Bing functionality
- No third-party analytics or telemetry

**Transparency**: Extension is open-source and behavior matches description.

---

## Technical Summary

**Lines of Code**: ~60,000 (mostly React framework in app/assets/index.js)
**External Dependencies**: React, React Router (bundled in production build)
**Third-Party Libraries**: jQuery (in content_script.js)
**Remote Code Loading**: None
**Dynamic Code Execution**: None

---

## Conclusion

New Bing Anywhere is a **legitimate, open-source browser extension** that enables Microsoft Bing Chat (Copilot) on non-Edge browsers by spoofing user-agent strings and modifying Bing cookies. The extension operates transparently with its GitHub repository documenting all functionality.

**Security Concerns**:
1. Unvalidated postMessage listener (easily fixable)
2. User-agent spoofing (core functionality, expected)
3. Cookie manipulation (scoped to Bing, functional)

**No Malicious Behavior Detected**:
- No data exfiltration
- No tracking or surveillance
- No hidden functionality
- Transparent network calls (Bing Chat API, GitHub notifications)

**Final Verdict: LOW RISK** - Safe for use with ~40K users. Recommended improvements: add origin validation and disclose affiliate redirect.

---

## References
- **GitHub Repository**: https://github.com/ha0z1/New-Bing-Anywhere
- **Chrome Web Store**: https://chrome.google.com/webstore/detail/hceobhjokpdbogjkplmfjeomkeckkngi
- **Version Analyzed**: 2.7.2 (MV3)
