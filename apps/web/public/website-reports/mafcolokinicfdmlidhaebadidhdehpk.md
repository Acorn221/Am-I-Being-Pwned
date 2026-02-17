# Security Analysis: Story Saver (mafcolokinicfdmlidhaebadidhdehpk)

## Extension Metadata
- **Name**: Story Saver
- **Extension ID**: mafcolokinicfdmlidhaebadidhdehpk
- **Version**: 2.9.30
- **Manifest Version**: 3
- **Estimated Users**: ~200,000
- **Analysis Date**: 2026-02-14

## Executive Summary
Story Saver is a Chrome extension for downloading stories from Instagram, Facebook, and WhatsApp. Analysis reveals **HIGH risk** due to multiple critical vulnerabilities: user tracking via third-party domain (ex.zework.com), dangerous postMessage handlers without origin validation that enable XSS attacks, and scraping of Facebook authentication tokens from page HTML. While the extension's core functionality appears legitimate, the security flaws and tracking mechanisms pose significant privacy and security risks to users.

**Overall Risk Assessment: HIGH**

## Vulnerability Assessment

### 1. User Tracking and Analytics to Third-Party Domain
**Severity**: HIGH
**Files**:
- `/deobfuscated/background.js` (lines 11995-12015)

**Analysis**:
The extension implements persistent user tracking by sending a unique identifier to ex.zework.com on every startup. This constitutes unauthorized analytics collection.

**Code Evidence** (`background.js`):
```javascript
chrome.storage.local.get('KEYUSER', function (result) {
    var iduser = result.KEYUSER;
    if(iduser){
        fetch("https://ex.zework.com/?on="+iduser)
    }else {
        var keyidmake=randomkey(25)+navigator.language
        chrome.storage.local.set({ "KEYUSER":  keyidmake }).then(() => {
            console.log("Value is set");
        });
        fetch("https://ex.zework.com/?id="+keyidmake)
    }
})
```

**Data Transmitted**:
- Unique 25-character random ID (persistent across sessions)
- User's browser language (via `navigator.language`)
- On every extension startup: `?on={user_id}` (returning users)
- On first install: `?id={user_id}{language}` (new users)

**Privacy Impact**:
- Creates persistent cross-session tracking identifier
- No user consent or disclosure
- Third-party domain not disclosed in manifest permissions
- Enables user behavior correlation and profiling

**Verdict**: **CRITICAL PRIVACY VIOLATION** - Undisclosed telemetry to external domain.

---

### 2. Unsafe postMessage Handlers (XSS Attack Surface)
**Severity**: HIGH
**Files**:
- `/deobfuscated/instagramdowhandx.js` (line 28)
- `/deobfuscated/content_scripts/instagramdowhand.js` (line 275)
- `/deobfuscated/content_scripts/facebook-video.js` (line 13)

**Analysis**:
Multiple content scripts listen for window `message` events without validating the message origin, creating XSS attack vectors on Instagram and Facebook pages.

**Code Evidence** (`instagramdowhandx.js:28`):
```javascript
window.addEventListener("message", (event) => {
    if (event.data == "nullvideo" && elementping) {
        elementping.parentElement.parentElement.getElementsByClassName("violet_toolkit_dl_btn")[0].click();
    }
}, false);
```

**Code Evidence** (`facebook-video.js:13-18`):
```javascript
window.addEventListener(
    "message",
    (event) => {
        console.log(event)
        var username="";
        if(event.data.includes("https")){
            // ... processes message data without origin check
        }
    }
)
```

**Attack Vector**:
1. Malicious website opens Instagram/Facebook in iframe (or vice versa)
2. Attacker sends crafted `postMessage()` to victim tab
3. Extension content script processes message without origin validation
4. Can trigger clicks on extension buttons or inject malicious URLs

**ext-analyzer findings**:
- instagramdowhandx.js:28 - message data → fetch(ex.zework.com)
- instagramdowhand.js:275 - message data → *.innerHTML (XSS sink)
- facebook-video.js:13 - no origin check

**Verdict**: **CRITICAL VULNERABILITY** - Enables XSS and click-jacking attacks on social media pages.

---

### 3. Facebook Authentication Token Harvesting
**Severity**: MEDIUM-HIGH
**Files**:
- `/deobfuscated/content_scripts/facebook-video.js` (lines 452-453, 627-629, 728-729)

**Analysis**:
The extension scrapes Facebook authentication tokens and user IDs from page HTML and cookies for API requests. While used for legitimate download functionality, this creates credential exposure risk.

**Code Evidence** (`facebook-video.js`):
```javascript
var uid = "";
var fbag = ""
try {
    uid = document.cookie.match(/c_user.*?(?=;)/g)[0].split("=")[1]
    fbag = document.documentElement.innerHTML.match(/"token":".*?(?=")/g)[0].split("\"")[3]
} catch (ex) {
}

fetch("https://www.facebook.com/api/graphql/", {
    "body": "av="+uid+"&__user="+uid+"&fb_dtsg="+fbag+"&..."
})
```

**Security Concerns**:
1. **Cookie harvesting**: Extracts `c_user` cookie (Facebook user ID)
2. **Token scraping**: Regex-parses `fb_dtsg` token from page HTML
3. **Credentials in plaintext**: Tokens handled without encryption
4. **No sandboxing**: Runs in content script with full page access

**Mitigating Factors**:
- Tokens only sent to facebook.com (legitimate API endpoint)
- No evidence of exfiltration to third-party servers
- Used for downloading user's own content (authorized use case)

**Risk**:
If extension is compromised, attacker gains access to Facebook session tokens for 200K users.

**Verdict**: **MEDIUM-HIGH** - Legitimate use but dangerous pattern that increases attack surface.

---

### 4. Unsafe innerHTML Usage with Instagram Data
**Severity**: MEDIUM
**Files**:
- `/deobfuscated/content_scripts/facebook-video.js` (lines 861, 873)
- `/deobfuscated/content_scripts/facebook.js` (line 28)

**Analysis**:
Direct assignment to `innerHTML` with data from Instagram/Facebook pages creates DOM-based XSS risk.

**Code Evidence** (`facebook-video.js:861`):
```javascript
obj.innerHTML = '<span class="violet_toolkit_dl_pregress_loader"></span>    <span class="violet_toolkit_icon"></span>    '
```

**Code Evidence** (`facebook.js:28`):
```javascript
story.innerHTML= story.innerHTML+="<h1>download</h1>>"
```

**Current Risk**: LOW-MEDIUM
- Most innerHTML assignments use static strings
- Limited user-controlled input in observed cases
- However, ext-analyzer flagged message data → innerHTML flow

**Potential Attack**:
If message handler passes data to innerHTML (as flagged by analyzer), malicious postMessage could inject script tags.

**Verdict**: **MEDIUM** - Pattern is dangerous even if current exploitation is unclear.

---

### 5. Remote Configuration Token Checking
**Severity**: LOW-MEDIUM
**Files**: `/deobfuscated/background.js` (lines 11860-11987)

**Analysis**:
Background script polls browser localStorage every 60 seconds looking for authentication tokens, suggesting potential remote configuration or kill-switch capability.

**Code Evidence** (`background.js:11989-11992`):
```javascript
// Check for token in localStorage every minute
setInterval(checkLocalStorageForToken, 60000);
// Run once on startup
setTimeout(checkLocalStorageForToken, 5000);
```

**Function** (`background.js:11860-11886`):
```javascript
function checkLocalStorageForToken() {
    chrome.tabs.query({ url: ["*://*.instagram.com/*"] }, (tabs) => {
        tabs.forEach((tab) => {
            chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: function() {
                    const token = localStorage.getItem('ig_premium_token');
                    if (token) {
                        chrome.runtime.sendMessage({
                            action: "auth_success",
                            token: token
                        });
                    }
                }
            });
        }
    });
}
```

**Behavior**:
- Every 60 seconds, checks all Instagram tabs for `ig_premium_token` in localStorage
- Sends token to background script when found
- Token stored in `chrome.storage.sync` as `premiumStatus`

**Risk**:
- No token validation before storing in sync storage
- Could be exploited by malicious Instagram pages injecting fake tokens
- Creates dependency on external premium service (ex.zework.com)

**Verdict**: **LOW-MEDIUM** - Questionable architecture but not directly malicious.

---

## False Positive Patterns Identified

| Pattern | Location | Reason for FP | Actual Purpose |
|---------|----------|---------------|----------------|
| `document.cookie.match(/c_user/)` | `facebook-video.js` | Looks like cookie theft | Used for legitimate Facebook API calls |
| Facebook token scraping | `facebook-video.js:453` | Appears as credential harvesting | Required for downloading user's own stories |
| `addEventListener("message")` | Multiple files | Could be mistaken for safe messaging | Actually unsafe - missing origin checks |
| User ID tracking | `background.js:11995` | Could be dismissed as analytics | Actually privacy violation - undisclosed third-party |

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Risk Level |
|--------|---------|------------------|------------|
| `ex.zework.com` | User tracking & premium features | Unique user ID + language | HIGH |
| `www.instagram.com` | Download Instagram stories | User session cookies (legitimate) | LOW |
| `i.instagram.com` | Instagram media CDN | Story media URLs | LOW |
| `www.facebook.com` | Download Facebook stories | User ID + auth tokens (legitimate) | MEDIUM |

### Data Exfiltration Analysis

**What ex.zework.com receives**:
1. **On first install**: `?id={25-char-random-id}{navigator.language}`
2. **On every startup**: `?on={user-id}` (beacon)
3. **Premium features**: Authentication tokens from Instagram localStorage

**ext-analyzer findings confirm**:
- chrome.storage.sync.get → fetch(ex.zework.com) [HIGH severity flow]
- chrome.storage.local.get → fetch(ex.zework.com) [HIGH severity flow]

**No evidence found of**:
- Facebook/Instagram credentials sent to ex.zework.com
- Browsing history exfiltration
- Downloaded content uploaded to third-party

**Verdict**: Tracking is limited to user ID + language, but still constitutes undisclosed telemetry.

---

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `storage` | Required for download tracking | LOW (appropriate) |
| `downloads` | Core feature (downloading stories) | LOW (appropriate) |
| `scripting` | Inject download buttons into pages | MEDIUM (necessary but powerful) |
| `tabs` | Access to active tab URLs | MEDIUM (necessary) |
| `declarativeContent` | Page action conditions | LOW (appropriate) |
| `*://*.instagram.com/*` | Required for Instagram functionality | MEDIUM (appropriate scope) |
| `*://*.facebook.com/*` | Required for Facebook functionality | MEDIUM (appropriate scope) |
| `*://*.whatsapp.com/*` | Declared but minimal usage observed | LOW (unused?) |
| `*://*.zework.com/*` | **NOT DISCLOSED IN PRIVACY POLICY** | **HIGH (red flag)** |

**Assessment**: Permissions are mostly justified for stated functionality, but zework.com host permission enables undisclosed tracking.

---

## Content Security Policy
```
No custom CSP declared (Manifest V3 defaults apply)
```

Manifest V3 provides built-in protections against inline scripts and eval(), which mitigates some risks.

---

## Code Quality Observations

### Negative Indicators
1. **Obfuscated code**: Variable names are minified, logic is complex
2. **No origin validation**: postMessage handlers accept messages from any source
3. **Credential handling**: Facebook tokens parsed from HTML (fragile pattern)
4. **Third-party tracking**: Undisclosed analytics to ex.zework.com
5. **innerHTML usage**: Direct DOM manipulation without sanitization
6. **Hard-coded premium bypass**: `isPremium: true` in code (lines 2654-2660)

### Positive Indicators
1. No dynamic code execution (`eval()`, `Function()`)
2. No external script loading
3. No extension enumeration or killing
4. No XHR/fetch hooking or monkey-patching
5. Facebook/Instagram credentials stay on legitimate domains (not exfiltrated)

### Obfuscation Level
**MEDIUM-HIGH** - Code is minified and uses unclear variable names. Some sections have comments suggesting AI-generated or multi-developer origin. Hard to audit.

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| Cookie harvesting for exfiltration | ⚠ Partial | Harvests Facebook cookies but uses locally |
| Remote code loading | ✗ No | All code bundled |
| Hidden data exfiltration | ✓ Yes | User ID tracking to ex.zework.com |
| Unsafe postMessage handlers | ✓ Yes | Multiple handlers with no origin checks |
| Ad/coupon injection | ✗ No | Only internal "donate" ads |
| Market intelligence SDKs | ✗ No | No third-party tracking SDKs |

---

## Overall Risk Assessment

### Risk Level: **HIGH**

**Critical Issues (Must Fix)**:
1. **Undisclosed user tracking** to ex.zework.com (privacy violation)
2. **Unsafe postMessage handlers** enabling XSS attacks
3. **No origin validation** on cross-window messaging

**High-Priority Issues**:
1. Facebook token harvesting creates credential exposure risk
2. innerHTML usage with social media data (XSS vector)
3. Host permission for zework.com not disclosed to users

**Medium-Priority Issues**:
1. Remote configuration via localStorage polling
2. Hard-coded premium bypass in code
3. Obfuscated code makes auditing difficult

### Exploitation Likelihood
**MEDIUM-HIGH** - XSS vulnerabilities are easily exploitable by malicious websites. Tracking infrastructure is already active.

### Impact Severity
**HIGH** - 200,000 users exposed to:
- Undisclosed tracking
- XSS attacks while browsing Instagram/Facebook
- Potential Facebook credential compromise if extension is further exploited

---

## Recommendations

### For Users
1. **Uninstall recommended** until vulnerabilities are addressed
2. If keeping: Avoid clicking suspicious links while using Instagram/Facebook
3. Review browser extension permissions regularly
4. Consider privacy-focused alternatives

### For Developers (If Remediation Attempted)
1. **Remove ex.zework.com tracking** or disclose in privacy policy
2. **Add origin validation** to all postMessage handlers:
   ```javascript
   if (event.origin !== "https://www.instagram.com") return;
   ```
3. **Eliminate innerHTML usage** - use `textContent` or `createElement()`
4. **Document Facebook token usage** in privacy policy
5. **Remove obfuscation** for transparency and auditability
6. **Implement Content Security Policy** headers

### For Chrome Web Store Review
1. Request privacy policy update disclosing ex.zework.com data collection
2. Require fixes for postMessage origin validation
3. Consider suspension until critical XSS vulnerabilities are addressed

---

## Technical Summary

**Lines of Code**: ~15,000 (deobfuscated)
**External Dependencies**: SweetAlert2 (alerts library)
**Third-Party Services**: ex.zework.com (tracking + premium features)
**Dynamic Code Execution**: None detected
**Network Calls**: 4 domains (Instagram, Facebook, ex.zework.com, fbcdn.net)

---

## Conclusion

Story Saver provides functional story downloading capabilities but implements **dangerous security patterns** and **undisclosed user tracking**. The unsafe postMessage handlers create exploitable XSS vulnerabilities on Instagram and Facebook pages, while the persistent tracking to ex.zework.com violates user privacy expectations. The Facebook token harvesting, though used legitimately, increases the attack surface significantly.

Given the combination of XSS vulnerabilities, undisclosed tracking, and 200K user install base, this extension poses **HIGH risk** and should be considered for suspension until critical security issues are addressed.

**Final Verdict: HIGH RISK** - Not recommended for use in current state.
