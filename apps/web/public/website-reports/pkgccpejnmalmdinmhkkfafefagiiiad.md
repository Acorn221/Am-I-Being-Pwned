# Security Analysis: FeHelper(前端助手) (pkgccpejnmalmdinmhkkfafefagiiiad)

## Extension Metadata
- **Name**: FeHelper(前端助手)
- **Extension ID**: pkgccpejnmalmdinmhkkfafefagiiiad
- **Version**: 2025.11.2601
- **Manifest Version**: 3
- **Estimated Users**: ~200,000
- **Developer**: fehelper.com
- **Analysis Date**: 2026-02-14

## Executive Summary
FeHelper is a **legitimate developer tools extension** for frontend development with **MEDIUM** risk assessment. The extension provides extensive functionality (JSON formatting, code beautification, QR codes, screenshot tools, etc.) but includes concerning privacy practices: usage analytics tracking to fehelper.com, an embedded AI assistant with a hardcoded API key, remote configuration/hotfix capabilities, and postMessage handlers without origin validation. While no malicious behavior was detected, the broad permissions (all URLs access) combined with telemetry and third-party AI service integration present notable privacy and security concerns.

**Overall Risk Assessment: MEDIUM**

## ext-analyzer Report Summary
- **Total Findings**: 86 HIGH severity findings
- **Exfiltration Flows**: 84 data exfiltration patterns detected
- **Attack Surface**: 2 open postMessage handlers without origin checks
- **Risk Score**: 75/100 (manifest permissions: 30pts, flows: 40pts)
- **Obfuscation**: False (code is minified but not obfuscated)
- **WASM**: False

**Note**: The high finding count (86) is inflated by ext-analyzer detecting legitimate tool functionality as potential exfiltration. Manual analysis confirms most flows are benign feature implementation.

## Vulnerability Assessment

### 1. Hardcoded API Key for Third-Party AI Service
**Severity**: MEDIUM (Privacy/Cost Abuse Risk)
**Files**:
- `/aiagent/fh.ai.js` (line 238)

**Analysis**:
The extension includes an AI assistant feature powered by SiliconFlow (Chinese AI API provider). The API key is hardcoded and base64-encoded in the source code.

**Code Evidence**:
```javascript
// Line 238 in fh.ai.js
Authorization: "Bearer ".concat(n || EncodeUtils.base64Decode(
  "c2stamJ5eGlldmVmdmhnbnBnbGF3cmxlZ25uam9rY25kc3BpYndjZmh1d2Ntbm9jbmxp"
))

// Decoded: sjkjbyxievefvhgnpglawrlegnnjokndspibwcfhuwcmnocnli
// Line 258:
fetch("https://api.siliconflow.cn/v1/chat/completions", {
  method: "POST",
  headers: { "Content-Type": "application/json", Authorization: ... },
  body: JSON.stringify({
    model: "Qwen/Qwen2.5-Coder-7B-Instruct",
    messages: userMessages,  // User-provided prompts
    stream: true,
    max_tokens: 4096
  })
})
```

**Data Transmitted**:
- User-provided AI prompts (potentially containing code, debugging info, or sensitive data)
- System prompt: "你是由FeHelper提供的，一个专为开发者服务的AI助手..." (Chinese: "You are an AI assistant provided by FeHelper...")
- No user identifiers sent directly, but API provider logs may correlate requests

**Risks**:
1. **Privacy**: User prompts sent to Chinese AI service (SiliconFlow) may be logged/analyzed
2. **Cost Abuse**: Hardcoded API key allows anyone to extract and abuse it for free API access
3. **Data Exposure**: Developers might paste sensitive code/credentials into AI assistant
4. **No Consent**: Users may not realize AI queries leave their browser

**Mitigations in Code**:
- User must explicitly enable AI agent feature (not auto-enabled)
- User can provide their own API key (parameter `n` in function signature)
- API key stored in extension source, not fetched remotely

**Verdict**: **MEDIUM RISK** - While user-initiated, sending potentially sensitive prompts to third-party AI service without clear disclosure is concerning.

---

### 2. Usage Analytics / Telemetry to fehelper.com
**Severity**: MEDIUM (Privacy Risk)
**Files**:
- `/background/statistics.js` (lines 298-446)
- `/background/background.js` (lines 526, 618)

**Analysis**:
The extension implements comprehensive usage tracking, sending telemetry to `https://chrome.fehelper.com/api/track` on various events.

**Code Evidence**:
```javascript
// Line 298 in statistics.js
SERVER_TRACK_URL = "https://chrome.fehelper.com/api/track";

// Lines 429-446: Event tracking function
fetch(SERVER_TRACK_URL, {
  method: "POST",
  body: JSON.stringify({
    event: eventName,           // e.g., "daily_active_user", "tool_used", "extension_installed"
    userId: generatedUserId,    // Persistent ID: "fh_" + timestamp + "_" + random
    userAgent: navigator.userAgent,
    language: navigator.language,
    platform: navigator.platform,
    extensionVersion: chrome.runtime.getManifest().version,
    tool_name: toolName,        // Which tool user clicked
    date: "2026-02-14"
  }),
  headers: { "Content-Type": "application/json" },
  keepalive: true
})
```

**Events Tracked**:
1. **extension_installed**: On first install
2. **extension_updated**: On version update (includes previous version)
3. **extension_uninstall**: On uninstall (set via `chrome.runtime.setUninstallURL`)
4. **daily_active_user**: Once per day when extension is active
5. **tool_used**: Every time user uses a tool (JSON formatter, QR code, etc.)
6. **usage_summary**: Every 7 days (top 5 most-used tools)

**Data Transmitted**:
- Persistent user ID (generated on first run, stored in `chrome.storage.local`)
- Browser fingerprint: userAgent, language, platform
- Extension version
- Tool usage patterns (which tools, how often)
- **No browsing history, URLs visited, or page content**

**Storage Keys**:
- `FH_USER_ID`: Persistent tracking ID
- `FH_LAST_ACTIVE_DATE`: Last active date
- `FH_USER_USAGE_DATA`: Daily/lifetime usage statistics (stored locally)

**Privacy Impact**:
- User is assigned a persistent tracking ID across sessions
- Developer can build usage profiles (device fingerprint + behavior patterns)
- Data collection happens silently with no user consent dialog
- No opt-out mechanism visible in code
- **No PII collected** (no emails, names, IPs collected client-side)

**Comparison to Similar Extensions**:
This is more telemetry than most developer tools (e.g., JSONView has zero analytics), but less invasive than marketing/analytics extensions.

**Verdict**: **MEDIUM RISK** - Persistent tracking without consent is concerning, but no browsing data is collected.

---

### 3. Remote Configuration / Hotfix System
**Severity**: LOW (Remote Code Loading Risk - Mitigated)
**Files**:
- `/background/background.js` (lines 528-660)

**Analysis**:
The extension can fetch remote "hotfix" patches from fehelper.com and apply them to tools at runtime.

**Code Evidence**:
```javascript
// Line 530: Fetch hotfix JSON
fetch("https://fehelper.com/static/js/hotfix.json?v=" + Date.now())
  .then(e => e.text())
  .then(content => {
    // Store hotfix content (CSS/JS patches)
  })

// Line 633: Version-specific patches
fetch("https://fehelper.com/v1/fh-patchs/v" + version + ".json")
  .then(e => e.json())
  .then(patches => {
    // patches.patchs = { "tool-name": { css: "...", js: "..." } }
    chrome.storage.local.set({ "FH_PATCH_HOTFIX_" + version: patches })
  })

// Line 556-570: Apply patches to tools
chrome.storage.local.get("FH_PATCH_HOTFIX_" + version, function(data) {
  if (data[toolName]) {
    callback({ css: data[toolName].css, js: data[toolName].js })
  }
})
```

**How It Works**:
1. Extension periodically checks for hotfixes at `https://fehelper.com/static/js/hotfix.json`
2. Fetches version-specific patch file (e.g., `v2025.11.2601.json`)
3. Stores patch CSS/JS in `chrome.storage.local`
4. When user opens a tool, patch JS/CSS is injected into the tool page

**Potential Risks**:
- Developer could push malicious patches to all users
- Patches bypass Chrome Web Store review process
- Could be used for emergency fixes OR silent feature changes

**Mitigations**:
- Patches stored locally, not executed directly from network response
- No `eval()` or `Function()` used to execute patch code
- Patches only affect extension's own pages (not content scripts injected into websites)
- Manifest V3 CSP prevents inline script execution
- HTTP requests use HEAD method first to check if patch exists (fail-safe)

**Verdict**: **LOW RISK** - While remote config is generally concerning, implementation is relatively safe due to MV3 CSP restrictions. Main risk is developer could silently change functionality.

---

### 4. postMessage Handlers Without Origin Validation
**Severity**: HIGH (XSS/Data Injection Risk)
**Files**:
- `/json-format/json-decode.js` (lines 37-50)
- `/json-format/content-script.js` (line 1686)

**Analysis**:
The JSON formatter tool uses `window.postMessage()` to decode URL-encoded strings via an iframe, but **does not validate message origin**.

**Code Evidence**:
```javascript
// Line 42 in json-decode.js
urlDecodeByIframe: function(encodedText, charset) {
  return new Promise(function(resolve, reject) {
    var iframe = document.createElement("iframe");
    iframe.setAttribute("id", "_urlDecode_iframe_");
    iframe.style.display = "none";
    iframe.src = "about:blank";
    document.body.appendChild(iframe);

    // NO ORIGIN CHECK HERE
    window._urlDecodeCallback = function(event) {
      resolve(event.data);  // Accepts data from ANY origin
      iframe.remove();
    };

    window.removeEventListener("message", window._urlDecodeCallback);
    window.addEventListener("message", window._urlDecodeCallback, false);

    // Line 44: Inject script tag with user-controlled data into iframe
    iframe.contentWindow.document.write(
      '<script charset="' + charset + '" src="data:text/javascript;charset=' +
      charset + ',parent.postMessage(`' + encodedText + '`)"></script>'
    );
  })
}
```

**Attack Scenario**:
1. Malicious website detects FeHelper extension is installed (via web-accessible resources)
2. Malicious site sends crafted `postMessage()` to FeHelper pages
3. Because no origin check, FeHelper accepts malicious data
4. If malicious data passed to `document.write()` in iframe, potential XSS

**Impact**:
- **Cross-Site Scripting (XSS)** via malicious postMessage
- Attacker could inject code into FeHelper tool pages
- Limited to extension's own pages (not user's websites)
- Requires user to have FeHelper tool page open

**Industry Best Practice**:
```javascript
// CORRECT implementation:
window.addEventListener("message", function(event) {
  // Validate origin
  if (event.origin !== "chrome-extension://" + chrome.runtime.id) {
    return;  // Ignore messages from other origins
  }
  // Process event.data safely
});
```

**Mitigations in Code**:
- Only used in extension's own pages (not content scripts in user websites)
- Iframe src is `about:blank` (same origin as extension page)
- Data passed through iframe, not directly executed

**Verdict**: **HIGH RISK (but low exploitability)** - Textbook security vulnerability, but attack surface is limited to extension's own pages. Attacker would need to trick user into opening FeHelper JSON formatter while on malicious site.

---

### 5. Broad Host Permissions (All URLs)
**Severity**: LOW (Overprivileged but Justified)
**Files**: `manifest.json`

**Analysis**:
```json
"host_permissions": [
  "http://*/*",
  "https://*/*",
  "file://*/*"
]
```

**Justification**:
The extension provides developer tools that work on any webpage:
- JSON auto-formatter for API responses (any domain)
- Code beautifier for any webpage
- Screenshot tool (any page)
- QR code generator (current page URL)
- Page performance timing

**Actual Usage**:
Review of content scripts shows limited injection:
- Only injects jQuery and evalCore.min.js universally
- Other tools inject content scripts on-demand via `chrome.scripting.executeScript()`
- No evidence of data harvesting from visited pages

**Data Access**:
- Extension CAN read page content via content scripts
- No evidence of sending page content to external servers
- Tools only process data when user explicitly clicks icon/context menu

**Verdict**: **LOW RISK** - While broad, permissions align with extension's purpose. Users expect developer tools to work on all sites.

---

### 6. Dynamic Code Execution Patterns
**Severity**: LOW (Benign Use Cases)
**Files**: Multiple tool pages

**Analysis**:
ext-analyzer flagged dynamic code patterns, but manual review shows these are legitimate tool features:

1. **Code Beautifier** (`/code-beautify/`): Uses jsbeautifier library to format user-pasted code
2. **JSON Formatter** (`/json-format/`): Parses and displays JSON (uses `JSON.parse()`, not `eval()`)
3. **Regex Tester** (`/regexp/`): Tests user regex patterns (sandboxed)
4. **Console/Postman Tool** (`/postman/`): Allows developers to test API calls

**No `eval()` or `Function()` of remote data detected.** All dynamic execution is on user-provided input for tool functionality.

**Verdict**: **NOT A VULNERABILITY** - Expected behavior for developer tools.

---

### 7. CSP 'unsafe-inline' for Styles
**Severity**: LOW
**Files**: `manifest.json`

**Analysis**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'self'"
}
```

**Impact**:
- Allows inline `<style>` tags and `style=` attributes in extension pages
- Does NOT allow inline `<script>` tags (script-src is 'self' only)
- Reduces XSS protection slightly, but only for CSS injection

**Justification**:
Many of FeHelper's tools dynamically generate UI with inline styles (charts, visualizations, formatted JSON).

**Verdict**: **LOW RISK** - 'unsafe-inline' for styles is much safer than for scripts. No XSS risk.

---

## False Positive Patterns Identified

| ext-analyzer Finding | Actual Purpose | False Positive? |
|---------------------|----------------|-----------------|
| 84 data exfiltration flows | Tool functionality (chart generators fetching CDN libraries, postman tool testing user APIs) | **Yes** - Most are feature implementations, not data theft |
| `fetch()` to various domains | Tools downloading dependencies (chart.js, html2canvas, etc.) or user testing APIs | **Yes** - Legitimate tool usage |
| `openTabs flows to *.src` | Screenshot tool capturing page images | **Yes** - Expected behavior |
| `extensionStorage flows to fetch` | User-configured API testing in Postman-like tool | **Yes** - User-initiated |
| `document.write()` usage | URL decoder iframe mechanism | **No** - Real vulnerability (see #4) |
| postMessage without origin check | JSON formatter IPC | **No** - Real vulnerability (see #4) |

**ext-analyzer Accuracy**: The tool correctly identified the 2 high-risk postMessage vulnerabilities, but 84/86 findings are false positives from legitimate tool features.

---

## Network Activity Analysis

### Confirmed External Endpoints

| Domain | Purpose | Data Transmitted | Frequency | Risk |
|--------|---------|------------------|-----------|------|
| `chrome.fehelper.com/api/track` | Usage analytics | User ID, tool usage, browser fingerprint | Every tool use + daily | MEDIUM |
| `api.siliconflow.cn/v1/chat/completions` | AI assistant API | User prompts, API key | User-initiated (AI tool) | MEDIUM |
| `fehelper.com/static/js/hotfix.json` | Remote hotfixes | None (download only) | Periodic check | LOW |
| `fehelper.com/v1/fh-patchs/v{version}.json` | Version-specific patches | None (download only) | On update | LOW |
| `gips0.baidu.com`, `ss3.bdstatic.com` | (In code comments/examples) | None (not actual requests) | Never | NONE |
| `t.weather.sojson.com` | (Likely example URL in tools) | None (not actual requests) | Never | NONE |
| `github.com`, `npm.org`, etc. | (Referenced in tool UIs/docs) | None | Never | NONE |

**Important**: Many domains in endpoint list are NOT contacted by the extension itself - they appear in:
- Example URLs in developer tool UIs (Postman-like interface)
- URL constants in code comments
- Third-party library source maps

**Actual Network Activity**: Only fehelper.com and api.siliconflow.cn are contacted.

---

## Data Flow Summary

### Data Sent to External Servers

**To chrome.fehelper.com**:
- ✅ Persistent user tracking ID (e.g., "fh_1739564800_a7s3k9d2x")
- ✅ Browser fingerprint (userAgent, language, platform)
- ✅ Extension version
- ✅ Tool usage events (which tools, when)
- ❌ No browsing history
- ❌ No visited URLs
- ❌ No page content
- ❌ No personal information

**To api.siliconflow.cn** (only if user enables AI assistant):
- ✅ User-provided prompts (may contain code, questions, debugging info)
- ✅ Hardcoded API key (authentication)
- ❌ No user identifiers
- ❌ No browsing data

### Data Stored Locally

**chrome.storage.local**:
- `FH_USER_ID`: Tracking ID
- `FH_LAST_ACTIVE_DATE`: Last usage date
- `FH_USER_USAGE_DATA`: Tool usage statistics
- `FH_PATCH_HOTFIX_{version}`: Remote patches (CSS/JS)
- Tool-specific settings (JSON formatter preferences, etc.)

**No sensitive data collection detected.**

---

## Permission Analysis

| Permission | Justification | Risk Level | Used Appropriately? |
|------------|---------------|------------|---------------------|
| `tabs` | Required for context menus, tool injection | Medium | ✅ Yes |
| `scripting` | Inject content scripts for tools | Medium | ✅ Yes |
| `contextMenus` | Right-click menu for tools | Low | ✅ Yes |
| `activeTab` | Access current tab when user clicks icon | Low | ✅ Yes |
| `storage` | Save tool settings | Low | ✅ Yes |
| `notifications` | Chrome notifications (unused?) | Low | ⚠️ Declared but not used |
| `unlimitedStorage` | Large tool data (e.g., screenshots) | Low | ✅ Yes |
| `host_permissions: <all_urls>` | Tools work on any webpage | High | ✅ Yes (justified) |
| `optional: downloads` | Download generated files (QR codes, etc.) | Low | ✅ Yes |

**Assessment**: Permissions are broad but justified for a comprehensive developer toolset. No evidence of permission abuse.

---

## Code Quality Observations

### Positive Indicators
1. ✅ No extension enumeration or killing
2. ✅ No XHR/fetch hooking or monkey-patching
3. ✅ No residential proxy infrastructure
4. ✅ No hidden cryptocurrency miners
5. ✅ No ad/coupon injection
6. ✅ No cookie harvesting
7. ✅ Clean separation of concerns (modular tool architecture)
8. ✅ Manifest V3 (modern standard)
9. ✅ No eval() of remote code

### Negative Indicators
1. ❌ Hardcoded API key (security/cost abuse risk)
2. ❌ Persistent user tracking without consent UI
3. ❌ postMessage without origin validation (XSS risk)
4. ❌ Remote config system (silent updates)
5. ⚠️ Chinese comments/strings (not inherently bad, but notable for privacy concerns)

### Obfuscation Level
**Minimal** - Code is minified (standard build process) but not deliberately obfuscated. Function logic is readable after beautification.

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ⚠️ Partial | Collects user AI prompts (but only for AI feature, not chatGPT scraping) |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Remote code loading | ⚠️ Yes | Hotfix system (see #3) |
| Cookie harvesting | ✗ No | No cookie access |
| GA/analytics proxy bypass | ✗ No | No analytics manipulation |
| Hidden data exfiltration | ⚠️ Partial | Usage analytics (see #2) |
| Cryptocurrency mining | ✗ No | No miner code |

---

## Privacy Impact Assessment

**MEDIUM PRIVACY IMPACT**

### What FeHelper Knows About You:
1. ✅ When you use the extension (daily active tracking)
2. ✅ Which tools you use (JSON formatter, QR code, etc.)
3. ✅ Your browser fingerprint (userAgent, language, platform)
4. ✅ AI prompts you submit (if using AI assistant)
5. ❌ **NOT** your browsing history
6. ❌ **NOT** websites you visit
7. ❌ **NOT** page content (unless you explicitly paste into a tool)
8. ❌ **NOT** your personal information (name, email, etc.)

### Third-Party Data Sharing:
- **fehelper.com**: Receives usage analytics
- **api.siliconflow.cn**: Receives AI prompts (user-initiated)
- No other third parties

### User Control:
- ❌ No opt-out for analytics
- ⚠️ AI assistant is optional (user must enable)
- ✅ Can disable extension entirely
- ❌ No data deletion mechanism

---

## Recommendations

### For Users:
1. **Use with awareness** - This is a legitimate tool, but be aware of analytics
2. **Avoid pasting sensitive data into AI assistant** - Prompts sent to Chinese AI service
3. **Consider alternatives** if privacy is critical:
   - JSONView (no analytics)
   - Built-in browser DevTools
   - Standalone formatters

### For Developer (fehelper.com):
1. **Add analytics consent** - Let users opt-out of telemetry
2. **Remove hardcoded API key** - Require users to provide their own SiliconFlow key
3. **Fix postMessage vulnerability** - Add origin validation (see #4)
4. **Disclose data practices** - Add privacy policy link in extension
5. **Add data deletion** - Allow users to request tracking data removal

### For Chrome Web Store:
1. Request disclosure of analytics/AI service in description
2. Verify hotfix system doesn't bypass review process

---

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Justification**:
- **Legitimate extension** providing real value to 200K+ developers
- **No malicious intent** detected
- **Privacy concerns** due to persistent tracking and AI service integration
- **Security vulnerabilities** (postMessage without origin check)
- **Transparency issues** (no consent dialog, undisclosed data collection)

### Breakdown:
- **Functionality**: ✅ Works as advertised (developer toolset)
- **Malicious Behavior**: ✅ None detected
- **Privacy**: ⚠️ Tracks usage without consent
- **Security**: ⚠️ Has vulnerabilities (postMessage, hardcoded key)
- **Transparency**: ❌ No privacy policy or data disclosure

---

## Technical Summary

**Lines of Code**: ~50,000+ (deobfuscated, across 146 files)
**External Dependencies**: jQuery 3.3.1, Chart.js, html2canvas, SheetJS, Vue.js, jszip, Prism
**Third-Party APIs**: SiliconFlow (ai.siliconflow.cn)
**Remote Code Loading**: Hotfix system (JSON patches)
**Dynamic Code Execution**: Tool features only (JSON.parse, beautifiers)

---

## Conclusion

FeHelper is a **legitimate, feature-rich developer tools extension** with **MEDIUM risk** due to privacy practices rather than malicious behavior. The extension provides genuine value (JSON formatting, code beautification, 30+ tools) but collects usage analytics without user consent and includes an AI assistant powered by a third-party Chinese service with a hardcoded API key.

**The 86 HIGH findings from ext-analyzer are largely false positives** - they flag legitimate tool functionality (chart generators, API testing tools) as potential data exfiltration. Manual analysis confirms only **2 real vulnerabilities** (postMessage without origin validation) and **2 privacy concerns** (analytics tracking, AI API key).

**Recommendation**: **SAFE FOR USE** with awareness of privacy trade-offs. Users comfortable with usage analytics can use FeHelper confidently. Privacy-conscious developers should consider alternatives or disable the AI assistant feature. Not recommended for analyzing sensitive/proprietary code due to AI service.

**Final Verdict: MEDIUM** - Legitimate extension, privacy concerns, no malicious behavior detected.

---

## Appendix: Decoded Secrets

**SiliconFlow API Key** (base64 in code):
```
Encoded: c2stamJ5eGlldmVmdmhnbnBnbGF3cmxlZ25uam9rY25kc3BpYndjZmh1d2Ntbm9jbmxp
Decoded: sjkjbyxievefvhgnpglawrlegnnjokndspibwcfhuwcmnocnli
```

This key grants access to SiliconFlow's Qwen/Qwen2.5-Coder-7B-Instruct model and could be extracted and abused by malicious actors for free API quota.
