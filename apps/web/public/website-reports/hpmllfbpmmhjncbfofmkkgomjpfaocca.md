# Security Analysis Report: AutoTDK - SEO Search Keyword Tool

## Extension Metadata
- **Extension ID**: hpmllfbpmmhjncbfofmkkgomjpfaocca
- **Extension Name**: AutoTDK - SEO Search Keyword Tool (SeoStack)
- **Version**: 1.2.5
- **User Count**: ~40,000
- **Manifest Version**: 3

## Executive Summary

AutoTDK is an SEO analysis tool that provides keyword research, traffic analysis, and AI content detection features. The extension has **invasive permissions** and **sends page content to third-party servers**, but appears to serve its stated SEO functionality. The primary concerns are **data collection scope** and **third-party data transmission** without explicit user disclosure of what text content is being sent.

**Risk Level: MEDIUM**

The extension collects and transmits website content to autotdk.com servers for AI detection features, operates on all URLs via content scripts, and has access to cookies on major e-commerce/search platforms. While behavior aligns with SEO tool functionality, the broad permissions and data transmission practices raise privacy concerns.

## Vulnerability Analysis

### 1. Overly Broad Permissions - MEDIUM Severity

**Evidence:**
```json
"permissions": ["cookies", "storage"],
"content_scripts": [{
  "matches": ["<all_urls>"],
  "run_at": "document_end"
}],
"host_permissions": [
  "*://*.google.com/*",
  "*://*.duckduckgo.com/*",
  "*://*.bing.com/*",
  "*://*.pinterest.com/*",
  "*://*.yahoo.com/*",
  "*://*.amazon.com/*",
  "*://*.amazon.co.uk/*",
  "*://*.amazon.co.jp/*",
  "*://*.amazon.cn/*",
  "*://*.ebaystatic.com/*",
  "*://*.aliexpress.com/*",
  "*://*.sellercenter.io/*"
]
```

**Files**: `/deobfuscated/manifest.json`

**Analysis**:
- Content script runs on ALL URLs (`<all_urls>`) - extremely broad scope
- Cookie access to major search engines and e-commerce platforms
- Host permissions target major e-commerce sites (Amazon variants, eBay, AliExpress, seller platforms)

**Verdict**: This is typical for an SEO tool that needs to inject analysis UI on any page, but represents significant attack surface. Cookie access to e-commerce sites is concerning but appears unused beyond basic SEO analytics.

---

### 2. Third-Party Data Transmission - MEDIUM Severity

**Evidence:**
```javascript
// AI Detection - sends page content to remote server
else if ("ai-detector" === e.type) {
  let o = await fetch(`${t}/api/text/detect-ai?f=seo_search_keyword_tool&h=${e.host}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      source: "seo_search_keyword_tool"
    },
    body: JSON.stringify({
      text: e.content  // User-selected text content sent to autotdk.com
    })
  });
}

// Site usage tracking
else if ("recordSite" === e.type) {
  let o = await fetch(`${t}/api/text/init?o=${e.o}&p=${e.p}`);
  // Records origin and pathname to local storage, syncs with server
}
```

**Files**: `/deobfuscated/background.js` (lines 171-180, 149-169)

**Analysis**:
- **AI Detector Feature**: Sends user-selected text content to `autotdk.com/api/text/detect-ai` for analysis
- **Site Tracking**: Records visited origins and pathnames, sends to `/api/text/init`
- Data sent: page text content, visited URLs (origin + path), host information
- No evidence of sending cookies, credentials, or PII beyond text content user explicitly selects for AI detection

**Verdict**: While this aligns with the extension's AI detection feature, users may not realize their selected text is transmitted to third-party servers. The site tracking is relatively benign (just URL structure), but combined with text transmission represents moderate privacy risk.

---

### 3. Authentication & User Data Handling - LOW Severity

**Evidence:**
```javascript
else if ("login" === e.type) {
  let t = await fetch(e.url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(e.info)
  });
}

else if ("userinfoByGoogle" === e.type) {
  let t = await fetch(e.url, {
    method: "get",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + (e.token || "")
    }
  });
}
```

**Files**: `/deobfuscated/background.js` (lines 131-148)

**Analysis**:
- Implements user login system (email/password)
- Google OAuth integration with Bearer token handling
- Tokens handled in memory, passed via runtime messages
- No evidence of token exfiltration or misuse

**Verdict**: Standard authentication implementation for premium features. No security issues detected.

---

### 4. Page Analysis & DOM Manipulation - LOW Severity

**Evidence:**
```javascript
const j = () => {
  let e = document.querySelector('meta[name="title"]'),
      a = document.querySelector('meta[name="description"]'),
      n = document.querySelector('meta[name="keywords"]'),
      // ... extensive meta tag collection

  // Detects Google Analytics/AdSense presence
  k.forEach((e => {
    e.src.indexOf("https://www.googletagmanager.com/gtag/js") > -1 && (v = !0),
    (e.src.indexOf("adsbygoogle") > -1 || e.src.indexOf("googlesyndication.com")) && (f = !0)
  }))
}
```

**Files**: `/deobfuscated/content/content.js` (lines 84-140)

**Analysis**:
- Reads meta tags (title, description, keywords, Open Graph tags, robots, canonical)
- Detects presence of Google Analytics and AdSense (for SEO analysis)
- Collects heading structure, images, links for SEO reporting
- Creates Shadow DOM for UI (`autotdk_ext` element)
- No evidence of content modification, ad injection, or malicious DOM manipulation

**Verdict**: Legitimate SEO analysis behavior. Read-only page scanning aligns with tool purpose.

---

### 5. Keyboard Shortcut Handler - LOW Severity

**Evidence:**
```javascript
document.addEventListener("keydown", (function(e) {
  e.ctrlKey && e.altKey && !["Ctrl", "Alt"].includes(e.key) && (
    e.preventDefault(),
    "s" === e.key && chrome.storage.local.get(["setting"], (e => {
      window.open(`https://www.similarweb.com/website/{hostname}`)
    })),
    "d" === e.key && Ed(),  // Opens extension UI
    "r" === e.key && chrome.storage.local.get(["setting"], (e => {
      window.open(`https://www.semrush.com/analytics/overview/...`)
    }))
  )
}))
```

**Files**: `/deobfuscated/content/content.js` (line 7201)

**Analysis**:
- Keyboard shortcuts for Ctrl+Alt+S (Similarweb), Ctrl+Alt+D (extension UI), Ctrl+Alt+R (Semrush)
- Only captures shortcuts, not keylogging
- Opens SEO analysis tools in new tabs

**Verdict**: Benign keyboard shortcut functionality. No keylogging behavior.

---

### 6. Unused Cookie Listener - LOW Severity

**Evidence:**
```javascript
chrome.cookies.onChanged.addListener((e => {
  "xxxx" === e.name && console.log(e)
}))
```

**Files**: `/deobfuscated/background.js` (lines 101-103)

**Analysis**:
- Listens for cookie named "xxxx" (placeholder/debug code)
- Only logs to console, doesn't exfiltrate
- Likely leftover development code

**Verdict**: Appears to be debug/leftover code. Non-functional in production. No security impact.

---

## False Positives

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| Password strings in UI | `content.js` lines 6647-6689 | Internationalized UI labels ("Please enter password", "Forgot password") - not credential harvesting |
| Google Analytics detection | `content.js` line 107 | Detects if visited site uses GA/AdSense for SEO analysis - not tracking injection |
| Authorization header | `background.js` line 145 | OAuth Bearer token for autotdk.com API - legitimate authentication |
| Vue.js framework code | `vendor.js` | Standard Vue.js framework - not obfuscation |
| Large vendor bundle | `vendor.js` (3.7MB) | Vue.js + Element UI components - standard frontend framework stack |

---

## API Endpoints & Data Flows

### External API Calls

| Endpoint | Method | Data Sent | Purpose |
|----------|--------|-----------|---------|
| `autotdk.com/api/text/detect-ai` | POST | `{text: <content>, h: <host>}` | AI-generated content detection |
| `autotdk.com/api/text/detect-status` | GET | `task_id, s (status)` | Poll AI detection results |
| `autotdk.com/api/text/init` | GET | `o=<origin>, p=<pathname>` | Track site visits (rate limiting) |
| `{origin}/sitemap.xml` | GET | None | Check if site has sitemap |
| `{origin}/robots.txt` | GET | None | Check if site has robots.txt |

### Data Collection Summary

**Collected Locally:**
- Meta tags (title, description, keywords, OG tags, canonical, robots)
- Page structure (headings, images, links, favicon)
- Google Analytics/AdSense detection status
- Visited site origins/pathnames (last 1 hour only)

**Transmitted to autotdk.com:**
- User-selected text content (for AI detection)
- Origin + pathname of visited sites
- Extension source identifier (`seo_search_keyword_tool`)

**NOT Collected:**
- Cookies (despite permission, no evidence of exfiltration)
- Credentials or form data
- Full page HTML
- User keystrokes (except Ctrl+Alt shortcuts)

---

## Overall Risk Assessment

### Risk Level: MEDIUM

**Justification:**
- **Legitimate Functionality**: All observed behavior aligns with SEO analysis tool purpose
- **Privacy Concerns**: Sends page content to third-party server for AI detection without prominent disclosure
- **Broad Permissions**: `<all_urls>` content script and e-commerce cookie access create large attack surface
- **No Malicious Behavior**: No evidence of credential theft, ad injection, extension killing, or data exfiltration beyond stated features

### Key Concerns:
1. **Text transmission**: AI detector sends user-selected text to autotdk.com without clear opt-in warning
2. **Scope creep**: Cookie permissions to Amazon/eBay appear unused but represent risk if compromised
3. **Third-party dependency**: Relies on autotdk.com API - users must trust both extension and backend

### Mitigating Factors:
- No autonomous data collection (user must activate features)
- Site tracking limited to 1-hour window with rate limiting
- Read-only page analysis (no DOM modification)
- Standard authentication patterns (no token theft)
- Clean manifest v3 implementation

---

## Recommendations

**For Users:**
- Extension appears safe for intended SEO analysis use
- Be aware: Text you submit for AI detection is sent to autotdk.com servers
- Consider limiting usage to trusted/public websites given `<all_urls>` scope

**For Developers:**
- Add prominent disclosure when AI detection sends text to servers
- Reduce host_permissions to only domains where cookie access is actually needed
- Remove unused cookie listener debug code
- Consider implementing client-side AI detection to eliminate data transmission

---

## Conclusion

AutoTDK is a **functional SEO tool with legitimate use cases** but employs **invasive permissions and third-party data transmission** that may surprise users. The extension does not exhibit malicious behavior (no credential theft, ad injection, or extension enumeration), but the combination of `<all_urls>` access, cookie permissions on e-commerce sites, and server-side text analysis warrants a **MEDIUM risk** classification due to privacy implications.

**Verdict: CLEAN with privacy concerns** - The extension serves its intended purpose without clear malicious intent, but users should be informed about data transmission practices.
