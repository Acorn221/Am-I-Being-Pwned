# Vulnerability Assessment Report

## Extension Metadata
- **Name**: ChatGPT Exporter - ChatGPT to PDF, MD, and more
- **ID**: ilmdofdhpnhffldihboadndccenlnfll
- **Version**: 3.1.0
- **Users**: ~100,000
- **Manifest Version**: 3

## Executive Summary

ChatGPT Exporter is a legitimate browser extension that allows users to export ChatGPT conversations to various formats (PDF, Markdown, JSON, CSV, text, images). The extension includes analytics tracking (PostHog) and sends user conversation data to a third-party server for PDF generation. While no critical vulnerabilities or malicious behavior were detected, the extension raises **MEDIUM** privacy concerns due to external data transmission of potentially sensitive ChatGPT conversations.

## Vulnerability Details

### 1. MEDIUM - ChatGPT Conversation Data Transmission to Third-Party Server
**Severity**: MEDIUM
**Files**: `background.js` (lines 9814-9954), `content.js` (lines 31391-31430)
**Description**: When users export conversations to PDF format, the extension sends the full conversation content (including prompts and responses) to an external API endpoint at `https://api.chatgptexporter.com/api/pdf/v10`. This occurs via a POST request in the background script.

**Code Evidence**:
```javascript
// background.js:9868
n = c.backend.pdf, // "https://api.chatgptexporter.com/api/pdf/v10"
fetch(n, {
  method: "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: JSON.stringify(t)
})

// content.js:31391-31422
chrome.runtime.sendMessage({
  cmd: "pdf",
  payload: {
    cmd: "whatever",
    payload: {
      exportInfo: {
        name: o.name,
        user: {
          name: t.userName || o.user.name,
          email: t.userEmail || o.user.email
        },
        timestamps: {...},
        lst: o.lst.map((function(e) {
          return {
            role: e.role,
            html: e.checked ? e.html : null
          }
        })),
        textdocs: o.textdocs
      }
    }
  }
})
```

**Risk**: Users' ChatGPT conversations, which may contain sensitive or proprietary information, are transmitted to a third-party server. While this appears to be the developer's legitimate infrastructure for PDF generation, users may not be aware their data leaves the browser. No evidence of HTTPS certificate pinning or server authentication beyond standard HTTPS.

**Verdict**: CONCERN - Legitimate functionality but privacy-sensitive. Users should be clearly informed that PDF export requires server-side processing.

---

### 2. MEDIUM - Comprehensive Analytics and User Tracking
**Severity**: MEDIUM
**Files**: `content.js` (lines 16933-16937, 23614-26301), `background.js` (lines 1485-1486)
**Description**: Extension integrates PostHog analytics with comprehensive tracking including:
- Session recording capabilities (with URL triggers, event triggers)
- Web vitals monitoring
- Heatmap capture
- Exception capture
- Dead click tracking
- Autocapture of DOM events
- Performance monitoring

**Code Evidence**:
```javascript
// PostHog configuration
Oc.posthog = {
  key: Ic.env.posthog_key, // "phc_fJSJJQ9NnpESidVCLhnZiWD1PJSRlSkTWmCnH5MQHdZ"
  api_host: "https://phus.chatgptexporter.com",
  ui_host: "https://us.posthog.com"
}

// Analytics event tracking
Lw("Content Button Click", {
  name: "export pdf",
  status: "success"
})
```

**Risk**: Extensive telemetry collection that may include user behavior patterns on ChatGPT. PostHog session recording can capture user interactions. However, no evidence of conversation content being sent to analytics.

**Verdict**: CONCERN - Standard analytics implementation, but scope is broad. Privacy policy disclosure recommended.

---

### 3. LOW - Access to ChatGPT Backend API
**Severity**: LOW
**Files**: `content.js` (lines 31512, 31533, 33436, 33457)
**Description**: Extension makes authenticated requests to ChatGPT's internal API endpoints (`/backend-api/conversation/*`) using the user's session cookies to fetch conversation metadata and textdocs.

**Code Evidence**:
```javascript
// content.js:31512
fetch("/backend-api/conversation/".concat(o), {
  headers: {
    "chatgpt-account-id": null === (s = u.account) || void 0 === s ? void 0 : s.id
  }
})

// content.js:31533
fetch("/backend-api/conversation/".concat(o, "/textdocs"), {
  headers: {
    "chatgpt-account-id": null === (l = u.account) || void 0 === l ? void 0 : l.id
  }
})
```

**Risk**: Extension leverages ChatGPT's internal APIs, which could break if OpenAI changes their API structure. No evidence of API abuse or data exfiltration beyond export functionality.

**Verdict**: ACCEPTABLE - Necessary for functionality. Standard practice for extensions enhancing web applications.

---

### 4. LOW - Local Storage and Cookie Access
**Severity**: LOW
**Files**: `content.js` (lines 24214-24880)
**Description**: Extension accesses localStorage, sessionStorage, and cookies for its own persistence (settings, analytics state). No evidence of accessing or exfiltrating ChatGPT authentication tokens.

**Code Evidence**:
```javascript
// Standard storage operations
null == Nh || Nh.localStorage.setItem(e, JSON.stringify(t))
null == Nh || Nh.sessionStorage.getItem(e)
```

**Verdict**: ACCEPTABLE - Standard extension storage usage for settings and state management.

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `Function("r", "regeneratorRuntime = r")(n)` | Multiple files | Babel/Regenerator runtime polyfill for async/await support - standard transpilation artifact |
| `Function("return this")()` | Multiple files | Standard method to access global scope in strict mode - Webpack runtime |
| PostHog SDK hooks | content.js | Legitimate analytics SDK with expected hooking behavior |
| React `innerHTML` usage | content.js | React DOM manipulation for rendering exported content |
| `MSApp.execUnsafeLocalFunction` | Multiple files | React compatibility shim for legacy Microsoft Edge |
| Sentry error tracking patterns | background.js, content.js | Standard error reporting SDK integration |

---

## API Endpoints

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://api.chatgptexporter.com/api/pdf/v10` | PDF generation | Full conversation content, user name/email, timestamps |
| `https://apiv.chatgptexporter.com/api` | Backend API (version 2) | Unknown - not actively used in analyzed code |
| `https://phus.chatgptexporter.com` | PostHog analytics proxy | User events, session data, error logs |
| `https://us.posthog.com` | PostHog UI host | Analytics configuration |
| `/backend-api/conversation/{id}` | ChatGPT internal API | Authenticated requests for conversation data |
| `/backend-api/conversation/{id}/textdocs` | ChatGPT internal API | Authenticated requests for document attachments |
| `/api/auth/session` | ChatGPT session info | Fetches current user session details |

---

## Data Flow Summary

1. **User Interaction**: User clicks export button on ChatGPT interface
2. **Content Script**: Parses conversation DOM, extracts text/HTML content
3. **Local Processing**: For Markdown, JSON, CSV, text exports - processed locally in browser
4. **PDF Export Path**:
   - Content script sends conversation data to background script via `chrome.runtime.sendMessage`
   - Background script POSTs to `https://api.chatgptexporter.com/api/pdf/v10` with:
     - Extension ID and version
     - Customer ID (if authenticated)
     - Full conversation content (HTML)
     - User name and email
     - Timestamps
   - Server returns base64-encoded PDF
   - User downloads PDF
5. **Analytics**: PostHog tracks export events, button clicks, errors (no conversation content)
6. **Storage**: User preferences stored in chrome.storage.local

---

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
- Extension performs its advertised function legitimately
- No evidence of malicious behavior, credential theft, or unauthorized access
- Privacy concern: PDF export sends conversation content to third-party server
- Extensive analytics tracking may not be fully disclosed to users
- Minimal permissions requested (only "storage")
- Code quality appears professional with standard build tooling (Webpack, React)

**Recommendations**:
1. Clearly disclose to users that PDF export requires server-side processing
2. Provide privacy policy explaining data transmission for PDF generation
3. Consider adding option for local PDF generation (e.g., using jsPDF)
4. Disclose extent of analytics tracking in privacy policy
5. Consider implementing end-to-end encryption for PDF generation requests

**User Advisory**: This extension is safe for general use. Users exporting sensitive conversations to PDF should be aware that content is transmitted to chatgptexporter.com servers for processing. For highly sensitive conversations, use local export formats (Markdown, JSON, text) instead.
