# Security Analysis Report: YouTube Summary with ChatGPT & Claude

## Extension Metadata
- **Extension ID**: nmmicjeknamkfloonkhhcjmomieiodli
- **Name**: YouTube Summary with ChatGPT & Claude
- **Version**: 2.0.23
- **Users**: 1,000,000+
- **Manifest Version**: 3
- **Permissions**: storage
- **Content Script Matches**: `<all_urls>`, YouTube, ChatGPT, Claude, Gemini, Mistral AI, Grok, AI Studio, glasp.co, glasp.ai

## Executive Summary

**Risk Level: MEDIUM**

YouTube Summary with ChatGPT & Claude is a legitimate productivity extension that summarizes YouTube videos, web articles, and PDFs using various AI services (ChatGPT, Claude, Gemini, Mistral AI, Grok). While the extension serves its advertised purpose, it exhibits several security concerns including hardcoded Firebase API keys, reliance on third-party backend infrastructure (glasp.co/glasp.ai), and broad content script access across all URLs.

The extension does not appear to be malicious, but the presence of hardcoded credentials and extensive web access presents potential security risks for users. The extension communicates with Firebase backend services and appears to collect usage telemetry.

---

## Vulnerability Details

### 1. Hardcoded Firebase API Keys (MEDIUM)

**Severity**: Medium
**Category**: Hardcoded Credentials
**Location**: `assets/firebase-997f25e3.js`

The extension contains hardcoded Firebase configuration credentials embedded in the client-side code:

```javascript
const yg={
  apiKey:"AIzaSyCAdXVRjHTtC1MqWEioaH8nZ9t-e6EMM5A",
  authDomain:"auth.glasp.co",
  databaseURL:"https://driven-current-285910.firebaseio.com",
  projectId:"driven-current-285910",
  storageBucket:"glasp_images",
  messagingSenderId:"843827296791",
  appId:"1:843827296791:web:6bc729caeb6e531701fa52",
  measurementId:"G-Z2FG8Y72WK"
}
```

**Risk Assessment**:
- Firebase API keys in client-side code are accessible to anyone who inspects the extension
- While Firebase has security rules, exposed API keys can potentially be abused if security rules are misconfigured
- The project ID "driven-current-285910" and database URL are exposed
- API key could be extracted and used in unauthorized contexts

**Recommendation**: While this is a common pattern in web applications, sensitive operations should be protected by Firebase security rules rather than relying on API key secrecy alone.

---

### 2. Third-Party Backend Dependency (MEDIUM)

**Severity**: Medium
**Category**: Third-Party Backend Communication
**Affected Components**: Service worker, content scripts

The extension relies heavily on third-party backend services (glasp.co and glasp.ai) for core functionality:

```javascript
// From index.ts-a17128e1.js (service worker)
case"send_glasp_log":{
  const{data:r}=e;
  q({data:r});
  break
}
case"get_yt_scripts":
  return W({title:(e==null?void 0:e.title)??"",
           videoId:(e==null?void 0:e.videoId)??"",
           vssId:(e==null?void 0:e.vssId)??""}).then(r=>{a(r)}),!0
case"summarize_on_page":
  return z({prompt:e.prompt,title:e.title,thumbnail:e.thumbnail,
           url:e.url,retry:e.retry,
           transcripts:(e==null?void 0:e.transcripts)??[]}).then(r=>{a(r)}),!0
```

**Risk Assessment**:
- User data (video titles, URLs, transcripts, prompts) is sent to glasp.co/glasp.ai backend
- Extension functionality is entirely dependent on third-party infrastructure
- No indication of end-to-end encryption for transmitted data
- Users must trust the glasp.co service operator with their browsing data and AI interactions
- Telemetry collection via "send_glasp_log" with unclear scope

**Data Transmitted**:
- YouTube video titles and IDs
- Page URLs and titles
- User-generated prompts
- Video transcripts
- Usage telemetry

**Recommendation**: Users should review glasp.co's privacy policy to understand data retention and usage practices.

---

### 3. Broad Content Script Injection (LOW)

**Severity**: Low
**Category**: Excessive Permissions
**Affected Components**: Content scripts

The extension injects content scripts on `<all_urls>` to provide summarization functionality on any webpage:

```json
{
  "js": ["assets/web-helper.ts-loader-034b3e82.js"],
  "matches": ["<all_urls>"],
  "run_at": "document_idle",
  "all_frames": false
}
```

**Functionality Analysis**:
The web-helper script provides:
- Floating summarization button on all pages
- Keyboard shortcut detection (Ctrl+X pressed twice)
- OAuth/authentication page detection (to avoid injecting on login pages)
- Access to page content for summarization

**Code Evidence**:
```javascript
// OAuth page detection to avoid interfering with login flows
const Q=()=>{
  const e=[
    /accounts\.google\.com\/o\/oauth2/,
    /appleid\.apple\.com\/auth/,
    /login\.microsoftonline\.com/,
    /github\.com\/login\/oauth/,
    // ... extensive list of OAuth patterns
  ]
  // Checks URL patterns, query parameters, and meta tags
  // to detect authentication pages
}
```

**Risk Assessment**:
- While the extension has broad page access, it appears to use it legitimately for summarization
- The extension explicitly avoids interfering with OAuth/authentication flows
- Content script extracts page content and sends to backend for summarization
- No evidence of malicious data harvesting or credential theft

**Mitigation**: The extension includes safeguards to avoid injecting on authentication pages, reducing credential theft risk.

---

## Network Analysis

### External Endpoints Contacted

1. **glasp.co / glasp.ai** (Primary Backend)
   - Purpose: AI summarization API, user authentication, premium status checks
   - Data sent: Page content, URLs, titles, transcripts, user prompts
   - Authentication: Firebase Auth

2. **firebaseio.com / firebaseapp.com / googleapis.com**
   - Purpose: Firebase Realtime Database, Firestore, Authentication
   - Data sent: User authentication tokens, subscription status
   - Project: driven-current-285910

3. **YouTube.com**
   - Purpose: Video transcript extraction (legitimate functionality)

4. **ChatGPT, Claude, Gemini, Mistral AI, Grok, AI Studio**
   - Purpose: Content script injection to enable AI integration features
   - No direct network requests; operates within these pages only

### Firebase Services Used
- Firebase Authentication (`signInWithCustomToken`)
- Firestore Database (subscription management: `stripe_customers/{uid}/subscriptions`)
- Firebase callable functions for backend operations

---

## Permission Analysis

### Declared Permissions
- **storage**: Used for caching user configuration and preferences (LRU cache with 24-hour TTL)

### Content Script Access
The extension has the following content script access:
- `<all_urls>`: Full access to all web pages for summarization widget
- Specific AI service domains: ChatGPT, Claude, Gemini, Mistral AI, Grok, AI Studio
- glasp.co/glasp.ai: Integration with backend service
- YouTube: Video transcript extraction

### Web Accessible Resources
The extension exposes resources to web pages, which could potentially be fingerprinted:
- PDF worker: `src/utils/pdf/pdf.worker.min.mjs`
- React components and utilities
- Firebase integration code

**Fingerprinting Risk**: Web accessible resources can be probed by websites to detect extension presence, though this is common for extensions requiring page integration.

---

## Code Quality and Security Practices

### Positive Observations
1. **Manifest V3**: Uses modern, more secure manifest version
2. **CSP**: Has Content Security Policy: `script-src 'self'; object-src 'self'`
3. **OAuth Detection**: Actively avoids interfering with authentication flows
4. **Limited Permissions**: Only requests `storage` permission (no tabs, history, etc.)
5. **Premium Checks**: Implements server-side premium user verification via Firebase

### Security Concerns
1. **Hardcoded Credentials**: Firebase API keys embedded in client code
2. **Third-Party Dependency**: Heavy reliance on glasp.co backend infrastructure
3. **Data Transmission**: Page content and URLs sent to third-party servers
4. **No Source Maps**: Minified code makes auditing difficult (though source is TypeScript-based)

---

## Static Analysis Results

**ext-analyzer Output**:
```
EXFILTRATION (1 flow):
  [HIGH] document.getElementById → fetch(github.com)    assets/youtube-helper.ts-9d097084.js
```

**Analysis**: The flagged "exfiltration" flow is a false positive. Investigation reveals this is part of library license headers (JSZip, markdown-to-jsx) containing GitHub repository URLs, not actual network requests. The file contains bundled third-party libraries with embedded documentation references.

**Verification**:
```javascript
// License headers in youtube-helper.ts-9d097084.js
JSZip v3.10.1 - A JavaScript class for generating and reading zip files
<http://stuartk.com/jszip>
Dual licenced under the MIT license or GPLv3.
See https://raw.github.com/Stuk/jszip/main/LICENSE.markdown.
```

No actual `fetch(github.com)` network call exists in the code.

---

## Risk Assessment

### Overall Risk: MEDIUM

**Critical Issues**: 0
**High Issues**: 0
**Medium Issues**: 2
- Hardcoded Firebase credentials
- Third-party backend data transmission

**Low Issues**: 1
- Broad content script access

### User Recommendations

**Safe to Use If**:
1. You trust glasp.co/glasp.ai with your browsing data
2. You understand that page content and URLs are sent to third-party servers for AI processing
3. You are comfortable with Firebase-based authentication
4. You accept the privacy implications of cloud-based summarization

**Exercise Caution If**:
1. You work with sensitive/confidential information
2. You are concerned about data being sent to third-party services
3. You require offline functionality
4. You need guarantees about data retention and deletion

### Developer Recommendations

1. **API Key Management**: Consider implementing Firebase App Check to limit API key abuse
2. **Privacy Transparency**: Clearly document what data is sent to backend services
3. **Data Encryption**: Implement end-to-end encryption for sensitive user data
4. **Reduce Surface Area**: Consider optional content script injection instead of `<all_urls>`
5. **Security Audit**: Regular third-party security audits for backend infrastructure

---

## Conclusion

YouTube Summary with ChatGPT & Claude is a **legitimate productivity extension** that performs as advertised. The MEDIUM risk rating stems from architectural decisions (hardcoded credentials, third-party backend dependency) rather than malicious behavior. The extension is suitable for general use but may not be appropriate for users with strict privacy requirements or those working with confidential information.

The developer (glasp.co) appears to operate a legitimate service with integration across multiple AI platforms. However, users should be aware that their summarization requests and page content are processed by third-party servers, not locally.

**Final Verdict**: Safe for general use with informed consent about data sharing practices.
