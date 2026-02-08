# Security Analysis Report: EndNote Click

## Extension Metadata
- **Extension Name**: EndNote Click
- **Extension ID**: fjgncogppolhfdpijihbpfmeohpaadpc
- **Version**: 3.5.0
- **User Count**: ~4,000,000
- **Manifest Version**: 3
- **Developer**: EndNote/Clarivate Analytics (https://click.endnote.com)

## Executive Summary

EndNote Click is a legitimate academic research tool developed by Clarivate Analytics that provides one-click access to research paper PDFs. The extension employs broad permissions for its core functionality of finding and accessing academic papers across publisher websites. While the extension exhibits invasive capabilities including host access to all URLs, network request modification, and comprehensive analytics tracking, these features align with its stated purpose as an academic paper discovery and access tool.

**Overall Risk Level**: **CLEAN**

The extension demonstrates professional development practices, serves its intended purpose transparently, and does not exhibit malicious behavior patterns. However, users should be aware of extensive data collection practices through Snowplow analytics.

## Detailed Analysis

### 1. Manifest Permissions Analysis

#### Requested Permissions
- `storage` - For caching user preferences, research items, PDF metadata
- `webNavigation` - To detect navigation to academic paper pages
- `declarativeNetRequest` - To modify HTTP headers for institutional access
- `declarativeNetRequestWithHostAccess` - Enhanced header modification capabilities
- `<all_urls>` (host permissions) - Required to access academic content across all publisher domains

#### Optional Permissions
- `downloads` - For downloading PDF files
- `downloads.open` - For opening downloaded PDFs

#### Permission Justification
All permissions are appropriate for the extension's academic paper access functionality. The `<all_urls>` permission is necessary because academic publishers span thousands of domains globally. The `declarativeNetRequest` permissions enable institutional authentication (EZProxy, Shibboleth, OpenAthens).

**Severity**: LOW (High permissions but legitimately justified)

### 2. Content Security Policy
No CSP violations detected. The extension does not define custom CSP rules, relying on manifest v3 defaults which prohibit unsafe inline scripts and remote code execution.

### 3. Background Service Worker Analysis (`9jmupub.js`)

#### Legitimate Functionality Detected
- **DOI Detection**: Identifies Digital Object Identifiers in academic papers using standard regex patterns
- **PDF Discovery**: Searches for open access and publisher PDFs via multiple routes:
  - Unpaywall API for open access content
  - Crossref API for bibliographic metadata
  - Direct publisher integration (200+ providers in `simplifiedProviders.json`)
- **Institutional Authentication**: Supports EZProxy, Shibboleth, SAML2, OpenAthens authentication protocols
- **Reference Management**: Downloads PDFs and exports citations to EndNote

#### Chrome API Usage
```javascript
// Monitored APIs
chrome.storage.local          // User profile, research items cache
chrome.storage.sync           // Settings synchronization
chrome.runtime.sendMessage    // Content script communication
chrome.tabs.sendMessage       // Inject inline buttons
chrome.downloads.download     // PDF downloads
chrome.webNavigation.*        // Page load detection
chrome.declarativeNetRequest  // Header modification for auth
```

#### Network Communication
**Primary API Endpoints**:
1. `https://click.endnote.com` - Main service backend
   - `/api/v1/user-data` - User profile/locker sync
   - `/api/v1/unpaywall` - Open access lookup
   - `/api/v1/add-to-locker` - Save papers
   - `/api/v1/upload/generate-url-v2` - PDF upload

2. `https://malcolm.endnote.com` - Additional service endpoint (purpose unclear from code)

3. `https://api.crossref.org/works` - Public bibliographic metadata lookup

4. `https://snowplow-collector.userintel.prod.sp.aws.clarivate.net` - Analytics telemetry

**Verdict**: All network endpoints belong to legitimate Clarivate/EndNote infrastructure or public academic APIs (Crossref). No connections to suspicious third-party domains.

**Severity**: LOW (Extensive but legitimate data transmission)

### 4. Content Script Analysis (`g9nhm28jb13afdh.js`)

#### Functionality
- Injects inline "View PDF" buttons on academic publisher pages
- Detects DOIs in page content to identify papers
- Creates UI overlays for PDF access options
- Minimal DOM manipulation limited to button insertion
- Uses Google Fonts (fonts.gstatic.com) for UI styling

#### Exclusions
The manifest excludes 400+ popular domains (social media, e-commerce, banking, government) from content script injection, demonstrating responsible scoping:
```
exclude_globs: facebook.com, twitter.com, youtube.com, amazon.com,
               github.com, google.com, linkedin.com, etc.
```

**Verdict**: Content script is narrowly scoped to academic/research contexts and does not exhibit data harvesting behavior.

**Severity**: CLEAN

### 5. Cross-Site Communication (`tj9s5fs.js`)

This script runs on `click.endnote.com` and `kopernio.com` domains only. It implements a secure postMessage bridge for communication between the extension and the EndNote web application.

```javascript
window.addEventListener("message", (msg) => {
  const {origin} = msg;
  const {name, detail} = msg.data;
  if (["https://click.endnote.com"].includes(origin) &&
      name === "CnCanaryBridgeMessage") {
    chrome.runtime.sendMessage(detail).then((response) => {
      window.postMessage({name: "CnCanaryBridgeResponse", ...}, origin);
    });
  }
});
```

**Verdict**: Properly origin-validated. No security issues.

**Severity**: CLEAN

### 6. Analytics & Tracking

#### Snowplow Analytics Integration
The extension implements comprehensive usage tracking via Snowplow (Clarivate's analytics infrastructure):

**Configuration** (`settings.json`):
```json
{
  "ANALYTICS_ENABLED": true,
  "SNOWPLOW_URL": "https://snowplow-collector.userintel.prod.sp.aws.clarivate.net"
}
```

**Tracked Events** (from `tj9s5fs.js` message definitions):
- Extension activation/deactivation
- PDF found/not found events
- Link resolver clicks
- Locker additions/removals
- Login/logout events
- Reference exports to EndNote
- Search queries (PubMed, Google Scholar, Web of Science)
- User opt-in/opt-out for data sharing

**Privacy Considerations**:
- Users are prompted for consent: "Your EndNote Click usage data will help us identify areas where we may be missing coverage. Share your data with us to make the extension better."
- Users can opt-out via "No data sharing" option
- Analytics tracked via `StorageKeys.PrivacyOptIn`
- Tracking includes research behavior (papers accessed, searches performed)

**Verdict**: Extensive analytics collection, but user-consented and transparently disclosed. Data shared with Clarivate Analytics for service improvement.

**Severity**: MEDIUM (Privacy concern, but consensual)

### 7. Data Storage

**Local Storage Keys**:
- `researchItems` - Cached paper metadata
- `userProfile` - User account data
- `authtoken` - Authentication token for EndNote Click service
- `pdfCache` - Downloaded PDF metadata
- `wosCache` - Web of Science lookup results
- `crossrefcache` - Crossref API responses
- `selectedItems` - User-selected papers
- `privacyOptIn` - Analytics consent status

**Verdict**: Storage keys are appropriate for academic reference management. Auth tokens are stored locally (standard practice).

**Severity**: CLEAN

### 8. Cryptography Usage

The extension includes CryptoJS AES implementation for encryption purposes. Based on code analysis:
- Used for secure authentication flows with institutional proxies
- No evidence of malicious encryption/obfuscation
- Standard academic authentication protocols (Shibboleth, SAML2) require crypto

**Verdict**: Legitimate cryptographic usage for authentication.

**Severity**: CLEAN

### 9. Dynamic Code Execution

No instances of `eval()`, `Function()`, or `new Function()` detected. The code is static bundled JavaScript (likely webpack output).

**Severity**: CLEAN

### 10. Third-Party SDKs

**Identified Libraries**:
- CryptoJS (encryption)
- UUID generators (v1, v4)
- Snowplow Analytics SDK
- React/JSX (for popup UI)

All libraries are legitimate and commonly used in browser extensions.

**Severity**: CLEAN

## False Positives

| Pattern | Context | Reason for False Positive |
|---------|---------|---------------------------|
| `<all_urls>` permission | Manifest | Legitimate need to access academic papers across 1000+ publisher domains globally |
| AES encryption | CryptoJS library | Used for institutional authentication protocols (Shibboleth, SAML) |
| Extensive analytics | Snowplow tracking | User-consented data sharing for service improvement |
| Header modification | declarativeNetRequest | Required for institutional proxy authentication (EZProxy) |
| Large exclusion list | Content scripts | Actually demonstrates responsible scoping (avoiding non-academic sites) |

## API Endpoints Summary

| Endpoint | Purpose | Data Transmitted |
|----------|---------|------------------|
| `https://click.endnote.com/api/v1/user-data` | User profile sync | Auth token, user preferences |
| `https://click.endnote.com/api/v1/unpaywall` | Open access lookup | DOI of paper |
| `https://click.endnote.com/api/v1/add-to-locker` | Save papers | Paper metadata, DOI |
| `https://malcolm.endnote.com` | Backend service | Unknown (not heavily used in code) |
| `https://api.crossref.org/works` | Bibliographic data | Author names, article titles (public API) |
| `https://snowplow-collector.userintel.prod.sp.aws.clarivate.net` | Analytics | Usage events, clicks, searches |

## Data Flow Summary

1. **User visits academic paper page** → Content script detects DOI
2. **Extension queries APIs** → Checks Unpaywall, Crossref for open access
3. **Institution authentication** → Modifies headers for EZProxy/Shibboleth if configured
4. **PDF found** → Injects "View PDF" button, logs event to Snowplow
5. **User clicks button** → Downloads PDF via chrome.downloads API
6. **User exports** → Sends metadata to EndNote Cloud via click.endnote.com API
7. **Analytics** → All interactions logged to Snowplow (if user opted in)

## Vulnerabilities Identified

**None**. No security vulnerabilities or malicious patterns detected.

## Privacy Concerns

1. **Comprehensive Usage Tracking**: The extension tracks all research activities including:
   - Papers accessed
   - Search queries entered
   - PDF downloads
   - Institution library usage

   **Mitigation**: Users are prompted for consent and can opt-out.

2. **Third-Party Analytics Provider**: Data shared with Clarivate Analytics via AWS infrastructure.

   **Mitigation**: Disclosed in privacy policy (https://click.endnote.com/privacy).

## Recommendations

### For Users
1. Review and understand the analytics opt-in prompt
2. If privacy-sensitive, choose "No data sharing" option
3. Be aware that all paper access is logged (when opted in)
4. Extension requires broad permissions by nature of academic publishing landscape

### For Developers
1. Consider more granular analytics opt-in (e.g., disable specific event types)
2. Implement local-only mode for maximum privacy
3. Provide transparency dashboard showing what data was collected
4. Consider open-sourcing to build trust in academic community

## Comparison with Malicious Patterns

| Malicious Pattern | EndNote Click Behavior | Verdict |
|-------------------|------------------------|---------|
| Cookie theft | No cookie access detected | ✓ CLEAN |
| Credential harvesting | Only collects EndNote login (its own service) | ✓ CLEAN |
| Ad injection | No ad-related code | ✓ CLEAN |
| Affiliate hijacking | No affiliate link manipulation | ✓ CLEAN |
| Extension killing | No extension enumeration or interference | ✓ CLEAN |
| XHR/fetch hooking | No request interception beyond auth headers | ✓ CLEAN |
| Proxy infrastructure | No residential proxy behavior | ✓ CLEAN |
| Remote code loading | No dynamic script fetching | ✓ CLEAN |
| Market intelligence SDKs | No Sensor Tower, Pathmatics, etc. | ✓ CLEAN |
| Obfuscation | Standard webpack bundling only | ✓ CLEAN |

## Conclusion

EndNote Click is a **legitimate academic research tool** developed by a reputable company (Clarivate Analytics). While it employs broad permissions and comprehensive analytics tracking, these capabilities are transparently disclosed and serve the extension's stated purpose of providing academic PDF access.

The extension does not exhibit any malicious behavior patterns such as:
- Data theft (cookies, passwords, form data)
- Ad/coupon injection
- Extension interference or killing
- Hidden network exfiltration
- Code obfuscation or anti-debugging

**Privacy-conscious users** should be aware that usage data (papers accessed, searches performed) is shared with Clarivate when analytics are enabled, though this is opt-in and consentual.

**Overall Risk Assessment**: **CLEAN**

The extension is safe for use by academic researchers, students, and institutional users. It serves its intended purpose without malicious side effects.

---

**Analysis Date**: 2026-02-08
**Analyst**: Claude Sonnet 4.5
**Analysis Method**: Static code analysis + manifest review + network endpoint verification
