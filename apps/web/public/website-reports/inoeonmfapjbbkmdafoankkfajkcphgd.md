# Security Analysis Report: Read&Write for Google Chrome

## Extension Metadata
- **Extension Name**: Read&Write for Google Chrome™
- **Extension ID**: inoeonmfapjbbkmdafoankkfajkcphgd
- **Version**: 2.1.770
- **User Count**: ~18,000,000
- **Developer**: Texthelp Ltd.
- **Manifest Version**: 3

## Executive Summary

Read&Write for Google Chrome is a legitimate assistive technology tool developed by Texthelp Ltd. that provides reading and writing support features for students and professionals with learning disabilities. The extension requests extensive permissions and has broad access to all websites, which is necessary for its intended functionality of providing text-to-speech, dictation, translation, and document editing assistance across the web.

**Overall Risk Assessment: CLEAN**

While the extension requires invasive permissions and has access to sensitive user data (Google Drive files, email, browsing activity), this is justified by its core functionality as an accessibility tool. The extension communicates with legitimate Texthelp services for features like licensing, text-to-speech, translation, and grammar checking. No evidence of malicious behavior, data exfiltration, or privacy violations was found.

## Permissions Analysis

### Requested Permissions
```json
[
  "activeTab",
  "contextMenus",
  "storage",
  "tabs",
  "identity",
  "identity.email",
  "scripting",
  "management",
  "offscreen",
  "search",
  "alarms",
  "gcm",
  "downloads"
]
```

### Host Permissions
- `<all_urls>` - Required for providing reading/writing assistance on any webpage

### OAuth2 Scopes
```
- https://www.googleapis.com/auth/userinfo.email
- https://www.googleapis.com/auth/userinfo.profile
- https://www.googleapis.com/auth/drive.file
- https://www.googleapis.com/auth/drive.install
- https://www.googleapis.com/auth/drive.appdata
- https://www.googleapis.com/auth/drive.appfolder
```

**Assessment**: OAuth scopes are appropriate for Google Drive integration, allowing users to save/load documents created with Read&Write features. The `identity.email` permission is used for user authentication and license validation.

## Vulnerability & Security Findings

### No Critical or High Severity Issues Found

After comprehensive analysis of the codebase, no vulnerabilities, malicious code, or security issues were identified.

### Content Security Policy
```json
{
  "extension_pages": "script-src 'self'; object-src 'self';",
  "sandbox": "sandbox allow-scripts allow-forms allow-popups allow-modals; script-src 'self' 'unsafe-inline' 'unsafe-eval'; child-src 'self';"
}
```

**Assessment**: Strong CSP for extension pages. Sandbox allows `unsafe-eval` which is appropriate for sandboxed contexts running user-generated content like the rewordify feature.

### Dynamic Code Analysis
- No use of `eval()` or `new Function()` in main extension context
- DOMPurify library (v3.3.0) is included for sanitizing user content
- No code obfuscation detected beyond standard minification

## API Endpoints & Data Flow

### Texthelp Services
| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://licensing.texthelp.com/` | License validation | User email, license key |
| `https://ist.texthelp.com/queue/licen*` | License service queue | License data |
| `https://rwgoogle-webservices-7.texthelp.com/v1.11.0/*` | Dictionary, prediction, translation services | Text snippets for processing |
| `https://rwgoogle-webservices-eu.texthelp.com/v1.11.0/*` | EU region web services | Text snippets for processing |
| `https://speech.speechstream.net/` | Text-to-speech service | Text content for speech synthesis |
| `https://speech-eu-rwgoogle.speechstream.net/` | EU TTS service | Text content for speech synthesis |
| `https://rwforgoogle-checkit.texthelp.com/check2` | Grammar/spell checking | Document text |
| `https://idp.texthelp.com/oauth2` | Identity provider OAuth | Authentication tokens |
| `https://pra.texthelp.com/` | Practice Reading Aloud feature | Audio recordings for analysis |
| `https://orbit.texthelp.com/v2/viewer*` | Orbit Note integration | Note content |
| `https://rw4gc-simplify.texthelp.com/` | Page simplification service | Webpage content |

### Google Services
| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://www.googleapis.com/drive/v3/file*` | Google Drive integration | Documents created/edited |
| `https://www.googleapis.com/auth/*` | OAuth authentication | Auth tokens |
| `https://docs.google.com/document/*` | Google Docs integration | In-page interactions |
| `https://www.google-analytics.com/mp/collect` | Usage analytics | Anonymous usage metrics |
| `https://graph.microsoft.com/v1.0/me/drive/*` | OneDrive integration | Documents (Microsoft accounts) |

### Third-Party Services
| Endpoint | Purpose |
|----------|---------|
| `https://textcheck.everway.com:443/` | Text checking service |
| `https://services.lingapps.dk/prediction/` | Prediction service |

## Data Flow Summary

1. **Authentication Flow**: User authenticates via Google OAuth → Extension receives token → Token sent to Texthelp licensing service
2. **Text Processing**: User selects text → Text sent to Texthelp web services (dictionary/TTS/translation) → Response rendered in UI
3. **Document Storage**: User creates document → Saved to Google Drive via Google APIs (with user consent)
4. **Analytics**: Usage events → Google Analytics (session tracking, feature usage)

**Privacy Assessment**: All data transmission is to legitimate first-party (Texthelp) or user-authorized third-party services (Google Drive). No evidence of unauthorized data collection or exfiltration.

## False Positive Analysis

| Pattern | Location | Verdict |
|---------|----------|---------|
| DOMPurify `innerHTML` usage | google-docs-integration.js, pra.content.js | **False Positive** - DOMPurify is a security library for sanitizing HTML |
| Google Analytics tracking | serviceworker.bundle.js | **Expected** - Standard usage analytics for legitimate extension |
| Chrome storage API usage | All bundles | **Expected** - Storing user preferences and settings |
| `chrome.windows.getAll()` | serviceworker.bundle.js | **Expected** - Used to clear analytics session when all windows close |
| OAuth token handling | serviceworker.bundle.js | **Expected** - Legitimate Google/Microsoft authentication |
| `chrome.management` permission | manifest.json | **Low Risk** - No actual enumeration/killing of other extensions detected in code |

## Content Scripts Analysis

### Injection Scope
The extension injects content scripts into `<all_urls>` with multiple run times:
- `document_start` - For early initialization
- `document_idle` - For main toolbar injection
- `document_end` - For voice note watcher

### Content Script Functions
1. **frame.bundle.js** - Main toolbar UI and feature activation
2. **content.error.js** - Error logging to background service worker
3. **google-docs-preloader.js** - Google Docs integration setup
4. **domdistiller.js** - Page simplification/reading mode
5. **startup.bundle.js** - Extension initialization
6. **voicenotewatcher.bundle.js** - Voice note feature handler

**Assessment**: Content scripts serve legitimate accessibility functions. No DOM manipulation for ad injection, no keystroke logging outside of legitimate dictation features, no cookie harvesting.

## Background Service Worker Analysis

The service worker (`serviceworker.bundle.js`, 290 lines) handles:
- License validation and authentication
- Message passing between content scripts and extension
- Google Drive file operations
- Push notifications via GCM (for feature updates)
- Usage analytics
- Chrome storage management

**Assessment**: Standard background service worker pattern. No malicious network interception, no unauthorized API calls, no proxy infrastructure.

## Manifest Version 3 Compliance

Extension properly migrated to Manifest V3:
- Uses service worker instead of background page
- Declarative content scripts
- Proper host permissions
- No remotely hosted code

## Enterprise Configuration

The extension includes `preferences_schema.json` for enterprise/education deployment with managed policies:
- Account type selection (Google/Microsoft)
- Feature toggles for individual tools
- Voice/TTS settings
- Theme preferences

This is appropriate for educational software deployed at scale.

## Overall Risk Assessment

**Risk Level: CLEAN**

### Justification
1. **Legitimate Purpose**: Well-established assistive technology with 18M users
2. **Appropriate Permissions**: All permissions are necessary for stated functionality
3. **No Malicious Patterns**: No evidence of:
   - Extension enumeration/killing
   - Cookie harvesting
   - Keystroke logging (except in dictation context)
   - Ad/coupon injection
   - Residential proxy infrastructure
   - Market intelligence SDKs
   - AI conversation scraping
   - Unauthorized data exfiltration
4. **Transparent Data Usage**: Data sent to Texthelp services for legitimate features (TTS, translation, grammar checking)
5. **Strong Security Practices**: Uses DOMPurify for sanitization, proper CSP, no eval()
6. **Enterprise Support**: Managed policy schema for institutional deployment

### Privacy Considerations
While the extension is clean from a security perspective, users should be aware:
- Text content is sent to Texthelp servers for processing (TTS, translation, grammar)
- Google Drive integration requires OAuth access to user files
- Usage analytics collected via Google Analytics
- These are disclosed in privacy policy and necessary for core features

## Recommendations

**For Users:**
- Extension is safe to use as intended
- Review OAuth permissions when connecting Google/Microsoft accounts
- Understand that text sent through features (TTS, translation) is processed on Texthelp servers

**For Administrators:**
- Extension is appropriate for educational/enterprise deployment
- Use managed policies to control feature availability
- Review privacy policy for compliance with institutional data policies

## Conclusion

Read&Write for Google Chrome is a legitimate, well-maintained assistive technology extension with no security vulnerabilities or malicious behavior. The extensive permissions are justified by its comprehensive accessibility features. While it handles sensitive user data (documents, browsing activity), this is transparently disclosed and necessary for its intended purpose. The extension follows security best practices and is safe for its 18 million users.

---

**Analysis Date**: 2026-02-08
**Analyst**: Claude Sonnet 4.5
**Analysis Methodology**: Static code analysis, manifest review, API endpoint mapping, data flow analysis
