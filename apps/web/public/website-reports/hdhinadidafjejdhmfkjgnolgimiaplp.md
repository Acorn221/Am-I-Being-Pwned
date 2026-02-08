# Security Analysis Report: Read Aloud: A Text to Speech Voice Reader

## Extension Metadata
- **Extension ID**: hdhinadidafjejdhmfkjgnolgimiaplp
- **Extension Name**: Read Aloud: A Text to Speech Voice Reader
- **Version**: 2.22.0
- **User Count**: ~6,000,000
- **Manifest Version**: 3

## Executive Summary

Read Aloud is a legitimate text-to-speech extension that provides TTS functionality for web pages, documents, and various online content platforms. The extension integrates with multiple TTS engines (browser native, Google Translate, Amazon Polly, Google Wavenet, IBM Watson, OpenAI, Azure, and custom Piper/Supertonic voices) and offers premium paid features.

**Overall Risk: CLEAN**

The extension requires extensive permissions and makes numerous network calls to third-party TTS services, which is **entirely expected and necessary** for its core functionality. All observed data collection and transmission is directly related to the TTS service delivery. No malicious behavior, data exfiltration, or security vulnerabilities were identified.

## Permissions Analysis

### Declared Permissions
```json
{
  "permissions": [
    "activeTab",      // Required to read page content for TTS
    "contextMenus",   // Adds "Read Selection" context menu
    "identity",       // OAuth for premium account login
    "offscreen",      // Audio playback in MV3
    "scripting",      // Inject content scripts for text extraction
    "storage",        // Store user settings and voice preferences
    "tts",           // Chrome TTS API
    "ttsEngine"      // Custom TTS engine support
  ],
  "optional_permissions": [
    "webRequest",     // Only for Google Wavenet auth token capture
    "webNavigation"   // Frame detection for embedded documents
  ],
  "host_permissions": [
    "https://translate.google.com/"  // Google Translate TTS
  ],
  "optional_host_permissions": [
    "http://*/",      // Required for file:// PDF access
    "https://*/",     // Required for file:// PDF access
    "file://*/*"      // Local file reading
  ]
}
```

### Permission Justification
All permissions are legitimately required for the extension's functionality:
- **activeTab/scripting**: Extract text content from web pages for reading aloud
- **identity**: OAuth login for premium voice subscriptions
- **storage**: Persist voice preferences, authentication tokens, and settings
- **tts/ttsEngine**: Use browser's native TTS and custom voice engines
- **webRequest** (optional): Capture Google Cloud TTS API tokens during Wavenet authentication flow
- **webNavigation** (optional): Detect iframes for reading Google Play Books, VitalSource textbooks, etc.

## Network Communication Analysis

### API Endpoints

| Endpoint | Purpose | Data Transmitted | Verdict |
|----------|---------|------------------|---------|
| `https://support.readaloud.app/read-aloud/speak/*` | Premium TTS synthesis | Text to speak, language, voice name, client ID, auth token | **Legitimate** - Core service |
| `https://support.readaloud.app/read-aloud/get-account` | Account balance check | Auth token | **Legitimate** - Premium features |
| `https://support.readaloud.app/read-aloud/report-issue` | Bug reporting | User settings, URL, browser info, user comment | **Legitimate** - Support feature |
| `https://support.readaloud.app/read-aloud/list-voices/*` | Fetch voice lists | None | **Legitimate** - Voice discovery |
| `https://support.readaloud.app/read-aloud/config` | Remote config | None | **Legitimate** - Feature flags |
| `https://translate.google.com/_/TranslateWebserverUi/data/batchexecute` | Google Translate TTS | Text to synthesize, language | **Legitimate** - Free TTS option |
| `https://texttospeech.googleapis.com/v1/text:synthesize` | Google Cloud TTS | Text, voice config, API key | **Legitimate** - Wavenet voices |
| `https://cxl-services.appspot.com/proxy?url=...` | Proxied Google TTS | Text, voice config, token | **Legitimate** - Token-based auth |
| `https://polly.*.amazonaws.com` | Amazon Polly TTS | Text, voice config, AWS credentials | **Legitimate** - User-provided AWS |
| `https://*.tts.speech.microsoft.com` | Azure TTS | Text, voice config, Azure credentials | **Legitimate** - User-provided Azure |
| `https://api.openai.com/v1` | OpenAI TTS | Text, voice config, API key | **Legitimate** - User-provided OpenAI |
| `https://piper.ttstool.com/` | Piper voice manager | Voice metadata | **Legitimate** - Offline voice manager |
| `https://supertonic.ttstool.com/` | Supertonic voice manager | Voice metadata | **Legitimate** - Voice manager |
| `https://readaloud.app/login.html` | OAuth login | None (webAuthFlow) | **Legitimate** - Account authentication |
| `https://assets.lsdsoftware.com/read-aloud/pdf-viewer-2/` | PDF viewer | None | **Legitimate** - PDF rendering |

### Authentication & Token Handling
- **Premium accounts**: Uses OAuth2 via `chrome.identity.launchWebAuthFlow` with legitimate redirect
- **Auth tokens**: Stored in `chrome.storage.local`, transmitted only to `support.readaloud.app` API
- **Google Wavenet**: Captures GCP API token from Google's own demo page (`cloud.google.com/text-to-speech`)
- **User-provided credentials**: AWS, Azure, IBM Watson, OpenAI API keys stored locally, never transmitted to Read Aloud servers

## Content Script Analysis

### Injection Targets
The extension injects content scripts into:
1. **Google Docs** (`https://docs.google.com/document/*`) - Extracts document text
2. **Google Play Books** (`https://books.googleusercontent.com/`) - Reads e-books
3. **OneDrive/SharePoint/Dropbox DOCX** - Reads Word documents
4. **VitalSource/Chegg textbooks** - Academic e-book readers
5. **Kindle books** (`read.amazon.com`)
6. **ChatGPT** (`chatgpt.com`) - Adds read-aloud buttons to AI responses
7. **Various e-learning platforms** (Pearson, IXL, WebNovel, etc.)

### Content Script Behavior
- **Primary function**: Extract visible text from specialized document viewers
- **No data exfiltration**: Text is sent only to TTS engines (user-initiated)
- **ChatGPT integration** (`js/content/chatgpt.js`):
  ```javascript
  for (const el of document.querySelectorAll("[data-message-author-role=assistant]")) {
    // Adds read-aloud button to ChatGPT responses
    // Calls bgPageInvoke("playText", [text]) on click
  }
  ```
  **Verdict**: Benign UI enhancement, no scraping of conversation data

## Vulnerability Assessment

### 1. Dynamic Code Execution
**Severity**: NONE
**Finding**: No use of `eval()`, `new Function()`, or dynamic script injection detected
**Verdict**: Clean

### 2. Third-Party SDK Analysis
- **RxJS 7.x**: Standard reactive programming library - **Clean**
- **jQuery 3.7.1**: DOM manipulation - **Clean**
- **PeerJS**: Used for "Use My Phone" feature (WebRTC voice sync) - **Clean**
- **AWS SDK**: User-provided credentials for Amazon Polly - **Clean**

### 3. Data Leakage
**Severity**: NONE
**Finding**: Extension transmits:
- Text content to TTS engines (user-initiated, expected)
- User settings to `support.readaloud.app` (only for premium features)
- No cookies, browsing history, or sensitive data harvested
**Verdict**: All data transmission is functional and transparent

### 4. Content Security Policy
```json
{
  "cross_origin_opener_policy": {"value": "same-origin"},
  "cross_origin_embedder_policy": {"value": "require-corp"}
}
```
**Verdict**: Strong CSP configuration, prevents malicious embedding

### 5. Obfuscation
**Severity**: NONE
**Finding**: Code is well-structured and readable (deobfuscated cleanly)
**Verdict**: No malicious obfuscation

### 6. Extension Enumeration/Killing
**Severity**: NONE
**Finding**: No code detected for detecting or interfering with other extensions
**Verdict**: Clean

### 7. XHR/Fetch Hooking
**Severity**: NONE
**Finding**: No window.fetch or XMLHttpRequest monkey-patching detected
**Verdict**: Clean

### 8. Keylogging/Input Monitoring
**Severity**: NONE
**Finding**: No keyboard event listeners or input field monitoring
**Verdict**: Clean

### 9. Cookie/Storage Harvesting
**Severity**: NONE
**Finding**: Only accesses `chrome.storage.local` for its own settings
**Verdict**: Clean

### 10. Ad/Coupon Injection
**Severity**: NONE
**Finding**: No DOM manipulation for ads, affiliate links, or coupons
**Verdict**: Clean

## False Positive Analysis

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| `innerHTML` usage | `js/events.js:335,346` | Static UI text for Wavenet auth instructions | **False Positive** |
| `outerHTML` usage | `js/content.js:201` | Cloning DOM elements for text extraction | **False Positive** |
| `document.` references | Multiple content scripts | Legitimate DOM traversal for text extraction | **False Positive** |
| Third-party domains | TTS engine endpoints | All TTS services require remote API calls | **False Positive** |
| Token/credential storage | `chrome.storage.local` | Standard OAuth token persistence | **False Positive** |
| `remote` property | `js/tts-engines.js:65` | Voice metadata from browser TTS API | **False Positive** |

## Data Flow Summary

```
User Action (Read Page)
  ↓
Content Script extracts text
  ↓
Background script receives text
  ↓
TTS engine selected (based on voice preference)
  ↓
[One of the following paths:]
  1. Browser TTS API (chrome.tts) - No network
  2. Google Translate - Text → translate.google.com → Audio
  3. Premium TTS - Text → support.readaloud.app → Audio
  4. Cloud TTS (AWS/Azure/GCP) - Text → User's API key → Audio
  5. Offline (Piper/Supertonic) - Text → WASM processing → Audio
  ↓
Audio playback via player.html
```

**Sensitive Data Handling**:
- **Text content**: Only transmitted when user explicitly requests TTS
- **Auth tokens**: Stored locally, transmitted only to Read Aloud servers
- **API keys**: User-provided, stored locally, never sent to Read Aloud servers
- **No PII collection**: Extension does not collect email, name, location, etc. beyond OAuth

## Premium Feature Analysis

### Subscription Model
- Extension offers free TTS (browser voices, Google Translate) and paid premium voices
- Premium requires account login via `https://readaloud.app/login.html`
- Account balance checked before premium voice usage (`get-account` API)
- Payment required error if balance insufficient

**Verdict**: Legitimate freemium business model, no dark patterns detected

### Issue Reporting (`reportIssue` function)
```javascript
reportIssue(url, comment) {
  ajaxPost(config.serviceUrl + "/read-aloud/report-issue", {
    url: JSON.stringify(settings),  // User settings + URL + version + userAgent
    comment: comment                 // User-provided feedback
  })
}
```
**Verdict**: Standard bug reporting, user-initiated only

## Remote Configuration

```javascript
getRemoteConfig() {
  // Fetches config from support.readaloud.app/read-aloud/config
  // Cached for 1 hour
}
```
**Purpose**: Feature flags, voice list updates, service endpoints
**Risk**: Could theoretically be used for kill switches or behavior changes
**Mitigation**: No evidence of malicious config usage, standard for cloud-connected apps
**Verdict**: Acceptable for legitimate service

## Overall Risk Assessment

| Category | Risk Level | Justification |
|----------|-----------|---------------|
| Malware | **NONE** | No malicious code detected |
| Data Exfiltration | **NONE** | Only functional TTS data transmission |
| Privacy | **LOW** | Collects minimal data (only for TTS service) |
| Permissions | **JUSTIFIED** | All permissions required for advertised features |
| Third-party SDKs | **CLEAN** | Standard libraries, no malicious dependencies |
| Obfuscation | **NONE** | Code is readable and well-structured |
| Network Activity | **EXPECTED** | All API calls are TTS-related |
| User Trust | **HIGH** | 6M users, transparent functionality |

## Recommendations

### For Users
1. ✅ Extension is safe to use for its intended purpose
2. ⚠️ Be aware that text you read aloud is sent to TTS providers (expected behavior)
3. ⚠️ Optional permissions (webRequest, file://) grant broad access - only enable if needed
4. ✅ Premium features require login and payment - standard subscription model
5. ⚠️ If using cloud TTS (AWS/Azure/GCP), you are responsible for API key security

### For Developers (None - Extension is Clean)
No security improvements required.

## Conclusion

**Final Verdict: CLEAN**

Read Aloud is a **legitimate, well-designed text-to-speech extension** with no security vulnerabilities or malicious behavior. The extension:
- ✅ Performs only its advertised TTS functionality
- ✅ Handles user data responsibly (minimal collection, functional use only)
- ✅ Uses appropriate permissions for its feature set
- ✅ Maintains good security practices (CSP, OAuth, no dynamic code)
- ✅ Integrates with multiple TTS providers transparently

While the extension requires extensive permissions and makes numerous network calls, this is **entirely justified** for a TTS service that supports multiple cloud providers and document formats. The 6 million user base and transparent operation confirm this is a trusted, legitimate extension.

**Recommendation**: Safe for production use. Users should understand that text content is sent to TTS services (expected for any TTS extension) and optional permissions grant broad access (only enable if reading PDFs/local files).
