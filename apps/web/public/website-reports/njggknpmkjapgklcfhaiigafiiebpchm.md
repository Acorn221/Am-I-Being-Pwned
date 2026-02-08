# Security Analysis Report: BrowserGPT

## Extension Metadata
- **Extension Name**: BrowserGPT: ChatGPT Anywhere Powered by GPT 4
- **Extension ID**: njggknpmkjapgklcfhaiigafiiebpchm
- **Version**: 3.1.8
- **User Count**: ~40,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

BrowserGPT is a legitimate AI writing assistant extension that integrates ChatGPT functionality across various websites. The extension communicates with the HIX.ai API backend (`https://hix.ai`) to provide AI-powered writing assistance, text generation, and content summarization features.

**Overall Risk Level: CLEAN**

While the extension requires extensive permissions and has broad access to web content, the functionality aligns with its stated purpose as an AI writing assistant. The code demonstrates legitimate use cases for AI content generation across multiple platforms (Gmail, Google Docs, social media, search engines, YouTube). No clear evidence of malicious behavior, data exfiltration beyond intended functionality, or security vulnerabilities was identified.

## Permissions Analysis

### Declared Permissions
- `activeTab` - Access to currently active tab
- `scripting` - Inject and execute scripts
- `contextMenus` - Add context menu items
- `storage` - Store user settings and cache
- `clipboardWrite` / `clipboardRead` - Clipboard operations for text manipulation
- `cookies` - Cookie access (for authentication with hix.ai)
- `management` - Extension management events
- `sidePanel` - Side panel UI

### Host Permissions
- `https://hix.ai/*` - Primary API backend
- `<all_urls>` - Required for content script injection across all websites

**Assessment**: Permissions are extensive but appropriate for an AI writing assistant that needs to:
- Inject UI elements on any website
- Access page content for context-aware suggestions
- Communicate with backend AI services
- Provide clipboard integration
- Maintain user authentication state

## Content Security Policy

No custom CSP defined in manifest. Uses default Manifest V3 CSP which prevents:
- Inline scripts
- Remote code execution
- eval() usage
- Unsafe script sources

**Assessment**: Acceptable security posture with MV3 defaults.

## Vulnerability Analysis

### 1. No Critical Vulnerabilities Identified

**Verdict**: CLEAN

The extension does not exhibit any of the following critical security issues:
- No extension enumeration or killing mechanisms
- No XHR/fetch hooking for MITM attacks
- No residential proxy infrastructure
- No remote config with kill switches
- No keylogger implementation
- No credential harvesting
- No ad/coupon injection
- No cryptocurrency mining

### 2. Data Collection and Privacy

**Severity**: INFORMATIONAL
**Files**: `background.js` (lines 6580-6640, 7418-7434, 9076-9096)
**Code Snippets**:
```javascript
// Analytics tracking
const _ApiStaticsAnalysis = class _ApiStaticsAnalysis extends StaticsAnalysis {
  __publicField(this, "trackToolEvent", async (params) => {
    await this.track("use_tool", params);
  });
}

// API communication with common headers
async function getCommonHeaders() {
  const locale = await getLocalSetting("locale", "English");
  return {
    "platform": `${getBrowserName()}_extension`,
    "version": "3.2.0",
    "ext-version": browser.runtime.getManifest().version,
    "language": (findSettingLanguage?.code) || "English"
  };
}

// tRPC client setup
const trpc = createTRPCProxyClient({
  transformer: SuperJSON,
  links: [httpBatchLink({
    url: `${API_BASE_URL}/api/trpc`,
    headers() {
      return getCommonHeaders();
    }
  })]
});
```

**Description**: The extension tracks tool usage and sends telemetry to hix.ai. User-generated content (prompts and AI responses) are transmitted to the backend API for AI processing. This is clearly part of the intended functionality as an AI service.

**Verdict**: CLEAN - Expected behavior for AI-powered SaaS extension. Users implicitly consent to sending text to AI service when using the tool.

### 3. Authentication and Session Management

**Severity**: INFORMATIONAL
**Files**: `background.js` (lines 6616-6641, 7172-7230)
**Code Snippets**:
```javascript
// NextAuth cookie handling
const SESSION_TOKEN_NAME = "__Secure-next-auth.session-token";
const CALLBACK_URL_NAME = "__Secure-next-auth.callback-url";
const CSRF_TOKEN_NAME = "__Host-next-auth.csrf-token";

// User state management
async function updateMeBg(force = false) {
  try {
    const data = await API.fetch({
      type: "user.find",
      params: [],
      options: { force }
    });
    setStorageMe(data);
  } catch (err) {
    setStorageMe(null);
  }
}
```

**Description**: Extension uses NextAuth for authentication with secure cookie flags (`__Secure-` and `__Host-` prefixes). Session tokens are managed via browser storage and synchronized with hix.ai backend.

**Verdict**: CLEAN - Follows secure authentication practices with HttpOnly/Secure cookie flags.

### 4. Content Script Injection Scope

**Severity**: LOW
**Files**: `manifest.json` (content_scripts section), `background.js` (lines 7272-7300)
**Code Snippets**:
```javascript
// Dynamic script injection on all tabs
async function executeScript(tabId) {
  const manifest = browser.runtime.getManifest();
  const scriptsJs = manifest.content_scripts?.reduce((previous, current) => {
    if (current.js) {
      return [...previous, ...current.js];
    }
    return previous;
  }, []) || [];

  await browser.scripting.executeScript({
    target: { tabId },
    files: [...new Set(allJs)]
  });
}
```

**Description**: Extension injects content scripts on `<all_urls>` to provide AI writing assistance across all websites. Total content script code: ~719K lines (deobfuscated).

**Verdict**: CLEAN - Extensive but legitimate for cross-site AI assistant functionality. No malicious DOM manipulation detected.

## API Endpoints and Data Flow

### Primary Backend Endpoints

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://hix.ai/api/trpc` | tRPC API gateway | User queries, tool selections, settings |
| `https://hix.ai/api/chat` | Chat/conversation streaming | Chat history, user messages, context |
| `https://hix.ai/api/generate` | Quick AI text generation | Text content, tool ID, language, model |
| `https://hix.ai/api/generate/v1` | AI generation v1 | User prompts, context, metadata |
| `https://hix.ai/api/social` | Social media AI assistance | Social platform context, user input |
| `https://hix.ai/api/upload/sign` | S3 upload URL generation | File metadata for uploads |
| `https://bypass.hix.ai` | Bypass domain (unused in code) | Not actively used |

### Data Flow Summary

```
User Input → Content Script → Background Service Worker → hix.ai API
                                                        ↓
User Interface ← Content Script ← Message Passing ← AI Response (SSE)
```

**Assessment**: All data flows to legitimate hix.ai backend. Uses Server-Sent Events (SSE) for streaming AI responses. No evidence of data exfiltration to third parties.

## Technology Stack

- **Framework**: React (production build, minified)
- **State Management**: Standard React patterns
- **API Communication**: tRPC with SuperJSON serialization, Server-Sent Events (SSE)
- **Build Tool**: Modern bundler (Webpack/Vite based on output structure)
- **Browser Polyfill**: webextension-polyfill for cross-browser compatibility
- **UI Libraries**: Multiple UI components for different injection contexts (sidebar, search results, social media, email, docs)

## False Positives

| Pattern | Context | Verdict |
|---------|---------|---------|
| `innerHTML` usage | React's `dangerouslySetInnerHTML` in minified code (line 2182) | FP - React SVG rendering |
| `password` references | Language bundle strings for UI text | FP - Internationalization strings |
| Cookie access | NextAuth session management via hix.ai domain | FP - Legitimate authentication |
| Storage API usage | User settings, API cache, authentication state | FP - Standard extension storage |
| Extensive permissions | Required for AI assistant across all websites | FP - Aligns with functionality |
| Large content scripts | React + UI libraries for different site contexts | FP - Legitimate feature-rich UI |

## Security Strengths

1. **Manifest V3 Compliance**: Uses modern extension architecture with service workers
2. **No Remote Code Execution**: No eval(), Function(), or dynamic script loading
3. **Secure Authentication**: NextAuth with secure cookie flags
4. **HTTPS Only**: All API communication over TLS to hix.ai
5. **No Obfuscation**: Code is readable (deobfuscated) with clear purpose
6. **Proper Error Handling**: Abort controllers for SSE, proper exception handling
7. **Credential Management**: Uses include credentials for same-origin requests only

## Recommendations

While the extension is clean, users should be aware:

1. **Privacy Consideration**: All text input to the AI is sent to hix.ai for processing
2. **Broad Access**: Extension can read content on all websites to provide context
3. **Authentication State**: Session tokens are stored locally and synchronized with backend
4. **Service Dependency**: Requires active hix.ai account and network connectivity

## Conclusion

BrowserGPT is a legitimate, feature-rich AI writing assistant extension that operates as designed. The extensive permissions and data flows are justified by its functionality as a cross-site AI service. No security vulnerabilities or malicious behavior detected.

The extension properly implements:
- Modern extension security practices (MV3)
- Secure authentication (NextAuth with secure cookies)
- Standard API communication patterns (tRPC, SSE)
- Appropriate permission usage for stated functionality

**Risk Level: CLEAN**

Users installing this extension should be comfortable with:
- Sharing text content with HIX.ai's AI processing service
- Extension having broad website access for contextual AI assistance
- Standard telemetry for usage analytics
