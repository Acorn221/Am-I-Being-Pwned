# Security Analysis Report: PromptStorm - ChatGPT, Gemini, Claude Prompts

## Extension Metadata
- **Extension ID**: gkcdaooannhlioejchebhpkllbcackig
- **Extension Name**: PromptStorm - ChatGPT, Gemini, Claude Prompts
- **Version**: 1.9
- **User Count**: ~30,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

PromptStorm is a prompt management extension that injects UI into ChatGPT, Google Gemini, and Claude AI websites to help users manage and use pre-crafted prompts. The extension collects user prompt usage data and sends it to the vendor's servers, including tracking what prompts users execute on AI platforms. While the extension serves its intended purpose legitimately, it engages in **invasive AI conversation tracking** that raises privacy concerns.

**Overall Risk Level: LOW**

The extension is not malicious but collects detailed analytics on user interactions with AI platforms, which may not be fully transparent to average users.

## Vulnerability Analysis

### 1. AI Conversation/Prompt Usage Tracking
**Severity**: MEDIUM
**Files**:
- `assets/index.ts.7d1b842c.js` (background service worker)
- `assets/index.ts.6e6a590d.js` (content script)

**Description**:
The extension tracks every prompt a user executes through the PromptStorm interface and sends it to `https://promptstorm.app/api/history/add` along with:
- User session ID (from cookie `promptStorm_session_id`)
- Prompt ID
- Full prompt text
- User's selected choices/parameters

**Code Evidence**:
```javascript
// Background script: assets/index.ts.7d1b842c.js lines 38-58
async function d(e, a, t, o) {
  return new Promise(async (s, p) => {
    if (console.log("addHistory: " + e + a, t, o), e !== void 0) {
      let r = JSON.stringify({
        promptstormSessionId: e,
        prompt_id: a,
        prompt: t,
        choices: o
      });
      await fetch("https://promptstorm.app/api/history/add", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: r
      })
    }
  })
}

// Monitoring submit button for ChatGPT (lines 961-997)
new MutationObserver(L).observe(S, u)
// ...monitors button state changes to detect when user submits prompt
// Then sends: chrome.runtime.sendMessage({ type: "addHistory", message: {...}})
```

The extension monitors the ChatGPT send button, Gemini send button, and Claude send button via MutationObservers to detect when users submit prompts, then reports this usage back to the vendor.

**Verdict**: This is **legitimate analytics** for a prompt management tool - tracking which prompts users find useful. However, it's invasive as it sends user prompt text to a third-party server. This is within the extension's stated purpose (prompt management) but may not be clearly disclosed to users.

### 2. Cookie Access for Session Management
**Severity**: LOW
**Files**: `assets/index.ts.7d1b842c.js`

**Description**:
The extension reads the `promptStorm_session_id` cookie from `promptstorm.app` to identify logged-in users.

**Code Evidence**:
```javascript
// Lines 26-37
async function g() {
  return new Promise((e, a) => {
    chrome.cookies.get({
      url: "https://promptstorm.app",
      name: "promptStorm_session_id"
    }, function(t) {
      chrome.storage.local.set({
        promptStorm_session_id: t == null ? void 0 : t.value.toString()
      })
    })
  })
}
```

**Verdict**: CLEAN - This is standard session management for the extension's own authentication system. The cookie is only from the vendor's domain.

### 3. DOM Manipulation on AI Platforms
**Severity**: LOW
**Files**: `assets/index.ts.6e6a590d.js`

**Description**:
The extension directly manipulates input fields on ChatGPT, Gemini, and Claude to insert prompt text:

**Code Evidence**:
```javascript
// Lines 1082-1096
if (a != null && a.includes("chatgpt.com")) {
  const H = document.querySelector("div#prompt-textarea.ProseMirror") ||
            document.querySelector(".ProseMirror") ||
            document.querySelector("textarea");
  H ? H.tagName.toLowerCase() === "textarea" ?
    (H.value = F, H.dispatchEvent(new Event("input", {bubbles: !0}))) :
    (H.textContent = F, H.dispatchEvent(new Event("input", {bubbles: !0})))
}
```

**Verdict**: CLEAN - This is the core functionality of the extension (inserting prompts into AI chat interfaces). The manipulation is limited to the intended purpose.

### 4. Content Security Policy
**Severity**: LOW
**Files**: `manifest.json`

**Description**:
No CSP is defined in the manifest, but this is not required for MV3 extensions and the extension doesn't load remote scripts.

**Verdict**: CLEAN - Not a concern for this extension architecture.

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML` usage | `assets/index.ts.6e6a590d.js` | All instances are static SVG icons defined inline, not user-controlled content |
| Cookie access | `assets/index.ts.7d1b842c.js:28` | Only accesses the extension's own session cookie from promptstorm.app |
| MutationObserver | `assets/index.ts.6e6a590d.js:963,965,967` | Used to detect prompt submissions on AI platforms for analytics - part of intended functionality |

## API Endpoints

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `https://promptstorm.app/api/history/add` | POST | Track prompt usage | Session ID, prompt ID, prompt text, choices |
| `https://promptstorm.app/api/categories` | GET | Fetch prompt categories | None |
| `https://promptstorm.app/api/subcategories` | GET | Fetch prompt subcategories | None |
| `https://promptstorm.app/api/prompts-{id}` | GET | Fetch prompts for subcategory | Subcategory ID in URL |
| `https://promptstorm.app/api/options-{id}` | GET | Fetch prompt options | Options ID in URL |
| `https://promptstorm.app/api/choice-{id}` | GET | Fetch choice details | Choice ID in URL |
| `https://promptstorm.app/api/search-{query}` | GET | Search prompts | Search query in URL |

## Data Flow Summary

1. **User authenticates**: Extension reads `promptStorm_session_id` cookie from promptstorm.app
2. **User browses prompts**: Extension fetches categories, subcategories, and prompts from API
3. **User selects prompt**: Extension inserts prompt text into ChatGPT/Gemini/Claude input field
4. **User submits to AI**: MutationObserver detects submission, extension sends usage data to API including:
   - Session ID (identifying the user)
   - Prompt ID
   - Full prompt text
   - User's selected parameters/choices
5. **All data sent over HTTPS** to promptstorm.app

## Permissions Analysis

| Permission | Justification | Risk |
|------------|---------------|------|
| `tabs` | Monitor active tabs to detect AI platform pages | LOW - Standard for content script injection |
| `cookies` | Read session cookie from promptstorm.app | LOW - Only reads vendor's own cookies |
| `storage` | Store session ID and user preferences | LOW - Standard storage usage |
| Host permissions for chatgpt.com, gemini.google.com, claude.ai, promptstorm.app | Inject UI and monitor interactions on AI platforms | MEDIUM - Broad access but serves stated purpose |

## Overall Risk Assessment

**Risk Level**: LOW

**Rationale**:
- The extension performs its stated function (managing and inserting prompts for AI chatbots)
- No evidence of credential theft, cryptocurrency mining, or malicious code execution
- Data collection is analytics-focused and related to the extension's purpose
- All network traffic goes to the legitimate vendor domain (promptstorm.app)
- Uses HTTPS for all communications
- No obfuscation beyond standard build minification

**Privacy Concerns**:
- Tracks detailed prompt usage including full prompt text sent to vendor servers
- Users may not be fully aware their prompt selections are being logged remotely
- Session-based tracking allows vendor to build usage profiles per user

**Recommendation**: CLEAN with disclosure recommendation. The extension should clearly inform users that their prompt usage is tracked and sent to PromptStorm servers for analytics purposes.
