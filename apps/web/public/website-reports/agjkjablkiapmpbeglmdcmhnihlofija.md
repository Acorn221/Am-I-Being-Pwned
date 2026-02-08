# Security Analysis Report: YoutubeDigest

## Extension Metadata
- **Name:** YoutubeDigest: summarize and translate using ChatGPT
- **ID:** agjkjablkiapmpbeglmdcmhnihlofija
- **Version:** 2.4.1.1
- **Users:** ~70,000
- **Manifest Version:** 3

## Executive Summary

YoutubeDigest is a legitimate Chrome extension that summarizes YouTube videos using AI (ChatGPT/Gemini). The extension displays **MEDIUM** risk due to several security concerns including excessive OAuth scopes, hard-coded localhost endpoints, storage of user API keys, and communication with third-party backend services that proxy ChatGPT requests. While no clear malicious behavior was detected, the extension's architecture introduces privacy and security considerations for users.

## Vulnerability Details

### 1. MEDIUM - Excessive OAuth Scopes & Third-Party Token Exchange
**Severity:** MEDIUM
**Files:**
- `background.js` (lines 2449-2483, 2692-2727)
- `manifest.json` (lines 16-21)

**Description:**
The extension requests OAuth access to Google and Twitter accounts, but critically **exchanges authorization codes with a third-party server** (`youtubedigest.app`) instead of directly with Google/Twitter OAuth endpoints.

**Code Evidence:**
```javascript
// Google OAuth - exchanges code with youtubedigest.app
let d = new URL(n).searchParams.get("code"),
  s = await (await fetch("https://www.youtubedigest.app/api/exchange", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      authCode: d
    })
  })).json(),
  p = s.accessToken,
  i = s.refreshToken;
```

**Verdict:** The extension uses OAuth in a potentially insecure manner. While OAuth flow starts correctly, the authorization code is sent to youtubedigest.app rather than being exchanged directly with Google/Twitter. This creates a trust dependency on the third-party service and potential for token interception.

**Risk:** User Google/Twitter tokens pass through third-party infrastructure. If youtubedigest.app is compromised, attackers could harvest OAuth tokens.

---

### 2. MEDIUM - Storage of User-Provided ChatGPT API Keys
**Severity:** MEDIUM
**Files:** `background.js` (lines 2036-2042)

**Description:**
The extension allows users to provide their own OpenAI API keys, which are stored in `chrome.storage.local` and used directly in requests to `api.openai.com`.

**Code Evidence:**
```javascript
P = await co.default.storage.local.get("chatgpt_apikey"),
C = await fetch(`
  https://api.openai.com/v1/chat/completions`, {
  method: "post",
  headers: {
    "Content-Type": "application/json",
    Authorization: `Bearer ${P.chatgpt_apikey}`
  },
```

**Verdict:** While providing API key functionality is legitimate, storing sensitive credentials in `chrome.storage.local` without encryption presents a security risk if other extensions or malware gain access to storage.

**Risk:** API keys stored in plain text could be extracted by malicious extensions with storage permissions.

---

### 3. MEDIUM - ChatGPT Session Token Extraction & Caching
**Severity:** MEDIUM
**Files:** `background.js` (lines 2794-2807, 2801-2806)

**Description:**
The extension extracts ChatGPT session tokens from authenticated `chatgpt.com` sessions and caches them for 10 seconds.

**Code Evidence:**
```javascript
async function Ao() {
  if (Oe.get(ke)) return Oe.get(ke);
  let r = await fetch("https://chatgpt.com/api/auth/session");
  if (r.status === 403) throw new Error("CLOUDFLARE");
  let e = await r.json().catch(() => ({}));
  if (!e.accessToken) throw new Error("UNAUTHORIZED");
  return Oe.set(ke, e.accessToken), e.accessToken
}
```

**Verdict:** The extension legitimately extracts user ChatGPT sessions to enable free summarization via ChatGPT. This is the extension's core functionality but represents a privacy consideration - the extension can access/use ChatGPT sessions without explicit per-request user consent.

**Risk:** Users may not realize the extension is using their ChatGPT account to generate summaries. Could lead to unexpected ChatGPT usage limits or rate limiting.

---

### 4. LOW - Hard-Coded Localhost Development Endpoints
**Severity:** LOW
**Files:** `background.js` (lines 2963-2995)

**Description:**
The extension contains hard-coded `localhost:3000` endpoints for TTS/video generation features that would fail in production.

**Code Evidence:**
```javascript
else if (e.type === "GET_VOICE_LANGUAGES") W("http://localhost:3000/api/get_tts?type=languages", "get", null, o => {
```

**Verdict:** Development code left in production. These endpoints are non-functional for users but indicate incomplete removal of development artifacts.

**Risk:** Minimal - features simply won't work. Could indicate poor code hygiene but no security exploit.

---

### 5. LOW - Broad Content Script Injection
**Severity:** LOW
**Files:** `manifest.json` (lines 36-229)

**Description:**
Content scripts are injected into all YouTube domains worldwide (200+ domains) and ChatGPT.com.

**Verdict:** Necessary for extension functionality - needs to run on YouTube pages to extract video data and ChatGPT pages to interact with the AI interface. Scope is appropriate for stated functionality.

**Risk:** Minimal - expected behavior for a YouTube summarization tool.

---

### 6. INFO - Data Transmission to Third-Party Backend
**Severity:** INFO
**Files:** `background.js` (lines 2659-2689, 2868-3064)

**Description:**
YouTube transcripts, summaries, and user preferences are sent to `youtubedigest.app` backend for processing.

**Code Evidence:**
```javascript
W("https://www.youtubedigest.app/api/summarize", "post", {
  transcripts: r,
  language: a.language,
  summaryMode: a.summaryMode,
  maxBulletPointsPerTranscript: a.maxBulletPointsPerTranscript,
  numberOfWordsPerArticle: a.numberOfWordsPerArticle,
  numberOfTweetReplies: a.numberOfTweetReplies,
  customPrompt: o,
  videoId: a.videoId,
  startTime: a.startTime,
  endTime: a.endTime,
  forceLoad: a.forceLoad,
  summaryProvider: a.summarizationProvider
}, f => {
```

**Verdict:** Legitimate architecture for a freemium service. The backend proxies ChatGPT/Gemini API calls to provide free summaries. However, users should be aware their YouTube viewing data (video IDs, transcripts) is transmitted to third-party servers.

**Risk:** Privacy consideration - video watch history and transcript content visible to youtubedigest.app.

---

## False Positives

| Pattern | Location | Why False Positive |
|---------|----------|-------------------|
| `webextension-polyfill` library | `background.js:115-999`, `options.js:24-800` | Standard Mozilla polyfill for cross-browser compatibility |
| `innerHTML` usage | `content-script.js` (multiple) | React framework's standard DOM rendering - not dynamic code injection |
| Arkose token handling | `background.js:1887-1907` | Legitimate OpenAI Arkose anti-bot challenge handling for ChatGPT API |
| SHA3-512 hashing | `background.js:1800-1803` | Proof-of-work for ChatGPT API sentinel requirements, not malicious obfuscation |
| `storage.local` operations | Throughout | Standard extension settings storage, not credential harvesting |

---

## API Endpoints

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://chatgpt.com/api/auth/session` | Extract ChatGPT session token | None (GET) |
| `https://chatgpt.com/backend-api/conversation` | Send prompts to ChatGPT | Video transcripts, user prompts, conversation state |
| `https://chatgpt.com/backend-api/sentinel/chat-requirements` | Get ChatGPT anti-bot challenge | Conversation mode |
| `https://api.openai.com/v1/chat/completions` | Direct OpenAI API (when user provides key) | Transcripts, prompts |
| `https://www.youtubedigest.app/api/summarize` | Backend summarization service | Transcripts, video metadata, settings |
| `https://www.youtubedigest.app/api/exchange` | OAuth token exchange | Google/Twitter authorization codes |
| `https://www.youtubedigest.app/api/refresh` | OAuth token refresh | Google/Twitter refresh tokens |
| `https://www.googleapis.com/oauth2/v2/userinfo` | Get Google user email | None (Bearer token in header) |
| `https://www.youtubedigest.app/api/twitter/user` | Get Twitter user info | Access token |
| `https://www.youtubedigest.app/api/credits` | Check user credit balance | None |
| `https://www.youtubedigest.app/api/prompts` | Custom prompt CRUD | User-created prompts |
| `https://www.youtubedigest.app/api/sharesummary` | Share summary feature | Video summary text, video ID, URL |
| `http://localhost:3000/*` | Development TTS/video endpoints (non-functional) | TTS content |

---

## Data Flow Summary

1. **YouTube Video Access**: Content script extracts video metadata and transcript from YouTube pages
2. **Transcript Extraction**: Uses YouTube's native transcript API to get captions
3. **Authentication Options**:
   - **Free tier**: Extracts user's existing ChatGPT session token from `chatgpt.com/api/auth/session`
   - **API key mode**: User provides their own OpenAI API key (stored in `chrome.storage.local`)
   - **Premium tier**: OAuth to Google/Twitter via `youtubedigest.app` token exchange
4. **Summarization Processing**:
   - Transcripts sent to either:
     - ChatGPT API directly (with user's session or API key)
     - `youtubedigest.app/api/summarize` backend (which proxies to ChatGPT/Gemini)
5. **Data Storage**: OAuth tokens, API keys, preferences stored in `chrome.storage.local`
6. **Additional Features**: Tweet posting, Medium export, summary sharing all proxied through youtubedigest.app

**Key Privacy Note**: Video watch history (video IDs, transcripts) is transmitted to `youtubedigest.app` servers for processing.

---

## Overall Risk Assessment

**MEDIUM**

### Reasoning:
- ✅ **No malware detected**: No keyloggers, credential theft, ad injection, or malicious obfuscation
- ✅ **Legitimate functionality**: Extension does what it advertises (YouTube video summarization)
- ✅ **Appropriate permissions**: Manifest permissions align with stated features
- ⚠️ **OAuth architecture concern**: Third-party token exchange creates trust dependency
- ⚠️ **API key storage**: User-provided ChatGPT keys stored unencrypted
- ⚠️ **ChatGPT session usage**: Extracts and uses ChatGPT sessions without explicit per-use consent
- ⚠️ **Privacy considerations**: Video watch data transmitted to third-party backend
- ℹ️ **Development artifacts**: Localhost endpoints indicate incomplete cleanup

### Recommendations for Users:
1. Understand that video watch history is sent to youtubedigest.app servers
2. If using API key mode, be aware keys are stored locally without encryption
3. Free tier uses your ChatGPT account - may impact usage limits
4. OAuth flow routes through third-party servers - trust in youtubedigest.app required

### Recommendations for Developers:
1. Implement direct OAuth token exchange without third-party intermediary
2. Encrypt stored API keys using Web Crypto API
3. Remove hard-coded localhost endpoints
4. Add clearer privacy disclosures about data transmission
5. Consider implementing end-to-end encryption for transcript data in transit
