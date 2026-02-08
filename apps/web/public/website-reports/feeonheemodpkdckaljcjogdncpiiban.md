# Security Analysis Report

## Extension Metadata

- **Name**: Zuvu AI: The Ultimate AI Agent Sidebar for Google Search & Beyond
- **Extension ID**: feeonheemodpkdckaljcjogdncpiiban
- **Version**: 3.0.0
- **User Count**: ~100,000
- **Manifest Version**: 3

## Executive Summary

Zuvu AI is an AI-powered sidebar extension that provides conversational AI capabilities for web browsing and Google Search integration. The extension collects and transmits sensitive browsing data including full page content and chat history to a third-party proxy server. While the extension appears to be legitimate AI tooling rather than outright malware, it raises **significant privacy concerns** due to its data collection practices and the transmission of potentially sensitive user data through an intermediary proxy service.

**Risk Level: HIGH**

## Vulnerability Details

### 1. CRITICAL: Sensitive Data Exfiltration via Third-Party Proxy

**Severity**: HIGH
**Files**: `background.js` (lines 44086-44200)
**Code**:
```javascript
const PROXY_CHAT_URL = "https://agent-ai-proxy-production.up.railway.app/proxy-chat";

async sendMessage({message: e, addUserMessageToHistory: t = !0, htmlContent: r}) {
  const l = {
    input: e,
    history: s.map(g => ({
      role: g.sender,
      content: g.content
    })),
    config: {
      temperature: .7
    },
    stream: !0,
    destination_url: "https://openrouter.fly.dev/chat?model=openai/gpt-4.5-preview"
  };

  const g = await fetch(PROXY_CHAT_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "text/event-stream"
    },
    body: JSON.stringify(l),
    signal: (d = this.abortController) == null ? void 0 : d.signal
  });
}
```

**Verdict**: HIGH RISK - The extension transmits all user conversations and chat history to a third-party proxy server (`agent-ai-proxy-production.up.railway.app`). This includes:
- Complete chat history (all previous conversations)
- User messages and AI responses
- Full conversation context

The proxy server sits between the user and the actual AI service (OpenRouter), creating an intermediary that can log, store, or modify all user data. Users have no visibility into what this proxy does with their data.

### 2. CRITICAL: Full Page Content Extraction and Transmission

**Severity**: HIGH
**Files**: `background.js` (lines 41850-41870, 44111-44120)
**Code**:
```javascript
async function getTabText(o) {
  var r;
  return ((r = (await browser$1.scripting.executeScript({
    target: {
      tabId: o
    },
    func: () => document.body.innerText
  }))[0]) == null ? void 0 : r.result) || ""
}

async function extractRelevantTabText(o, e, t = {}) {
  const s = await getTabText(o),
        l = new VectorWorker;
  const d = await l.addDocuments(s, t);
  const g = await l.similaritySearch(e, {k: r});
  return g
}

// In sendRichMessage:
const l = r.tabMentions.map(p => p.id);
s = `Do not mention the tab context in your response, only use it to answer the user's message.
[...]
The user made reference to the following tabs:
${(await Promise.all(l.map(p=>extractRelevantTabText(p,t)))).map(p=>p.map(h=>h.pageContent).join(`
`)).map((p,h)=>`Reference:${r.tabMentions[h].title}, text: ${p}`).join(`
`)}

Message: ${t}`
```

**Verdict**: HIGH RISK - The extension extracts full page content from active tabs using `chrome.scripting.executeScript()` and includes this content in messages sent to the proxy server. This means:
- Complete webpage text content is extracted
- Tab titles and page content are transmitted to third-party servers
- Users browsing sensitive content (banking, medical, private documents) could have that data sent externally
- The vector similarity search runs locally, but the extracted content is still transmitted in chat messages

### 3. MEDIUM: Overly Broad Permissions

**Severity**: MEDIUM
**Files**: `manifest.json`
**Code**:
```json
{
  "permissions": ["storage", "scripting", "activeTab", "tabs", "sidePanel"],
  "host_permissions": ["<all_urls>"]
}
```

**Verdict**: MEDIUM RISK - The extension requests `<all_urls>` host permissions, allowing it to access any website. While necessary for the stated functionality, this creates a very broad attack surface. Combined with `scripting` permission, the extension can execute code on any webpage.

### 4. MEDIUM: Persistent User Tracking

**Severity**: MEDIUM
**Files**: `background.js` (lines 687-696)
**Code**:
```javascript
const STORAGE_KEY = "sync:user_id",
  generateUniqueId = () => v4$1(),
  getUniqueId = async () => {
    const o = await storage.getItem(STORAGE_KEY);
    if (o) return o;
    {
      const e = generateUniqueId();
      return await storage.setItem(STORAGE_KEY, e), e
    }
  };
```

**Verdict**: MEDIUM RISK - The extension generates and stores a persistent unique user ID in sync storage. While the ID is not explicitly transmitted in the analyzed code, this creates a persistent identifier that could be used for tracking across browser sessions and devices (via Chrome sync).

### 5. LOW: WASM Usage in Service Worker

**Severity**: LOW
**Files**: `ort/*.wasm`, `models/all-MiniLM-L6-v2/onnx/model_quantized.onnx`
**Details**:
- 4 ONNX Runtime WASM files (~9-10MB each)
- 1 ML model file (all-MiniLM-L6-v2, 22MB)
- Used for local text embeddings and vector similarity search

**Verdict**: LOW RISK - The WASM files are legitimate ONNX Runtime libraries for running machine learning models. The model is a standard sentence transformer model (all-MiniLM-L6-v2) used for semantic search. This is a legitimate use case for providing local AI features. The CSP includes `'wasm-unsafe-eval'` which is appropriate for this use case.

### 6. LOW: Limited Content Script Scope

**Severity**: LOW
**Files**: `content-scripts/content.js`, `manifest.json`
**Code**:
```javascript
const i = {
  matches: ["*://*.google.com/*"],
  main() {
    console.log("Hello content.")
  }
}
```

**Verdict**: CLEAN - The content script only matches Google domains and has minimal functionality (just a hello log). No malicious behavior detected.

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `eval("quire".replace(/^/, "re"))` | background.js:4134 | Dynamic require for Node.js compatibility - not executed in browser context |
| `innerHTML` references | Various | Part of React/DOM manipulation libraries, not direct code injection |
| `Function()` constructor | background.js:17508 | Part of polyfill for getting global object, standard library pattern |
| HuggingFace tokens | background.js:17625 | Checking for optional HF_TOKEN environment variable for model downloads (not present) |

## API Endpoints & Network Traffic

| Endpoint | Purpose | Data Transmitted | Risk |
|----------|---------|------------------|------|
| `https://agent-ai-proxy-production.up.railway.app/proxy-chat` | AI chat proxy | User messages, chat history, tab content, conversation context | HIGH |
| `https://openrouter.fly.dev/chat?model=openai/gpt-4.5-preview` | Destination AI service | Same as above (via proxy) | HIGH |
| HuggingFace model CDN | ONNX model downloads | None (read-only) | CLEAN |

## Data Flow Summary

1. **User Input**: User types message in sidebar
2. **Tab Content Extraction**: If user mentions tabs, extension extracts full `document.body.innerText` from referenced tabs via `chrome.scripting.executeScript()`
3. **Local Processing**: Extracted text is chunked and embedded using local ONNX model (all-MiniLM-L6-v2)
4. **Vector Search**: Similarity search runs locally to find relevant chunks
5. **Data Transmission**: User message + relevant page content chunks + full chat history sent to proxy server
6. **Proxy Forwarding**: Proxy forwards request to OpenRouter AI service
7. **Response Streaming**: AI response streamed back through proxy to extension

**Privacy Concerns**:
- All user conversations pass through third-party proxy with no transparency
- Complete page content from visited sites can be transmitted
- Chat history stored locally but transmitted in every request
- No encryption or privacy controls visible
- No indication that proxy doesn't log/store sensitive data

## Overall Risk Assessment

**RISK LEVEL: HIGH**

### Rationale

While Zuvu AI is not traditional malware, it presents **significant privacy and security risks**:

1. **Data Exfiltration**: The extension transmits sensitive user data (conversations, browsing content) to a third-party proxy service with no transparency about data handling
2. **Broad Access**: With `<all_urls>` and `scripting` permissions, the extension can read any webpage content
3. **Intermediary Risk**: The Railway.app proxy server is an unnecessary intermediary that could log, modify, or misuse user data
4. **Sensitive Content Risk**: Users discussing or browsing sensitive information (medical, financial, personal) could have that data exposed

### Legitimate Use Case vs. Privacy Trade-off

The extension provides legitimate AI assistant functionality, but the architecture creates serious privacy concerns. A more privacy-respecting design would:
- Communicate directly with AI providers without proxy
- Disclose data collection practices clearly
- Allow users to control what content is shared
- Minimize data transmission to only necessary context

### Comparison to Similar Extensions

Many AI assistant extensions (e.g., official ChatGPT extension, Anthropic's extensions) communicate directly with their backend services without intermediary proxies, providing better transparency and accountability.

## Recommendations

**For Users**:
- Avoid using this extension when viewing sensitive content
- Be aware that conversations and page content may be logged by third parties
- Consider alternatives that communicate directly with AI providers

**For Developers**:
- Remove the intermediary proxy and communicate directly with OpenRouter
- Add clear privacy disclosures about data collection
- Implement user controls for data sharing
- Add end-to-end encryption for sensitive data
- Provide transparency about proxy server logs/retention

## Verdict

**RISK LEVEL: HIGH**

The extension is functionally legitimate but employs privacy-invasive practices that create significant risk for users. The third-party proxy architecture introduces an unnecessary intermediary with access to all user conversations and browsing content, without clear privacy protections or disclosures.
