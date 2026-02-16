# Vulnerability Report: ChatGPT for YouTube

## Metadata
- **Extension ID**: ocbklpkcikpidkleacbohkobinlilgbd
- **Extension Name**: ChatGPT for YouTube
- **Version**: 2.1.0
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

ChatGPT for YouTube is a browser extension that provides AI-powered summaries of YouTube videos by extracting video titles and transcripts and sending them to third-party servers for processing. The extension has two primary privacy concerns: (1) undisclosed transmission of complete video transcripts and titles to external servers (chatgpt4youtube.com and api.wenanxia.com), and (2) use of window.postMessage without origin validation which could allow malicious websites to inject data. While the data collection aligns with the extension's stated purpose of video summarization, users may not be fully aware that their viewing history (in the form of video titles/transcripts) is being transmitted to external servers.

The extension appears to be a legitimate tool for its stated purpose, but the lack of origin validation in message handlers and the transmission of potentially sensitive viewing data to third parties warrant a MEDIUM risk classification.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Video Data Transmission to Third-Party Servers

**Severity**: MEDIUM
**Files**: assets/index.tsx-0dd019d3.js (lines 648-651), assets/index-86631bbc.js (lines 16-37)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension extracts YouTube video titles and complete transcripts, then sends this data to external servers at chatgpt4youtube.com and api.wenanxia.com for AI summarization. This creates a comprehensive log of users' video viewing habits on third-party servers.

**Evidence**:
```javascript
// Content script sends video data to background via chrome.runtime.connect
u.postMessage({
  video: t.video,
  transcript: d.transcript.map(w => w.text).join(""),
  languageCode: d.languageCode
})

// API requests to external servers
n = async (t, s) => fetch(`https://chatgpt4youtube.com/${t}`, {
  method: s?.method ?? "POST",
  headers: {
    "Content-Type": "application/json"
  },
  body: s?.method === "GET" ? void 0 : JSON.stringify(s?.data ?? {})
})

// Additional API endpoints
p = async t => fetch(`https://api.wenanxia.com/v1/chats/${t}/likes`, {
  method: "PUT"
})
```

**Verdict**: MEDIUM severity. While the data transmission is necessary for the extension's core functionality (video summarization), the complete transcript transmission creates privacy concerns. Users' video viewing patterns could be inferred from the titles and transcripts sent to third-party servers. The extension's privacy policy should clearly disclose this data transmission.

### 2. MEDIUM: window.postMessage Without Origin Validation

**Severity**: MEDIUM
**Files**: assets/index.tsx-0dd019d3.js (line 532), assets/index.tsx-b3e65a0b.js (line 532), assets/index.tsx-1452ae6d.js (line 532)
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension uses window.addEventListener("message") to receive YouTube player data without validating the message origin, allowing any website to potentially inject malicious data.

**Evidence**:
```javascript
const n = r => {
  r.data.from === "ytInitialPlayerResponse" && (window.removeEventListener("message", n), e(r.data.data), i.remove())
};
window.addEventListener("message", n), o.appendChild(i)
```

**Verdict**: MEDIUM severity. While the message handler checks for a specific property (`from === "ytInitialPlayerResponse"`), it does not validate the message origin. A malicious website could craft messages with this property to inject fake video data. However, exploitation is limited since the extension only runs on YouTube domains and the injected data would only affect the summarization feature, not leading to more severe impacts like credential theft or code execution.

## False Positives Analysis

1. **Webpack Bundled Code**: The extension uses webpack/vite bundling which creates minified variable names. This is standard practice for modern web development and not indicative of malicious obfuscation.

2. **Multiple Identical Content Scripts**: The presence of multiple similar files (index.tsx-*.js) is due to webpack's code splitting and module loading system, not code duplication for obfuscation purposes.

3. **API Access to chatgpt4youtube.com**: While the domain name suggests ChatGPT integration, this appears to be a legitimate backend service operated by the extension developer for providing the summarization feature, not unauthorized access to OpenAI's services.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| chatgpt4youtube.com/api/chat | Submit video for summarization | Video title, transcript, language code | Medium - Creates viewing history log |
| api.wenanxia.com/v1/chats/{id}/likes | Like/unlike summaries | Chat ID | Low - Analytics only |
| www.youtube.com/watch?v={id} | Fetch video metadata | Video ID (in URL) | Low - Public data access |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: The extension performs its stated function (YouTube video summarization) but has privacy implications due to transmission of complete video transcripts and titles to third-party servers. This creates a comprehensive log of users' viewing habits that could be sensitive. Additionally, the lack of origin validation in postMessage handlers introduces a potential attack vector, though exploitation is limited in scope.

The extension would be rated LOW if:
- Privacy policy clearly disclosed the data transmission
- Message handlers validated origins
- Data transmission was minimized or encrypted end-to-end

The extension is not rated HIGH because:
- Data collection aligns with stated functionality
- No evidence of credential harvesting or malicious intent
- No code execution vulnerabilities
- Data transmission appears necessary for the AI summarization feature

**Recommendations**:
1. Add origin validation to all window.postMessage listeners
2. Clearly disclose in the privacy policy that video titles and transcripts are sent to external servers
3. Consider implementing local processing or end-to-end encryption for sensitive video content
4. Minimize data retention on backend servers and provide clear data deletion policies
