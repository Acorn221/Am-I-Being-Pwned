# Vulnerability Report: KahootGPT | AI Integration (NEW: File + Multi-Ans)

## Metadata
- **Extension ID**: mmnbfkefbancfkmcbfeepiiniggfaobm
- **Extension Name**: KahootGPT | AI Integration (NEW: File + Multi-Ans)
- **Version**: 4.0.0
- **Users**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

KahootGPT is a Kahoot quiz cheating tool that uses AI models (OpenAI, Anthropic, Google) to automatically answer quiz questions. The extension collects user email addresses, access tokens, and quiz data which are transmitted to a third-party backend server (api.kahootgpt.itsmarsss.com) for subscription verification and query management. While the extension's purpose is disclosed (cheating on Kahoot quizzes), it implements a freemium monetization model where user credentials and query usage are tracked on remote servers. Users also provide their own API keys for AI services, which are stored locally and transmitted to external APIs. The extension modifies DOM elements on Kahoot pages and can automatically click answers, raising concerns about academic integrity.

The primary privacy concerns involve the transmission of email addresses, access tokens, and quiz content to a third-party server, as well as the local storage of valuable API keys. However, the extension's cheating functionality is its stated purpose, and the data collection appears to be primarily for subscription management rather than undisclosed surveillance.

## Vulnerability Details

### 1. MEDIUM: Credential and User Data Exfiltration to Third-Party Backend

**Severity**: MEDIUM

**Files**: scripts/background.js (lines 29-58, 464-533)

**CWE**: CWE-359 (Exposure of Private Information)

**Description**: The extension transmits user email addresses, access tokens, and quiz data to api.kahootgpt.itsmarsss.com for subscription verification and query processing. On the "is_paid" message, it sends `email` and `accessToken` stored in chrome.storage.local to the backend for login verification. For users with available queries (free/bonus/light), the extension sends email, accessToken, question content, quiz answers, and optionally file content to the backend's `/api/queryGPT` endpoint.

**Evidence**:
```javascript
// Background.js lines 29-40
chrome.storage.local.get(["email", "accessToken"], async (result) => {
    try {
        const response = await fetch("https://api.kahootgpt.itsmarsss.com/api/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                email: result.email,
                accessToken: result.accessToken,
            }),
        });
```

```javascript
// Background.js lines 497-505
const response = await fetch("https://api.kahootgpt.itsmarsss.com/api/queryGPT", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
        email,
        accessToken,
        ...queryData,
    }),
});
```

**Verdict**: This is a MEDIUM severity issue because while user credentials are being transmitted to a third-party server, the extension's functionality explicitly requires a backend service for subscription management and the freemium query system. The access tokens appear to be extension-specific authentication tokens rather than Kahoot credentials. However, the lack of transparency about what data the backend server retains and how it's protected is concerning.

### 2. MEDIUM: User API Keys Stored and Transmitted to External Services

**Severity**: MEDIUM

**Files**: scripts/background.js (lines 194-331), scripts/contentScript.js (lines 1093-1118)

**CWE**: CWE-522 (Insufficiently Protected Credentials)

**Description**: The extension requires users to provide their own API keys for OpenAI, Anthropic, and Google AI services. These valuable API keys are stored in chrome.storage.local and transmitted directly from the browser to the respective AI provider APIs. While this is necessary for the extension's functionality when users don't have queries available, API keys stored in browser storage are vulnerable to exfiltration by other extensions or malicious scripts.

**Evidence**:
```javascript
// Background.js lines 194-201
response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
        Authorization: `Bearer ${request.apiKey}`,
        "Content-Type": "application/json",
    },
    body: JSON.stringify(requestBody),
});
```

```javascript
// ContentScript.js lines 1097-1109
chrome.runtime.sendMessage({
    type: "llm_chat_completions",
    apiKey: openAIKey,
    model: model,
    provider: provider,
    thinkingLevel: thinkingLevel,
    promptData: promptData,
    question: promptData.question,
    triangle: promptData.triangle,
    rhombus: promptData.rhombus,
    circle: promptData.circle,
    square: promptData.square,
    fileContent: uploadedFileContent || undefined,
}, ...);
```

**Verdict**: While storing API keys in chrome.storage.local is common practice for extensions that require API access, it presents a security risk. If the user's browser or other extensions are compromised, these API keys could be stolen, leading to unauthorized usage charges. The extension does use these keys for their intended purpose (calling the respective AI APIs), which is MEDIUM severity rather than HIGH.

### 3. LOW: DOM Manipulation for Quiz Answer Automation

**Severity**: LOW

**Files**: scripts/contentScript.js (lines 186-221, 1253-1263)

**CWE**: CWE-494 (Download of Code Without Integrity Check)

**Description**: The extension manipulates the Kahoot quiz interface by modifying DOM elements to highlight answers and automatically click correct answers when "Auto-hoist" mode is enabled. This involves querying for Kahoot answer buttons and programmatically triggering click events and modifying their styles.

**Evidence**:
```javascript
// ContentScript.js lines 186-201
function tap(val) {
    const answerButtons = document.querySelectorAll('[data-functional-selector^="answer-"]');
    const correctButton = answerButtons[val];
    if (!correctButton)
        return;
    if (toggled) {
        correctButton.click();
        correctButton.style.position = "fixed";
        correctButton.style.top = "0";
        correctButton.style.left = "0";
        correctButton.style.width = "100vw";
        correctButton.style.height = "50%";
        correctButton.style.outline = "3px solid gold";
        correctButton.style.zIndex = "1000";
    }
    createAlert("<strong>KahootGPT Info!</strong> Clicked best answer according to AI.", "#46a8f5");
}
```

**Verdict**: While this is the core functionality of a cheating tool, from a security perspective this is LOW severity. The DOM manipulation is limited to the Kahoot website and only affects the user's own quiz session. This is not a security vulnerability per se, but rather the intended (albeit ethically questionable) behavior of the extension.

## False Positives Analysis

1. **Obfuscated Code Flag**: The ext-analyzer flagged the extension as "obfuscated." Upon manual review, the deobfuscated code appears to be standard TypeScript/JavaScript bundled with Webpack or similar build tools. There is no evidence of intentional obfuscation to hide malicious behavior - the code is well-structured with clear variable names and comments.

2. **EXFILTRATION Flow**: The static analyzer detected `chrome.storage.local.get → fetch(api.kahootgpt.itsmarsss.com)` as an exfiltration flow. While this is technically accurate, the data being sent (email, accessToken) is part of the extension's disclosed subscription verification system. This is not covert exfiltration but rather expected functionality for a freemium model.

3. **Message Data Flows**: The analyzer detected message data flowing to `fetch(api.openai.com)` and `*.innerHTML`. The fetch calls are legitimate API requests to AI services (the extension's core purpose), and the innerHTML usage is for displaying UI elements in the shadow DOM.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.kahootgpt.itsmarsss.com/api/login | Subscription verification | email, accessToken | MEDIUM - Third-party credential verification |
| api.kahootgpt.itsmarsss.com/api/queryGPT | AI query for users with available queries | email, accessToken, question, quiz answers, optional file content | MEDIUM - Quiz data sent to third-party server |
| api.openai.com/v1/responses | OpenAI API for answer generation | User's API key, quiz question, quiz answers, optional file content | LOW - User's own API usage |
| api.anthropic.com/v1/messages | Anthropic API for answer generation | User's API key, quiz question, quiz answers, optional file content | LOW - User's own API usage |
| generativelanguage.googleapis.com | Google Gemini API for answer generation | User's API key, quiz question, quiz answers, optional file content | LOW - User's own API usage |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

KahootGPT is a quiz cheating extension with disclosed functionality that raises moderate privacy concerns. The extension's primary security issues stem from its freemium monetization model which requires transmitting user credentials (email, access tokens) and quiz data to a third-party backend server. While this is somewhat expected for a subscription-based service, the lack of transparency about server-side data retention and security practices is concerning.

The extension also requires users to provide valuable API keys for AI services (OpenAI, Anthropic, Google), which are stored in browser storage where they could potentially be accessed by other malicious extensions or scripts. However, the extension does use these keys appropriately for their stated purpose.

From an ethical standpoint, the extension's core purpose is to enable cheating on educational quizzes, which violates academic integrity policies. However, from a pure security analysis perspective, the extension does not appear to contain malware, hidden surveillance capabilities, or credential theft mechanisms beyond what is required for its disclosed functionality.

The risk level is MEDIUM rather than HIGH because:
1. The data collection appears to be limited to what's necessary for subscription management
2. The extension's cheating functionality is openly disclosed in its name and description
3. There is no evidence of credential theft, keylogging, or covert surveillance
4. The API keys are used for their intended purpose (calling AI services)

However, it remains MEDIUM (not LOW or CLEAN) due to:
1. Transmission of user credentials to third-party servers
2. Storage of valuable API keys in browser storage
3. Lack of transparency about backend data handling
4. The ethical concerns of enabling academic dishonesty
