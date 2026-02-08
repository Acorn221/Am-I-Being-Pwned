# Vulnerability Report: Gener8 (agplbamogoflhammoccnkehefjgkcncl)

**Extension**: Gener8 v3.7.3
**Manifest Version**: 3
**Triage Flags**: V1=4, V2=1 -- innerhtml_dynamic, outerhtml_dynamic, dynamic_tab_url
**Analysis Date**: 2026-02-06

## Executive Summary

After thorough analysis of all flagged patterns and related code, **no exploitable XSS or code injection vulnerabilities were found** in this extension. All triage-flagged patterns resolve to either standard library code (React SVG polyfill, CountUp.js), data collection normalization on detached DOM elements, or hardcoded URL construction.

The extension does, however, perform extensive AI conversation harvesting from six major AI chat platforms plus server-configured targets, which represents a significant privacy concern but is not a code vulnerability in the traditional sense.

---

## Triage Flag Analysis

### Flag 1: innerhtml_dynamic (content.js:8304, frames.js:4897)

**Pattern**: `s.innerHTML = u.content, f = pe(s).innerHTML, s.remove()`

**Context**: This occurs inside `RemoteWidget.parseThread()` (class `xo` in content.js, class `dr` in frames.js). The `RemoteWidget` is configured via server-pushed JSONata expressions and CSS selectors to scrape third-party chat widgets on arbitrary websites.

**Data Flow**:
1. `fn()` (content.js:4285) recursively builds a JSON tree from page DOM elements
2. A JSONata expression evaluates the DOM tree to extract chat messages
3. For non-"User" messages, the content string is set as innerHTML on a **detached** `document.createElement("div")`
4. `pe()` (content.js:4232) strips all attributes except `href`, `src`, `alt` recursively
5. The sanitized `.innerHTML` string is read back and stored as data
6. The detached div is immediately removed
7. Data is sent to background script via `chrome.runtime.sendMessage`

**Verdict**: NOT VULNERABLE. The innerHTML is set on a detached element that is never inserted into the page DOM. `<script>` tags do not execute via innerHTML. Event handler attributes (onerror, onload, etc.) are stripped by `pe()`. While `javascript:` URIs in `href`/`src` survive sanitization, the element is never rendered or interacted with -- the innerHTML is read back as a string for data exfiltration only.

### Flag 2: innerhtml_dynamic (content.js:6949)

**Pattern**: `d.innerHTML = \`\n ${s} { display: none !important; }\n\``

**Context**: This occurs in `ChatGPTWidget.getSources()`. The variable `s` is a hardcoded CSS class name string (`.bg-token-sidebar-surface-primary`), not user/page-controlled input.

**Verdict**: NOT VULNERABLE. Static CSS string.

### Flag 3: outerhtml_dynamic (content.js:4298, frames.js:4311)

**Pattern**: `e.outerHTML = t.outerHTML || ""`

**Context**: Inside `fn()`, the DOM tree serialization function. `e` is a **plain JavaScript object** `{id, tagName, textContent, classList, attributes, children}`, NOT a DOM element. `t` is the DOM element being serialized. This assigns the outerHTML string as a property on the data object.

**Verdict**: NOT VULNERABLE. This is object property assignment, not DOM manipulation.

### Flag 4: dynamic_tab_url (background.js:4111)

**Pattern**: `chrome.tabs.create({ url: \`${z}/onboarding/mode?completed=true\` })`

**Context**: `z` is `Ct[$].feHost` where `Ct` is a static config object mapping environment names to hardcoded URLs:
- development: `http://localhost:3000`
- staging: `https://gener8.tech`
- production: `https://gener8ads.com`

**Verdict**: NOT VULNERABLE. Hardcoded URL with no user-controlled input.

---

## Additional Patterns Examined

### popup.js innerHTML (lines 2728, 2733, 6373, 6432, 16253)

All instances are standard third-party library code:
- **Lines 2728/2733**: React SVG namespace innerHTML polyfill (standard React internals)
- **Line 6373**: React's `dangerouslySetInnerHTML` validation helper
- **Line 6432**: React script element creation workaround
- **Line 16253**: CountUp.js library rendering formatted numbers

**Verdict**: NOT VULNERABLE. All standard library code.

### CSS Selector Injection (content.js:6821, 6940)

`document.querySelector(\`[data-message-id="${e}"]\`)` where `e` comes from `getAttribute("data-message-id")` on ChatGPT page elements. This is a potential CSS selector injection, but:
- The value originates from the same page being queried
- The result is only used for read-only DOM traversal
- No privileged operations depend on the query result
- An attacker would need XSS on chatgpt.com to control this value, at which point they already have full page control

**Verdict**: NOT VULNERABLE (theoretical only, no practical impact).

---

## Privacy/Behavioral Observations (Not Vulnerabilities)

While not traditional code vulnerabilities, the following behaviors are noteworthy:

### AI Conversation Harvesting

The extension actively scrapes AI chat conversations from:
- **ChatGPT** (chatgpt.com, chat.openai.com) -- class `jr`
- **Claude** (claude.ai) -- class `Hr`
- **Gemini** (gemini.google.com) -- class `br`
- **Perplexity** (perplexity.ai) -- class `$r`
- **Grok** (grok.com) -- class `Ur`
- **DeepSeek** (chat.deepseek.com) -- class `Nr`
- **Google AI Mode** (google.com/search?udm=50) -- classes `Fr`/`_r`
- **Server-configured targets** via JSONata expressions (class `xo`/RemoteWidget)

Data collected includes: conversation content (prompts and responses), model names, tools used, thinking/reasoning traces, source citations, timestamps, and page metadata.

### Customer Support Widget Scraping

The extension also scrapes interactions from customer support chat widgets:
- BigSurAI, Gladly, Gorgias, Kustomer, RepAI, ShopifyInbox, Sierra
- Plus remotely-configured chat widgets via server-pushed selectors

### Data Exfiltration Endpoints

Collected data is sent to `apollo.gener8ads.com` via:
- `POST datavault/chat-agent/events` -- individual chat messages
- `POST datavault/chat-agent/snapshots` -- conversation snapshots
- `POST datavault/website/technologies/interactions` -- website interactions

### Consent Mechanism

A server-side consent check (`analytics/consents` API) gates data transmission in the background script. However:
- The content script always collects data regardless of consent status
- The consent decision is fetched from Gener8's server, not stored locally
- The extension's stated purpose ("be rewarded for your data") suggests this data collection is the core business model

---

## Conclusion

**No exploitable vulnerabilities were identified.** All triage-flagged patterns are false positives:
- innerHTML on detached elements for data normalization (not XSS)
- outerHTML property assignment on data objects (not DOM manipulation)
- Hardcoded tab URL construction (not injectable)

The extension's primary security concern is its extensive data collection of AI conversations and customer support interactions, which is a privacy/design issue rather than a code vulnerability.
