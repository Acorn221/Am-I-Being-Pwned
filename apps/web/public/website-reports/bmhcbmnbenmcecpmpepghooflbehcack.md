# Security Analysis: Liner - ChatGPT AI Copilot for Web YouTube and PDF

**Extension ID**: bmhcbmnbenmcecpmpepghooflbehcack
**Users**: ~300,000
**Risk Level**: LOW
**Analysis Date**: 2026-02-06

## Executive Summary

Liner is a legitimate productivity extension providing AI-powered chat, web highlighting, and Kindle integration features. No malicious behavior was detected. The extension operates as advertised with transparent data collection for its core functionality.

## Manifest Analysis

### Permissions (Justifiable)
- `tabs` - Required for page context awareness
- `clipboardWrite` - For copying highlights/text
- `storage` - User preferences and highlights storage
- `scripting` - Content script injection (standard)
- `contextMenus` - Right-click menu integration
- `host_permissions: *://*/*` - Required for highlight feature on all websites

### Content Security Policy
Standard MV3 CSP (no modifications).

## Background Service Worker Analysis

### Network Endpoints (All Legitimate)
**Primary Backend**:
- `api.liner.com` - Main API server
- `lks.getliner.com` - Liner Knowledge System (recommendation engine)
- `app.liner.com` - Web application
- `static.getliner.com` - Static assets/config

**Remote Configuration**:
```javascript
// backgrounds/endpoints.js:637
function getExtensionConfigFromGCP(callback) {
  http(SERVER.GCP_CONFIG, '/config.json', 'GET', {}, (json) => {
    callback(json);
  });
}
```
**Purpose**: Feature flags and project configurations. No evidence of malicious config usage.

**Analytics**:
- Amplitude analytics (`event-hub.liner.com/amplitude2-server`)
- Standard product telemetry (usage tracking, not PII harvesting)

### Authentication & Session Management
Uses `sidCookie` (session ID) obtained via:
```javascript
// Fetches auth cookie from getliner.com domain
fetchWith('https://getliner.com/auth/cookie', { method: 'GET' })
```
Session tokens stored in `chrome.storage.local`, not exfiltrated.

## Content Script Analysis (`liner-core.be.js`)

### DOM Interactions
- **Highlight rendering**: Injects UI overlays for user-created highlights
- **Text selection**: Captures user-selected text for highlight/AI features
- **No keylogging**: Input event listeners limited to UI interaction (no credential capture)

### Page Data Collection
**What's collected**:
1. User-initiated highlights (text selections)
2. Page metadata (title, URL, language)
3. Page content sent to AI copilot ONLY when user explicitly queries it

**Code reference** (backgrounds/chatApis.js:335-344):
```javascript
postAnswerUserQuery: async ({ tabId, data }) => {
  const { query, lang, html, url, userId, uuid } = data;

  const body = JSON.stringify({
    uniqueId: userId >= 0 ? `${userId}` : uuid,
    query: query.text,  // User's explicit question
    lang,
    html,  // Page content for context
    url,
  });
}
```
**Verdict**: Page HTML sent to backend ONLY during AI copilot usage. Not passive surveillance.

## Third-Party Integrations

### Amazon Kindle Sync (Legitimate Feature)
```javascript
// backgrounds/endpoints.js:743-756
function getReadAmazonNotebook() {
  return fetch('https://read.amazon.com/notebook', { method: 'GET' });
}

function getAmazonDpBook(bookAsin, state) {
  return fetch('https://read.amazon.com/notebook?asin=${bookAsin}...', { method: 'GET' });
}
```
**Purpose**: Sync Kindle highlights to Liner library. User-initiated feature requiring Amazon login.

**Background Manager** (backgrounds/handler.js:39-274):
- `LINER_KINDLE_SYNC_MANAGER` class handles sync workflow
- Scrapes Amazon's notebook HTML to extract highlights
- Replaces Amazon signin page if not authenticated (lines 104-116)
- Silent auto-sync triggers daily or on `app.liner.com/my-highlights` visit (lines 257-273)

**Verdict**: Legitimate productivity feature. No credential theft—uses Amazon's existing auth.

### Google Autocomplete
```javascript
AUTO_COMPLETE_GOOGLE: 'https://suggestqueries.google.com/complete'
```
Standard Google suggestion API for search features.

## Cookie Handling

**Amplitude SDK** (backgrounds/amplitude.js:660-710):
```javascript
var ca = document.cookie.split(';');  // Read-only access
document.cookie = str;  // Sets own amplitude_* cookies
```
**Verdict**: Standard analytics library behavior. No third-party cookie harvesting.

## Absence of Malicious Patterns

### ✅ No XHR/Fetch Hooking
- Uses standard `fetch()` calls—no prototype patching
- Amplitude SDK present but for analytics only (not market intelligence like Sensor Tower)

### ✅ No Extension Enumeration/Killing
- No `chrome.management` usage
- No competitor extension targeting

### ✅ No AI Conversation Scraping
- AI copilot sends page content ONLY on explicit user queries
- No passive scraping of ChatGPT/Claude/Gemini sessions

### ✅ No Residential Proxy Infrastructure
- No proxy-related code
- No bandwidth selling/tunnel APIs

### ✅ No Ad/Coupon Injection
- Content script limited to highlight UI
- No DOM manipulation for ads/affiliate links

### ✅ No Obfuscation
- Clean, readable JavaScript (jsbeautifier processed)
- Korean comments indicate in-house development

## Data Flow Summary

### User → Extension → Backend
1. **Highlights**: Selected text + page metadata → `api.liner.com/pages`
2. **AI Queries**: User question + page context → `api.liner.com/platform/copilot/v3/answer`
3. **Kindle Sync**: Amazon highlight HTML → `api.liner.com/user/integration/kindle/book/highlights`
4. **Analytics**: Feature usage events → `event-hub.liner.com/amplitude2-server`

### Extension → Third Parties
1. **Amazon**: Read-only access to `read.amazon.com/notebook` (Kindle highlights)
2. **Google**: Autocomplete queries to `suggestqueries.google.com`
3. **IPIFY**: IP address lookup (`api.ipify.org`) - for geolocation

## Privacy Considerations

### Moderate Privacy Impact
1. **Page Content Sharing**: Full HTML sent to Liner servers when using AI copilot on a page
2. **Browsing History**: URLs of highlighted pages tracked (inherent to highlight sync)
3. **Kindle Library**: Book titles and highlights uploaded to Liner

### Mitigations
- Features are opt-in (require explicit user action)
- No passive data collection detected
- Data sent to first-party Liner infrastructure (not third-party marketplaces)

## Comparison to Known Threats

| Feature | Liner | StayFree/StayFocusd (Sensor Tower) | Verdict |
|---------|-------|-------------------------------------|---------|
| XHR/Fetch Hooks | ❌ None | ✅ Pathmatics SDK on ALL pages | CLEAN |
| AI Scraping | Context on demand | Passive ChatGPT/Gemini scraping | CLEAN |
| Market Intelligence | ❌ None | ✅ Ad creative harvesting | CLEAN |
| Remote Config | Feature flags only | Behavior modification | LOW RISK |
| Extension Killing | ❌ None | ✅ Competitor targeting | CLEAN |

## False Positives Confirmed

1. **Amplitude SDK cookie access**: Standard analytics (not third-party harvesting)
2. **Amazon fetch()**: Legitimate Kindle integration (not credential theft)
3. **Remote GCS config**: Feature flags (not kill switches/malicious payloads)
4. **Page HTML in AI requests**: Expected for context-aware AI (not surveillance)

## Recommendations

### For Users
- **Safe to Use**: Extension operates as advertised
- **Privacy-Conscious Users**: Be aware page content is sent to Liner when using AI copilot
- **Kindle Feature**: Only enable if comfortable with Liner storing your highlights

### For Developers
1. **Reduce permissions**: Consider optional host permissions for highlight-only users
2. **Transparency**: Add privacy notice explaining when page content is sent to servers
3. **Kindle sync**: Make silent auto-sync configurable (currently triggers automatically)

## Technical Evidence Summary

### Code Locations
- **Main backend logic**: `/backgrounds/handler.js` (2795 lines)
- **API endpoints**: `/backgrounds/endpoints.js` (1821 lines)
- **AI chat APIs**: `/backgrounds/chatApis.js` (1010 lines)
- **Content script**: `/liner-core.be.js` (126,112 lines - includes bundled libraries)
- **Analytics**: `/backgrounds/amplitude.js` (5921 lines - standard Amplitude SDK)

### Network Domains (All First-Party)
```
api.liner.com
lks.getliner.com
app.liner.com
static.getliner.com
event-hub.liner.com
ads.getliner.com
```

### Third-Party Integrations
```
read.amazon.com (Kindle highlights)
suggestqueries.google.com (autocomplete)
api.ipify.org (IP geolocation)
```

## Conclusion

**VERDICT: CLEAN**

Liner is a legitimate productivity extension with no evidence of:
- Market intelligence data harvesting
- AI conversation surveillance
- Extension manipulation/killing
- Ad injection or affiliate hijacking
- Residential proxy operations
- Credential theft

The extension's data collection is proportional to its advertised features (AI copilot, highlight sync, Kindle integration). Privacy-conscious users should note that page content is sent to Liner servers when actively using AI features, but this is disclosed through the product's nature as an "AI Copilot."

**Risk Rating Justification**: LOW - Standard SaaS product data flows with no adversarial behavior detected.
