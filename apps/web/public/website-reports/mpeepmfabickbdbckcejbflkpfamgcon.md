# Vulnerability Report: Grammar Checker

## Extension Metadata
- **Extension ID**: mpeepmfabickbdbckcejbflkpfamgcon
- **Extension Name**: Grammar Checker
- **Version**: 1.0.10
- **User Count**: ~40,000 users
- **Developer**: Linang Data
- **Manifest Version**: 3

## Executive Summary

Grammar Checker is a browser extension that provides grammar, spelling, and style checking functionality. The extension utilizes the public LanguageTool API for grammar analysis and operates primarily through a popup interface.

**Key Finding**: The extension dynamically loads untrusted HTML content from remote servers (`linangdata.com/servedcontent/*.php`) and directly injects it into the popup DOM via `innerHTML`. This creates a **HIGH SEVERITY** vulnerability as the remote server could inject malicious scripts, perform ad injection, or execute arbitrary code within the extension context.

## Vulnerability Details

### 1. CRITICAL: Remote Code Execution via Dynamic HTML Injection

**Severity**: HIGH
**Location**: `/app.js` lines 17-47
**CVSS**: 8.5 (High)

**Description**: The extension makes three separate jQuery GET requests to PHP endpoints on `linangdata.com` and directly injects the responses into the popup DOM using jQuery's `.html()` method (which uses `innerHTML` internally). This pattern allows the remote server to inject arbitrary HTML and JavaScript.

**Vulnerable Code**:
```javascript
$.get( `https://linangdata.com/servedcontent/dynamiclinks.php?source=grammarChecker${uuid}`, function( data ) {
  $( "#links" ).html( data );  // DANGEROUS: Direct HTML injection

  $(".navopentab").unbind().on("click", function(e){
    e.preventDefault();
    var link = $(this).attr('href');
    chrome.tabs.create({url:link});
  })
});

$.get( `https://linangdata.com/servedcontent/bannertop.php?source=grammarChecker${uuid}`, function( data ) {
  if (data) {
    $( "#banner-top" ).html( data ).removeClass('hidden');  // DANGEROUS: Direct HTML injection
  }
  // ... click handlers
});

$.get( `https://linangdata.com/servedcontent/bannerbottom.php?source=grammarChecker${uuid}`, function( data ) {
  if (data) {
    $( "#banner-bottom" ).html( data ).removeClass('hidden');  // DANGEROUS: Direct HTML injection
  }
  // ... click handlers
});
```

**Attack Vectors**:
1. **Man-in-the-Middle**: If HTTPS is compromised or downgraded, an attacker could inject malicious content
2. **Compromised Server**: If `linangdata.com` is compromised, malicious scripts could be served to all 40,000 users
3. **Malicious Developer**: The developer could intentionally serve malicious content (ads, trackers, phishing, etc.)
4. **No CSP Protection**: The manifest lacks Content Security Policy, allowing inline scripts if injected

**Exploitation Impact**:
- Execute arbitrary JavaScript in extension popup context
- Access extension APIs (contextMenus, chrome.tabs)
- Inject malicious ads or phishing content
- Steal user data being checked for grammar
- Redirect users to malicious sites via chrome.tabs.create
- Track user behavior via embedded scripts

**Verdict**: This is a design flaw that violates Chrome extension security best practices. Even if the current server is benign, the attack surface exists and could be exploited.

### 2. MEDIUM: No Content Security Policy

**Severity**: MEDIUM
**Location**: `/manifest.json`
**CVSS**: 5.0 (Medium)

**Description**: The extension's manifest does not define a Content Security Policy (CSP). While MV3 extensions have some default protections, the absence of an explicit CSP leaves the door open for script injection vulnerabilities.

**Missing CSP**:
```json
{
  "manifest_version": 3,
  "name": "Grammar Checker",
  // ... no "content_security_policy" field
}
```

**Impact**:
- If HTML is injected via the vulnerability above, inline scripts could execute
- No protection against unsafe-eval or unsafe-inline
- No restriction on external script sources

**Verdict**: Combined with the dynamic HTML injection vulnerability, this amplifies the attack surface.

### 3. LOW: User Data Transmitted to External Service

**Severity**: LOW
**Location**: `/app.js` lines 173-197, `/background.js` lines 25-35
**CVSS**: 3.5 (Low)

**Description**: User text is sent to two external services for processing:

1. **LanguageTool API** (`languagetool.org/api/v2/check`) - Public grammar checking service
2. **Linangdata.com** (`linangdata.com/grammar-checker/`) - Developer's website (via context menu)

**Code**:
```javascript
// Sends user text to LanguageTool API
var jqxhr = $.post( "https://languagetool.org/api/v2/check", formData,  function( data ) {
  // Process grammar results
});

// Context menu sends selected text to linangdata.com
function openGrammarTab(info, tab) {
  var selectionText = info.selectionText.trim();
  selectionText = LZString.compressToEncodedURIComponent(selectionText);
  var url = 'https://linangdata.com/grammar-checker/' + selectionText;
  chrome.tabs.create({ url });
}
```

**Privacy Considerations**:
- LanguageTool is a well-known, legitimate grammar service (similar to Grammarly)
- Text is compressed using LZ-String before transmission
- No evidence of data being stored or misused
- This is expected functionality for a grammar checker

**Verdict**: LOW risk - This is legitimate functionality for the extension's stated purpose. However, users should be aware their text is sent to external services.

## False Positives Analysis

| Pattern | Location | Reason | False Positive? |
|---------|----------|--------|-----------------|
| `innerHTML` in jQuery | libs/jquery-3.5.1.min.js | Standard jQuery library functionality | YES |
| `innerHTML` in Bootstrap | libs/bootstrap-5.0.1/js/bootstrap.bundle.min.js | Standard Bootstrap tooltip/popover rendering | YES |
| `Function()` in underscore | libs/underscore-min.js | Templating engine (controlled context) | YES |
| `eval` references | libs/*.js | Third-party library internals, not executed with user input | YES |
| `chrome.tabs.create` | app.js, background.js | Opens tabs to user-selected or extension-controlled URLs | PARTIAL - See dynamic content issue |

## API Endpoints and External Connections

| Endpoint | Purpose | Method | Risk Level |
|----------|---------|--------|-----------|
| `https://languagetool.org/api/v2/check` | Grammar checking API | POST | LOW - Legitimate service |
| `https://linangdata.com/grammar-checker/` | Full-page grammar checker | GET (new tab) | LOW - Developer's site |
| `https://linangdata.com/servedcontent/dynamiclinks.php` | Dynamic navigation menu | GET | **HIGH - Untrusted content injection** |
| `https://linangdata.com/servedcontent/bannertop.php` | Top banner ads/content | GET | **HIGH - Untrusted content injection** |
| `https://linangdata.com/servedcontent/bannerbottom.php` | Bottom banner ads/content | GET | **HIGH - Untrusted content injection** |

## Data Flow Summary

1. **User Input Flow**:
   - User types/pastes text into popup → Stored in localStorage (compressed with LZ-String)
   - User clicks "Check Grammar" → Text sent to LanguageTool API via POST
   - Results returned → Displayed with highlighting and suggestions

2. **Dynamic Content Flow**:
   - Popup opens → Three GET requests to `linangdata.com/servedcontent/*.php`
   - Server responses → **Directly injected into DOM via `.html()`** (VULNERABLE)
   - Injected HTML contains navigation links and banner content

3. **Context Menu Flow**:
   - User selects text → Right-click → "Check Grammar"
   - Selected text compressed → Opened in new tab at `linangdata.com/grammar-checker/`

## Permissions Analysis

**Declared Permissions**:
- `contextMenus` - Used to add right-click grammar check option (LEGITIMATE)

**Effective Permissions** (no host_permissions declared):
- No access to web page content (no content scripts)
- No access to user browsing data
- No access to cookies, history, or downloads

**Assessment**: Permission footprint is minimal and appropriate for stated functionality. The security issue stems from design choices, not over-permissioning.

## Overall Risk Assessment

**Risk Level**: **HIGH**

**Rationale**:
1. **Remote Code Execution Vector**: The dynamic HTML injection from `linangdata.com/servedcontent/*.php` creates a critical attack surface affecting all 40,000 users
2. **No CSP Mitigation**: Lack of Content Security Policy means injected scripts could execute
3. **Extension Context Access**: Malicious injected code would have access to extension APIs (chrome.tabs, contextMenus)
4. **Trust Dependency**: Security entirely depends on `linangdata.com` server integrity and HTTPS security

**Why HIGH instead of CRITICAL**:
- Limited permission scope (only contextMenus, no webRequest or broad host access)
- No content scripts (cannot access user's web pages)
- Exploitation requires server compromise or MITM attack (not purely client-side)
- Core functionality (grammar checking via LanguageTool) is legitimate

**Mitigating Factors**:
- Extension has been published since at least 2018 (based on copyright)
- Uses legitimate LanguageTool API for grammar checking
- No evidence of current malicious behavior
- Developer identity is known (Linang Data)

## Recommendations

1. **CRITICAL**: Remove dynamic HTML loading from remote servers. Embed static navigation and content in the extension package.

2. **HIGH**: Implement Content Security Policy in manifest:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```

3. **MEDIUM**: If remote content is required, use JSON API responses and build DOM programmatically instead of innerHTML injection.

4. **LOW**: Add privacy policy disclosure about data transmission to LanguageTool and linangdata.com.

## Verdict

**RISK LEVEL: HIGH**

The Grammar Checker extension performs its stated function legitimately using the LanguageTool API. However, the practice of loading and injecting untrusted HTML from remote PHP endpoints (`linangdata.com/servedcontent/*.php`) directly into the extension popup creates a serious security vulnerability. While the extension is not currently behaving maliciously, the design pattern allows for potential remote code execution if the server is compromised or if the developer turns malicious.

This vulnerability affects approximately 40,000 users and could be exploited to inject ads, track users, phish credentials, or execute arbitrary code within the extension context.
