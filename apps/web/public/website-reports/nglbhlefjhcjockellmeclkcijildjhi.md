# Vulnerability Report: Lingualeo Language Translator

## Metadata
- **Extension ID**: nglbhlefjhcjockellmeclkcijildjhi
- **Extension Name**: Lingualeo Language Translator
- **Version**: 3.1.2
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Lingualeo Language Translator is a legitimate language learning extension that translates words and phrases on web pages. The extension collects authentication cookies and sends page content to Lingualeo's API servers for translation and dictionary management. While the extension's data collection is disclosed and aligned with its stated functionality, there are minor privacy concerns around the extensive permissions and automatic page text extraction that warrant a MEDIUM risk classification.

The extension properly uses authenticated API endpoints (api.lingualeo.com) for its language translation services and includes proper error handling. The cookie access is necessary for maintaining user authentication with the Lingualeo service. However, the extension requests broad permissions (<all_urls> host permissions and cookies across all domains) which could be more narrowly scoped.

## Vulnerability Details

### 1. MEDIUM: Broad Permission Scope
**Severity**: MEDIUM
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests `<all_urls>` for both content scripts and host permissions, along with cookies permission across all domains. While necessary for the extension's functionality (translating text on any page), this is more privilege than strictly required.

**Evidence**:
```json
"host_permissions": [
  "<all_urls>"
],
"content_scripts": [{
  "matches": ["<all_urls>"],
  "js": ["readability/readability.js", "googleDocsUtil/googleDocsUtil.js", "guessLanguage/guessLanguage.js", "content.js"]
}],
"permissions": [
  "storage",
  "tabs",
  "cookies",
  "notifications",
  "contextMenus",
  "activeTab"
]
```

**Verdict**: This is standard for translation extensions that need to work on all pages, but it does grant broad access to user browsing data.

### 2. MEDIUM: Page Content Extraction
**Severity**: MEDIUM
**Files**: content.js (lines 85-105), popup/popup.js (lines 202-222)
**CWE**: CWE-359 (Exposure of Private Personal Information)
**Description**: The extension extracts full page content using the Readability library and sends it to Lingualeo servers when users want to learn materials. While this appears to be opt-in functionality, the automatic language detection feature processes page text on every page load.

**Evidence**:
```javascript
// content.js - Automatic language detection
function detectLanguage(tabChanged = false) {
    chrome.storage.local.get(null, settings => {
        const { sourceLanguage, targetLanguage, showHints, knownLanguages, learningLanguage } = settings;
        const pageText = document.body.innerText.replace(/(<([^>]+)>)/gi, "");
        const pageTitle = document.title;
        const pageContent = new Readability(document.cloneNode(true)).parse();
        chrome.i18n.detectLanguage(
            pageText, langObj => {
                chrome.storage.local.set({sourceLanguage: languages.includes(l) ? l : 'unknown', pageText: pageContent.textContent.replace(/^\s+/g, ''), pageTitle})
                // ...
            }
        )
    });
}

// popup/popup.js - Sending page content to server
learnMaterial = () => {
    const data = JSON.stringify({
        "apiVersion":"1.0.1",
        "port": 1001,
        "content":[{
            "contentId":null,
            "valueList":{
                "targetLang": sourceLanguage,
                "contentName": pageTitle,
                "contentText":pageText,
                // ...
            }
        }]
    })
    fetch(`https://${host}/SetJungleContent`, {method: 'POST', body: data, headers: { ... }})
}
```

**Verdict**: The automatic language detection stores page content locally, and the server upload requires explicit user action ("Learn Material" button). This is legitimate functionality for a language learning tool, though the automatic page text extraction on all pages is privacy-invasive.

### 3. LOW: Cookie Access Across All Domains
**Severity**: LOW
**Files**: storage.js (lines 65-77, 89-105)
**CWE**: CWE-522 (Insufficiently Protected Credentials)
**Description**: The extension accesses cookies to maintain user authentication with Lingualeo services. It specifically monitors and reads the "remember" and "userid" cookies from lingualeo.com domains, but has the permission to access cookies on all domains due to the broad permissions scope.

**Evidence**:
```javascript
export const getAuth = () => {
    chrome.storage.local.get(null, restored => {
        const clearHost = restored.host.split('.')[1] + '.' + restored.host.split('.')[2];
        chrome.cookies.get({url: `https://${clearHost}/ru/dashboard`, name: "userid"}, cookie => {
            chrome.storage.local.set({userid: cookie ? cookie.value : ''})
            chrome.cookies.get({url: `https://${clearHost}/ru/dashboard`, name: "remember"}, cookie => {
                chrome.storage.local.set({remember: cookie ? cookie.value : ''})
                // ...
            })
        });
    });
}
```

**Verdict**: The extension only accesses Lingualeo-specific cookies in practice, but the declared permissions allow broader access. This is a minor concern since the code shows responsible use.

## False Positives Analysis

**Obfuscation Flag**: The static analyzer flagged this extension as "obfuscated." However, examination of the deobfuscated code shows this is standard webpack-bundled code with minification, not true obfuscation intended to hide malicious behavior. The code is readable and follows standard patterns for a translation extension.

**Network Communication**: All fetch requests go to legitimate Lingualeo API endpoints (api.lingualeo.com) and are used for:
- Word/phrase translation (gettranslates)
- Adding words to user's personal dictionary (SetWords)
- User profile retrieval (getUserProfile)
- Learning material upload (SetJungleContent)

These are all expected and disclosed behaviors for a language learning extension.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://api.lingualeo.com/gettranslates | Translate words/phrases | Selected text, source/target language | LOW |
| https://api.lingualeo.com/SetWords | Add words to dictionary | Word, translation, context, user cookies | MEDIUM |
| https://api.lingualeo.com/getUserProfile | Get user profile data | User ID, remember cookie | LOW |
| https://api.lingualeo.com/SetJungleContent | Upload learning materials | Page title, page text, user cookies | MEDIUM |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
This is a legitimate language learning extension from a known service (Lingualeo). The extension's behavior aligns with its stated purpose of translating text and building a personal dictionary. However, several privacy concerns warrant a MEDIUM risk rating:

1. **Broad Permissions**: The extension requests access to all websites and cookies, which is broader than ideal though necessary for its functionality
2. **Page Content Collection**: Automatic extraction of page text for language detection, though the data is stored locally unless the user explicitly uploads it
3. **User Data Sent to Remote Server**: Selected text, translations, and optionally full page content are sent to Lingualeo's servers with user authentication

**Mitigating Factors**:
- All network requests go to legitimate Lingualeo API endpoints
- The extension is from a known language learning service with ~100K users
- Cookie access is limited to Lingualeo domains in practice
- Page content upload to server requires explicit user action
- No evidence of data exfiltration to third parties
- Proper error handling and user consent patterns

**Recommendation**: Users should be aware that this extension processes page content for language detection and sends selected text and translations to Lingualeo's servers. Users concerned about privacy should disable automatic language detection in settings and be selective about which pages they use for translation or material learning.
