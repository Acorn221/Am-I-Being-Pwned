# Vulnerability Report: Bkav Pro plugin - Tiện ích bảo vệ trình duyệt

## Metadata
- **Extension ID**: kjomkjjpbjeennhagfmlahfnlgleecmn
- **Extension Name**: Bkav Pro plugin - Tiện ích bảo vệ trình duyệt
- **Version**: 2.1.30
- **Users**: ~60,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Bkav Pro plugin is a Vietnamese browser protection extension published by Bkav Corporation, a Vietnamese cybersecurity company. While the extension appears to provide legitimate antivirus and phishing protection features, it implements several concerning data exfiltration patterns and vulnerable coding practices. The extension communicates with a local native application via WebSocket (localhost:2345), sending complete page HTML content, browsing history, search queries, and Facebook comment data to this local application. The extension also contains XSS vulnerabilities through unsafe use of innerHTML and intercepts XHR responses on Facebook to analyze comment content.

The primary security concerns are: (1) extensive data exfiltration to local WebSocket server including full page HTML, user search queries, and social media activity, (2) XSS vulnerabilities through unsafe innerHTML usage without sanitization, (3) interception and analysis of all Facebook XHR responses, and (4) injection of warning banners into Facebook comments. Given the disclosed nature of this being a security product and the local-only communication, the risk is HIGH but not CRITICAL.

## Vulnerability Details

### 1. HIGH: Data Exfiltration to Local WebSocket Server

**Severity**: HIGH
**Files**: js/filter.js, js/contentscripts.js
**CWE**: CWE-359 (Exposure of Private Information)

**Description**: The extension establishes a WebSocket connection to `ws://localhost:2345/` and exfiltrates extensive browsing data to a local native application. This includes complete page HTML content, Google search queries, page titles, URLs, and Facebook comment content with links.

**Evidence**:

```javascript
// filter.js lines 68-90
function sendMs(strMsg) {
    if (version == 1) {
        if(m_cWebsocket == null) {
            m_cWebsocket = new WebSocket("ws://localhost:2345/");
            // ... setup handlers
        }
    }
    if (m_cWebsocket.readyState != 1) {
        reconnect();
        return false;
    }
    m_cWebsocket.send(strMsg);
    return true;
}

// contentscripts.js lines 21-29 - Sends full page HTML
$(document).ready(function() {
    var htmlS = "";
    if(window.location.href.search("https://www.facebook.com/") == -1) {
        if(document.getElementsByTagName('html')[0] != undefined)
            htmlS = document.getElementsByTagName('html')[0].innerHTML;
    } else {
        htmlS = getHTMLFb();
    }
    var szJS = {};
    szJS.htmlSe = window.btoa(unescape(encodeURIComponent(htmlS)));
    szJS.msg = "SOURCE";
    chrome.runtime.sendMessage(JSON.stringify(szJS), function(response) {});
});

// filter.js lines 34-44 - Exfiltrates page content and search queries
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    request = JSON.parse(request);
    if(request.msg == "SOURCE" || request.msg == "XHR_RESPONSE") {
        var obMsgSendJS = {};
        obMsgSendJS.msg = request.msg;
        obMsgSendJS.tabID = sender.tab.id;
        obMsgSendJS.url = window.btoa(unescape(encodeURIComponent(sender.tab.url)));
        obMsgSendJS.keyword = request.htmlSe;  // Full HTML content
        obMsgSendJS.tittle = request.tittle;
        obMsgSendJS.brower = sBrower;
        sendMs(JSON.stringify(obMsgSendJS));
    }
});

// filter.js lines 45-54 - Exfiltrates Facebook comment data
else if(request.msg == "CHECK_FB_COMMENT") {
    var objMsg = {};
    objMsg.msg = request.msg;
    objMsg.tabID = sender.tab.id;
    objMsg.content = utf16tohex(request.content).toLowerCase();
    objMsg.url = request.url;
    objMsg.hrefs = request.hrefs.toLowerCase();
    sendMs(JSON.stringify(objMsg));
}
```

**Verdict**: This is a HIGH severity issue. The extension sends complete page HTML, browsing URLs, search queries, and Facebook activity to a local WebSocket server. However, this appears to be the documented behavior of a browser security product that requires a local native application for malware/phishing scanning. The data stays local (localhost) rather than being sent to remote servers. Users installing a "browser protection" product would reasonably expect this type of scanning behavior, though the extent of data collection is concerning.

### 2. HIGH: Cross-Site Scripting (XSS) Vulnerability via innerHTML

**Severity**: HIGH
**Files**: js/contentscripts.js
**CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)

**Description**: The extension receives messages from the background script and directly injects HTML content into the DOM using innerHTML without any sanitization. This creates an XSS vulnerability if the WebSocket server (native application) is compromised or malicious.

**Evidence**:

```javascript
// contentscripts.js lines 53-64
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.msg == "SAFEDOWNLOAD_DATA") {
        ProcessMsgShowResult(request.data);
    } else if(request.msg == "FakeFB") {
        var m_objWrapperDiv2 = null;
        m_objWrapperDiv2 = $('<div id="div123"></div>');
        var sData = b64DecodeUnicode(request.data);
        m_objWrapperDiv2.innerHTML = sData;  // Unsafe innerHTML
        $("body").append(sData);  // Injecting unvalidated HTML
    }
});

// contentscripts.js lines 186-309 - AddSafeDownloadBox function
function AddSafeDownloadBox(strData) {
    // ... builds HTML string with external data
    strHTML += "<a style = 'color:#2518B5;...' href='";
    if (_link.indexOf("http://") < 0 && _link.indexOf("https://") < 0)
        strHTML += "http://";
    strHTML += _link;  // Unsanitized link injection
    strHTML += "'>";
    strHTML += title[i];  // Unsanitized title injection
    // ...
    _BoxBkavSafeRun.innerHTML = strHTML;  // Unsafe innerHTML
}
```

**Verdict**: HIGH severity XSS vulnerability. The extension trusts data from the background script/WebSocket server without validation. If the native application is compromised, malicious HTML/JavaScript could be injected into any webpage the user visits. The attack surface is significantly flagged by ext-analyzer: "message data → *.innerHTML from: js/filter.js ⇒ js/contentscripts.js".

### 3. MEDIUM: XHR Response Interception and Monitoring

**Severity**: MEDIUM
**Files**: js/contentscripts.js
**CWE**: CWE-200 (Exposure of Sensitive Information)

**Description**: The extension intercepts all XMLHttpRequest responses on Facebook by monkey-patching the native XHR object, specifically targeting GraphQL API calls (`/api/graphql/`). This allows the extension to read all API responses, including private messages, friend data, and other sensitive information.

**Evidence**:

```javascript
// contentscripts.js lines 317-361
function getXHRResponse() {
    var xhrInsertScript = document.createElement('script');
    xhrInsertScript.type = 'text/javascript';
    xhrInsertScript.innerHTML = `
        (function() {
            var XHR = XMLHttpRequest.prototype;
            var send = XHR.send;
            var open = XHR.open;
            XHR.open = function(method, url) {
                this.url = url;
                return open.apply(this, arguments);
            }
            XHR.send = function() {
                this.addEventListener('load', function() {
                    if (typeof(this.url) === "string" && this.url.includes('/api/graphql/')) {
                        var docExist = document.getElementById('xhr_response');
                        if(!docExist) {
                            var dataDOMResponse = document.createElement('div');
                            dataDOMResponse.id = 'xhr_response';
                            dataDOMResponse.style.height = 0;
                            dataDOMResponse.style.overflow = 'hidden';
                            document.body.appendChild(dataDOMResponse);
                            if(this.response != null && this.response != '' && this.response != undefined)
                                document.getElementById('xhr_response').innerText = this.response;
                        }
                    }
                });
                return send.apply(this, arguments);
            };
        })();
    `;
    document.head.prepend(xhrInsertScript);
}

// contentscripts.js lines 379-401 - Sends intercepted XHR data to background
function sendXHRResponse() {
    var xhrContentResponse = document.getElementById('xhr_response');
    if (xhrContentResponse != undefined) {
        if(xhrContentResponse.innerText != '' && xhrContentResponse.innerText != null) {
            if(checkValidResponse(xhrContentResponse.innerText) == true) {
                var szJS = {};
                szJS.htmlSe = window.btoa(unescape(encodeURIComponent(xhrContentResponse.innerText)));
                szJS.msg = "XHR_RESPONSE";
                szJS.tittle = window.btoa(unescape(encodeURIComponent("Facebook")));
                chrome.runtime.sendMessage(JSON.stringify(szJS), function(response) {});
            }
            xhrContentResponse.innerText = '';
        }
    }
    requestIdleCallback(sendXHRResponse);
}
```

**Verdict**: MEDIUM severity. While XHR interception for security scanning is a legitimate use case for antivirus products, the broad scope of interception (all GraphQL calls) and the lack of transparency about what specific data is analyzed raises privacy concerns. The extension filters for `display_comments` in responses, suggesting it's focused on comment analysis for phishing detection, which aligns with its stated purpose.

### 4. MEDIUM: Facebook Comment Content Monitoring and Injection

**Severity**: MEDIUM
**Files**: js/contentscripts.js
**CWE**: CWE-602 (Client-Side Enforcement of Server-Side Security)

**Description**: The extension monitors all Facebook comments using MutationObserver, extracts comment text and links, sends them to the native application for analysis, and injects warning banners into comments flagged as spam/phishing. This modifies the user's Facebook experience without full transparency.

**Evidence**:

```javascript
// contentscripts.js lines 428-444 - Comment analysis
function CheckComment(comment) {
    var objMsg = {};
    objMsg.msg = "CHECK_FB_COMMENT";
    objMsg.content = getElementText(comment.children[1]);
    objMsg.url = comment.closest("[role='article']").getElementsByClassName("...")[0].href
    objMsg.hrefs = "";
    var CmtHrefs = comment.getElementsByTagName("a");
    if(CmtHrefs.length > 1) {
        for(var i = 1; i < CmtHrefs.length; i ++) {
            objMsg.hrefs += CmtHrefs[i].outerHTML;
            objMsg.hrefs += "||||||||";
        }
    }
    chrome.runtime.sendMessage(JSON.stringify(objMsg),function(response){});
}

// contentscripts.js lines 65-89 - Injects warning banner
else if(request.msg = "BLOCK_FB_COMMENT") {
    var comment = $("[href='" + request.url + "']")[0].closest("[role='article']").getElementsByClassName("...")[0];
    // ... extracts comment structure
    if(FbDarkTheme)
        comment.innerHTML= UserName.innerHTML + szAlertFakeCommentDark + CommentContent.innerHTML;
    else
        comment.innerHTML= UserName.innerHTML + szAlertFakeCommentLight + CommentContent.innerHTML;
}

// contentscripts.js lines 3-4 - Warning banner HTML
var szAlertFakeCommentLight = "<table class='Bkav_Detect_Phishing_Comment' ...>
    <span>Bình luận này có thể chứa nội dung spam, phản cảm hoặc lừa đảo!
    <a href='https://www.bkav.com.vn/tin-tuc-noi-bat/-/view-content/134066/...' target='_blank'>
    Tìm hiểu thêm</a></span></table>";
```

**Verdict**: MEDIUM severity. The comment monitoring and warning injection is a legitimate anti-phishing feature, but the implementation raises concerns: (1) All comment text and links are sent to the native application, (2) The modification of Facebook's UI could potentially be used to inject misleading warnings, (3) No clear opt-out mechanism is visible in the code. However, this appears to be the core advertised functionality of the extension.

### 5. LOW: Google Search Query Injection

**Severity**: LOW
**Files**: js/filter.js, js/contentscripts.js
**CWE**: CWE-200 (Exposure of Sensitive Information)

**Description**: The extension monitors Google search pages and injects "safe download" recommendations into search results. This involves extracting search queries and sending them to the local native application.

**Evidence**:

```javascript
// filter.js lines 199-234
function onUpdateListener(tabId, changeInfo, tab) {
    if (version == 1) {
        var obMsgSend = {};
        var strKeyword = null;
        if (changeInfo.status === 'complete') {
            if ((tab.url.indexOf("www.google.com") >= 0) && (tab.url.indexOf("url") < 0)) {
                strKeyword = getKeywordSearch(tab.url);
                if (strKeyword == null || strKeyword == undefined || strKeyword == "") {
                    return;
                }
                obMsgSend.msg = "GET_SAFEDOWNLOAD_DATA";
                obMsgSend.tabID = tabId;
                obMsgSend.keyword = window.btoa(unescape(encodeURIComponent(strKeyword)));
                sendMs(JSON.stringify(obMsgSend));
            }
        }
    }
}

// filter.js lines 260-296 - Extracts search query from URL
function getKeywordSearch(strURL) {
    var strKeyword = "";
    if (strURL.indexOf("www.google.com") == -1) {
        return "";
    }
    if (strURL.lastIndexOf("q=") == (strURL.indexOf("oq=") + 1)) {
        strKeyword = strURL.substring(strURL.indexOf("q=") + 2, strURL.indexOf("&", strURL.indexOf("q=")));
    } else {
        // ... extracts q= parameter
    }
    strKeyword = decodeURIComponent(strKeyword);
    // ...
    return strKeyword;
}
```

**Verdict**: LOW severity. The search query extraction is used to provide "safe download" recommendations on Google search results, which is a legitimate feature for security software. The queries are only sent to localhost, not to remote servers. However, users should be aware that their search queries are being analyzed by the local application.

## False Positives Analysis

Several patterns that might appear suspicious are actually legitimate for this extension type:

1. **WebSocket Communication to localhost:2345**: This is the expected architecture for a browser extension that works with a native antivirus application. The communication stays local and does not exfiltrate data to remote servers.

2. **Obfuscated Flag**: The ext-analyzer flagged this as obfuscated, but inspection shows the code is actually readable and uses standard jQuery 1.10.2 (minified but not maliciously obfuscated). The complexity comes from legitimate functionality, not intentional code hiding.

3. **Full Page HTML Extraction**: While extensive, this is necessary for malware/phishing detection by antivirus software. Similar to how traditional antivirus scans file contents, this extension scans web page contents.

4. **Facebook-Specific Permissions**: The extension requests `https://www.facebook.com/*` specifically because it provides Facebook comment phishing detection, which is a valuable feature given the prevalence of phishing attacks via social media comments.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| ws://localhost:2345/ | Native app communication | Full page HTML, URLs, search queries, Facebook comments | MEDIUM - Local only, but extensive data collection |
| www.bkav.com.vn | Company website (link only) | None - referenced in injected warning banners | LOW - Information link |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

Bkav Pro plugin is a legitimate browser security extension from a recognized Vietnamese cybersecurity company (Bkav Corporation), but it implements several concerning security and privacy practices that elevate it to HIGH risk:

**Security Vulnerabilities:**
- XSS vulnerability via unsafe innerHTML usage creates attack surface if the native application is compromised
- No apparent input sanitization for content received from WebSocket server
- Broad interception of XHR responses on Facebook could expose sensitive data if the native app is malicious

**Privacy Concerns:**
- Extensive data collection: full HTML of every visited page, all search queries, complete Facebook comment monitoring
- All browsing activity is sent to a local native application at localhost:2345
- XHR response interception on Facebook includes potentially sensitive GraphQL API data
- No visible opt-out or selective privacy controls in the extension code

**Mitigating Factors:**
- Data is sent to localhost only, not remote servers (assuming WebSocket server is legitimate Bkav software)
- Extension appears to provide legitimate antivirus/anti-phishing functionality
- Published by a known cybersecurity vendor in Vietnam with 60,000+ users
- Facebook comment warnings link to legitimate Bkav educational content
- The extensive permissions and data access are disclosed in the extension's purpose as browser protection

**Recommendation**: The extension requires a high level of trust in Bkav Corporation and their native application. Users should:
1. Verify the native application at localhost:2345 is legitimate Bkav software
2. Understand that all browsing activity is monitored and analyzed locally
3. Be aware of the XSS vulnerabilities if the native application is compromised
4. Consider whether the phishing protection benefits outweigh the extensive data collection

The HIGH rating reflects the combination of technical vulnerabilities (XSS), extensive data exfiltration (even if local), and the dependency on trusting both the extension and the native application it communicates with.
