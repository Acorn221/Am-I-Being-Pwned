# Vulnerability Report: 金山毒霸上网保护 (Kingsoft WebShield Chrome Plugin)

## Metadata
- **Extension ID**: oegbiabdgimjipcgkfcdfeocdmkmlgak
- **Extension Name**: 金山毒霸上网保护 (Kingsoft WebShield Chrome Plugin)
- **Version**: 3.0
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Kingsoft WebShield is a native messaging extension that communicates with the Kingsoft Duba (金山毒霸) desktop antivirus application. The extension monitors all browsing activity, sends URLs and page content to the native application, and allows the native app to remotely control browser tabs through script injection and navigation. While presented as a security tool, the extension implements invasive surveillance capabilities that extract page content (titles, body text, meta keywords, and descriptions) without adequate user disclosure or consent. The native messaging architecture creates an opacity barrier where the actual data handling occurs in the desktop application, making it impossible to verify whether collected data stays local or is transmitted to remote servers.

The extension's broad permissions (all URLs, scripting, tabs, nativeMessaging) combined with bidirectional command/control capabilities make it a critical privacy risk. Users installing this extension grant comprehensive browser surveillance to Kingsoft's desktop software with no visibility into what happens to the collected data.

## Vulnerability Details

### 1. CRITICAL: Undisclosed Page Content Exfiltration to Native Application

**Severity**: CRITICAL
**Files**: service.js, scripts/content.js
**CWE**: CWE-359 (Exposure of Private Information), CWE-923 (Improper Restriction of Communication Channel to Intended Endpoints)

**Description**: The extension extracts comprehensive page content from all websites the user visits and sends it to the native Kingsoft Duba application via native messaging. This occurs automatically as the user browses.

**Evidence**:

In `service.js`, the extension monitors all tab events and sends URLs to the native app:
```javascript
function OnCreate(tab)
{
    if (0 == tab.url.length || tab.url.match(/^chrome/) || tab.url.match(/^edge/))
    {
        return;
    }
    kwsCheckUrl(tab.id, tab.url);
}

function OnUpdate(tabId, obj, tab)
{
    if (0 == tab.url.length || tab.url.match(/^chrome/) || tab.url.match(/^edge/))
    {
        return;
    }

    if (obj.status == "loading")
    {
        if (tab.url.match("^http://api.pc120.com"))
        {
            return;
        }
        kwsCheckUrl(tabId, tab.url);
    }
    else if (obj.status == "complete")
        kwsNPComplete(tabId, tab.url, tab.title);
}
```

The native app can then request detailed page content via the `kwsGetContent` function:
```javascript
function kwsGetContent(id, flags)
{
    chrome.scripting.executeScript(
        {
            target: {tabId: id},
            files: ["scripts/content.js"],
        },
        function()
        {
            chrome.tabs.sendMessage(id, {f: flags});
        });
}
```

In `scripts/content.js`, the injected script extracts page content based on flag bits:
```javascript
chrome.runtime.onMessage.addListener(
  function(request, sender, sendResponse) {
    var url_ = document.location.href;
    var titleStr="";
    var bodyStr="";
    var keywordsStr="";
    var desStr="";

    if (request.f & 1){//title
        titleStr=document.title.substring(0,512);
    }
    if (request.f & 2){//keywords
        var metaElements = document.getElementsByTagName("meta");
        for (i=0;i<metaElements.length;i++){
            if (metaElements[i].name == "keywords") {
                    keywordsStr = metaElements[i].content.substring(0,512);
                    break;
                }
        }
    }
    if (request.f & 4){//des
        var metaElements = document.getElementsByTagName("meta");
        for (i=0;i<metaElements.length;i++){
            if (metaElements[i].name == "description") {
                    desStr = metaElements[i].content.substring(0,512);
                    break;
                }
        }
    }
    if (request.f & 8){//body
        bodyStr = document.body.outerText.substring(0, 512);
    }

    chrome.extension.sendRequest({type:"fish", url:url_, title:titleStr, body:bodyStr, keyword:keywordsStr, description:desStr});
  });
```

All extracted data (URL, title, body text, keywords, description) is sent back to the extension background, which forwards it to the native application via `kwsCheckContent()`.

**Verdict**: CRITICAL severity. The extension creates a comprehensive surveillance pipeline that captures URLs, page titles, body content, and metadata from every website the user visits. While the data goes to the native app rather than directly to a remote server, users have no way to verify what the native app does with this data. This level of undisclosed data collection constitutes a severe privacy violation.

### 2. HIGH: Remote Script Injection and Tab Control via Native Application

**Severity**: HIGH
**Files**: service.js
**CWE**: CWE-94 (Improper Control of Generation of Code), CWE-250 (Execution with Unnecessary Privileges)

**Description**: The extension accepts commands from the native Kingsoft application to inject scripts into arbitrary tabs and navigate tabs to arbitrary URLs.

**Evidence**:

```javascript
function onRecievedNativeMessage(message) {
    console.log('recieved message from native app: ' + JSON.stringify(message));
    var func = message["Function"];
    if (func == "kwsNavigate")
    {
        var id = message["TabId"];
        var url = message["NavigateUrl"];
        kwsNavigate(id,url);
    }
    else if (func == "kwsGetContent")
    {
        var id = message["TabId"];
        var updateFlag = message["UploadFlag"];
        kwsGetContent(id,updateFlag);
    }
    else if (func == "kwsInjectPC120")
    {
        var id = message["TabId"];
        kwsInjectPC120(id);
    }
}

function kwsNavigate(id,url)
{
    if (0 == url.length)
    {
        return;
    }

    chrome.tabs.update(id,{"url":url});
}

function kwsInjectPC120(id)
{
    chrome.scripting.executeScript(
        {
            target:{tabId: id},
            files: ["scripts/pc120.js"],
        }
    );
}
```

The native application can:
1. Force navigate any tab to any URL (`kwsNavigate`)
2. Inject the pc120.js script into any tab (`kwsInjectPC120`)
3. Inject content.js and extract page content (`kwsGetContent`)

**Verdict**: HIGH severity. This creates a command-and-control architecture where the desktop application has full control over the browser. While the stated purpose is phishing protection, the architecture allows for abuse including forced navigation to malicious sites, arbitrary script injection, and content manipulation.

### 3. MEDIUM: Absence of Origin Validation in Native Messaging

**Severity**: MEDIUM
**Files**: service.js
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The extension connects to the native messaging host `com.kingsoft.duba.kschext` without any validation of the native application's integrity or identity. It blindly trusts all messages from the native app.

**Evidence**:

```javascript
function connectToNativeHost()
{
    var nativeHostName = "com.kingsoft.duba.kschext";
    console.log(nativeHostName);
    port = chrome.runtime.connectNative(nativeHostName);
    port.onMessage.addListener(onRecievedNativeMessage);
    port.onDisconnect.addListener(onDisconnected);
}
```

All messages from the native app are processed without validation:
```javascript
function onRecievedNativeMessage(message) {
    console.log('recieved message from native app: ' + JSON.stringify(message));
    var func = message["Function"];
    // No validation of message authenticity or integrity
    if (func == "kwsNavigate") { ... }
    else if (func == "kwsGetContent") { ... }
    else if (func == "kwsInjectPC120") { ... }
}
```

**Verdict**: MEDIUM severity. While Chrome's native messaging requires the native application manifest to be properly installed, there's no runtime validation of message authenticity. If the native app or its registration is compromised, a malicious application could replace it and gain full control over the browser.

## False Positives Analysis

The following patterns are NOT false positives despite being common in security software:

1. **Native messaging for antivirus integration**: While legitimate antivirus extensions do use native messaging, the scope of data collection here (full page content from all sites) exceeds what's necessary for URL-based phishing protection.

2. **Script injection for blocking malicious pages**: The `kwsInjectPC120` function appears designed to inject warning pages, which is legitimate. However, the architecture allows unrestricted injection with no validation of when/why injection occurs.

3. **URL checking**: Sending URLs to the native app for reputation checking is standard for security software. The concern is the additional page content extraction (titles, body text, keywords) which goes beyond URL reputation.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native App: com.kingsoft.duba.kschext | Bidirectional messaging with Kingsoft Duba desktop app | URLs, page titles, body content (512 chars), keywords, descriptions, tab IDs | CRITICAL - No visibility into what native app does with data |

Note: The extension itself does not make direct network requests. All data flows through the native messaging interface to the Kingsoft Duba desktop application. This creates an opacity barrier - the extension's code is reviewable, but the native application's behavior is not.

## Privacy Concerns

1. **Comprehensive browsing surveillance**: Every URL visited, every page title, and potentially full page content is sent to the Kingsoft application.

2. **No opt-out mechanism**: The monitoring is automatic and continuous whenever the extension is enabled.

3. **Data minimization violation**: Collecting page body content, titles, keywords, and descriptions far exceeds what's needed for URL-based phishing protection.

4. **Unknown data retention**: No way to verify whether collected data is stored, aggregated, or transmitted to remote servers by the native application.

5. **Lack of transparency**: Users installing this extension likely don't realize the depth of browser monitoring they're consenting to.

## Overall Risk Assessment

**RISK LEVEL: CRITICAL**

**Justification**: This extension implements comprehensive browser surveillance under the guise of security protection. While the stated purpose (phishing/malware protection) is legitimate, the implementation grossly exceeds what's necessary for that purpose. The combination of:

1. Automatic extraction of URLs, titles, and page content from all browsing activity
2. Transmission of this data to an opaque native application
3. Remote control capabilities allowing the native app to inject scripts and navigate tabs
4. Installation base of 100,000+ users
5. No meaningful user consent or transparency about data collection

...constitutes a critical privacy violation. Users have no way to verify whether their browsing data stays local or is transmitted to Kingsoft's servers in China. The architecture creates a perfect surveillance system with minimal visibility or user control.

**Recommendation**: Users should uninstall this extension unless they explicitly need Kingsoft Duba integration and understand that all their browsing activity will be monitored by the desktop application. The Chrome Web Store should require clearer privacy disclosures about the extent of data collection.
