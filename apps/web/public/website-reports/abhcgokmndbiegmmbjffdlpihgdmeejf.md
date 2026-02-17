# Vulnerability Report: GrowBot Automator for Instagram

## Metadata
- **Extension ID**: abhcgokmndbiegmmbjffdlpihgdmeejf
- **Extension Name**: GrowBot Automator for Instagram
- **Version**: 2.5.1
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

GrowBot Automator for Instagram is an Instagram automation tool that performs automated follow/unfollow/like actions on behalf of users. While the extension's primary purpose is disclosed (Instagram automation), it collects and exfiltrates user data including Instagram usernames and installation timestamps to its remote server (growbotforfollowers.com) without explicit user consent in the extension description. The extension also implements a licensing/subscription system that checks user status on a remote server.

The extension violates Instagram's Terms of Service by automating user interactions and manipulating the Instagram API, which presents both legal and security risks for users. It collects significant amounts of Instagram user data as part of its automation functionality, though this data collection is inherent to the tool's stated purpose.

## Vulnerability Details

### 1. HIGH: Undisclosed Data Exfiltration to Remote Server
**Severity**: HIGH
**Files**: backgroundscript.js (lines 290-305)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension automatically collects and transmits user data to its remote server without explicit disclosure in the extension listing. On initialization and when Instagram user information is updated, the extension sends the user's unique GUID, Instagram username, and installation timestamps to `https://www.growbotforfollowers.com/igBotUser/`.

**Evidence**:
```javascript
saveToServer: function() {
    for (var i = 0; i < this.ig_users.length; i++) {
        fetch("https://www.growbotforfollowers.com/igBotUser/", {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                'user_guid': this.user_guid,
                'ig_username': this.current_ig_username,
                'install_date': this.install_date,
                'instabot_install_date': this.instabot_install_date
            })
        });
    }
}
```

**Verdict**: This constitutes undisclosed data collection and exfiltration. While the data being sent is relatively limited (GUID, Instagram username, install dates), users are not explicitly informed that their data will be sent to a remote server. This violates user privacy expectations and Chrome Web Store policies requiring transparent data collection practices.

### 2. HIGH: License Verification with Remote Server
**Severity**: HIGH
**Files**: backgroundscript.js (lines 433-454), contentscript.js (line 8034)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension implements a subscription/licensing system that sends the user's GUID and base64-encoded Instagram username to a remote server for license verification. This creates a persistent tracking mechanism and exposes user identity to third-party servers.

**Evidence**:
```javascript
function checkLicenseOnServer() {
    var url = 'https://www.growbotforfollowers.com/check_subscription.php?guid=' + gblIgBotUser.user_guid + '&ign=' + btoa(gblIgBotUser.current_ig_username);
    console.log(url);
    fetch(url, {
            method: 'GET'
        })
        .then(response => response.text())
        .then(function(data) {
            // ... handles license status
        });
}
```

And in contentscript.js:
```javascript
function relinkSubscription() {
    $.post('https://www.growbotforfollowers.com/find_subscription2.php', $('#formRelinkSubscription').serialize()).done(function(data) {
        if (data && data[0] && data[0].subscriptions && data[0].subscriptions.data && data[0].subscriptions.data.length > 0) {
            var guidFromServer = data[0].id;
            chrome.runtime.sendMessage({
                "guidCookie": guidFromServer
            }, function() {
                $('#resultFindSubscription').text('Subscription updated.  Please reload the page.');
            });
        }
    });
}
```

**Verdict**: The licensing system creates a tracking mechanism that ties user identities to specific Instagram accounts. While this is necessary for subscription management, it should be clearly disclosed to users.

### 3. MEDIUM: Extensive Instagram API Manipulation
**Severity**: MEDIUM
**Files**: contentscript.js (multiple locations)
**CWE**: CWE-441 (Unintended Proxy or Intermediary)
**Description**: The extension performs extensive automated interactions with Instagram's internal APIs, including following/unfollowing users, liking posts, removing followers, and blocking users. This violates Instagram's Terms of Service and could result in account suspension or banning for users.

**Evidence**:
Multiple Instagram API endpoints are accessed:
- `https://www.instagram.com/api/v1/friendships/create/` (follow)
- `https://www.instagram.com/api/v1/friendships/destroy/` (unfollow)
- `https://www.instagram.com/web/likes/[id]/like/` (like posts)
- `https://i.instagram.com/api/v1/users/[id]/info/` (user info)
- `https://www.instagram.com/graphql/query` (GraphQL queries)

**Verdict**: While this is the extension's stated purpose, users should be aware they are violating Instagram's ToS and risking account suspension. The extension provides no warnings about these risks.

### 4. MEDIUM: Automated Tab Manipulation and Scripting
**Severity**: MEDIUM
**Files**: backgroundscript.js (lines 16-223)
**CWE**: CWE-610 (Externally Controlled Reference to a Resource)
**Description**: The extension automatically creates and manipulates browser tabs, injecting scripts and clicking buttons on Instagram pages without explicit user action for each operation. This includes opening profile pages, story pages, and reel pages, then automatically clicking follow/like/save buttons.

**Evidence**:
```javascript
if (request.follow) {
    var u = request.follow;
    chrome.tabs.create({
        url: "https://www.instagram.com/" + u.username
    }, function(tab) {
        var tabId = tab.id;
        chrome.tabs.onUpdated.addListener(function(tabId, info) {
            if (info.status === 'complete') {
                setTimeout(function() {
                    chrome.tabs.sendMessage(tab.id, {
                        clickSomething: 'button div[dir="auto"]:contains("Follow")'
                    });
                }, 3000);
                setTimeout(function() {
                    chrome.tabs.remove(tab.id);
                }, 20000);
            }
        });
    });
}
```

**Verdict**: This automation behavior is expected for an Instagram bot tool, but the level of automation presents usability and security concerns, particularly the ability to perform actions without direct user confirmation.

### 5. LOW: Main World Script Injection
**Severity**: LOW
**Files**: backgroundscript.js (lines 373-389)
**CWE**: CWE-94 (Improper Control of Generation of Code)
**Description**: The extension injects scripts into the MAIN world context of Instagram pages using `chrome.scripting.executeScript` with `world: 'MAIN'`. This allows the extension to access and potentially manipulate page-level JavaScript variables.

**Evidence**:
```javascript
function runWinVarsScript() {
    chrome.tabs.query({
        url: ["https://www.instagram.com/*", "https://www.instagram.com/"]
    }, tabs => {
        for (var i = 0; i < tabs.length; i++) {
            var igTabId = tabs[i].id;
            chrome.scripting.executeScript({
                    target: {
                        tabId: igTabId
                    },
                    files: ['winvars.js'],
                    world: 'MAIN'
                },
                function() {});
        }
    });
}
```

**Verdict**: While MAIN world injection is sometimes necessary for extensions that interact with page scripts, it increases the attack surface and could potentially be exploited if combined with other vulnerabilities.

## False Positives Analysis

1. **Instagram Data Collection**: The extension collects extensive Instagram user data (followers, following, posts, etc.), but this is necessary for its filtering and automation features. This is not malicious in the context of an Instagram automation tool.

2. **AJAX Requests**: The numerous fetch/AJAX requests to Instagram endpoints are expected behavior for an Instagram automation tool and are not inherently malicious.

3. **Chrome Storage Usage**: Extensive use of chrome.storage.local is expected for saving user preferences, queues, and whitelist data.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.growbotforfollowers.com/igBotUser/ | User tracking | User GUID, Instagram username, install dates | HIGH - Undisclosed data collection |
| www.growbotforfollowers.com/check_subscription.php | License verification | User GUID, Instagram username (base64) | MEDIUM - User tracking |
| www.growbotforfollowers.com/find_subscription2.php | Subscription relinking | Form data (likely email/payment info) | MEDIUM - Sensitive data transmission |
| www.instagram.com/api/v1/* | Instagram automation | User credentials, target user IDs, action data | HIGH - ToS violation, account risk |
| i.instagram.com/api/v1/* | Instagram data fetching | User credentials, query parameters | MEDIUM - ToS violation |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

The extension is assigned a HIGH risk level due to:

1. **Undisclosed Data Exfiltration**: User data (Instagram usernames and installation timestamps) is automatically sent to remote servers without explicit disclosure in the extension description, violating user privacy expectations and Chrome Web Store policies.

2. **Terms of Service Violations**: The extension automates Instagram interactions in direct violation of Instagram's Terms of Service, putting users at risk of account suspension or permanent banning.

3. **Remote Tracking**: The licensing system creates a persistent tracking mechanism that ties specific users to their Instagram accounts on third-party servers.

4. **User Account Risk**: Users of this extension face significant risk of Instagram account penalties, including temporary or permanent account suspension.

While the extension's automation functionality is its stated purpose and users likely understand they are installing an Instagram bot, the lack of transparency regarding data collection and the absence of warnings about Instagram ToS violations constitute significant privacy and security concerns.

The extension would be rated MEDIUM if it provided clear disclosure of all data collection practices and warnings about potential account risks. However, the undisclosed data exfiltration elevates this to HIGH risk.
