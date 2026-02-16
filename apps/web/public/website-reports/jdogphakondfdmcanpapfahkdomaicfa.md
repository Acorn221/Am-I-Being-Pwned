# Vulnerability Report: CKAuthenticator

## Metadata
- **Extension ID**: jdogphakondfdmcanpapfahkdomaicfa
- **Extension Name**: CKAuthenticator
- **Version**: 2.1.4
- **Users**: ~300,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

CKAuthenticator is an enterprise authentication extension for ContentKeeper web filtering systems, primarily deployed in educational and corporate environments. The extension collects user email addresses via Chrome's identity API, obtains the user's IP address from remote servers, encrypts this data using Native Client (NaCl) cryptographic modules, and transmits it to hardcoded IP addresses (192.0.2.1 and 192.0.2.2) for authentication purposes. While the extension appears to be a legitimate enterprise security tool, it demonstrates privacy-invasive behaviors including user tracking, header modification, and sensitive data transmission that would be concerning if deployed without proper user consent and disclosure.

The extension intercepts all HTTP/HTTPS traffic to modify User-Agent headers and communicates with infrastructure endpoints for authentication token retrieval. Given its 300,000 user base and 1.1 star rating, this appears to be an institutional deployment rather than a consumer product.

## Vulnerability Details

### 1. MEDIUM: User Email and IP Address Exfiltration
**Severity**: MEDIUM
**Files**: background.js (lines 46-50, 233-265)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension collects the user's email address via `chrome.identity.getProfileUserInfo()` and Chrome's IP address from remote servers, encrypts this data, and transmits it to hardcoded IP addresses.

**Evidence**:
```javascript
chrome.identity.getProfileUserInfo(function(userInfo)
{
    console.log(">>>>>>>" + userInfo.email);
    userEmail = userInfo.email;
});

function prepDataForCK ()
{
    if ((!thisCKPortIP) || (!userEmail))
        return;

    if (common.naclModule == null)
        return;

    var data = "<st>Chrome</st><>1</v><uname>" + userEmail + "</uname><iip>" + thisChromeIP + "</iip>";
    common.naclModule.postMessage('encrypt|'+data);
}

function sendDataToSYNResp(ip)
{
    var url = "http://" + ip + "/?send_ck_ping=" + ckAuthData;
    jQuery.ajax({ type: "GET", url: url }).done(function(data) {
        console.log (ip);
    }).fail(function(data){
        console.log(data);
        if (ip == "192.0.2.1") {
            console.log ("send ping to second responder");
            sendDataToSYNResp("192.0.2.2", ckAuthData);
        }
    });
}
```

**Verdict**: While this behavior appears intentional for an enterprise authentication system (ContentKeeper is a legitimate web filtering vendor), the collection and transmission of user email addresses and IP information represents significant privacy exposure. In an enterprise context with proper disclosure, this is expected behavior. However, the 1.1 star rating suggests users may not be aware of or consent to this data collection.

### 2. MEDIUM: User-Agent Header Modification on All Traffic
**Severity**: MEDIUM
**Files**: background.js (lines 77-113)
**CWE**: CWE-20 (Improper Input Validation)
**Description**: The extension intercepts and modifies User-Agent headers on all outbound requests, appending an authentication hash received from ContentKeeper servers.

**Evidence**:
```javascript
chrome.webRequest.onBeforeSendHeaders.addListener(function(details)
{
    var headers = details.requestHeaders;

    if (ckIDHash.length > 1)
    {
        for(i = 0, l = headers.length; i < l; ++i)
        {
            if( headers[i].name == 'User-Agent' )
            {
                headers[i].value = headers[i].value + "ck={" + ckIDHash + "}";
                console.log (headers[i].value);
                break;
            }
        }
    }

    return {requestHeaders: headers};

}, requestFilter, ['requestHeaders']);
```

**Verdict**: User-Agent modification allows ContentKeeper servers to track and authenticate users across all web requests. This is standard behavior for enterprise web filtering systems but represents a fingerprinting and tracking mechanism. The authentication hash (`ckIDHash`) is retrieved from `X-CKBYOD` response headers and appended to all subsequent requests.

### 3. MEDIUM: Communication with Hardcoded IP Addresses
**Severity**: MEDIUM
**Files**: background.js (lines 82-83, 241, 267-279, 371-402)
**CWE**: CWE-798 (Use of Hard-coded Credentials)
**Description**: The extension communicates with two hardcoded IP addresses (192.0.2.1 and 192.0.2.2) to retrieve configuration data and submit authentication information.

**Evidence**:
```javascript
var ippos1 = url.search ("192.0.2.1");
var ippos2 = url.search ("192.0.2.2");

getCKPortIP("192.0.2.1", parsePortIPData);

function getCKPortIP(ip, callback) {
    console.log ("sending request to " + ip)

    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function(data)
    {
        if (xhr.readyState == 4)
        {
            if (xhr.status == 200) {
                var dataT = xhr.responseText;
                callback(ip, dataT);
            } else {
                callback(ip, null);
            }
        }
    };

    var url = "http://" + ip + "/?get_ck_ip";
    xhr.open('GET', url, true);
    try {
        xhr.send();
    }
    catch (e) {
        console.log ("exception: ", e);
        callback(ip, null);
    }
}
```

**Verdict**: The hardcoded IP addresses (192.0.2.1 and 192.0.2.2) are from the TEST-NET-1 and TEST-NET-2 ranges (RFC 5737), which are reserved for documentation and examples. In production, these would be replaced with actual ContentKeeper infrastructure IPs. The extension has fallback logic to try the second IP if the first fails. Communication occurs over unencrypted HTTP, though the payload is encrypted via NaCl modules.

### 4. LOW: Use of Deprecated Native Client (NaCl) Technology
**Severity**: LOW
**Files**: common.js (entire file), background.js (lines 129-168, 259-265, 363-369)
**CWE**: CWE-477 (Use of Obsolete Function)
**Description**: The extension relies on Native Client (NaCl) for cryptographic operations. NaCl was deprecated by Google and removed from Chrome in 2021.

**Evidence**:
```javascript
function moduleDidLoad()
{
    console.log ("moduleDidLoad started");

    chrome.browserAction.setBadgeBackgroundColor({color:redColor});
    chrome.browserAction.setBadgeText({text: "off"});

    common.hideModule();
    if (!common.naclModule)
        console.log ("naclModule is NOT loaded!!!");
    else
    {
        console.log ("naclModule is loaded!!!");
        ring();
    }
}

// NaCl modules in newlib/Release/:
// ckauth_arm.nexe, ckauth_x86_32.nexe, ckauth_x86_64.nexe
```

**Verdict**: This extension would not function in modern Chrome browsers as NaCl support was removed. The presence of compiled `.nexe` binaries (Native Executables for ARM, x86_32, and x86_64) indicates this extension was designed for ChromeOS or legacy Chrome deployments. This is likely why the extension has a low rating - it no longer works on current Chrome versions.

## False Positives Analysis

### Native Client Binary Modules
The presence of compiled native binaries (`ckauth_arm.nexe`, `ckauth_x86_32.nexe`, `ckauth_x86_64.nexe`) in the `newlib/Release/` directory might appear suspicious, but these are legitimate NaCl modules used for cryptographic operations (encryption/decryption of authentication data). The NaCl manifest file (`ckauth.nmf`) properly declares these modules for different CPU architectures.

### Header Interception
While intercepting headers on `<all_urls>` is a powerful capability, it is necessary for this extension's purpose of injecting authentication tokens into all web requests for enterprise web filtering.

### Hardcoded Documentation IPs
The IP addresses 192.0.2.1 and 192.0.2.2 are from RFC 5737 documentation ranges, indicating this may be sample/test code or that actual production IPs would be configured differently in deployed versions.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| 192.0.2.1/?get_ck_ip | Retrieve ContentKeeper server IP address (encrypted) | None | MEDIUM - Unencrypted HTTP to infrastructure endpoint |
| 192.0.2.2/?get_ck_ip | Fallback endpoint for ContentKeeper IP retrieval | None | MEDIUM - Unencrypted HTTP fallback |
| 192.0.2.1/?send_ck_ping | Submit encrypted authentication data | Encrypted XML containing user email, Chrome IP, system type | MEDIUM - User identification data transmission |
| 192.0.2.2/?send_ck_ping | Fallback authentication submission | Encrypted XML containing user email, Chrome IP, system type | MEDIUM - User identification data transmission |
| 192.0.2.1/?tickle_user | Keep-alive/session validation | Authentication hash from X-CKBYOD header | MEDIUM - Session tracking |
| 192.0.2.2/?tickle_user | Fallback keep-alive | Authentication hash from X-CKBYOD header | MEDIUM - Session tracking |

All communications occur over HTTP (not HTTPS), though sensitive data is encrypted client-side via NaCl modules before transmission.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: CKAuthenticator is a legitimate enterprise authentication extension for ContentKeeper web filtering systems, but it demonstrates privacy-invasive behaviors that would be highly concerning in a consumer context:

1. **Data Collection**: Collects and transmits user email addresses and IP addresses to remote servers
2. **Traffic Interception**: Modifies all HTTP/HTTPS requests to inject authentication tokens
3. **Broad Permissions**: Uses `<all_urls>`, `webRequest`, and `identity.email` permissions
4. **Deprecated Technology**: Relies on Native Client, which has been removed from modern Chrome

The MEDIUM rating reflects that:
- This appears to be a legitimate enterprise tool from ContentKeeper (established web filtering vendor)
- The behaviors are expected for institutional web filtering/authentication systems
- However, the extension is non-functional on modern Chrome (NaCl deprecated since 2021)
- The low 1.1 star rating suggests user dissatisfaction, possibly due to forced deployment
- The use of TEST-NET IP ranges suggests this may be sample code or misconfigured
- Lack of HTTPS for infrastructure communication is concerning even with encrypted payloads

In an enterprise environment with proper disclosure and user consent, this would be acceptable. However, the technical obsolescence and apparent lack of maintenance raise concerns about whether this extension should still be deployed. Organizations using this extension should migrate to a modern authentication solution that doesn't rely on deprecated NaCl technology.
