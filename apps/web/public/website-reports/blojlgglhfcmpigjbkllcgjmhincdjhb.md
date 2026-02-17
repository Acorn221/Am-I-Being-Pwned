# Vulnerability Report: Snow Web Application Metering

## Metadata
- **Extension ID**: blojlgglhfcmpigjbkllcgjmhincdjhb
- **Extension Name**: Snow Web Application Metering
- **Version**: 1.0.8
- **Users**: ~2,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Snow Web Application Metering is an enterprise monitoring extension developed by Snow Software (Flexera) that tracks web application usage for license compliance and cost optimization purposes. The extension monitors all HTTP/HTTPS requests across all websites using the webRequest permission and sends collected URLs to a local native application via nativeMessaging. While the extension is transparent about its monitoring purpose in the description, it represents significant privacy implications as it tracks all user browsing activity. This is categorized as MEDIUM risk due to its disclosed but extensive data collection scope, which is standard for enterprise monitoring tools but requires user awareness and organizational consent.

The extension does not exfiltrate data to external servers, instead communicating only with a locally-installed native host application. This architectural choice reduces external security risks but still represents comprehensive monitoring of employee browsing behavior.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Browsing Activity Monitoring

**Severity**: MEDIUM
**Files**: eventPage.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension uses the webRequest API with host_permissions for `*://*/*` to monitor all HTTP/HTTPS requests made by the user. Every successful request (HTTP status 200-299) is captured and sent to the native host application for analysis.

**Evidence**:
```javascript
chrome.webRequest.onCompleted.addListener(
    function(details)
    {
        if( !details.fromCache && IsWantedStatusCode( details.statusCode ) ) {
            // Filter calls to localhost
            var result = localhostExp.exec( details.url );
            if( result == null ) {
                StoreURL( details.url, "" );
            }
        }
        return { cancel: false };
    },
    {
        urls: ["*://*/*"]
    },
    []
);
```

**Verdict**: This is expected behavior for an enterprise monitoring tool. The extension's description clearly states its purpose is to "track web application use for the purpose of license compliance and cost optimization." The data is not sent to external servers but rather to a local native application (`com.snowsoftware.cloudmetering`). This is standard for enterprise asset management software and is appropriately disclosed.

### 2. LOW: Native Messaging to Local Application

**Severity**: LOW
**Files**: eventPage.js
**CWE**: CWE-927 (Use of Implicit Intent for Sensitive Communication)
**Description**: The extension communicates with a native host application (`com.snowsoftware.cloudmetering`) every 5 seconds, sending batches of collected URLs.

**Evidence**:
```javascript
const hostName = "com.snowsoftware.cloudmetering";
const sendIntervalInSeconds = 5;

function SendToAgent( data, numberOfURLs )
{
    if (port) {
        console.log("Sending message to native host...");
        lastSend = new Date();
        port.postMessage(data);
    }
}

function SendWaitingData()
{
    let count = Object.keys( gatheredData ).length;
    if( count > 0 ) {
        console.log("Sending " + count + " URLs.");

        let dataToSend = {
            "source-browser" : "Chrome",
            "url" : gatheredData
        };

        SendToAgent(dataToSend, count);
        gatheredData = {};
    }
    else {
        console.log("Nothing to send");
    }
    StartTimer();
}
```

**Verdict**: The native messaging approach is appropriate for enterprise software as it requires local installation and administrative privileges to configure. This is more secure than sending data to external servers. The 5-second batching interval is reasonable and includes connection management to avoid resource waste.

## False Positives Analysis

1. **webRequest Permission on All URLs**: While this is a highly sensitive permission, it is the core functionality of this enterprise monitoring tool. The extension's stated purpose requires monitoring web application usage.

2. **Data Collection**: The extension collects URLs of all visited pages, which could be seen as surveillance. However, this is the explicitly stated purpose of the extension and is typical for enterprise asset management and software license compliance tools.

3. **Localhost Filtering**: The code explicitly filters out localhost and 127.0.0.1 addresses, showing consideration for developer workflows and reducing noise in collected data.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native Host (com.snowsoftware.cloudmetering) | Send browsing data to local agent | URLs visited with timestamps | LOW - Local only, no external transmission |

No external network endpoints are contacted by this extension. All communication is with a locally-installed native application.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: This extension is a legitimate enterprise monitoring tool that performs comprehensive browsing activity tracking. While the data collection is extensive (all URLs visited), it is:

1. **Disclosed**: The description clearly states the extension tracks web application use for license compliance
2. **Local-only**: Data is sent to a native application rather than external servers
3. **Purpose-appropriate**: The functionality matches the stated enterprise monitoring use case
4. **Properly implemented**: Clean code with no evidence of malicious behavior or security vulnerabilities

The MEDIUM risk classification reflects that while this is disclosed and legitimate enterprise software, it represents significant privacy implications for users. Organizations deploying this should ensure:
- Employee awareness of monitoring
- Compliance with local privacy and employment laws
- Appropriate data handling policies for the collected information
- User consent where legally required

This extension is not malicious but requires organizational governance and user awareness. Individual users who are not part of an enterprise deployment should be cautious about installing this extension, as it will monitor all browsing activity.
