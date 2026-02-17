# Vulnerability Report: Ads Killer

## Metadata
- **Extension ID**: jjckigopagkhaikodedjnmbccfpnmiea
- **Extension Name**: Ads Killer
- **Version**: 0.99.70
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Ads Killer is an ad-blocking extension that operates similarly to AdBlock Plus by using filter subscriptions and element hiding. While its primary function is legitimate ad blocking, the extension collects and transmits usage statistics to remote servers without clear disclosure in its description. The extension also enumerates installed extensions and sends this information to external servers, which raises privacy concerns. The extension collects detailed blocking statistics including target domains, blocked domains, blocked URLs, and filtering rules, transmitting this browsing-related data to stat.adskiller.me.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Statistics Collection and Transmission
**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension collects detailed blocking statistics and sends them to stat.adskiller.me without clear user disclosure. This includes target domains visited, blocked domains, blocked URLs, and filter rules applied.

**Evidence**:
```javascript
// background.js lines 401-409
function getStatBlockUrls(url, tabid, selector, size) {
    chrome.tabs.query({}, function(tabs) {
        tabs.forEach(function(tab) {
            if (tab.id === tabid) {
                setStatBlockAll(extractHostFromUrl(tab.url), extractHostFromUrl(url), url, selector, "");
            }
        });
    });
}

// background.js lines 411-420
function setStatBlockAll(target_domain, blocked_domain, blocked_url, rule, size) {
    var stat ={
        "target_domain": target_domain,
        "blocked_domain": blocked_domain,
        "blocked_url": blocked_url,
        "rule": rule,
        "size": size
    }
    saveStatBlockUrls(stat);
}

// background.js lines 456-467
function sendStatsBlock() {
    chrome.storage.local.get( 'stat_block', function(stats) {
        if (is_send_stat) return;
        is_send_stat = true;
        chrome.storage.local.set({'end_send_stat': getTimeSec()});
        chrome.storage.local.set({'stat_block': []});
        stats = JSON.stringify(stats.stat_block);
        if (stats.length == 0) return;
        var url = "https://stat.adskiller.me/external/stats/blocking/";
        XHRequest(url, "POST", stats, function(response) {}, function(err){}, "", "");
    });
}
```

**Verdict**: This constitutes undisclosed data collection. The target_domain field reveals user browsing patterns. While the data may be used for improving filter lists, users should be explicitly informed about this collection.

### 2. MEDIUM: Extension Enumeration and External Reporting
**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-497 (Exposure of Sensitive System Information)
**Description**: The extension enumerates all installed browser extensions using chrome.management.getAll and sends the list to stat.adskiller.me for "matching" against a remote database. Extensions flagged as "bad" by the server trigger a popup prompting users to disable them.

**Evidence**:
```javascript
// background.js lines 761-775
function getInfoExtensions() {
    chrome.management.getAll(function(list) {
        var extensions = [];
        for (var i = 0; i < list.length; i++) {
            if (list[i].enabled) {
                extensions.push({"id": list[i].id});
                errorExtensions[list[i].id] = list[i].shortName;
            }
        }
        if (extensions.length > 0) {
            sendStatExtension(extensions);
        }
    });
}

// background.js lines 737-758
function sendStatExtension(extensions) {
    var url = "https://stat.adskiller.me/external/api/addons-match";
    var body = "data=" + encodeURIComponent(JSON.stringify(extensions));
    XHRequest(url, "POST", body, function(response) {
        try {
            var json  = parseJSON(response.responseText);
            var new_error_extensions = {};
            for (var i = 0; i < json.length; i++) {
                if (json[i].match) {
                    new_error_extensions[json[i].id] = errorExtensions[json[i].id];
                }
            }
            errorExtensions = new_error_extensions;
        } catch(e) {
            errorExtensions = {};
            console.log("Ошибка проверки расширений!!!")
        }
        if (Object.keys(errorExtensions).length > 0) {
            openPopup();
        }
    }, "", "application/x-www-form-urlencoded", "");
}
```

**Verdict**: While the intent appears to be warning users about malicious extensions, this functionality exposes the user's installed extension list to a third-party server. The code is currently commented out (line 802: `//getInfoExtensions();`) but remains in the codebase and could be activated in an update.

## False Positives Analysis

1. **Filter Subscription Updates**: The extension downloads filter lists from stat.adskiller.me, which is expected behavior for an ad blocker that maintains its own filter lists.

2. **Google Analytics**: The extension loads Google Analytics (UA-71613677-1) for basic usage tracking (extension starts), which is relatively common but should still be disclosed.

3. **Remote Configuration**: The extension fetches settings from stat.adskiller.me/external/api/settings to configure update intervals and record limits. This is legitimate remote configuration but contributes to the data collection concerns.

4. **Ad Blocking Mechanism**: The core ad blocking functionality using filter matching, element hiding, and webRequest blocking is legitimate and expected for this extension type.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| stat.adskiller.me/external/stats/blocking/ | Submit blocking statistics | Target domains, blocked URLs, filter rules | MEDIUM - Exposes browsing patterns |
| stat.adskiller.me/external/api/addons-match | Extension enumeration | List of installed extension IDs | MEDIUM - Privacy exposure (currently disabled) |
| stat.adskiller.me/external/api/settings | Fetch remote config | Extension version | LOW - Standard config fetch |
| stat.adskiller.me/external/api/list | Fetch filter lists | Locale info | LOW - Standard filter update |
| stat.adskiller.me/external/stats/add/ | Installation tracking | Extension version, source | LOW - Basic telemetry |
| ssl.google-analytics.com | Usage analytics | Extension start events | LOW - Standard analytics |
| adskiller.me/uninstall | Uninstall page | None (just opens URL) | CLEAN |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: Ads Killer is a legitimate ad-blocking extension with functionality comparable to AdBlock Plus. However, it collects and transmits browsing-related data (domains visited, URLs blocked) to its backend servers without prominent disclosure to users. The extension enumeration code, while currently disabled, represents additional privacy concerns.

The extension is not malicious but engages in data collection practices that exceed what users would typically expect from an ad blocker. Users should be clearly informed about:
1. Collection of target domains and blocking statistics
2. Transmission of this data to stat.adskiller.me
3. The presence (even if disabled) of extension enumeration code

The risk is classified as MEDIUM rather than HIGH because:
- The primary ad-blocking functionality is legitimate
- No evidence of credential theft or malicious exfiltration
- Statistics collection appears intended for filter list improvement
- Extension enumeration is currently commented out
- The extension has proper permissions declarations

Users privacy-conscious about their browsing data should be aware of these collection practices before installing this extension.
