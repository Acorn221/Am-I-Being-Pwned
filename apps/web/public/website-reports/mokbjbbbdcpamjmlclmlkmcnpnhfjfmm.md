# Vulnerability Report: Valorant Bot(unofficial) Extension

## Metadata
- **Extension ID**: mokbjbbbdcpamjmlclmlkmcnpnhfjfmm
- **Extension Name**: Valorant Bot(unofficial) Extension
- **Version**: 1.0.4
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension acts as a companion tool for a Discord bot called "Valorant Bot", designed to streamline the authentication process for Riot Games/Valorant accounts. While the extension appears to serve a legitimate purpose of linking Discord accounts with Valorant accounts through a third-party bot service, it implements several concerning security practices.

The extension collects sensitive authentication credentials (session cookies and access tokens) from Riot Games domains and transmits them to a third-party server (valobot.net) along with user-agent information. While the stated purpose is to enable automated Valorant store checking through a Discord bot, the collection and transmission of authentication cookies presents significant security and privacy risks. Users are consenting to share their authentication data, but the lack of security controls around cookie handling, the broad permissions requested, and the reliance on a third-party service for credential storage raise concerns about potential account compromise if the valobot.net service is compromised or acts maliciously.

## Vulnerability Details

### 1. HIGH: Harvesting and Exfiltration of Authentication Cookies
**Severity**: HIGH
**Files**: background.js (lines 91-138)
**CWE**: CWE-522 (Insufficiently Protected Credentials)
**Description**: The extension actively harvests session cookies and access tokens from Riot Games and Valorant domains, then transmits them to a third-party server at valobot.net. This includes cookies with names containing "ssid" and "access_token" which are critical authentication credentials.

**Evidence**:
```javascript
const allCookies = [];
allCookies.push(...(await chrome.cookies.getAll({ domain: "riotgames.com" })));
allCookies.push(...(await chrome.cookies.getAll({ domain: "playvalorant.com" })));

const ssidCookie = allCookies.find((cookie) => cookie.name.includes("ssid"));
const accessToken = allCookies.find((cookie) => cookie.name.includes("access_token"));

// ...

const response = await fetch("https://valobot.net/api/bot/ssid", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ discordId: discordId, reauthHeaders: reauthHeaders, cookies: allCookies }),
});
```

**Verdict**: While the extension requires user consent before transmitting cookies (background.js checks consent via checkbox), the transmission of authentication credentials to third-party servers is inherently risky. If the valobot.net service is compromised, malicious actors could gain access to users' Riot Games accounts. The extension sends ALL cookies from these domains, not just the minimum required, increasing the attack surface.

### 2. HIGH: Third-Party Credential Storage and Trust Model
**Severity**: HIGH
**Files**: background.js, popup.js, content.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension's entire security model relies on trusting the valobot.net third-party service to securely store and handle user authentication credentials. Users are linking their Discord accounts with their Riot Games credentials through an intermediary service with no transparency about how credentials are stored, protected, or used.

**Evidence**:
- Discord account information is stored in cookies on valobot.net domain (`_Extension-discord_account_id`, `_Extension-discord_account_username`, `_Extension-discord_account_icon_url`)
- All Riot authentication cookies are transmitted to valobot.net/api/bot/ssid endpoint
- No evidence of encryption, secure token handling, or credential rotation

**Verdict**: This creates a single point of failure. If the valobot.net service is breached, both Discord and Riot accounts could be compromised. The extension does not implement any client-side security measures beyond basic user consent.

### 3. MEDIUM: Overly Broad Cookie Access
**Severity**: MEDIUM
**Files**: manifest.json, background.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests cookie permissions for broad domain patterns (https://*.riotgames.com/*, https://*.playvalorant.com/*) and collects ALL cookies from these domains rather than specifically targeted authentication cookies.

**Evidence**:
```javascript
allCookies.push(...(await chrome.cookies.getAll({ domain: "riotgames.com" })));
allCookies.push(...(await chrome.cookies.getAll({ domain: "playvalorant.com" })));
// Sends ALL cookies in the POST body
body: JSON.stringify({ discordId: discordId, reauthHeaders: reauthHeaders, cookies: allCookies }),
```

**Verdict**: The extension could be more privacy-preserving by only collecting the specific cookies needed (ssid and access_token) rather than all cookies from these domains. This violates the principle of least privilege.

## False Positives Analysis

**Auto-popup behavior**: The extension automatically opens its popup up to 3 times when users visit playvalorant.com (background.js lines 43-61). While this could be considered intrusive, it's a legitimate onboarding mechanism for first-time setup, not a malicious pattern.

**Content script XPath queries**: The content script uses XPath to detect login status and extract display names (content.js lines 25, 81). This is a legitimate technique for interacting with web page elements and not indicative of malicious scraping.

**Message passing**: The extension uses extensive message passing between background, content scripts, and popup (chrome.runtime.sendMessage). This is standard practice for Chrome extensions and not suspicious in itself.

**Extension check manipulation**: The content script automatically checks a checkbox with id "extension_check" on valobot.net (content.js lines 35-43). This is specifically to signal to the valobot.net website that the extension is installed, which is a legitimate feature detection mechanism.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://valobot.net/api/bot/ssid | Submit authentication credentials | Discord ID, User-Agent headers, ALL cookies from riotgames.com and playvalorant.com domains | HIGH - Transmits sensitive authentication credentials to third-party |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:
While this extension serves a disclosed purpose (linking Discord and Riot accounts for a Valorant Discord bot), it implements a high-risk architecture by harvesting and transmitting authentication credentials to a third-party service. The key concerns are:

1. **Credential Exposure**: Session cookies and access tokens are sent to valobot.net, creating a dependency on that service's security practices
2. **Single Point of Failure**: Compromise of valobot.net could lead to widespread account takeovers
3. **Overprivileged Access**: Collects ALL cookies from Riot domains rather than only required ones
4. **Limited Transparency**: No evidence of secure credential handling, encryption in transit beyond HTTPS, or data retention policies

The extension does implement user consent before transmitting credentials and clearly states its purpose in Japanese. However, the inherent risk of third-party credential handling elevates this to HIGH risk. Users should be aware that installing this extension means trusting both the extension developer and the valobot.net service with their Riot Games account access.

**Recommendations for users**:
- Only install if you fully trust the valobot.net service
- Enable two-factor authentication on your Riot account
- Monitor your Riot account for unusual activity
- Be aware that this extension creates a third-party dependency for your account security
