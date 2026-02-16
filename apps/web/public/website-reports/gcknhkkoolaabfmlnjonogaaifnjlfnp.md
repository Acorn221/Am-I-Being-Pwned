# Vulnerability Report: FoxyProxy

## Metadata
- **Extension ID**: gcknhkkoolaabfmlnjonogaaifnjlfnp
- **Extension Name**: FoxyProxy
- **Version**: 9.2
- **Users**: ~500,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

FoxyProxy is a legitimate proxy management extension with 500,000+ users that provides advanced proxy configuration capabilities. The extension collects proxy credentials (username/password) from users to authenticate with proxy servers, which is essential to its core functionality. While the extension communicates with the developer's domains (getfoxyproxy.org and bilestoad.com) for IP geolocation lookups and account import features, these network activities are disclosed and appropriate for a proxy management tool. The extension is clean with no security or privacy concerns beyond its stated purpose.

The extension uses modern browser APIs appropriately, stores proxy configurations locally, and synchronizes settings via browser.storage.sync when enabled by the user. All external communications are for legitimate features: IP lookup service, location data for proxy servers, and FoxyProxy account import functionality.

## Vulnerability Details

### 1. LOW: Username/Password Collection for Proxy Authentication
**Severity**: LOW
**Files**: authentication.js, import-account.js
**CWE**: None (Expected behavior)
**Description**: The extension collects and stores proxy credentials (username and password) to authenticate with HTTP/HTTPS/SOCKS proxy servers. This is standard and necessary functionality for a proxy management tool.
**Evidence**:
```javascript
// authentication.js - lines 20-24
static init(data) {
  this.data = {};
  data.forEach(i => {
    const {hostname, port, username, password} = i;
    hostname && port && username && password &&
      (this.data[`${hostname}:${port}`] = {username, password});
  });
}
```
**Verdict**: This is expected behavior for a proxy extension. Credentials are stored locally and used only for proxy authentication via the webRequest.onAuthRequired API. The extension also supports importing proxy credentials from FoxyProxy accounts, which is a disclosed feature for users who purchase proxy services from the vendor.

### 2. LOW: External Network Requests to Developer Domains
**Severity**: LOW
**Files**: proxy.js, import-account.js, get-location.js
**CWE**: None (Disclosed behavior)
**Description**: The extension makes network requests to getfoxyproxy.org and bilestoad.com for IP geolocation lookups and FoxyProxy account imports.
**Evidence**:
```javascript
// proxy.js - line 151
static getIP() {
  fetch('https://getfoxyproxy.org/webservices/lookup.php')
  .then(response => response.json())
  .then(data => {
    const [ip, {cc, city}] = Object.entries(data)[0];
    const text = [ip, city, Location.get(cc)].filter(Boolean).join('\n');
    App.notify(text);
  })
}

// import-account.js - lines 30-32
const url = options.includes('alt') ?
  'https://bilestoad.com/webservices/get-accounts.php' :
  'https://getfoxyproxy.org/webservices/get-accounts.php';
```
**Verdict**: These endpoints are used for legitimate features: checking the user's current IP/location (useful for verifying proxy functionality) and importing proxy server lists from FoxyProxy accounts. All requests are user-initiated and appropriate for the extension's purpose.

## False Positives Analysis

**Proxy Credential Storage**: While the extension stores usernames and passwords, this is necessary for HTTP/HTTPS/SOCKS proxy authentication. The credentials are stored only in browser.storage.local and never transmitted to third parties (only to the configured proxy servers for authentication).

**fetch() Calls to External Domains**: The static analyzer flagged the extension as "obfuscated" but this is incorrect - the code is clean, modular ES6 JavaScript. The fetch calls to getfoxyproxy.org are for disclosed features (IP lookup, proxy account import) and are initiated only by explicit user actions.

**Storage Sync**: The extension uses browser.storage.sync to synchronize proxy configurations across devices when enabled by the user. This is a standard browser feature and does not involve third-party servers.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| getfoxyproxy.org/webservices/lookup.php | IP geolocation lookup | None (GET request) | LOW - User-initiated feature to check current IP |
| getfoxyproxy.org/webservices/get-accounts.php | Import proxy list from FoxyProxy account | Username, password (POST) | LOW - Disclosed feature for FoxyProxy customers |
| bilestoad.com/webservices/get-accounts.php | Alternative endpoint for account import | Username, password (POST) | LOW - Alternative domain for same feature |

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: FoxyProxy is a legitimate proxy management extension with appropriate permissions for its stated purpose. The extension:
- Does not engage in undisclosed data collection
- Uses credentials only for proxy authentication (expected behavior)
- Makes external requests only for disclosed features (IP lookup, account import)
- Has no code execution vulnerabilities
- Has no XSS or injection vulnerabilities
- Does not modify web pages or inject content
- Uses modern MV3 architecture with secure coding practices

The extension has 500,000+ users and is a well-established tool in the proxy management space. All network activity is transparent and related to core functionality. There are no security or privacy concerns beyond the extension's documented capabilities.
