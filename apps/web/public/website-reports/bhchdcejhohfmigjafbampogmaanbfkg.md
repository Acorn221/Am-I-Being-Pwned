# Vulnerability Report: User-Agent Switcher and Manager

## Metadata
- **Extension ID**: bhchdcejhohfmigjafbampogmaanbfkg
- **Extension Name**: User-Agent Switcher and Manager
- **Version**: 0.6.6
- **Users**: ~300,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

User-Agent Switcher and Manager is a browser extension that allows users to spoof their user-agent string to bypass website restrictions or test cross-browser compatibility. The extension provides legitimate functionality for changing user-agent strings per-site or globally. However, it implements a remote configuration feature that allows fetching extension preferences from arbitrary user-specified URLs without proper security validation. While this feature appears designed for enterprise deployment scenarios, it introduces a medium-severity security risk where users could be tricked into loading malicious configurations that modify extension behavior. The extension does not exfiltrate user data and its core functionality aligns with its stated purpose.

The static analyzer flagged one exfiltration flow (storage.local → fetch) which corresponds to the remote configuration feature. This is a legitimate use case for remote administration but lacks origin validation controls.

## Vulnerability Details

### 1. MEDIUM: Unvalidated Remote Configuration Loading

**Severity**: MEDIUM
**Files**: managed.js, data/options/index.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)

**Description**: The extension allows users to configure a "remote-address" URL from which extension preferences can be fetched and applied. When set, the extension will fetch JSON configuration from this URL and automatically apply it to chrome.storage.local, overwriting existing settings. This feature is accessible through the options page and can be triggered manually or automatically on startup/storage changes.

**Evidence**:

From `managed.js`:
```javascript
chrome.storage.local.get({
  'remote-address': ''
}, prefs => {
  if (prefs['remote-address']) {
    fetch(prefs['remote-address']).then(r => r.json()).then(configure).catch(e => {
      console.error('REMOTE_JSON_PARSE_ERROR', e);
    });
  }
});
```

From `data/options/index.js`:
```javascript
document.getElementById('update').onclick = () => chrome.runtime.sendMessage({
  method: 'update-from-remote',
  href: document.getElementById('remote-address').value
}, resp => {
  if (resp === true) {
    notify('Updated, refreshing options page...', 1200, () => {
      location.reload();
    });
  }
  else {
    alert(resp);
  }
});
```

The message handler in `managed.js`:
```javascript
chrome.runtime.onMessage.addListener((request, sender, response) => {
  if (request.method === 'update-from-remote') {
    fetch(request.href).then(r => r.json()).then(configure)
      .then(() => response(true)).catch(e => response(e.message));
    return true;
  }
});
```

**Verdict**: MEDIUM severity. While this feature is likely intended for enterprise/managed deployments, there are no origin restrictions, integrity checks, or signed configuration requirements. A malicious actor could socially engineer users into setting a remote URL pointing to attacker-controlled content, which would then modify extension preferences including custom user-agent rules, whitelist/blacklist settings, and potentially inject custom JavaScript via the parser configuration. However, exploitation requires explicit user action to configure the remote URL.

### 2. MEDIUM: Message Handler Accepts Arbitrary URLs

**Severity**: MEDIUM
**Files**: managed.js, data/options/index.js
**CWE**: CWE-20 (Improper Input Validation)

**Description**: The `update-from-remote` message handler accepts a URL directly from message parameters without sender validation. While only the extension's own pages can call `chrome.runtime.sendMessage`, the options page allows users to input arbitrary URLs that are then passed to the background script.

**Evidence**:
```javascript
chrome.runtime.onMessage.addListener((request, sender, response) => {
  if (request.method === 'update-from-remote') {
    fetch(request.href).then(r => r.json()).then(configure)
      .then(() => response(true)).catch(e => response(e.message));
    return true;
  }
});
```

The `configure` function will apply any JSON that matches the expected structure:
```javascript
const configure = j => chrome.storage.local.get({
  'json-guid': 'na'
}, prefs => {
  if (prefs['json-guid'] !== j['json-guid'] || j['json-forced']) {
    chrome.storage.local.set(j);
    console.info('preferences are updated by an admin');
  }
});
```

**Verdict**: MEDIUM severity. The handler lacks proper input validation on the URL parameter. An attacker who can convince a user to trigger this functionality (via the options page or potentially through a malicious website if CSP is weak) could load configurations from arbitrary origins. The risk is mitigated by the fact that the attacker would need to either control the options page interaction or find an XSS vulnerability in the extension's pages.

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated" - however, upon inspection, the code is cleanly written and appears to be original source code without obfuscation. The complexity of the user-agent parsing and network header manipulation logic may have triggered this flag, but it is a false positive.

The EXFILTRATION flow (chrome.storage.local.get → fetch) is technically accurate - the extension does fetch from remote URLs based on stored configuration. However, this is not covert data exfiltration; it's an explicitly documented remote configuration feature. The risk lies in the lack of security controls around this feature rather than malicious exfiltration.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| webextension.org | Homepage/FAQ redirect on install/update | Extension name, version, install type | LOW - Standard analytics/support |
| User-configured remote URL | Fetch extension preferences JSON | None (GET request) | MEDIUM - No origin restrictions |

The extension does not contain any hardcoded external API endpoints beyond the homepage URL. The remote configuration endpoint is entirely user-defined, which is both a feature and a risk.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

User-Agent Switcher and Manager provides legitimate functionality for its stated purpose of user-agent spoofing. The core privacy concern with such extensions - that they modify browser fingerprinting characteristics - is inherent to their purpose and not a vulnerability.

However, the remote configuration feature introduces a MEDIUM severity risk:

1. **No cryptographic signing or integrity verification** - Configurations fetched from remote URLs are applied directly without validation
2. **No origin restrictions** - Any HTTPS URL can be used as a configuration source
3. **Requires user interaction** - Exploitation requires the user to explicitly configure a remote URL, limiting the attack surface
4. **Enterprise use case** - The feature appears designed for managed deployments but lacks the security controls typically required for such scenarios

The extension does not exhibit malicious behavior such as:
- Undisclosed data collection or exfiltration
- Credential harvesting
- Hidden network communications
- Malicious code injection

**Recommendations for developers**:
1. Implement configuration signing/verification for remote configs
2. Add a whitelist of trusted configuration domains
3. Require explicit user confirmation before applying remote configurations
4. Add visual indicators when remote configuration is active
5. Use Chrome's managed storage API for enterprise deployments instead of custom remote fetch

**Recommendations for users**:
- Only configure remote-address if you fully trust the configuration source
- Avoid clicking "Update" buttons in the options page unless you understand what remote URL is configured
- For most users, leave the remote-address field empty (default behavior)
