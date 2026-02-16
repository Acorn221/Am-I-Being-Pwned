# Vulnerability Report: Tab Reloader (page auto refresh)

## Metadata
- **Extension ID**: dejobinhdiimklegodgbmbifijpppopn
- **Extension Name**: Tab Reloader (page auto refresh)
- **Version**: 0.6.6
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Tab Reloader is a legitimate productivity extension that allows users to automatically reload browser tabs on scheduled intervals. The extension provides extensive configuration options including custom reload schedules, conditional reloading based on tab state, content change detection via SHA-256 hashing, and custom JavaScript code execution. While the core functionality is benign and appropriate for its stated purpose, the extension includes features that allow user-defined code injection which presents minor security concerns when combined with optional `<all_urls>` permissions.

The extension demonstrates good security practices in several areas: it uses MV3 architecture, implements proper permission handling with optional host permissions, and includes legitimate use of dynamic code execution for user customization. However, the lack of input validation on user-provided JavaScript code could potentially be exploited if a malicious actor gains access to the user's browser profile or tricks users into configuring dangerous reload scripts.

## Vulnerability Details

### 1. LOW: User-Controlled Code Injection Without Validation

**Severity**: LOW
**Files**: reload.js (lines 218-243, 338-384), context.js (lines 3-44)
**CWE**: CWE-94 (Improper Control of Generation of Code)
**Description**: The extension allows users to configure custom JavaScript code that executes in both isolated and MAIN world contexts when tabs reload. This code is stored in `profile['code-value']` and `profile['pre-code-value']` and is executed without any validation or sanitization.

**Evidence**:
```javascript
// reload.js lines 218-243 - Pre-code execution in MAIN world
if (profile['pre-code']) {
  const code = profile['pre-code-value'];

  try {
    const [{result}] = await api.inject(tabId, {
      world: 'MAIN',
      func: code => {
        const s = document.createElement('script');
        s.textContent = code;
        document.body.append(s);
        s.remove();

        return s.dataset.continue;
      },
      args: [code]
    });

    if (result !== 'true') {
      return skip(`Policy Code return "${result}"`);
    }
  }
  catch (e) {
    console.warn(e);
    return skip(`Policy Code Failed "${e.message}"`);
  }
}
```

```javascript
// reload.js lines 338-384 - Post-reload code execution
if (profile.code && profile['code-value'].trim()) {
  const id = 'scr-' + Math.random();
  api.inject(tabId, {
    func: id => {
      const span = document.createElement('span');
      span.id = id;
      span.addEventListener('post', e => chrome.runtime.sendMessage(e.detail));

      document.documentElement.append(span);
    },
    args: [id]
  }).then(() => api.inject(tabId, {
    world: 'MAIN',
    func: (id, code) => {
      const span = document.getElementById(id);
      span.remove();
      const s = document.createElement('script');
      s.textContent = code;
      // ... event listener setup
      document.body.append(s);
      s.remove();
    },
    args: [id, profile['code-value']]
  })).catch(error);
}
```

**Verdict**: This is a LOW severity issue because:
1. The user must explicitly configure this code themselves through the extension's options
2. The extension requests optional permissions rather than mandatory `<all_urls>` access
3. The code runs in the user's own browser with their own data
4. This is a documented feature for power users who want custom reload behaviors

However, it does present a minor risk if a malicious actor gains access to the user's browser profile or social engineers users into pasting dangerous code.

### 2. LOW: CSP Removal Feature

**Severity**: LOW
**Files**: context.js (lines 229-283)
**CWE**: CWE-693 (Protection Mechanism Failure)
**Description**: The extension provides a context menu option to remove Content Security Policy headers from web pages using declarativeNetRequest API. This weakens browser security protections.

**Evidence**:
```javascript
else if (info.menuItemId === 'csp.remove') {
  if (tab.url.startsWith('http')) {
    let origin = tab.url.replace(/^https*/, '*');
    try {
      origin = '*://' + (new URL(tab.url)).hostname + '/';
    }
    catch (e) {}

    api.permissions.request({
      origins: [origin]
    }).then(async granted => {
      if (granted) {
        try {
          const [{result}] = await api.inject(tab.id, {
            world: 'MAIN',
            func: msg => {
              return confirm(msg);
            },
            args: [chrome.i18n.getMessage('bg_msg_3')]
          });
          if (result === true) {
            await chrome.declarativeNetRequest.updateSessionRules({
              removeRuleIds: [tab.id],
              addRules: [{
                id: tab.id,
                action: {
                  type: 'modifyHeaders',
                  responseHeaders: [{
                    header: 'Content-Security-Policy',
                    operation: 'remove'
                  }]
                },
                condition: {
                  tabIds: [tab.id],
                  urlFilter: '*/*/*',
                  resourceTypes: ['main_frame']
                }
              }]
            });
          }
        }
```

**Verdict**: This is a LOW severity issue because:
1. It requires explicit user action through the context menu
2. It requests permission dynamically and shows a confirmation dialog
3. It's limited to the specific tab (session rules only)
4. It's a legitimate feature for developers/power users testing sites with strict CSP
5. The rules are session-based and can be reset

This is an intentional feature for legitimate use cases (debugging, testing) rather than a vulnerability.

## False Positives Analysis

The following patterns were identified but are NOT security concerns:

1. **Dynamic Script Injection for Visual Countdown**: The extension injects scripts for displaying countdown timers (`vcd.js`) and scroll-to-end functionality (`ste.js`). These are legitimate UI features with fixed, reviewed code.

2. **SHA-256 Hash Calculation**: The extension calculates SHA-256 hashes of page content to detect changes (`sha.js`). This is a legitimate feature for conditional reloading and does not exfiltrate data.

3. **External URL in Manifest**: The homepage URL `https://webextension.org/listing/tab-reloader.html` is a legitimate project website, not an exfiltration endpoint.

4. **Offscreen Document for Audio**: Uses offscreen API to play notification sounds on page changes. This is proper MV3 architecture for background audio.

5. **Form Data Handling in Reload**: The `form` parameter option reloads pages by removing query parameters. This is a legitimate feature to handle form resubmission warnings.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| webextension.org | Extension homepage/documentation | None (referenced in manifest only) | None |
| chrome.storage.local | Local configuration storage | User preferences, reload profiles | None - local only |

**Note**: No external API calls detected in the code. All network activity is browser-initiated page reloads.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

Tab Reloader is a legitimate productivity tool with a clear, stated purpose that it fulfills appropriately. The extension follows MV3 best practices and uses optional permissions rather than requesting broad access by default.

The two identified issues are both LOW severity:

1. The custom code execution feature is an intentional power-user capability that requires explicit user configuration. While it lacks input validation, this is acceptable given that users are injecting code into their own browsing sessions with full awareness.

2. The CSP removal feature is also intentional and properly gated behind permission requests and confirmation dialogs.

Neither issue represents undisclosed behavior, hidden data collection, or malicious intent. The extension does not:
- Exfiltrate user data
- Make unauthorized network requests
- Inject ads or affiliate links
- Access sensitive information beyond what's necessary for tab reloading
- Include obfuscated code or suspicious patterns

The extension is suitable for users who need automatic tab reloading functionality and understand the security implications of using custom JavaScript code injection features. Standard users who don't configure custom code or CSP removal face essentially no security risk from this extension.

**Recommendation**: Safe for general use. Power users should exercise caution when configuring custom JavaScript code execution and only use trusted code snippets.
