# Vulnerability Report: SEO Minion

## Metadata
- **Extension ID**: giihipjfimkajhlcilipnjeohabimjhi
- **Extension Name**: SEO Minion
- **Version**: 3.19
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

SEO Minion is a legitimate SEO analysis tool that helps users with on-page SEO analysis, broken link checking, SERP preview, and other SEO-related tasks. The extension requires a Keywords Everywhere API key (Silver, Gold, or Platinum plan) to function. While the static analyzer flagged some data flows to keywordseverywhere.com and identified postMessage handlers without strict origin checks, the extension's behavior is consistent with its stated purpose as an SEO analysis tool. The extension fetches remote configuration and validates API keys, which is standard behavior for a cloud-connected tool. The risk level is LOW due to a single minor vulnerability in message handling.

## Vulnerability Details

### 1. LOW: Insecure postMessage Handlers Without Origin Validation

**Severity**: LOW
**Files**: js/sidebar-content.js, js/cs-serp-iframe.js, js/cs-google.js, js/SidebarController.js, js/SERP.js
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)

**Description**: The extension implements multiple postMessage event listeners without strict origin validation. While the code does check for a command prefix to avoid collision, it does not validate the event.origin property before processing messages.

**Evidence**:
```javascript
// sidebar-content.js line 36
window.addEventListener("message", function (event) {
  var payload = event.data;
  if (typeof payload !== 'object') return;
  var cmd = payload.cmd;
  var data = payload.data;
  var prefix = Prefix.get('');
  if (cmd.indexOf(prefix) !== 0) {
    // console.log('Command without prefix. Aborting to avoid collision', cmd, data);
    return;
  }
  // ... processes message without checking event.origin
});
```

**Verdict**: The extension uses a prefix-based command filtering mechanism rather than origin-based validation. This is a minor security weakness, but the risk is mitigated by the prefix check that prevents arbitrary messages from being processed. A malicious page could potentially craft messages with the correct prefix, but the impact is limited to UI manipulation rather than data exfiltration.

## False Positives Analysis

1. **Data Exfiltration Flag**: The static analyzer flagged storage data being sent to keywordseverywhere.com. This is expected behavior - the extension validates API keys by sending them to the backend service and fetching configuration data. The extension explicitly requests user consent and is transparent about requiring a Keywords Everywhere subscription.

2. **Remote Config**: The extension fetches configuration from `keywordseverywhere.com/seominion/service/vars.php` every 24 hours. This is standard practice for cloud-connected tools and is not malicious.

3. **WASM/Obfuscated Flags**: The static analyzer flagged WASM and obfuscation, but review of the deobfuscated code shows standard webpack-bundled JavaScript with jQuery and normal coding patterns. No true obfuscation or WASM usage detected.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| keywordseverywhere.com/service/2/getPlan.php | API key validation | User's API key | LOW - Required for subscription validation |
| keywordseverywhere.com/seominion/service/vars.php | Fetch config/locale data | Locale, timestamp | LOW - Standard remote config |
| keywordseverywhere.com/seominion/service/widget.php | Load widget iframe | URL parameters, locale | LOW - UI component loading |
| keywordseverywhere.com/seominion/service/serpWidget.php | SERP analysis widget | Version, plan tier | LOW - Functionality delivery |
| keywordseverywhere.com/seominion/setup | Installation redirect | None (navigation only) | LOW - Setup page |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: SEO Minion is a legitimate SEO tool owned by Keywords Everywhere that provides on-page analysis, broken link checking, and SERP preview functionality. The extension requires user authentication via API key and is transparent about its requirements (Silver/Gold/Platinum subscription). The data flows flagged by the static analyzer are all consistent with the extension's stated purpose:

- API key validation is necessary for subscription verification
- Remote config fetching is standard for cloud-connected tools
- SERP data analysis requires examining page content (legitimate use of broad permissions)
- Communication with keywordseverywhere.com domain is expected and disclosed

The only security concern is the lack of strict origin validation on postMessage handlers, which is a minor vulnerability that could allow UI manipulation but does not enable data theft or code execution. The extension follows MV3 best practices and does not exhibit any malicious behavior.

**Recommendation**: Users should ensure they only use the official version from the Chrome Web Store and maintain their Keywords Everywhere API key security.
