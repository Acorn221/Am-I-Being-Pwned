# Vulnerability Report: MSN New Tab

## Metadata
- **Extension ID**: lklfbkdigihjaaeamncibechhgalldgl
- **Extension Name**: MSN New Tab
- **Version**: 2.8.0.2
- **Users**: ~500,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

MSN New Tab is an official Microsoft browser extension that replaces the new tab page with MSN content featuring news, search, and frequently visited sites. The extension exhibits one minor dark pattern issue where it displays a manipulative popup trying to discourage users from changing their new tab preference back. The extension also collects telemetry data including machine IDs and sends pings to Microsoft servers for analytics purposes. Given that this is an official Microsoft product with disclosed functionality, the privacy concerns are within expected norms for a corporate-backed extension, though the competitor popup represents a questionable UX practice.

## Vulnerability Details

### 1. LOW: Dark Pattern Competitor Popup

**Severity**: LOW
**Files**: content.js
**CWE**: CWE-451 (User Interface Misrepresentation of Critical Information)
**Description**: The extension detects when users attempt to change their new tab page away from MSN and displays a manipulative popup overlay with messaging designed to discourage this action.

**Evidence**:
```javascript
// content.js lines 26-87
(async () => {
    const url = new URL(location.href);
    if (url.searchParams.get("pc") !== "U526" || url.searchParams.get("ocid") !== "chromentpnews") return;
    if (document.referrer) return;

    const timestamp = await chrome.runtime.sendMessage("checkCompetitorPopup")
    if (timestamp) return;

    const popup = document.createElement("div");
    popup.innerHTML = `
        <div class="msnnewtab-competitorpopup">
            <h1>
                <span>Wait—don't change it back!</span>
            </h1>
            <p>If you do, you'll turn off <span>MSN New Tab</span> and lose access to the latest news...</p>
            <p>Select <span>Keep it</span> to continue using MSN New Tab</p>
        </div>
    `;
    document.body.appendChild(popup);
})();
```

**Verdict**: While manipulative, this is a one-time popup (timestamp prevents re-showing) and users can dismiss it with a click. This is a dark pattern UX practice but not a security vulnerability. Common among extensions trying to retain users, though ethically questionable.

## False Positives Analysis

1. **Telemetry Collection**: The extension sends pings to `g.ceipmsn.com` with machine IDs, extension version, browser info, and usage status. While this tracks users, it's within expected behavior for official Microsoft products and likely disclosed in privacy policies.

2. **Cookie Access**: The extension reads cookies from `browserdefaults.microsoft.com` and `msnnewtab.microsoft.com` to retrieve partner codes and channel information. This is for attribution tracking of installation source, not credential theft.

3. **Installation Redirects**: Opens a Microsoft analytics URL on install (`go.microsoft.com/fwlink/?linkid=2128904`) - standard conversion tracking for marketing purposes.

4. **Uninstall URL**: Sets an uninstall URL pointing to a feedback form - legitimate practice for gathering user feedback.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://www.microsoftstart.com | New tab content | URL parameters (pc, ocid) | Low |
| https://browserdefaults.microsoft.com | Partner code retrieval | Cookie access only | Low |
| https://msnnewtab.microsoft.com | Partner code retrieval | Cookie access only | Low |
| http://g.ceipmsn.com/8SE/44 | Telemetry pings | Machine ID, extension ID, version, browser info, status, language, channel | Low |
| https://go.microsoft.com/fwlink/?linkid=2128904 | Install analytics redirect | Extension ID, partner code, market, channel, machine ID | Low |
| https://go.microsoft.com/fwlink/?linkid=2138838 | Uninstall feedback | Extension ID, market, machine ID, browser | Low |
| https://assets.msn.com | Static assets (logos) | None | Low |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This is an official Microsoft extension that functions as advertised - replacing the new tab page with MSN content. The main concern is the use of a dark pattern popup to discourage users from changing their new tab preference, which is manipulative but not malicious. The telemetry collection is extensive but expected for a Microsoft product and likely disclosed in privacy policies. The extension uses reasonable permissions scoped to Microsoft domains, implements MV3, and does not exhibit any credential theft, code injection, or undisclosed data exfiltration behaviors. The dark pattern popup is a minor UX ethics issue rather than a security vulnerability.

**Recommendation**: The extension is safe to use for users who want MSN content on their new tab. Users should be aware that Microsoft collects usage telemetry and that the extension will attempt to retain users with persuasive messaging if they try to switch away.
