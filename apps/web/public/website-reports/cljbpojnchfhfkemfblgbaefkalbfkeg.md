# Vulnerability Report: BlissNxt Phone Extension

## Metadata
- **Extension ID**: cljbpojnchfhfkemfblgbaefkalbfkeg
- **Extension Name**: BlissNxt Phone Extension
- **Version**: 1.0.5
- **Users**: Unknown (likely internal Uber deployment)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

BlissNxt Phone Extension is an internal Uber enterprise tool designed for their phone support system. The extension communicates exclusively with Uber's internal infrastructure (*.uberinternal.com) and localhost development environments. It collects agent activity data (routing status, timestamps, agent IDs) and sends it to Uber's internal "Heatpipe" event collection system.

The extension exhibits one minor security consideration related to its externally_connectable configuration, but the scope is appropriately restricted to Uber's internal domains. This is a legitimate enterprise monitoring tool with no evidence of malicious behavior or excessive data collection beyond its stated purpose.

## Vulnerability Details

### 1. LOW: Externally Connectable Configuration
**Severity**: LOW
**Files**: manifest.json
**CWE**: N/A
**Description**: The extension uses `externally_connectable` to allow external web pages to communicate with it. While this expands the attack surface, the scope is restricted to `*.uberinternal.com` and `localhost:3000`, which are appropriate for an internal enterprise tool.

**Evidence**:
```json
"externally_connectable": {
  "matches": ["https://*.uberinternal.com/*", "http://localhost:3000/*"]
}
```

**Verdict**: This configuration is appropriate for the extension's purpose as an internal enterprise tool. The wildcard subdomain is necessary for Uber's internal infrastructure, and the localhost entry supports development workflows.

## False Positives Analysis

1. **Data Exfiltration to blissnxt.uberinternal.com**: While the ext-analyzer flagged a data flow from `chrome.tabs.query` to `fetch(blissnxt.uberinternal.com)`, this is legitimate behavior. The extension:
   - Only queries tabs matching Uber's internal domains
   - Sends agent activity telemetry (routing status, timestamps) to Uber's internal event system
   - Does not access sensitive browser data like browsing history, passwords, or data from non-Uber sites

2. **Cookie Access**: The extension requests the `cookies` permission and reads cookies from `*.uberinternal.com`. Specifically, it retrieves the `bliss-agent-id` cookie to identify the agent using the phone system. This is legitimate for an enterprise phone/CRM integration tool.

3. **Tab Enumeration**: The extension uses `chrome.tabs.query()` to check if popup windows are already open and to manage its UI state. This is standard extension behavior, not reconnaissance.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://blissnxt.uberinternal.com/_events` | Heatpipe event collection | Agent ID, channel ("phone"), routing status, timestamp, source application | LOW - Internal telemetry |
| `https://blissnxt.uberinternal.com/*` (general) | Main application UI | None directly from extension | LOW - Internal application |

## Detailed Functionality

### Core Features
1. **Popup Management**: Creates a small popup window (425x350px) displaying the BlissNxt phone interface from `blissnxt.uberinternal.com`
2. **Mode Switching**: Supports production/development mode switching via context menu, changing between production and localhost URLs
3. **Activity Tracking**: When all extension tabs are closed, sends an "OFF_QUEUE" routing status event to Heatpipe

### Data Collection
The extension collects minimal telemetry:
- `agent_id`: Retrieved from cookie `bliss-agent-id` on `*.uberinternal.com`
- `channel`: Hardcoded as "phone"
- `routing_status`: "OFF_QUEUE" when extension is closed
- `timestamp_ms`: Current time
- `source_application`: "bliss-nxt"

This data is sent to `https://blissnxt.uberinternal.com/_events` using the Heatpipe event format.

### Security Boundaries
- **Host Permissions**: Restricted to `*.uberinternal.com` and `localhost:3000`
- **Content Scripts**: Only inject into Uber internal domains
- **No Cross-Origin Access**: Cannot access data from public websites
- **No Sensitive Permissions**: Does not request tabs, history, bookmarks, or webRequest permissions

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This is a legitimate internal enterprise tool for Uber's phone support system with appropriate security boundaries. The extension:

1. **Scope-Limited**: Only operates on Uber's internal infrastructure, preventing access to user browsing data
2. **Minimal Permissions**: Uses only necessary permissions (storage, contextMenus, cookies)
3. **Transparent Telemetry**: Collects only operational metrics (agent status, timestamps) for internal monitoring
4. **Enterprise Context**: Designed for internal deployment to Uber support agents, not public distribution

The one identified vulnerability (externally_connectable) is rated LOW because the scope is appropriately restricted to internal domains. This extension poses no risk to general Chrome users and minimal risk to Uber employees who would knowingly install it as part of their work tools.

**Recommendation**: No action required. This is appropriate enterprise software for its intended use case.
