# Vulnerability Report: Endpoint Verification

## Metadata
- **Extension Name:** Endpoint Verification
- **Extension ID:** callobklhcbilhphinckomhgkigmfocg
- **Version:** 1.138.0
- **Users:** ~7,000,000
- **Author:** secureconnect-cws-publishing@google.com
- **Manifest Version:** 3
- **Published by:** Google LLC

## Executive Summary

Endpoint Verification is an **official Google enterprise security extension** used by organizations to verify device compliance with Google Workspace and BeyondCorp Enterprise policies. It collects device information (OS version, disk encryption status, screen lock, serial number, MAC addresses, device certificates, installed antivirus, firewall status, etc.) and reports it to Google's SecureConnect backend for zero-trust access control.

The extension is highly privileged and collects extensive device telemetry, but all behavior is consistent with its stated enterprise endpoint verification purpose. There is no evidence of malicious behavior, data exfiltration to unauthorized parties, obfuscation beyond standard Closure Compiler minification, or any vulnerability that could be exploited by third parties.

## Permissions Analysis

| Permission | Justification | Verdict |
|---|---|---|
| `cookies` | Monitors sign-in cookie changes for account detection | Expected |
| `idle` | Detects user idle state for sync scheduling | Expected |
| `nativeMessaging` | Communicates with native helper (`com.google.endpoint_verification.api_helper`) for device info collection | Expected |
| `storage` | Persists quirks/config, cached device data, application logs | Expected |
| `alarms` | Periodic sync scheduling | Expected |
| `enterprise.deviceAttributes` | Enterprise ChromeOS device attribute collection | Expected |
| `enterprise.platformKeys` | Enterprise certificate/key management | Expected |
| `gcm` | Google Cloud Messaging for push-triggered syncs | Expected |
| `identity` / `identity.email` | OAuth2 token acquisition for API authentication | Expected |
| `platformKeys` | Platform key operations for device attestation | Expected |
| `enterprise.reportingPrivate` | Browser security state reporting (SafeBrowsing level, password protection, etc.) | Expected |
| `offscreen` | MV3 offscreen document for fetch/network operations | Expected |
| `oauth2` (scope: cloud-platform) | Google Cloud Platform API access for verified access | Expected |
| **Host permission:** `*://*.google.com/*` | API calls to Google SecureConnect endpoints | Expected |

## Vulnerability Details

### 1. Sandboxed iframe with `unsafe-eval` CSP

- **Severity:** LOW (Informational)
- **File:** `iframe_sandbox.html`
- **Description:** The sandbox page uses `unsafe-eval` and `unsafe-inline` in its CSP to enable CSP-compatible eval for file download functionality (`SafeDownloader`). The sandbox is properly isolated with `sandbox allow-scripts` attribute and validates it is running in a sandboxed origin before accepting any messages.
- **Code:** `"sandbox": "sandbox allow-scripts allow-downloads allow-forms allow-popups allow-modals; script-src 'self' 'unsafe-inline' 'unsafe-eval'; child-src 'self'"`
- **Verdict:** FALSE POSITIVE -- Standard Google Closure Library pattern for CSP-compatible eval in sandboxed contexts. The sandbox origin check (`self.origin == "null"`) prevents exploitation.

### 2. Extensive Device Telemetry Collection

- **Severity:** INFORMATIONAL
- **Files:** `background_service_worker.js` (lines ~19530-19560)
- **Description:** The extension collects: OS version, disk encryption status, screen lock status, device serial number, device model, hostname, MAC addresses, device ID, mTLS certificate fingerprints, enterprise device certificates, secure boot status, OS patch updates, installed/enabled antiviruses, Windows domain name, OS firewall status, browser info (version, affiliation IDs, security settings).
- **Verdict:** EXPECTED -- This is the entire purpose of an endpoint verification/zero-trust compliance extension. All data is sent to Google SecureConnect APIs only.

### 3. Native Messaging to Local Helper

- **Severity:** INFORMATIONAL
- **File:** `background_service_worker.js` (line ~17515)
- **Description:** Connects to `com.google.endpoint_verification.api_helper` native host for device data retrieval, file reading (registry/plist), and key management.
- **Verdict:** EXPECTED -- Native helper is required for OS-level device information that browser APIs cannot provide.

## False Positive Table

| Pattern | Location | Reason |
|---|---|---|
| `unsafe-eval` in CSP | `manifest.json` sandbox | Google Closure Library CSP-compatible eval in sandboxed iframe only |
| `fetch()` calls | `offscreen_script.js`, `background_service_worker.js` | Standard HTTP client for Google API communication |
| `chrome.runtime.connectNative()` | `background_service_worker.js` | Expected native messaging for device info collection |
| `chrome.cookies.onChanged` | `background_service_worker.js` | Monitors Google sign-in cookies for account detection |
| `chrome.enterprise.reportingPrivate` | `background_service_worker.js` | Expected enterprise browser security state reporting |
| Clearcut/play.google.com logging | `background_service_worker.js` | Google internal telemetry/analytics (Clearcut) -- standard for Google products |
| `sendBeacon` to play.google.com | `background_service_worker.js` | Google Clearcut analytics flush on page hide |
| `chrome.identity.getAuthToken` | `background_service_worker.js` | OAuth2 token for Google API authentication |
| `importScripts` not found | N/A | MV3 service worker, no dynamic script loading |

## API Endpoints Table

| Endpoint | Purpose | Auth |
|---|---|---|
| `https://secureconnect-pa.clients6.google.com/v1:enrollDevice` | Device enrollment | SAPISIDHASH cookie |
| `https://secureconnect-pa.clients6.google.com/v1:reportDeviceState` | Device state reporting | SAPISIDHASH cookie + OAuth |
| `https://secureconnect-pa.clients6.google.com/v1:getManagementState` | Check management level | SAPISIDHASH cookie |
| `https://secureconnect-pa.clients6.google.com/v1:updatePartnerData` | Update partner data (CrowdStrike ZTA etc.) | SAPISIDHASH cookie |
| `https://secureconnect-pa.clients6.google.com/v1:getProxyConfig` | Proxy configuration | SAPISIDHASH cookie |
| `https://secureconnect-pa.mtls.clients6.google.com/*` | mTLS variant of above | Client certificate |
| `https://verifiedaccess.googleapis.com` | Verified Access challenge | OAuth |
| `https://accounts.google.com/ListAccounts` | Account discovery | Cookie |
| `https://play.google.com/log` | Clearcut telemetry | Cookie |

## Data Flow Summary

1. Extension starts on browser launch / install / alarm / cookie change
2. Lists Google accounts via `accounts.google.com/ListAccounts`
3. Checks management state for each account via SecureConnect API
4. For managed accounts, collects device info via:
   - Chrome Enterprise APIs (`enterprise.reportingPrivate`, `enterprise.deviceAttributes`, `enterprise.platformKeys`)
   - Native messaging helper (`com.google.endpoint_verification.api_helper`) for OS-level data
   - ChromeOS-specific APIs on CrOS devices
5. Signs collected data with platform keys / verified access challenge
6. Reports device state to `secureconnect-pa.clients6.google.com`
7. Updates UI icon based on sync status
8. Periodically re-syncs (configurable, default ~50 minutes)
9. Logs telemetry events to Google Clearcut (`play.google.com/log`)

All data flows are to Google-owned domains only. No third-party data exfiltration observed.

## Overall Risk Assessment

**CLEAN**

This is a legitimate Google enterprise security extension (Endpoint Verification / BeyondCorp). While it collects extensive device telemetry and uses highly privileged permissions, all behavior is consistent with its stated purpose of verifying device compliance for zero-trust access. The code is compiled with Google Closure Compiler (standard for Google products, not obfuscation). All API endpoints are Google-owned. The native messaging host is Google's official endpoint verification helper. No malicious behavior, unauthorized data collection, or exploitable vulnerabilities were identified.
