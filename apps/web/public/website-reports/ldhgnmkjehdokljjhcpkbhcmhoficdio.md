# Security Analysis: FileWave Inventory (ldhgnmkjehdokljjhcpkbhcmhoficdio)

## Extension Metadata
- **Name**: FileWave Inventory
- **Extension ID**: ldhgnmkjehdokljjhcpkbhcmhoficdio
- **Version**: 2025.01.22
- **Manifest Version**: 3
- **Estimated Users**: ~400,000
- **Developer**: FileWave (enterprise MDM vendor)
- **Analysis Date**: 2026-02-15

## Executive Summary
FileWave Inventory is a **legitimate enterprise device management extension** for Chromebook inventory and tracking, deployed via managed enterprise policies. The extension collects extensive device information including serial numbers, asset IDs, browsing history, geolocation, system specs, and installed extensions, then transmits this data to an admin-configured FileWave inventory server. The extension also uses Firebase Cloud Messaging for push notifications. While the data collection is extensive, it matches the disclosed purpose as stated in the manifest description: "Reports device information from enterprise-enrolled Chromebooks to FileWave inventory."

**Overall Risk Assessment: MEDIUM**

The MEDIUM rating reflects that this is enterprise software operating as designed, with disclosed data collection for inventory management. However, users should be aware that if deployed by their organization, this extension grants comprehensive device monitoring capabilities including browsing history and real-time location tracking.

## Vulnerability Assessment

### 1. Browsing History Exfiltration to Firebase
**Severity**: MEDIUM
**Files**: `background.js`

**Analysis**:
The ext-analyzer detected a data flow where `chrome.history.search` results reach Firebase API endpoints (`firebaseinstallations.googleapis.com`). This indicates that browsing history data may be transmitted as part of the Firebase Cloud Messaging registration or installation flow.

**Data Flow**:
```
chrome.history.search (browsingHistory source)
  → fetch(firebaseinstallations.googleapis.com)
```

**Context**:
While the direct connection between history data and Firebase is flagged, the primary purpose appears to be establishing Firebase Cloud Messaging for administrative notifications. The extension uses Firebase for push notifications as configured via the `FirebaseConfig` managed schema (apiKey, projectId, messagingSenderId, appId).

**Privacy Impact**:
- Browsing history is collected via the `history` permission
- May be transmitted to Firebase alongside device registration
- Admin-controlled Firebase project receives history data

**Mitigation**:
- Enterprise deployment only (requires managed_schema configuration)
- Usage disclosed in manifest description
- Deployed via enterprise policy, not user choice

**Verdict**: Expected behavior for enterprise MDM tool, but privacy-invasive. Users have limited control.

---

### 2. Extension Storage Data Exfiltration to Firebase
**Severity**: MEDIUM
**Files**: `background.js`

**Analysis**:
The analyzer detected a second exfiltration flow where `chrome.storage.local.get` data reaches the same Firebase endpoint. This suggests the extension's configuration data (including the admin-configured inventory server address, shared keys, and tracking settings) is transmitted to Firebase during initialization.

**Data Flow**:
```
chrome.storage.local.get (extensionStorage source)
  → fetch(firebaseinstallations.googleapis.com)
```

**Storage Schema** (from `schema.json`):
The extension stores the following admin-configured settings:
- `InventoryAddress`: FileWave inventory server URL
- `InventoryPort`: Server port (default 20445)
- `InventorySharedKey`: Authentication key for inventory server
- `FirebaseConfig`: Firebase credentials (apiKey, projectId, messagingSenderId, appId)
- `UpdateIntervalInMinutes`: How often to send data to inventory server
- `TrackingIntervalInMinutesWhenMissing`: Geolocation update frequency when device marked "Missing" (default 15 min)
- `TrackingDisabled`: Whether to disable tracking unconditionally

**Privacy Impact**:
- Extension configuration (including server credentials) sent to Firebase
- Enables remote configuration management via Firebase
- Admin-controlled Firebase project has access to inventory server credentials

**Verdict**: Standard Firebase Cloud Messaging initialization pattern for enterprise apps, but transmits sensitive configuration data.

---

### 3. Open postMessage Handler Without Origin Check
**Severity**: LOW
**Files**: `background.js`, `geowindow.js`

**Analysis**:
The analyzer flagged a `window.addEventListener("message")` handler without explicit origin validation in the background service worker. However, further inspection reveals this is used for internal communication between the background script and the `geowindow.html` popup window that collects geolocation data.

**Code Context** (`geowindow.js`):
The geowindow is a popup that requests `navigator.geolocation.getCurrentPosition()` and then posts the result back to the background service worker:
```javascript
navigator.geolocation.getCurrentPosition(
  (position) => {
    serviceWorkerActive.postMessage({
      type: "GET_LOCATION_SUCCESS",
      requestId: t,
      position: {
        longitude: position.coords.longitude,
        latitude: position.coords.latitude,
        accuracy: position.coords.accuracy,
        altitude: position.coords.altitude,
        altitudeAccuracy: position.coords.altitudeAccuracy,
        timestamp: position.timestamp
      }
    });
    window.close();
  },
  (error) => {
    serviceWorkerActive.postMessage({
      type: "GET_LOCATION_ERROR",
      requestId: t,
      error: {code: error.code, message: error.message}
    });
    window.close();
  },
  {maximumAge: 10000, timeout: 30000, enableHighAccuracy: true}
);
```

**Message Types**:
- `GET_LOCATION_SUCCESS`: Contains geolocation coordinates
- `GET_LOCATION_ERROR`: Contains error information

**Attack Vector**:
Since the background script doesn't validate `event.origin`, a malicious webpage could theoretically inject crafted messages. However, the attack surface is limited because:
1. Messages are between extension contexts (geowindow → background), not from web pages
2. The extension doesn't have `externally_connectable` in manifest
3. Message handler likely validates message structure/requestId

**Verdict**: Low severity - internal messaging pattern, limited external attack surface. Best practice would add origin check.

---

## Data Collection Summary

The extension collects and transmits the following data to the admin-configured FileWave inventory server:

### Device Identifiers
- Device serial number (`chrome.enterprise.deviceAttributes.getDeviceSerialNumber`)
- Device asset ID (`chrome.enterprise.deviceAttributes.getDeviceAssetId`)
- Directory device ID (`chrome.enterprise.deviceAttributes.getDirectoryDeviceId`)
- IP addresses (via WebRTC local IP discovery in popup.js)

### Network Information
- Network details (`chrome.enterprise.networkingAttributes.getNetworkDetails`)

### System Information
- CPU info (`system.cpu`)
- Memory info (`system.memory`)
- Storage info (`system.storage`)

### Browser Data
- Browsing history (`history` permission)
- Installed extensions (`management` permission)
- Content settings (`contentSettings`)
- Font settings (`fontSettings`)

### Location Data
- Real-time geolocation via `navigator.geolocation.getCurrentPosition()`
- High accuracy mode enabled
- Configurable tracking interval when device marked "Missing" (default: every 15 minutes)

### User Identity
- User email (`identity.email` permission)

### Transmission Frequency
- Configurable via `UpdateIntervalInMinutes` (set by admin)
- Tracking interval when "Missing": `TrackingIntervalInMinutesWhenMissing` (default 15 min)
- Uses `alarms` permission for scheduled updates

## Notification System

The extension includes a custom notification UI (`notification.html`, `notification.css`, `notification.js`) that displays admin-pushed messages via Firebase Cloud Messaging. Notifications can include:
- Custom title, author, body text
- Company logo (loaded from URL)
- Clickable link with custom label
- Styled using IBM Plex Sans font from Google Fonts

This allows IT administrators to push messages to managed Chromebooks (e.g., compliance reminders, security alerts).

## Enterprise Deployment Context

This extension is designed for **enterprise-managed Chromebook deployments only**. Key indicators:

1. **Managed Schema**: `schema.json` defines required configuration that must be pushed via Chrome Enterprise policy
2. **Required Fields**: `InventoryAddress` and `InventorySharedKey` are marked as required, meaning the extension won't function without admin configuration
3. **Firebase Config**: Also requires admin-provided Firebase credentials for push notifications
4. **Enterprise Permissions**: Uses `enterprise.deviceAttributes` and `enterprise.networkingAttributes` which only work on enterprise-enrolled devices

**Deployment Method**: IT administrators deploy this extension via Google Admin Console with a force-installed policy that includes the managed configuration. Individual users cannot install or configure this extension themselves.

## Privacy & Compliance Considerations

### User Awareness
- The manifest description clearly states: "Reports device information from enterprise-enrolled Chromebooks to FileWave inventory"
- However, it does not explicitly disclose browsing history collection or real-time geolocation tracking

### Data Control
- Users have **no control** over this extension if deployed by their organization
- Cannot disable, uninstall, or opt out
- All configuration managed remotely by IT administrators
- Tracking can only be disabled if admin sets `TrackingDisabled: true`

### Regulatory Concerns
Organizations deploying this extension should ensure:
- **GDPR Compliance**: Employees notified of monitoring scope (especially browsing history and location tracking)
- **CCPA Compliance**: California employees aware of data collection
- **Workplace Privacy Laws**: Disclosure requirements vary by jurisdiction
- **Consent Requirements**: Some regions may require explicit consent for location tracking

### "Missing" Device Mode
The schema includes `TrackingIntervalInMinutesWhenMissing` which enables frequent geolocation updates when a device is marked as missing. This implies:
- Stolen/lost device recovery functionality
- Could enable real-time tracking of employee movements
- Default 15-minute interval is quite aggressive
- No user override if tracking is enabled

## Security Posture

### Positive Security Indicators
- Manifest V3 (modern, more secure architecture)
- Uses service worker instead of persistent background page
- Content Security Policy: `script-src 'self'; object-src 'self'` (no inline scripts)
- No `eval()` usage detected
- Credentials stored in managed schema (not hardcoded)
- HTTPS-only endpoints

### Security Concerns
- Broad host permissions (`https://*/`) - can access all HTTPS sites
- No apparent encryption of data in transit beyond HTTPS (inventory server protocol unclear)
- Shared key authentication (`InventorySharedKey`) - unclear if this is a strong auth mechanism
- Firebase credentials stored in managed schema could be extracted by malware

## Comparison to Similar Tools

FileWave Inventory is comparable to other enterprise Chromebook management extensions like:
- Absolute Secure Access for Chromebook
- Cisco Secure Endpoint for Chrome
- VMware Workspace ONE Intelligent Hub

All share similar characteristics:
- Extensive device data collection
- Admin-controlled deployment
- Tracking/location capabilities
- Enterprise-only use case

The MEDIUM risk rating reflects that while this is a legitimate enterprise tool, the data collection is extensive and privacy-invasive. Organizations should carefully consider employee privacy rights when deploying such tools.

## Recommendations

### For IT Administrators Deploying This Extension
1. **Disclose monitoring scope** to employees in acceptable use policies
2. **Disable tracking** if real-time location is not necessary (`TrackingDisabled: true`)
3. **Increase tracking intervals** if location tracking is needed (e.g., 60 min instead of 15 min)
4. **Secure the inventory server** - ensure proper authentication, encryption, and access controls
5. **Protect Firebase credentials** - treat as sensitive secrets
6. **Regular audits** of collected data to ensure compliance with privacy policies
7. **Limit deployment** to devices where monitoring is justified (e.g., public kiosks vs. personal devices)

### For Developers (FileWave)
1. **Add origin validation** to postMessage handlers
2. **Minimize Firebase data transmission** - avoid sending history/config data if not necessary
3. **Document data flows** more transparently in privacy policy
4. **Provide privacy-preserving options** (e.g., hash browsing history before transmission)
5. **Implement client-side filtering** so admins can exclude sensitive sites from history collection

### For End Users
If this extension is deployed on your work/school Chromebook:
- Assume all browsing activity is monitored
- Your location may be tracked in real-time
- Contact IT department if you have privacy concerns
- Be aware that you cannot uninstall enterprise-managed extensions
- Consider using personal devices for sensitive browsing

## Conclusion

FileWave Inventory is a **MEDIUM risk** extension that operates as designed for its enterprise use case. The risk rating reflects:

**Why Not HIGH or CRITICAL:**
- Functionality is disclosed in manifest description
- Deployed via enterprise policy (not deceptive installation)
- Legitimate vendor (FileWave is established enterprise MDM company)
- Data sent to admin-configured server (not hidden third-party)

**Why Not LOW or CLEAN:**
- Extensive data collection including browsing history
- Real-time geolocation tracking capability
- Limited user awareness of full monitoring scope
- Potential for privacy violations if misused
- Data flows to Firebase (third-party)

**Final Verdict**: This is enterprise spyware with legitimate business justification. Organizations should deploy it responsibly with full employee disclosure. The extension itself is not malicious, but its capabilities could enable privacy violations if misused or deployed without proper consent and disclosure.
