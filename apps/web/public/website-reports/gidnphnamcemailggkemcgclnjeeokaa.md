# Vulnerability Report: Tealium Tools

## Extension Metadata

- **Extension Name**: Tealium Tools
- **Extension ID**: gidnphnamcemailggkemcgclnjeeokaa
- **Version**: 3.0.34
- **User Count**: ~30,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

Tealium Tools is a legitimate developer tools extension designed for Tealium iQ integration and tag management. The extension provides comprehensive debugging and configuration capabilities for websites using Tealium's Customer Data Platform. While the extension requests broad permissions and collects telemetry data, all functionality aligns with its stated purpose as a professional development tool. No malicious behavior or critical vulnerabilities were identified.

**Overall Risk Level: CLEAN**

The extension serves its intended purpose as a developer tool without exhibiting malicious behavior. Permissions and data collection are appropriate for its debugging and tag management functionality.

---

## Detailed Analysis

### 1. Manifest Analysis

**Permissions Requested:**
- `activeTab` - Access current tab
- `scripting` - Execute scripts in pages
- `storage` - Store configuration/session data
- `cookies` - Read cookies for Tealium integration
- `notifications` - User notifications
- `webRequest` - Monitor network requests
- `declarativeNetRequest` / `declarativeNetRequestFeedback` - Modify network requests
- `contextMenus` - Add context menu items
- `sidePanel` - Side panel UI

**Host Permissions:**
- `https://*/*` and `http://*/*` - All websites

**Content Security Policy**: Not explicitly defined (uses MV3 defaults)

**Verdict**: ✅ **APPROPRIATE** - Permissions align with stated functionality for tag debugging and environment switching. Broad host permissions necessary for developer tools that work across any website.

---

### 2. Background Script Analysis

**File**: `background.js`

**Key Functionality:**

1. **Environment Switching** (Lines 192-240)
   - Uses `declarativeNetRequest` API to redirect Tealium tag loads between environments
   - Implements URL/regex-based request interception for `utag.js` files
   - Legitimate debugging feature for QA/staging environments

2. **SSO Login Flow** (Lines 118-191)
   - Manages Single Sign-On authentication to Tealium iQ platform
   - Opens popup window for login, extracts session tokens via script injection
   - Stores UTK (Tealium tracking key) and user email in local storage
   - Cookie extraction from `window.utui.login.email` and `localStorage.utk`

3. **Telemetry Collection** (via imported modules)
   - Tracks extension install/update events
   - Sends usage analytics to `https://collect.tealiumiq.com/event`
   - Collects: user email, tool version, browser info, domain, session IDs
   - **No sensitive page content or user data collected**

4. **Custom Tool Fetch Proxy** (Lines 271-295)
   - Background script can execute `fetch()` calls on behalf of content scripts
   - Used for API calls to Tealium platform endpoints
   - Error handling includes stack trace sanitization

**Network Endpoints:**
- `https://collect.tealiumiq.com/event` - Telemetry endpoint (background telemetry)
- `https://datacloud.tealiumiq.com/*` - Tealium platform APIs
- `https://tags.tiqcdn.com/utag/*` - Tag file downloads

**Verdict**: ✅ **CLEAN** - Background script implements legitimate debugging tools. Telemetry is minimal and only tracks extension usage, not user browsing data.

---

### 3. Content Script Analysis

**Files**:
- `scripts/import-content-script.js` - Loader
- `scripts/content-script.js` - Main content script

**Key Functionality:**

1. **Message Passing Bridge** (Lines 18-43)
   - Listens for `window.postMessage` from injected page-level scripts
   - Relays messages to background script via `chrome.runtime.sendMessage`
   - Uses unique ID `202601141213` to namespace messages

2. **Script Injection** (Lines 145-168)
   - Dynamically injects web-accessible scripts into page context
   - Scripts include: account profile grabbers, cookie helpers, debugger, data exporters
   - All injected scripts are from extension's own bundle (not remote)

3. **Tool Storage** (Lines 30-33)
   - Stores custom tool data in chrome.storage for persistence
   - `CustomToolsSend` and `CustomToolsResults` storage keys

4. **Error Handling** (Lines 137-142)
   - Catches and reports errors to background script
   - Stack traces are sanitized before transmission

**Verdict**: ✅ **CLEAN** - Content script acts as a bridge between page context and extension background. No DOM manipulation, keylogging, or data harvesting detected.

---

### 4. Web Accessible Resources

**34 injected scripts** including:
- `get_account_profile.js` - Extracts Tealium account/profile from page's `window.utag`
- `grab_utui_email.js` / `grab_utk.js` - Extract session info from Tealium UI
- `launch_utag_debugger.js` - Tag debugger initialization
- `trace_kill_visitor_session.js` - Debugging visitor session reset
- `cookie_helper-*.js` - Cookie manipulation for testing
- `*-exporter-*.js` / `*-migrate-*.js` - Data export/migration tools
- `selector_tool-import-page-code.js` - CSS selector tool

**Analysis of sample scripts:**

**`trace_kill_visitor_session.js`** (Lines 65-73):
- Calls `window.utag.track('kill_visitor_session')` to reset visitor tracking
- Legitimate debugging function for testing visitor profiles
- Only works on pages with Tealium implementation

**Verdict**: ✅ **CLEAN** - All web-accessible scripts are legitimate debugging utilities that interact with Tealium's own platform code (`window.utag`, `window.tealium`). No malicious script injection detected.

---

### 5. Data Collection & Privacy

**Telemetry Payload** (from `chunks/utils2.js` lines 4203-4209):
```javascript
{
  tealium_account: "tealium",
  tealium_profile: "tools",
  tealium_datasource: "kceqf5",
  tealium_event: <event_name>,
  tealium_visitor_id: <uuid>,
  user: <email_if_logged_in>,
  internal_user: <boolean_if_@tealium.com>,
  tool_version: "3.0.34-ef38068b-202601141213",
  local_timestamp: <timestamp>,
  useragent: <browser_UA>,
  domain_prefix: <user_setting>,
  sso: <sso_settings>,
  store_id: <extension_id>,
  browser: "chrome"
}
```

**Data Collected:**
- Extension usage events (install, update, tool launches)
- Error logs (sanitized stack traces, no PII)
- User email (only if logged into Tealium platform)
- Session/visitor IDs (Tealium-specific UUIDs)
- Tool configuration settings

**NOT Collected:**
- Browsing history
- Page content or user inputs
- Credentials/passwords
- Cross-site tracking data
- Personal user data beyond email

**Storage:**
- `chrome.storage.local`: User settings, visitor ID, user email
- `chrome.storage.session`: Session ID, event counters, custom tool data

**Verdict**: ✅ **ACCEPTABLE** - Telemetry is limited to extension functionality tracking and error reporting. No invasive user data collection. Email collection only occurs when user authenticates with Tealium platform.

---

### 6. Permission Usage Justification

| Permission | Purpose | Justified? |
|------------|---------|------------|
| `activeTab` | Inject debugging scripts | ✅ Yes |
| `scripting` | Execute tag debuggers | ✅ Yes |
| `storage` | Save user settings/sessions | ✅ Yes |
| `cookies` | Read Tealium cookies for debugging | ✅ Yes |
| `webRequest` | Monitor tag loads for environment switcher | ✅ Yes |
| `declarativeNetRequest` | Redirect tag loads between environments | ✅ Yes |
| `notifications` | Notify login/operation status | ✅ Yes |
| `contextMenus` | Quick access to side panel | ✅ Yes |
| `sidePanel` | Persistent debugging UI | ✅ Yes |
| `host_permissions: <all_urls>` | Debug any website using Tealium | ✅ Yes |

---

### 7. Security Observations

**Positive Security Practices:**
1. ✅ Manifest V3 compliance (modern security model)
2. ✅ No `eval()` or dynamic code execution detected
3. ✅ All resources bundled (no remote script loading)
4. ✅ CSP-compliant (MV3 defaults)
5. ✅ Error sanitization before telemetry transmission
6. ✅ Session tokens stored in `chrome.storage.session` (cleared on browser close)
7. ✅ Password explicitly NOT stored (per documentation)

**Low-Risk Observations:**
1. ⚠️ Broad host permissions - **Justified** as developer tool needs to work on any site
2. ⚠️ DeclarativeNetRequest usage - **Justified** for environment switching feature
3. ⚠️ Telemetry to `collect.tealiumiq.com` - **Acceptable** for product analytics
4. ⚠️ Email collection - **Transparent** and only for authenticated users

---

### 8. Code Quality & Obfuscation

**Build Process:**
- Webpack/Rollup bundled (standard minification)
- React framework detected (utils2.js contains React library code)
- Variable mangling present but not malicious obfuscation
- Source maps not included (typical for production builds)

**Verdict**: ✅ Standard production build. No suspicious obfuscation patterns.

---

## False Positive Analysis

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|----------|
| `fetch()` in background | background.js:274 | Proxy for content script API calls | ✅ False Positive |
| Telemetry to external domain | utils2.js:4229 | Product analytics to Tealium's own service | ✅ False Positive |
| Cookie access | background.js:108, userAuth.js:71 | Reading Tealium session cookies for debugging | ✅ False Positive |
| Email extraction | background.js:46 | From `window.utui.login.email` on Tealium platform only | ✅ False Positive |
| DeclarativeNetRequest redirect | background.js:198-209 | Environment switcher for QA/staging workflows | ✅ False Positive |
| Script injection | content-script.js:145-159 | Legitimate debugging scripts into page context | ✅ False Positive |

---

## API Endpoints

| Endpoint | Purpose | Method | Data Sent |
|----------|---------|--------|-----------|
| `https://collect.tealiumiq.com/event` | Extension telemetry | POST | Usage events, errors |
| `https://datacloud.tealiumiq.com/*` | Tealium CDP APIs | Various | User queries/exports |
| `https://tags.tiqcdn.com/utag/*` | Tag file access | GET | None (downloads only) |
| `https://my.tealiumiq.com/*` | Tealium UI integration | Various | User operations |

All endpoints belong to Tealium's infrastructure (legitimate vendor).

---

## Data Flow Summary

1. **User Interaction** → Extension popup/side panel
2. **Tool Activation** → Content script injects debugging scripts
3. **Page Data Extraction** → Scripts read `window.utag` / `window.tealium` objects (Tealium's own data)
4. **Environment Switching** → DeclarativeNetRequest redirects tag loads
5. **Telemetry** → Usage events sent to `collect.tealiumiq.com`
6. **Storage** → User settings/sessions in `chrome.storage`

**No cross-site data leakage or unauthorized third-party data sharing detected.**

---

## Vulnerabilities

### None Identified

No security vulnerabilities, malicious behavior, or privacy violations were found. The extension operates as documented.

---

## Overall Risk Assessment

**Risk Level**: **CLEAN**

**Justification**:
Tealium Tools is a legitimate professional developer tool for debugging and managing Tealium tag implementations. While it requests extensive permissions, all are justified for its stated purpose:

- **Environment switching** requires request interception
- **Tag debugging** requires script injection and cookie access
- **Data export tools** require storage and API access
- **Cross-site functionality** requires `<all_urls>` permissions (works on any client website)

The extension serves a valid enterprise use case and does not exhibit malicious behavior. Telemetry collection is minimal, transparent, and limited to product analytics. No user browsing data, credentials, or sensitive information is harvested.

**Recommendation**: Safe for use by Tealium customers and developers. Extension is functioning as designed without privacy violations or security risks.

---

## Summary

Tealium Tools is a **clean, legitimate developer tool** for Tealium's Customer Data Platform. Extensive permissions are necessary and appropriate for tag management debugging across customer websites. No malicious patterns detected.

