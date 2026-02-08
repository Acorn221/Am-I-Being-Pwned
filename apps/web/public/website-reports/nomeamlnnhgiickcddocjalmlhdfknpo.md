# Vulnerability Assessment Report

## Extension Metadata

- **Name**: Fellow: AI Meeting Notes, Agendas, and Action items
- **ID**: nomeamlnnhgiickcddocjalmlhdfknpo
- **Version**: 2.8.5.1
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Fellow is a legitimate productivity extension for Google Meet and Google Calendar that provides AI-powered meeting notes, transcription, and collaboration features. The extension integrates with the fellow.app service to enhance meeting workflows. After comprehensive analysis, **no malicious behavior or critical vulnerabilities were identified**. The extension follows standard security practices for a meeting productivity tool and uses appropriate permissions for its stated functionality.

**Overall Risk Level: CLEAN**

## Detailed Analysis

### Manifest Analysis

**Permissions Requested:**
- `cookies` - Used to retrieve user session information from fellow.app
- `storage` - Used to store user preferences (salary settings, meeting cost display preferences)

**Host Permissions:**
- `https://*.fellow.app/*` - Access to Fellow's own domain
- `https://*.fellow.co/*` - Access to Fellow's secondary domain

**Content Scripts:**
- Google Meet (`https://meet.google.com/*`) - Injects meeting notes UI and recording controls
- Google Calendar (`https://calendar.google.com/*`) - Adds meeting management features
- Fellow domains - Adds metadata tag to identify extension presence

**Content Security Policy:** None explicitly set (uses default MV3 CSP)

**Assessment:** Permission model is appropriate and minimalistic for the stated functionality. No excessive or suspicious permissions requested.

### Background Script Analysis

**File**: `background.js`

**Key Functionality:**
1. **Cookie Management**: Reads `fellow_accounts` cookie to identify active Fellow workspace
2. **Analytics Integration**: Uses RudderStack for telemetry (write key: `2qMBuBWVTQirZytpXEH11AaSyDw`)
3. **Message Handling**: Responds to content script requests for cookies, analytics events, and settings
4. **User Info Fetch**: Contacts `{uri}/ext/notes/v2/user-info/` to retrieve user profile
5. **Extension Info Upload**: Reports extension install type and version to Fellow servers

**Network Endpoints:**
- `https://fellow.app/ext/notes/v2/user-info/` (POST) - User authentication check
- `https://fellow.app/ext/notes/v2/update-extension-info/` (POST) - Extension metadata reporting
- `https://fellowbriickyj.dataplane.rudderstack.com/v1/batch` (POST) - Analytics telemetry
- `https://heapanalytics.com/api/track` (POST) - Secondary analytics (Heap)

**Assessment:** Standard authentication and analytics flow. No suspicious API calls or data exfiltration patterns.

### Content Scripts Analysis

#### Google Meet Integration (`scripts/google/meet.js`, `scripts/videocall.js`)

**Functionality:**
1. Injects Fellow notes sidebar into Google Meet UI
2. Embeds iframe from `https://fellow.app/embedded-meetings/`
3. Manages meeting recording controls via Fellow's "Note Taker" bot
4. Displays meeting cost calculator based on attendee count and duration
5. Handles meeting start/stop/pause/resume recording via API calls

**Recording API Endpoint:**
- `{uri}/ext/notes/google-meet-meeting-recorder/` (POST)
- Parameters: `eventGuid`, `meetUrl`, `action` (start/stop/pause/resume)

**Meeting Cost Data Collection:**
- Scrapes Google Meet attendee count from people panel
- Extracts meeting duration from event details
- Sends to Fellow for cost calculation (user-configurable salary settings)

**DOM Manipulation:**
- Uses `innerHTML` for button creation (sanitized static templates)
- No user-controlled input passed to `innerHTML`
- postMessage communication restricted to fellow.app origin

**Assessment:** Legitimate meeting enhancement features. Recording functionality requires user interaction and is clearly indicated in UI.

#### Google Calendar Integration (`scripts/google/calendar.js`, `scripts/google/observer.js`)

**Functionality:**
1. Adds Fellow sidebar toggle button to Google Calendar toolbar
2. Embeds iframe from `https://fellow.app/companion-mode/`
3. Injects meeting guideline prompts (attendee limits, no-meeting days, etc.)
4. Displays meeting cost estimates in calendar event creation forms
5. Monitors calendar DOM for event changes using MutationObserver

**API Endpoints:**
- `{uri}/ext/notes/account-settings/` (GET) - Fetch workspace meeting guidelines
- `{uri}/ext/notes/meeting-cost/` (GET) - Retrieve meeting cost settings
- `{uri}/ext/notes/meeting/{eventGuid}/info/` (GET) - Check if note exists for event

**Data Collection:**
- Attendee email addresses from calendar events (for meeting cost calculation)
- Meeting duration and timing information
- Event GUID for linking to Fellow notes

**Assessment:** Standard calendar integration patterns. Data collected is minimal and directly related to stated functionality.

### Analytics and Telemetry

**RudderStack Implementation** (`scripts/rudderstack.js`):
- Forked from Segment.io analytics-node library
- Tracks extension events: installation, notes displayed/hidden, sidebar toggled, recording actions
- Collects: user ID, anonymous ID, event names, timestamps, browser metadata
- Data batched and sent to `https://fellowbriickyj.dataplane.rudderstack.com/v1/batch`

**Heap Analytics** (optional secondary channel):
- App ID: `3011455610`
- Sends track events to `https://heapanalytics.com/api/track`

**Assessment:** Standard product analytics. No PII beyond user IDs. Analytics can be blocked via browser extensions without breaking functionality.

### Third-Party Dependencies

**Identified Libraries:**
- RudderStack/Segment analytics SDK (custom implementation)
- TypeScript async/await polyfills
- No minified or obfuscated third-party code detected

**Assessment:** Minimal dependencies, all legitimate and expected for a productivity tool.

## Vulnerability Details

### No Critical or High Vulnerabilities Found

After thorough analysis of all JavaScript files, no exploitable vulnerabilities were identified.

## False Positive Analysis

| Pattern | Location | Verdict |
|---------|----------|---------|
| `innerHTML` usage | `videocall.js:259,274,632` | **FALSE POSITIVE** - Static HTML templates for UI elements, no user input |
| `innerHTML` usage | `sidebar.js:7,137,167` | **FALSE POSITIVE** - Static HTML for iframe and icon containers |
| `innerHTML` in buttons | `meetingRecorderButtons.js:50,169` | **FALSE POSITIVE** - Static SVG and button text from predefined maps |
| Cookie access | `background.js:26` | **LEGITIMATE** - Reading Fellow authentication cookies from own domain |
| postMessage calls | `videocall.js:363,558,697,839,873` | **LEGITIMATE** - Communication with own iframe on fellow.app domain |
| Fetch to third-party | `rudderstack.js:265,295` | **LEGITIMATE** - Analytics to RudderStack and Heap (standard product telemetry) |
| DOM observer | `observer.js:211,265` | **LEGITIMATE** - MutationObserver for detecting calendar event changes |
| Extension enumeration | None found | **N/A** - No attempts to detect other extensions |
| XHR/fetch hooking | None found | **N/A** - No global fetch/XHR interception |
| Remote code execution | None found | **N/A** - No eval(), Function(), or dynamic script injection |

## API Endpoints Summary

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `https://fellow.app/ext/notes/v2/user-info/` | POST | User authentication | Cookies (credentials: include) |
| `https://fellow.app/ext/notes/v2/update-extension-info/` | POST | Extension metadata | installType, mayDisable, version |
| `https://fellow.app/ext/notes/account-settings/` | GET | Meeting guidelines | None (authenticated) |
| `https://fellow.app/ext/notes/meeting-cost/` | GET | Cost calculator settings | None (authenticated) |
| `https://fellow.app/ext/notes/google-meet-meeting-recorder/` | POST | Recording control | eventGuid, meetUrl, action |
| `https://fellow.app/ext/notes/meeting/{guid}/info/` | GET | Note existence check | None (authenticated) |
| `https://fellowbriickyj.dataplane.rudderstack.com/v1/batch` | POST | Analytics telemetry | Event data, user IDs, timestamps |
| `https://heapanalytics.com/api/track` | POST | Secondary analytics | Event data (optional) |

All endpoints use HTTPS. Authentication via cookies with `credentials: include`.

## Data Flow Summary

1. **User Authentication**:
   - Extension checks for `fellow_accounts` cookie on fellow.app domain
   - Retrieves most recently used workspace URI
   - Fetches user profile from `/ext/notes/v2/user-info/`

2. **Meeting Integration**:
   - Content scripts inject Fellow UI into Google Meet/Calendar
   - Embeds iframes pointing to fellow.app for notes interface
   - Bidirectional communication via postMessage (origin-restricted)

3. **Meeting Data Collection**:
   - Scrapes meeting metadata from Google UI (attendee count, duration, emails)
   - Sends to Fellow API for cost calculation and note linking
   - User-configurable (can disable meeting cost feature)

4. **Recording Functionality**:
   - User clicks recording button in Google Meet
   - Extension sends API request to Fellow backend
   - Fellow bot joins meeting (or botless recording starts)
   - Recording status updates via postMessage from iframe

5. **Analytics**:
   - Extension events tracked locally (page views, button clicks)
   - Batched and sent to RudderStack every 10 seconds or 20 events
   - Includes extension version, anonymous ID, user ID (if authenticated)

**Privacy Notes:**
- Meeting content is NOT scraped or sent to Fellow directly by extension
- Recording is handled by Fellow's backend bot service or browser-based audio capture
- Extension only facilitates UI and API communication

## Security Strengths

1. **Minimal Permissions**: Only requests cookies and storage, no broad host permissions
2. **Manifest V3**: Uses modern extension architecture with service worker
3. **No eval()**: No dynamic code execution patterns detected
4. **Origin Restrictions**: postMessage limited to fellow.app domain
5. **HTTPS Only**: All network requests use secure transport
6. **No Obfuscation**: Code is readable and follows standard patterns
7. **Legitimate Use Case**: All functionality aligns with stated purpose

## Recommendations

1. **For Users**: Extension is safe to use. Ensure you trust Fellow with meeting metadata (attendee emails, timing, etc.) before installing.

2. **For Developers**:
   - Consider implementing Subresource Integrity (SRI) if external resources are loaded
   - Add explicit CSP header in manifest for additional hardening
   - Document data collection practices more transparently in privacy policy

3. **For Security Researchers**: No action required. Extension follows best practices.

## Overall Risk Assessment

**Risk Level: CLEAN**

Fellow is a legitimate productivity extension with appropriate permissions and transparent functionality. No malicious behavior, data exfiltration, or security vulnerabilities were identified. The extension operates as advertised and follows Chrome Web Store security best practices.

**Confidence Level: HIGH**

Analysis covered all JavaScript files, manifest configuration, API endpoints, and data flows. Code quality is professional with clear naming conventions and no suspicious obfuscation.
