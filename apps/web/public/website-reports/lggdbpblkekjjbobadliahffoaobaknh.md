# Security Analysis Report: Tango - Document and Automate Your Processes

## Extension Metadata
- **Extension ID**: lggdbpblkekjjbobadliahffoaobaknh
- **Version**: 8.5.6
- **Users**: ~400,000
- **Developer**: Tango (tango.us)
- **Manifest Version**: 3

## Executive Summary

**OVERALL RISK: LOW**

Tango is a legitimate process documentation and workflow automation tool that captures user interactions (clicks, inputs, screenshots) to create step-by-step guides. The extension operates transparently with user consent and appears to be functioning as documented. While it has extensive permissions and captures sensitive data, this is necessary for its core functionality and data handling appears appropriate for a productivity/documentation tool.

**Key Findings:**
- ✅ Legitimate business use case (workflow documentation & automation)
- ✅ All data collection is purpose-driven and user-initiated
- ✅ API endpoints are exclusively tango.us/tango.ai domains
- ✅ No evidence of third-party data sharing or malicious SDKs
- ✅ No extension enumeration/killing behavior
- ✅ No ad injection or coupon engines
- ⚠️ Extensive data capture (screenshots, DOM, user inputs, keystrokes) - but disclosed in product purpose
- ⚠️ Chrome management API check (for enterprise deployment detection only)

## Detailed Vulnerability Analysis

### 1. Permission Scope Analysis

**Manifest Permissions:**
```json
"permissions": [
  "storage",
  "activeTab",
  "offscreen",
  "tabs",
  "scripting",
  "unlimitedStorage",
  "sidePanel",
  "webRequest"
],
"host_permissions": ["<all_urls>"]
```

**Severity**: INFORMATIONAL
**Verdict**: APPROPRIATE - All permissions are necessary for documentation/automation workflow capture.

**Details:**
- `<all_urls>`: Required to capture workflows across all websites
- `webRequest`: Used for monitoring page loads, not intercepting requests
- `scripting`: Needed to inject content scripts for DOM interaction recording
- `unlimitedStorage`: Reasonable for storing workflow snapshots and screenshots

---

### 2. User Input & Keystroke Monitoring

**File**: `/assets/BfqqK6YY.js` (DomRecorder)

**Code Evidence:**
```javascript
eventList = ["input", "click", "copy", "paste", "cut", "auxclick", "keydown"];

attachEventListeners(e) {
  for (const t of this.eventList)
    e.addEventListener(t, this.handleEvent, !0);
  e.addEventListener("mouseover", this.showElementFocus, !0);
  e.addEventListener("keydown", this.handleKeyDown, !0);
}

handleEvent = e => {
  // Captures all user interactions when recording
  const r = this.createTangoEventFromDomEvent(e, t);
  this.lastPendingTangoEvent = a.then(() => this._handleEvent(r, s))
}
```

**Severity**: MEDIUM
**Verdict**: EXPECTED BEHAVIOR - This is the core functionality.

**Context:**
- Event capture only occurs during active recording sessions initiated by user
- Data is used to generate step-by-step documentation
- The extension explicitly advertises "capture your workflow" as primary feature
- Events are processed to create structured tutorial steps, not exfiltrated raw

**Mitigations Observed:**
- Sensitive field detection and auto-blur (`isBlurred`, `isSensitive` flags)
- PII redaction mechanisms for passwords, SSNs, credit cards
- User controls to manually blur additional fields

---

### 3. Screenshot & DOM Snapshot Collection

**File**: `/assets/BfqqK6YY.js`, `/assets/CzC1tciU.js`

**Code Evidence:**
```javascript
async takeSnapshot(e) {
  // Captures DOM snapshot for each workflow step
  s = await u({ name: l.GenerateSnapshot })
  // Also captures simplified DOM structure
  e.simplifiedDom = await u({
    name: l.GenerateSimplifiedDom,
    source: "capture"
  })
}

async scheduleSave({ tangoEvent: e, isTextField: t }) {
  const n = u({
    name: l.TakeStepScreenshot,
    eventId: e.eventId
  })
}
```

**Severity**: MEDIUM
**Verdict**: EXPECTED BEHAVIOR - Screenshots are the product's core feature.

**Details:**
- Screenshots captured for each workflow step with user-initiated recording
- DOM snapshots enable automation replay (another core feature)
- Used to generate visual step-by-step guides
- Session recording via `SessionRecorder` class tracks full page interactions

**Data Collected Per Step:**
- Screenshot with bounding box highlighting target element
- Simplified DOM structure (for element identification)
- Full HTML snapshot (optional, via rrweb library)
- Target element XPath, CSS selectors, attributes

---

### 4. API Endpoints & Data Transmission

**Primary Backend**: `https://app.tango.us` (production), `https://int.tango.us` (staging)

**GraphQL API**: `https://aura.tango.us` (workflow analytics/automation backend)

**Endpoints Identified:**
```javascript
// Workflow management
`${b.webUrl}api/convert-workflow?workflowId=${t}`
`${b.webUrl}api/generate-document-name`
`${b.webUrl}api/automatix/config`
`${b.webUrl}api/ai/realtime-token`
`${b.webUrl}api/variables/label-instructions`

// Analytics (LaunchNotes - third-party product changelog service)
"https://app.launchnotes.io/graphql"
```

**Severity**: LOW
**Verdict**: CLEAN - All first-party domains, appropriate third-party.

**Data Flow:**
1. User initiates workflow capture
2. Extension records interactions → local processing
3. Screenshots uploaded to Tango backend (presigned S3 URLs)
4. Workflow metadata saved via GraphQL mutations
5. LaunchNotes used only for extension changelog announcements (non-sensitive)

---

### 5. Enterprise Deployment Detection

**File**: `/assets/DcwyZewY.js`

**Code Evidence:**
```javascript
cr = async () => {
  const e = (await chrome.management.getSelf()).installType === "admin";
  await T({
    isForceInstalled: e
  })
}
```

**Severity**: INFORMATIONAL
**Verdict**: BENIGN - Standard enterprise feature detection.

**Details:**
- Checks if extension is force-installed via enterprise policy
- Used to enable/disable certain features for managed deployments
- Does NOT enumerate or interact with other extensions
- Common pattern for enterprise SaaS products

---

### 6. Content Security Policy Analysis

**Manifest CSP:**
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
}
```

**Severity**: LOW
**Verdict**: APPROPRIATE - Minimal inline script allowances.

**Details:**
- `wasm-unsafe-eval` likely for rrweb (session replay library) or PDF generation
- No remote script sources allowed
- No eval() permissions beyond WASM

---

### 7. Automation & Element Interaction

**File**: `/assets/BH7scBx3.js`

**Code Evidence:**
```javascript
const ee = async ({ elementId, action, text, clearExisting, direction }) => {
  if (action === "go_back") return window.history.go(-1), {};
  if (action === "scroll") return { scrolled: z(direction ?? "down") };

  const a = elementId ? H(elementId) : null;
  if (action === "click") return await J(a), { title: L(a).label };
  if (action === "input_text") {
    await Y(a, text, signal, {
      insertOption: clearExisting ? C.Replace : C.Append
    })
  }
}
```

**Severity**: LOW
**Verdict**: EXPECTED BEHAVIOR - Workflow automation playback.

**Details:**
- Interactive guide feature ("Guide Me") automates documented workflows
- User explicitly triggers automation for documented processes
- Element interaction (click, type, scroll) based on saved workflow data
- Simulates user actions to guide them through multi-step processes

---

## False Positive Analysis

| Pattern | Finding | Verdict |
|---------|---------|---------|
| Sentry SDK | `SENTRY_RELEASE = { id: "extension@8.5.6" }` in multiple bundles | **FALSE POSITIVE** - Standard error tracking setup, no actual Sentry DSN/transmission found in code |
| GraphQL | Extensive GraphQL schema definitions | **FALSE POSITIVE** - Standard Apollo/GraphQL client for backend API communication |
| `window.open` hooking | Patches `window.open` to detect popup blockers | **BENIGN** - Used to handle blocked popups during workflow capture, dispatches `tangoPopupBlocked` event for logging |
| Keydown listeners | Global keydown event listeners | **EXPECTED** - Necessary for keyboard shortcut capture in workflow documentation |

---

## API Endpoints Summary

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| `https://app.tango.us/api/*` | Workflow CRUD, document generation | Workflow metadata, screenshots, DOM snapshots | LOW (first-party) |
| `https://aura.tango.us/session/*` | Session replay/analytics | Interaction traces, automation logs | LOW (first-party) |
| `https://app.launchnotes.io/graphql` | Extension changelog | Bearer token (public), query for announcements | LOW (read-only third-party) |
| AWS S3 presigned URLs | Screenshot/snapshot upload | Image blobs, HTML snapshots | LOW (temporary presigned URLs) |

---

## Data Flow Summary

### Recording Flow (User-Initiated)
```
User clicks "Record" → Content script injects DomRecorder
→ Captures: clicks, inputs, keydowns, screenshots, DOM snapshots
→ Applies PII redaction (blur sensitive fields)
→ Uploads to app.tango.us via GraphQL mutations
→ Generates shareable workflow guide
```

### Automation Flow (User-Initiated)
```
User clicks "Guide Me" → Loads workflow from API
→ Highlights next step element on page
→ Optionally auto-executes (click/type) on user confirmation
→ Tracks completion analytics to aura.tango.us
```

### Analytics/Telemetry
- Workflow view counts
- Step completion rates
- Automation success/failure metrics
- Performance tracking (snapshot generation time, DOM parsing)
- All sent to first-party Tango backends

---

## Security Posture Assessment

### Strengths
✅ **No third-party SDKs** for analytics or market intelligence
✅ **No extension enumeration** or competitive interference
✅ **No ad injection** or affiliate/coupon behavior
✅ **No proxy infrastructure** or residential proxy patterns
✅ **Transparent data collection** aligned with product description
✅ **PII redaction** mechanisms for sensitive form fields
✅ **User-initiated actions** - no background surveillance
✅ **Enterprise features** properly scoped (force-install detection)

### Concerns (Context-Appropriate)
⚠️ **Extensive data capture** - Screenshots, DOM, inputs, keystrokes
  → Mitigated by: User-initiated recording, disclosed product functionality

⚠️ **Host permissions on all URLs**
  → Mitigated by: Required for cross-site workflow documentation

⚠️ **Session replay library** (rrweb)
  → Mitigated by: Industry-standard tool for DOM recording, user-controlled

---

## Privacy Considerations

**User Consent:** Explicit - Users install Tango specifically to document workflows
**Data Minimization:** Moderate - Captures extensive data but necessary for functionality
**Retention:** Unknown - Would require reviewing Tango privacy policy
**Sharing:** No evidence of third-party data sharing in extension code
**Encryption:** HTTPS for all transmissions (first-party APIs)

**Recommended User Actions:**
- Review Tango privacy policy before capturing sensitive workflows
- Use blur tools for PII before sharing workflows
- Avoid recording workflows containing credentials or financial data
- Verify workspace access controls for shared workflows

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Tango Behavior | Match? |
|-------------------|----------------|--------|
| Sensor Tower SDK | No market intelligence SDKs found | ❌ NO |
| Extension killing | No chrome.management.setEnabled calls | ❌ NO |
| Ad injection | No DOM manipulation for ads/coupons | ❌ NO |
| Residential proxy | No peer-to-peer networking code | ❌ NO |
| Hidden telemetry | All tracking aligned with product purpose | ❌ NO |
| Remote config abuse | Config fetches are for automation rules, not malicious updates | ❌ NO |
| AI conversation scraping | No AI platform monitoring beyond Tango's own automation | ❌ NO |

---

## Verdict Summary

**RISK LEVEL: LOW**
**CLASSIFICATION: CLEAN**

Tango is a legitimate productivity tool that operates transparently within its advertised scope. While it collects extensive user data (screenshots, interactions, DOM state), this is:

1. **Disclosed** - Product is marketed as "capture and document your processes"
2. **User-initiated** - Recording only occurs when user explicitly starts capture
3. **Purpose-aligned** - All data collection serves documented workflow automation
4. **First-party** - No evidence of data sharing with third-party analytics/marketing platforms

**Recommendation:** Safe for general use with standard privacy precautions. Users should avoid recording workflows containing sensitive credentials or compliance-restricted data. Enterprise deployments should review Tango's data processing agreements.

---

## Technical Indicators

**Build System:** Vite/Rollup (modern JS bundler)
**Framework:** React (UI components in side panel/popup)
**State Management:** XState (workflow automation state machines)
**Recording Engine:** rrweb + custom DomRecorder class
**API Client:** GraphQL (Apollo/urql-style client)
**Error Tracking:** Sentry references (no active DSN found)
**Session Replay:** rrweb library (industry-standard)

**Code Quality:** Professional, well-structured, follows modern web extension patterns.

---

## Files Analyzed

**Primary Analysis:**
- `/deobfuscated/manifest.json` - Permissions and configuration
- `/deobfuscated/serviceWorker.js` → `/assets/DcwyZewY.js` - Background service worker
- `/deobfuscated/content/content.js` → `/assets/BH7scBx3.js` - Content script coordinator
- `/deobfuscated/assets/BfqqK6YY.js` - DomRecorder (event capture)
- `/deobfuscated/assets/CzC1tciU.js` - SessionRecorder (rrweb integration)
- `/deobfuscated/assets/B9ETOf1F.js` - GraphQL schema and API client
- `/deobfuscated/assets/BJAryfe0.js` - Automation engine
- `/deobfuscated/assets/LrLYpgVV.js` - GraphQL request library

**Supporting Files:** 80+ asset bundles (React components, utilities)

---

**Report Generated:** 2025-02-06
**Analyst:** Claude (Anthropic AI Security Analysis)
**Methodology:** Static code analysis, pattern matching, API endpoint enumeration, data flow tracing
