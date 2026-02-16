# McAfee WebAdvisor - Attack Surface Map

**Extension ID:** `fheoggkfdfchfphceeifdbepaooicaho`
**Version:** 8.1.0.8572
**Manifest Version:** 3

## Permissions Analysis

### High-Risk Permissions
| Permission | Risk | Notes |
|------------|------|-------|
| `<all_urls>` | HIGH | Full web access |
| `webRequest` | HIGH | Intercepts all HTTP traffic |
| `nativeMessaging` | HIGH | Talks to local McAfee app |
| `scripting` | MEDIUM | Can inject scripts |
| `tabs` | MEDIUM | Access tab info |
| `declarativeNetRequest` | MEDIUM | Can modify network requests |
| `downloads` | LOW | Download API access |

### Content Scripts
```json
{
  "matches": ["http://*/*", "https://*/*"],
  "js": ["scripts/content_navigate_complete.js"],
  "all_frames": true,
  "run_at": "document_end"
}
```
**Note:** `all_frames: true` means content script runs in ALL iframes on every page.

### Externally Connectable - CRITICAL
```json
{
  "ids": ["*"],
  "matches": ["https://*.mcafee.com/*"]
}
```
**CRITICAL:** `ids: ["*"]` means ANY Chrome extension can send messages to this extension!

### Web Accessible Resources
- `html/*.html`
- `images/*.png`, `*.gif`, `*.svg`
- `json/*.json`
- `fonts/*.ttf`
- `css/*.css`
- `txt/*.txt`
- `MockingBird-Package/scripts/worklet_processor.js`
- `wasm_feature.wasm`

All exposed to `<all_urls>`.

---

## Entry Points

### 1. External Message Handlers
Multiple `onMessageExternal` handlers found:
- Line 6676: Native forwarding handler
- Line 10306: Auto policy handler
- Line 12218: External website handler

### 2. Native Messaging
- Connection string: `com.webadvisor.native`
- Forwards messages between extensions and native app

### 3. Content Script IPC
- Uses `chrome.tabs.sendMessage` for content script communication

---

## Dangerous Sinks (To Investigate)

### URL Navigation
- `tabs.create` - multiple locations
- `tabs.update` - multiple locations
- Need to check URL validation

### Dynamic Dispatch
- Line 10308: `this[e.request_type] && this.processMessage(e, t, n)`
- Line 12220: `this[e.request_type] && this.processMessage(e, t, n)`

### Property Access
- Line 10373: `Rt[e.payload.name]` - reads property by user-controlled name

### Native Message Forwarding
- Line 6672-6674: Forwards payloads to native app
- Line 6703: `this._nativePostMessage(e)`

---

## Investigation Status

- [x] Trace all `tabs.update` calls for URL validation
- [x] Check if external message dynamic dispatch is exploitable
- [x] Analyze native message forwarding for injection
- [x] Check postMessage handlers for origin validation
- [x] Look for innerHTML/eval sinks with user input

---

## Final Findings

### Vulnerability Assessment

| Severity | Issue | Exploitable? |
|----------|-------|--------------|
| INFO | `externally_connectable.ids: ["*"]` | Protected by internal whitelist |
| INFO | Dynamic dispatch `this[e.request_type]` | Protected by URL/extension validation |
| INFO | Native message forwarding | Protected by extension whitelist |
| INFO | `MPC_DOMAIN_IN_USE` URL setting | Protected by mcafee.com URL check |
| LOW | Property read `Rt[e.payload.name]` | Info leak to mcafee.com only |

### Why No Standalone Exploits

1. **Extension-to-Extension Messaging**: Despite `externally_connectable.ids: ["*"]`, line 6680 checks `_isSupported(t.id)` against a hardcoded whitelist of McAfee extension IDs.

2. **Web Page Messaging**: Line 12219 checks `isUrlSupported(t.url)` which only allows mcafee.com domains.

3. **URL Navigation**: `openNewOrNavToUrl()` checks `startsWith("https")` blocking javascript:/data: URLs.

4. **tabs.update Calls**: All calls either:
   - Set `active: true` only (focus tab)
   - Use internal extension URLs (`chrome.runtime.getURL`)
   - Use hardcoded mcafee.com URLs

### Extension Whitelist (Chrome)
```javascript
["fheoggkfdfchfphceeifdbepaooicaho",  // WebAdvisor itself
 "cpaibbcbodhimfnjnakiidgbpiehfgci",
 "klekeajafkkpokaofllcadenjdckhinm",
 "enppghjcblldgigemljohkgpcompnjgh",
 "kanjcmmieblbpbihaafnedamppkhfadn",
 "ciahhpibjeonlihjdefecmhminjpmfkk",
 "nbeldjopgciegccabfohnefghfpinncn",
 "hkflippjghmgogabcfmijhamoimhapkh",
 "bipjijaejfebbgbhchciejpabkhgpegh"]
```

---

## Preliminary Findings

### External Messaging Validation
The external message handlers check:
1. `isUrlSupported()` - must be mcafee.com domain
2. `_isSupported()` - must be in allowed extension ID list

### URL Validation
`openNewOrNavToUrl()` checks `startsWith("https")` - blocks javascript:/data: URLs.

### SUPPORTED_WEBSITE_LIST
Only McAfee domains:
- protection.mcafee.com
- protection-dev-roadhouse-int.dvqa.mcafee.com
- protection-qa-roadhouse-int.dvqa.mcafee.com
- protection-stg-roadhouse-pub.dvqa.mcafee.com
- etc.

---

## Conclusion

**Verdict: No standalone exploits found.**

Despite having a large attack surface (12MB extension, native messaging, WASM module, runs on all pages), McAfee WebAdvisor implements proper validation:

1. External messaging protected by hardcoded extension whitelist
2. Web page messaging restricted to mcafee.com domains
3. URL navigation validates https:// scheme
4. No unsafe innerHTML/eval with external input

The `externally_connectable.ids: ["*"]` in the manifest is misleading - the code enforces its own stricter whitelist.

**Potential vectors if you have XSS on mcafee.com:**
- Set `MPC_DOMAIN_IN_USE` to arbitrary https:// URL
- Read internal state via `Rt[e.payload.name]`
- Trigger native messaging commands

But these require pre-existing compromise of mcafee.com.
