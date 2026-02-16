export interface PermAnnotation {
  /** Matches the permission chip text, e.g. "cookies" */
  permission: string;
  /** Short label, e.g. "Cookie Theft" */
  title: string;
  /** Brief explanation, e.g. "Reads & exfiltrates session cookies" */
  description: string;
}

export interface HeroSlide {
  phrase: string;
  extensionId: string;
  annotations?: PermAnnotation[];
}

/**
 * Each slide pairs a typing phrase with a specific extension from the database.
 * The phrase describes the extension category; the card shows the real data.
 *
 * Annotations focus on what the extension ACTUALLY DOES to the user — concrete,
 * verifiable behaviours from our vulnerability reports. We never speculate about
 * intent (e.g. "sold") — only state what the code does and where data goes.
 *
 * Ordered to lead with the most shocking examples and highest user counts.
 * Data sourced from our vulnerability reports in /website-reports/.
 */
export const HERO_SLIDES: HeroSlide[] = [
  {
    phrase: "free VPN",
    extensionId: "fcfhplploccackoneaefokcmbjfbkenj", // Free VPN 1clickvpn (high) — 8M users
    annotations: [
      { permission: "proxy", title: "You Are the VPN", description: "Your home internet is used as a proxy to route strangers' traffic" },
      { permission: "webRequest", title: "Ads Injected", description: "Injects ads into pages you visit to generate revenue" },
    ],
  },
  {
    phrase: "productivity app",
    extensionId: "laankejkbhbdhmipfmgcngdelahlfoji", // StayFocusd (critical) — 700K users, owned by Sensor Tower
    annotations: [
      { permission: "tabs", title: "AI Chats Uploaded", description: "Your ChatGPT, Gemini & DeepSeek conversations are sent to Sensor Tower" },
      { permission: "webNavigation", title: "Search Queries Captured", description: "Every URL parameter — including Google searches — is uploaded to Sensor Tower" },
    ],
  },
  {
    phrase: "VPN proxy",
    extensionId: "adlpodnneegcnbophopdmhedicjbcgco", // Troywell VPN (high) — 600K users
    annotations: [
      { permission: "proxy", title: "You're an Exit Node", description: "Unknown traffic is routed through your home connection" },
      { permission: "management", title: "Kills Other Extensions", description: "Silently disables every other VPN so you can't switch away" },
      { permission: "cookies", title: "Shopping Hijacked", description: "Injects affiliate codes into your purchases via CityAds network" },
    ],
  },
  {
    phrase: "website finder",
    extensionId: "necpbmbhhdiplmfhmjicabdeighkndkn", // Similar Sites (high) — 300K users
    annotations: [
      { permission: "webRequest", title: "File Uploads Intercepted", description: "Documents you upload can be silently forwarded to a server-configured domain" },
      { permission: "tabs", title: "Encrypted Exfiltration", description: "Collected data is RSA+AES encrypted before being sent to similarsites.com" },
    ],
  },
  {
    phrase: "email tracker",
    extensionId: "bnompdfnhdbgdaoanapncknhmckenfog", // Email Tracker (high) — 300K users
    annotations: [
      { permission: "cookies", title: "Email Data Collected", description: "Email metadata and tracking data is sent to emailtracker.website servers" },
      { permission: "<all_urls>", title: "Network Hooks on All Sites", description: "Hooks XHR & fetch on every site, not just email providers" },
    ],
  },
  { phrase: "ad blocker", extensionId: "cfhdojbkjhnklbpkdaibdccddilifddb" }, // Adblock Plus (clean)
  {
    phrase: "screen time tracker",
    extensionId: "elfaihghhjjoknimpccccmkioofjjfkf", // StayFree (critical) — 200K users, also Sensor Tower
    annotations: [
      { permission: "*://*/*", title: "Ad Intelligence Sensor", description: "Embeds Sensor Tower's Pathmatics SDK to scrape ads from every page" },
      { permission: "tabs", title: "AI Chats Uploaded", description: "Your ChatGPT, Gemini & Copilot prompts are sent to Sensor Tower's servers" },
    ],
  },
  {
    phrase: "video editor",
    extensionId: "ohgkmilcibaoempgifldidkidnbkbeii", // Movie maker (critical) — 100K users
    annotations: [
      { permission: "tabs", title: "Every Site Reported", description: "Every URL you visit is hex-encoded and sent to stream.redcoolmedia.net" },
      { permission: "storage", title: "Permanent Tracking ID", description: "A unique ID stored in chrome.storage.sync follows you across devices" },
    ],
  },
  {
    phrase: "YouTube tool",
    extensionId: "hmbnhhcgiecenbbkgdoaoafjpeaboine", // Autoskip for Youtube Ads (critical) — 100K users
    annotations: [
      { permission: "declarativeNetRequest", title: "Remote Control Server", description: "Receives commands from backend.ytadblock.com to execute on your browser" },
      { permission: "<all_urls>", title: "Runs on Every Site", description: "Injected into all websites — not just YouTube — with no justification" },
    ],
  },
  {
    phrase: "browser theme",
    extensionId: "meffljleomgifbbcffejnmhjagncfpbd", // Infinite Dashboard (critical) — 100K users
    annotations: [
      { permission: "topSites", title: "Top Sites Harvested", description: "Your most-visited sites are collected and sent to infinitetab.com" },
      { permission: "<all_urls>", title: "ChatGPT Cookies Extracted", description: "Reads all your chat.openai.com cookies to make API calls on your behalf" },
    ],
  },
  {
    phrase: "notepad",
    extensionId: "fefodpegbocmidnfphgggnjcicipaibk", // Notepad online (high) — 100K users
    annotations: [
      { permission: "unlimitedStorage", title: "All Local Data Sent", description: "Your entire localStorage is dumped and uploaded to zework.com" },
      { permission: "storage", title: "Tracked Until 2033", description: "A tracking cookie is set to expire in 10+ years" },
    ],
  },
  {
    phrase: "office suite",
    extensionId: "aobjedggladklcfbokddfgjkfdioknak", // OfficeWork (critical) — 90K users
    annotations: [
      { permission: "tabs", title: "Browsing History Uploaded", description: "Every URL you visit is hex-encoded and sent to stream.redcoolmedia.net" },
      { permission: "storage", title: "Remote Tab Redirect", description: "The server can force your active tab to navigate to a different URL" },
    ],
  },
  {
    phrase: "audio editor",
    extensionId: "dfmpaemifkgbnlgcccccnfjjkeiikeie", // AudioStudio (critical) — 80K users
    annotations: [
      { permission: "tabs", title: "Full Surveillance", description: "Every page you visit is reported to redcoolmedia.net in real time" },
      { permission: "storage", title: "Remote Tab Redirect", description: "Server responses can force your active tab to navigate elsewhere" },
    ],
  },
  { phrase: "security tool", extensionId: "fheoggkfdfchfphceeifdbepaooicaho" }, // McAfee WebAdvisor (clean)
  {
    phrase: "QR code reader",
    extensionId: "likadllkkidlligfcdhfnnbkjigdkmci", // QR Code Reader (high) — 200K users
    annotations: [
      { permission: "tabs", title: "Browsing Data Sent", description: "Your browsing activity is sent to external data collection servers" },
      { permission: "storage", title: "Remote Config", description: "A remote config can expand what data is collected without an update" },
    ],
  },
  {
    phrase: "video downloader",
    extensionId: "penndbmahnpapepljikkjmakcobdahne", // Video Downloader Pro (high) — 100K users
    annotations: [
      { permission: "<all_urls>", title: "Keylogging Code Found", description: "Contains keylogging and XHR hooking code in its source" },
      { permission: "tabs", title: "Ads Injected", description: "Injects ads and affiliate links across sites you visit" },
    ],
  },
  {
    phrase: "PDF converter",
    extensionId: "kdpelmjpfafjppnhbloffcjpeomlnpah", // WPS PDF (medium) — 8M users
    annotations: [
      { permission: "cookies", title: "Has Cookie Access", description: "Requests access to cookies on all sites — far more than PDF viewing needs" },
      { permission: "nativeMessaging", title: "Reaches Your OS", description: "Talks directly to a desktop app outside the browser sandbox" },
    ],
  },
  {
    phrase: "download manager",
    extensionId: "ahmpjcflkgiildlgicmcieglgoilbfdp", // Free Download Manager (medium) — 3M users
    annotations: [
      { permission: "cookies", title: "All Headers Forwarded", description: "Every HTTP header — including cookies — is forwarded to its desktop app" },
      { permission: "history", title: "Full Traffic Visible", description: "Monitors all network requests and responses across every site" },
    ],
  },
];
