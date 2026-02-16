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
    phrase: "ad blocker",
    extensionId: "gbdjcgalliefpinpmggefbloehmmknca", // Ad block & Adblocker (critical) — 700K users
    annotations: [
      { permission: "tabs", title: "Every URL Uploaded", description: "Every page you visit is sent to smartadblocker.com with a persistent tracking UUID" },
      { permission: "<all_urls>", title: "Cross-Device Tracking", description: "Your tracking ID syncs across all your devices via chrome.storage.sync" },
    ],
  },
  {
    phrase: "focus timer",
    extensionId: "laankejkbhbdhmipfmgcngdelahlfoji", // StayFocusd (high) — 700K users, Sensor Tower
    annotations: [
      { permission: "tabs", title: "AI Chats Uploaded", description: "Your ChatGPT, Gemini & DeepSeek conversations are sent to Sensor Tower" },
      { permission: "webNavigation", title: "Search Queries Captured", description: "Every URL parameter — including Google searches — is uploaded to Sensor Tower" },
    ],
  },
  {
    phrase: "VPN proxy",
    extensionId: "adlpodnneegcnbophopdmhedicjbcgco", // Troywell VPN (critical) — 600K users
    annotations: [
      { permission: "proxy", title: "You're an Exit Node", description: "Unknown traffic is routed through your home connection as a residential proxy" },
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
    phrase: "ad skip tool",
    extensionId: "pcjlckhhhmlefmobnnoolakplfppdchi", // Ad Speedup (critical) — 200K users
    annotations: [
      { permission: "tabs", title: "ChatGPT Sessions Stolen", description: "Creates hidden ChatGPT tabs to hijack your access tokens and prompts" },
      { permission: "*://*/*", title: "Residential Proxy Botnet", description: "Your browser becomes a proxy node via orangemonkey.site command server" },
    ],
  },
  {
    phrase: "screen timer",
    extensionId: "elfaihghhjjoknimpccccmkioofjjfkf", // StayFree (critical) — 200K users, Sensor Tower
    annotations: [
      { permission: "*://*/*", title: "Ad Intelligence Sensor", description: "Embeds Sensor Tower's Pathmatics SDK to scrape ads from every page" },
      { permission: "tabs", title: "AI Chats Uploaded", description: "Your ChatGPT, Gemini & Copilot prompts are sent to Sensor Tower's servers" },
    ],
  },
  {
    phrase: "Twitter tool",
    extensionId: "amoldiondpmjdnllknhklocndiibkcoe", // Tweet Hunter X (critical) — 40K users
    annotations: [
      { permission: "cookies", title: "X Session Stolen", description: "Reads your x.com auth cookies to make API calls as you" },
      { permission: "webRequest", title: "Credential Harvesting", description: "Intercepts login requests to capture your X/Twitter credentials" },
    ],
  },
  {
    phrase: "one-click VPN",
    extensionId: "fcfhplploccackoneaefokcmbjfbkenj", // Free VPN 1clickvpn (high) — 8M users
    annotations: [
      { permission: "proxy", title: "You Are the VPN", description: "Your home internet is used as a proxy to route strangers' traffic" },
      { permission: "webRequest", title: "Ads Injected", description: "Injects ads into pages you visit to generate revenue" },
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
    phrase: "new tab page",
    extensionId: "meffljleomgifbbcffejnmhjagncfpbd", // Infinite Dashboard (high) — 100K users
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
  {
    phrase: "YouTube tool",
    extensionId: "hmbnhhcgiecenbbkgdoaoafjpeaboine", // Autoskip for Youtube Ads (high) — 100K users
    annotations: [
      { permission: "declarativeNetRequest", title: "Remote Control Server", description: "Receives commands from backend.ytadblock.com to execute on your browser" },
      { permission: "<all_urls>", title: "Runs on Every Site", description: "Injected into all websites — not just YouTube — with no justification" },
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
];
