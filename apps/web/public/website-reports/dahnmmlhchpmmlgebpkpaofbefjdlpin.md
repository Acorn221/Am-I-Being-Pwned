# Vulnerability Report: GamersClub Booster

## Metadata
- **Extension ID**: dahnmmlhchpmmlgebpkpaofbefjdlpin
- **Extension Name**: GamersClub Booster
- **Version**: 2.82.2
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

GamersClub Booster is a browser extension designed to enhance the user experience on GamersClub.com.br, a Brazilian Counter-Strike 2 gaming platform. The extension provides quality-of-life improvements including automatic lobby actions, UI enhancements (dark mode, compact mode), player statistics, sound notifications, and optional Discord webhook integration for match notifications.

The extension operates exclusively on the GamersClub domain and implements user-controlled Discord webhook integration for sending lobby and match information. All data collection is transparent, user-initiated, and directly supports the extension's stated purpose of enhancing the gaming platform experience. The extension poses minimal security risk and operates within the bounds of a legitimate gaming platform enhancement tool.

## Vulnerability Details

### 1. LOW: User-Controlled Discord Webhook Configuration
**Severity**: LOW
**Files**: content-scripts/lobby.js, index.js
**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
**Description**: The extension allows users to configure Discord webhooks to automatically send lobby and match information. While this is a legitimate feature disclosed in the manifest permissions (`https://discord.com/api/webhooks/*`), users should understand what data is being sent.

**Evidence**:
```javascript
// From content-scripts/lobby.js, lines 4885-4912
async function u(e, t) {
  if ("object" != typeof t) return !1;
  await i(e, {
    color: "2391737",
    fields: [{
      name: `Time ${t.teamA.admin.nick} - ` + t.teamA.averageLevel,
      value: c(t.teamA)
    }, {
      name: `Time ${t.teamB.admin.nick} - ` + t.teamB.averageLevel,
      value: c(t.teamB)
    }, {
      name: "IP da partida:",
      value: `connect ${t.ip};password ${t.password} \n[Conectar ao servidor](steam://connect/${t.ip}/${t.password})`
    }, {
      name: "Mapa:",
      value: t.map.name
    }, {
      name: "Warmup",
      value: l(t.warmupExpiresInSeconds)
    }, {
      name: "Link da partida",
      value: `https://${r.b7}/lobby/partida/${t.gameId}`
    }]
  })
}
```

Data sent to Discord webhooks (when enabled by user):
- Player nicknames and levels
- Lobby information (admin, victory sequence, pre-vetoed maps)
- Player KDR (Kill/Death Ratio) statistics
- Match server IP and password
- Team compositions
- Map information

**Verdict**: This is NOT a vulnerability but a legitimate feature. The extension clearly requests the Discord webhook permission in the manifest, and the feature is entirely opt-in. Users must manually configure their own webhook URL and explicitly enable the automatic sending features via checkboxes (`enviarLinkLobby`, `enviarPartida`). The data being sent is already visible to the user on the GamersClub platform and is not being exfiltrated to third-party servers controlled by the developer.

## False Positives Analysis

### Static Analyzer Flags

The ext-analyzer tool flagged several patterns that appear benign upon code review:

1. **EXFILTRATION flows to static.gamersclub.com.br**: These are legitimate API calls to the GamersClub platform itself to fetch player data, match history, and lobby information. The extension retrieves:
   - Player statistics (KDR, level, rating)
   - Match history
   - Lobby information
   - Player profiles

   This is expected behavior for a platform enhancement extension.

2. **CSP 'unsafe-eval'**: The manifest declares `script-src 'self' 'wasm-unsafe-eval'` for extension pages. This is a standard configuration for MV3 extensions and does not allow arbitrary `eval()` - only WebAssembly instantiation, which is not used in this extension.

3. **Obfuscated flag**: The code is webpack-bundled, which creates compressed but not maliciously obfuscated code. This is standard practice for modern JavaScript applications.

### Legitimate Platform Integration

The extension integrates deeply with GamersClub features:
- Auto-accepting ready/pre-ready states
- Automatic IP copying for game servers
- Player blocking/unblocking
- UI customizations (dark mode, compact mode)
- Sound notifications for kicks
- Warmup timers
- Complete match finder

All of these features operate on data already available on the GamersClub website and do not introduce new data collection vectors.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| static.gamersclub.com.br | Fetch player statistics and match data | Player IDs from page DOM | Low - legitimate platform API |
| gamersclub.com.br/api/box/* | Retrieve player profiles, match history | Player IDs | Low - legitimate platform API |
| gamersclub.com.br/api/player-card/* | Get player card information | Player IDs | Low - legitimate platform API |
| discord.com/api/webhooks/* | User-configured webhook (opt-in) | Lobby/match info (see above) | Low - user-controlled, opt-in |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
GamersClub Booster is a legitimate gaming platform enhancement extension with transparent functionality. The extension:

1. **Operates on the correct domain**: Only accesses GamersClub and user-configured Discord webhooks
2. **Transparent permissions**: All host permissions are clearly stated and justified
3. **User control**: Discord integration is entirely opt-in and user-configured
4. **No hidden data collection**: All API calls are to the GamersClub platform itself or user-specified webhooks
5. **Open source**: The extension appears to be open source based on references to GitHub in the code
6. **Legitimate purpose**: Enhances user experience on a gaming platform with quality-of-life features

The only minor concern is that users should be aware of what data is sent when they configure Discord webhooks, but this is a disclosed, opt-in feature with a clear purpose (sharing match information with Discord communities). The extension does not collect or transmit data to developer-controlled servers, and all functionality aligns with the stated purpose of improving the GamersClub user experience.

**Recommendation**: CLEAN for most users. Users who enable Discord integration should verify they are using their own webhook URLs and understand that lobby/match data will be posted to their configured Discord channels.
