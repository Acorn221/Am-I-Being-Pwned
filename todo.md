# TODO

## Extension - `handleNewExtension` fixes

- [ ] **RISK_SEVERITY scale mismatch** - local risk threshold check compares `RISK_SEVERITY` (0-6) against `maxRiskScore` (0-100). Risk blocking silently never fires. Check if `ExtensionReport` has a numeric `riskScore` field and use that instead, or define a 0-100 mapping.
  - `apps/ext/entrypoints/background.ts` - `handleNewExtension`

- [ ] **`management.onInstalled` fires on updates** - block-first causes brief disable/re-enable on every extension auto-update for org devices. Differentiate fresh installs from updates and only apply block-first on new extension IDs.
  - `apps/ext/entrypoints/background.ts` - `management.onInstalled` listener

- [ ] **Quarantine list not checked before re-enabling** - `handleNewExtension` checks `getDisableList()` before calling `setEnabled(true)` but not `getQuarantineList()`. Could re-enable an extension currently quarantined for an unscanned update.
  - `apps/ext/entrypoints/background.ts` - `handleNewExtension`
