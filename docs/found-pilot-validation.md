# Found pilot validation: v0.17.0-found.2

The [published prerelease](https://github.com/found-ai/clauth/releases/tag/v0.17.0-found.2)
is ready for a small team pilot. The initial Apple Silicon Mac pilot completed
on October 16, 2026. A second person's Mac remains the next adoption check;
this is not a claim that every team environment has been validated.

## Evidence

- Release source: `32401d974a8d697869ae643379ad53e2802fba64`.
- [Candidate CI](https://github.com/found-ai/clauth/actions/runs/38834316242):
  Linux, macOS, and Windows passed. Linux coverage was 90.7%; coverage gates
  remain enabled. The local debug suite passed 6,087 tests.
- [Release build](https://github.com/found-ai/clauth/actions/runs/38834750131):
  all four platform binaries built. All four downloaded checksums were verified;
  the installed Mac binary's GitHub provenance matched the exact tag, source,
  repository, and release workflow.
- Real account switching and daemon restart preserved the selected account and
  left both live credential destinations current.
- A read-only observer sampled the selected account 512 times, from
  `2026-10-16T01:57:30Z` through `2026-10-16T13:14:13Z`. It verified two distinct
  new access tokens in both the credential file and Keychain, first at
  `07:14:08Z`, then at `13:14:13Z`. Every recorded sample passed all health checks.
  Two consumed refresh-token fingerprints in the private profile's spent record
  support these being OAuth refreshes. Token values and fingerprints are not
  published here. The observer stopped and unloaded itself after passing.
- Subsequent live checks still identified the expected account, current file
  and Keychain, successful authentication, and fresh usage data. macOS power
  history records overnight sleep/dark-wake cycles and subsequent full wake.
  This was natural sleep/wake observation, not a controlled sleep-through-expiry
  experiment.
- The published installer passed a clean installation and an upgrade from
  0.15.2, followed by binary rollback to 0.15.2 and reinstallation of the pilot.
  These checks used temporary home/config/data directories and synthetic latest
  credentials, which stayed unchanged throughout. Both binary versions ran;
  the old daemon was not started against the operator's account.

The post-merge CI run exposed a separate macOS render-test timing failure: the
logo blinked between two header comparisons. The layout test now pins its
existing test-only animation clock. The released production binary is unchanged.

## Next Mac acceptance

Use the [pinned installation and rollback instructions](found-pilot-release.md).
Keep the latest credentials when upgrading or rolling back.

1. Stop all old clauth processes, retain the old binary, install the matching
   release binary, and verify `clauth --version` is `0.17.0-found.2`. Check the
   executable path used by the daemon as well as the interactive shell.
2. Verify `clauth which --json` identifies the intended account. Check its
   `credential_sync` destinations are current. With multiple Claude profiles,
   switch to another saved account and back; confirm no unexpected capture or
   overwrite prompt appears. Account switching applies globally to Claude, so
   schedule this around active sessions.
3. Restart the daemon and use Claude normally. Confirm authentication and usage
   fetching work after a natural refresh and a sleep/wake cycle.
4. Record version, platform, timestamps, and pass/fail outcomes only. Do not
   share credential files, access tokens, refresh tokens, or token fingerprints.

Once this additional Mac passes, recommend the pinned prerelease more broadly
to the team. Automatic updates stay disabled in this build; a later signed
release/update channel needs separate validation. Linux and Windows have native
CI coverage but have not had an interactive account pilot in this rollout.
