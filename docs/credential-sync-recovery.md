# Credential publication recovery

This patch starts at upstream `9726ec3b7477e8abfd6df7f9d7953e0ac8ae92bc`.
That revision already follows a successful rotation into a regular live
credential file (#104). The remaining failure is losing recognition of a live
token after a publication fails and the profile rotates again.

## Behavior

The latest saved credential and the credential successfully installed in a live
destination have separate lifetimes. `credential-sync.json`, in the clauth
state directory, records the global slot's owner, desired token fingerprint,
generation, and independent file/Keychain publication state. Each destination
retains its last observed managed fingerprint, its unverified write attempt,
and up to 32 recent managed fingerprints. The two anchors are not evicted by
the bounded history. The record contains SHA-256 fingerprints, never tokens,
and uses the existing atomic owner-only writer.

A rotation records its trusted predecessor before overwriting the profile.
Startup recovery also records a staged rotation's predecessor when the new
pair was already saved but its publication hooks did not finish. An explicit
installation establishes ownership before either live destination moves.

The shared reconciler reads the latest install source from disk. It updates a
recognized managed predecessor, preserves an unfamiliar login, and never
installs an expired credential. A rolling profile's private refresh-bearing
pair cannot be installed when its session-token stamp is absent. File merges
preserve sibling blocks; Keychain merges retain the existing same-account
preservation and malformed-item quarantine rules. An unreadable Keychain is
never treated as an empty one for a repair.

A write intent is durable before the write. Only read-back of the desired
token acknowledges success. If the write landed but read-back failed, the
next pass can acknowledge it without rewriting it. A failed update from A to B
does not prevent a later update directly from A to C.

The usage-fetch lease holder runs reconciliation on every scheduler tick,
independently of rolling-token expiry and usage polling. Successful destinations
are checked at most once per 30 seconds. Transient failures use exponential
backoff capped at five minutes, and a new desired credential releases backoff.
Actual cadence is bounded by the scheduler's configured tick interval. Retry
deadlines persist, including a backwards-clock clamp. No OAuth request or
inference call is made by reconciliation itself.

## Concurrency

The new reentrant `.installation.lock` ranks between Config and State. Every
state-lock acquisition participates, so a repair can release the state flock
around bounded Keychain subprocesses while excluding account switches,
sign-outs, and other clauth credential writers. Its thread and process waits
are bounded. Journal writes and source snapshots use short state holds.
The reconciler shares one 20-second elapsed budget across its adapter calls;
state-flock waits do not occur inside a Keychain budget scope.

Source, owner, and generation are checked again before a write and before
acknowledgement. A partially completed switch has the incoming profile's
journal owner, so the outgoing profile's retry cannot undo that installation.
Rename/delete/sign-out retire ownership; an API-key installation retires the
outgoing OAuth slot. Disabled, removed, or quarantined profiles cannot repair
live destinations.

Claude Code and older clauth binaries do not take this new lock. There is no
atomic compare-and-swap API spanning another application's writes and the
macOS Keychain. Rechecks and verification detect observable conflicts, but
cannot eliminate an external write in the final read/write gap. All clauth
processes must use the patched build for the cross-process serialization
guarantee.

## Diagnostics and migration

`status` and the Claude `which --json` view add `credential_sync` when a record
exists. It contains the owner and per-destination states, without hashes or
credentials. Values are `pending`, `current`, `conflict`, `unavailable`,
`expired`, `absent`, or `not_applicable`. These describe publication, not
server-side authentication validity. The field is omitted when no record
exists, retaining legacy serialized output in that case.

`which` can attribute an older managed global file with source
`managed_predecessor`; that attribution does not claim freshness. Recognized
stale files no longer raise the unsaved-login prompt. Unrecognized files are
still protected, and the CLI no longer calls every mismatch a "newer login."
Switching to the already-selected profile runs guarded reconciliation, making
it useful for retrying a failed publication.

Migration does not infer ownership of an arbitrary historical token. Without
a journal, matching the current saved token can establish ownership; an old
unknown live login still requires an explicit user-directed installation or
the existing reconciliation flow. Malformed/unsupported records fail closed;
an explicit installation may replace the record.

## Verification

The new ordinary tests drive the production reconciler through an injected
backend, use synthetic credentials and `HomeSandbox`, and make no OAuth calls.
They cover multiple failed rotations, restart and crash recovery, verification
failure, foreign logins, source changes by an external writer, expired tokens,
backoff and backwards time, same-profile repair, rename/delete/sign-out/API-key
transitions, sibling preservation, and bounded secret-free persistence.
A child process tests exclusion between publication and state writers.

`repro_sync_missed_follow_survives_two_rotations` was demonstrated failing on
the baseline: the regular file retained A after the profile reached C. It
passes through the new reconciliation path.

Run the normal debug and release CI checks. The optional macOS adapter test
uses security(1) with synthetic credentials under a unique throwaway service,
cleans it up with a drop guard, and never reads or writes the operator's
`Claude Code-credentials` item:

```sh
cargo test --locked keychain::tests::credential_sync_recovers_on_a_throwaway_service -- --ignored --exact
```

The existing ordinary test configuration still disables the real Keychain
adapter. The throwaway test supplies its own adapter to the same reconciler.

## Installation and rollback

Build and review the fork before replacing the installed binary. Retain the
working binary. Stop every existing clauth daemon/TUI before switching builds,
and restart them all from the same fork build; leaving an old writer running
does not provide the installation-lock guarantee. Prevent the fork from
self-replacing with an upstream binary by setting `CLAUTH_NO_UPDATE=1` for
each fork invocation, including its daemon.

After installation, verify the chosen account and inspect synchronization
status. Exercise an explicit same-profile reinstall if migration encounters
an unknown historical login; preserve any unfamiliar login before resolving
it. Do not turn a failed publication into a fresh browser login by default.

Rollback replaces the binary and restarts its processes. Preserve the current
profile credentials and session-token files: restoring an old credential
backup can restore a refresh token that has already been consumed. The older
binary ignores the additional journal, but does not provide its recovery
behavior. Installing or restarting Eugene's live setup is outside this patch.
