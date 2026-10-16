# Found clauth pilot: v0.17.0-found.1

Found's pilot fork of [uwuclxdy/clauth](https://github.com/uwuclxdy/clauth),
based on upstream `9726ec3b7477e8abfd6df7f9d7953e0ac8ae92bc`.

This release repairs credential publication after failed token rotations and
restarts, recognizes previously managed stale credentials, and protects
unfamiliar logins from automatic replacement. Synchronization status is exposed
through the existing status/which JSON output. See
[the recovery design](https://github.com/found-ai/clauth/blob/v0.17.0-found.1/docs/credential-sync-recovery.md) for migration and concurrency
limitations.

## Pilot installation

Use this release for the initial local pilot. Team adoption follows verification
of real account switches, at least two natural token rotations, and a daemon
restart. Automated tests include injected publication failures and a real
throwaway macOS Keychain test; those do not replace observation of real sessions.

Download the binary matching your platform and `sha256sums.txt` from
[this exact Found release](https://github.com/found-ai/clauth/releases/tag/v0.17.0-found.1).
Verify the binary's SHA-256 against the corresponding entry before installation.
Release assets also have GitHub build-provenance attestations. Pilot checksum
files are unsigned unless a Found release-signing secret is configured.

Alternatively, download and inspect the installer from this exact tag, then run:

```sh
CLAUTH_INSTALL_DIR="$HOME/.local/bin" bash install.sh
```

The installer always downloads this exact Found release, including when Cargo
is installed. It refuses a missing or mismatched checksum. Source installation
must also name the fork and tag explicitly:

```sh
cargo install --git https://github.com/found-ai/clauth --tag v0.17.0-found.1 --locked clauth
```

Before replacing an existing installation, retain its binary and stop every
clauth daemon/TUI. Restart all clauth processes from the pilot binary, and
verify `clauth --version` reports `0.17.0-found.1`. Claude sessions are external
credential writers and do not participate in clauth's installation lock.

Background self-updates and remote automatic reinstalls are disabled in the
pilot build regardless of saved settings or `CLAUTH_NO_UPDATE`. This is a
build-level gate. The dormant update endpoint points to Found, but enabling it
requires a Found signing key, a configured release channel, and validation of
that path. Manual upgrades remain available.

## Verify and roll back

Verify `clauth which`, perform a deliberate account switch and switch back, and
inspect `credential_sync` in `clauth which --json`. It should identify the
expected owner and current applicable destinations. Record only non-secret
status and timestamps when observing rotations. Unknown historical credentials
are protected; preserve and resolve an unrecognized login before reinstalling
a profile.

Rollback replaces the binary and restarts all clauth processes. Keep the newest
profile credentials and session-token files. Do not restore an old credential
backup: it may contain a refresh token that has already been consumed.
