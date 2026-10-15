//! Recover publication failures independently of OAuth rotation. The profile
//! store is the authority for the *desired* login; this journal remembers what
//! each destination could still hold. It contains hashes, never credentials.
//!
//! InstallationLock serializes the entire read/check/write/read-back cycle with
//! every clauth state writer. The state flock covers journal writes only, never
//! security(1). Claude Code does not take our locks: backends recheck immediately
//! before a write and verification detects observable external interference.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::lock::{InstallationLock, with_state_lock};
use crate::profile::{ClaudeCredentials, ProfileName, atomic_write_600};

const VERSION: u32 = 1;
const HISTORY_LIMIT: usize = 32;
const SCAN_MS: u64 = 30_000;
const MAX_BACKOFF_MS: u64 = 5 * 60_000;

pub(crate) fn fingerprint(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Destination {
    File,
    Keychain,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Observation {
    Login(String),
    Empty,
    Missing,
    Corrupt,
}

impl Observation {
    pub(crate) fn from_blob(blob: Option<&serde_json::Value>) -> Self {
        let Some(value) = blob else {
            return Self::Missing;
        };
        if !value.is_object() {
            return Self::Corrupt;
        }
        let Some(oauth) = value.get("claudeAiOauth").filter(|v| !v.is_null()) else {
            return Self::Empty;
        };
        if !oauth.is_object() {
            return Self::Corrupt;
        }
        match oauth.get("accessToken") {
            Some(serde_json::Value::String(token)) if !token.is_empty() => {
                Self::Login(fingerprint(token))
            }
            Some(v) if !v.is_string() => Self::Corrupt,
            _ if oauth
                .get("refreshToken")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty()) =>
            {
                Self::Corrupt
            }
            _ => Self::Empty,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SyncState {
    #[default]
    Pending,
    Current,
    Conflict,
    Unavailable,
    Expired,
    Absent,
    NotApplicable,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Target {
    confirmed: Option<String>,
    attempted: Option<String>,
    // A bounded recent history also recognizes an older CC process putting
    // back a managed bearer. The confirmed/attempted anchors are never evicted.
    known: Vec<String>,
    state: SyncState,
    failures: u32,
    retry_at: u64,
}

impl Target {
    fn owns(&self, fp: &str) -> bool {
        self.confirmed.as_deref() == Some(fp)
            || self.attempted.as_deref() == Some(fp)
            || self.known.iter().any(|s| s == fp)
    }

    fn remember(&mut self, fp: &str) {
        if !self.known.iter().any(|s| s == fp) {
            self.known.push(fp.to_owned());
            if self.known.len() > HISTORY_LIMIT {
                self.known.remove(0);
            }
        }
    }

    fn wait(&mut self, state: SyncState, now: u64) {
        self.state = state;
        self.failures = self.failures.saturating_add(1);
        let delay = SCAN_MS
            .saturating_mul(1 << self.failures.saturating_sub(1).min(4))
            .min(MAX_BACKOFF_MS);
        self.retry_at = now.saturating_add(delay);
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Journal {
    version: u32,
    owner: ProfileName,
    generation: u64,
    desired: Option<String>,
    file: Target,
    keychain: Target,
}

impl Journal {
    fn new(owner: &ProfileName) -> Self {
        Self {
            version: VERSION,
            owner: owner.clone(),
            generation: 0,
            desired: None,
            file: Target::default(),
            keychain: Target::default(),
        }
    }

    fn target_mut(&mut self, dest: Destination) -> &mut Target {
        match dest {
            Destination::File => &mut self.file,
            Destination::Keychain => &mut self.keychain,
        }
    }
}

fn path() -> Result<PathBuf> {
    Ok(crate::profile::clauth_dir()?.join("credential-sync.json"))
}

fn read() -> Result<Option<Journal>> {
    let bytes = match std::fs::read(path()?) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("cannot read credential synchronization record"),
    };
    // Parse failures deliberately carry no serde input values to a log.
    let journal: Journal = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid credential synchronization record"))?;
    anyhow::ensure!(
        journal.version == VERSION,
        "unsupported credential synchronization record version"
    );
    Ok(Some(journal))
}

fn save(journal: &Journal) -> Result<()> {
    atomic_write_600(&path()?, serde_json::to_vec(journal)?)
        .context("cannot save credential synchronization record")
}

/// Cooperating publishers are excluded by InstallationLock. Rechecking the
/// source and generation also catches observable writes by older clauth builds
/// or Claude Code, which do not participate in that lock.
fn save_if_current(journal: &Journal) -> Result<()> {
    with_state_lock(|_| {
        let disk = read()?.context("credential synchronization record disappeared")?;
        anyhow::ensure!(
            disk.owner == journal.owner
                && disk.generation == journal.generation
                && disk.desired == journal.desired
                && crate::profile::active_profile_name().as_ref() == Some(&journal.owner)
                && crate::profile::is_configured(&journal.owner)?,
            "credential synchronization target changed; retry"
        );
        let source: ClaudeCredentials =
            crate::profile::read_json_file(&crate::claude::install_source_path(&journal.owner)?)?;
        anyhow::ensure!(
            source.access_token().map(fingerprint).as_ref() == journal.desired.as_ref(),
            "stored credentials changed during synchronization; retry"
        );
        save(journal)
    })
}

/// Record the currently trusted install source BEFORE a rotation overwrites it.
/// This migrates existing installs without trusting whatever happens to be live.
pub(crate) fn remember_current(name: &ProfileName) -> Result<()> {
    with_state_lock(|_| {
        if crate::profile::active_profile_name().as_ref() != Some(name)
            || !crate::profile::is_configured(name)?
        {
            return Ok(());
        }
        let mut journal = read()?.unwrap_or_else(|| Journal::new(name));
        // A partially completed explicit switch belongs to its incoming profile.
        // An outgoing refresh must not reverse that installation.
        if &journal.owner != name {
            return Ok(());
        }
        if let Ok(source) = crate::claude::install_source_path(name)
            && let Ok(creds) = crate::profile::read_json_file::<ClaudeCredentials>(&source)
            && let Some(token) = creds.access_token().filter(|s| !s.is_empty())
        {
            let fp = fingerprint(token);
            journal.file.remember(&fp);
            journal.keychain.remember(&fp);
            save(&journal)?;
        }
        Ok(())
    })
}

/// A staged rotation can already be saved when startup runs its hooks. Its
/// verified chain predecessor is still evidence even though the store moved.
pub(crate) fn remember_replaced(name: &ProfileName, token: &str) -> Result<()> {
    remember_current(name)?;
    with_state_lock(|_| {
        if token.is_empty() || crate::profile::active_profile_name().as_ref() != Some(name) {
            return Ok(());
        }
        if let Some(mut journal) = read()?.filter(|j| &j.owner == name) {
            let fp = fingerprint(token);
            journal.file.remember(&fp);
            journal.keychain.remember(&fp);
            save(&journal)?;
        }
        Ok(())
    })
}

/// Explicit installations may replace an unfamiliar login, just as the existing
/// switch command does. Establish new ownership BEFORE either destination moves.
pub(crate) fn begin_install(name: &ProfileName) -> Result<()> {
    with_state_lock(|_| {
        let mut journal = read()
            .ok()
            .flatten()
            .filter(|j| &j.owner == name)
            .unwrap_or_else(|| Journal::new(name));
        journal.generation = journal.generation.saturating_add(1);
        journal.desired = None;
        journal.file.retry_at = 0;
        journal.keychain.retry_at = 0;
        let source = crate::claude::install_source_path(name)?;
        if let Ok(creds) = crate::profile::read_json_file::<ClaudeCredentials>(&source)
            && let Some(token) = creds.access_token().filter(|s| !s.is_empty())
        {
            let fp = fingerprint(token);
            journal.desired = Some(fp.clone());
            for dest in [Destination::File, Destination::Keychain] {
                let target = journal.target_mut(dest);
                target.attempted = Some(fp.clone());
                target.remember(&fp);
                target.state = SyncState::Pending;
            }
            save(&journal)
        } else {
            // An explicit API-key/credential-less installation retires the
            // outgoing OAuth slot, whatever profile owned its previous record.
            match std::fs::remove_file(path()?) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            }
        }
    })
}

pub(crate) fn forget(name: &ProfileName) -> Result<()> {
    with_state_lock(|_| {
        if read().ok().flatten().is_some_and(|j| &j.owner == name) {
            match std::fs::remove_file(path()?) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    })
}

pub(crate) fn recognizes(name: &ProfileName, dest: Destination, token: &str) -> bool {
    if token.is_empty()
        || crate::profile::active_profile_name().as_ref() != Some(name)
        || !crate::profile::is_configured(name).unwrap_or(false)
    {
        return false;
    }
    read()
        .ok()
        .flatten()
        .filter(|j| &j.owner == name)
        .is_some_and(|j| {
            let target = match dest {
                Destination::File => &j.file,
                Destination::Keychain => &j.keychain,
            };
            target.owns(&fingerprint(token))
        })
}

pub(crate) fn file_owner(token: &str) -> Option<ProfileName> {
    let name = crate::profile::active_profile_name()?;
    recognizes(&name, Destination::File, token).then_some(name)
}

/// Public diagnostics omit all fingerprints. They report publication health,
/// not the validity of a server-side login.
#[derive(Clone, Debug, Serialize, Deserialize, utoipa::ToSchema)]
pub(crate) struct SyncStatus {
    #[schema(value_type = String)]
    pub(crate) profile: ProfileName,
    pub(crate) file: SyncState,
    pub(crate) keychain: SyncState,
}

pub(crate) fn status() -> Option<SyncStatus> {
    let j = read().ok()??;
    Some(SyncStatus {
        profile: j.owner,
        file: j.file.state,
        keychain: j.keychain.state,
    })
}

/// The same orchestration runs against a fake backend in ordinary tests. The
/// native adapter alone touches files or security(1).
pub(crate) trait Backend {
    fn has_keychain(&self) -> bool;
    fn read(&mut self, dest: Destination) -> Result<Observation>;
    fn write(
        &mut self,
        dest: Destination,
        expected: &Observation,
        incoming: &ClaudeCredentials,
    ) -> Result<()>;
}

struct Native;
impl Backend for Native {
    fn has_keychain(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            crate::keychain::enabled()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }

    fn read(&mut self, dest: Destination) -> Result<Observation> {
        match dest {
            Destination::File => {
                let path = crate::profile::claude_dir()?.join(".credentials.json");
                let bytes = match std::fs::read(path) {
                    Ok(bytes) => bytes,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(Observation::Missing);
                    }
                    Err(e) => return Err(e.into()),
                };
                Ok(serde_json::from_slice::<serde_json::Value>(&bytes)
                    .map(|v| Observation::from_blob(Some(&v)))
                    .unwrap_or(Observation::Corrupt))
            }
            Destination::Keychain => {
                #[cfg(target_os = "macos")]
                {
                    crate::keychain::read_sync_login()
                }
                #[cfg(not(target_os = "macos"))]
                {
                    anyhow::bail!("Keychain unavailable on this platform")
                }
            }
        }
    }

    fn write(
        &mut self,
        dest: Destination,
        expected: &Observation,
        incoming: &ClaudeCredentials,
    ) -> Result<()> {
        match dest {
            Destination::File => {
                // Recheck ownership in the same read used for the merge. An
                // external CC rename between this read and ours is still an
                // unavoidable race; verification never acknowledges a mismatch.
                let path = crate::profile::claude_dir()?.join(".credentials.json");
                let bytes = std::fs::read(&path)?;
                let value: serde_json::Value = serde_json::from_slice(&bytes)
                    .map_err(|_| anyhow::anyhow!("live credential file is unreadable"))?;
                anyhow::ensure!(
                    &Observation::from_blob(Some(&value)) == expected,
                    "live login changed during synchronization"
                );
                if path.symlink_metadata()?.file_type().is_symlink() {
                    anyhow::bail!(
                        "live credential link does not follow the selected install source"
                    );
                }
                let token = value
                    .get("claudeAiOauth")
                    .and_then(|v| v.get("accessToken"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let oauth = incoming
                    .claude_ai_oauth
                    .as_ref()
                    .context("missing incoming OAuth login")?;
                match crate::claude::follow_live_file_login(&[token], oauth)? {
                    crate::claude::LiveSlotFollow::Followed => {}
                    crate::claude::LiveSlotFollow::Unreadable(e) => return Err(e.into()),
                    _ => anyhow::bail!("live login could not be synchronized"),
                }
                Ok(())
            }
            Destination::Keychain => {
                #[cfg(target_os = "macos")]
                {
                    crate::keychain::write_sync_login(expected, incoming)
                }
                #[cfg(not(target_os = "macos"))]
                {
                    anyhow::bail!("Keychain unavailable on this platform")
                }
            }
        }
    }
}

pub(crate) fn reconcile(name: &ProfileName, force: bool) -> Result<()> {
    reconcile_with(name, crate::usage::now_ms(), force, &mut Native)
}

/// Lease-holder scheduler task: unlike rolling expiry scans, this is due even
/// while the stored bearer has hours left. No network or token rotation here.
pub(crate) fn tick() {
    if let Some(name) = crate::profile::active_profile_name()
        && let Err(e) = reconcile(&name, false)
    {
        crate::logline::logline!("clauth: credential synchronization deferred: {e}");
    }
}

pub(crate) fn reconcile_with(
    name: &ProfileName,
    now: u64,
    force: bool,
    backend: &mut impl Backend,
) -> Result<()> {
    let _publication = InstallationLock::acquire()?;
    let prepared = with_state_lock(|_| {
        if crate::profile::active_profile_name().as_ref() != Some(name)
            || !crate::profile::is_configured(name)?
        {
            return Ok(None);
        }
        let profile = crate::profile::load_profile(name)?;
        if profile.is_disabled() || crate::profile::load_app_state()?.is_auth_broken(name) {
            return Ok(None);
        }
        let mut journal = read()?.unwrap_or_else(|| Journal::new(name));
        if &journal.owner != name {
            return Ok(None);
        }
        let source = crate::claude::install_source_path(name)?;
        if !source.exists() {
            return Ok(None);
        }
        let incoming: ClaudeCredentials = crate::profile::read_json_file(&source)?;
        let Some(token) = incoming.access_token().filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        // Never leak the private rotating pair if a rolling stamp failed.
        if profile.rolling_token && incoming.refresh_token().is_some() {
            return Ok(None);
        }
        let desired = fingerprint(token);
        if journal.desired.as_ref() != Some(&desired) {
            journal.desired = Some(desired);
            journal.generation = journal.generation.saturating_add(1);
            for dest in [Destination::File, Destination::Keychain] {
                let target = journal.target_mut(dest);
                target.retry_at = 0;
                target.failures = 0;
                target.state = SyncState::Pending;
            }
        }
        save(&journal)?;
        Ok(Some((journal, incoming)))
    })?;
    let Some((mut journal, incoming)) = prepared else {
        return Ok(());
    };
    let started = Instant::now();
    for dest in [Destination::File, Destination::Keychain] {
        if dest == Destination::Keychain && !backend.has_keychain() {
            journal.keychain.state = SyncState::NotApplicable;
            with_state_lock(|_| save(&journal))?;
            continue;
        }
        let desired = journal
            .desired
            .clone()
            .context("missing desired fingerprint")?;
        let target = journal.target_mut(dest);
        // Clamp a backwards wall-clock step rather than parking indefinitely.
        target.retry_at = target.retry_at.min(now.saturating_add(MAX_BACKOFF_MS));
        if !force && now < target.retry_at {
            // Persist a backwards-clock clamp, or every tick moves the
            // deadline forward again and recovery never becomes due.
            with_state_lock(|_| save(&journal))?;
            continue;
        }
        let observed = crate::lock::with_keychain_budget(
            Duration::from_secs(20).saturating_sub(started.elapsed()),
            || backend.read(dest),
        );
        match observed {
            Err(_) => target.wait(SyncState::Unavailable, now),
            Ok(Observation::Login(ref fp)) if fp == &desired => {
                target.confirmed = Some(desired.clone());
                target.attempted = None;
                target.remember(&desired);
                target.state = SyncState::Current;
                target.failures = 0;
                target.retry_at = now.saturating_add(SCAN_MS);
            }
            Ok(Observation::Missing) if dest == Destination::File => {
                // CC may intentionally migrate to Keychain-only storage.
                target.state = SyncState::Absent;
                target.retry_at = now.saturating_add(SCAN_MS);
            }
            Ok(observation) => {
                let ours = match &observation {
                    Observation::Login(fp) => target.owns(fp),
                    Observation::Empty | Observation::Missing => true,
                    Observation::Corrupt => dest == Destination::Keychain,
                };
                // Pin the actual managed predecessor even when the desired
                // token is expired and this pass cannot install anything.
                if ours && let Observation::Login(fp) = &observation {
                    target.confirmed = Some(fp.clone());
                    target.remember(fp);
                }
                if !ours {
                    target.wait(SyncState::Conflict, now);
                } else if incoming.access_token_expires_at().is_none_or(|exp| {
                    exp <= now.saturating_add(started.elapsed().as_millis() as u64) as i64
                }) {
                    target.wait(SyncState::Expired, now);
                } else {
                    // Intent is durable before any write. A crash after writing
                    // but before acknowledgement leaves a recognized attempt.
                    if let Some(old) = target.attempted.clone() {
                        target.remember(&old);
                    }
                    target.attempted = Some(desired.clone());
                    save_if_current(&journal)?;
                    let written = crate::lock::with_keychain_budget(
                        Duration::from_secs(20).saturating_sub(started.elapsed()),
                        || {
                            backend.write(dest, &observation, &incoming)?;
                            backend.read(dest)
                        },
                    );
                    let target = journal.target_mut(dest);
                    match written {
                        Ok(Observation::Login(fp)) if fp == desired => {
                            target.confirmed = Some(desired.clone());
                            target.remember(&desired);
                            target.attempted = None;
                            target.state = SyncState::Current;
                            target.failures = 0;
                            target.retry_at = now.saturating_add(SCAN_MS);
                        }
                        Ok(Observation::Login(fp)) if !target.owns(&fp) => {
                            target.wait(SyncState::Conflict, now)
                        }
                        _ => target.wait(SyncState::Unavailable, now),
                    }
                }
            }
        }
        save_if_current(&journal)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/inline/credential_sync.rs"]
mod tests;
