#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::profile::{AppState, OAuthToken, Profile};
use crate::testutil::HomeSandbox;

const NOW: u64 = 1_900_000_000_000;

fn creds(token: &str) -> ClaudeCredentials {
    ClaudeCredentials {
        claude_ai_oauth: Some(OAuthToken {
            access_token: token.into(),
            refresh_token: None,
            expires_at: Some(NOW as i64 + 8 * 3_600_000),
            scopes: Some(vec!["user:inference".into(), "user:profile".into()]),
            subscription_type: Some("team".into()),
            ..OAuthToken::default_extra()
        }),
    }
}

fn fixture() -> (HomeSandbox, ProfileName) {
    let home = HomeSandbox::new();
    let name = ProfileName::from("sync-test");
    let mut profile = Profile::new(name.to_string(), None, None);
    profile.credentials = Some(creds("A"));
    crate::profile::save_profile(&profile).unwrap();
    let mut state = AppState::default();
    state.profiles.push(name.clone());
    state.active_profile = Some(name.clone());
    crate::profile::save_app_state(&state).unwrap();
    begin_install(&name).unwrap();
    (home, name)
}

fn advance(name: &ProfileName, token: &str) {
    remember_current(name).unwrap();
    with_state_lock(|held| {
        crate::profile::write_profile_credentials(name, Some(&creds(token)), held)
    })
    .unwrap();
}

struct Fake {
    file: Observation,
    keychain: Observation,
    fail_write: bool,
    fail_read: bool,
    lose_verification: bool,
    next_read_fails: bool,
    race: bool,
    writes: usize,
}

impl Fake {
    fn new(token: &str) -> Self {
        Self {
            file: Observation::Login(fingerprint(token)),
            keychain: Observation::Login(fingerprint(token)),
            fail_write: false,
            fail_read: false,
            lose_verification: false,
            next_read_fails: false,
            race: false,
            writes: 0,
        }
    }
    fn slot(&mut self, dest: Destination) -> &mut Observation {
        match dest {
            Destination::File => &mut self.file,
            Destination::Keychain => &mut self.keychain,
        }
    }
}

impl Backend for Fake {
    fn has_keychain(&self) -> bool {
        true
    }
    fn read(&mut self, dest: Destination) -> Result<Observation> {
        if self.fail_read || std::mem::take(&mut self.next_read_fails) {
            anyhow::bail!("injected read failure");
        }
        Ok(self.slot(dest).clone())
    }
    fn write(
        &mut self,
        dest: Destination,
        expected: &Observation,
        incoming: &ClaudeCredentials,
    ) -> Result<()> {
        self.writes += 1;
        if self.race {
            *self.slot(dest) = Observation::Login(fingerprint("foreign"));
        }
        anyhow::ensure!(self.slot(dest) == expected, "concurrent login");
        if self.fail_write {
            anyhow::bail!("injected write failure");
        }
        *self.slot(dest) = Observation::Login(fingerprint(incoming.access_token().unwrap()));
        self.next_read_fails = self.lose_verification;
        Ok(())
    }
}

#[test]
fn failed_keychain_and_file_writes_recover_after_multiple_rotations_and_restart() {
    let (_home, name) = fixture();
    let mut backend = Fake::new("A");
    reconcile_with(&name, NOW, true, &mut backend).unwrap();
    backend.fail_write = true;
    for token in ["B", "C", "D"] {
        advance(&name, token);
        reconcile_with(&name, NOW, true, &mut backend).unwrap();
    }
    let disk = read().unwrap().unwrap();
    assert_eq!(
        disk.keychain.confirmed.as_deref(),
        Some(fingerprint("A").as_str())
    );
    assert_eq!(disk.keychain.state, SyncState::Unavailable);
    // No process-local state is retained by reconcile_with: a restarted daemon
    // reads this journal and repairs directly to D, without another refresh.
    backend.fail_write = false;
    reconcile_with(&name, NOW + MAX_BACKOFF_MS, false, &mut backend).unwrap();
    assert_eq!(backend.keychain, Observation::Login(fingerprint("D")));
    assert_eq!(backend.file, backend.keychain);
    assert_eq!(read().unwrap().unwrap().keychain.state, SyncState::Current);
}

#[test]
fn stale_file_is_owned_without_recapturing_credentials() {
    let (_home, name) = fixture();
    let path = crate::profile::claude_dir()
        .unwrap()
        .join(".credentials.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    atomic_write_600(&path, serde_json::to_vec(&creds("A")).unwrap()).unwrap();
    advance(&name, "B");
    assert!(crate::claude::live_login_is_stored(&name));
    assert!(!crate::claude::live_diverged_and_unsaved(&name).unwrap());
    reconcile_with(&name, NOW, true, &mut Native).unwrap();
    let live: ClaudeCredentials = crate::profile::read_json_file(&path).unwrap();
    assert_eq!(live.access_token(), Some("B"));
    assert_eq!(
        crate::profile::read_json_file::<ClaudeCredentials>(
            &crate::claude::install_source_path(&name).unwrap()
        )
        .unwrap()
        .access_token(),
        Some("B")
    );
}

#[test]
fn foreign_logins_and_unreadable_files_are_preserved() {
    let (_home, name) = fixture();
    advance(&name, "B");
    let mut backend = Fake::new("foreign");
    backend.file = Observation::Corrupt;
    reconcile_with(&name, NOW, true, &mut backend).unwrap();
    assert_eq!(backend.writes, 0);
    let j = read().unwrap().unwrap();
    assert_eq!(j.file.state, SyncState::Conflict);
    assert_eq!(j.keychain.state, SyncState::Conflict);
}

#[test]
fn unreadable_keychain_is_not_treated_as_an_empty_item() {
    let (_home, name) = fixture();
    advance(&name, "B");
    let mut backend = Fake::new("A");
    backend.fail_read = true;
    reconcile_with(&name, NOW, true, &mut backend).unwrap();
    assert_eq!(backend.writes, 0);
    assert_eq!(
        read().unwrap().unwrap().keychain.state,
        SyncState::Unavailable
    );
}

#[test]
fn write_without_verification_is_pending_and_later_acknowledged() {
    let (_home, name) = fixture();
    advance(&name, "B");
    let mut backend = Fake::new("A");
    backend.lose_verification = true;
    reconcile_with(&name, NOW, true, &mut backend).unwrap();
    assert_eq!(
        read().unwrap().unwrap().keychain.state,
        SyncState::Unavailable
    );
    assert_eq!(
        read().unwrap().unwrap().keychain.attempted,
        Some(fingerprint("B"))
    );
    let writes = backend.writes;
    backend.lose_verification = false;
    reconcile_with(&name, NOW + MAX_BACKOFF_MS, false, &mut backend).unwrap();
    assert_eq!(
        backend.writes, writes,
        "read-back recovery must not rewrite a landed token"
    );
    assert_eq!(read().unwrap().unwrap().keychain.state, SyncState::Current);
}

#[test]
fn crash_after_profile_save_is_recovered_from_pre_rotation_history() {
    let (_home, name) = fixture();
    advance(&name, "B"); // no reconcile: process dies after saving the profile
    let mut backend = Fake::new("A");
    reconcile_with(&name, NOW, false, &mut backend).unwrap();
    assert_eq!(backend.keychain, Observation::Login(fingerprint("B")));
}

#[test]
fn a_foreign_login_arriving_during_a_write_is_not_acknowledged() {
    let (_home, name) = fixture();
    advance(&name, "B");
    let mut backend = Fake::new("A");
    backend.race = true;
    reconcile_with(&name, NOW, true, &mut backend).unwrap();
    assert_eq!(backend.keychain, Observation::Login(fingerprint("foreign")));
    assert_ne!(read().unwrap().unwrap().keychain.state, SyncState::Current);
    let writes = backend.writes;
    backend.race = false;
    reconcile_with(&name, NOW + MAX_BACKOFF_MS, false, &mut backend).unwrap();
    assert_eq!(backend.writes, writes);
    assert_eq!(read().unwrap().unwrap().keychain.state, SyncState::Conflict);
}

#[test]
fn expired_desired_tokens_are_never_installed() {
    let (_home, name) = fixture();
    advance(&name, "B");
    let mut backend = Fake::new("A");
    reconcile_with(&name, NOW + 9 * 3_600_000, true, &mut backend).unwrap();
    assert_eq!(backend.writes, 0);
    assert_eq!(read().unwrap().unwrap().keychain.state, SyncState::Expired);
}

#[test]
fn retry_backoff_is_bounded_and_does_not_require_another_rotation() {
    let (_home, name) = fixture();
    advance(&name, "B");
    let mut backend = Fake::new("A");
    backend.fail_write = true;
    reconcile_with(&name, NOW, false, &mut backend).unwrap();
    let writes = backend.writes;
    backend.fail_write = false;
    reconcile_with(&name, NOW + 1, false, &mut backend).unwrap();
    assert_eq!(backend.writes, writes);
    reconcile_with(&name, NOW + SCAN_MS, false, &mut backend).unwrap();
    assert_eq!(backend.keychain, Observation::Login(fingerprint("B")));
}

#[test]
fn switching_profile_or_partial_switch_prevents_outgoing_retry() {
    let (_home, old) = fixture();
    advance(&old, "B");
    let new = ProfileName::from("incoming");
    let mut profile = Profile::new(new.to_string(), None, None);
    profile.credentials = Some(creds("X"));
    crate::profile::save_profile(&profile).unwrap();
    let mut state = crate::profile::load_app_state().unwrap();
    state.profiles.push(new.clone());
    crate::profile::save_app_state(&state).unwrap();
    begin_install(&new).unwrap(); // crash here, before active marker advances
    let mut backend = Fake::new("X");
    reconcile_with(&old, NOW, true, &mut backend).unwrap();
    assert_eq!(backend.writes, 0);
    state.active_profile = Some(new.clone());
    crate::profile::save_app_state(&state).unwrap();
    reconcile_with(&old, NOW, true, &mut backend).unwrap();
    assert_eq!(backend.writes, 0);
    reconcile_with(&new, NOW, true, &mut backend).unwrap();
    assert_eq!(read().unwrap().unwrap().owner, new);
}

#[test]
fn absent_or_corrupt_journals_do_not_claim_foreign_credentials() {
    let (_home, name) = fixture();
    std::fs::remove_file(path().unwrap()).unwrap();
    let mut backend = Fake::new("foreign");
    reconcile_with(&name, NOW, true, &mut backend).unwrap();
    assert_eq!(backend.writes, 0);
    atomic_write_600(&path().unwrap(), b"{broken").unwrap();
    assert!(reconcile_with(&name, NOW, true, &mut backend).is_err());
    assert!(!recognizes(&name, Destination::Keychain, "foreign"));
    assert_eq!(backend.writes, 0);
}

#[test]
fn journal_permissions_secrets_and_history_bound() {
    let (_home, name) = fixture();
    let mut backend = Fake::new("A");
    backend.fail_write = true;
    for n in 0..(HISTORY_LIMIT + 10) {
        advance(&name, &format!("synthetic-secret-{n}"));
        reconcile_with(&name, NOW, true, &mut backend).unwrap();
    }
    let bytes = std::fs::read(path().unwrap()).unwrap();
    assert!(
        !String::from_utf8(bytes)
            .unwrap()
            .contains("synthetic-secret")
    );
    let j = read().unwrap().unwrap();
    assert!(j.file.known.len() <= HISTORY_LIMIT);
    assert!(
        j.file.owns(&fingerprint("A")),
        "failed publication must never evict the installed anchor"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn disabled_deleted_and_disowned_profiles_cannot_publish() {
    let (_home, name) = fixture();
    advance(&name, "B");
    let mut backend = Fake::new("A");
    let mut p = crate::profile::load_profile(&name).unwrap();
    p.disabled = true;
    crate::profile::save_profile(&p).unwrap();
    reconcile_with(&name, NOW, true, &mut backend).unwrap();
    assert_eq!(backend.writes, 0);
    forget(&name).unwrap();
    assert!(!recognizes(&name, Destination::File, "A"));
    let mut state = crate::profile::load_app_state().unwrap();
    state.profiles.clear();
    crate::profile::save_app_state(&state).unwrap();
    reconcile_with(&name, NOW, true, &mut backend).unwrap();
    assert_eq!(backend.writes, 0);
}

#[test]
fn empty_keychain_is_repaired_but_absent_file_is_not_resurrected() {
    let (_home, name) = fixture();
    advance(&name, "B");
    let mut backend = Fake::new("A");
    backend.keychain = Observation::Missing;
    backend.file = Observation::Missing;
    reconcile_with(&name, NOW, true, &mut backend).unwrap();
    assert_eq!(backend.file, Observation::Missing);
    assert_eq!(backend.keychain, Observation::Login(fingerprint("B")));
}

#[test]
fn read_modify_write_preserves_non_login_file_blocks() {
    let (_home, name) = fixture();
    let path = crate::profile::claude_dir()
        .unwrap()
        .join(".credentials.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut value = serde_json::to_value(creds("A")).unwrap();
    value["mcpOAuth"] = serde_json::json!({"test-server": {"accessToken":"mcp-synthetic"}});
    value["other"] = serde_json::json!({"device":"synthetic"});
    atomic_write_600(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    advance(&name, "B");
    reconcile_with(&name, NOW, true, &mut Native).unwrap();
    let after: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(after["mcpOAuth"], value["mcpOAuth"]);
    assert_eq!(after["other"], value["other"]);
    assert!(after["claudeAiOauth"].get("refreshToken").is_none());
}

#[test]
#[ignore = "child process fixture; invoked by installation_lock_serializes_processes"]
fn installation_lock_child() {
    let root = std::env::var_os("CLAUTH_TEST_SYNC_ROOT").expect("child root");
    crate::profile::set_home_override(root.into());
    crate::lock::set_state_lock_timeout_override(Some(Duration::from_millis(80)));
    assert!(
        with_state_lock(|_| Ok(())).is_err(),
        "a second process must not publish during repair"
    );
}

#[test]
fn installation_lock_serializes_processes() {
    let (_home, _name) = fixture();
    let _publication = InstallationLock::acquire().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "credential_sync::tests::installation_lock_child",
            "--ignored",
            "--nocapture",
        ])
        .env("CLAUTH_TEST_SYNC_ROOT", crate::profile::home_dir().unwrap())
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn backwards_clock_step_does_not_extend_a_retry_forever() {
    let (_home, name) = fixture();
    advance(&name, "B");
    let mut backend = Fake::new("A");
    backend.fail_write = true;
    reconcile_with(&name, NOW, false, &mut backend).unwrap();
    backend.fail_write = false;
    let earlier = NOW - 86_400_000;
    reconcile_with(&name, earlier, false, &mut backend).unwrap();
    assert!(read().unwrap().unwrap().keychain.retry_at <= earlier + MAX_BACKOFF_MS);
    reconcile_with(&name, earlier + MAX_BACKOFF_MS, false, &mut backend).unwrap();
    assert_eq!(backend.keychain, Observation::Login(fingerprint("B")));
}

#[test]
fn same_profile_cli_switch_repairs_a_managed_file_without_recapture() {
    let (_home, name) = fixture();
    let path = crate::profile::claude_dir()
        .unwrap()
        .join(".credentials.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    atomic_write_600(&path, serde_json::to_vec(&creds("A")).unwrap()).unwrap();
    advance(&name, "B");
    let config = crate::profile::load_config().unwrap();
    assert_eq!(
        crate::which::resolve_global(&config).unwrap().1,
        crate::which::Source::ManagedPredecessor
    );
    crate::actions::switch_profile_cli(config, &name).unwrap();
    let live: ClaudeCredentials = crate::profile::read_json_file(&path).unwrap();
    assert_eq!(live.access_token(), Some("B"));
}

#[test]
fn real_rename_and_delete_actions_retire_old_publication_ownership() {
    let (_home, old) = fixture();
    let new = ProfileName::from("renamed");
    let mut config = crate::profile::load_config().unwrap();
    {
        let rotation = crate::actions::rotation_guard_for_mutation(&old).unwrap();
        crate::actions::rename_profile(&mut config, &old, &new, &rotation).unwrap();
    }
    assert!(!recognizes(&old, Destination::File, "A"));
    assert!(recognizes(&new, Destination::File, "A"));
    let mut backend = Fake::new("A");
    reconcile_with(&old, NOW, true, &mut backend).unwrap();
    assert_eq!(backend.writes, 0);
    {
        let rotation = crate::actions::rotation_guard_for_mutation(&new).unwrap();
        crate::actions::delete_profile(&mut config, &new, false, &rotation).unwrap();
    }
    assert!(read().unwrap().is_none());
    reconcile_with(&new, NOW, true, &mut backend).unwrap();
    assert_eq!(backend.writes, 0);
}

#[test]
fn sign_out_and_api_key_installations_cannot_resurrect_oauth_credentials() {
    let (_home, name) = fixture();
    let handle = std::sync::Arc::new(crate::lockorder::RankedMutex::new(
        crate::profile::load_config().unwrap(),
    ));
    crate::actions::switch_off(&handle).unwrap();
    assert!(read().unwrap().is_none());
    let mut backend = Fake::new("A");
    reconcile_with(&name, NOW, true, &mut backend).unwrap();
    assert_eq!(backend.writes, 0);
    let mut state = crate::profile::load_app_state().unwrap();
    state.active_profile = Some(name.clone());
    crate::profile::save_app_state(&state).unwrap();
    begin_install(&name).unwrap();
    let api = ProfileName::from("api-only");
    let profile = Profile::new(
        api.to_string(),
        Some("https://example.invalid".into()),
        Some("synthetic-key".into()),
    );
    crate::profile::save_profile(&profile).unwrap();
    begin_install(&api).unwrap();
    assert!(read().unwrap().is_none());
    state.active_profile = Some(api.clone());
    state.profiles.push(api.clone());
    crate::profile::save_app_state(&state).unwrap();
    reconcile_with(&api, NOW, true, &mut backend).unwrap();
    assert_eq!(backend.writes, 0);
}

#[test]
fn malformed_observations_are_not_interpreted_as_a_signed_out_shell() {
    for value in [
        serde_json::json!("scalar"),
        serde_json::json!({"claudeAiOauth":[]}),
        serde_json::json!({"claudeAiOauth":{"accessToken":1}}),
        serde_json::json!({"claudeAiOauth":{"refreshToken":"synthetic-refresh"}}),
    ] {
        assert_eq!(Observation::from_blob(Some(&value)), Observation::Corrupt);
    }
}

#[test]
fn a_source_changed_by_an_external_writer_is_not_reinstalled_or_acknowledged() {
    let (_home, name) = fixture();
    advance(&name, "B");
    struct MovingSource {
        inner: Fake,
        name: ProfileName,
        moved: bool,
    }
    impl Backend for MovingSource {
        fn has_keychain(&self) -> bool {
            true
        }
        fn read(&mut self, dest: Destination) -> Result<Observation> {
            let observation = self.inner.read(dest)?;
            if !self.moved {
                self.moved = true;
                // Deliberately bypass clauth's locks: model a CC/editor write.
                atomic_write_600(
                    &crate::claude::install_source_path(&self.name)?,
                    serde_json::to_vec(&creds("external-newer"))?,
                )?;
            }
            Ok(observation)
        }
        fn write(
            &mut self,
            dest: Destination,
            expected: &Observation,
            incoming: &ClaudeCredentials,
        ) -> Result<()> {
            self.inner.write(dest, expected, incoming)
        }
    }
    let mut backend = MovingSource {
        inner: Fake::new("A"),
        name: name.clone(),
        moved: false,
    };
    assert!(reconcile_with(&name, NOW, true, &mut backend).is_err());
    assert_eq!(backend.inner.writes, 0);
    assert_ne!(read().unwrap().unwrap().file.state, SyncState::Current);
}
