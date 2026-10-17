//! Ephemeral synthetic joined-test bootstrap only. No spending account, witness
//! admission, opaque construction owner or completed checkpoint is seeded here.
//! The caller must drive every actual foreground Terminal challenge on a PTY.
use super::*;
use crate::{
    generation_restore::RestoredGenerationCapsule,
    recovery_generation::{
        PendingGeneration, layered::PendingLayeredGeneration, manual_target::ManualCommittedTarget,
    },
    recovery_inventory::tests::{PASSWORD, native_empty_pending_fixture},
};

/// Return a genuinely opened, natively enrolled empty layered Host and its temp
/// root. All protocol owners must subsequently be produced by their real paths.
/// Initial empty archive setup uses maintained test storage APIs only; it is
/// not evidence of attended backup consent or any prior account continuity.
pub(in crate::host) fn create(terminal: Terminal) -> Result<(tempfile::TempDir, Host)> {
    let initial=terminal.approve_historical("SYNTHETIC TEMPORARY JOINED TEST: create genuinely EMPTY encrypted Host source journals and first pending generation in a new temporary root. No spending account, seed, prior account history, proof, completion row or authority is fabricated. All contents are ephemeral test data and disappear with the owning temporary directory. This is test-controller evidence, not an attended user approval.")?;
    let mut pending: Option<(tempfile::TempDir, PendingGeneration, PathBuf)> = None;
    initial.effect(&mut || {
        pending = Some(native_empty_pending_fixture());
        Ok(())
    })?;
    let (temp, pending, g1) = pending.ok_or(Error::Invalid)?;
    let construction=terminal.approve_historical("SYNTHETIC TEMPORARY JOINED TEST: copy this genuinely empty original archive into its exact first generation. Preserve all source/destination identities and encrypted journal schemas. This authorizes only local test storage construction, never an account, financial activity or fabricated history.")?;
    let mut pending = Some(pending);
    let mut prepared = None;
    construction.effect(&mut || {
        prepared = Some(
            pending
                .take()
                .ok_or(Error::Invalid)?
                .construct()?
                .prepare_publication(vec![])?,
        );
        Ok(())
    })?;
    let prepared = prepared.ok_or(Error::Invalid)?;
    if !prepared.requests()?.is_empty() {
        return Err(Error::Authentication);
    }
    let publication=terminal.approve_publication(prepared.manifest_digest(),"SYNTHETIC TEMPORARY JOINED TEST: publish this actual empty first-generation manifest. There are genuinely no prior accounts requiring recovery admissions; this is NOT an invented empty history for any existing signer or wallet.")?;
    prepared.publish(vec![], publication)?;

    // Use the ordinary native complete-capsule backup and quarantine restore
    // code, including every exact private-read/copy/passphrase decision.
    let backup = temp.path().join("joined-g1-capsule");
    let quarantine = temp.path().join("joined-g1-quarantine");
    crate::generation_backup::backup(terminal.clone(), &g1, &backup)?;
    crate::generation_restore::restore(terminal.clone(), &backup, &quarantine)?;
    let read=terminal.approve_historical("SYNTHETIC TEMPORARY JOINED TEST: authenticate the exact just-restored empty parent capsule for a new layered Host. No account or financial original may be synthesized. This reads only this temporary test's own encrypted files.")?;
    let mut source = None;
    read.effect(&mut || {
        source = Some(RestoredGenerationCapsule::open(&quarantine, PASSWORD)?);
        Ok(())
    })?;
    let source = source.ok_or(Error::Invalid)?;
    if !source
        .capsule()
        .root()
        .current_semantics()
        .accounts()
        .is_empty()
    {
        return Err(Error::Authentication);
    }
    let target = temp.path().join("joined-layered-host");
    let create=terminal.approve_historical("SYNTHETIC TEMPORARY JOINED TEST: create a NEW exact layered generation plan/key intent for this same genuinely empty capsule. This is ephemeral non-signing storage; no old authority is revived.")?;
    let mut source = Some(source);
    let mut pending = None;
    create.effect(&mut || {
        pending = Some(PendingLayeredGeneration::create(
            source.take().ok_or(Error::Invalid)?,
            &target,
            PASSWORD,
        )?);
        Ok(())
    })?;
    let copy=terminal.approve_historical("SYNTHETIC TEMPORARY JOINED TEST: copy the exact complete authenticated parent capsule into this new layered generation and initialize only its required new empty runtime journals. Keep original graph and file identities; never insert account/constructor/proof rows.")?;
    let prepared = pending
        .ok_or(Error::Invalid)?
        .construct(&copy)?
        .prepare_publication(vec![])?;
    if !prepared.requests()?.is_empty() {
        return Err(Error::Authentication);
    }
    let publication=terminal.approve_publication(prepared.manifest_digest(),"SYNTHETIC TEMPORARY JOINED TEST: publish the actual empty layered generation. All future born accounts must be created, reviewed and enrolled independently through real native/IPC/witness producers.")?;
    prepared.publish(vec![], publication)?;
    let directory = Directory::open(&target)?;
    let secrets = Secrets::open(&directory.read("profile.vault", 1024)?, PASSWORD)?;
    let mut host = Host::open(directory, secrets, terminal)?;
    {
        let actual = ManualCommittedTarget::open(&host.directory, &host.secrets)?;
        actual.coverage().require_complete()?;
        actual.check_current()?;
    }
    // Actual native session and financial attachment prompts. The test driver
    // supplies only fixed synthetic labels/passphrases and a path under temp.
    host.terminal.message(&format!(
        "SYNTHETIC_JOINED_BOOTSTRAP_PATH={}\n",
        temp.path().join("joined-native-session.token").display()
    ))?;
    host.enroll()?;
    host.terminal.message(&format!(
        "SYNTHETIC_JOINED_FINANCIAL_PATH={}\n",
        temp.path().join("joined-primary-financial").display()
    ))?;
    host.financial_open(true)?;
    host.require_manual_session()?;
    host.financial
        .as_ref()
        .ok_or(Error::Locked)?
        .check_current_journals()?;
    Ok((temp, host))
}
