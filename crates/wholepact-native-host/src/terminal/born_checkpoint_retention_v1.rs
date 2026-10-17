//! Fresh, purpose-specific permission for an already verified born checkpoint.
//! This never extends the original construction/signing/current-input window.
use super::{historical::HistoricalApproval, *};
use std::time::{Duration, Instant};
use wholepact_authority::born_offline_checkpoint_origin_v1::BornOfflineCheckpointOriginV1;

pub(crate) struct BornCheckpointRetentionV1 {
    terminal: Terminal,
    foreground_file: File,
    origin_digest: String,
    deadline: Instant,
}
impl BornCheckpointRetentionV1 {
    pub(crate) fn check(&self, origin: &BornOfflineCheckpointOriginV1) -> Result<()> {
        if Instant::now() >= self.deadline
            || origin.digest().map_err(|_| Error::Authentication)? != self.origin_digest
        {
            return Err(Error::Permission);
        }
        foreground(&self.foreground_file)
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn approve_publication(
        &self,
        origin: &BornOfflineCheckpointOriginV1,
        digest: &str,
        detail: &str,
    ) -> Result<PublicationApproval> {
        self.terminal
            .confirm_checked(detail, || self.check(origin))?;
        self.check(origin)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid);
        }
        let file = self.terminal.0.lock().map_err(|_| Error::Terminal)?;
        foreground(&file)?;
        Ok(PublicationApproval {
            terminal: self.terminal.clone(),
            foreground_file: file.try_clone()?,
            manifest_digest: digest.into(),
            deadline: (Instant::now() + Duration::from_secs(120)).min(self.deadline),
        })
    }
}
impl Terminal {
    pub(crate) fn approve_born_checkpoint_retention_v1(
        &self,
        initial: &HistoricalApproval,
        read: &HistoricalApproval,
        origin: &BornOfflineCheckpointOriginV1,
    ) -> Result<BornCheckpointRetentionV1> {
        origin.validate().map_err(|_| Error::Authentication)?;
        self.confirm_checked(&format!("Keep and use ONLY this already independently verified completed private checkpoint in this Host's memory for at most15 minutes, ending sooner on lock/revoke/foreground loss. This includes the original full proof policy, participant viewing material and exact original transaction bytes. Its permitted purpose is exact checkpoint-origin export, authenticated signature-only return verification and separate explicit local signature/transaction retention. Fresh current-input, signer/witness and backend approvals are STILL required before dispatch. Nothing renews an original construction deadline, writer session, signing window, packet expiry or current-input observation. No spending key, new proof, renewed reservation or new credential is authorized. The data remains private unless separately disclosed through an exact native export approval.\nExact immutable checkpoint origin: {}",serde_json::to_string_pretty(origin)?), || { initial.check()?;read.check() })?;
        initial.check()?;
        read.check()?;
        let file = self.0.lock().map_err(|_| Error::Terminal)?;
        foreground(&file)?;
        Ok(BornCheckpointRetentionV1 {
            terminal: self.clone(),
            foreground_file: file.try_clone()?,
            origin_digest: origin.digest().map_err(|_| Error::Authentication)?,
            deadline: Instant::now() + Duration::from_secs(900),
        })
    }
}
