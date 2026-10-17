//! Finite request/assertion/export composition over actual ephemeral verifier
//! and contributor owners. Imported bytes remain untrusted protocol input.
use super::*;
use crate::native_ui::synthetic_born_joined_qualification::EphemeralNamedPaymentV1;
use sha2::{Digest, Sha256};

impl EphemeralNamedVerifierV1 {
    pub fn start_original_assertion(
        &mut self,
        request_bytes: &[u8],
        owners: [&EphemeralNamedPaymentV1; 2],
    ) -> Result<()> {
        if self.workspace.pending.is_some()
            || self.workspace.assertion.is_some()
            || self.completed_row.is_some()
        {
            return Err(Error::Locked);
        }
        let key = self.public_keys()?.0;
        let request = RequestFile::parse(request_bytes, &key)?;
        if request.scopes.len() != 2 {
            return Err(Error::ReviewMismatch);
        }
        let mut providers = Vec::with_capacity(2);
        for ((scope, endpoint), actual) in request.scopes.iter().zip(&request.endpoints).zip(owners)
        {
            actual.require_original_verifier_lane(scope, endpoint)?;
            providers.push(actual.provider()?);
        }
        let owner = self.workspace.owner.as_ref().ok_or(Error::Locked)?;
        owner.check_current()?;
        let filename = format!(
            "request-{}.json",
            hex::encode(Sha256::digest(request_bytes))
        );
        if owner.directory.exists(&filename)? {
            if owner.directory.read(&filename, 2 * 1024 * 1024)? != request_bytes {
                return Err(Error::ReviewMismatch);
            }
        } else {
            owner.directory.write(&filename, request_bytes)?;
        }
        owner.check_current()?;
        self.workspace.filename = filename;
        self.workspace.synthetic_providers = Some(providers);
        self.workspace.stage_request(EPOCH)?;
        self.consume_exact_assertion_step(0)?;
        if self.workspace.owner.is_some()
            || self.workspace.native.is_some()
            || self.workspace.assertion.is_none()
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(())
    }

    pub fn poll_original_assertion(&mut self) -> Result<Option<String>> {
        if self.completed_row.is_some() {
            return Ok(self.completed_row.clone());
        }
        let workspace = self.workspace.assertion.as_mut().ok_or(Error::Locked)?;
        let row = workspace.poll_synthetic_original(PASSWORD, EPOCH)?;
        if let Some(row) = row {
            workspace.drain_synthetic_original();
            self.workspace.assertion = None;
            self.completed_row = Some(row.clone());
            return Ok(Some(row));
        }
        Ok(None)
    }

    pub fn export_original_assertion(
        &mut self,
        row: &str,
        recipient: &EphemeralNamedPaymentV1,
    ) -> Result<Vec<u8>> {
        if self.workspace.assertion.is_some()
            || self.completed_row.as_deref() != Some(row)
            || self.workspace.pending.is_some()
        {
            return Err(Error::ReviewMismatch);
        }
        let (_, _, key) = recipient.original_local_public_context()?;
        self.workspace.password = Zeroizing::new(PASSWORD.into());
        self.workspace.open()?;
        self.workspace.row = row.into();
        self.workspace.recipient_key = hex::encode(key);
        self.workspace.stage_export_step(1, EPOCH)?;
        self.consume_exact_assertion_step(1)?;
        self.workspace.stage_export_step(2, EPOCH)?;
        self.consume_exact_assertion_step(2)?;
        let owner = self.workspace.owner.as_ref().ok_or(Error::Locked)?;
        owner.check_current()?;
        let bytes = owner.directory.read(
            &format!("assertion-{row}.wpe"),
            wholepact_transport::MAX_FILE_BYTES,
        )?;
        wholepact_transport::EncryptedEnvelope::from_bytes(bytes.clone())
            .map_err(|_| Error::Verification)?;
        if recipient.original_local_public_context()?.2 != key {
            return Err(Error::ReviewMismatch);
        }
        owner.check_current()?;
        self.completed_row = None;
        Ok(bytes)
    }

    fn consume_exact_assertion_step(&mut self, kind: u8) -> Result<()> {
        let pending = self.workspace.pending.as_mut().ok_or(Error::Locked)?;
        if !matches!(
            (&pending.step, kind),
            (Step::Request(_), 0) | (Step::Pin(_), 1) | (Step::Export(_), 2)
        ) || pending.exact.confirming()
            || pending.exact.display().is_empty()
        {
            return Err(Error::ReviewMismatch);
        }
        self.workspace.frame = self.workspace.frame.saturating_add(1);
        if self.workspace.frame <= pending.shown
            || pending
                .exact
                .continue_from_native_click(false, EPOCH)
                .is_ok()
            || pending
                .exact
                .continue_from_native_click(true, EPOCH + 1)
                .is_ok()
        {
            return Err(Error::ReviewMismatch);
        }
        pending.exact.continue_from_native_click(true, EPOCH)?;
        pending.continued = Some(self.workspace.frame);
        self.workspace.frame = self.workspace.frame.saturating_add(1);
        if !pending.continued.is_some_and(|f| self.workspace.frame > f) {
            return Err(Error::ReviewMismatch);
        }
        self.workspace.phrase =
            Zeroizing::new(format!("AUTHORIZE {}", &pending.exact.digest()[..12]));
        self.workspace.consume(true, EPOCH)
    }
}
