//! Test-only live original owner inspection and checked transport parking.
//! No window reconstruction, native decision, new journal or restored approval.
use super::*;
impl EphemeralNativeWitnessV1 {
    /// Inspect actual original births/journals without consuming the original
    /// native owner or creating any prospective request or native permission.
    pub fn describe_coordinated_pre_v3_originals_v1(&mut self)->Result<Vec<u8>> {
        require_drained(self.listener.server_handles.load(Ordering::Acquire),
            self.listener.server_join_failed.load(Ordering::Acquire))?;
        if self.durable_delivery.historical_only
            || self.durable_delivery.pending.is_some()
            || !self.durable_delivery.committed.is_empty()
            || self.durable_delivery.original_signed_births.len()!=3
            || !matches!(self.durable_payment,durable_payment_v1::FixturePhaseV1::Idle)
            || !self.window.can_select()
            || !self.financial_continuation.is_idle_for_original_transport_v1()
            || !self.listener.address.ip().is_loopback() || self.listener.address.port()==0
            || self.window.input.endpoint!=self.listener.address.to_string()
            || self.listener.local_addr().map_err(|_|AuthorityError::Permission)?!=self.listener.address
        {return Err(AuthorityError::Permission);}
        let owner_pin=crate::transport::certificate_digest(&CertificateDer::from(self.owner_certificate.as_slice()));
        let mut accounts=Vec::with_capacity(3);
        for (account_id,envelope) in self.durable_delivery.original_signed_births.clone() {
            if envelope.is_empty()||envelope.len()>crate::MAX_FRAME_BYTES{return Err(AuthorityError::Limit);}
            let signed:crate::pending_birth_signature::PendingBirthOwnerSignature=
                serde_json::from_slice(&envelope).map_err(|_|AuthorityError::InvalidBinding)?;
            let verified=crate::pending_birth_signature::verify_pending_birth_owner_signature(&signed,&owner_pin)?;
            let journal=crate::witness_locator::open_born_history(self.original_namespace_input(&account_id)?)?;
            let head={
                let connection=journal.connection.lock().map_err(|_|AuthorityError::Storage)?;
                let ledger=crate::journal::load(connection.connection())?;
                ledger.require_supported_durable_payment_history_v1()?;
                let birth=crate::pending_birth_storage::read(connection.connection(),&ledger.policy)?
                    .ok_or(AuthorityError::RecoveryRequired)?;
                if verified.request()!=&birth.request
                    || verified.certificate_digest()!=birth.authenticated_owner_certificate_digest
                    || verified.evidence_digest()!=birth.owner_approval_evidence_digest
                    || ledger.snapshot.account_id!=account_id
                    || ledger.snapshot.head.sequence!=4 || ledger.operations.len()!=4
                    || ledger.selected_durable_payment_admission_v1()?.is_some()
                    || ledger.selected_durable_delivery_admission_v2()?.is_some()
                    || ledger.selected_financial_continuation_v1()?.is_some()
                {return Err(AuthorityError::CorruptHistory);}
                ledger.snapshot.head
            };
            accounts.push(PristineAccountBaselineV1 {account_id,head,
                original_signed_birth:String::from_utf8(envelope).map_err(|_|AuthorityError::InvalidBinding)?,
                original_source_commitment:original_source_commitment(&journal)?});
            drop(journal); // release actual namespace/journal exclusion per account
        }
        let path=|name:&str|->Result<String> {
            let path=if name.is_empty(){self.root.clone()}else{self.root.join(name)};
            let text=path.to_str().ok_or(AuthorityError::InvalidBinding)?;
            if !path.is_absolute()||text.len()>4096||text.chars().any(char::is_control){return Err(AuthorityError::InvalidBinding);}
            Ok(text.to_owned())
        };
        let mut descriptor=PreservedPreV3V1 {version:1,purpose:"coordinated-pre-v3-live-originals-v1",installation:Vec::new(),home_path:path("")?,
            form:PreV3FormV1 {endpoint:self.window.input.endpoint.clone(),server_name:self.window.input.server_name.clone(),
                witness_id:self.window.input.witness_id.clone(),pinned_server_certificate_digest:self.server_certificate_digest.clone(),
                network_profile_id:self.window.input.network_profile_id.clone(),owner_certificate_der_hex:hex::encode(&self.owner_certificate),
                storage_key_file:path("synthetic-namespace.key")?,server_certificate_der:path("server.der")?,
                server_private_key_pkcs8_der:path("server.pk8")?,trusted_client_root_der:path("ca.der")?},
            owner_client:PristineOwnerClientPathsV1 {certificate_der:path("owner.der")?,private_key_pkcs8_der:path("owner.pk8")?,trusted_server_root_der:path("ca.der")?},
            writer_client:PristineOwnerClientPathsV1 {certificate_der:path("writer.der")?,private_key_pkcs8_der:path("writer.pk8")?,trusted_server_root_der:path("ca.der")?},accounts};
        if serde_json::to_vec(&descriptor).map_err(|_|AuthorityError::InvalidBinding)?.len()>MAX_PRESERVED_BYTES-64*1024{return Err(AuthorityError::Limit);}
        require_drained(self.listener.server_handles.load(Ordering::Acquire),
            self.listener.server_join_failed.load(Ordering::Acquire))?;
        // Only inert original identity bytes; actual original owner/TempDir
        // stays alive. Probe and original journal exclusions are dropped here.
        descriptor.installation=self.installation.describe_original_for_live_qualification_v1()?;
        let bytes=serde_json::to_vec(&descriptor).map_err(|_|AuthorityError::InvalidBinding)?;
        if bytes.len()>MAX_PRESERVED_BYTES{return Err(AuthorityError::Limit);}
        Ok(bytes)
    }
}

impl EphemeralNativeWitnessV1 {
    /// Release only the transport of a fully idle original native owner. Real
    /// delivery start/bootstrap later rebind the exact original endpoint. All
    /// native workers and retained DB histories must already have drained.
    pub fn release_original_listener_when_idle_v1(&mut self) -> Result<()> {
        require_drained(self.listener.server_handles.load(Ordering::Acquire),
            self.listener.server_join_failed.load(Ordering::Acquire))?;
        require_idle_transport([
            self.window.can_select(), self.durable_delivery.pending.is_none(),
            !self.durable_delivery.historical_only,
            matches!(self.durable_payment,durable_payment_v1::FixturePhaseV1::Idle),
            self.financial_continuation.is_idle_for_original_transport_v1(),
        ])?;
        if self.window.pending.is_some()
            || self.window.job.is_some() || self.window.historical.is_some()
            || self.durable_delivery.pending.is_some()
            || self.durable_delivery.historical_only
            || !matches!(self.durable_payment,durable_payment_v1::FixturePhaseV1::Idle)
            || !self.financial_continuation.is_idle_for_original_transport_v1()
            || self.window.input.endpoint != self.listener.address.to_string()
        { return Err(AuthorityError::Permission); }
        if let Some(listener) = &self.listener.bound {
            if listener.local_addr().map_err(|_|AuthorityError::Storage)? != self.listener.address {
                return Err(AuthorityError::Authentication);
            }
        }
        // Probe/release through the maintained exclusion kernel: no journal or
        // installation guard may remain borrowed when parking succeeds.
        let files = self.installation.probe()?.open_existing()?;
        files.check_current()?;
        drop(files);
        drop(self.listener.bound.take());
        Ok(())
    }
}

fn require_idle_transport(checks: [bool; 5]) -> Result<()> {
    if checks.into_iter().all(|ok| ok) { Ok(()) } else { Err(AuthorityError::Permission) }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn parking_requires_every_idle_condition_independently() {
        assert!(require_idle_transport([true;5]).is_ok());
        for index in 0..5 {
            let mut checks=[true;5]; checks[index]=false;
            assert!(require_idle_transport(checks).is_err());
        }
    }
}
