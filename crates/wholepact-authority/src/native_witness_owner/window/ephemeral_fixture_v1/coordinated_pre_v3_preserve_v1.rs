//! Consuming test-only preservation before any V3 admission exists.
//! Ordinary original paths and audited birth metadata, never a source factory.
use super::*;

#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PreservedPreV3V1 {
    version:u16,
    purpose:&'static str,
    installation:Vec<u8>,
    home_path:String,
    form:PreV3FormV1,
    owner_client:PristineOwnerClientPathsV1,
    writer_client:PristineOwnerClientPathsV1,
    accounts:Vec<PristineAccountBaselineV1>,
}
#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PreV3FormV1 {
    endpoint:String, server_name:String, witness_id:String,
    pinned_server_certificate_digest:String, network_profile_id:String,
    owner_certificate_der_hex:String, storage_key_file:String,
    server_certificate_der:String, server_private_key_pkcs8_der:String,
    trusted_client_root_der:String,
}
fn require_drained(handles:usize,join_failed:bool)->Result<()> {
    if handles!=0||join_failed {return Err(AuthorityError::Permission);}
    Ok(())
}
// The original fixture contains one unused Single anchor and exactly two
// selected V2 roster accounts. Selection is compared with the retained original
// birth map; it cannot manufacture an account, history, native grant or owner.
fn require_selected_original_accounts(
    originals: &std::collections::BTreeMap<String, Vec<u8>>,
    selected: &[String; 2],
) -> Result<()> {
    for account in selected { crate::hash(account)?; }
    if originals.len() != 3 || selected[0] == selected[1]
        || !selected.iter().all(|account| originals.contains_key(account)) {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(())
}

// Full authenticated replay is performed by the caller before this additional
// role-exact baseline check. Both roles retain their original four events and
// no prospective delivery/payment/financial admission is accepted.
fn require_pre_v3_original_history(ledger: &crate::policy::Ledger, selected_roster: bool) -> Result<()> {
    if ledger.snapshot.head.sequence != 4 || ledger.operations.len() != 4
        || ledger.selected_durable_payment_admission_v1()?.is_some()
        || ledger.selected_durable_delivery_admission_v2()?.is_some()
        || ledger.selected_financial_continuation_v1()?.is_some() {
        return Err(AuthorityError::CorruptHistory);
    }
    if selected_roster {
        ledger.require_supported_durable_payment_history_v1()?;
        let attempt = ledger.latest_manual_roster_attempt_v2()?;
        if attempt.sequence != 1 || attempt.continuation.is_some() || attempt.admission.is_none() {
            return Err(AuthorityError::CorruptHistory);
        }
    } else {
        // latest_manual_attempt explicitly refuses roster extensions and checks
        // the original Single admission against its actual extension.
        ledger.require_supported_manual_history()?;
        let attempt = ledger.latest_manual_attempt()?;
        if attempt.sequence != 1 || attempt.continuation.is_some()
            || !matches!(attempt.admission, Some(crate::manual_session_continuation::ManualEnrollmentAdmissionEvidence::First { .. })) {
            return Err(AuthorityError::CorruptHistory);
        }
    }
    Ok(())
}

impl EphemeralNativeWitnessV1 {
    /// Consume the actual synthetic owner only after its original servers and
    /// all borrowers were dropped. No prospective request, completion DTO,
    /// private credential bytes, new account or review grant is accepted.
    pub fn preserve_coordinated_pre_v3_originals_v1(mut self, selected_accounts: &[String; 2])->Result<Vec<u8>> {
        require_selected_original_accounts(&self.durable_delivery.original_signed_births, selected_accounts)?;
        require_drained(self.listener.server_handles.load(Ordering::Acquire),
            self.listener.server_join_failed.load(Ordering::Acquire))?;
        if self.durable_delivery.historical_only
            || self.durable_delivery.pending.is_some()
            || !self.durable_delivery.committed.is_empty()
            || self.durable_delivery.original_signed_births.len()!=3
            || !matches!(self.durable_payment,durable_payment_v1::FixturePhaseV1::Idle)
            || !self.window.can_select()
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
                require_pre_v3_original_history(&ledger, selected_accounts.contains(&account_id))?;
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
        let mut descriptor=PreservedPreV3V1 {version:1,purpose:"coordinated-pre-v3-originals-v1",installation:Vec::new(),home_path:path("")?,
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
        let installation=self.installation.clone();
        self.window.input.synthetic_installation.take();
        drop(self); // actual window and original listener released before preserve
        // The maintained storage kernel requires exclusive Arc custody, audits
        // the original installation and keeps its SAME TempDir without copying.
        descriptor.installation=installation.preserve_original_for_process_exit_v2()?;
        let bytes=serde_json::to_vec(&descriptor).map_err(|_|AuthorityError::InvalidBinding)?;
        if bytes.len()>MAX_PRESERVED_BYTES{return Err(AuthorityError::Limit);}
        Ok(bytes)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]fn pre_v3_preservation_requires_both_zero_handles_and_successful_joins(){
        assert!(require_drained(0,false).is_ok());
        assert!(require_drained(1,false).is_err());
        assert!(require_drained(0,true).is_err());
        assert!(require_drained(1,true).is_err());
    }
}

#[path = "coordinated_live_pre_v3_v1.rs"]
mod live_pre_v3_v1;

#[cfg(test)]
mod role_tests {
    use super::*;
    use crate::policy::Ledger;

    fn roster_original() -> Ledger {
        use wholepact_core::manual_roster_v2::{
            HostRosterAppendBindingV2, HostRosterPredecessorV2,
        };
        let (birth, inner, _, _) = crate::manual_session_continuation::tests::continued_fixture();
        let extension = crate::manual_roster_extension_v2::ManualRosterEnrollmentExtensionV2 {
            version: 2,
            roster: HostRosterAppendBindingV2 {
                version: 2,
                generation_id: inner.terms.host.generation_id.clone(),
                store_destination_identity: inner.terms.host.store_destination_identity.clone(),
                roster_sequence: 2,
                predecessor: HostRosterPredecessorV2::InitialPublicationV2 {
                    audit_digest: "d".repeat(64),
                },
            },
            signer_roster_record_digest: "e".repeat(64),
            account_extension: inner,
        };
        extension.validate_original_birth(&birth).unwrap();
        let mut ledger = Ledger::new(birth.request.policy.clone()).unwrap();
        let mut events = vec![crate::manual_roster_witness_v2::tests::extension_event(
            &ledger, &extension,
        )];
        ledger.apply(&events[0]).unwrap();
        crate::manual_roster_witness_v2::tests::bootstrap(
            &birth,
            &extension,
            &mut ledger,
            &mut events,
            5000,
            crate::session::session_id(&[0x55; 32]),
        );
        // Exercise maintained complete event replay, not a synthetic snapshot.
        let mut replay = Ledger::new(birth.request.policy).unwrap();
        for event in events {
            replay.apply(&event).unwrap();
        }
        replay
    }

    #[test]
    fn pre_v3_single_anchor_requires_its_actual_initial_admitted_history() {
        let (birth, _, events, _) = crate::manual_enrollment::tests::bootstrap_events();
        let mut replay = Ledger::new(birth.request.policy).unwrap();
        for event in events {
            replay.apply(&event).unwrap();
        }
        assert_eq!(replay.snapshot.head.sequence, 4);
        assert_eq!(replay.operations.len(), 4);
        // This is the exact prior bug: the real Single original is not a roster.
        assert!(replay
            .require_supported_durable_payment_history_v1()
            .is_err());
        assert!(require_pre_v3_original_history(&replay, false).is_ok());
        assert!(require_pre_v3_original_history(&replay, true).is_err());
    }

    #[test]
    fn pre_v3_roster_cannot_be_relabelled_as_unused_single_anchor() {
        let replay = roster_original();
        assert!(require_pre_v3_original_history(&replay, true).is_ok());
        assert!(require_pre_v3_original_history(&replay, false).is_err());
    }

    #[test]
    fn pre_v3_incomplete_or_changed_original_history_is_refused() {
        let (birth, _, events, _) = crate::manual_enrollment::tests::bootstrap_events();
        for length in 0..events.len() {
            let mut replay = Ledger::new(birth.request.policy.clone()).unwrap();
            for event in events.iter().take(length) {
                replay.apply(event).unwrap();
            }
            assert!(require_pre_v3_original_history(&replay, false).is_err());
            assert!(require_pre_v3_original_history(&replay, true).is_err());
        }
        let mut roster = roster_original();
        roster.snapshot.head.sequence += 1;
        assert!(require_pre_v3_original_history(&roster, true).is_err());
    }

    #[test]
    fn pre_v3_roles_require_two_distinct_selected_originals_and_one_anchor() {
        let selected = ["a".repeat(64), "b".repeat(64)];
        let mut originals = std::collections::BTreeMap::from([
            (selected[0].clone(), vec![1]),
            (selected[1].clone(), vec![2]),
            ("c".repeat(64), vec![3]),
        ]);
        assert!(require_selected_original_accounts(&originals, &selected).is_ok());
        assert!(require_selected_original_accounts(
            &originals,
            &[selected[0].clone(), selected[0].clone()]
        )
        .is_err());
        assert!(require_selected_original_accounts(
            &originals,
            &[selected[0].clone(), "d".repeat(64)]
        )
        .is_err());
        assert!(require_selected_original_accounts(
            &originals,
            &[selected[0].clone(), "invalid".into()]
        )
        .is_err());
        originals.remove(&"c".repeat(64));
        assert!(require_selected_original_accounts(&originals, &selected).is_err());
        originals.insert("c".repeat(64), vec![3]);
        originals.insert("d".repeat(64), vec![4]);
        assert!(require_selected_original_accounts(&originals, &selected).is_err());
    }
}
