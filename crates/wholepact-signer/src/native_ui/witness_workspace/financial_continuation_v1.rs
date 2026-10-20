//! Separate owner/writer credential custody for the explicit financial profile.
//! Configuration proves key/certificate consistency, not remote authentication.
use super::*;
use crate::native_ui::runtime::financial_v1::diagnostics::{self as diag, FinancialNativeStageV1 as Stage};
use crate::account::birth::enrollment::roster_v2::financial_source_v1::PreparedOriginalFinancialSourceV1;
use crate::consent_journal::PendingFinancialContinuationAdmissionV1;
use crate::native_ui::financial_authority_v1::{FinancialAdmitActionV1, FinancialReadLeaseV1};
use std::time::Instant;
use wholepact_authority::{AccountSnapshot, ReconciledAuthorityHistory};

pub(in crate::native_ui) struct FinancialWitnessCustodyV1 {
    client: AuthorityClient,
    certificate_digest: String,
    owner: bool,
}
impl FinancialWitnessCustodyV1 {
    pub(in crate::native_ui) fn prepare_owner(
        json: &str,
        source: &PreparedOriginalFinancialSourceV1,
        disclosure: &WitnessDisclosureDescriptor,
    ) -> Result<Self> {
        source.check_custody()?;
        let selected = prepare_selected_witness_configuration(
            json,
            &disclosure.account_id,
            Some(&disclosure.network_profile_id),
        )?;
        if selected.client.disclosure_descriptor() != *disclosure {
            return Err(Error::Authentication);
        }
        source.require_original_owner_witness(disclosure, &selected.writer_certificate_digest)?;
        Ok(Self {
            client: selected.client,
            certificate_digest: selected.writer_certificate_digest,
            owner: true,
        })
    }
    fn check(&self, source: &PreparedOriginalFinancialSourceV1) -> Result<()> {
        if self.owner {
            source.require_original_owner_witness(
                &self.client.disclosure_descriptor(),
                &self.certificate_digest,
            )
        } else {
            source.require_original_writer_witness(
                &self.client.disclosure_descriptor(),
                &self.certificate_digest,
            )
        }
    }
    pub(in crate::native_ui) fn read_history(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        read: &FinancialReadLeaseV1,
        deadline: Instant,
    ) -> Result<ReconciledAuthorityHistory> {
        source.check_read(read)?;
        self.check(source)?;
        diag::at(Stage::AuthorityHistoryRead);
        let history = self
            .client
            .reconcile_history_checked_until(deadline, || {
                source
                    .check_read(read)
                    .and_then(|_| self.check(source))
                    .map_err(|error| { diag::signer(&error); wholepact_authority::AuthorityError::Permission })
            })
            .map_err(|error| { diag::authority(&error); Error::Uncertain })?;
        source.check_read(read)?;
        self.check(source)?;
        Ok(history)
    }
    pub(in crate::native_ui) fn admit(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        pending: PendingFinancialContinuationAdmissionV1,
        action: FinancialAdmitActionV1,
        deadline: Instant,
    ) -> Result<AccountSnapshot> {
        // ContinueExact has ended. This fresh action can send only the already
        // saved immutable request, after the independent Witness review.
        let check = || -> Result<()> {
            self.check(source)?;
            source.check_pending(&pending)?;
            action.check_source(source.identity_digest())?;
            if action.terms_digest() != pending.admission_terms_digest(source.identity_digest())? {
                return Err(Error::ReviewMismatch);
            }
            Ok(())
        };
        check()?;
        diag::at(Stage::AuthorityAdmit);
        #[cfg(feature = "synthetic-qualification")]
        let observation = diag::begin_checked_authority();
        #[cfg(feature = "synthetic-qualification")]
        let result = self.client.admit_financial_continuation_v1_diagnosed_checked_until(
            pending.request(),
            deadline.min(source.original_deadline()),
            || check().map_err(|error| { diag::signer(&error); wholepact_authority::AuthorityError::Permission }),
        ).map_err(|failure| diag::checked_authority(failure, observation));
        #[cfg(not(feature = "synthetic-qualification"))]
        let result = self.client.admit_financial_continuation_v1_checked_until(
            pending.request(),
            deadline.min(source.original_deadline()),
            || check().map_err(|error| { diag::signer(&error); wholepact_authority::AuthorityError::Permission }),
        );
        if let Err(error)=&result { diag::authority(error); }
        let current = check();
        drop(action);
        drop(pending);
        current?;
        result.map_err(|error| { diag::authority(&error); Error::Uncertain })
    }
}
impl FinancialWitnessCustodyV1 {
    pub(in crate::native_ui) fn prepare_writer(
        json: &str,
        source: &PreparedOriginalFinancialSourceV1,
        disclosure: &WitnessDisclosureDescriptor,
    ) -> Result<Self> {
        source.check_custody()?;
        let selected = prepare_selected_witness_configuration(
            json,
            &disclosure.account_id,
            Some(&disclosure.network_profile_id),
        )?;
        source.require_original_writer_witness(disclosure, &selected.writer_certificate_digest)?;
        Ok(Self {
            client: selected.client,
            certificate_digest: selected.writer_certificate_digest,
            owner: false,
        })
    }
    pub(in crate::native_ui) fn financial_history(&self,source:&PreparedOriginalFinancialSourceV1,read:&FinancialReadLeaseV1,deadline:Instant)->Result<wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1>{
        source.check_read(read)?;
        self.check(source)?;
        let exact = source.continuation_request()?;
        diag::at(Stage::FinancialHistoryRead);
        let history = self
            .client
            .financial_continuation_history_v1_checked_until(&exact.operation_id, deadline, || {
                source
                    .check_read(read)
                    .and_then(|_| self.check(source))
                    .map_err(|error| { diag::signer(&error); wholepact_authority::AuthorityError::Permission })
            })
            .map_err(|error| { diag::authority(&error); Error::Uncertain })?;
        if history.continuation_request() != &exact {
            return Err(Error::ReviewMismatch);
        }
        source.check_read(read)?;
        Ok(history)
    }
    pub(in crate::native_ui) fn acquire(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        history:&wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
        action: crate::native_ui::financial_authority_v1::FinancialAcquireActionV1,
        deadline: Instant,
    ) -> Result<wholepact_authority::WriterSessionReceipt> {
        self.check(source)?;
        action.check_source(source.identity_digest())?;
        if self.owner
            || history.continuation_request() != &source.continuation_request()?
            || action.terms_digest() != financial_acquire_digest(history)?
        {
            return Err(Error::ReviewMismatch);
        }
        diag::at(Stage::AuthorityAcquire);
        #[cfg(feature = "synthetic-qualification")]
        let observation = diag::begin_checked_authority();
        #[cfg(feature = "synthetic-qualification")]
        let result = self.client
            .acquire_financial_continuation_writer_v1_diagnosed_checked_until(
                history,
                &history.continuation_request().operation_id,
                deadline,
                || {
                    source
                        .check_custody()
                        .and_then(|_| action.check_source(source.identity_digest()))
                        .map_err(|error| { diag::signer(&error); wholepact_authority::AuthorityError::Permission })
                },
            )
            .map_err(|failure| diag::checked_authority(failure, observation));
        #[cfg(not(feature = "synthetic-qualification"))]
        let result = self.client
            .acquire_financial_continuation_writer_v1_checked_until(
                history,
                &history.continuation_request().operation_id,
                deadline,
                || {
                    source
                        .check_custody()
                        .and_then(|_| action.check_source(source.identity_digest()))
                        .map_err(|error| { diag::signer(&error); wholepact_authority::AuthorityError::Permission })
                },
            );
        result
            .map_err(|error| { diag::authority(&error); Error::Uncertain })
    }
    pub(in crate::native_ui) fn activate(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        history:&wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
        request: &wholepact_authority::OwnerControlRequest,
        action: crate::native_ui::financial_authority_v1::FinancialActivationActionV1,
        deadline: Instant,
    ) -> Result<AccountSnapshot> {
        self.check(source)?;
        action.check_source(source.identity_digest())?;
        if !self.owner
            || history.continuation_request() != &source.continuation_request()?
            || action.terms_digest() != financial_activation_digest(history, request)?
        {
            return Err(Error::ReviewMismatch);
        }
        diag::at(Stage::AuthorityActivate);
        #[cfg(feature = "synthetic-qualification")]
        let observation = diag::begin_checked_authority();
        #[cfg(feature = "synthetic-qualification")]
        let result = self.client
            .activate_financial_continuation_writer_v1_diagnosed_checked_until(
                history,
                &history.continuation_request().operation_id,
                request,
                deadline,
                || {
                    source
                        .check_custody()
                        .and_then(|_| action.check_source(source.identity_digest()))
                        .map_err(|error| { diag::signer(&error); wholepact_authority::AuthorityError::Permission })
                },
            )
            .map_err(|failure| diag::checked_authority(failure, observation));
        #[cfg(not(feature = "synthetic-qualification"))]
        let result = self.client
            .activate_financial_continuation_writer_v1_checked_until(
                history,
                &history.continuation_request().operation_id,
                request,
                deadline,
                || {
                    source
                        .check_custody()
                        .and_then(|_| action.check_source(source.identity_digest()))
                        .map_err(|error| { diag::signer(&error); wholepact_authority::AuthorityError::Permission })
                },
            );
        result
            .map_err(|error| { diag::authority(&error); Error::Uncertain })
    }
}
pub(in crate::native_ui) fn financial_acquire_digest(
    history:&wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"wholepact:financial-native-acquire:v1\0");
    h.update(
        serde_json::to_vec(&(
            history.continuation_request(),
            history.history_digest(),
            history.snapshot(),
        ))
        .map_err(|_| Error::InvalidData)?,
    );
    Ok(hex::encode(h.finalize()))
}
pub(in crate::native_ui) fn financial_activation_digest(
    history:&wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
    request: &wholepact_authority::OwnerControlRequest,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"wholepact:financial-native-activate:v1\0");
    h.update(
        serde_json::to_vec(&(
            history.continuation_request(),
            history.history_digest(),
            request,
        ))
        .map_err(|_| Error::InvalidData)?,
    );
    Ok(hex::encode(h.finalize()))
}
impl FinancialWitnessCustodyV1 {
    pub(in crate::native_ui) fn verify_active(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        read: &FinancialReadLeaseV1,
        history:&wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
        deadline: Instant,
    ) -> Result<wholepact_authority::AuthenticatedWriterSession> {
        self.check(source)?;
        source.check_read(read)?;
        if self.owner || history.continuation_request() != &source.continuation_request()? {
            return Err(Error::ReviewMismatch);
        }
        diag::at(Stage::AuthorityVerifyActive);
        #[cfg(feature = "synthetic-qualification")]
        let observation = diag::begin_checked_authority();
        #[cfg(feature = "synthetic-qualification")]
        let result = self.client
            .verify_financial_continuation_session_v1_diagnosed_checked_until(
                history,
                &history.continuation_request().operation_id,
                deadline,
                || {
                    source
                        .check_read(read)
                        .and_then(|_| self.check(source))
                        .map_err(|error| { diag::signer(&error); wholepact_authority::AuthorityError::Permission })
                },
            )
            .map_err(|failure| diag::checked_authority(failure, observation));
        #[cfg(not(feature = "synthetic-qualification"))]
        let result = self.client
            .verify_financial_continuation_session_v1_checked_until(
                history,
                &history.continuation_request().operation_id,
                deadline,
                || {
                    source
                        .check_read(read)
                        .and_then(|_| self.check(source))
                        .map_err(|error| { diag::signer(&error); wholepact_authority::AuthorityError::Permission })
                },
            );
        result
            .map_err(|error| { diag::authority(&error); Error::Uncertain })
    }
    pub(in crate::native_ui) fn sign(
        &self,
        source: &PreparedOriginalFinancialSourceV1,
        approved: crate::consent_journal::ApprovedFinancialSpendConsentV1,
        history:&wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
        active: &wholepact_authority::AuthenticatedWriterSession,
        wallet: &mut wholepact_wallet::wallet::protected_sync::ProtectedWalletSync,
        ticket: &wholepact_wallet::wallet::protected_sync::key_use::WalletKeyUseTicket,
        deadline: Instant,
    ) -> crate::authority_bridge::Result<crate::authority_bridge::AuthorizationCommit> {
        self.check(source)
            .map_err(|error| { diag::signer(&error); crate::authority_bridge::BridgeError::Permission })?;
        if self.owner {
            return Err(crate::authority_bridge::BridgeError::Permission);
        }
        crate::authority_bridge::financial_continuation_v1::reserve_financial_authorization_v1(
            source,
            approved,
            &self.client,
            history,
            active,
            deadline,
        )?
        .sign_and_retain(wallet, ticket)
    }
}
