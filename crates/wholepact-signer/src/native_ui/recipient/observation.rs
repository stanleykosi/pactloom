//! Explicitly consented named-provider observation, independent of coordinator
//! storage. The sealed snapshot is produced only by the maintained chain adapter.
use super::*;
use wholepact_chain::{ChainAdapter, NetworkPolicy, TransactionObservation, TransactionStatus};
use wholepact_core::{
    ChainObservation, ChainStatus, CoreError, ErrorCode,
    records::{ExactTransactionReference, SettlementObservationSource, SourcedChainObservation},
};
const ADAPTER: &str = "recipient-native-lightwalletd-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    source_id: String,
    endpoint: String,
    required_confirmations: u32,
}
pub(in crate::native_ui) struct PreparedObservation {
    source: ChainAdapter,
    config: Config,
    reference: String,
    instruction_digest: String,
    exact: ExactTransactionReference,
    expiry_height: u32,
    native: NativeAuthorityBinding,
    account_id: String,
    digest: String,
    display: String,
    started: Instant,
}
pub(in crate::native_ui) struct ObservationJob(PreparedObservation);
pub(in crate::native_ui) struct CompletedObservation {
    prepared: PreparedObservation,
    observation: TransactionObservation,
}
impl PreparedObservation {
    pub(in crate::native_ui) fn prepare(
        json: &str,
        reference: &str,
        authority: &NativeAuthority,
        vault: &AccountVault,
    ) -> Result<Self> {
        authority.check_current()?;
        if json.len() > 4096 {
            return Err(Error::InvalidData);
        }
        let config: Config = serde_json::from_str(json).map_err(|_| Error::InvalidData)?;
        if !(1..=100).contains(&config.required_confirmations) {
            return Err(Error::InvalidData);
        }
        let source = ChainAdapter::testnet(
            &config.source_id,
            &config.endpoint,
            NetworkPolicy::default(),
        )
        .map_err(|_| Error::InvalidData)?;
        let all = records(vault)?;
        let record = all
            .iter()
            .find(|r| r.instructions.reference == reference)
            .ok_or(Error::ReviewMismatch)?;
        let evidence = record
            .observations
            .iter()
            .rev()
            .find_map(|r| r.get("evidence"))
            .ok_or(Error::ReviewMismatch)?;
        let field = |name| {
            evidence
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or(Error::Verification)
        };
        let exact = ExactTransactionReference {
            network_profile_id: wholepact_protocol::recipient_local::NETWORK.into(),
            transaction_id: field("transaction_id")?,
            transaction_bytes_digest: field("transaction_digest")?,
            effects_commitment: field("effects_commitment")?,
        };
        exact.validate().map_err(|_| Error::Verification)?;
        let expiry_height = evidence
            .get("expiry_height")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or(Error::Verification)?;
        let display = format!(
            "RECIPIENT CHAIN OBSERVATION DISCLOSURE\nReference: {}\nTransaction: {}\nSource: {}\nEndpoint: {}\nRequired confirmations: {}\n\nSend this exact transaction ID to this named TLS provider. The provider and configured proxy can observe your IP, timing and transaction-interest linkage. No viewing key, memo, contributor or wallet data is sent. Retain the source-bound response locally. This is a trusted single-provider report, NOT independently verified consensus. Missing observations, errors and expiry do not prove absence. Approval is one bounded observation only; no recurring monitor, submission, refund, exposure clearance or delivery decision.",
            reference,
            exact.transaction_id,
            source.identity().source_id,
            source.identity().endpoint,
            config.required_confirmations
        );
        let account_id = vault.account_id()?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:recipient-chain-review:v1",
            &(&account_id, &display, crate::vault::random::<32>()?),
        )
        .map_err(|_| Error::InvalidData)?;
        Ok(Self {
            source,
            config,
            reference: reference.into(),
            instruction_digest: record.digest.clone(),
            exact,
            expiry_height,
            native: authority.binding(),
            account_id,
            digest,
            display,
            started: Instant::now(),
        })
    }
    pub(in crate::native_ui) fn digest(&self) -> &str {
        &self.digest
    }
    pub(in crate::native_ui) fn display(&self) -> String {
        self.display.clone()
    }
    pub(in crate::native_ui) fn approve(
        self,
        decision: NativeDecision,
        authority: &NativeAuthority,
        vault: &AccountVault,
    ) -> Result<ObservationJob> {
        authority.check_current()?;
        if self.native != authority.binding()
            || decision.binding() != &self.native
            || decision.reviewed_digest() != self.digest
            || self.account_id != vault.account_id()?
            || self.started.elapsed() >= Duration::from_secs(120)
        {
            return Err(Error::ReviewMismatch);
        }
        Ok(ObservationJob(self))
    }
}
impl ObservationJob {
    pub(in crate::native_ui) fn run(self) -> Result<CompletedObservation> {
        self.0.native.check_current()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Unavailable)?;
        let observation = runtime
            .block_on(
                self.0
                    .source
                    .observe_transaction(&self.0.exact.transaction_id),
            )
            .map_err(|_| Error::Unavailable)?;
        self.0.native.check_current()?;
        Ok(CompletedObservation {
            prepared: self.0,
            observation,
        })
    }
}
/// This adapter cannot be constructed from caller JSON. Creation requires the
/// sealed chain-adapter return and current exact native permission above.
struct RecipientSettlementSource<'a> {
    completed: &'a CompletedObservation,
}
impl SettlementObservationSource for RecipientSettlementSource<'_> {
    fn observe_exact_transaction(
        &mut self,
        exact: &ExactTransactionReference,
    ) -> wholepact_core::Result<SourcedChainObservation> {
        let c = self.completed;
        let p = &c.prepared;
        let o = &c.observation;
        let reject = || {
            CoreError::new(
                ErrorCode::MissingEvidence,
                "recipient provider observation is stale, mismatched or unqualified",
            )
        };
        p.native.check_current().map_err(|_| reject())?;
        o.context
            .check_fresh_at(now().map_err(|_| reject())?)
            .map_err(|_| reject())?;
        if exact != &p.exact
            || o.transaction_id != exact.transaction_id
            || o.context.source() != p.source.identity()
            || o.independently_consensus_verified
            || o.clears_authorization_exposure
        {
            return Err(reject());
        }
        let (status, inclusion_height, inclusion_hash, confirmations) = match &o.status {
            TransactionStatus::NotObserved => (ChainStatus::SubmissionUnknown, None, None, 0),
            TransactionStatus::PendingObserved => (ChainStatus::PendingObserved, None, None, 0),
            TransactionStatus::Reorganized => (ChainStatus::Reorganized, None, None, 0),
            TransactionStatus::Included {
                block,
                confirmations,
            } => {
                if !o.confirms_raw_transaction_id || block.height > u64::from(p.expiry_height) {
                    return Err(reject());
                }
                let count = u32::try_from(*confirmations).map_err(|_| reject())?;
                (
                    if count >= p.config.required_confirmations {
                        ChainStatus::ConfirmationPolicyMet
                    } else {
                        ChainStatus::Included
                    },
                    Some(u32::try_from(block.height).map_err(|_| reject())?),
                    Some(block.hash.clone()),
                    count,
                )
            }
        };
        let stamp = time::OffsetDateTime::from_unix_timestamp(
            i64::try_from(o.context.observed_at_unix_seconds()).map_err(|_| reject())?,
        )
        .map_err(|_| reject())?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| reject())?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:recipient-provider-observation:v1",
            o,
        )?;
        let observation = ChainObservation {
            observation_id: digest.clone(),
            source_id: o.context.source().source_id.clone(),
            trust_profile_id: o.context.source().trust_profile.into(),
            observed_at: stamp,
            tip_height: u32::try_from(o.context.tip().height).map_err(|_| reject())?,
            tip_hash: o.context.tip().hash.clone(),
            synchronized: true,
            status,
            inclusion_height,
            inclusion_hash,
            confirmations,
            evidence_ref: digest,
        };
        observation.validate()?;
        Ok(SourcedChainObservation {
            transaction: exact.clone(),
            adapter_id: ADAPTER.into(),
            observation,
        })
    }
}
impl CompletedObservation {
    pub(in crate::native_ui) fn retain(
        self,
        authority: &NativeAuthority,
        vault: &AccountVault,
    ) -> Result<String> {
        authority.check_current()?;
        if self.prepared.native != authority.binding()
            || self.prepared.account_id != vault.account_id()?
        {
            return Err(Error::ReviewMismatch);
        }
        let mut source = RecipientSettlementSource { completed: &self };
        let observed = source
            .observe_exact_transaction(&self.prepared.exact)
            .map_err(|_| Error::Verification)?;
        let mut all = records(vault)?;
        let record = all
            .iter_mut()
            .find(|r| {
                r.instructions.reference == self.prepared.reference
                    && r.digest == self.prepared.instruction_digest
            })
            .ok_or(Error::Verification)?;
        if record.observations.len() >= 64 {
            return Err(Error::InvalidData);
        }
        let summary = format!(
            "Provider snapshot {:?}, {} confirmations, observed {}. Source {} (single TLS provider, not consensus). Fresh only through Unix time {}. Commercial delivery remains your decision.",
            observed.observation.status,
            observed.observation.confirmations,
            observed.observation.observed_at,
            observed.observation.source_id,
            self.observation.context.valid_until_unix_seconds()
        );
        record.observations.push(serde_json::json!({"provenance": "native_named_provider_transaction_observation", "required_confirmations": self.prepared.config.required_confirmations, "source": self.prepared.source.identity(), "valid_until_unix_seconds": self.observation.context.valid_until_unix_seconds(), "observation": observed, "raw_source_report": self.observation}));
        self.prepared.native.check_current()?;
        vault.write_recipient_records(&Zeroizing::new(
            serde_json::to_vec(&all).map_err(|_| Error::InvalidData)?,
        ))?;
        Ok(summary)
    }
}
