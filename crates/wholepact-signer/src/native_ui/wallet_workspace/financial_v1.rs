//! Fresh exact-input wallet observation for the original financial source.
//! The wallet action ends before SignExact. The resulting controller/ticket is
//! custody and data only; real key use still needs the new SignExact owner.
use super::*;
use crate::native_ui::runtime::financial_v1::diagnostics::{self as diag, FinancialNativeStageV1 as Stage};
use crate::{
    account::birth::enrollment::roster_v2::financial_source_v1::PreparedOriginalFinancialSourceV1,
    native_ui::{
        durable_proposal_v1::VerifiedDurableEconomicsV1,
        financial_authority_v1::FinancialWalletActionV1,
    },
};
use std::os::unix::fs::PermissionsExt;
use crate::account::birth::enrollment::roster_v2::financial_source_v1::{FinancialOperationV1 as Operation,FinancialOperationSourcePinV1};
use wholepact_storage_security::{DatabaseFileIdentity, DatabaseKey, create_encrypted};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema_version: u32,
    purpose: String,
    policy: WalletKeyUsePolicy,
    birthday: BirthdayCheckpoint,
    maximum_blocks: u32,
    retention: String,
}
impl Config {
    /// Ordinary configuration parsing only; no source, FVK, network or authority.
    fn parse_exact(json: &str) -> Result<Self> {
        if json.is_empty() || json.len() > MAX_SETUP {
            return Err(Error::InvalidData);
        }
        let config: Config =
            wholepact_core::parse_typed_json(json.as_bytes()).map_err(|_| Error::InvalidData)?;
        if config.schema_version != 1
            || config.purpose != "fresh_born_ephemeral_viewing_wallet_v1"
            || config.retention != "current_native_owner_only"
            || !(1..=1000).contains(&config.maximum_blocks)
            || config.policy.confidence != WalletKeyUseConfidence::TrustedSingleProviderSnapshot
            || !(1..=300).contains(&config.policy.maximum_observation_age_seconds)
            || !(1..=100).contains(&config.policy.minimum_confirmations)
            || config.policy.minimum_expiry_margin_blocks == 0
            || config.policy.source_id.is_empty()
            || config.policy.source_id.len() > 128
            || config.policy.endpoint.is_empty()
            || config.policy.endpoint.len() > 2048
            || config.policy.endpoint.ends_with('/')
        {
            return Err(Error::InvalidData);
        }
        Ok(config)
    }
}
#[cfg(feature = "coordinated-financial-workflow-v1")]
#[path = "coordinated_wallet_bounds_v1.rs"]
mod coordinated_wallet_bounds_v1;
pub(in crate::native_ui) struct PreparedFinancialWalletV1 {
    source: Arc<PreparedOriginalFinancialSourceV1>,
    fixed: Arc<VerifiedDurableEconomicsV1>,
    config: Config,
    chain: ChainAdapter,
    birthday: AccountBirthday,
    digest: String,
}
impl PreparedFinancialWalletV1 {
    pub(in crate::native_ui) fn prepare(
        source: Arc<PreparedOriginalFinancialSourceV1>,
        fixed: Arc<VerifiedDurableEconomicsV1>,
        json: &str,
    ) -> Result<Self> {
        source.check_custody()?;
        let config = Config::parse_exact(json)?;
        let account = source.financial_account()?;
        let account_id = account.account_id()?;
        let (material, scope) = fixed.original_for_account(&account_id)?;
        scope
            .check_valid_at(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| Error::Locked)?
                    .as_secs(),
            )
            .map_err(|_| Error::Locked)?;
        let _ = material;
        diag::at(Stage::WalletChain);
        let chain = ChainAdapter::testnet(
            &config.policy.source_id,
            &config.policy.endpoint,
            NetworkPolicy {
                observation_ttl: Duration::from_secs(u64::from(
                    config.policy.maximum_observation_age_seconds,
                )),
                ..Default::default()
            },
        )
        .map_err(|error| { diag::chain(&error); Error::InvalidData })?;
        let b = &config.birthday;
        diag::at(Stage::WalletBirthday);
        let birthday = account_birthday_from_tree(TreeState {
            network: "test".into(),
            height: u64::from(b.prior_height),
            hash: b.prior_block_hash.clone(),
            sapling_tree: b.sapling_tree.clone(),
            orchard_tree: b.orchard_tree.clone(),
            ironwood_tree: b.ironwood_tree.clone(),
            ..Default::default()
        })
        .map_err(|error| { diag::sync(&error); Error::InvalidData })?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:financial-exact-wallet-review:v1",
            &(
                source.identity_digest(),
                fixed.verified().identity(),
                &config,
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        Ok(Self {
            source,
            fixed,
            config,
            chain,
            birthday,
            digest,
        })
    }
    pub(in crate::native_ui) fn reviewed_digest(&self) -> &str {
        &self.digest
    }
    pub(in crate::native_ui) fn display(&self) -> Result<String> {
        Ok(format!(
            "FRESH EXACT FINANCIAL VIEWING-WALLET CHECK\n{}\nOnly the original fixed inputs and anchor will be checked. No input selection, proof replacement or signing. Dedicated FVK stays in a private ephemeral encrypted local cache; provider receives public block queries and can observe IP/timing/heights. Existing proxy route only; one chosen provider is not independent consensus. Approval ends after this bounded scan, before SignExact.\nExact review: {}",
            serde_json::to_string_pretty(&self.config).map_err(|_| Error::InvalidData)?,
            self.digest
        ))
    }
    pub(in crate::native_ui) async fn observe(
        self,
        action: FinancialWalletActionV1,
    ) -> Result<(FinancialWalletCustodyV1, ReviewInputs)> {
        action.check_source(self.source.identity_digest())?;
        let pin=self.source.prepare_financial_operation_source_pin_v1(Operation::WalletObserve,None)?;
        action.check_source(self.source.identity_digest())?;
        if action.terms_digest() != self.digest {
            return Err(Error::ReviewMismatch);
        }
        let original = std::fs::canonicalize(self.source.original_root())?;
        let parent = std::fs::canonicalize(std::env::temp_dir())?;
        if parent.starts_with(&original) {
            return Err(Error::InvalidData);
        }
        let temporary = tempfile::Builder::new()
            .prefix("wholepact-financial-viewing-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)?;
        let lock = crate::files::PrivateDirectory::open(temporary.path())?;
        let key = DatabaseKey::from_bytes(crate::vault::random::<32>()?);
        let connection = create_encrypted(temporary.path().join("viewing.sqlite"), &key)
            .map_err(|error| { diag::storage(&error); Error::Unavailable })?;
        drop(key);
        let identity = connection
            .database_identity()
            .map_err(|error| { diag::storage(&error); Error::Verification })?;
        identity
            .check_current(connection.connection())
            .map_err(|error| { diag::storage(&error); Error::Verification })?;
        let account = self.source.financial_account_for_operation_v1(&pin,Operation::WalletObserve)?;
        let fvk = account.fvk()?;
        let account_id = account.account_id()?;
        diag::at(Stage::WalletInitialize);
        let mut wallet = DedicatedTestnetWallet::from_encrypted_connection(connection)
            .map_err(|error| { diag::wallet(&error); Error::RecoveryRequired })?;
        {
            let _held = action.publication_lease()?;
            self.source.check_financial_operation_source_pin_v1(&pin,Operation::WalletObserve)?;
            action.check_source(self.source.identity_digest())?;
            diag::at(Stage::WalletImport);
            wallet
                .import_dedicated_fvk(&fvk, self.birthday)
                .map_err(|error| { diag::wallet(&error); Error::RecoveryRequired })?;
        }
        diag::at(Stage::WalletController);
        let mut controller = ProtectedWalletSync::from_initialized_wallet(
            wallet,
            self.chain,
            NonZeroU32::new(self.config.policy.minimum_confirmations).ok_or(Error::InvalidData)?,
        )
        .map_err(|error| { diag::sync(&error); Error::RecoveryRequired })?;
        diag::at(Stage::WalletVerify);
        controller
            .verify_account_fvk(&fvk)
            .map_err(|error| { diag::sync(&error); Error::Verification })?;
        diag::at(Stage::WalletStatus);
        let access = Access {
            source: &self.source,
            pin: &pin,
            action: &action,
            identity: &identity,
            account: controller.account_uuid(),
            backend: controller.status().map_err(|error| { diag::sync(&error); Error::Verification })?.source,
        };
        let (material, scope) = self.fixed.original_for_account(&account_id)?;
        diag::at(Stage::WalletMaterial);
        controller
            .validate_durable_material_source_v1(material, scope, &fvk)
            .map_err(|error| { diag::durable(&error); Error::Verification })?;
        let immutable = self.fixed.fixed_context();
        diag::at(Stage::WalletSynchronize);
        controller
            .synchronize(
                &access,
                SyncLimits {
                    maximum_blocks: self.config.maximum_blocks.min(scope.maximum_scan_blocks),
                    anchor_height: Some(immutable.anchor_height),
                    deadline: Duration::from_secs(120),
                },
            )
            .await
            .map_err(|error| { diag::sync(&error); Error::Verification })?;
        access.check()?;
        diag::at(Stage::WalletTicket);
        let ticket = controller
            .exact_durable_review_ticket_v1(material, scope, &access, &fvk, &self.config.policy)
            .map_err(|error| { diag::durable(&error); Error::Verification })?;
        let local = LocalSelection::from_key_use_ticket(&ticket, &self.config.policy)?;
        // This is only the contemporaneous review-context required by the
        // maintained manifest reconciler (observed tip + 1). No constructor or
        // prover is invoked: fixed PCZT bytes/anchor/expiry remain unchanged.
        let mut context = immutable;
        context.target_height = local
            .context
            .tip_height
            .checked_add(1)
            .ok_or(Error::Verification)?;
        let inputs = ReviewInputs {
            construction_context: context,
            policy: self.fixed.verified().private_review_policy().clone(),
            input_actions: self.fixed.input_actions().to_vec(),
            output_actions: self.fixed.output_actions().to_vec(),
            own_selection: local,
        };
        diag::at(Stage::WalletReconcile);
        crate::manifest::reconcile(
            &AcceptedManifest {
                proposal: self.fixed.proposal().clone(),
            },
            &inputs,
            &account_id,
            &fvk,
        )?;
        self.fixed
            .verified()
            .verify_action_mappings(&inputs.input_actions, &inputs.output_actions)
            .map_err(|_| Error::Verification)?;
        access.check()?;
        drop(access);
        drop(action);
        Ok((
            FinancialWalletCustodyV1 {
                controller,
                ticket: Some(ticket),
                identity,
                source: self.source,
                _lock: lock,
                _temporary: temporary,
            },
            inputs,
        ))
    }
}
struct Access<'a> {
    pin: &'a FinancialOperationSourcePinV1,
    source: &'a PreparedOriginalFinancialSourceV1,
    action: &'a FinancialWalletActionV1,
    identity: &'a DatabaseFileIdentity,
    account: AccountUuid,
    backend: BackendIdentity,
}
impl Access<'_> {
    fn check(&self) -> Result<()> {
        self.action.check_source(self.source.identity_digest()).map_err(|error| { diag::signer(&error); error })?;
        self.source.check_financial_operation_source_pin_v1(self.pin,Operation::WalletObserve).map_err(|error| { diag::signer(&error); error })?;
        self.action.check_source(self.source.identity_digest()).map_err(|error| { diag::signer(&error); error })?;
        self.identity
            .check_retained_owner_path()
            .map_err(|error| { diag::storage(&error); Error::Verification })
    }
}
impl LocalWalletAccess for Access<'_> {
    fn permits(
        &self,
        account: AccountUuid,
        provider: &BackendIdentity,
        _purpose: WalletAccessPurpose,
    ) -> bool {
        account == self.account && provider == &self.backend && self.check().is_ok()
    }
}
pub(in crate::native_ui) struct FinancialWalletCustodyV1 {
    controller: ProtectedWalletSync,
    ticket: Option<WalletKeyUseTicket>,
    identity: DatabaseFileIdentity,
    source: Arc<PreparedOriginalFinancialSourceV1>,
    _lock: crate::files::PrivateDirectory,
    _temporary: tempfile::TempDir,
}
impl FinancialWalletCustodyV1 {
    pub(in crate::native_ui) fn sign(
        self,
        witness:&crate::native_ui::witness_workspace::financial_continuation_v1::FinancialWitnessCustodyV1,
        approved: crate::consent_journal::ApprovedFinancialSpendConsentV1,
        history:&wholepact_authority::durable_financial_continuation_v1::AuthenticatedFinancialContinuationHistoryV1,
        active: &wholepact_authority::AuthenticatedWriterSession,
        deadline: Instant,
    ) -> crate::authority_bridge::Result<crate::authority_bridge::AuthorizationCommit> {
        let mut this = self;
        this.source
            .check_custody()
            .map_err(|error| { diag::signer(&error); crate::authority_bridge::BridgeError::Permission })?;
        this.identity
            .check_retained_owner_path()
            .map_err(|error| { diag::storage(&error); crate::authority_bridge::BridgeError::Permission })?;
        let ticket = this
            .ticket
            .take()
            .ok_or(crate::authority_bridge::BridgeError::Permission)?;
        witness.sign(
            &this.source,
            approved,
            history,
            active,
            &mut this.controller,
            &ticket,
            deadline,
        )
    }
}
