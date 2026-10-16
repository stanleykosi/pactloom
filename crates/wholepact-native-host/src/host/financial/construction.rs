//! Fresh manual construction from independently consented live signer viewing
//! exports and actual maintained wallet scans. No byte/flag import substitutes
//! for source, account or disclosure authority.
use super::*;
use crate::authority::construction::ConstructionWalletAccess;
use wholepact_engine::{
    candidates::ScannedWalletConstruction, proof_jobs::ScannedWalletCheckpoint,
};
use wholepact_protocol::{
    construction::{DisclosureAcknowledgement, DisclosureScope},
    proving::ProvingLimits,
};
use wholepact_signer::{
    authority_bridge::{
        ipc::OriginalHistoryClient, preconstruction_ipc::PreconstructionRequest,
        provider::InstalledSignerProvider,
    },
    ipc::PairScope,
};
use wholepact_wallet::wallet::protected_sync::{SyncLimits, TreeState, account_birthday_from_tree};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParticipantSource {
    request: PreconstructionRequest,
    financial_directory: PathBuf,
    create: bool,
    signer_socket: PathBuf,
}
impl Host {
    pub(in crate::host) fn financial_construct(&self) -> Result<()> {
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        self.access()?;
        self.financial.as_ref().ok_or(Error::Locked)?;
        let candidate_id = self.terminal.ask("Exact candidate ID: ")?;
        let revision = self.financial_revision()?;
        let key = self
            .terminal
            .ask("Stable construction idempotency key (preserve for retries): ")?;
        self.financial_construct_exact(&candidate_id, revision, &key)
    }

    // Only the native owner calls this. Exact inert request metadata does not
    // replace any permission, lineage check or installed signer approval below.
    fn financial_construct_exact(
        &self,
        candidate_id: &str,
        revision: u64,
        key: &str,
    ) -> Result<()> {
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        let access = self.access()?;
        let financial = self.financial.as_ref().ok_or(Error::Locked)?;
        let (_, candidate) = self.engine.candidate(access, candidate_id)?;
        let sources: Vec<ParticipantSource> = self.read_json("Private configuration file for independently approved participant sources (public descriptors only): ")?;
        if sources.is_empty()
            || sources.len() > 8
            || sources.len() != candidate.proposal.manifest.participants.len()
        {
            return Err(Error::Invalid);
        }
        self.financial_lineage_preflight(&candidate, Some(key), &[])?;
        financial.inventory()?;
        let proof_destination = financial.directory.path("proof.sqlite")?;
        let mut accounts = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for source in &sources {
            let scope = &source.request.scope;
            source.request.validate().map_err(|_| Error::Invalid)?;
            let expected_wallet = source.financial_directory.join("wallet.sqlite");
            self.directory
                .external_destination(&source.financial_directory)?;
            if !source.signer_socket.is_absolute()
                || scope.proposal != candidate.proposal
                || scope.profile_id != self.secrets.profile()
                || scope.principal_id != access.principal_id
                || scope.operator_destination != proof_destination.to_str().ok_or(Error::Invalid)?
                || scope.wallet_destination != expected_wallet.to_str().ok_or(Error::Invalid)?
                || !accounts.insert(scope.account_id.clone())
                || !paths.insert(source.financial_directory.clone())
                || scope.anchor_height != sources[0].request.scope.anchor_height
                || scope.purpose != sources[0].request.scope.purpose
                || scope.retention_policy != sources[0].request.scope.retention_policy
            {
                return Err(Error::Invalid);
            }
        }
        // Snapshot actual retained local exclusions before pairing or disclosure.
        // This is not complete owner/witness history and admits no successor.
        let exclusions = sources
            .iter()
            .map(|source| {
                self.engine
                    .retained_financial_input_exclusions(
                        access,
                        &candidate,
                        &source.request.scope.account_id,
                    )
                    .map_err(Error::from)
            })
            .collect::<Result<Vec<_>>>()?;
        self.financial_lineage_preflight(&candidate, Some(key), &[])?;
        self.terminal.message("Each account now needs its own installed signer's native approval. Viewing keys disclose history and future account activity permanently. New encrypted participant directories must be preserved with the primary financial profile; incomplete backups remain disabled. This command contacts only the individually approved public-block providers.\n")?;
        // Pair every client before borrowing any live lease. No credentials,
        // provider pin, pairing receipt or native decision is accepted from JSON.
        let mut clients = Vec::new();
        for source in &sources {
            self.financial_lineage_preflight(&candidate, Some(key), &[])?;
            let scope = &source.request.scope;
            self.terminal.json(&source.request)?;
            self.terminal.confirm(&format!("Request separate signer-native viewing disclosure for account {} via {} and {} encrypted participant directory {}? Provider: {}. Exact witness destination: {}. No spending permission is requested.", scope.account_id, source.signer_socket.display(), if source.create { "CREATE" } else { "OPEN" }, source.financial_directory.display(), scope.provider.endpoint, scope.operator_destination))?;
            let provider = InstalledSignerProvider::load().map_err(|_| Error::Permission)?;
            let client = OriginalHistoryClient::pair(
                provider,
                &source.signer_socket,
                "wholepact-native-construction",
                PairScope {
                    account_id: scope.account_id.clone(),
                    agreement_id: scope.proposal.manifest.agreement.agreement_id.clone(),
                    participant_id: scope.participant_id.clone(),
                    manifest_digest: candidate.manifest_digest.clone(),
                    history_read: false,
                    authorization_export: false,
                    preconstruction_export: true,
                },
            )
            .map_err(|_| Error::Permission)?;
            clients.push(client);
        }
        let leases = clients
            .iter()
            .zip(&sources)
            .map(|(client, source)| {
                client
                    .request_preconstruction(&source.request)
                    .map_err(|_| Error::Permission)
            })
            .collect::<Result<Vec<_>>>()?;
        let consent = self
            .authority
            .construction_consent(&access.principal_id, &leases)?;
        let mut wallets = Vec::new();
        for (source, lease) in sources.iter().zip(&leases) {
            self.financial_lineage_preflight(&candidate, Some(key), &[])?;
            consent.check()?;
            let password = self.terminal.secret(if source.create {
                "New participant financial passphrase: "
            } else {
                "Participant financial passphrase: "
            })?;
            if source.create
                && *password
                    != *self
                        .terminal
                        .secret("Repeat participant financial passphrase: ")?
            {
                return Err(Error::Authentication);
            }
            crate::financial_inventory::register(
                &self.directory,
                &self.secrets,
                &source.financial_directory,
                crate::financial_inventory::AttachmentRole::ParticipantWallet,
                Some(lease.account_id()),
            )?;
            let mut profile = if source.create {
                crate::financial_profile::FinancialProfile::create(
                    &source.financial_directory,
                    &self.secrets.profile(),
                    password.as_bytes(),
                )?
            } else {
                crate::financial_profile::FinancialProfile::open(
                    &source.financial_directory,
                    &self.secrets.profile(),
                    password.as_bytes(),
                )?
            };
            drop(password);
            let scope = lease.scope();
            if source.create {
                let b = &scope.birthday;
                let birthday = account_birthday_from_tree(TreeState {
                    network: "test".into(),
                    height: u64::from(b.prior_height),
                    hash: b.prior_block_hash.clone(),
                    sapling_tree: b.sapling_tree.clone(),
                    orchard_tree: b.orchard_tree.clone(),
                    ironwood_tree: b.ironwood_tree.clone(),
                    ..Default::default()
                })
                .map_err(|_| Error::Invalid)?;
                lease.check_current().map_err(|_| Error::Permission)?;
                profile
                    .wallet
                    .import_dedicated_fvk(lease.fvk(), birthday)
                    .map_err(|_| Error::Invalid)?;
                lease.check_current().map_err(|_| Error::Permission)?;
            }
            let source = ChainAdapter::testnet(
                &scope.provider.source_id,
                &scope.provider.endpoint,
                NetworkPolicy::default(),
            )?;
            let wallet = profile.into_construction_wallet(
                source,
                std::num::NonZeroU32::new(scope.minimum_confirmations).ok_or(Error::Invalid)?,
            )?;
            wallet
                .sync
                .verify_account_fvk(lease.fvk())
                .map_err(|_| Error::Invalid)?;
            wallets.push(wallet);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Storage)?;
        let mut contributions = Vec::new();
        for ((wallet, lease), retained) in wallets.iter_mut().zip(&leases).zip(&exclusions) {
            let scope = lease.scope();
            let gate = ConstructionWalletAccess {
                account: wallet.sync.account_uuid(),
                lease,
                consent: &consent,
            };
            let limits = SyncLimits {
                maximum_blocks: scope.maximum_blocks,
                anchor_height: Some(scope.anchor_height),
                deadline: Duration::from_secs(120),
            };
            let status = runtime.block_on(async {
                let scan = wallet.sync.synchronize(&gate, limits);
                tokio::pin!(scan);
                let mut progress = tokio::time::interval(Duration::from_secs(1));
                loop { tokio::select! {
                    result = &mut scan => break result.map_err(|_| Error::Invalid),
                    _ = progress.tick() => { consent.check()?; self.terminal.message("Scanning approved public blocks locally; no signing or submission is active.\n")?; }
                }}
            })?;
            self.terminal.json(&status)?;
            consent.check()?;
            let proposal = wholepact_core::Proposal::validate(scope.proposal.clone())
                .map_err(|_| Error::Invalid)?;
            let debit = proposal
                .accounting()
                .participant_net_debits
                .get(&scope.participant_id)
                .ok_or(Error::Invalid)?
                .as_zatoshis();
            // Store restrictions are protocol nullifiers/local outpoints, while
            // the wallet filter accepts ReceivedNoteId. Resolve only through the
            // actual consented wallet selection; never cast or trust JSON IDs.
            let mut excluded_note_refs = Vec::new();
            let selected = loop {
                consent.check()?;
                self.financial_lineage_preflight(&candidate, Some(key), &[])?;
                let current = self.engine.retained_financial_input_exclusions(
                    access,
                    &candidate,
                    &scope.account_id,
                )?;
                if &current != retained || current.account_id() != scope.account_id {
                    return Err(Error::Permission);
                }
                let selected = wallet
                    .sync
                    .select_contribution(
                        &gate,
                        lease.fvk(),
                        &scope.account_id,
                        debit,
                        &excluded_note_refs,
                    )
                    .map_err(|_| Error::Invalid)?;
                selected.check_current().map_err(|_| Error::Permission)?;
                let evidence = selected.selection().evidence();
                let refs = selected.selection().local_note_refs();
                if evidence.account_id() != scope.account_id
                    || evidence.inputs().len() != refs.len()
                {
                    return Err(Error::Invalid);
                }
                let before = excluded_note_refs.len();
                let mut conflict = false;
                for (input, local_ref) in evidence.inputs().iter().zip(refs) {
                    if retained.excludes(input.input_id(), &hex::encode(input.nullifier())) {
                        conflict = true;
                        if !excluded_note_refs.contains(local_ref) {
                            excluded_note_refs.push(*local_ref);
                        }
                    }
                }
                if !conflict {
                    break selected;
                }
                if excluded_note_refs.len() == before {
                    return Err(Error::Permission);
                }
                // Never persist or expose a conflicting selection. Bounded local
                // reselection is before construction/randomized checkpoint bytes.
                if excluded_note_refs.len() > 1024 {
                    return Err(Error::Permission);
                }
            };
            consent.check()?;
            contributions.push(selected);
        }
        let manifest_digest: [u8; 32] = hex::decode(&candidate.manifest_digest)
            .map_err(|_| Error::Invalid)?
            .try_into()
            .map_err(|_| Error::Invalid)?;
        let declarations = leases
            .iter()
            .map(|lease| {
                let scope = lease.scope();
                DisclosureAcknowledgement {
                    account_id: scope.account_id.clone(),
                    manifest_digest,
                    operator: scope.operator_name.clone(),
                    reviewer_account_ids: scope.reviewer_account_ids.clone(),
                    purpose: scope.purpose.clone(),
                    retention_policy: scope.retention_policy.clone(),
                    scope: DisclosureScope::DedicatedAccountFvkAndSelectedNotesAndOutputs,
                }
            })
            .collect::<Vec<_>>();
        consent.check()?;
        self.review_construction_sponsors(access, candidate_id, &leases)?;
        self.financial_lineage_preflight(&candidate, Some(key), &[])?;
        for (source, retained) in sources.iter().zip(&exclusions) {
            if self.engine.retained_financial_input_exclusions(
                access,
                &candidate,
                &source.request.scope.account_id,
            )? != *retained
            {
                return Err(Error::Permission);
            }
        }
        let result = self.engine.checkpoint_candidate_from_wallets(
            access,
            key,
            candidate_id,
            revision,
            ScannedWalletCheckpoint {
                construction: ScannedWalletConstruction {
                    contributions,
                    declarations: &declarations,
                },
                jobs: &financial.proof,
                limits: ProvingLimits { maximum_actions: 8 },
                consent: &consent,
            },
        )?;
        consent.check()?;
        self.terminal.json(&result)?;
        self.terminal.message("Exact private candidate retained in the encrypted proof journal. No proof, signature, disclosure export or submission has run. Preserve the original construction key and every financial directory, including after any partial failure.\n")
    }
}

impl Host {
    pub(in crate::host) fn native_construction_request(&self) -> Result<()> {
        // Ordinary route only. Recovered manual admission is a separate owner
        // workflow and must never be selected as a fallback for this request.
        require_financial_generation_admission(&self.secrets)?;
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        self.financial.as_ref().ok_or(Error::Locked)?.inventory()?;
        let agreement = self.terminal.ask("Exact selected agreement ID: ")?;
        let access = self.access()?;
        self.terminal
            .json(&self.engine.native_requests(access, &agreement)?)?;
        let request = self.terminal.ask("Exact queued native request ID: ")?;
        let view = self.engine.native_request(access, &agreement, &request)?;
        let (_, candidate) = self.engine.candidate(access, &view.candidate_id)?;
        let key = format!("native-construction-{}", view.request_id);
        self.financial_lineage_preflight(&candidate, Some(&key), &[])?;
        self.terminal.json(&view)?;
        self.terminal.message(&format!("Preserve this CONSTRUCTION key for exact native inspection: {key}\nCandidate: {}\nExpected construction revision: {}\nThis is separate from the browser enqueue key.\n", view.candidate_id, view.queued_revision.checked_add(1).ok_or(Error::Invalid)?))?;
        self.terminal.confirm("Start this exact ordinary candidate-construction request? The original terms remain fixed. Two metadata-only revisions precede construction. Private configuration and every installed signer approval are requested separately next. If interrupted, do not dispatch it again; preserve the original key and inspect retained checkpoints. No proof, signature or submission is requested.")?;
        self.financial_permission(Permission::Coordinate)?;
        self.financial_permission(Permission::Disclose)?;
        self.financial_lineage_preflight(&candidate, Some(&key), &[])?;
        let attempt = self
            .engine
            .mark_native_construction_attempt(access, &agreement, &request)?;
        self.financial_construct_exact(
            attempt.candidate_id(),
            attempt.revision(),
            attempt.construction_key(),
        )
    }
}
