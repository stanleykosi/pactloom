//! Synthetic-only historical comparison after the original product owner and
//! every original child have drained. This creates no Window, source authority,
//! credentials, request, deadline, approval or journal row. The maintained
//! existing-history openers may touch locks/sidecars, not historical journal rows.
use super::*;
use crate::policy::{Event, Ledger};
use std::collections::BTreeSet;
use wholepact_storage_security::witness_namespace_fs::InstallationProbe;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExpectedHistory {
    Pristine,
    OneExactAppend,
}
impl ExpectedHistory {
    fn from_expectation(one_exact_append: bool) -> Self {
        if one_exact_append { Self::OneExactAppend } else { Self::Pristine }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Pristine => "pristine",
            Self::OneExactAppend => "one_exact_append",
        }
    }
    fn target_events(self) -> u64 {
        match self {
            Self::Pristine => 4,
            Self::OneExactAppend => 5,
        }
    }
}

fn parse_descriptor(bytes: &[u8]) -> Result<PreservedPristineDeliveryV1> {
    if bytes.is_empty() || bytes.len() > MAX_PRESERVED_BYTES {
        return Err(AuthorityError::Limit);
    }
    // Struct deserialization rejects duplicate and unknown fields at every level.
    let descriptor: PreservedPristineDeliveryV1 =
        serde_json::from_slice(bytes).map_err(|_| AuthorityError::InvalidBinding)?;
    if descriptor.version != 1
        || descriptor.installation.is_empty()
        || descriptor.installation.len() > 16 * 1024
        || descriptor.accounts.len() != 3
        || descriptor.form.server_name != "localhost"
        || descriptor.form.network_profile_id != PROFILE
    {
        return Err(AuthorityError::InvalidBinding);
    }
    let home = Path::new(&descriptor.home_path);
    if !home.is_absolute()
        || descriptor.home_path.len() > 4096
        || home.components().any(|part| !matches!(
            part, std::path::Component::RootDir | std::path::Component::Normal(_)
        ))
        || home.components().collect::<PathBuf>().as_os_str() != home.as_os_str()
    {
        return Err(AuthorityError::InvalidBinding);
    }
    // These are comparison strings only. Audit never reads TLS private keys or
    // owner-client credentials, and never treats a caller path as a namespace.
    for (actual, name) in [
        (&descriptor.form.storage_key_file, "synthetic-namespace.key"),
        (&descriptor.form.server_certificate_der, "server.der"),
        (&descriptor.form.server_private_key_pkcs8_der, "server.pk8"),
        (&descriptor.form.trusted_client_root_der, "ca.der"),
        (&descriptor.owner_client.certificate_der, "owner.der"),
        (&descriptor.owner_client.private_key_pkcs8_der, "owner.pk8"),
        (&descriptor.owner_client.trusted_server_root_der, "ca.der"),
    ] {
        if actual.len() > 4096 || actual.as_str() != home.join(name).to_str().ok_or(AuthorityError::InvalidBinding)? {
            return Err(AuthorityError::InvalidBinding);
        }
    }
    let address: std::net::SocketAddr = descriptor.form.endpoint.parse()
        .map_err(|_| AuthorityError::InvalidBinding)?;
    if !address.ip().is_loopback()
        || address.port() == 0
        || address.to_string() != descriptor.form.endpoint
    {
        return Err(AuthorityError::InvalidBinding);
    }
    crate::id(&descriptor.form.witness_id)?;
    crate::hash(&descriptor.form.pinned_server_certificate_digest)?;
    crate::hash(&descriptor.form.expected_account_id)?;
    let mut seen = BTreeSet::new();
    for account in &descriptor.accounts {
        crate::hash(&account.account_id)?;
        crate::hash(&account.head.digest)?;
        crate::hash(&account.original_source_commitment)?;
        if !seen.insert(account.account_id.as_str())
            || account.original_signed_birth.is_empty()
            || account.original_signed_birth.len() > crate::MAX_FRAME_BYTES
        {
            return Err(AuthorityError::InvalidBinding);
        }
    }
    let selected = descriptor.accounts.iter()
        .find(|account| account.account_id == descriptor.form.expected_account_id)
        .ok_or(AuthorityError::InvalidBinding)?;
    if selected.head.sequence != 4 {
        return Err(AuthorityError::InvalidBinding);
    }
    Ok(descriptor)
}

fn exact_request(descriptor: &PreservedPristineDeliveryV1) -> Result<OwnerControlRequest> {
    if descriptor.form.request_json.is_empty()
        || descriptor.form.request_json.len() > crate::MAX_FRAME_BYTES
    {
        return Err(AuthorityError::Limit);
    }
    let request: OwnerControlRequest = crate::decode(descriptor.form.request_json.as_bytes())?;
    let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control else {
        return Err(AuthorityError::Permission);
    };
    record.validate_request_shape(&request)?;
    let selected = descriptor.accounts.iter()
        .find(|account| account.account_id == descriptor.form.expected_account_id)
        .ok_or(AuthorityError::InvalidBinding)?;
    if request.account_id != selected.account_id
        || request.network_profile_id != descriptor.form.network_profile_id
        || request.expected_head != selected.head
        || record.scope.witness.endpoint != descriptor.form.endpoint
        || record.scope.witness.witness_id != descriptor.form.witness_id
        || record.scope.witness.pinned_server_certificate_digest
            != descriptor.form.pinned_server_certificate_digest
    {
        return Err(AuthorityError::InvalidBinding);
    }
    // No live-clock check or deadline replacement: this is past-event evidence.
    Ok(request)
}

fn owner_pin(descriptor: &PreservedPristineDeliveryV1) -> Result<String> {
    let encoded = &descriptor.form.owner_certificate_der_hex;
    if encoded.is_empty() || encoded.len() > 2 * 65_536 {
        return Err(AuthorityError::Limit);
    }
    let certificate = hex::decode(encoded).map_err(|_| AuthorityError::InvalidBinding)?;
    Ok(crate::transport::certificate_digest(&CertificateDer::from(certificate)))
}

/// Deny-only inventory bound. The maintained namespace opener independently
/// authenticates registry records and original database identities. This checks
/// exact main filenames, not a claim about all historical registry cardinality.
fn require_three_main_journals(root: &Path, descriptor: &PreservedPristineDeliveryV1) -> Result<()> {
    // Same fixed journals/<validated-account-id>.wp layout as witness_locator.
    // No path derived here is ever supplied to a database/source opener.
    let expected: BTreeSet<_> = descriptor.accounts.iter()
        .map(|account| format!("{}.wp", account.account_id)).collect();
    let mut actual = BTreeSet::new();
    let mut count = 0usize;
    for entry in fs::read_dir(root.join("journals")).map_err(|_| AuthorityError::Storage)? {
        count += 1;
        if count > 12 { return Err(AuthorityError::Limit); }
        let entry = entry.map_err(|_| AuthorityError::Storage)?;
        let name = entry.file_name().into_string().map_err(|_| AuthorityError::InvalidBinding)?;
        let main = name.strip_suffix("-wal")
            .or_else(|| name.strip_suffix("-shm"))
            .or_else(|| name.strip_suffix("-journal"))
            .unwrap_or(&name);
        if !expected.contains(main) { return Err(AuthorityError::CorruptHistory); }
        if main == name { actual.insert(name); }
    }
    if actual != expected { return Err(AuthorityError::CorruptHistory); }
    Ok(())
}

fn require_original_fixed_installation(descriptor: &PreservedPristineDeliveryV1) -> Result<()> {
    // Storage's descriptor-only reopen verifies original home/root/journals
    // devices/inodes, marker identity and installation ID. This custody is only
    // a comparison handle and MUST end before the production namespace opener.
    let original = EphemeralWitnessInstallation::reopen_preserved_original_v2(
        &descriptor.installation,
    )?;
    let probe = original.probe()?;
    let root = probe.root_path();
    if root.parent().and_then(Path::to_str) != Some(descriptor.home_path.as_str()) {
        return Err(AuthorityError::InvalidBinding);
    }
    require_three_main_journals(&root, descriptor)?;
    drop(probe);
    drop(original);
    // Resolve the genuine OS password database, never HOME or an override.
    let fixed = InstallationProbe::fixed_user_installation()?;
    if fixed.root_path().as_os_str() != root.as_os_str() { return Err(AuthorityError::InvalidBinding); }
    drop(fixed);
    Ok(())
}

fn namespace_input(
    descriptor: &PreservedPristineDeliveryV1,
    owner: &str,
    account: &str,
) -> NamespaceOpenInput {
    NamespaceOpenInput {
        synthetic_installation: None,
        endpoint: descriptor.form.endpoint.clone(),
        server_name: descriptor.form.server_name.clone(),
        witness_id: descriptor.form.witness_id.clone(),
        pinned_server_certificate_digest: descriptor.form.pinned_server_certificate_digest.clone(),
        owner_certificate_digest: owner.into(),
        network_profile_id: descriptor.form.network_profile_id.clone(),
        storage_key_file: descriptor.form.storage_key_file.clone(),
        expected_account_id: account.into(),
    }
}

/// Replay ONLY actual first-four stored payloads, after the complete real journal
/// has passed journal::load. Maintained Ledger verification is reused, and every
/// sequence/operation/previous/head link is rechecked. No invented event exists.
fn authenticated_original_prefix(c: &rusqlite::Connection, actual: &Ledger) -> Result<Ledger> {
    let mut prefix = Ledger::new(actual.policy.clone())?;
    let mut query = c.prepare(
        "SELECT sequence,operation_id,previous_head,head,payload FROM authority_events WHERE sequence<=4 ORDER BY sequence",
    )?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        let sequence: u64 = row.get(0)?;
        let operation: String = row.get(1)?;
        let previous: String = row.get(2)?;
        let head: String = row.get(3)?;
        let raw = Zeroizing::new(row.get::<_, Vec<u8>>(4)?);
        let event: Event = crate::decode(&raw)?;
        if sequence != prefix.snapshot.head.sequence + 1
            || previous != prefix.snapshot.head.digest
            || operation != event.mutation.operation_id()
            || prefix.replay(&event)?.is_some()
        {
            return Err(AuthorityError::CorruptHistory);
        }
        prefix.apply(&event)?;
        if prefix.snapshot.head.digest != head { return Err(AuthorityError::CorruptHistory); }
    }
    if prefix.snapshot.head.sequence != 4 || prefix.operations.len() != 4 {
        return Err(AuthorityError::CorruptHistory);
    }
    prefix.require_supported_durable_payment_history_v1()?;
    if prefix.selected_durable_payment_admission_v1()?.is_some()
        || prefix.selected_durable_delivery_admission_v2()?.is_some()
    {
        return Err(AuthorityError::CorruptHistory);
    }
    Ok(prefix)
}

fn verify_exact_append(
    journal: &crate::AuthorityJournal,
    baseline: &PristineAccountBaselineV1,
    request: &OwnerControlRequest,
) -> Result<()> {
    journal.require_born_read_current()?;
    let namespace = journal.born_owner.as_ref().ok_or(AuthorityError::Permission)?
        .namespace_binding_digest_v1()?;
    let connection = journal.connection.lock().map_err(|_| AuthorityError::Storage)?;
    let c = connection.connection();
    let actual = crate::journal::load(c)?;
    let birth = crate::pending_birth_storage::read(c, &actual.policy)?
        .ok_or(AuthorityError::RecoveryRequired)?;
    let events: u64 = c.query_row("SELECT count(*) FROM authority_events", [], |row| row.get(0))?;
    let keys: u64 = c.query_row("SELECT count(*) FROM authority_session_keys", [], |row| row.get(0))?;
    if events != 5 || actual.snapshot.head.sequence != 5 || actual.operations.len() != 5
        || actual.selected_durable_delivery_admission_v2()? != Some(request)
        || actual.selected_durable_payment_admission_v1()?.is_some()
    {
        return Err(AuthorityError::CorruptHistory);
    }
    let mut prefix = authenticated_original_prefix(c, &actual)?;
    prefix.validate_manual_birth(Some(&birth))?;
    if prefix.snapshot.head != baseline.head || prefix.snapshot.head != request.expected_head
        || actual.sessions != prefix.sessions
        || actual.activated_sessions != prefix.activated_sessions
        || keys != prefix.sessions.len() as u64
    {
        return Err(AuthorityError::CorruptHistory);
    }
    // EXACT same commitment tuple/domain as preserve's original_source_commitment.
    // Namespace and birth are actual authenticated originals. Only the replayed
    // actual first-four projection and its actual retained key count are used.
    let original = crate::digest("wholepact:synthetic-original-delivery-history:v2", &(
        namespace, &birth, &prefix.policy, &prefix.snapshot, &prefix.operations,
        &prefix.sessions, &prefix.activated_sessions, 4_u64, keys,
    ))?;
    if original != baseline.original_source_commitment {
        return Err(AuthorityError::CorruptHistory);
    }
    let raw = Zeroizing::new(c.query_row(
        "SELECT payload FROM authority_events WHERE sequence=5", [], |row| row.get::<_, Vec<u8>>(0),
    )?);
    let event: Event = crate::decode(&raw)?;
    if event.mutation != crate::AuthorityMutation::OwnerControl(request.clone())
        || event.authenticated_certificate_digest != actual.policy.owner_certificate_digest
        || event.writer_session_id.is_some() || event.original_request_link.is_some()
        || prefix.replay(&event)?.is_some()
    {
        return Err(AuthorityError::CorruptHistory);
    }
    // The event-time maintained validator checks the exact original deadline.
    // Its sole append closes old session pointers; it creates no successor use.
    prefix.apply(&event)?;
    if prefix.snapshot != actual.snapshot || prefix.operations != actual.operations
        || prefix.sessions != actual.sessions || prefix.activated_sessions != actual.activated_sessions
        || actual.snapshot.outstanding_reservations != 0
        || actual.snapshot.outstanding_debit_zatoshis != 0
        || actual.snapshot.settled_debit_zatoshis != 0
        || actual.snapshot.reserved_input_value_zatoshis != 0
        || actual.snapshot.pending_writer_session.is_some()
        || actual.snapshot.active_writer_session.is_some()
    {
        return Err(AuthorityError::CorruptHistory);
    }
    drop(connection);
    journal.require_born_read_current()?;
    Ok(())
}

pub(super) fn audit(bytes: &[u8], expected_one_exact_append: bool) -> Result<serde_json::Value> {
    let expected = ExpectedHistory::from_expectation(expected_one_exact_append);
    let descriptor = parse_descriptor(bytes)?;
    let request = exact_request(&descriptor)?;
    let owner = owner_pin(&descriptor)?;
    let mut single_accounts = 0_u8;
    let mut roster_accounts = 0_u8;
    for account in &descriptor.accounts {
        require_original_fixed_installation(&descriptor)?;
        {
            // Every account is opened at the real fixed passwd-home source.
            // This entire scope drops journal, connection and namespace custody
            // before the next same-namespace account is independently opened.
            let journal = crate::witness_locator::open_born_history(namespace_input(
                &descriptor, &owner, &account.account_id,
            ))?;
            journal.require_born_read_current()?;
            let is_target = account.account_id == request.account_id;
            {
                let signed: crate::pending_birth_signature::PendingBirthOwnerSignature =
                    crate::decode(account.original_signed_birth.as_bytes())?;
                let verified = crate::pending_birth_signature::verify_pending_birth_owner_signature(
                    &signed, &owner,
                )?;
                let connection = journal.connection.lock().map_err(|_| AuthorityError::Storage)?;
                let ledger = crate::journal::load(connection.connection())?;
                let birth = crate::pending_birth_storage::read(connection.connection(), &ledger.policy)?
                    .ok_or(AuthorityError::RecoveryRequired)?;
                let disclosure = &birth.request.disclosure;
                if verified.request() != &birth.request
                    || verified.certificate_digest() != birth.authenticated_owner_certificate_digest
                    || verified.evidence_digest() != birth.owner_approval_evidence_digest
                    || verified.request().policy != ledger.policy
                    || ledger.snapshot.account_id != account.account_id
                    || disclosure.account_id != account.account_id
                    || disclosure.endpoint != descriptor.form.endpoint
                    || disclosure.server_name != descriptor.form.server_name
                    || disclosure.witness_id != descriptor.form.witness_id
                    || disclosure.network_profile_id != descriptor.form.network_profile_id
                    || disclosure.pinned_server_certificate_digest != descriptor.form.pinned_server_certificate_digest
                {
                    return Err(AuthorityError::CorruptHistory);
                }
                match (ledger.manual_extension()?.is_some(), ledger.manual_roster_extension()?.is_some()) {
                    (true, false) => single_accounts += 1,
                    // The maintained manual accessor intentionally projects the
                    // roster extension's original account record as well.
                    (true, true) => roster_accounts += 1,
                    _ => return Err(AuthorityError::CorruptHistory),
                }
                if is_target {
                    let OwnerControl::AdmitDurablePaymentWithDeliveryV2 { record } = &request.control else {
                        return Err(AuthorityError::Permission);
                    };
                    record.validate_request(&request, disclosure)?;
                    if ledger.snapshot.head.sequence != expected.target_events()
                        || ledger.manual_roster_extension()?.is_none()
                    {
                        return Err(AuthorityError::CorruptHistory);
                    }
                }
                if !is_target || expected == ExpectedHistory::Pristine {
                    if ledger.snapshot.head != account.head
                        || ledger.selected_durable_payment_admission_v1()?.is_some()
                        || ledger.selected_durable_delivery_admission_v2()?.is_some()
                    {
                        return Err(AuthorityError::CorruptHistory);
                    }
                }
            }
            if is_target && expected == ExpectedHistory::OneExactAppend {
                verify_exact_append(&journal, account, &request)?;
            } else if original_source_commitment(&journal)? != account.original_source_commitment {
                return Err(AuthorityError::CorruptHistory);
            }
            journal.require_born_read_current()?;
        }
    }
    require_original_fixed_installation(&descriptor)?;
    if single_accounts != 1 || roster_accounts != 2 {
        return Err(AuthorityError::CorruptHistory);
    }
    // Closed finite facts only, never paths, PIDs, keys or arbitrary receipt text.
    Ok(serde_json::json!({
        "version": 1,
        "kind": "pristine_delivery_originals_audit_v1",
        "expectation": expected.label(),
        "original_account_histories": 3,
        "original_main_journals": 3,
        "target_original_prefix_events": 4,
        "target_current_events": expected.target_events(),
        "unchanged_non_target_histories": 2,
        "exact_retained_request_appends": expected.target_events() - 4,
        "original_source_commitments_match": true,
        "no_successor_effect": true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Data-only refusals. No files, native state, sockets, keys or setup exist.
    fn syntactic_descriptor() -> serde_json::Value {
        let home = "/tmp/wholepact-synthetic-witness-installation-data-only";
        let path = |name: &str| format!("{home}/{name}");
        let accounts = ["1", "2", "3"].map(|digit| serde_json::json!({
            "account_id": digit.repeat(64),
            "head": { "sequence": 4, "digest": "4".repeat(64) },
            "original_signed_birth": "{}", "original_source_commitment": "5".repeat(64)
        }));
        serde_json::json!({
            "version": 1, "installation": [0], "home_path": home,
            "form": {
                "endpoint": "127.0.0.1:12345", "server_name": "localhost", "witness_id": "synthetic-only",
                "pinned_server_certificate_digest": "a".repeat(64), "network_profile_id": PROFILE,
                "expected_account_id": "2".repeat(64), "owner_certificate_der_hex": "00",
                "storage_key_file": path("synthetic-namespace.key"), "server_certificate_der": path("server.der"),
                "server_private_key_pkcs8_der": path("server.pk8"), "trusted_client_root_der": path("ca.der"),
                "request_json": ""
            },
            "owner_client": { "certificate_der": path("owner.der"), "private_key_pkcs8_der": path("owner.pk8"), "trusted_server_root_der": path("ca.der") },
            "accounts": accounts
        })
    }
    #[test]
    fn descriptor_refuses_unknown_and_duplicate_fields_without_opening_sources() {
        let mut value = syntactic_descriptor();
        value["form"]["restored_approval"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PreservedPristineDeliveryV1>(value).is_err());
        let raw = serde_json::to_string(&syntactic_descriptor()).unwrap();
        let duplicate = raw.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
        assert!(serde_json::from_str::<PreservedPristineDeliveryV1>(&duplicate).is_err());
    }
    #[test]
    fn descriptor_refuses_missing_originals_and_oversize_without_opening_sources() {
        let mut value = syntactic_descriptor();
        value["accounts"] = serde_json::json!([]);
        assert!(parse_descriptor(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(parse_descriptor(&[]).is_err());
        assert!(parse_descriptor(&vec![b' '; MAX_PRESERVED_BYTES + 1]).is_err());
    }
    #[test]
    fn descriptor_refuses_duplicate_accounts_wrong_membership_and_replaced_prefix() {
        let value = syntactic_descriptor();
        // Parsing alone admits inert data, never storage or authority.
        assert!(parse_descriptor(&serde_json::to_vec(&value).unwrap()).is_ok());
        let mut duplicate = value.clone();
        duplicate["accounts"][2] = duplicate["accounts"][0].clone();
        assert!(parse_descriptor(&serde_json::to_vec(&duplicate).unwrap()).is_err());
        let mut missing = value.clone();
        missing["form"]["expected_account_id"] = serde_json::json!("6".repeat(64));
        assert!(parse_descriptor(&serde_json::to_vec(&missing).unwrap()).is_err());
        let mut changed = value;
        changed["accounts"][1]["head"]["sequence"] = serde_json::json!(5);
        assert!(parse_descriptor(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
    #[test]
    fn descriptor_refuses_noncanonical_or_redirected_paths_and_nonloopback_origin() {
        for (field, replacement) in [
            ("storage_key_file", "/tmp/replacement.key"),
            ("server_certificate_der", "/tmp/wholepact-synthetic-witness-installation-data-only/./server.der"),
            ("endpoint", "192.0.2.1:12345"),
        ] {
            let mut value = syntactic_descriptor();
            value["form"][field] = serde_json::json!(replacement);
            assert!(parse_descriptor(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let mut value = syntactic_descriptor();
        value["home_path"] = serde_json::json!("/tmp/./wholepact-synthetic-witness-installation-data-only");
        assert!(parse_descriptor(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn expectation_is_only_the_closed_four_or_five_event_comparison() {
        assert_eq!(ExpectedHistory::from_expectation(false).target_events(), 4);
        assert_eq!(ExpectedHistory::from_expectation(true).target_events(), 5);
    }
}
