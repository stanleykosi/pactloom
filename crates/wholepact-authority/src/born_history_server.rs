//! Namespace-owned informational witness server opener. This grants no mutation,
//! writer session, financial admission or born-account activation.
use crate::witness_locator::{NamespaceOpenInput, open_born_history};
use crate::{AuthorityError, AuthorityJournal, Result};

/// Untrusted bounded configuration is checked against the actual encrypted fixed
/// namespace. The supplied server identity comes from the selected TLS certificate
/// at the CLI boundary; it is not a new origin enrollment or arbitrary DB path.
pub fn open_born_history_for_server(
    namespace_json: &[u8],
    actual_server_certificate_digest: &str,
    actual_listen: &str,
) -> Result<AuthorityJournal> {
    if namespace_json.is_empty() || namespace_json.len() > 16 * 1024 {
        return Err(AuthorityError::Limit);
    }
    let input: NamespaceOpenInput =
        serde_json::from_slice(namespace_json).map_err(|_| AuthorityError::InvalidBinding)?;
    if input.pinned_server_certificate_digest != actual_server_certificate_digest
        || input.endpoint != actual_listen
    {
        return Err(AuthorityError::InvalidBinding);
    }
    open_born_history(input)
}

/// Serve ONLY a previously native-published exact manual-enrollment extension.
/// Configuration cannot create or replace a scope; the original fixed namespace
/// is opened and authenticated, including all aliases, exclusions and intent.
pub fn open_born_manual_enrollment_for_server(
    namespace_json: &[u8],
    selected_extension_digest: &str,
    actual_server_certificate_digest: &str,
    actual_listen: &str,
) -> Result<AuthorityJournal> {
    // Compatibility endpoint selects only the original attempt. It never
    // silently follows a successor approved after this server was configured.
    open_born_manual_attempt_inner(
        namespace_json,
        selected_extension_digest,
        None,
        actual_server_certificate_digest,
        actual_listen,
    )
}
/// Select exactly one already-native-approved attempt from the actual namespace.
/// A successor needs an explicit new selection; a running old server is fenced.
pub fn open_born_manual_attempt_for_server(
    namespace_json: &[u8],
    selected_extension_digest: &str,
    selected_attempt_digest: &str,
    actual_server_certificate_digest: &str,
    actual_listen: &str,
) -> Result<AuthorityJournal> {
    crate::hash(selected_attempt_digest)?;
    open_born_manual_attempt_inner(
        namespace_json,
        selected_extension_digest,
        Some(selected_attempt_digest),
        actual_server_certificate_digest,
        actual_listen,
    )
}
fn open_born_manual_attempt_inner(
    namespace_json: &[u8],
    selected_extension_digest: &str,
    selected_attempt_digest: Option<&str>,
    actual_server_certificate_digest: &str,
    actual_listen: &str,
) -> Result<AuthorityJournal> {
    crate::hash(selected_extension_digest)?;
    let mut journal = open_born_history_for_server(
        namespace_json,
        actual_server_certificate_digest,
        actual_listen,
    )?;
    journal
        .born_owner
        .as_ref()
        .ok_or(AuthorityError::Permission)?
        .check_mutation_current()?;
    let attempt_digest = {
        let c = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(c.connection())?;
        let attempt = ledger.latest_manual_attempt()?;
        let e = &ledger
            .manual_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        if e.digest()? != selected_extension_digest
            || crate::now_ms()? >= e.terms.scope.expires_at_ms
        {
            return Err(AuthorityError::Permission);
        }
        let selected = match selected_attempt_digest {
            Some(d) => d.to_owned(),
            None => crate::manual_session_continuation::initial_manual_attempt_digest(e)?,
        };
        if attempt.attempt_digest != selected {
            return Err(AuthorityError::StaleHead);
        }
        selected
    };
    journal.born_manual_scope = Some(
        crate::manual_session_continuation::BornManualBootstrapScope {
            extension_digest: selected_extension_digest.into(),
            attempt_digest,
        },
    );
    Ok(journal)
}

/// Opens one exact already-native-approved V2 roster attempt. Configuration is
/// inert selection only; an older server cannot follow a new continuation.
pub fn open_born_manual_roster_attempt_v2_for_server(
    namespace_json: &[u8],
    selected_extension_digest: &str,
    selected_attempt_digest: &str,
    actual_server_certificate_digest: &str,
    actual_listen: &str,
) -> Result<AuthorityJournal> {
    crate::hash(selected_extension_digest)?;
    crate::hash(selected_attempt_digest)?;
    let mut journal = open_born_history_for_server(
        namespace_json,
        actual_server_certificate_digest,
        actual_listen,
    )?;
    journal
        .born_owner
        .as_ref()
        .ok_or(AuthorityError::Permission)?
        .check_mutation_current()?;
    {
        let c = journal
            .connection
            .lock()
            .map_err(|_| AuthorityError::Storage)?;
        let ledger = crate::journal::load(c.connection())?;
        ledger.require_supported_manual_history()?;
        let e = &ledger
            .manual_roster_extension()?
            .ok_or(AuthorityError::Permission)?
            .extension;
        let a = ledger.latest_manual_roster_attempt_v2()?;
        if e.digest()? != selected_extension_digest
            || crate::now_ms()? >= e.account_extension.terms.scope.expires_at_ms
        {
            return Err(AuthorityError::Permission);
        }
        if a.attempt_digest != selected_attempt_digest {
            return Err(AuthorityError::StaleHead);
        }
    }
    journal.born_manual_scope = Some(
        crate::manual_session_continuation::BornManualBootstrapScope {
            extension_digest: selected_extension_digest.into(),
            attempt_digest: selected_attempt_digest.into(),
        },
    );
    Ok(journal)
}
