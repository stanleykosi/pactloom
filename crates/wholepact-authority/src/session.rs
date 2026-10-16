//! TLS exporter session access using maintained ring HMAC-SHA256. The exporter
//! key never enters wire JSON or signer backups. Each proof binds a fresh TLS
//! channel and exact canonical mutation, including its head and owner scope.
use crate::*;
use ring::hmac;
use serde::Serialize;

pub(crate) const EXPORTER_LABEL: &[u8] = b"EXPORTER-Wholepact-Authority-Writer-v2";

pub(crate) fn session_id(key: &[u8; 32]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"wholepact:writer-session-id:v2\0");
    hash.update(key);
    hex::encode(hash.finalize())
}
pub(crate) fn history_digest(snapshot: &AccountSnapshot) -> Result<String> {
    digest(
        "wholepact:reconciled-authority-history:v2",
        &(
            &snapshot.policy_digest,
            &snapshot.head,
            snapshot.outstanding_reservations,
            snapshot.outstanding_debit_zatoshis,
            snapshot.settled_debit_zatoshis,
            snapshot.aggregate_budget_zatoshis,
            snapshot.reserved_input_value_zatoshis,
        ),
    )
}
#[derive(Serialize)]
struct ProofContext<'a> {
    domain: &'static str,
    protocol_version: u16,
    session_id: &'a str,
    disclosure: &'a WitnessDisclosureDescriptor,
    writer_epoch: u64,
    channel_binding: String,
    mutation: &'a AuthorityMutation,
}
fn context<'a>(
    scope: (&'a str, &'a WitnessDisclosureDescriptor, u64),
    exporter: &[u8; 32],
    mutation: &'a AuthorityMutation,
) -> ProofContext<'a> {
    ProofContext {
        domain: "wholepact:writer-channel-request:v2",
        protocol_version: PROTOCOL_VERSION,
        session_id: scope.0,
        disclosure: scope.1,
        writer_epoch: scope.2,
        channel_binding: hex::encode(Sha256::digest(exporter)),
        mutation,
    }
}
pub(crate) fn proof(
    key: &[u8; 32],
    scope: (&str, &WitnessDisclosureDescriptor, u64),
    exporter: &[u8; 32],
    mutation: &AuthorityMutation,
) -> Result<protocol::WriterSessionProof> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, &encode(&context(scope, exporter, mutation))?);
    Ok(protocol::WriterSessionProof {
        session_id: scope.0.into(),
        tag: hex::encode(tag.as_ref()),
    })
}
pub(crate) fn verify(
    key: &[u8; 32],
    receipt: &WriterSessionReceipt,
    exporter: &[u8; 32],
    mutation: &AuthorityMutation,
    proof: &protocol::WriterSessionProof,
) -> Result<()> {
    hash(&proof.session_id)?;
    hash(&proof.tag)?;
    if proof.session_id != receipt.session_id || session_id(key) != receipt.session_id {
        return Err(AuthorityError::Authentication);
    }
    let tag = hex::decode(&proof.tag).map_err(|_| AuthorityError::Authentication)?;
    let scope = (
        receipt.session_id.as_str(),
        &receipt.disclosure,
        receipt.writer_epoch,
    );
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::verify(&key, &encode(&context(scope, exporter, mutation))?, &tag)
        .map_err(|_| AuthorityError::Authentication)
}
