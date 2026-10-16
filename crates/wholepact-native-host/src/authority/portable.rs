//! Separate exact native transaction-disclosure approval; never spending consent.
use super::*;
use wholepact_protocol::authorization::retention::transaction::portable::{
    TransactionDisclosureConsent, TransactionDisclosureScope,
};
pub(crate) struct PortableConsent<'a> {
    authority: &'a Authority,
    principal: String,
    approved: Mutex<Option<(String, Held)>>,
}
impl Authority {
    pub(crate) fn portable_consent(&self, principal: &str) -> Result<PortableConsent<'_>> {
        self.principal(principal)?;
        Ok(PortableConsent {
            authority: self,
            principal: principal.into(),
            approved: Mutex::new(None),
        })
    }
}
impl TransactionDisclosureConsent for PortableConsent<'_> {
    fn permits(&self, scope: &TransactionDisclosureScope<'_>) -> bool {
        (|| -> Result<()> {
            self.authority.principal(&self.principal)?;
            let encoded = serde_json::to_vec(&(scope.retention, scope.transaction_digest, scope.transaction_id, scope.recipient_id, scope.purpose))?;
            let digest = hex::encode(Sha256::digest(&encoded));
            let mut approved = self.approved.lock().map_err(|_| Error::Permission)?;
            if let Some((original, held)) = approved.as_ref() {
                if original != &digest { return Err(Error::Permission); }
                return held.check();
            }
            let held = self.authority.fence.acquire(now()?.saturating_add(900))?;
            self.authority.terminal.confirm(&format!("Separate finalized transaction disclosure consent. Exact transaction ID: {}. SHA256: {}. Recipient label: {}. Purpose: {}. This discloses usable finalized transaction bytes and can allow the recipient to broadcast them. It exposes transaction linkage and cannot recall copies. No private PCZT, viewing keys or coordinator journals are included. Pinned recipient key and encrypted file destination require the following separate transport approval. Signing, retention and receipt approval do not authorize this disclosure.", scope.transaction_id, scope.transaction_digest, scope.recipient_id, scope.purpose))?;
            held.check()?;
            *approved = Some((digest, held));
            Ok(())
        })().is_ok()
    }
}
