//! Bounded inert handoff metadata, never financial permission or socket custody.
use crate::{rejected, Result, FinancialActorContextV1, SignerReturnRequestDataV1};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerFinancialResultSelectorV1 {
    pub actor: FinancialActorContextV1,
    pub source_identity_digest: String,
    pub sign_presentation_digest: String,
    pub signer_socket: String,
    pub request_json: String,
}
impl SignerFinancialResultSelectorV1 {
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        if !crate::signer_continue_state::hash(&self.source_identity_digest)
            || !crate::signer_continue_state::hash(&self.sign_presentation_digest)
            || self.signer_socket.is_empty() || self.signer_socket.len() > 4096
            || !std::path::Path::new(&self.signer_socket).is_absolute()
            || self.signer_socket.chars().any(char::is_control)
        { return Err(rejected("financial result selector metadata")); }
        SignerReturnRequestDataV1::parse_json(&self.request_json)?;
        Ok(())
    }
    /// The caller can explicitly save this public metadata. It cannot authorize
    /// a Return, select a different original peer, or expose signature bytes.
    pub fn selector_json(&self) -> Result<String> {
        self.validate()?;
        #[derive(Serialize)]
        struct Selector<'a> { version:u16, signer_socket:&'a str, request:SignerReturnRequestDataV1 }
        let encoded=serde_json::to_string(&Selector {version:1, signer_socket:&self.signer_socket,
            request:SignerReturnRequestDataV1::parse_json(&self.request_json)?})
            .map_err(|_|rejected("financial selector encoding"))?;
        if encoded.len()>16384 {return Err(rejected("financial selector envelope bound"));}
        Ok(encoded)
    }
}
