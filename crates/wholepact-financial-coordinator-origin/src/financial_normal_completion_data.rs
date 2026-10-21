//! Bounded saved-result observations. These ordinary values are never close authority.
use crate::{rejected,Result,SignerReturnCompletedV1,signer_continue_state::hash};
use serde::{Serialize,Deserialize};
use sha2::{Digest,Sha256};
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialSavedSummaryV1 {
 pub checkpoint_id:String,pub transaction_digest:String,pub transaction_id:String,pub operation_id:String,pub original_valid_until_ms:u64,
}
impl FinancialSavedSummaryV1 {pub fn validate(&self)->Result<()> {
 if self.checkpoint_id.is_empty()||self.checkpoint_id.len()>256||self.operation_id.is_empty()||self.operation_id.len()>128||!hash(&self.transaction_digest)||!hash(&self.transaction_id)||self.original_valid_until_ms==0{return Err(rejected("normal saved summary shape"));}Ok(())
}}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialNormalCompletionNoticeV1 {
 pub summary:FinancialSavedSummaryV1,pub returned:[SignerReturnCompletedV1;2],pub pair_presentation_digest:String,pub notice_digest:String,
}
impl FinancialNormalCompletionNoticeV1 {
 pub(crate) fn digest(&self)->Result<String>{self.summary.validate()?;for r in &self.returned{r.validate()?;}if !hash(&self.pair_presentation_digest){return Err(rejected("normal Pair digest"));}let mut h=Sha256::new();h.update(b"wholepact:normal-completion:v1\0");h.update(serde_json::to_vec(&(&self.summary,&self.returned,&self.pair_presentation_digest)).map_err(|_|rejected("normal notice encoding"))?);Ok(hex::encode(h.finalize()))}
 pub fn validate(&self)->Result<()>{if !hash(&self.notice_digest)||self.digest()?!=self.notice_digest{return Err(rejected("normal completion commitment changed"));}Ok(())}
}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinancialNormalCloseContextV1 {
 pub coordinator:String,pub session:String,pub challenge:String,pub notice:FinancialNormalCompletionNoticeV1,pub cleanup_ceiling_ms:u64,
}
impl FinancialNormalCloseContextV1 {pub(crate) fn validate(&self)->Result<()>{self.notice.validate()?;if ![&self.coordinator,&self.session,&self.challenge].iter().all(|s|hash(s))||self.cleanup_ceiling_ms==0||self.cleanup_ceiling_ms>1_805_000{return Err(rejected("normal close original context"));}Ok(())}}

#[cfg(test)]mod tests {
 use super::*;
 fn notice()->FinancialNormalCompletionNoticeV1{let h="ab".repeat(32);let r=SignerReturnCompletedV1{return_presentation_digest:h.clone(),preview_digest:h.clone(),result_digest:h.clone(),outbox_digest:h.clone()};let mut n=FinancialNormalCompletionNoticeV1{summary:FinancialSavedSummaryV1{checkpoint_id:"checkpoint-1".into(),transaction_digest:h.clone(),transaction_id:h.clone(),operation_id:"original-operation".into(),original_valid_until_ms:1234},returned:[r.clone(),r],pair_presentation_digest:h,notice_digest:String::new()};n.notice_digest=n.digest().unwrap();n}
 #[test]fn notice_binds_both_actual_results_and_saved_summary(){let n=notice();n.validate().unwrap();let mut changed=n.clone();changed.returned[1].result_digest="cd".repeat(32);assert!(changed.validate().is_err());let mut changed=n.clone();changed.summary.checkpoint_id.push('x');assert!(changed.validate().is_err());let mut changed=n;changed.pair_presentation_digest="cd".repeat(32);assert!(changed.validate().is_err());}
 #[test]fn normal_context_rejects_new_cleanup_or_unknown_fields(){let h="ab".repeat(32);let mut c=FinancialNormalCloseContextV1{coordinator:h.clone(),session:h.clone(),challenge:h,notice:notice(),cleanup_ceiling_ms:1_805_001};assert!(c.validate().is_err());c.cleanup_ceiling_ms=5_000;c.validate().unwrap();let json=serde_json::to_string(&c).unwrap().replacen('{',"{\"permit\":true,",1);assert!(serde_json::from_str::<FinancialNormalCloseContextV1>(&json).is_err());}
}
