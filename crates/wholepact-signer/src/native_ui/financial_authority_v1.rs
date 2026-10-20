//! Fresh, purpose-separated financial decisions for an original source.
//! Historical delivery/read receipts cannot construct these owners. Every owner
//! is issued by this process's focused native review and ends on lock/drop.
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn hash(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(Error::InvalidData)
    }
}
fn unix_ms() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Locked)?
            .as_millis(),
    )
    .map_err(|_| Error::Locked)
}
/// Closed purposes: a read owner is never usable as a financial effect owner.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::native_ui) enum FinancialPurposeV1 {
    ReadOriginal,
    ContinueExact,
    AdmitExact,
    AcquireExact,
    ActivateExact,
    WalletExact,
    SignExact,
    ReturnExact,
}
impl FinancialPurposeV1 {
    fn label(self) -> &'static str {
        match self {
            Self::ReadOriginal => "read_original",
            Self::ContinueExact => "continue_exact",
            Self::AdmitExact => "admit_exact",
            Self::AcquireExact => "acquire_exact",
            Self::ActivateExact => "activate_exact",
            Self::WalletExact => "wallet_exact",
            Self::SignExact => "sign_exact",
            Self::ReturnExact => "return_exact",
        }
    }
}
/// Setup/review only. The source has already completed KDF, source validation,
/// and proof preparation; this value exposes no account or key-use API.
pub(in crate::native_ui) struct PreparedFinancialReviewV1 {
    native: NativeAuthority,
    source_identity: String,
    terms_digest: String,
    review_digest: String,
    purpose: FinancialPurposeV1,
    original_ceiling_ms: u64,
    original_deadline: Instant,
}
impl PreparedFinancialReviewV1 {
    pub(in crate::native_ui) fn enter(
        entry: crate::native_ui::runtime::PendingBirthEntry,
        source_identity: &str,
        terms_digest: &str,
        purpose: FinancialPurposeV1,
        original_ceiling_ms: u64,
        retained_original_deadline: Instant,
    ) -> Result<Self> {
        hash(source_identity)?;
        hash(terms_digest)?;
        let (_, parent) = entry.into_parts();
        let now = unix_ms()?;
        let remaining = original_ceiling_ms
            .checked_sub(now)
            .filter(|n| *n > 0)
            .ok_or(Error::Locked)?;
        let original_deadline = Instant::now()
            .checked_add(Duration::from_millis(remaining))
            .ok_or(Error::InvalidData)?
            .min(retained_original_deadline);
        if Instant::now() >= original_deadline {
            return Err(Error::Locked);
        }
        let review_deadline = (Instant::now() + Duration::from_secs(120)).min(original_deadline);
        let native = NativeAuthority::entered_retirement_window(review_deadline, parent)?;
        let review_digest = wholepact_core::proposal::canonical_digest(
            "wholepact:original-financial-native-review:v1",
            &(
                source_identity,
                terms_digest,
                purpose.label(),
                original_ceiling_ms,
                native.binding.entry_digest(),
            ),
        )
        .map_err(|_| Error::InvalidData)?;
        Ok(Self {
            native,
            source_identity: source_identity.into(),
            terms_digest: terms_digest.into(),
            review_digest,
            purpose,
            original_ceiling_ms,
            original_deadline,
        })
    }
    pub(in crate::native_ui) fn native(&self) -> &NativeAuthority {
        &self.native
    }
    pub(in crate::native_ui) fn digest(&self) -> &str {
        &self.review_digest
    }
    fn approve(
        self,
        decision: NativeDecision,
        expected: FinancialPurposeV1,
    ) -> Result<FinancialDecisionV1> {
        self.native.check_current()?;
        if self.purpose != expected
            || decision.binding() != &self.native.binding()
            || decision.reviewed_digest() != self.review_digest
            || decision.consumed_at() > Instant::now()
        {
            return Err(Error::ReviewMismatch);
        }
        let reviewed_at_ms = decision.consumed_at_unix_ms();
        let deadline =
            (decision.consumed_at() + Duration::from_secs(120)).min(self.original_deadline);
        let monotonic_ms = u64::try_from(
            deadline
                .saturating_duration_since(decision.consumed_at())
                .as_millis(),
        )
        .map_err(|_| Error::InvalidData)?;
        let expires_at_ms = reviewed_at_ms
            .checked_add(monotonic_ms.min(120_000))
            .ok_or(Error::InvalidData)?
            .min(self.original_ceiling_ms);
        let wall_now = unix_ms()?;
        if Instant::now() >= deadline
            || reviewed_at_ms >= expires_at_ms
            || wall_now < reviewed_at_ms
            || wall_now >= expires_at_ms
        {
            return Err(Error::Locked);
        }
        // Fresh purpose owner. The former review binding is not mutated and
        // cannot be replayed as a later action, old source, or writer session.
        let native = NativeAuthority {
            binding: NativeAuthorityBinding {
                instance: Arc::new(AtomicBool::new(true)),
                publication: Arc::new(std::sync::RwLock::new(())),
                expires_at: Some(deadline),
                retirement_parent: self.native.binding.retirement_parent.clone(),
                identity: hex::encode(crate::vault::random::<32>()?),
                construction_transport: Arc::new(std::sync::Mutex::new(None)),
            },
            principal: self.native.principal.clone(),
            measurement: self.native.measurement.clone(),
        };
        Ok(FinancialDecisionV1 {
            native,
            source_identity: self.source_identity,
            terms_digest: self.terms_digest,
            review_digest: self.review_digest,
            purpose: self.purpose,
            nonce: hex::encode(crate::vault::random::<32>()?),
            reviewed_at_ms,
            expires_at_ms,
            deadline,
        })
    }
    pub(in crate::native_ui) fn approve_continuation(
        self,
        decision: NativeDecision,
    ) -> Result<FinancialContinuationReviewV1> {
        Ok(FinancialContinuationReviewV1(
            self.approve(decision, FinancialPurposeV1::ContinueExact)?,
        ))
    }
    pub(in crate::native_ui) fn approve_admit(
        self,
        decision: NativeDecision,
    ) -> Result<FinancialAdmitActionV1> {
        Ok(FinancialAdmitActionV1(
            self.approve(decision, FinancialPurposeV1::AdmitExact)?,
        ))
    }
    pub(in crate::native_ui) fn approve_read(
        self,
        decision: NativeDecision,
    ) -> Result<FinancialReadLeaseV1> {
        Ok(FinancialReadLeaseV1(
            self.approve(decision, FinancialPurposeV1::ReadOriginal)?,
        ))
    }
    pub(in crate::native_ui) fn approve_acquire(
        self,
        decision: NativeDecision,
    ) -> Result<FinancialAcquireActionV1> {
        Ok(FinancialAcquireActionV1(
            self.approve(decision, FinancialPurposeV1::AcquireExact)?,
        ))
    }
    pub(in crate::native_ui) fn approve_activation(
        self,
        decision: NativeDecision,
    ) -> Result<FinancialActivationActionV1> {
        Ok(FinancialActivationActionV1(
            self.approve(decision, FinancialPurposeV1::ActivateExact)?,
        ))
    }
    pub(in crate::native_ui) fn approve_wallet(
        self,
        decision: NativeDecision,
    ) -> Result<FinancialWalletActionV1> {
        Ok(FinancialWalletActionV1(
            self.approve(decision, FinancialPurposeV1::WalletExact)?,
        ))
    }
    pub(in crate::native_ui) fn approve_sign(
        self,
        decision: NativeDecision,
    ) -> Result<FinancialSignActionV1> {
        Ok(FinancialSignActionV1(
            self.approve(decision, FinancialPurposeV1::SignExact)?,
        ))
    }
    pub(in crate::native_ui) fn approve_return(
        self,
        decision: NativeDecision,
    ) -> Result<FinancialReturnActionV1> {
        Ok(FinancialReturnActionV1(
            self.approve(decision, FinancialPurposeV1::ReturnExact)?,
        ))
    }
}
struct FinancialDecisionV1 {
    native: NativeAuthority,
    source_identity: String,
    terms_digest: String,
    review_digest: String,
    purpose: FinancialPurposeV1,
    nonce: String,
    reviewed_at_ms: u64,
    expires_at_ms: u64,
    deadline: Instant,
}
impl FinancialDecisionV1 {
    fn check(&self) -> Result<()> {
        self.native.check_current()?;
        let now = unix_ms()?;
        if Instant::now() >= self.deadline || now < self.reviewed_at_ms || now >= self.expires_at_ms
        {
            return Err(Error::Locked);
        }
        Ok(())
    }
    fn check_source(&self, source: &str) -> Result<()> {
        self.check()?;
        if self.source_identity != source {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}
macro_rules! financial_owner {
    ($name:ident) => {
        pub(crate) struct $name(FinancialDecisionV1);
        impl $name {
            pub(crate) fn check_current(&self) -> Result<()> {
                self.0.check()
            }
            pub(crate) fn check_source(&self, source: &str) -> Result<()> {
                self.0.check_source(source)
            }
            pub(crate) fn source_identity_digest(&self) -> &str {
                &self.0.source_identity
            }
            pub(crate) fn principal_id(&self) -> &str {
                self.0.native.principal_id()
            }
            pub(crate) fn measurement(&self) -> &str {
                self.0.native.measurement()
            }
            pub(crate) fn session_digest(&self) -> &str {
                self.0.native.binding.entry_digest()
            }
            pub(crate) fn permission_generation(&self) -> u64 {
                1
            }
            pub(crate) fn nonce(&self) -> &str {
                &self.0.nonce
            }
            pub(crate) fn reviewed_at_unix_ms(&self) -> u64 {
                self.0.reviewed_at_ms
            }
            pub(crate) fn expires_at_unix_ms(&self) -> u64 {
                self.0.expires_at_ms
            }
            pub(crate) fn terms_digest(&self) -> &str {
                &self.0.terms_digest
            }
            pub(crate) fn native_review_digest(&self) -> &str {
                &self.0.review_digest
            }
            pub(crate) fn publication_lease(&self) -> Result<NativePublicationLease<'_>> {
                self.0.native.binding.publication_lease()
            }
            pub(crate) fn binding(&self) -> NativeAuthorityBinding {
                self.0.native.binding()
            }
            pub(crate) fn revocation(&self) -> FinancialNativeRevocationV1 {
                FinancialNativeRevocationV1(self.0.native.binding())
            }
            pub(crate) fn invalidate(&self) {
                self.0.native.revoke_informational_now();
            }
        }
    };
}
financial_owner!(FinancialContinuationReviewV1);
financial_owner!(FinancialAdmitActionV1);
financial_owner!(FinancialReadLeaseV1);
financial_owner!(FinancialAcquireActionV1);
financial_owner!(FinancialActivationActionV1);
financial_owner!(FinancialSignActionV1);
financial_owner!(FinancialReturnActionV1);

/// Revocation only, never authority. The actual GUI retains this before moving
/// each freshly consumed purpose owner into an asynchronous effect.
pub(crate) struct FinancialNativeRevocationV1(NativeAuthorityBinding);
impl FinancialNativeRevocationV1 {
    pub(crate) fn invalidate(&self) {
        self.0
            .instance
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

financial_owner!(FinancialWalletActionV1);
