//! Scoped, never-funded owners for fabricated-chain component fixtures only.
//! No secret serialization, global cache, deterministic seed, or persistent wallet.
#[cfg(feature = "synthetic-qualification")]
use super::{SelectionContext, WalletContribution, WalletError};
use orchard::keys::SpendingKey;
use rand::{Rng, rand_core::UnwrapErr, rngs::SysRng};

/// Two fresh owners shared by a fixture's scanner and synthetic authorizer.
/// This type is available outside this crate only with `synthetic-qualification`.
/// It grants no product authority and must never be used for funded accounts.
pub struct SyntheticContributionFixture {
    owners: [SpendingKey; 2],
}

impl SyntheticContributionFixture {
    /// Draw fresh test-only spending material from the operating system.
    /// Entropy failure aborts the fixture; there is no deterministic fallback.
    pub fn generate() -> Self {
        let first = random_spending_key();
        let second = loop {
            let candidate = random_spending_key();
            if candidate.to_bytes() != first.to_bytes() {
                break candidate;
            }
        };
        Self {
            owners: [first, second],
        }
    }

    /// Borrow the same owner used to encrypt and scan this fixture's notes.
    pub fn owner_spending_key(&self, index: usize) -> &SpendingKey {
        &self.owners[index]
    }

    /// Scan both owners' fabricated notes through the maintained SQLite backend.
    #[cfg(feature = "synthetic-qualification")]
    pub fn scanned_contributions(
        &self,
    ) -> Result<(Vec<WalletContribution>, SelectionContext), WalletError> {
        super::qualification::scanned_contributions(self)
    }

    /// Fabricated ciphertext matching this context, never network inclusion evidence.
    #[cfg(feature = "synthetic-qualification")]
    pub fn compact_block(&self) -> zcash_client_backend::proto::compact_formats::CompactBlock {
        super::qualification::synthetic_wallet_with_fixture(self)
            .4
            .0
            .remove(0)
    }
}

fn random_spending_key() -> SpendingKey {
    loop {
        let mut bytes = [0; 32];
        UnwrapErr(SysRng).fill_bytes(&mut bytes);
        if let Some(key) = Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes)) {
            return key;
        }
    }
}

#[test]
fn generated_owner_contexts_are_distinct() {
    let first = SyntheticContributionFixture::generate();
    let second = SyntheticContributionFixture::generate();
    // Boolean assertions deliberately avoid rendering private bytes on failure.
    assert!(first.owner_spending_key(0).to_bytes() != first.owner_spending_key(1).to_bytes());
    for a in &first.owners {
        for b in &second.owners {
            assert!(a.to_bytes() != b.to_bytes());
        }
    }
}

#[cfg(feature = "synthetic-qualification")]
#[test]
fn scanned_notes_belong_to_the_retained_owner_context() {
    use orchard::keys::FullViewingKey;
    let fixture = SyntheticContributionFixture::generate();
    let (wallets, _) = fixture.scanned_contributions().unwrap();
    for (index, wallet) in wallets.into_iter().enumerate() {
        let contribution = wallet.into_contribution();
        let expected = FullViewingKey::from(fixture.owner_spending_key(index));
        assert!(contribution.fvk.to_bytes() == expected.to_bytes());
    }
}
