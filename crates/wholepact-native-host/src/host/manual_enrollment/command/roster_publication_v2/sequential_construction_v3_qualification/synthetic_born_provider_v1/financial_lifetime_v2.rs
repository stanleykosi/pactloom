//! A separately versioned, initially bounded financial qualification fixture.
//! Saved wall expiry and monotonic cutoff are never renewed by reopening.
use super::*;
const LIMIT_MS: u64 = 1_800_000;
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FinancialProviderLifetimeV2 {
    issued_at_ms: u64,
    expires_at_ms: u64,
    issued_monotonic_ns: u64,
    cutoff_monotonic_ns: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedFinancialProviderV2 {
    version: u32,
    endpoint: String,
    material: Vec<u8>,
    lifetime: FinancialProviderLifetimeV2,
}
fn parse_saved_financial_v2(
    bytes: &[u8],
) -> io::Result<(SavedFinancialProviderV2, std::net::SocketAddr)> {
    if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
        return Err(io::Error::other("fixture limit"));
    }
    let saved: SavedFinancialProviderV2 =
        serde_json::from_slice(bytes).map_err(|_| io::Error::other("fixture encoding"))?;
    let address: std::net::SocketAddr = saved
        .endpoint
        .strip_prefix("https://")
        .ok_or_else(|| io::Error::other("fixture endpoint"))?
        .parse()
        .map_err(|_| io::Error::other("fixture endpoint"))?;
    if saved.version != 2 || !address.ip().is_loopback() || address.port() == 0 {
        return Err(io::Error::other("fixture profile or endpoint"));
    }
    Ok((saved, address))
}
fn monotonic_ns() -> io::Result<u64> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::zeroed();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let value = unsafe { value.assume_init() };
    let seconds = u64::try_from(value.tv_sec).map_err(|_| io::Error::other("fixture clock"))?;
    let nanos = u64::try_from(value.tv_nsec).map_err(|_| io::Error::other("fixture clock"))?;
    if nanos >= 1_000_000_000 {
        return Err(io::Error::other("fixture clock"));
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(nanos))
        .ok_or_else(|| io::Error::other("fixture clock"))
}
fn original_deadline(
    observed: Instant,
    inherited: Instant,
    remaining: Duration,
) -> io::Result<Instant> {
    let deadline = inherited.min(
        observed
            .checked_add(remaining)
            .ok_or_else(|| io::Error::other("fixture bound"))?,
    );
    if deadline <= observed {
        return Err(io::Error::other("expired original fixture cutoff"));
    }
    Ok(deadline)
}
impl FinancialProviderLifetimeV2 {
    fn remaining(&self, wall_ms: u64, monotonic_ns: u64) -> io::Result<Duration> {
        let invalid = || io::Error::other("expired or invalid financial fixture lifetime");
        let wall_span = self
            .expires_at_ms
            .checked_sub(self.issued_at_ms)
            .ok_or_else(invalid)?;
        let mono_span = self
            .cutoff_monotonic_ns
            .checked_sub(self.issued_monotonic_ns)
            .ok_or_else(invalid)?;
        if wall_span == 0
            || wall_span > LIMIT_MS
            || mono_span == 0
            || mono_span > LIMIT_MS * 1_000_000
            || wall_ms < self.issued_at_ms
            || monotonic_ns < self.issued_monotonic_ns
        {
            return Err(invalid());
        }
        let wall = self
            .expires_at_ms
            .checked_sub(wall_ms)
            .filter(|v| *v > 0)
            .ok_or_else(invalid)?;
        let mono = self
            .cutoff_monotonic_ns
            .checked_sub(monotonic_ns)
            .filter(|v| *v > 0)
            .ok_or_else(invalid)?;
        // A backwards wall step cannot extend the original monotonic lifetime.
        Ok(Duration::from_millis(wall).min(Duration::from_nanos(mono)))
    }
}
impl SyntheticBornProviderV1 {
    pub(in super::super) async fn start_financial_v2(
        material: SyntheticBornReceiverBlocksV1,
        tls: ServerConfig,
        original_cutoff: Instant,
    ) -> io::Result<Self> {
        let observed = Instant::now();
        let issued_monotonic_ns = monotonic_ns()?;
        let issued_at_ms = fixture_now_ms()?;
        let remaining = original_cutoff.saturating_duration_since(observed);
        if remaining.is_zero() || remaining > Duration::from_millis(LIMIT_MS) {
            return Err(io::Error::other("invalid financial fixture lifetime"));
        }
        let lifetime = FinancialProviderLifetimeV2 {
            issued_at_ms,
            expires_at_ms: issued_at_ms
                .checked_add(
                    u64::try_from(remaining.as_millis())
                        .map_err(|_| io::Error::other("fixture bound"))?,
                )
                .ok_or_else(|| io::Error::other("fixture bound"))?,
            issued_monotonic_ns,
            cutoff_monotonic_ns: issued_monotonic_ns
                .checked_add(
                    u64::try_from(remaining.as_nanos())
                        .map_err(|_| io::Error::other("fixture bound"))?,
                )
                .ok_or_else(|| io::Error::other("fixture bound"))?,
        };
        lifetime.remaining(fixture_now_ms()?, monotonic_ns()?)?;
        Self::start_at(
            material,
            tls,
            original_cutoff,
            "127.0.0.1:0",
            Some(lifetime.expires_at_ms),
            Some(lifetime),
        )
        .await
    }
    pub(in super::super) fn preserve_financial_original_v2(&self) -> io::Result<Vec<u8>> {
        let lifetime = self
            .state
            .financial_lifetime
            .as_ref()
            .ok_or_else(|| io::Error::other("financial fixture profile"))?;
        lifetime.remaining(fixture_now_ms()?, monotonic_ns()?)?;
        if Instant::now() >= self.state.deadline
            || lifetime.expires_at_ms != self.state.expires_at_ms
        {
            return Err(io::Error::other("expired financial fixture"));
        }
        let bytes = serde_json::to_vec(&SavedFinancialProviderV2 {
            version: 2,
            endpoint: self.endpoint.clone(),
            material: self
                .state
                .material
                .preserve_public_original_v1()
                .map_err(|_| io::Error::other("fixture material"))?,
            lifetime: lifetime.clone(),
        })
        .map_err(|_| io::Error::other("fixture encoding"))?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err(io::Error::other("fixture limit"));
        }
        Ok(bytes)
    }
    pub(in super::super) async fn reopen_financial_original_v2(
        bytes: &[u8],
        tls: ServerConfig,
        original_cutoff: Instant,
    ) -> io::Result<Self> {
        let (saved, address) = parse_saved_financial_v2(bytes)?;
        let observed = Instant::now();
        let remaining = saved
            .lifetime
            .remaining(fixture_now_ms()?, monotonic_ns()?)?;
        let deadline = original_deadline(observed, original_cutoff, remaining)?;
        let material = SyntheticBornReceiverBlocksV1::reopen_public_original_v1(&saved.material)
            .map_err(|_| io::Error::other("fixture material"))?;
        Self::start_at(
            material,
            tls,
            deadline,
            &address.to_string(),
            Some(saved.lifetime.expires_at_ms),
            Some(saved.lifetime),
        )
        .await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn financial_fixture_original_lifetime_is_not_renewed() {
        let lifetime = FinancialProviderLifetimeV2 {
            issued_at_ms: 10_000,
            expires_at_ms: 1_810_000,
            issued_monotonic_ns: 1_000_000,
            cutoff_monotonic_ns: 1_800_001_000_000,
        };
        assert_eq!(
            lifetime.remaining(10_000, 1_000_000).unwrap(),
            Duration::from_secs(1800)
        );
        for (wall_span, mono_span) in [
            (0, 1_800_000_000_000),
            (1_800_000, 0),
            (1_800_000, 1_800_000_000_001),
        ] {
            let mut invalid = lifetime.clone();
            invalid.expires_at_ms = invalid.issued_at_ms + wall_span;
            invalid.cutoff_monotonic_ns = invalid.issued_monotonic_ns + mono_span;
            assert!(invalid.remaining(10_000, 1_000_000).is_err());
        }
        assert_eq!(
            lifetime.remaining(910_000, 900_001_000_000).unwrap(),
            Duration::from_secs(900)
        );
        // Backward wall time inside the valid wall interval never adds lifetime.
        assert_eq!(
            lifetime.remaining(20_000, 900_001_000_000).unwrap(),
            Duration::from_secs(900)
        );
        assert!(lifetime.remaining(9_999, 1_000_000).is_err());
        assert!(lifetime.remaining(10_000, 999_999).is_err());
        assert!(lifetime.remaining(1_810_000, 1_000_000).is_err());
        assert!(lifetime.remaining(10_000, 1_800_001_000_000).is_err());
        let mut invalid = lifetime.clone();
        invalid.expires_at_ms += 1;
        assert!(invalid.remaining(10_000, 1_000_000).is_err());
        let observed = Instant::now();
        assert_eq!(
            original_deadline(
                observed,
                observed + Duration::from_secs(10),
                Duration::from_secs(900)
            )
            .unwrap(),
            observed + Duration::from_secs(10)
        );
        assert_eq!(
            original_deadline(
                observed,
                observed + Duration::from_secs(900),
                Duration::from_secs(10)
            )
            .unwrap(),
            observed + Duration::from_secs(10)
        );
        assert!(original_deadline(observed, observed, Duration::from_secs(900)).is_err());
        let encoded = serde_json::to_value(&lifetime).unwrap();
        assert_eq!(encoded["expires_at_ms"], 1_810_000);
        let mut unknown = encoded;
        unknown["renew"] = true.into();
        assert!(serde_json::from_value::<FinancialProviderLifetimeV2>(unknown).is_err());
    }
    #[test]
    fn financial_fixture_saved_profiles_are_not_interchangeable() {
        let v1 = PreservedPublicProviderV1 {
            version: 1,
            endpoint: "https://127.0.0.1:1234".into(),
            material: vec![1],
            expires_at_ms: 1_810_000,
        };
        let v2 = SavedFinancialProviderV2 {
            version: 2,
            endpoint: v1.endpoint.clone(),
            material: vec![1],
            lifetime: FinancialProviderLifetimeV2 {
                issued_at_ms: 10_000,
                expires_at_ms: 1_810_000,
                issued_monotonic_ns: 1_000_000,
                cutoff_monotonic_ns: 1_800_001_000_000,
            },
        };
        let bytes1 = serde_json::to_vec(&v1).unwrap();
        let bytes2 = serde_json::to_vec(&v2).unwrap();
        assert!(parse_saved_public_v1(&bytes1).is_ok());
        assert!(parse_saved_financial_v2(&bytes2).is_ok());
        assert!(parse_saved_public_v1(&bytes2).is_err());
        assert!(parse_saved_financial_v2(&bytes1).is_err());
        for (bytes, financial) in [(&bytes1, false), (&bytes2, true)] {
            for version in [0, 1, 2, 3] {
                if version == (if financial { 2 } else { 1 }) {
                    continue;
                }
                let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
                value["version"] = version.into();
                let wrong = serde_json::to_vec(&value).unwrap();
                if financial {
                    assert!(parse_saved_financial_v2(&wrong).is_err());
                } else {
                    assert!(parse_saved_public_v1(&wrong).is_err());
                }
            }
        }
        let (roundtrip, _) = parse_saved_financial_v2(&bytes2).unwrap();
        assert_eq!(roundtrip.lifetime.expires_at_ms, v2.lifetime.expires_at_ms);
        assert_eq!(
            roundtrip.lifetime.cutoff_monotonic_ns,
            v2.lifetime.cutoff_monotonic_ns
        );
    }
}
