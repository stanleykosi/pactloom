//! Private restriction-only sampling for retained SQL reads. Legacy is inert;
//! coordinated variants borrow genuine closed nominal guards, never callbacks.
use crate::Result;
#[derive(Clone, Copy)]
pub(crate) enum ReadGuardV1<'a> {
    Legacy(std::marker::PhantomData<&'a ()>),
    #[cfg(all(target_os = "linux", feature = "native-witness-owner"))]
    Coordinated {
        guard: crate::native_witness_owner::financial_setup_guard_v1::FinancialSetupGuardV1<'a>,
        original_deadline: Option<std::time::Instant>,
    },
}
impl<'a> ReadGuardV1<'a> {
    pub(crate) fn legacy() -> Self {
        Self::Legacy(std::marker::PhantomData)
    }
    #[cfg(all(target_os = "linux", feature = "native-witness-owner"))]
    pub(crate) fn coordinated(
        guard: crate::native_witness_owner::financial_setup_guard_v1::FinancialSetupGuardV1<'a>,
    ) -> Self {
        Self::Coordinated {
            guard,
            original_deadline: None,
        }
    }
    /// Additional immutable accepted-connection ceiling, never a new lease.
    #[cfg(all(target_os = "linux", feature = "native-witness-owner"))]
    pub(crate) fn coordinated_until(
        guard: crate::native_witness_owner::financial_setup_guard_v1::FinancialSetupGuardV1<'a>,
        original_deadline: std::time::Instant,
    ) -> Self {
        Self::Coordinated {
            guard,
            original_deadline: Some(original_deadline),
        }
    }
    pub(crate) fn check(self) -> Result<()> {
        match self {
            Self::Legacy(_) => Ok(()),
            #[cfg(all(target_os = "linux", feature = "native-witness-owner"))]
            Self::Coordinated {
                guard,
                original_deadline,
            } => {
                check_deadline_at(original_deadline, std::time::Instant::now())?;
                guard.check()?;
                check_deadline_at(original_deadline, std::time::Instant::now())
            }
        }
    }
}
fn check_deadline_at(
    original_deadline: Option<std::time::Instant>,
    now: std::time::Instant,
) -> Result<()> {
    if original_deadline.is_some_and(|deadline| now >= deadline) {
        return Err(crate::AuthorityError::Permission);
    }
    Ok(())
}
// Preserve the original SQL error when its admitted operation fails. A current
// read may finish after its pre-sample; no later read starts without resampling.
macro_rules! guarded_read {
    ($guard:expr,$read:expr) => {{
        $guard.check()?;
        let result = $read;
        if result.is_ok() {
            $guard.check()?;
        }
        result
    }};
}
pub(crate) use guarded_read;
pub(crate) fn collect_guarded<T, I, C>(mut rows: I, guard: ReadGuardV1<'_>) -> Result<C>
where
    I: Iterator<Item = rusqlite::Result<T>>,
    C: FromIterator<T>,
{
    let mut values = Vec::new();
    loop {
        guard.check()?;
        match rows.next() {
            Some(Ok(value)) => {
                guard.check()?;
                values.push(value);
            }
            Some(Err(error)) => return Err(error.into()),
            None => {
                guard.check()?;
                return Ok(values.into_iter().collect());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guarded_legacy_collection_preserves_values_order_and_duplicates() {
        let rows = [Ok(3u8), Ok(1), Ok(3)];
        let actual: Vec<u8> = collect_guarded(rows.into_iter(), ReadGuardV1::legacy()).unwrap();
        assert_eq!(actual, [3, 1, 3]);
    }
    #[test]
    fn guarded_legacy_collection_preserves_empty_and_set_collection() {
        let empty: Vec<u8> = collect_guarded(std::iter::empty(), ReadGuardV1::legacy()).unwrap();
        assert!(empty.is_empty());
        let actual: std::collections::BTreeSet<u8> =
            collect_guarded([Ok(3u8), Ok(1), Ok(3)].into_iter(), ReadGuardV1::legacy()).unwrap();
        assert_eq!(actual.into_iter().collect::<Vec<_>>(), [1, 3]);
    }
    #[test]
    fn guarded_legacy_collection_stops_at_original_iterator_error() {
        let visited = std::cell::Cell::new(0);
        let rows = [Ok(1u8), Err(rusqlite::Error::InvalidQuery), Ok(2)]
            .into_iter()
            .inspect(|_| visited.set(visited.get() + 1));
        let actual: Result<Vec<u8>> = collect_guarded(rows, ReadGuardV1::legacy());
        assert!(matches!(actual, Err(crate::AuthorityError::Storage)));
        assert_eq!(visited.get(), 2);
    }
    #[test]
    fn guarded_read_retains_original_optional_deadline_without_renewal() {
        let original = std::time::Instant::now();
        assert!(check_deadline_at(None, original).is_ok());
        assert!(check_deadline_at(
            Some(original),
            original - std::time::Duration::from_nanos(1)
        )
        .is_ok());
        assert!(matches!(
            check_deadline_at(Some(original), original),
            Err(crate::AuthorityError::Permission)
        ));
        assert!(matches!(
            check_deadline_at(
                Some(original),
                original + std::time::Duration::from_nanos(1)
            ),
            Err(crate::AuthorityError::Permission)
        ));
    }
    // Macro-only probes are local restrictions, never nominal action objects.
    struct CheckProbe<'a> {
        checks: &'a std::cell::Cell<u8>,
        deny_on: u8,
    }
    impl CheckProbe<'_> {
        fn check(&self) -> Result<()> {
            let count = self.checks.get() + 1;
            self.checks.set(count);
            if count == self.deny_on {
                Err(crate::AuthorityError::Permission)
            } else {
                Ok(())
            }
        }
    }
    struct OwnedProbe<'a>(&'a std::cell::Cell<u8>);
    impl Drop for OwnedProbe<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    #[test]
    fn guarded_read_pre_denial_never_evaluates_operation() {
        let checks = std::cell::Cell::new(0);
        let expressions = std::cell::Cell::new(0);
        let guard = CheckProbe {
            checks: &checks,
            deny_on: 1,
        };
        let actual = (|| -> Result<()> {
            guarded_read!(guard, {
                expressions.set(expressions.get() + 1);
                Ok::<(), crate::AuthorityError>(())
            })
        })();
        assert!(matches!(actual, Err(crate::AuthorityError::Permission)));
        assert_eq!(checks.get(), 1);
        assert_eq!(expressions.get(), 0);
    }
    #[test]
    fn guarded_read_post_denial_drops_owned_result_before_return() {
        let checks = std::cell::Cell::new(0);
        let drops = std::cell::Cell::new(0);
        let guard = CheckProbe {
            checks: &checks,
            deny_on: 2,
        };
        let actual = (|| -> Result<OwnedProbe<'_>> {
            guarded_read!(guard, Ok::<_, crate::AuthorityError>(OwnedProbe(&drops)))
        })();
        assert!(matches!(actual, Err(crate::AuthorityError::Permission)));
        assert_eq!(checks.get(), 2);
        assert_eq!(drops.get(), 1);
    }
    #[test]
    fn guarded_read_preserves_operation_error_without_post_masking() {
        let checks = std::cell::Cell::new(0);
        let guard = CheckProbe {
            checks: &checks,
            deny_on: 2,
        };
        let actual = (|| -> Result<()> {
            guarded_read!(guard, Err::<(), _>(crate::AuthorityError::StaleHead))
        })();
        assert!(matches!(actual, Err(crate::AuthorityError::StaleHead)));
        assert_eq!(checks.get(), 1);
    }
}
