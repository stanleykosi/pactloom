//! Closed additional restriction for the genuine fixed-role setup interval.
//! Setup and Arm remain distinct borrowed originals; neither converts to Final authority.
#[derive(Clone, Copy)]
pub(crate) enum FinancialSetupGuardV1<'a> {
    Legacy(std::marker::PhantomData<&'a ()>),
    #[cfg(feature = "coordinated-witness-financial-continuation")]
    Coordinated(&'a wholepact_financial_coordinator_origin::WitnessFinancialContinuationSetupV1),
    #[cfg(feature = "coordinated-witness-financial-continuation")]
    Arm(&'a wholepact_financial_coordinator_origin::WitnessFinancialContinuationArmV1),
    #[cfg(feature = "coordinated-witness-financial-continuation")]
    Final(&'a wholepact_financial_coordinator_origin::WitnessFinancialContinuationFinalV1),
}
impl<'a> FinancialSetupGuardV1<'a> {
    pub(crate) fn legacy() -> Self {
        Self::Legacy(std::marker::PhantomData)
    }
    pub(crate) fn check(self) -> crate::Result<()> {
        match self {
            Self::Legacy(_) => Ok(()),
            #[cfg(feature = "coordinated-witness-financial-continuation")]
            Self::Final(grant) => grant
                .check_current()
                .map_err(|_| crate::AuthorityError::Permission),
            #[cfg(feature = "coordinated-witness-financial-continuation")]
            Self::Arm(arm) => arm
                .check_current()
                .map_err(|_| crate::AuthorityError::Permission),
            #[cfg(feature = "coordinated-witness-financial-continuation")]
            Self::Coordinated(setup) => setup
                .check_current()
                .map_err(|_| crate::AuthorityError::Permission),
        }
    }
    pub(crate) fn read(
        self,
        path: &std::path::Path,
        maximum: usize,
    ) -> crate::Result<zeroize::Zeroizing<Vec<u8>>> {
        match self {
            Self::Legacy(_) => {
                wholepact_storage_security::witness_namespace_fs::read_existing_private_file(
                    path, maximum,
                )
                .map_err(Into::into)
            }
            #[cfg(feature = "coordinated-witness-financial-continuation")]
            Self::Final(_) => Err(crate::AuthorityError::Permission),
            #[cfg(feature = "coordinated-witness-financial-continuation")]
            Self::Coordinated(_) | Self::Arm(_) => {
                self.check()?;
                let check = || {
                    self.check().map_err(|_| {
                        wholepact_storage_security::StorageSecurityError::SourceChanged
                    })
                };
                let value = wholepact_storage_security::witness_namespace_fs::read_existing_private_file_restricted(path, maximum, Some(&check))?;
                self.check()?;
                Ok(value)
            }
        }
    }
}
