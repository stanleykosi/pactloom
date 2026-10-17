//! Finite V3 continuation facade. Inputs are inert correlation only; every
//! returned opaque value owns its actual predecessor and native controller.
use super::*;
use crate::native_ui::born_manual_roster_v2::born_manual_roster::continuation_fixture::construction_fixture::{
    CommonContextReadFixtureV3, CompletionFixtureV3, ConsumedNamedFixtureV3,
    DormantConstructionFixtureV3, ExpectedCommonContextReadV3, ExpectedCompletionOperationsV3,
    ExportedFullPlanFixtureV3, sign_and_export_full_plan_v3,
};

pub struct ExpectedCommonContextReadV3Input {
    pub plan: wholepact_core::manual_roster_construction_v3::ManualRosterConstructionPlanV3,
    pub durable_receipt_digest: String,
    pub witness_plan_approval_digest: String,
    pub read_operation: String,
    pub handoff_operation: String,
}
pub struct ExpectedCompletionOperationsV3Input {
    pub reentry_operation: String,
    pub construction_operation: String,
}
impl EphemeralAcknowledgedBornV1 {
    pub fn sign_and_export_original_full_plan_v3(
        self,
        actual_host_plan_file: &Path,
    ) -> Result<EphemeralExportedFullPlanV3> {
        let exports = self.original.temporary.path().join(format!(
            "full-plan-v3-{}",
            hex::encode(crate::vault::random::<16>()?),
        ));
        private_export_directory(&exports)?;
        let ui = NativeRuntime::entered_born_roster_for_qualification(&self.original.root)?;
        Ok(EphemeralExportedFullPlanV3 {
            inner: sign_and_export_full_plan_v3(
                ui,
                self.original,
                actual_host_plan_file,
                &exports,
            )?,
        })
    }
    /// A real exact continued publication supplies the maintained source. A
    /// blank account open, request DTO, old receipt or fixture flag cannot.
    pub fn open_common_context_read_v3(
        self,
        actual_publication: HostManualRosterPublicationRequestV2,
        expected: ExpectedCommonContextReadV3Input,
    ) -> Result<EphemeralCommonContextReadV3> {
        let ui = NativeRuntime::entered_born_roster_for_qualification(&self.original.root)?;
        let publication = ContinuedPublicationFixture::open(ui, self.original, actual_publication)?;
        Ok(EphemeralCommonContextReadV3 {
            inner: CommonContextReadFixtureV3::new(
                publication,
                ExpectedCommonContextReadV3 {
                    plan: expected.plan,
                    durable_receipt_digest: expected.durable_receipt_digest,
                    witness_plan_approval_digest: expected.witness_plan_approval_digest,
                    read_operation: expected.read_operation,
                    handoff_operation: expected.handoff_operation,
                },
            )?,
        })
    }
}
pub struct EphemeralExportedFullPlanV3 {
    inner: ExportedFullPlanFixtureV3,
}
impl EphemeralExportedFullPlanV3 {
    pub fn exported_file(&self) -> &Path {
        &self.inner.exported_file
    }
    pub fn close_for_witness_review(self) -> EphemeralAcknowledgedBornV1 {
        EphemeralAcknowledgedBornV1 {
            original: self.inner.close(),
        }
    }
}
pub struct EphemeralCommonContextReadV3 {
    inner: CommonContextReadFixtureV3,
}
impl EphemeralCommonContextReadV3 {
    pub fn endpoint(&self) -> Result<PathBuf> {
        self.inner.endpoint()
    }
    pub fn provider(&self) -> Result<InstalledSignerProvider> {
        current_provider()
    }
    pub fn deadline(&self) -> Result<Instant> {
        self.inner.deadline()
    }
    pub fn poll_publication_read_and_handoff(&mut self) -> Result<bool> {
        self.inner.poll()
    }
    pub fn park_original_completion(self) -> Result<EphemeralDormantCommonContextV3> {
        Ok(EphemeralDormantCommonContextV3 {
            inner: self.inner.into_dormant()?,
        })
    }
}
pub struct EphemeralDormantCommonContextV3 {
    inner: DormantConstructionFixtureV3,
}
impl EphemeralDormantCommonContextV3 {
    pub fn open_original_completion(
        self,
        expected: ExpectedCompletionOperationsV3Input,
        client_scope: wholepact_authority::native_witness_owner::EphemeralConstructionClientScopeV1,
    ) -> Result<EphemeralCommonContextCompletionV3> {
        Ok(EphemeralCommonContextCompletionV3 {
            inner: self.inner.reopen(
                ExpectedCompletionOperationsV3 {
                    reentry_operation: expected.reentry_operation,
                    construction_operation: expected.construction_operation,
                },
                client_scope,
            )?,
        })
    }
}
pub struct EphemeralCommonContextCompletionV3 {
    inner: CompletionFixtureV3,
}
impl EphemeralCommonContextCompletionV3 {
    pub fn endpoint(&self) -> Result<PathBuf> {
        self.inner.endpoint()
    }
    pub fn provider(&self) -> Result<InstalledSignerProvider> {
        current_provider()
    }
    pub fn deadline(&self) -> Result<Instant> {
        self.inner.deadline()
    }
    pub fn poll_exact_completion_and_park(&mut self) -> Result<bool> {
        self.inner.poll()
    }
    pub fn take_consumed_named_original(self) -> Result<EphemeralConsumedNamedV3> {
        Ok(EphemeralConsumedNamedV3 {
            inner: self.inner.into_named()?,
        })
    }
}
/// No public constructor, native token accessor or alternate Host adoption.
/// The next finite named wrapper alone consumes this actual controller.
pub struct EphemeralConsumedNamedV3 {
    pub(in crate::native_ui) inner: ConsumedNamedFixtureV3,
}
