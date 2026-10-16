//! Status-only participant record composition. Private record content, account
//! identifiers, disclosure selection and retirement plans stay native-only.
use std::sync::Arc;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use wholepact_core::records::ObservationWindow;
use wholepact_engine::{
    participant_records::{
        ParticipantRecordAuthority, ParticipantRecordRuntime, ParticipantRecordStatus,
    },
    Access, ApiError, Engine,
};

/// An embedding supplies an existing protected store and authenticated local
/// account/record authority. This constructor never creates an enrollment grant.
/// The freshness policy is explicit local configuration, never an HTTP parameter.
pub struct ProtectedRecordsRuntime {
    engine: Engine,
    profile_id: String,
    authority: Arc<dyn ParticipantRecordAuthority>,
    maximum_observation_age_seconds: u16,
}
impl ProtectedRecordsRuntime {
    pub fn new(
        engine: Engine,
        profile_id: String,
        authority: Arc<dyn ParticipantRecordAuthority>,
        maximum_observation_age_seconds: u16,
    ) -> Result<Self, ApiError> {
        engine.protected_record_store_binding()?;
        if profile_id.is_empty()
            || profile_id.len() > 128
            || !profile_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
            || !(1..=300).contains(&maximum_observation_age_seconds)
        {
            return Err(ApiError::new("INVALID_REQUEST", "Protected record runtime needs an exact local profile and an observation freshness policy of 1 to 300 seconds"));
        }
        Ok(Self {
            engine,
            profile_id,
            authority,
            maximum_observation_age_seconds,
        })
    }
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
    pub fn status(&self, access: &Access) -> Result<ParticipantRecordStatus, ApiError> {
        let now = OffsetDateTime::now_utc()
            .replace_nanosecond(0)
            .map_err(|_| ApiError::new("INTERNAL_ERROR", "Local record clock is unavailable"))?;
        let oldest = now
            .checked_sub(time::Duration::seconds(
                self.maximum_observation_age_seconds.into(),
            ))
            .ok_or_else(|| {
                ApiError::new(
                    "INTERNAL_ERROR",
                    "Local record freshness window is unavailable",
                )
            })?;
        let window = ObservationWindow {
            now: now
                .format(&Rfc3339)
                .map_err(|_| ApiError::new("INTERNAL_ERROR", "Local record clock is invalid"))?,
            oldest_acceptable: oldest
                .format(&Rfc3339)
                .map_err(|_| ApiError::new("INTERNAL_ERROR", "Local record clock is invalid"))?,
        };
        self.engine.participant_record_status(
            access,
            Some(ParticipantRecordRuntime {
                profile_id: &self.profile_id,
                authority: self.authority.as_ref(),
                window: &window,
            }),
        )
    }
}
