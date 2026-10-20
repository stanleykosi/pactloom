//! Closed, bounded qualification evidence only. Never authority or raw errors.
#[cfg(feature = "synthetic-qualification")]
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

/// Fixed-size counters at actual error mapping boundaries, not inferred causes.
/// Connect includes tonic's TCP/proxy/TLS establishment as one opaque boundary.
/// Unary status may count propagation of an already counted inner failure.
#[cfg(feature = "synthetic-qualification")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportDiagnosticSnapshot {
    pub connect_including_tls: u64,
    pub readiness: u64,
    pub request: u64,
    pub body_drain: u64,
    pub unary_status: u64,
}
#[cfg(feature = "synthetic-qualification")]
const MAX_DIAGNOSTIC_COUNT: u64 = 1_000_000;
#[cfg(feature = "synthetic-qualification")]
impl TransportDiagnosticSnapshot {
    pub fn validate(&self) -> bool {
        [
            self.connect_including_tls,
            self.readiness,
            self.request,
            self.body_drain,
            self.unary_status,
        ]
        .iter()
        .all(|count| *count <= MAX_DIAGNOSTIC_COUNT)
    }
}
#[cfg(feature = "synthetic-qualification")]
#[derive(Clone, Default)]
pub struct TransportDiagnostics(Arc<[AtomicU64; 5]>);
#[cfg(feature = "synthetic-qualification")]
impl TransportDiagnostics {
    pub fn snapshot(&self) -> TransportDiagnosticSnapshot {
        let values = self.0.each_ref().map(|value| value.load(Ordering::Relaxed));
        TransportDiagnosticSnapshot {
            connect_including_tls: values[0],
            readiness: values[1],
            request: values[2],
            body_drain: values[3],
            unary_status: values[4],
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) enum FailureSite {
    ConnectIncludingTls,
    Readiness,
    Request,
    BodyDrain,
    UnaryStatus,
}
#[derive(Clone, Default)]
pub(crate) struct Observer {
    #[cfg(feature = "synthetic-qualification")]
    pub(crate) diagnostics: Option<TransportDiagnostics>,
}
impl Observer {
    pub(crate) fn record(&self, site: FailureSite) {
        #[cfg(feature = "synthetic-qualification")]
        if let Some(diagnostics) = &self.diagnostics {
            let _ = diagnostics.0[site as usize].fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |value| Some(value.saturating_add(1).min(MAX_DIAGNOSTIC_COUNT)),
            );
        }
        #[cfg(not(feature = "synthetic-qualification"))]
        let _ = site;
    }
}

#[cfg(all(test, feature = "synthetic-qualification"))]
mod tests {
    use super::*;

    #[test]
    fn counters_are_closed_shared_and_saturating() {
        let diagnostics = TransportDiagnostics::default();
        let observer = Observer {
            diagnostics: Some(diagnostics.clone()),
        };
        for site in [
            FailureSite::ConnectIncludingTls,
            FailureSite::Readiness,
            FailureSite::Request,
            FailureSite::BodyDrain,
            FailureSite::UnaryStatus,
        ] {
            observer.record(site);
        }
        assert_eq!(
            diagnostics.snapshot(),
            TransportDiagnosticSnapshot {
                connect_including_tls: 1,
                readiness: 1,
                request: 1,
                body_drain: 1,
                unary_status: 1,
            }
        );
        diagnostics.0[3].store(MAX_DIAGNOSTIC_COUNT, Ordering::Relaxed);
        observer.clone().record(FailureSite::BodyDrain);
        assert_eq!(diagnostics.snapshot().body_drain, MAX_DIAGNOSTIC_COUNT);
        assert!(diagnostics.snapshot().validate());
        let encoded = serde_json::to_value(diagnostics.snapshot()).unwrap();
        let decoded: TransportDiagnosticSnapshot = serde_json::from_value(encoded.clone()).unwrap();
        assert!(decoded.validate());
        let mut extra = encoded;
        extra["raw_error"] = serde_json::json!("forbidden");
        assert!(serde_json::from_value::<TransportDiagnosticSnapshot>(extra).is_err());
        let mut invalid = decoded;
        invalid.request = MAX_DIAGNOSTIC_COUNT + 1;
        assert!(!invalid.validate());
        Observer::default().record(FailureSite::Request);
        assert_eq!(diagnostics.snapshot().request, 1);
    }
}
