//! Bounded private PTY parsing state for the finite synthetic test only.
//! Consumed review text is erased; retained paths never become public output.
use std::{
    collections::{BTreeMap, VecDeque},
    path::{Component, Path},
};
use zeroize::{Zeroize, Zeroizing};

pub(super) const MAX_BYTES: usize = 262_144;
const MAX_MARKERS: usize = 16;
const MAX_PATH: usize = 4096;
const MAX_DIAGNOSTICS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    OutputLimit,
    IncompleteUtf8,
    InvalidUtf8,
    InvalidPath,
    MissingPath,
}

struct CapturedPath {
    value: Zeroizing<String>,
    end: usize,
}

pub(super) struct Transcript<'a> {
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    financial_progress: Option<super::financial_progress_v1::Capture>,
    bytes: Zeroizing<Vec<u8>>,
    base: usize,
    consumed: usize,
    line_start: usize,
    paths: BTreeMap<&'a str, Option<CapturedPath>>,
    diagnostics: VecDeque<String>,
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    delivery_first_failure: Option<super::safe_diagnostics_v1::DeliveryFailureCapture>,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    timing: crate::host::synthetic_roster_timing_v1::Capture,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    history_measurements: super::safe_diagnostics_v1::HistoryMeasurementCapture,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    admission_diagnostics: super::safe_diagnostics_v1::AdmissionDiagnosticCapture,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    durable_flow: super::safe_diagnostics_v1::DurableFlowCapture,
    #[cfg(feature = "synthetic-born-joined-qualification")]
    durable_lifecycle: super::safe_diagnostics_v1::DurableLifecycleCapture,
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    private_fixed_diagnostic: super::safe_diagnostics_v1::PrivateFixedDiagnosticCapture,
}

impl<'a> Transcript<'a> {
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn finish_financial_progress(&mut self) {
        if let Some(capture) = self.financial_progress.as_mut() {
            capture.finish_partial(&self.bytes[self.line_start..]);
        }
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn enable_financial_progress(&mut self) {
        self.enable_financial_progress_at(std::time::Instant::now());
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn enable_financial_v2(&mut self, start: std::time::Instant, reader: bool) {
        self.financial_progress = Some(if reader {
            super::financial_progress_v1::Capture::financial_reader(start)
        } else {
            super::financial_progress_v1::Capture::financial_producer(start)
        });
    }

    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn enable_financial_progress_at(&mut self, start: std::time::Instant) {
        self.financial_progress = Some(super::financial_progress_v1::Capture::with_workflow_start(
            start,
        ));
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn observe_financial_reader_exit(&mut self, now: std::time::Instant) {
        if let Some(capture) = self.financial_progress.as_mut() {
            capture.observe_reader_exit(now);
        }
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn freeze_financial_progress_timing(&mut self, now: std::time::Instant) {
        if let Some(capture) = self.financial_progress.as_mut() {
            capture.freeze_timing(now);
        }
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn financial_progress_timing(&self) -> Option<super::financial_progress_v1::Timing> {
        self.financial_progress
            .as_ref()
            .and_then(|capture| capture.timing())
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn financial_progress_check(
        &mut self,
        now: std::time::Instant,
    ) -> Option<super::financial_progress_v1::Failure> {
        self.financial_progress
            .as_mut()
            .and_then(|capture| capture.failure_at(now))
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn financial_progress_global_deadline(&mut self) {
        if let Some(capture) = self.financial_progress.as_mut() {
            capture.global_deadline();
        }
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn financial_progress_failure(
        &self,
    ) -> Option<super::financial_progress_v1::Failure> {
        self.financial_progress
            .as_ref()
            .and_then(|capture| capture.failure())
    }

    pub(super) fn new(markers: impl IntoIterator<Item = &'a str>) -> Result<Self, Failure> {
        let mut paths = BTreeMap::new();
        for marker in markers {
            if marker.len() > 96
                || marker.len() < 2
                || !marker.ends_with('=')
                || !marker[..marker.len() - 1]
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b == b'_')
            {
                return Err(Failure::InvalidPath);
            }
            paths.insert(marker, None);
            if paths.len() > MAX_MARKERS {
                return Err(Failure::OutputLimit);
            }
        }
        Ok(Self {
            #[cfg(all(
                feature = "durable-proposal",
                feature = "synthetic-born-joined-qualification"
            ))]
            financial_progress: None,
            // No reallocation can leave a discarded private transcript copy.
            // All populated bytes share the original aggregate content budget.
            bytes: Zeroizing::new(Vec::with_capacity(MAX_BYTES)),
            base: 0,
            consumed: 0,
            line_start: 0,
            paths,
            diagnostics: VecDeque::new(),
            #[cfg(all(
                feature = "durable-proposal",
                feature = "synthetic-born-joined-qualification"
            ))]
            delivery_first_failure: None,
            #[cfg(feature = "synthetic-born-joined-qualification")]
            timing: Default::default(),
            #[cfg(feature = "synthetic-born-joined-qualification")]
            history_measurements: Default::default(),
            #[cfg(feature = "synthetic-born-joined-qualification")]
            admission_diagnostics: Default::default(),
            #[cfg(feature = "synthetic-born-joined-qualification")]
            durable_flow: Default::default(),
            #[cfg(feature = "synthetic-born-joined-qualification")]
            durable_lifecycle: Default::default(),
            #[cfg(all(
                feature = "durable-proposal",
                feature = "synthetic-born-joined-qualification"
            ))]
            private_fixed_diagnostic: Default::default(),
        })
    }

    fn retained_bytes(&self) -> usize {
        self.bytes.len()
            + self.delivery_first_failure_retained_bytes()
            + self.timing_retained_bytes()
            + self.history_measurement_retained_bytes()
            + self.admission_diagnostic_retained_bytes()
            + self.durable_flow_retained_bytes()
            + self.durable_lifecycle_retained_bytes()
            + self.private_fixed_diagnostic_retained_bytes()
            + self
                .paths
                .values()
                .flatten()
                .map(|p| p.value.len())
                .sum::<usize>()
            + self.diagnostics.iter().map(String::len).sum::<usize>()
            + self.diagnostics.len().saturating_sub(1)
    }

    // Disabled for every older adapter. Only the B1 delivery child stages opt in.
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn enable_delivery_first_failure(&mut self) {
        self.delivery_first_failure
            .get_or_insert_with(Default::default);
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn delivery_first_failure(
        &self,
    ) -> Option<super::safe_diagnostics_v1::DeliveryFailure> {
        self.delivery_first_failure
            .as_ref()
            .and_then(|capture| capture.value())
    }
    fn delivery_first_failure_retained_bytes(&self) -> usize {
        #[cfg(all(
            feature = "durable-proposal",
            feature = "synthetic-born-joined-qualification"
        ))]
        {
            self.delivery_first_failure
                .as_ref()
                .map_or(0, |capture| capture.retained_bytes())
        }
        #[cfg(not(all(
            feature = "durable-proposal",
            feature = "synthetic-born-joined-qualification"
        )))]
        {
            0
        }
    }

    fn timing_retained_bytes(&self) -> usize {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            crate::host::synthetic_roster_timing_v1::Capture::RETAINED_BYTES
        }
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        {
            0
        }
    }
    fn history_measurement_retained_bytes(&self) -> usize {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            self.history_measurements.retained_bytes()
        }
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        {
            0
        }
    }
    fn admission_diagnostic_retained_bytes(&self) -> usize {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            self.admission_diagnostics.retained_bytes()
        }
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        {
            0
        }
    }
    fn durable_flow_retained_bytes(&self) -> usize {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            self.durable_flow.retained_bytes()
        }
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        {
            0
        }
    }
    fn durable_lifecycle_retained_bytes(&self) -> usize {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        {
            self.durable_lifecycle.retained_bytes()
        }
        #[cfg(not(feature = "synthetic-born-joined-qualification"))]
        {
            0
        }
    }
    fn private_fixed_diagnostic_retained_bytes(&self) -> usize {
        #[cfg(all(
            feature = "durable-proposal",
            feature = "synthetic-born-joined-qualification"
        ))]
        {
            self.private_fixed_diagnostic.retained_bytes()
        }
        #[cfg(not(all(
            feature = "durable-proposal",
            feature = "synthetic-born-joined-qualification"
        )))]
        {
            0
        }
    }
    fn discard_private_fixed_diagnostic_for_budget(&mut self) {
        #[cfg(all(
            feature = "durable-proposal",
            feature = "synthetic-born-joined-qualification"
        ))]
        self.private_fixed_diagnostic.discard_for_budget();
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn finish_private_fixed_diagnostic(&mut self) {
        self.private_fixed_diagnostic
            .finish(&self.bytes[self.line_start..]);
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn private_fixed_diagnostic(
        &self,
    ) -> Option<&crate::host::durable_private_workspace_v1::PrivateFixedDiagnosticV1> {
        self.private_fixed_diagnostic.value()
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn financial_diagnostic(
        &self,
    ) -> Option<&crate::host::financial_diagnostics_v1::FinancialDiagnosticV1> {
        self.private_fixed_diagnostic.financial_value()
    }
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    pub(super) fn diagnostic_withheld(&self) -> bool {
        self.private_fixed_diagnostic.withheld()
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn durable_lifecycle_lines(&self) -> Vec<&str> {
        self.durable_lifecycle.public_lines(&self.durable_flow)
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn durable_flow_lines(&self) -> Vec<&str> {
        self.durable_flow.public_lines()
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn admission_diagnostic_lines(&self) -> Vec<&str> {
        self.admission_diagnostics.public_lines()
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn history_measurement_lines(&self) -> Vec<&str> {
        self.history_measurements.public_lines()
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn capture_timing(&mut self, bytes: &[u8]) {
        self.timing.feed(bytes);
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn timing_json(&self) -> Option<String> {
        self.timing.public_json()
    }
    #[cfg(feature = "synthetic-born-joined-qualification")]
    pub(super) fn finish_timing(&mut self, drained: bool) {
        self.timing.finish_input(drained);
    }

    pub(super) fn append(&mut self, chunk: &[u8], root: &Path) -> Result<(), Failure> {
        #[cfg(feature = "synthetic-born-joined-qualification")]
        self.capture_timing(chunk);
        // Optional retained copies yield to the original transcript budget.
        // Their original raw PTY bytes still count normally; no raw limit is
        // bypassed, and truly over-budget original text still fails below.
        #[cfg(all(
            feature = "durable-proposal",
            feature = "synthetic-born-joined-qualification"
        ))]
        if chunk.len() > MAX_BYTES.saturating_sub(self.retained_bytes()) {
            if let Some(capture) = &mut self.delivery_first_failure {
                capture.discard_for_budget();
            }
        }
        if chunk.len() > MAX_BYTES.saturating_sub(self.retained_bytes()) {
            self.discard_private_fixed_diagnostic_for_budget();
        }
        #[cfg(feature = "synthetic-born-joined-qualification")]
        if chunk.len() > MAX_BYTES.saturating_sub(self.retained_bytes()) {
            self.history_measurements.discard_for_budget();
            self.admission_diagnostics.discard_for_budget();
            self.durable_flow.discard_for_budget();
            self.durable_lifecycle.discard_for_budget();
        }
        if chunk.len() > MAX_BYTES.saturating_sub(self.retained_bytes()) {
            return Err(Failure::OutputLimit);
        }
        self.bytes.extend_from_slice(chunk);
        if let Err(error) = std::str::from_utf8(&self.bytes) {
            if error.error_len().is_some() {
                return Err(Failure::InvalidUtf8);
            }
            // A final incomplete scalar is retained, not interpreted. It must
            // become valid before an input is matched or terminal success.
        }
        let mut retained = self.retained_bytes();
        while let Some(relative_end) = self.bytes[self.line_start..]
            .iter()
            .position(|b| *b == b'\n')
        {
            let end = self.line_start + relative_end;
            let line = &self.bytes[self.line_start..end];
            let summary = super::safe_diagnostics_v1::summary(line);
            if summary != "none" {
                // The maintained parser currently emits at most one entry per
                // physical line. Flatten its closed projection defensively so
                // the public history bound always counts entries, not chunks.
                for entry in summary.split(',') {
                    let count = self.diagnostics.len();
                    let removed = if count == MAX_DIAGNOSTICS {
                        self.diagnostics.front().map_or(0, String::len)
                    } else {
                        0
                    };
                    let new_count = (count + 1).min(MAX_DIAGNOSTICS);
                    retained = retained - removed - count.saturating_sub(1)
                        + entry.len()
                        + new_count.saturating_sub(1);
                    #[cfg(all(
                        feature = "durable-proposal",
                        feature = "synthetic-born-joined-qualification"
                    ))]
                    if retained > MAX_BYTES {
                        if let Some(capture) = &mut self.delivery_first_failure {
                            retained -= capture.retained_bytes();
                            capture.discard_for_budget();
                        }
                    }
                    if retained > MAX_BYTES {
                        retained -= self.private_fixed_diagnostic_retained_bytes();
                        #[cfg(all(
                            feature = "durable-proposal",
                            feature = "synthetic-born-joined-qualification"
                        ))]
                        self.private_fixed_diagnostic.discard_for_budget();
                    }
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    if retained > MAX_BYTES {
                        retained -= self.history_measurements.retained_bytes()
                            + self.admission_diagnostics.retained_bytes()
                            + self.durable_flow.retained_bytes()
                            + self.durable_lifecycle.retained_bytes();
                        self.history_measurements.discard_for_budget();
                        self.admission_diagnostics.discard_for_budget();
                        self.durable_flow.discard_for_budget();
                        self.durable_lifecycle.discard_for_budget();
                    }
                    if retained > MAX_BYTES {
                        return Err(Failure::OutputLimit);
                    }
                    if count == MAX_DIAGNOSTICS {
                        self.diagnostics.pop_front();
                    }
                    self.diagnostics.push_back(entry.to_owned());
                }
            }
            // Complete lines are UTF-8 because append already refused invalid
            // bytes, and an incomplete scalar cannot contain the newline.
            let line = std::str::from_utf8(line).map_err(|_| Failure::InvalidUtf8)?;
            #[cfg(all(
                feature = "durable-proposal",
                feature = "synthetic-born-joined-qualification"
            ))]
            let private_fixed_line = line.strip_suffix('\r').unwrap_or(line);
            let line = line.trim_end_matches('\r');
            #[cfg(all(
                feature = "durable-proposal",
                feature = "synthetic-born-joined-qualification"
            ))]
            if let Some(capture) = self.financial_progress.as_mut() {
                capture.line(private_fixed_line, std::time::Instant::now());
            }
            #[cfg(all(
                feature = "durable-proposal",
                feature = "synthetic-born-joined-qualification"
            ))]
            if let Some(capture) = &mut self.delivery_first_failure {
                if capture.retained_bytes() > 0 {
                    // Existing optional diagnostic copies have priority over
                    // this new slot too. Preflight only finite valid records;
                    // never let the slot change their original budget result.
                    let required = self
                        .history_measurements
                        .additional_bytes_for_line(line)
                        .or_else(|| self.admission_diagnostics.additional_bytes_for_line(line))
                        .or_else(|| self.durable_flow.additional_bytes_for_line(line))
                        .or_else(|| self.durable_lifecycle.additional_bytes_for_line(line))
                        .or_else(|| {
                            self.private_fixed_diagnostic
                                .additional_bytes_for_line(private_fixed_line)
                        });
                    if required.is_some_and(|bytes| bytes > MAX_BYTES.saturating_sub(retained)) {
                        retained -= capture.retained_bytes();
                        capture.discard_for_budget();
                    }
                }
            }
            #[cfg(feature = "synthetic-born-joined-qualification")]
            {
                let previous = self.history_measurements.retained_bytes();
                self.history_measurements
                    .capture_line(line, MAX_BYTES.saturating_sub(retained));
                retained = retained - previous + self.history_measurements.retained_bytes();
                let previous = self.admission_diagnostics.retained_bytes();
                self.admission_diagnostics
                    .capture_line(line, MAX_BYTES.saturating_sub(retained));
                retained = retained - previous + self.admission_diagnostics.retained_bytes();
                let previous = self.durable_flow.retained_bytes();
                self.durable_flow
                    .capture_line(line, MAX_BYTES.saturating_sub(retained));
                retained = retained - previous + self.durable_flow.retained_bytes();
                let previous = self.durable_lifecycle.retained_bytes();
                self.durable_lifecycle
                    .capture_line(line, MAX_BYTES.saturating_sub(retained));
                retained = retained - previous + self.durable_lifecycle.retained_bytes();
            }
            #[cfg(all(
                feature = "durable-proposal",
                feature = "synthetic-born-joined-qualification"
            ))]
            {
                let previous = self.private_fixed_diagnostic.retained_bytes();
                self.private_fixed_diagnostic
                    .capture_line(private_fixed_line, MAX_BYTES.saturating_sub(retained));
                retained = retained - previous + self.private_fixed_diagnostic.retained_bytes();
            }
            let mut private_fixed_retained = self.private_fixed_diagnostic_retained_bytes();
            for (marker, path) in &mut self.paths {
                // Preserve the original exact substring lookup, even when a
                // prior terminal prompt has not supplied a line break. Only
                // complete lines are considered and the last literal wins.
                if let Some((_, value)) = line.rsplit_once(*marker) {
                    let actual = Path::new(value);
                    if value.len() > MAX_PATH
                        || value.contains(['\r', '\n', '\0'])
                        || !actual.is_absolute()
                        || !actual.starts_with(root)
                        || actual
                            .components()
                            .any(|c| matches!(c, Component::ParentDir))
                    {
                        return Err(Failure::InvalidPath);
                    }
                    retained = retained - path.as_ref().map_or(0, |p| p.value.len()) + value.len();
                    #[cfg(all(
                        feature = "durable-proposal",
                        feature = "synthetic-born-joined-qualification"
                    ))]
                    if retained > MAX_BYTES {
                        if let Some(capture) = &mut self.delivery_first_failure {
                            retained -= capture.retained_bytes();
                            capture.discard_for_budget();
                        }
                    }
                    if retained > MAX_BYTES {
                        retained -= private_fixed_retained;
                        #[cfg(all(
                            feature = "durable-proposal",
                            feature = "synthetic-born-joined-qualification"
                        ))]
                        self.private_fixed_diagnostic.discard_for_budget();
                        private_fixed_retained = 0;
                    }
                    #[cfg(feature = "synthetic-born-joined-qualification")]
                    if retained > MAX_BYTES {
                        retained -= self.history_measurements.retained_bytes()
                            + self.admission_diagnostics.retained_bytes()
                            + self.durable_flow.retained_bytes()
                            + self.durable_lifecycle.retained_bytes();
                        self.history_measurements.discard_for_budget();
                        self.admission_diagnostics.discard_for_budget();
                        self.durable_flow.discard_for_budget();
                        self.durable_lifecycle.discard_for_budget();
                    }
                    if retained > MAX_BYTES {
                        return Err(Failure::OutputLimit);
                    }
                    let Some(absolute_end) = self.base.checked_add(end + 1) else {
                        #[cfg(all(
                            feature = "durable-proposal",
                            feature = "synthetic-born-joined-qualification"
                        ))]
                        if let Some(capture) = &mut self.delivery_first_failure {
                            capture.discard_for_budget();
                        }
                        return Err(Failure::OutputLimit);
                    };
                    // Drop erases the replaced exact path before allocating its
                    // successor. Never retain another owner's stale path copy.
                    *path = None;
                    *path = Some(CapturedPath {
                        value: Zeroizing::new(value.to_owned()),
                        end: absolute_end,
                    });
                }
            }
            #[cfg(all(
                feature = "durable-proposal",
                feature = "synthetic-born-joined-qualification"
            ))]
            if let Some(capture) = &mut self.delivery_first_failure {
                let previous = capture.retained_bytes();
                capture.capture_complete_line(
                    &self.bytes[self.line_start..end],
                    MAX_BYTES.saturating_sub(retained),
                );
                retained = retained - previous + capture.retained_bytes();
            }
            self.line_start = end + 1;
        }
        Ok(())
    }

    pub(super) fn tail(&self) -> Result<Option<&str>, Failure> {
        match std::str::from_utf8(&self.bytes[self.consumed..]) {
            Ok(text) => Ok(Some(text)),
            Err(error) if error.error_len().is_none() => Ok(None),
            Err(_) => Err(Failure::InvalidUtf8),
        }
    }

    pub(super) fn finish_text(&self) -> Result<(), Failure> {
        std::str::from_utf8(&self.bytes)
            .map(|_| ())
            .map_err(|error| {
                if error.error_len().is_none() {
                    Failure::IncompleteUtf8
                } else {
                    Failure::InvalidUtf8
                }
            })
    }

    /// The latest complete exact marker must precede this matched prompt, not
    /// merely occur later in the same read. A used marker cannot be reused.
    pub(super) fn path(&mut self, marker: &str, prompt_in_tail: usize) -> Result<&str, Failure> {
        let Some(prompt) = self
            .base
            .checked_add(self.consumed)
            .and_then(|position| position.checked_add(prompt_in_tail))
        else {
            #[cfg(all(
                feature = "durable-proposal",
                feature = "synthetic-born-joined-qualification"
            ))]
            if let Some(capture) = &mut self.delivery_first_failure {
                capture.discard_for_budget();
            }
            return Err(Failure::OutputLimit);
        };
        let path = self
            .paths
            .get(marker)
            .and_then(Option::as_ref)
            .ok_or(Failure::MissingPath)?;
        if path.end > prompt {
            return Err(Failure::MissingPath);
        }
        Ok(path.value.as_str())
    }

    /// Only after the exact current input was successfully written. Captured
    /// markers are now one-use, stricter than the former all-history lookup;
    /// actual repeated producers emit a fresh marker for each corresponding use.
    /// Preserve the original end-of-read cursor, including already-read prompt
    /// bytes, and preserve any unfinished metadata line without rematching it.
    pub(super) fn consume(&mut self, captured: Option<&str>) -> Result<(), Failure> {
        if let Some(marker) = captured {
            *self.paths.get_mut(marker).ok_or(Failure::MissingPath)? = None;
        }
        let cut = self.line_start;
        let Some(base) = self.base.checked_add(cut) else {
            #[cfg(all(
                feature = "durable-proposal",
                feature = "synthetic-born-joined-qualification"
            ))]
            if let Some(capture) = &mut self.delivery_first_failure {
                capture.discard_for_budget();
            }
            return Err(Failure::OutputLimit);
        };
        let length = self.bytes.len() - cut;
        erase_consumed_prefix(&mut self.bytes, cut);
        self.bytes.truncate(length);
        self.base = base;
        self.consumed = length;
        self.line_start = 0;
        Ok(())
    }

    pub(super) fn summary(&self) -> String {
        if self.diagnostics.is_empty() {
            "none".into()
        } else {
            self.diagnostics
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",")
        }
    }
}

// Includes all formerly populated tail storage before truncate. The retained
// prefix is the only remaining copy of the unfinished line.
fn erase_consumed_prefix(bytes: &mut [u8], cut: usize) {
    let retained = bytes.len() - cut;
    bytes.copy_within(cut.., 0);
    bytes[retained..].zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    const MARKER: &str = "SYNTHETIC_JOINED_DRAFT_PATH=";
    const SECOND: &str = "SYNTHETIC_JOINED_CANDIDATE_SELECTION_PATH=";

    #[test]
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn actual_full_input_markers_fit_the_fixed_metadata_bound() {
        use super::super::{full_payment_inputs_v1, Input};
        let inputs = full_payment_inputs_v1::inputs();
        assert_eq!(inputs.len(), 204);
        let names = inputs
            .iter()
            .filter_map(|input| match input {
                Input::CapturedPath { marker, .. } => Some(*marker),
                _ => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names.len(), 10);
        let transcript = Transcript::new(names.iter().copied()).unwrap();
        assert_eq!(transcript.paths.len(), 10);
        assert!(transcript.paths.len() <= MAX_MARKERS);
    }

    #[test]
    fn consumed_reviews_compact_without_replaying_old_prompts() {
        let root = Path::new("/tmp/owned");
        let mut transcript = Transcript::new([MARKER]).unwrap();
        transcript
            .append(
                b"SYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/exact.json\r\n",
                root,
            )
            .unwrap();
        for _ in 0..16 {
            let mut chunk = vec![b'x'; 32_768];
            chunk.extend_from_slice(b"\nEXACT CURRENT PROMPT: ");
            transcript.append(&chunk, root).unwrap();
            assert!(transcript
                .tail()
                .unwrap()
                .unwrap()
                .ends_with("EXACT CURRENT PROMPT: "));
            transcript.consume(None).unwrap();
            assert_eq!(transcript.tail().unwrap(), Some(""));
            assert!(transcript.retained_bytes() < 1024 + transcript.timing_retained_bytes());
        }
        transcript
            .append(b"\nDIFFERENT CURRENT PROMPT: ", root)
            .unwrap();
        let tail = transcript.tail().unwrap().unwrap();
        assert!(!tail.contains("EXACT CURRENT PROMPT"));
        let position = tail.find("DIFFERENT CURRENT PROMPT").unwrap();
        assert_eq!(
            transcript.path(MARKER, position).unwrap(),
            "/tmp/owned/exact.json"
        );
    }

    #[test]
    fn compaction_erases_discarded_populated_storage() {
        let mut bytes = *b"PRIVATE\nretained";
        erase_consumed_prefix(&mut bytes, 8);
        assert_eq!(&bytes[..8], b"retained");
        assert!(bytes[8..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn paths_require_complete_exact_markers_and_original_scope() {
        let root = Path::new("/tmp/owned");
        let mut transcript = Transcript::new([MARKER]).unwrap();
        transcript
            .append(b"SYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/first", root)
            .unwrap();
        assert_eq!(transcript.path(MARKER, 0), Err(Failure::MissingPath));
        transcript.append(b".json\nPROMPT", root).unwrap();
        let prompt = transcript.tail().unwrap().unwrap().find("PROMPT").unwrap();
        assert_eq!(
            transcript.path(MARKER, prompt).unwrap(),
            "/tmp/owned/first.json"
        );
        transcript.consume(Some(MARKER)).unwrap();
        assert_eq!(transcript.path(MARKER, 0), Err(Failure::MissingPath));
        transcript.append(b"\nSYNTHETIC_JOINED_DRAFT_PATH_MORE=/tmp/owned/wrong\nSYNTHETIC_JOINED_DRAFT_PATH/tmp/owned/wrong\n", root).unwrap();
        assert_eq!(transcript.path(MARKER, 0), Err(Failure::MissingPath));
        transcript.append(b"prior prompt text SYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/older SYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/latest\nNEXT PROMPT", root).unwrap();
        let prompt = transcript
            .tail()
            .unwrap()
            .unwrap()
            .find("NEXT PROMPT")
            .unwrap();
        assert_eq!(
            transcript.path(MARKER, prompt).unwrap(),
            "/tmp/owned/latest"
        );
        transcript.consume(Some(MARKER)).unwrap();
        assert_eq!(
            transcript.append(b"SYNTHETIC_JOINED_DRAFT_PATH=/tmp/other/escape\n", root),
            Err(Failure::InvalidPath)
        );
        let mut transcript = Transcript::new([MARKER]).unwrap();
        assert_eq!(
            transcript.append(b"SYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/../escape\n", root),
            Err(Failure::InvalidPath)
        );
    }

    #[test]
    fn batched_paths_are_latest_before_prompt_and_each_one_use() {
        let root = Path::new("/tmp/owned");
        let mut transcript = Transcript::new([MARKER, SECOND]).unwrap();
        transcript.append(b"SYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/old\nSYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/replacement\nSYNTHETIC_JOINED_CANDIDATE_SELECTION_PATH=/tmp/owned/second\nFIRST PROMPT", root).unwrap();
        let position = transcript
            .tail()
            .unwrap()
            .unwrap()
            .find("FIRST PROMPT")
            .unwrap();
        assert_eq!(
            transcript.path(MARKER, position).unwrap(),
            "/tmp/owned/replacement"
        );
        transcript.consume(Some(MARKER)).unwrap();
        transcript.append(b"\nSECOND PROMPT", root).unwrap();
        let position = transcript
            .tail()
            .unwrap()
            .unwrap()
            .find("SECOND PROMPT")
            .unwrap();
        assert_eq!(
            transcript.path(SECOND, position).unwrap(),
            "/tmp/owned/second"
        );
        assert_eq!(transcript.path(MARKER, position), Err(Failure::MissingPath));
        transcript.consume(Some(SECOND)).unwrap();
        transcript
            .append(
                b"\nTHIRD PROMPT\nSYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/future\n",
                root,
            )
            .unwrap();
        let position = transcript
            .tail()
            .unwrap()
            .unwrap()
            .find("THIRD PROMPT")
            .unwrap();
        assert_eq!(transcript.path(MARKER, position), Err(Failure::MissingPath));
        transcript.consume(None).unwrap();
        transcript.append(b"\nFOURTH PROMPT", root).unwrap();
        let position = transcript
            .tail()
            .unwrap()
            .unwrap()
            .find("FOURTH PROMPT")
            .unwrap();
        assert_eq!(
            transcript.path(MARKER, position).unwrap(),
            "/tmp/owned/future"
        );
    }

    #[test]
    fn utf8_partial_waits_but_malformed_bytes_refuse() {
        let root = Path::new("/tmp/owned");
        let mut transcript = Transcript::new([]).unwrap();
        transcript.append(b"exact \xe2", root).unwrap();
        assert_eq!(transcript.tail().unwrap(), None);
        assert_eq!(transcript.finish_text(), Err(Failure::IncompleteUtf8));
        transcript.append(b"\x80\x93 purpose\n", root).unwrap();
        assert_eq!(transcript.tail().unwrap(), Some("exact \u{2013} purpose\n"));
        assert_eq!(transcript.finish_text(), Ok(()));
        transcript.consume(None).unwrap();
        assert_eq!(transcript.append(b"\xff", root), Err(Failure::InvalidUtf8));
    }

    #[test]
    fn only_closed_last_diagnostics_survive_private_text_compaction() {
        let root = Path::new("/tmp/owned");
        let mut transcript = Transcript::new([]).unwrap();
        for _ in 0..80 {
            transcript.append(b"private contents\n[JOINED_DIAGNOSTIC Bootstrap Begin]\n[JOINED_DIAGNOSTIC Bootstrap unknown-private]\n", root).unwrap();
            transcript.consume(None).unwrap();
        }
        let summary = transcript.summary();
        assert_eq!(summary.split(',').count(), 64);
        assert!(summary.split(',').all(|s| s == "Bootstrap:Begin"));
        assert!(!summary.contains("private"));
        assert!(transcript.retained_bytes() < MAX_BYTES);
    }

    #[test]
    fn diagnostic_history_counts_entries_not_physical_line_groups() {
        let root = Path::new("/tmp/owned");
        let mut transcript = Transcript::new([]).unwrap();
        // Multiple markers on one physical line remain invalid under the
        // existing whole-line closed parser; no fuzzy marker extraction.
        transcript
            .append(
                b"[JOINED_DIAGNOSTIC Bootstrap Begin][JOINED_DIAGNOSTIC Session Complete]\n",
                root,
            )
            .unwrap();
        assert_eq!(transcript.summary(), "none");
        transcript.consume(None).unwrap();
        for _ in 0..40 {
            transcript
                .append(
                    b"[JOINED_DIAGNOSTIC Bootstrap Begin]\n[JOINED_DIAGNOSTIC Session Complete]\n",
                    root,
                )
                .unwrap();
            transcript.consume(None).unwrap();
        }
        let summary = transcript.summary();
        assert_eq!(summary.split(',').count(), MAX_DIAGNOSTICS);
        assert_eq!(
            transcript.retained_bytes(),
            summary.len() + transcript.timing_retained_bytes()
        );
        for (index, entry) in summary.split(',').enumerate() {
            assert_eq!(
                entry,
                if index % 2 == 0 {
                    "Bootstrap:Begin"
                } else {
                    "Session:Complete"
                }
            );
        }
    }

    #[test]
    fn aggregate_budget_includes_paths_and_closed_history() {
        let root = Path::new("/tmp/owned");
        let mut transcript = Transcript::new([MARKER]).unwrap();
        transcript.append(b"SYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/exact\n[JOINED_DIAGNOSTIC Bootstrap Begin]\n", root).unwrap();
        transcript.consume(None).unwrap();
        let metadata = transcript.retained_bytes();
        assert_eq!(
            metadata,
            "/tmp/owned/exact".len() + "Bootstrap:Begin".len() + transcript.timing_retained_bytes()
        );
        transcript
            .append(&vec![b'x'; MAX_BYTES - metadata], root)
            .unwrap();
        assert_eq!(transcript.append(b"x", root), Err(Failure::OutputLimit));
        assert_eq!(transcript.retained_bytes(), MAX_BYTES);
    }

    #[test]
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn history_measurements_survive_split_lines_and_compaction_without_raw_text() {
        let root = Path::new("/tmp/owned");
        let mut transcript = Transcript::new([]).unwrap();
        let line = format!(
            "[HISTORY_MEASUREMENT_V1 {}]\r\n",
            super::super::safe_diagnostics_v1::HISTORY_MEASUREMENT_TEST_JSON
        );
        let split = line.len() / 2;
        transcript.append(&line.as_bytes()[..split], root).unwrap();
        assert!(transcript.history_measurement_lines().is_empty());
        transcript.append(&line.as_bytes()[split..], root).unwrap();
        assert_eq!(transcript.history_measurement_lines().len(), 1);
        transcript.consume(None).unwrap();
        assert!(transcript.bytes.is_empty());
        assert_eq!(
            transcript.retained_bytes(),
            transcript.timing_retained_bytes() + transcript.history_measurement_lines()[0].len()
        );
        assert_eq!(transcript.summary(), "none");
        transcript
            .append(
                b"private [HISTORY_MEASUREMENT_V1 {\"private\":\"payload\"}]\n",
                root,
            )
            .unwrap();
        transcript.consume(None).unwrap();
        assert_eq!(transcript.history_measurement_lines().len(), 1);
        assert!(!transcript.history_measurement_lines()[0].contains("private"));
        transcript.append(line.as_bytes(), root).unwrap();
        transcript.consume(None).unwrap();
        assert_eq!(transcript.history_measurement_retained_bytes(), 0);
        assert!(transcript.history_measurement_lines()[0].contains("invalid=true"));
        transcript
            .append(
                b"[HISTORY_SERVER_MEASUREMENT_V1 {\"private\":\"payload\"}]\n",
                root,
            )
            .unwrap();
        transcript.consume(None).unwrap();
        assert!(transcript
            .history_measurement_lines()
            .iter()
            .all(|line| !line.contains("payload")));
    }

    #[test]
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn history_measurement_copies_yield_before_original_chunk_budget() {
        let root = Path::new("/tmp/owned");
        let mut measured = Transcript::new([]).unwrap();
        let mut original = Transcript::new([]).unwrap();
        let line = format!(
            "[HISTORY_MEASUREMENT_V1 {}]\n",
            super::super::safe_diagnostics_v1::HISTORY_MEASUREMENT_TEST_JSON
        );
        measured.append(line.as_bytes(), root).unwrap();
        measured.consume(None).unwrap();
        assert!(measured.history_measurement_retained_bytes() > 0);
        let original_capacity = MAX_BYTES - original.timing_retained_bytes();
        let chunk = vec![b'x'; original_capacity];
        original.append(&chunk, root).unwrap();
        measured.append(&chunk, root).unwrap();
        assert_eq!(measured.retained_bytes(), original.retained_bytes());
        assert_eq!(measured.history_measurement_retained_bytes(), 0);
        assert!(measured
            .history_measurement_lines()
            .iter()
            .all(|line| line.contains("invalid=true")));
        assert_eq!(original.append(b"x", root), Err(Failure::OutputLimit));
        assert_eq!(measured.append(b"x", root), Err(Failure::OutputLimit));
        // No raw limit bypass: only the optional already-validated retained
        // copy was evicted. Its earlier raw line used the original budget.
    }

    #[test]
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn history_measurement_copies_yield_before_original_metadata_budget() {
        let root = Path::new("/tmp/owned");
        for metadata in [
            "[JOINED_DIAGNOSTIC Bootstrap Begin]\n",
            "SYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/exact\n",
        ] {
            let mut measured = Transcript::new([MARKER]).unwrap();
            let mut original = Transcript::new([MARKER]).unwrap();
            let line = format!(
                "[HISTORY_MEASUREMENT_V1 {}]\n",
                super::super::safe_diagnostics_v1::HISTORY_MEASUREMENT_TEST_JSON
            );
            measured.append(line.as_bytes(), root).unwrap();
            measured.consume(None).unwrap();
            let captured = measured.history_measurement_retained_bytes();
            let filler =
                MAX_BYTES - measured.timing_retained_bytes() - captured - metadata.len() - 1;
            let mut chunk = vec![b'x'; filler];
            chunk.push(b'\n');
            chunk.extend_from_slice(metadata.as_bytes());
            original.append(&chunk, root).unwrap();
            measured.append(&chunk, root).unwrap();
            assert_eq!(measured.history_measurement_retained_bytes(), 0);
            assert_eq!(measured.retained_bytes(), original.retained_bytes());
            assert_eq!(measured.summary(), original.summary());
            assert!(measured
                .history_measurement_lines()
                .iter()
                .all(|line| line.contains("invalid=true")));
        }
    }

    #[test]
    fn one_unconsumed_review_still_cannot_exceed_original_bound() {
        let root = Path::new("/tmp/owned");
        let mut transcript = Transcript::new([]).unwrap();
        transcript
            .append(
                &vec![b'x'; MAX_BYTES - transcript.timing_retained_bytes()],
                root,
            )
            .unwrap();
        assert_eq!(transcript.append(b"x", root), Err(Failure::OutputLimit));
        assert_eq!(transcript.retained_bytes(), MAX_BYTES);
    }
    #[test]
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn admission_diagnostics_survive_split_lines_and_compaction() {
        use super::super::safe_diagnostics_v1::{
            ADMISSION_MEASUREMENT_TEST_JSON, SIGNER_ADMISSION_TEST_JSON,
            WITNESS_ADMISSION_TEST_JSON,
        };
        let root = Path::new("/tmp/owned");
        let mut transcript = Transcript::new([]).unwrap();
        for (prefix, json) in [
            ("ADMISSION_MEASUREMENT_V1", ADMISSION_MEASUREMENT_TEST_JSON),
            ("SIGNER_ADMISSION_V1", SIGNER_ADMISSION_TEST_JSON),
            ("WITNESS_ADMISSION_V1", WITNESS_ADMISSION_TEST_JSON),
        ] {
            let line = format!("[{prefix} {json}]\r\n");
            let before = transcript.admission_diagnostic_lines().len();
            let split = line.len() / 2;
            transcript.append(&line.as_bytes()[..split], root).unwrap();
            assert_eq!(transcript.admission_diagnostic_lines().len(), before);
            transcript.append(&line.as_bytes()[split..], root).unwrap();
            transcript.consume(None).unwrap();
            assert_eq!(transcript.admission_diagnostic_lines().len(), before + 1);
        }
        assert!(transcript.bytes.is_empty());
        assert_eq!(
            transcript.retained_bytes(),
            transcript.timing_retained_bytes() + transcript.admission_diagnostic_retained_bytes()
        );
        transcript
            .append(
                b"private [SIGNER_ADMISSION_V1 {\"private\":\"payload\"}]\n",
                root,
            )
            .unwrap();
        transcript.consume(None).unwrap();
        assert_eq!(transcript.admission_diagnostic_lines().len(), 3);
        assert!(transcript
            .admission_diagnostic_lines()
            .iter()
            .all(|line| !line.contains("private")));
        transcript
            .append(
                b"CI_SYNTHETIC_SIGNER_ADMISSION invalid=true details_withheld=true\n",
                root,
            )
            .unwrap();
        transcript.consume(None).unwrap();
        assert!(transcript.admission_diagnostic_lines()[1].contains("invalid=true"));
    }

    #[test]
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn admission_optional_copies_yield_to_original_chunk_budget() {
        let root = Path::new("/tmp/owned");
        let mut measured = Transcript::new([]).unwrap();
        let mut original = Transcript::new([]).unwrap();
        let line = format!(
            "[WITNESS_ADMISSION_V1 {}]\n",
            super::super::safe_diagnostics_v1::WITNESS_ADMISSION_TEST_JSON
        );
        measured.append(line.as_bytes(), root).unwrap();
        measured.consume(None).unwrap();
        assert!(measured.admission_diagnostic_retained_bytes() > 0);
        let chunk = vec![b'x'; MAX_BYTES - original.timing_retained_bytes()];
        original.append(&chunk, root).unwrap();
        measured.append(&chunk, root).unwrap();
        assert_eq!(measured.retained_bytes(), original.retained_bytes());
        assert_eq!(measured.admission_diagnostic_retained_bytes(), 0);
        assert!(measured.admission_diagnostic_lines()[0].contains("invalid=true"));
        assert_eq!(original.append(b"x", root), Err(Failure::OutputLimit));
        assert_eq!(measured.append(b"x", root), Err(Failure::OutputLimit));
    }

    #[test]
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn admission_optional_copies_yield_to_original_metadata_budget() {
        let root = Path::new("/tmp/owned");
        for metadata in [
            "[JOINED_DIAGNOSTIC Bootstrap Begin]\n",
            "SYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/exact\n",
        ] {
            let mut measured = Transcript::new([MARKER]).unwrap();
            let mut original = Transcript::new([MARKER]).unwrap();
            let line = format!(
                "[SIGNER_ADMISSION_V1 {}]\n",
                super::super::safe_diagnostics_v1::SIGNER_ADMISSION_TEST_JSON
            );
            measured.append(line.as_bytes(), root).unwrap();
            measured.consume(None).unwrap();
            let captured = measured.admission_diagnostic_retained_bytes();
            let filler =
                MAX_BYTES - measured.timing_retained_bytes() - captured - metadata.len() - 1;
            let mut chunk = vec![b'x'; filler];
            chunk.push(b'\n');
            chunk.extend_from_slice(metadata.as_bytes());
            original.append(&chunk, root).unwrap();
            measured.append(&chunk, root).unwrap();
            assert_eq!(measured.admission_diagnostic_retained_bytes(), 0);
            assert_eq!(measured.retained_bytes(), original.retained_bytes());
            assert_eq!(measured.summary(), original.summary());
            assert!(measured.admission_diagnostic_lines()[0].contains("invalid=true"));
        }
    }
    #[test]
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn durable_flow_survives_split_lines_and_compaction() {
        let root = Path::new("/tmp/owned");
        let mut transcript = Transcript::new([]).unwrap();
        let line = format!(
            "[DURABLE_FLOW_V1 {}]\r\n",
            super::super::safe_diagnostics_v1::DURABLE_FLOW_MAXIMAL_TEST_JSON
        );
        let split = line.len() / 2;
        transcript.append(&line.as_bytes()[..split], root).unwrap();
        assert!(transcript.durable_flow_lines().is_empty());
        transcript.append(&line.as_bytes()[split..], root).unwrap();
        transcript.consume(None).unwrap();
        assert!(transcript.bytes.is_empty());
        assert_eq!(transcript.durable_flow_lines().len(), 1);
        assert_eq!(
            transcript.retained_bytes(),
            transcript.timing_retained_bytes() + transcript.durable_flow_retained_bytes()
        );
        assert!(transcript.durable_flow_lines()[0].starts_with("CI_SYNTHETIC_DURABLE_FLOW {"));
        transcript.append(line.as_bytes(), root).unwrap();
        assert!(transcript.durable_flow_lines()[0].contains("invalid=true"));
    }
    #[test]
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn durable_flow_optional_copy_yields_to_original_chunk_budget() {
        let root = Path::new("/tmp/owned");
        let mut measured = Transcript::new([]).unwrap();
        let mut original = Transcript::new([]).unwrap();
        let line = format!(
            "[DURABLE_FLOW_V1 {}]\n",
            super::super::safe_diagnostics_v1::DURABLE_FLOW_MAXIMAL_TEST_JSON
        );
        measured.append(line.as_bytes(), root).unwrap();
        measured.consume(None).unwrap();
        assert!(measured.durable_flow_retained_bytes() > 0);
        let chunk = vec![b'x'; MAX_BYTES - original.timing_retained_bytes()];
        original.append(&chunk, root).unwrap();
        measured.append(&chunk, root).unwrap();
        assert_eq!(measured.retained_bytes(), original.retained_bytes());
        assert_eq!(measured.durable_flow_retained_bytes(), 0);
        assert!(measured.durable_flow_lines()[0].contains("invalid=true"));
        assert_eq!(original.append(b"x", root), Err(Failure::OutputLimit));
        assert_eq!(measured.append(b"x", root), Err(Failure::OutputLimit));
    }
    #[test]
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn durable_flow_optional_copy_yields_to_original_metadata_budget() {
        let root = Path::new("/tmp/owned");
        for metadata in [
            "[JOINED_DIAGNOSTIC Bootstrap Begin]\n",
            "SYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/exact\n",
        ] {
            let mut measured = Transcript::new([MARKER]).unwrap();
            let mut original = Transcript::new([MARKER]).unwrap();
            let line = format!(
                "[DURABLE_FLOW_V1 {}]\n",
                super::super::safe_diagnostics_v1::DURABLE_FLOW_MAXIMAL_TEST_JSON
            );
            measured.append(line.as_bytes(), root).unwrap();
            measured.consume(None).unwrap();
            let filler = MAX_BYTES
                - measured.timing_retained_bytes()
                - measured.durable_flow_retained_bytes()
                - metadata.len()
                - 1;
            let mut chunk = vec![b'x'; filler];
            chunk.push(b'\n');
            chunk.extend_from_slice(metadata.as_bytes());
            original.append(&chunk, root).unwrap();
            measured.append(&chunk, root).unwrap();
            assert_eq!(measured.durable_flow_retained_bytes(), 0);
            assert_eq!(measured.retained_bytes(), original.retained_bytes());
            assert_eq!(measured.summary(), original.summary());
            assert!(measured.durable_flow_lines()[0].contains("invalid=true"));
        }
    }
    #[test]
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn durable_lifecycle_split_compaction_and_pairing() {
        let root = Path::new("/tmp/owned");
        let mut transcript = Transcript::new([]).unwrap();
        let flow = format!(
            "[DURABLE_FLOW_V1 {}]\n",
            super::super::safe_diagnostics_v1::DURABLE_FLOW_MAXIMAL_TEST_JSON
        );
        let lifecycle = format!(
            "[DURABLE_LIFECYCLE_V1 {}]\r\n",
            super::super::safe_diagnostics_v1::DURABLE_LIFECYCLE_MAXIMAL_TEST_JSON
        );
        transcript.append(flow.as_bytes(), root).unwrap();
        let split = lifecycle.len() / 2;
        transcript
            .append(&lifecycle.as_bytes()[..split], root)
            .unwrap();
        assert!(transcript.durable_lifecycle_lines().is_empty());
        transcript
            .append(&lifecycle.as_bytes()[split..], root)
            .unwrap();
        transcript.consume(None).unwrap();
        assert!(transcript.bytes.is_empty());
        assert!(
            transcript.durable_lifecycle_lines()[0].starts_with("CI_SYNTHETIC_DURABLE_LIFECYCLE {")
        );
        assert_eq!(
            transcript.retained_bytes(),
            transcript.timing_retained_bytes()
                + transcript.durable_flow_retained_bytes()
                + transcript.durable_lifecycle_retained_bytes()
        );
        transcript.append(lifecycle.as_bytes(), root).unwrap();
        assert!(transcript.durable_lifecycle_lines()[0].contains("invalid=true"));
        assert!(!transcript.durable_flow_lines()[0].contains("invalid=true"));
    }
    #[test]
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn durable_lifecycle_optional_copy_yields_to_original_chunk_budget() {
        let root = Path::new("/tmp/owned");
        let mut measured = Transcript::new([]).unwrap();
        let mut original = Transcript::new([]).unwrap();
        let lines = format!(
            "[DURABLE_FLOW_V1 {}]\n[DURABLE_LIFECYCLE_V1 {}]\n",
            super::super::safe_diagnostics_v1::DURABLE_FLOW_MAXIMAL_TEST_JSON,
            super::super::safe_diagnostics_v1::DURABLE_LIFECYCLE_MAXIMAL_TEST_JSON
        );
        measured.append(lines.as_bytes(), root).unwrap();
        measured.consume(None).unwrap();
        assert!(measured.durable_lifecycle_retained_bytes() > 0);
        let chunk = vec![b'x'; MAX_BYTES - original.timing_retained_bytes()];
        original.append(&chunk, root).unwrap();
        measured.append(&chunk, root).unwrap();
        assert_eq!(measured.retained_bytes(), original.retained_bytes());
        assert_eq!(measured.durable_lifecycle_retained_bytes(), 0);
        assert_eq!(measured.durable_flow_retained_bytes(), 0);
        assert!(measured.durable_lifecycle_lines()[0].contains("invalid=true"));
        assert_eq!(original.append(b"x", root), Err(Failure::OutputLimit));
        assert_eq!(measured.append(b"x", root), Err(Failure::OutputLimit));
    }
    #[test]
    #[cfg(feature = "synthetic-born-joined-qualification")]
    fn durable_lifecycle_optional_copy_yields_to_original_metadata_budget() {
        let root = Path::new("/tmp/owned");
        for metadata in [
            "[JOINED_DIAGNOSTIC Bootstrap Begin]\n",
            "SYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/exact\n",
        ] {
            let mut measured = Transcript::new([MARKER]).unwrap();
            let mut original = Transcript::new([MARKER]).unwrap();
            let lines = format!(
                "[DURABLE_FLOW_V1 {}]\n[DURABLE_LIFECYCLE_V1 {}]\n",
                super::super::safe_diagnostics_v1::DURABLE_FLOW_MAXIMAL_TEST_JSON,
                super::super::safe_diagnostics_v1::DURABLE_LIFECYCLE_MAXIMAL_TEST_JSON
            );
            measured.append(lines.as_bytes(), root).unwrap();
            measured.consume(None).unwrap();
            let filler = MAX_BYTES
                - measured.timing_retained_bytes()
                - measured.durable_flow_retained_bytes()
                - measured.durable_lifecycle_retained_bytes()
                - metadata.len()
                - 1;
            let mut chunk = vec![b'x'; filler];
            chunk.push(b'\n');
            chunk.extend_from_slice(metadata.as_bytes());
            original.append(&chunk, root).unwrap();
            measured.append(&chunk, root).unwrap();
            assert_eq!(measured.durable_lifecycle_retained_bytes(), 0);
            assert_eq!(measured.durable_flow_retained_bytes(), 0);
            assert_eq!(measured.retained_bytes(), original.retained_bytes());
            assert_eq!(measured.summary(), original.summary());
            assert!(measured.durable_lifecycle_lines()[0].contains("invalid=true"));
        }
    }

    #[test]
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    fn private_fixed_diagnostic_all_fragment_boundaries_survive_consume() {
        let root = Path::new("/tmp/owned");
        let line = format!(
            "CI_SYNTHETIC_PRIVATE_FIXED_DIAGNOSTIC {}\r\n",
            super::super::safe_diagnostics_v1::PRIVATE_FIXED_DIAGNOSTIC_TEST_JSON
        );
        for split in 0..line.len() {
            let mut transcript = Transcript::new([]).unwrap();
            transcript.append(&line.as_bytes()[..split], root).unwrap();
            assert!(transcript.private_fixed_diagnostic().is_none());
            transcript.consume(None).unwrap();
            transcript.append(&line.as_bytes()[split..], root).unwrap();
            transcript.consume(None).unwrap();
            transcript.finish_private_fixed_diagnostic();
            assert!(transcript.private_fixed_diagnostic().is_some());
            assert!(transcript.bytes.is_empty());
            assert_eq!(
                transcript.retained_bytes(),
                transcript.timing_retained_bytes()
                    + transcript.private_fixed_diagnostic_retained_bytes()
            );
        }
        let mut transcript = Transcript::new([]).unwrap();
        transcript
            .append("private é".as_bytes().split_last().unwrap().1, root)
            .unwrap();
        transcript.append(&[0xa9, b'\n'], root).unwrap();
        transcript.append(line.as_bytes(), root).unwrap();
        assert!(transcript.private_fixed_diagnostic().is_some());
    }
    #[test]
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    fn private_fixed_diagnostic_counts_against_original_aggregate_budget() {
        let root = Path::new("/tmp/owned");
        // Exercise all three pre-existing pressure sites: raw append, closed
        // diagnostic history and exact retained path metadata.
        for metadata in [
            None,
            Some("[JOINED_DIAGNOSTIC Bootstrap Begin]\n"),
            Some("SYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/exact\n"),
        ] {
            let mut measured = Transcript::new([MARKER]).unwrap();
            let mut original = Transcript::new([MARKER]).unwrap();
            let history = format!(
                "[HISTORY_MEASUREMENT_V1 {}]\n",
                super::super::safe_diagnostics_v1::HISTORY_MEASUREMENT_TEST_JSON
            );
            measured.append(history.as_bytes(), root).unwrap();
            measured.consume(None).unwrap();
            original.append(history.as_bytes(), root).unwrap();
            original.consume(None).unwrap();
            let line = format!(
                "CI_SYNTHETIC_PRIVATE_FIXED_DIAGNOSTIC {}\n",
                super::super::safe_diagnostics_v1::PRIVATE_FIXED_DIAGNOSTIC_TEST_JSON
            );
            measured.append(line.as_bytes(), root).unwrap();
            measured.consume(None).unwrap();
            let captured = measured.private_fixed_diagnostic_retained_bytes();
            assert!(captured > 0);
            let chunk = if let Some(metadata) = metadata {
                let filler = MAX_BYTES - original.retained_bytes() - captured - metadata.len() - 1;
                let mut chunk = vec![b'x'; filler];
                chunk.push(b'\n');
                chunk.extend_from_slice(metadata.as_bytes());
                chunk
            } else {
                vec![b'x'; MAX_BYTES - original.retained_bytes()]
            };
            original.append(&chunk, root).unwrap();
            measured.append(&chunk, root).unwrap();
            assert_eq!(measured.private_fixed_diagnostic_retained_bytes(), 0);
            assert!(measured.diagnostic_withheld());
            assert!(measured.history_measurement_retained_bytes() > 0);
            assert_eq!(measured.retained_bytes(), original.retained_bytes());
            assert_eq!(measured.summary(), original.summary());
            if metadata.is_none() {
                let freed = original.history_measurement_retained_bytes();
                original.append(&vec![b'x'; freed], root).unwrap();
                measured.append(&vec![b'x'; freed], root).unwrap();
                assert_eq!(original.append(b"x", root), Err(Failure::OutputLimit));
                assert_eq!(measured.append(b"x", root), Err(Failure::OutputLimit));
            }
        }
    }
    #[test]
    #[cfg(all(
        feature = "durable-proposal",
        feature = "synthetic-born-joined-qualification"
    ))]
    fn private_fixed_diagnostic_duplicate_and_partial_records_are_unavailable() {
        let root = Path::new("/tmp/owned");
        let line = format!(
            "CI_SYNTHETIC_PRIVATE_FIXED_DIAGNOSTIC {}\n",
            super::super::safe_diagnostics_v1::PRIVATE_FIXED_DIAGNOSTIC_TEST_JSON
        );
        for second in [
            line.as_bytes(),
            b"CI_SYNTHETIC_PRIVATE_FIXED_DIAGNOSTIC_UNAVAILABLE\n",
            b"CI_SYNTHETIC_PRIVATE_FIXED_DIAGNOSTIC {private",
        ] {
            let mut transcript = Transcript::new([]).unwrap();
            transcript.append(line.as_bytes(), root).unwrap();
            transcript.consume(None).unwrap();
            let captured = transcript.private_fixed_diagnostic_retained_bytes();
            transcript.append(second, root).unwrap();
            transcript.finish_private_fixed_diagnostic();
            assert!(
                transcript.private_fixed_diagnostic().is_none() && transcript.diagnostic_withheld()
            );
            assert_eq!(
                transcript.private_fixed_diagnostic_retained_bytes(),
                captured
            );
        }
        let mut transcript = Transcript::new([]).unwrap();
        transcript
            .append(format!("private review {line}").as_bytes(), root)
            .unwrap();
        transcript.finish_private_fixed_diagnostic();
        assert!(
            transcript.private_fixed_diagnostic().is_none() && !transcript.diagnostic_withheld()
        );
    }
}

#[cfg(all(
    test,
    feature = "durable-proposal",
    feature = "synthetic-born-joined-qualification"
))]
mod delivery_first_failure_tests {
    use super::*;
    const FIRST: &[u8] = b"[JOINED_DIAGNOSTIC DeliveryExportCommit EngineDisclosureUnknown]\n";
    const LATER: &[u8] = b"[JOINED_DIAGNOSTIC DeliveryArtifactImport BridgeBinding]\n";
    const MARKER: &str = "SYNTHETIC_JOINED_DRAFT_PATH=";
    fn delivery(markers: impl IntoIterator<Item = &'static str>) -> Transcript<'static> {
        let mut transcript = Transcript::new(markers).unwrap();
        transcript.enable_delivery_first_failure();
        transcript
    }
    fn labels(transcript: &Transcript<'_>) -> Option<(&'static str, &'static str)> {
        transcript
            .delivery_first_failure()
            .map(|pair| pair.labels())
    }
    #[test]
    fn delivery_first_failure_survives_more_than_64_later_diagnostics() {
        let root = Path::new("/tmp/owned");
        let mut transcript = delivery([]);
        transcript.append(FIRST, root).unwrap();
        transcript.consume(None).unwrap();
        let pair_bytes = "DeliveryExportCommit:EngineDisclosureUnknown".len();
        assert_eq!(
            transcript.delivery_first_failure_retained_bytes(),
            pair_bytes
        );
        assert_eq!(
            transcript.retained_bytes(),
            pair_bytes + transcript.summary().len() + transcript.timing_retained_bytes()
        );
        for _ in 0..80 {
            transcript.append(LATER, root).unwrap();
            transcript.consume(None).unwrap();
        }
        assert_eq!(transcript.summary().split(',').count(), MAX_DIAGNOSTICS);
        assert!(!transcript.summary().contains("DeliveryExportCommit"));
        assert_eq!(
            labels(&transcript),
            Some(("DeliveryExportCommit", "EngineDisclosureUnknown"))
        );
    }
    #[test]
    fn delivery_first_failure_requires_complete_exact_finite_marker() {
        let root = Path::new("/tmp/owned");
        let mut transcript = delivery([]);
        for invalid in [
            "[JOINED_DIAGNOSTIC DeliverySourceOpen Begin]\n",
            "[JOINED_DIAGNOSTIC DeliveryExportCommit Complete]\n",
            "[JOINED_DIAGNOSTIC Bootstrap HostInvalid]\n",
            "[JOINED_IO DeliveryExportCommit Other 1]\n",
            "prefix [JOINED_DIAGNOSTIC DeliveryExportCommit HostInvalid]\n",
            "[JOINED_DIAGNOSTIC DeliveryExportCommit HostInvalid] suffix\n",
            "[JOINED_DIAGNOSTIC DeliveryExportCommit HostInvalid extra]\n",
            "[JOINED_DIAGNOSTIC DeliveryExportCommit unknown-private]\n",
            "[JOINED_DIAGNOSTIC unknown-private HostInvalid]\n",
            "[JOINED_DIAGNOSTIC DeliveryExportCommit HostInvalid]\r\r\n",
            "[JOINED_DIAGNOSTIC DeliveryExportCommit HostInvalid][JOINED_DIAGNOSTIC DeliverySourceOpen HostInvalid]\n",
        ] {
            transcript.append(invalid.as_bytes(), root).unwrap();
            assert!(labels(&transcript).is_none());
            transcript.consume(None).unwrap();
        }
        transcript.append(&FIRST[..FIRST.len() - 1], root).unwrap();
        assert!(labels(&transcript).is_none());
        transcript.append(b"\r\n", root).unwrap();
        assert_eq!(
            labels(&transcript),
            Some(("DeliveryExportCommit", "EngineDisclosureUnknown"))
        );
        transcript.append(LATER, root).unwrap();
        assert_eq!(
            labels(&transcript),
            Some(("DeliveryExportCommit", "EngineDisclosureUnknown"))
        );
    }
    #[test]
    fn delivery_first_failure_is_opt_in_and_isolated_per_child() {
        let root = Path::new("/tmp/owned");
        let mut old_adapter = Transcript::new([]).unwrap();
        let mut producer = delivery([]);
        let mut reader = delivery([]);
        old_adapter.append(FIRST, root).unwrap();
        producer.append(FIRST, root).unwrap();
        assert!(labels(&old_adapter).is_none());
        assert!(labels(&reader).is_none());
        reader.append(LATER, root).unwrap();
        assert_eq!(
            labels(&producer),
            Some(("DeliveryExportCommit", "EngineDisclosureUnknown"))
        );
        assert_eq!(
            labels(&reader),
            Some(("DeliveryArtifactImport", "BridgeBinding"))
        );
        assert_eq!(old_adapter.summary(), producer.summary());
        assert_eq!(
            producer.retained_bytes() - old_adapter.retained_bytes(),
            producer.delivery_first_failure_retained_bytes()
        );
    }
    #[test]
    fn delivery_first_failure_yields_to_chunk_budget_and_never_recaptures() {
        let root = Path::new("/tmp/owned");
        for initially_captured in [false, true] {
            let mut transcript = delivery([]);
            let mut original = Transcript::new([]).unwrap();
            if initially_captured {
                transcript.append(FIRST, root).unwrap();
                original.append(FIRST, root).unwrap();
                transcript.consume(None).unwrap();
                original.consume(None).unwrap();
            }
            let mut fill = vec![b'x'; MAX_BYTES - original.retained_bytes()];
            *fill.last_mut().unwrap() = b'\n';
            transcript.append(&fill, root).unwrap();
            original.append(&fill, root).unwrap();
            assert_eq!(transcript.retained_bytes(), original.retained_bytes());
            assert_eq!(transcript.append(b"x", root), Err(Failure::OutputLimit));
            assert_eq!(original.append(b"x", root), Err(Failure::OutputLimit));
            transcript.consume(None).unwrap();
            transcript.enable_delivery_first_failure(); // Cannot reset Unavailable.
            transcript.append(LATER, root).unwrap();
            assert!(labels(&transcript).is_none());
            assert_eq!(transcript.delivery_first_failure_retained_bytes(), 0);
            assert!(matches!(
                transcript.delivery_first_failure,
                Some(super::super::safe_diagnostics_v1::DeliveryFailureCapture::Unavailable)
            ));
        }
    }
    #[test]
    fn delivery_first_failure_yields_to_summary_and_path_metadata_budget() {
        let root = Path::new("/tmp/owned");
        for metadata in [
            "[JOINED_DIAGNOSTIC Bootstrap Begin]\n",
            "SYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/exact\n",
        ] {
            let mut transcript = delivery([MARKER]);
            let mut original = Transcript::new([MARKER]).unwrap();
            transcript.append(FIRST, root).unwrap();
            original.append(FIRST, root).unwrap();
            transcript.consume(None).unwrap();
            original.consume(None).unwrap();
            let mut chunk =
                vec![b'x'; MAX_BYTES - transcript.retained_bytes() - metadata.len() - 1];
            chunk.push(b'\n');
            chunk.extend_from_slice(metadata.as_bytes());
            transcript.append(&chunk, root).unwrap();
            original.append(&chunk, root).unwrap();
            assert!(labels(&transcript).is_none());
            assert_eq!(transcript.retained_bytes(), original.retained_bytes());
            assert_eq!(transcript.summary(), original.summary());
            transcript.consume(None).unwrap();
            transcript.append(LATER, root).unwrap();
            assert!(labels(&transcript).is_none());
        }
    }
    #[test]
    fn delivery_first_failure_yields_before_existing_optional_capture_budget() {
        use super::super::safe_diagnostics_v1 as diagnostics;
        let root = Path::new("/tmp/owned");
        for record in [
            format!(
                "[HISTORY_MEASUREMENT_V1 {}]",
                diagnostics::HISTORY_MEASUREMENT_TEST_JSON
            ),
            format!(
                "[ADMISSION_MEASUREMENT_V1 {}]",
                diagnostics::ADMISSION_MEASUREMENT_TEST_JSON
            ),
            format!(
                "[DURABLE_FLOW_V1 {}]",
                diagnostics::DURABLE_FLOW_MAXIMAL_TEST_JSON
            ),
            format!(
                "[DURABLE_LIFECYCLE_V1 {}]",
                diagnostics::DURABLE_LIFECYCLE_MAXIMAL_TEST_JSON
            ),
            format!(
                "CI_SYNTHETIC_PRIVATE_FIXED_DIAGNOSTIC {}",
                diagnostics::PRIVATE_FIXED_DIAGNOSTIC_TEST_JSON
            ),
        ] {
            let mut transcript = delivery([]);
            let mut original = Transcript::new([]).unwrap();
            transcript.append(FIRST, root).unwrap();
            original.append(FIRST, root).unwrap();
            transcript.consume(None).unwrap();
            original.consume(None).unwrap();
            let required = transcript
                .history_measurements
                .additional_bytes_for_line(&record)
                .or_else(|| {
                    transcript
                        .admission_diagnostics
                        .additional_bytes_for_line(&record)
                })
                .or_else(|| transcript.durable_flow.additional_bytes_for_line(&record))
                .or_else(|| {
                    transcript
                        .durable_lifecycle
                        .additional_bytes_for_line(&record)
                })
                .or_else(|| {
                    transcript
                        .private_fixed_diagnostic
                        .additional_bytes_for_line(&record)
                })
                .unwrap();
            // Raw line plus old capture fit exactly without the optional pair.
            let filler = MAX_BYTES - original.retained_bytes() - required - record.len() - 2;
            let mut chunk = vec![b'x'; filler];
            chunk.push(b'\n');
            chunk.extend_from_slice(record.as_bytes());
            chunk.push(b'\n');
            original.append(&chunk, root).unwrap();
            transcript.append(&chunk, root).unwrap();
            assert!(labels(&transcript).is_none());
            assert_eq!(transcript.retained_bytes(), original.retained_bytes());
            assert_eq!(
                transcript.history_measurement_lines(),
                original.history_measurement_lines()
            );
            assert_eq!(
                transcript.admission_diagnostic_lines(),
                original.admission_diagnostic_lines()
            );
            assert_eq!(
                transcript.durable_flow_lines(),
                original.durable_flow_lines()
            );
            assert_eq!(
                transcript.durable_lifecycle_lines(),
                original.durable_lifecycle_lines()
            );
            assert_eq!(
                transcript.private_fixed_diagnostic_retained_bytes(),
                original.private_fixed_diagnostic_retained_bytes()
            );
            assert_eq!(
                transcript.diagnostic_withheld(),
                original.diagnostic_withheld()
            );
        }
    }
    #[test]
    fn delivery_first_failure_yields_before_position_budget_refusals() {
        let root = Path::new("/tmp/owned");
        for operation in 0..3 {
            let mut transcript = delivery([MARKER]);
            transcript.append(FIRST, root).unwrap();
            transcript.base = usize::MAX;
            let refused = match operation {
                0 => transcript.append(b"SYNTHETIC_JOINED_DRAFT_PATH=/tmp/owned/exact\n", root),
                1 => transcript.consume(None),
                _ => transcript.path(MARKER, 1).map(|_| ()),
            };
            assert_eq!(refused, Err(Failure::OutputLimit));
            assert!(labels(&transcript).is_none());
        }
    }
    #[test]
    fn delivery_first_failure_insufficient_capture_budget_is_sticky() {
        use super::super::safe_diagnostics_v1::DeliveryFailureCapture;
        let mut capture = DeliveryFailureCapture::default();
        capture.capture_complete_line(&FIRST[..FIRST.len() - 1], 0);
        assert!(matches!(capture, DeliveryFailureCapture::Unavailable));
        capture.capture_complete_line(&LATER[..LATER.len() - 1], MAX_BYTES);
        assert!(capture.value().is_none());
    }
}

#[test]
#[cfg(all(
    feature = "durable-proposal",
    feature = "synthetic-born-joined-qualification"
))]
fn financial_diagnostic_survives_all_fragment_boundaries() {
    use crate::host::financial_diagnostics_v1::{
        FinancialCommitStateV1 as K, FinancialComponentV1 as C, FinancialDiagnosticV1,
        FinancialErrorClassV1 as E, FinancialStageV1 as S,
    };
    let value = FinancialDiagnosticV1 {
        schema: 1,
        stage: S::ResultFinishAcknowledgement,
        component: C::SignerBridge,
        error_class: E::Uncertain,
        commit_state: K::IntakeCommitted,
        current_timing: None,
        authority_call: None,
    };
    let json = serde_json::to_string(&value).unwrap();
    let line = format!("[FINANCIAL_DIAGNOSTIC_V1 {json}]\r\n");
    for split in 0..line.len() {
        let mut transcript = Transcript::new([]).unwrap();
        transcript
            .append(&line.as_bytes()[..split], Path::new("/tmp/owned"))
            .unwrap();
        assert!(transcript.financial_diagnostic().is_none());
        transcript
            .append(&line.as_bytes()[split..], Path::new("/tmp/owned"))
            .unwrap();
        transcript.finish_private_fixed_diagnostic();
        assert_eq!(transcript.financial_diagnostic(), Some(&value));
        assert!(transcript.retained_bytes() <= MAX_BYTES);
    }
}

#[cfg(all(
    test,
    feature = "durable-proposal",
    feature = "synthetic-born-joined-qualification"
))]
#[test]
fn financial_progress_fragmented_lines_and_legacy_disabled() {
    use super::financial_progress_v1::{Phase, Reason};
    let line =
        b"[FINANCIAL_PROGRESS_V1 {\"kind\":\"Begin\",\"owner\":1,\"phase\":\"SourceOpen\"}]\r\n";
    for split in 0..line.len() {
        let mut transcript = Transcript::new(std::iter::empty::<&str>()).unwrap();
        transcript.enable_financial_progress();
        transcript
            .append(&line[..split], Path::new("/tmp/owned"))
            .unwrap();
        assert!(transcript.financial_progress_failure().is_none());
        transcript
            .append(&line[split..], Path::new("/tmp/owned"))
            .unwrap();
        let failure = transcript
            .financial_progress_check(
                std::time::Instant::now() + std::time::Duration::from_secs(121),
            )
            .unwrap();
        assert_eq!(failure.reason, Reason::PhaseDeadline);
        assert_eq!(failure.last.unwrap().phase, Phase::SourceOpen);
    }
    let mut transcript = Transcript::new(std::iter::empty::<&str>()).unwrap();
    transcript.append(line, Path::new("/tmp/owned")).unwrap();
    assert!(transcript
        .financial_progress_check(std::time::Instant::now() + std::time::Duration::from_secs(901))
        .is_none());
    transcript.financial_progress_global_deadline();
    assert!(transcript.financial_progress_failure().is_none());
}
