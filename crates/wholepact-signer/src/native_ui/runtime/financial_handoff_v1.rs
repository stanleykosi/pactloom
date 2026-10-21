//! Deliberate, inert metadata handoff from the original financial UI. These
//! encodings contain no private-key material, signature bytes, native decision or
//! authenticated owner. The receiving Host must authenticate the exact original
//! histories and installed provider through its maintained protected IPC path.
use super::{financial_v1::FinancialPhaseV1, NativeRuntime};
use crate::{authority_bridge::financial_continuation_v1::FinancialResultRequestV1, Error, Result};
use eframe::egui;
use serde::Serialize;
use std::{io::Write, path::Path};
use wholepact_authority::{OwnerControl, OwnerControlRequest};

// Matches the foreground Host's closed selector-file input bound. Compact JSON
// is intentional: the envelope itself must fit, not merely its inner request.
const MAX_SELECTION_BYTES: usize = 262_144;

#[derive(Serialize)]
struct ContinuationSelectionV1<'a> {
    version: u16,
    continuation: &'a OwnerControlRequest,
}

#[derive(Serialize)]
struct ResultSelectionV1<'a> {
    version: u16,
    signer_socket: &'a str,
    request: &'a FinancialResultRequestV1,
}

enum ContinuationDestinationV1 {
    OriginalHost,
    OriginalWitness,
}

struct BoundedSelection(Vec<u8>);
impl Write for BoundedSelection {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|n| n > MAX_SELECTION_BYTES)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "financial selection exceeds its closed bound",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode_selection(value: &impl Serialize) -> Result<String> {
    let mut output = BoundedSelection(Vec::new());
    serde_json::to_writer(&mut output, value).map_err(|_| Error::InvalidData)?;
    String::from_utf8(output.0).map_err(|_| Error::InvalidData)
}

fn continuation_selection(
    request: &OwnerControlRequest,
    destination: ContinuationDestinationV1,
) -> Result<String> {
    let OwnerControl::AdmitFinancialContinuationV1 { record } = &request.control else {
        return Err(Error::ReviewMismatch);
    };
    record
        .validate_request(request, &record.terms.scope.witness)
        .map_err(|_| Error::InvalidData)?;
    match destination {
        ContinuationDestinationV1::OriginalHost => encode_selection(&ContinuationSelectionV1 {
            version: 1,
            continuation: request,
        }),
        // The existing native Witness UI consumes the exact raw request. Do
        // not change its authority/parser boundary to accept a Host envelope.
        ContinuationDestinationV1::OriginalWitness => encode_selection(request),
    }
}

fn result_selection(endpoint: &Path, request: &FinancialResultRequestV1) -> Result<String> {
    if !endpoint.is_absolute() {
        return Err(Error::InvalidData);
    }
    let signer_socket = endpoint.to_str().ok_or(Error::InvalidData)?;
    if signer_socket.len() > 4096 || signer_socket.chars().any(char::is_control) {
        return Err(Error::InvalidData);
    }
    request.validate().map_err(|_| Error::InvalidData)?;
    encode_selection(&ResultSelectionV1 {
        version: 1,
        signer_socket,
        request,
    })
}

impl NativeRuntime {
    pub(super) fn financial_handoff_ui_v1(&mut self, ui: &mut egui::Ui, focused: bool) {
        // The containing financial UI already polls the current focus epoch and
        // revokes on focus loss. This helper must never add a bypass or preserve
        // a stale editable selection when the phase changes.
        if !focused || self.pending.is_some() {
            return;
        }
        let phase = self.financial_phase_v1();
        let label = match phase {
            Some(FinancialPhaseV1::AwaitingAdmission) => {
                "Copy exact continuation selector for Host (metadata only)"
            }
            Some(FinancialPhaseV1::AwaitingReturn) => {
                "Copy exact result-request selector for Host (metadata only)"
            }
            _ => return,
        };
        ui.label("Selection data only, not proof of approval or permission. No key or signature bytes are copied. The Host must verify the exact original history and installed Signer.");
        ui.label("Copied financial metadata may be sensitive. Give it only to the intended original Host or Witness.");
        ui.label("Keep this Signer focused and the original Host running. Leaving this window locks the financial workflow; copying does not allow it to resume or renew its expiry.");
        let witness_request = phase == Some(FinancialPhaseV1::AwaitingAdmission)
            && ui
                .button("Copy exact continuation request for Witness (metadata only)")
                .clicked_by(egui::PointerButton::Primary);
        let host_selection = ui.button(label).clicked_by(egui::PointerButton::Primary);
        if !witness_request && !host_selection {
            return;
        }
        // Re-read the phase and exact existing getter only for the explicit
        // click. No buffer is retained and no financial effect is invoked here.
        let selection = if self.pending.is_some()
            || self.financial_phase_v1() != phase
            || (witness_request && host_selection)
        {
            Err(Error::ReviewMismatch)
        } else {
            match phase {
                Some(FinancialPhaseV1::AwaitingAdmission) => self
                    .financial_pending_continuation_v1()
                    .ok_or(Error::Unavailable)
                    .and_then(|request| {
                        continuation_selection(
                            request,
                            if witness_request {
                                ContinuationDestinationV1::OriginalWitness
                            } else {
                                ContinuationDestinationV1::OriginalHost
                            },
                        )
                    }),
                Some(FinancialPhaseV1::AwaitingReturn) => {
                    self.financial_result_request_v1().and_then(|request| {
                        result_selection(&self.financial_result_endpoint_v1()?, &request)
                    })
                }
                _ => Err(Error::ReviewMismatch),
            }
        };
        match selection {
            Ok(json) => {
                ui.ctx().copy_text(json);
                self.message = "Exact inert selector copied. No approval, signature, new request or renewed expiry was created.";
            }
            Err(_) => {
                self.message = "Exact selector unavailable or outside its closed bound. Nothing was copied; preserve the original state.";
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_encoding_includes_envelope_in_exact_bound() {
        let exact = "x".repeat(MAX_SELECTION_BYTES - 2);
        assert_eq!(encode_selection(&exact).unwrap().len(), MAX_SELECTION_BYTES);
        assert!(encode_selection(&format!("{exact}x")).is_err());
    }

    #[test]
    fn bounded_writer_does_not_append_an_overflowing_fragment() {
        let mut writer = BoundedSelection(vec![b'x'; MAX_SELECTION_BYTES - 1]);
        assert!(writer.write_all(b"yz").is_err());
        assert_eq!(writer.0.len(), MAX_SELECTION_BYTES - 1);
        writer.write_all(b"z").unwrap();
        assert_eq!(writer.0.len(), MAX_SELECTION_BYTES);
    }

    #[test]
    fn handoff_rejects_other_owner_control_purposes() {
        let request = OwnerControlRequest {
            operation_id: "inert-test-operation".into(),
            account_id: "a".repeat(64),
            network_profile_id: "inert-test-network".into(),
            expected_head: wholepact_authority::AuthorityHead {
                sequence: 5,
                digest: "b".repeat(64),
            },
            writer_epoch: 1,
            control: OwnerControl::Pause,
        };
        assert!(continuation_selection(&request, ContinuationDestinationV1::OriginalHost).is_err());
        assert!(
            continuation_selection(&request, ContinuationDestinationV1::OriginalWitness).is_err()
        );
        // Serialization is an exact, closed data envelope, never an approval.
        let value: serde_json::Value = serde_json::from_str(
            &encode_selection(&ContinuationSelectionV1 {
                version: 1,
                continuation: &request,
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(value.as_object().unwrap().len(), 2);
        assert_eq!(value["version"], 1);
        assert_eq!(
            value["continuation"],
            serde_json::to_value(&request).unwrap()
        );
    }
}
