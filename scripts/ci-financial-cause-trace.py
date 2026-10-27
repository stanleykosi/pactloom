#!/usr/bin/env python3
"""P75/P77/P80 exact-source cause-boundary and retirement ordering trace, not an authority fixture.

Unmodified relay pump/finish/Drop, custody/owner Drop and finite Slots methods
are executed with inert lifecycle, child and append adapters. No HostOrigin,
Final, process, socket, TLS or native actor is constructed. The Signer wrapper
is unmodified; its failure carrier/classifier are explicitly inert diagnostic
adapters, not actual transport. Actual Reporter/WRITER tests run separately.
P77 also executes selected retirement methods/guards and ordinary receive code
with inert packets/custody dependencies, not authenticated production authority.
P80 executes exact terminal report arms and typed resume tail with inert carriers;
DTO validation and native UI authority are not exercised.
Default requires exact pinned rustc; --source-only explicitly does NOT run Rust.
The script writes only to a temporary directory, never to repository sources.
"""
import argparse
import importlib.util
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PINNED_RUSTC = 'rustc 1.99.0 (b940084d7 2026-09-28)'
BASELINE = '33297608c4c7e89a8a4b662673eaa84d5d301d38'
PATHS = {'relay': 'crates/wholepact-financial-coordinator-origin/src/financial_workflow_origin.rs', 'custody': 'crates/wholepact-financial-coordinator-origin/src/fork_signer.rs', 'lifecycle': 'crates/wholepact-financial-coordinator-origin/src/host_interstage.rs', 'bootstrap': 'crates/wholepact-financial-coordinator-origin/src/bootstrap.rs', 'diagnostic': 'crates/wholepact-financial-coordinator-origin/src/financial_ci_host_diagnostics.rs', 'signer': 'crates/wholepact-signer/src/financial_ci_actor.rs'}
ANCHORS = {'relay_pump': ('relay', 'pub fn pump(&mut self)->Result<bool>'), 'relay_finish': ('relay', 'pub fn finish(mut self,work:Result<()>)'), 'relay_drop': ('relay', 'impl Drop for HostFinancialWorkflowRelayV1'), 'custody_struct': ('custody', 'pub(super) struct HostVerifierCustody'), 'custody_impl': ('custody', 'impl HostVerifierCustody'), 'custody_drop': ('custody', 'impl Drop for HostVerifierCustody'), 'owner_drop': ('lifecycle', 'impl Drop for HostLifecycleOwner'), 'codes_macro': ('diagnostic', 'macro_rules! codes'), 'slots_struct': ('diagnostic', 'struct Slots'), 'slots_new': ('diagnostic', 'const fn new()->Self'), 'slots_enter': ('diagnostic', 'fn enter(&self,pid:i32,role:u8)'), 'slots_active': ('diagnostic', 'fn active(&self,pid:i32,role:u8)'), 'slots_failure': ('diagnostic', 'fn failure(&self,pid:i32,stage:Stage,class:Class)'), 'classify_io': ('diagnostic', 'pub fn classify_io('), 'signer_wrapper': ('signer', 'pub(crate) fn admit_transport_diagnosed_result<T>')}
RESTORATION = {'crates/wholepact-financial-coordinator-origin/src/financial_workflow_origin.rs': {'baseline_sha256': '622279abb0938e482932d13841203645d7f40d79e8498c0294a9b0a96fdecfec', 'exact_inverse': [{'remove': '    pub fn pump(&mut self)->Result<bool>{let result=self.pump_inner();if result.is_err(){\n        #[cfg(wholepact_financial_rendered_host_semantic_ci)]\n        if let Err(error)=&result {crate::financial_ci_host_diagnostics::latch_failure(crate::financial_ci_host_diagnostics::Stage::RelayPump,crate::financial_ci_host_diagnostics::classify_io(error.kind()));}\n        self.lifecycle.poison();drop(self.host.take());}result}', 'restore': '    pub fn pump(&mut self)->Result<bool>{let result=self.pump_inner();if result.is_err(){self.lifecycle.poison();drop(self.host.take());}result}'}, {'remove': '        #[cfg(wholepact_financial_rendered_host_semantic_ci)]\n        if let Err(error)=&work {crate::financial_ci_host_diagnostics::latch_failure(crate::financial_ci_host_diagnostics::Stage::RelayFinish,crate::financial_ci_host_diagnostics::classify_io(error.kind()));}\n', 'restore': ''}]}, 'crates/wholepact-financial-coordinator-origin/src/fork_signer.rs': {'baseline_sha256': '6d6392d710ccc9fddb6935387dd2adc58e58e94cc157c5c10fb1895d5e313218', 'exact_inverse': [{'remove': '    fn drop(&mut self) { self.live.store(false, Ordering::Release);\n        #[cfg(wholepact_financial_rendered_host_semantic_ci)]\n        crate::financial_observer::financial_ci_flush_host_failure_before_owned_drop();\n    }', 'restore': '    fn drop(&mut self) { self.live.store(false, Ordering::Release); }'}]}}
BASE_ITEM_SHA = {'relay_drop': '07bd9f2f159f880ffc61a7c5e191b99b7a6e9fa1ac3511c8226cc4a192cab632', 'owner_drop': 'f922c11b41ff5f27fb438a921bd0bf943679ef205a4bcdd6f6fb86cd0785dc65', 'host_origin_fields': '35c2e2876890e61c7d8ea8699beb6b5e58479a7fcc77a8861e6b198298eeec4c', 'owner_struct': 'fbe4495c214174953a0c8ebd20d47b17bf40c17d952bbc8ca87a33da068b08fa'}

# Exact P89 observation-only native inverse. Restore the full H88 bytes before
# any historical P85/P77/P75 hash; no ignored region or alternate current state.
P89_RESTORATION = {'crates/wholepact-financial-coordinator-origin/src/financial_workflow_origin.rs': {'candidate_sha256': '2f878955c8a2ebe5bc5081710cf3b64ec953c924aaefc31ae83ee418fb59d96f', 'baseline_sha256': 'a3a8c9da5b5699bcbc3866622b8e0d07b7a3e28223338754129939f5621301b0', 'exact_inverse': [{'remove': '// Observation of the first failed returned operation, not its initiating cause.\n// A nested check may already have revoked/closed before it returns here.\n// Production expands to the original expression: no extra clock, IO or guard.\n#[cfg(wholepact_financial_rendered_host_semantic_ci)]\nmacro_rules! restriction_observed {\n    ($stage:ident, $operation:expr) => {\n        ($operation).inspect_err(|error| {\n            use crate::financial_ci_actor_diagnostics as d;\n            d::driver_detail(d::DriverStage::$stage,d::classify_io(error.kind()));\n        })\n    };\n    ($owner:expr, $one:ident, $two:ident, $operation:expr) => {\n        ($operation).inspect_err(|error| {\n            use crate::financial_ci_actor_diagnostics as d;\n            let stage=match $owner {0=>d::DriverStage::$one,1=>d::DriverStage::$two,_=>return};\n            d::driver_detail(stage,d::classify_io(error.kind()));\n        })\n    };\n}\n#[cfg(not(wholepact_financial_rendered_host_semantic_ci))]\nmacro_rules! restriction_observed {\n    ($stage:ident, $operation:expr) => {$operation};\n    ($owner:expr, $one:ident, $two:ident, $operation:expr) => {$operation};\n}\n\n', 'restore': ''}, {'remove': '    pub fn observe_restrictions(&self)->Result<()>{\n        let result=(||{\n            restriction_observed!(RestrictionCore, self.core.check())?;restriction_observed!(RestrictionSession, crate::channel::require_time(self.clocks.supervision()))?;\n            if self.core.phase.revoked(){return restriction_observed!(RestrictionAlreadyRevoked, Err(rejected("workflow permanently restricted")));}\n            for (i,slot) in self.v3_entries.iter().enumerate(){restriction_observed!(i, RestrictionOwner1V3Active, RestrictionOwner2V3Active, slot.observe_active(self.core.phase.phase(i),self.clocks))?;}\n            for (i,slot) in self.slots.iter().enumerate(){\n                let Some(slot)=slot else{continue};let phase=self.core.phase.phase(i);\n                if phase==ENTRY_PREPARING {\n                    restriction_observed!(i, RestrictionOwner1EntryPreparing, RestrictionOwner2EntryPreparing, self.clocks.restrict_received(PROFILE,slot.start.native_ceiling_ms,self.clocks.supervision(),Instant::now()))?;\n                }\n                if let Some(entry)=&slot.entry {\n                    restriction_observed!(i, RestrictionOwner1EntryCustody, RestrictionOwner2EntryCustody, entry.check_custody())?;\n                    if matches!(phase,ENTRY_REVIEW|ENTRY_ADMITTED){restriction_observed!(i, RestrictionOwner1EntryAction, RestrictionOwner2EntryAction, entry.check_action())?;}\n                }\n                if phase==CONT_PREPARING{\n                    let c=restriction_observed!(i, RestrictionOwner1ContinueMissing, RestrictionOwner2ContinueMissing, slot.continuation.as_ref().ok_or_else(||rejected("Continue context missing")))?;\n                    restriction_observed!(i, RestrictionOwner1ContinuePreparing, RestrictionOwner2ContinuePreparing, self.clocks.restrict_received(PROFILE,c.context.native_ceiling_ms,self.clocks.supervision(),Instant::now()))?;\n                }\n                if matches!(phase,CONT_REVIEW|CONT_ARMED|CONT_READY|CONT_ADMITTED){\n                    restriction_observed!(i, RestrictionOwner1ContinueBinding, RestrictionOwner2ContinueBinding, restriction_observed!(i, RestrictionOwner1ContinueBindingMissing, RestrictionOwner2ContinueBindingMissing, slot.continuation.as_ref().and_then(|c|c.binding.as_ref()).ok_or_else(||rejected("active Continue binding missing")))?.check(false))?;\n                }\n                if matches!(phase,READ_REVIEW|READ_ADMITTED){\n                    restriction_observed!(i, RestrictionOwner1ReadCurrent, RestrictionOwner2ReadCurrent, restriction_observed!(i, RestrictionOwner1ReadBindingMissing, RestrictionOwner2ReadBindingMissing, slot.read.as_ref().ok_or_else(||rejected("active Read binding missing")))?.check())?;\n                }\n                restriction_observed!(i, RestrictionOwner1AdmitActive, RestrictionOwner2AdmitActive, slot.admission.observe_active(phase))?;restriction_observed!(i, RestrictionOwner1WriterActive, RestrictionOwner2WriterActive, slot.writer_acquire.observe_active(phase))?;restriction_observed!(i, RestrictionOwner1ActivateActive, RestrictionOwner2ActivateActive, slot.activate.observe_active(phase))?;\n            }\n            for (i,w) in self.witnesses.iter().enumerate(){restriction_observed!(i, RestrictionOwner1WitnessActive, RestrictionOwner2WitnessActive, w.observe_active(&self.core,i))?;}\n            for(i,h)in self.histories.iter().enumerate(){restriction_observed!(i, RestrictionOwner1HistoryActive, RestrictionOwner2HistoryActive, h.observe_active(&self.core,i))?;}\n            for(i,g)in self.signing_services.iter().enumerate(){restriction_observed!(i, RestrictionOwner1SigningActive, RestrictionOwner2SigningActive, g.observe_active(&self.core,i))?;}\n            restriction_observed!(RestrictionPairService, self.pair_service.observe_active(&self.core))?;\n            Ok(())\n        })();\n        #[cfg(wholepact_financial_rendered_host_semantic_ci)]\n        if result.is_err(){crate::financial_ci_actor_diagnostics::mark_failed();}\n        if result.is_err(){self.core.phase.revoke();}result\n    }\n', 'restore': '    pub fn observe_restrictions(&self)->Result<()>{\n        let result=(||{\n            self.core.check()?;crate::channel::require_time(self.clocks.supervision())?;\n            if self.core.phase.revoked(){return Err(rejected("workflow permanently restricted"));}\n            for (i,slot) in self.v3_entries.iter().enumerate(){slot.observe_active(self.core.phase.phase(i),self.clocks)?;}\n            for (i,slot) in self.slots.iter().enumerate(){\n                let Some(slot)=slot else{continue};let phase=self.core.phase.phase(i);\n                if phase==ENTRY_PREPARING {\n                    self.clocks.restrict_received(PROFILE,slot.start.native_ceiling_ms,self.clocks.supervision(),Instant::now())?;\n                }\n                if let Some(entry)=&slot.entry {\n                    entry.check_custody()?;\n                    if matches!(phase,ENTRY_REVIEW|ENTRY_ADMITTED){entry.check_action()?;}\n                }\n                if phase==CONT_PREPARING{\n                    let c=slot.continuation.as_ref().ok_or_else(||rejected("Continue context missing"))?;\n                    self.clocks.restrict_received(PROFILE,c.context.native_ceiling_ms,self.clocks.supervision(),Instant::now())?;\n                }\n                if matches!(phase,CONT_REVIEW|CONT_ARMED|CONT_READY|CONT_ADMITTED){\n                    slot.continuation.as_ref().and_then(|c|c.binding.as_ref()).ok_or_else(||rejected("active Continue binding missing"))?.check(false)?;\n                }\n                if matches!(phase,READ_REVIEW|READ_ADMITTED){\n                    slot.read.as_ref().ok_or_else(||rejected("active Read binding missing"))?.check()?;\n                }\n                slot.admission.observe_active(phase)?;slot.writer_acquire.observe_active(phase)?;slot.activate.observe_active(phase)?;\n            }\n            for (i,w) in self.witnesses.iter().enumerate(){w.observe_active(&self.core,i)?;}\n            for(i,h)in self.histories.iter().enumerate(){h.observe_active(&self.core,i)?;}\n            for(i,g)in self.signing_services.iter().enumerate(){g.observe_active(&self.core,i)?;}\n            self.pair_service.observe_active(&self.core)?;\n            Ok(())\n        })();if result.is_err(){self.core.phase.revoke();}result\n    }\n'}]}}
def p89_restore(path,source):
    pin=P89_RESTORATION[path]
    assert sha(source)==pin['candidate_sha256'],('P89 current source',path)
    for change in pin['exact_inverse']:
        assert source.count(change['remove'])==1,('P89 exact inverse occurrence',path)
        source=source.replace(change['remove'],change['restore'],1)
    assert sha(source)==pin['baseline_sha256'],('P89 H88 source',path)
    return source

# Exact P85 changes are erased only for historical whole-file restoration.
# Runtime selected-item extraction and every prior hash remain unchanged.
P85_RESTORATION = {'crates/wholepact-financial-coordinator-origin/src/financial_workflow_origin.rs': {'candidate_sha256': 'a3a8c9da5b5699bcbc3866622b8e0d07b7a3e28223338754129939f5621301b0', 'baseline_sha256': '09b17969b32f2da549918c535d9d7b948a771e51dcde1201ea9648a67041dd6c', 'exact_inverse': [{'remove': '        if matches!(packet,Packet::V3AdmitDisplay{..}|Packet::V3AdmitReady{..}|Packet::V3Admitted{..}){return self.receive_v3_admission_event(packet).map(Some);}\n        if matches!(packet,Packet::V3AdmitReadDisplay{..}|Packet::V3AdmitReadRetained{..}){return self.receive_v3_admit_read_event(packet).map(Some);}\n        if matches!(packet,Packet::V3AuditDisplay{..}|Packet::V3Audited{..}){return self.receive_v3_audit_event(packet).map(Some);}\n        if matches!(packet,Packet::V3PrepareReadDisplay{..}|Packet::V3ReceiveDisplay{..}|Packet::V3Prepared{..}|Packet::V3Received{..}){return self.receive_v3_delivery_event(packet).map(Some);}\n        if matches!(packet,Packet::V3RedisclosureReadDisplay{..}|Packet::V3RediscloseDisplay{..}|Packet::V3RedisclosurePrepared{..}|Packet::V3Redisclosed{..}){return self.receive_v3_redisclosure_event(packet).map(Some);}\n        if matches!(packet,Packet::V3EnrollmentDisplay{..}|Packet::V3ManifestDisplay{..}|Packet::V3Enrolled{..}|Packet::V3ManifestAccepted{..}){return self.receive_v3_receipt_event(packet).map(Some);}\n        if matches!(packet,Packet::V3PairEndpoint{..}|Packet::V3PairDisplay{..}|Packet::V3Paired{..}){return self.receive_v3_pair_event(packet).map(Some);}\n        if matches!(packet,Packet::V3EntryOffer{..}|Packet::V3SourceOpened{..}|Packet::V3SourceFailed{..}){return self.receive_v3_entry_event(packet).map(Some);}\n        if matches!(packet,Packet::FinancialResultSelector{..}){return self.receive_financial_result_selector(packet).map(Some);}\n        if matches!(packet,Packet::ReturnReadDisplay{..}|Packet::ReturnExactDisplay{..}|Packet::ReturnPrepared{..}|Packet::ReturnCompleted{..}|Packet::ReturnFailed{..}){return self.receive_return_event(packet).map(Some);}\n        if matches!(packet,Packet::SignReadDisplay{..}|Packet::SignExactDisplay{..}|Packet::SignPrepared{..}|Packet::SignCommitted{..}|Packet::SignFailed{..}){return self.receive_sign_event(packet).map(Some);}\n        if matches!(packet,Packet::WalletPrepareDisplay{..}|Packet::WalletObserveDisplay{..}|Packet::WalletPrepared{..}|Packet::WalletObserved{..}|Packet::WalletFailed{..}){return self.receive_wallet_event(packet).map(Some);}\n        if matches!(packet,Packet::ActivateReadDisplay{..}|Packet::ActivateReadFailed{..}|Packet::ActivateDisplay{..}|Packet::ActivateReady{..}|Packet::ActivateOutcome{..}|Packet::Activated{..}){return self.receive_activate_event(packet).inspect_err(|_error|{\n            #[cfg(wholepact_financial_rendered_host_semantic_ci)]\n            crate::financial_ci_actor_diagnostics::work_fallback(crate::financial_ci_actor_diagnostics::DriverStage::WriterActivateReceiveError,_error);\n        }).map(Some);}\n        if matches!(packet,Packet::WriterReadDisplay{..}|Packet::WriterReadFailed{..}|Packet::AcquireDisplay{..}|Packet::AcquireReady{..}|Packet::AcquireOutcome{..}|Packet::Acquired{..}){return self.receive_writer_acquire_event(packet).inspect_err(|_error|{\n            #[cfg(wholepact_financial_rendered_host_semantic_ci)]\n            crate::financial_ci_actor_diagnostics::work_fallback(crate::financial_ci_actor_diagnostics::DriverStage::WriterAcquireReceiveError,_error);\n        }).map(Some);}\n        if matches!(packet,Packet::AdmitDisplay{..}|Packet::AdmitReady{..}|Packet::Admitted{..}|Packet::AdmitOutcome{..}) { return self.receive_admit_event(packet).map(Some); }\n        let mut retained_history=None;\n        let slot=self.slots[i].as_mut().ok_or_else(||rejected("workflow unsolicited response"))?;\n        if slot.failed{return Err(rejected("workflow response after failure"));}\n        let event=match packet{\n            Packet::EntryOffer{offer}=>{\n                offer.validate()?;\n                if slot.wire_phase!=ENTRY_PREPARING||slot.start!=offer.start||offer.presentation.actor.common_image_measurement!=self.image{return Err(rejected("workflow entry offer mismatch"));}\n                slot.wire_phase=ENTRY_REVIEW;\n\n                    let now=Instant::now();let source=self.clocks.restrict_received(PROFILE,offer.presentation.source_ceiling_ms,self.clocks.supervision(),now)?;\n                    let entry=self.clocks.restrict_received(PROFILE,offer.presentation.entry_ceiling_ms,self.clocks.supervision(),now)?;\n', 'restore': '        if matches!(packet,Packet::V3AdmitDisplay{..}|Packet::V3AdmitReady{..}|Packet::V3Admitted{..}){return self.receive_v3_admission_event(packet).map(Some);}\n        if matches!(packet,Packet::V3AdmitReadDisplay{..}|Packet::V3AdmitReadRetained{..}){return self.receive_v3_admit_read_event(packet).map(Some);}\n        if matches!(packet,Packet::V3AuditDisplay{..}|Packet::V3Audited{..}){return self.receive_v3_audit_event(packet).map(Some);}\n        if matches!(packet,Packet::V3PrepareReadDisplay{..}|Packet::V3ReceiveDisplay{..}|Packet::V3Prepared{..}|Packet::V3Received{..}){return self.receive_v3_delivery_event(packet).map(Some);}\n        if matches!(packet,Packet::V3RedisclosureReadDisplay{..}|Packet::V3RediscloseDisplay{..}|Packet::V3RedisclosurePrepared{..}|Packet::V3Redisclosed{..}){return self.receive_v3_redisclosure_event(packet).map(Some);}\n        if matches!(packet,Packet::V3EnrollmentDisplay{..}|Packet::V3ManifestDisplay{..}|Packet::V3Enrolled{..}|Packet::V3ManifestAccepted{..}){return self.receive_v3_receipt_event(packet).map(Some);}\n        if matches!(packet,Packet::V3PairEndpoint{..}|Packet::V3PairDisplay{..}|Packet::V3Paired{..}){return self.receive_v3_pair_event(packet).map(Some);}\n        if matches!(packet,Packet::V3EntryOffer{..}|Packet::V3SourceOpened{..}|Packet::V3SourceFailed{..}){return self.receive_v3_entry_event(packet).map(Some);}\n        if matches!(packet,Packet::FinancialResultSelector{..}){return self.receive_financial_result_selector(packet).map(Some);}\n        if matches!(packet,Packet::ReturnReadDisplay{..}|Packet::ReturnExactDisplay{..}|Packet::ReturnPrepared{..}|Packet::ReturnCompleted{..}|Packet::ReturnFailed{..}){return self.receive_return_event(packet).map(Some);}\n        if matches!(packet,Packet::SignReadDisplay{..}|Packet::SignExactDisplay{..}|Packet::SignPrepared{..}|Packet::SignCommitted{..}|Packet::SignFailed{..}){return self.receive_sign_event(packet).map(Some);}\n        if matches!(packet,Packet::WalletPrepareDisplay{..}|Packet::WalletObserveDisplay{..}|Packet::WalletPrepared{..}|Packet::WalletObserved{..}|Packet::WalletFailed{..}){return self.receive_wallet_event(packet).map(Some);}\n        if matches!(packet,Packet::ActivateReadDisplay{..}|Packet::ActivateReadFailed{..}|Packet::ActivateDisplay{..}|Packet::ActivateReady{..}|Packet::ActivateOutcome{..}|Packet::Activated{..}){return self.receive_activate_event(packet).map(Some);}\n        if matches!(packet,Packet::WriterReadDisplay{..}|Packet::WriterReadFailed{..}|Packet::AcquireDisplay{..}|Packet::AcquireReady{..}|Packet::AcquireOutcome{..}|Packet::Acquired{..}){return self.receive_writer_acquire_event(packet).map(Some);}\n        if matches!(packet,Packet::AdmitDisplay{..}|Packet::AdmitReady{..}|Packet::Admitted{..}|Packet::AdmitOutcome{..}) { return self.receive_admit_event(packet).map(Some); }\n        let mut retained_history=None;\n        let slot=self.slots[i].as_mut().ok_or_else(||rejected("workflow unsolicited response"))?;\n        if slot.failed{return Err(rejected("workflow response after failure"));}\n        let event=match packet{\n            Packet::EntryOffer{offer}=>{\n                offer.validate()?;\n                if slot.wire_phase!=ENTRY_PREPARING||slot.start!=offer.start||offer.presentation.actor.common_image_measurement!=self.image{return Err(rejected("workflow entry offer mismatch"));}\n                slot.wire_phase=ENTRY_REVIEW;\n\n                    let now=Instant::now();let source=self.clocks.restrict_received(PROFILE,offer.presentation.source_ceiling_ms,self.clocks.supervision(),now)?;\n                    let entry=self.clocks.restrict_received(PROFILE,offer.presentation.entry_ceiling_ms,self.clocks.supervision(),now)?;\n'}]}, 'crates/wholepact-financial-coordinator-origin/src/witness_retirement.rs': {'candidate_sha256': '84c11dd62cf844c40ccb5ad2e2f8e8dfc658d2ae9d043ce5ca4cc339b2f308ac', 'baseline_sha256': 'a0fd7bd9cc1327fcc755630842f5ff19d567d35e46a0619ff64d1c5361b489a0', 'exact_inverse': [{'remove': '            };\n            if proof.instance()!=t.request.witness_instance{return history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,Err(rejected("retirement instance proof mismatch")));}\n            history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.tree.as_mut().unwrap().install_retirement(&proof))?;history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.core.install_retired(&proof))?;\n            match t.request.purpose{\n                RetirementPurpose::FinancialSigning=>self.core.phase.signing_retirement_step(i,5,6)?,\n                RetirementPurpose::FinancialContinuation=>self.witnesses[i].retirement_reaped()?,\n                RetirementPurpose::InitialHistory=>{history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.histories[i].retirement_reaped())?;history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.core.phase.observe_history_retired(i))?;}\n            }\n            #[cfg(wholepact_financial_ci)]\n            if t.request.purpose==RetirementPurpose::FinancialSigning{crate::financial_observer::signer(t.request.target,"SigningRetired")?;}\n            history_retirement_detail!(t.request.purpose,HistoryRetirementHostResume,self.retirement_send_host(&Packet::RetireResume{request:t.request.clone()},cutoff))?;\n            history_retirement_detail!(t.request.purpose,HistoryRetirementHostResume,self.retirement_wait_host(&t.request,true,cutoff,Some(index)))?;\n            if let Some((entry,correlation,signed,service,writer,writer_wall,(service_valid_from_ms,service_valid_until_ms,last_wall)))=signed_record {\n                let record=Arc::new(super::signed_custody::SignedResultRecord{core:Arc::clone(&self.core),entry,correlation,signed,service,writer,writer_wall,retired_index:index,service_valid_from_ms,service_valid_until_ms,last_wall:std::sync::atomic::AtomicU64::new(last_wall)});\n                self.signing_services[i].install_retired_result(record)?;\n            }\n            self.retirement_resume=Some(cutoff);outbound.consumed=true;\n            Ok(CoordinatorWitnessRetiredV1{core:Arc::clone(&self.core),entries:t.entries.iter().map(Arc::clone).collect(),role:t.request.target,cutoff:cutoff,consumed:false})\n        })();\n        if result.is_err(){self.core.close();}result\n    }\n}\n\n// One immutable snapshot is validated and later supplied to the exact CAS.\n// A phase alone never proves disposal: actual retained W records are separate.\n// History5 is accepted only for the exact target with actual joined Disposed;\n', 'restore': '            };\n            if proof.instance()!=t.request.witness_instance{return history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,Err(rejected("retirement instance proof mismatch")));}\n            history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.tree.as_mut().unwrap().install_retirement(&proof))?;history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.core.install_retired(&proof))?;\n            match t.request.purpose{\n                RetirementPurpose::FinancialSigning=>self.core.phase.signing_retirement_step(i,5,6)?,\n                RetirementPurpose::FinancialContinuation=>self.witnesses[i].retirement_reaped()?,\n                RetirementPurpose::InitialHistory=>{history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.histories[i].retirement_reaped())?;history_retirement_detail!(t.request.purpose,HistoryRetirementOwnedStopReap,self.core.phase.observe_history_retired(i))?;}\n            }\n            #[cfg(wholepact_financial_ci)]\n            if t.request.purpose==RetirementPurpose::FinancialSigning{crate::financial_observer::signer(t.request.target,"SigningRetired")?;}\n            history_retirement_detail!(t.request.purpose,HistoryRetirementHostResume,self.retirement_send_host(&Packet::RetireResume{request:t.request.clone()},cutoff))?;\n            history_retirement_detail!(t.request.purpose,HistoryRetirementHostResume,self.retirement_wait_host(&t.request,true,cutoff,Some(index)))?;\n            if let Some((entry,correlation,signed,service,writer,(service_valid_from_ms,service_valid_until_ms,last_wall)))=signed_record {\n                let record=Arc::new(super::signed_custody::SignedResultRecord{core:Arc::clone(&self.core),entry,correlation,signed,service,writer,retired_index:index,service_valid_from_ms,service_valid_until_ms,last_wall:std::sync::atomic::AtomicU64::new(last_wall)});\n                self.signing_services[i].install_retired_result(record)?;\n            }\n            self.retirement_resume=Some(cutoff);outbound.consumed=true;\n            Ok(CoordinatorWitnessRetiredV1{core:Arc::clone(&self.core),entries:t.entries.iter().map(Arc::clone).collect(),role:t.request.target,cutoff:cutoff,consumed:false})\n        })();\n        if result.is_err(){self.core.close();}result\n    }\n}\n\n// One immutable snapshot is validated and later supplied to the exact CAS.\n// A phase alone never proves disposal: actual retained W records are separate.\n// History5 is accepted only for the exact target with actual joined Disposed;\n'}, {'remove': '    /// Sole driver only. All packet operations are nonblocking and each loop\n    /// samples original actors/R/source/cleanup. Final fallback kernel reap on\n    /// failure may block: no wall-bounded reap guarantee is claimed.\n    pub fn retire_witness(&mut self,mut outbound:CoordinatorWitnessRetirementOutboundV1)->Result<CoordinatorWitnessRetiredV1>{\n        let result=(||{\n            let t=&outbound.ticket;\n            let mut cutoff=t.cutoff;\n            let signed_record=if t.request.purpose==RetirementPurpose::FinancialSigning {\n                let slot=self.slots[t.request.target.index()].as_ref().ok_or_else(||rejected("Signing source absent"))?;\n                let(a,_)=slot.activate.wallet_predecessor()?;\n                let(_,signed)=slot.activate.wallet.sign.return_predecessor()?;\n                let(entry,correlation,service)=self.signing_services[t.request.target.index()].retirement_source()?;\n                Some((entry,correlation,signed.clone(),service,a.read.writer_deadline,a.read.writer_wall_deadline,self.signing_services[t.request.target.index()].retirement_wall_bounds()?))\n            }else{None};\n            if !Arc::ptr_eq(&self.core,&t.core){return history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,Err(rejected("foreign retirement outbound")));}\n            history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.retirement_bounds(cutoff))?;history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.core.check())?;history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.retirement_idle(t.phases,t.request.purpose,t.request.target))?;\n            history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.retirement_send_host(&Packet::RetireRequest{request:t.request.clone()},cutoff))?;\n            history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.retirement_wait_host(&t.request,false,cutoff,None))?;\n            let i=t.request.target.index();\n            match t.request.purpose{\n                RetirementPurpose::FinancialSigning=>{\n                    self.finish_signing_for_retirement(t.request.target)?;\n                    loop {self.retirement_bounds(cutoff)?;self.core.check()?;\n                        if let Some(event)=self.try_receive_signing()? {\n                            match event {CoordinatorFinancialSigningEventV1::Disposed(role) if role==t.request.target=>{cutoff=cutoff.min(self.signing_retirement_cleanup(role)?);break;},_=>return Err(rejected("normal Signing retirement expected exact Disposed"))}\n', 'restore': '    /// Sole driver only. All packet operations are nonblocking and each loop\n    /// samples original actors/R/source/cleanup. Final fallback kernel reap on\n    /// failure may block: no wall-bounded reap guarantee is claimed.\n    pub fn retire_witness(&mut self,mut outbound:CoordinatorWitnessRetirementOutboundV1)->Result<CoordinatorWitnessRetiredV1>{\n        let result=(||{\n            let t=&outbound.ticket;\n            let mut cutoff=t.cutoff;\n            let signed_record=if t.request.purpose==RetirementPurpose::FinancialSigning {\n                let slot=self.slots[t.request.target.index()].as_ref().ok_or_else(||rejected("Signing source absent"))?;\n                let(a,_)=slot.activate.wallet_predecessor()?;\n                let(_,signed)=slot.activate.wallet.sign.return_predecessor()?;\n                let(entry,correlation,service)=self.signing_services[t.request.target.index()].retirement_source()?;\n                Some((entry,correlation,signed.clone(),service,a.read.writer_deadline,self.signing_services[t.request.target.index()].retirement_wall_bounds()?))\n            }else{None};\n            if !Arc::ptr_eq(&self.core,&t.core){return history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,Err(rejected("foreign retirement outbound")));}\n            history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.retirement_bounds(cutoff))?;history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.core.check())?;history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.retirement_idle(t.phases,t.request.purpose,t.request.target))?;\n            history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.retirement_send_host(&Packet::RetireRequest{request:t.request.clone()},cutoff))?;\n            history_retirement_detail!(t.request.purpose,HistoryRetirementHostQuiescence,self.retirement_wait_host(&t.request,false,cutoff,None))?;\n            let i=t.request.target.index();\n            match t.request.purpose{\n                RetirementPurpose::FinancialSigning=>{\n                    self.finish_signing_for_retirement(t.request.target)?;\n                    loop {self.retirement_bounds(cutoff)?;self.core.check()?;\n                        if let Some(event)=self.try_receive_signing()? {\n                            match event {CoordinatorFinancialSigningEventV1::Disposed(role) if role==t.request.target=>{cutoff=cutoff.min(self.signing_retirement_cleanup(role)?);break;},_=>return Err(rejected("normal Signing retirement expected exact Disposed"))}\n'}, {'remove': '            phases,consumed:false}))\n    }\n    pub fn prepare_signing_retirement(&mut self,role:Target)->Result<CoordinatorWitnessRetirementTicketV1>{\n        self.core.check_action_restrictions()?;\n        let phases=self.core.phase.snapshot();self.retirement_idle(phases,RetirementPurpose::FinancialSigning,role)?;\n        let slot=self.slots[role.index()].as_ref().ok_or_else(||rejected("Signing retirement Source absent"))?;\n        if slot.wire_phase!=67||!slot.activate.wallet.sign.selector_seen{return Err(rejected("Signing retirement before actual committed Sign and selector"));}\n        let (activation,_)=slot.activate.wallet_predecessor()?;\n        let (_,signed)=slot.activate.wallet.sign.return_predecessor()?;\n        let (_,service,deadline)=self.signing_services[role.index()].retirement_source()?;\n        activation.read.service.require_same(&service)?;\n        let signing=crate::host_interstage::SigningRetirementBindingV1{original_commitment:service.original.commitment()?,signed:signed.clone()};\n        let cutoff=deadline.min(activation.read.writer_deadline).min(activation.read.writer_wall_deadline).min(self.clocks.supervision());\n        let request=RetirementRequest{profile:PROFILE.into(),coordinator:self.coordinator.clone(),session:self.session.clone(),target:role,purpose:RetirementPurpose::FinancialSigning,binding_digest:signing.commitment()?,witness_instance:service.witness_instance,challenge:state::nonce()?,cleanup_ceiling_ms:self.clocks.cleanup_offset(cutoff)?,signing:Some(signing)};\n        request.validate(self.clocks)?;\n        Ok(CoordinatorWitnessRetirementTicketV1{core:Arc::clone(&self.core),entries:self.slots.iter().flatten().filter_map(|s|s.entry.as_ref().map(Arc::clone)).collect(),request,cutoff,phases,consumed:false})\n    }\n    pub fn prepare_history_retirement(&mut self,role:Target)->Result<CoordinatorWitnessRetirementTicketV1>{\n        self.core.check_action_restrictions()?;let phases=self.core.phase.snapshot();self.retirement_idle(phases,RetirementPurpose::InitialHistory,role)?;\n        let slot=self.slots[role.index()].as_ref().ok_or_else(||rejected("History retirement Signer missing"))?;\n        if slot.wire_phase!=HISTORY_RETAINED||slot.continue_deadline.is_none(){return Err(rejected("History retirement before authenticated retention"));}\n        let read=slot.read.as_ref().ok_or_else(||rejected("History retirement Read missing"))?;\n        let(instance,cutoff)=self.histories[role.index()].retirement_record(read)?;\n        let request=RetirementRequest{profile:PROFILE.into(),coordinator:self.coordinator.clone(),session:self.session.clone(),target:role,\n            purpose:RetirementPurpose::InitialHistory,binding_digest:read.wire.presentation_digest.clone(),witness_instance:instance.to_owned(),challenge:state::nonce()?,cleanup_ceiling_ms:self.clocks.cleanup_offset(cutoff)?,signing:None};\n', 'restore': '            phases,consumed:false}))\n    }\n    pub fn prepare_signing_retirement(&mut self,role:Target)->Result<CoordinatorWitnessRetirementTicketV1>{\n        self.core.check_action_restrictions()?;\n        let phases=self.core.phase.snapshot();self.retirement_idle(phases,RetirementPurpose::FinancialSigning,role)?;\n        let slot=self.slots[role.index()].as_ref().ok_or_else(||rejected("Signing retirement Source absent"))?;\n        if slot.wire_phase!=67||!slot.activate.wallet.sign.selector_seen{return Err(rejected("Signing retirement before actual committed Sign and selector"));}\n        let (activation,_)=slot.activate.wallet_predecessor()?;\n        let (_,signed)=slot.activate.wallet.sign.return_predecessor()?;\n        let (_,service,deadline)=self.signing_services[role.index()].retirement_source()?;\n        activation.read.service.require_same(&service)?;\n        let signing=crate::host_interstage::SigningRetirementBindingV1{original_commitment:service.original.commitment()?,signed:signed.clone()};\n        let cutoff=deadline.min(activation.read.writer_deadline).min(self.clocks.supervision());\n        let request=RetirementRequest{profile:PROFILE.into(),coordinator:self.coordinator.clone(),session:self.session.clone(),target:role,purpose:RetirementPurpose::FinancialSigning,binding_digest:signing.commitment()?,witness_instance:service.witness_instance,challenge:state::nonce()?,cleanup_ceiling_ms:self.clocks.cleanup_offset(cutoff)?,signing:Some(signing)};\n        request.validate(self.clocks)?;\n        Ok(CoordinatorWitnessRetirementTicketV1{core:Arc::clone(&self.core),entries:self.slots.iter().flatten().filter_map(|s|s.entry.as_ref().map(Arc::clone)).collect(),request,cutoff,phases,consumed:false})\n    }\n    pub fn prepare_history_retirement(&mut self,role:Target)->Result<CoordinatorWitnessRetirementTicketV1>{\n        self.core.check_action_restrictions()?;let phases=self.core.phase.snapshot();self.retirement_idle(phases,RetirementPurpose::InitialHistory,role)?;\n        let slot=self.slots[role.index()].as_ref().ok_or_else(||rejected("History retirement Signer missing"))?;\n        if slot.wire_phase!=HISTORY_RETAINED||slot.continue_deadline.is_none(){return Err(rejected("History retirement before authenticated retention"));}\n        let read=slot.read.as_ref().ok_or_else(||rejected("History retirement Read missing"))?;\n        let(instance,cutoff)=self.histories[role.index()].retirement_record(read)?;\n        let request=RetirementRequest{profile:PROFILE.into(),coordinator:self.coordinator.clone(),session:self.session.clone(),target:role,\n            purpose:RetirementPurpose::InitialHistory,binding_digest:read.wire.presentation_digest.clone(),witness_instance:instance.to_owned(),challenge:state::nonce()?,cleanup_ceiling_ms:self.clocks.cleanup_offset(cutoff)?,signing:None};\n'}]}, 'crates/wholepact-financial-coordinator-origin/src/signer_sign_origin.rs': {'candidate_sha256': 'b1cfc9163e4b0b7aba0f15cad4e56797577cf3148ce427d691082d989b3d7d66', 'baseline_sha256': 'fe877489d647157ce1e8400987c3d63d3d1c151937e5fd972b4b0f1001da6c46', 'exact_inverse': [{'remove': '                .binding\n                .as_ref()\n                .ok_or_else(|| rejected("sign missing Exact"))?\n                .bounds(),\n            _ => Ok(()),\n        }\n    }\n}\n#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n    fn sign_relay_enforces_retained_wall_cap_without_relabelling() {\n        // Inert time-only Presentation exercises the actual relay clock, not\n        // a wire grant or authority constructor. Unused identity calls panic.\n        #[derive(Clone)] struct ClockOnly;\n        impl Presentation for ClockOnly {\n            fn validate(&self)->Result<()> { Ok(()) }\n            fn original(&self)->&SignerWalletOriginalV1 { panic!("not a grant") }\n            fn observed(&self)->&SignerWalletObservedV1 { panic!("not a grant") }\n            fn actor(&self)->&FinancialActorContextV1 { panic!("not a grant") }\n            fn digest(&self)->&str { panic!("not a grant") }\n            fn ceiling(&self)->u64 { 60_000 }\n            fn times(&self)->(u64,u64) { (0,u64::MAX) }\n            fn service(&self)->u64 { panic!("not a grant") }\n            fn writer(&self)->u64 { panic!("not a grant") }\n        }\n        let epoch=Instant::now();\n        let clocks=FullWorkflowClocksV1::from_initial_epoch(epoch).unwrap();\n        let original=epoch+Duration::from_secs(60);\n        let future_cap=epoch+Duration::from_secs(30);\n        let mut last=0;\n        relay_clock(&ClockOnly,original,original,future_cap,clocks,&mut last).unwrap();\n        assert!(last>0);\n        let retained=last;\n        assert!(relay_clock(&ClockOnly,original,original,epoch,clocks,&mut last).is_err());\n        assert_eq!(last,retained);\n        assert_eq!(clocks.restrictive_offset(original,original).unwrap(),60_000);\n    }\n\n    #[test]\n    fn actual_result_observation_preserves_r_and_cannot_repeat() {\n        let p = Phases::new();\n        p.step(0, 0, 66).unwrap();\n        p.revoke();\n        p.observe_sign_committed(0).unwrap();\n        assert_eq!(p.phase(0), 67);\n        assert!(p.revoked());\n        assert!(p.observe_sign_committed(0).is_err());\n    }\n    #[test]\n    fn no_other_phase_can_claim_actual_sign_result() {\n        for phase in 0..=255 {\n', 'restore': '                .binding\n                .as_ref()\n                .ok_or_else(|| rejected("sign missing Exact"))?\n                .bounds(),\n            _ => Ok(()),\n        }\n    }\n}\n#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n    fn actual_result_observation_preserves_r_and_cannot_repeat() {\n        let p = Phases::new();\n        p.step(0, 0, 66).unwrap();\n        p.revoke();\n        p.observe_sign_committed(0).unwrap();\n        assert_eq!(p.phase(0), 67);\n        assert!(p.revoked());\n        assert!(p.observe_sign_committed(0).is_err());\n    }\n    #[test]\n    fn no_other_phase_can_claim_actual_sign_result() {\n        for phase in 0..=255 {\n'}, {'remove': '                let d = s\n                    .read\n                    .result\n                    .as_ref()\n                    .ok_or_else(|| rejected("relay Exact before actual prepared"))?;\n                if s.read.phase != 64 || !s.read.reported || !exact_matches(presentation, rp, d) {\n                    return Err(rejected("relay Exact changed prepared source"));\n                }\n                relay_clock(\n                    presentation,\n                    deadline,\n                    writer,\n                    writer_wall,\n                    self.clocks,\n                    &mut slot.last_wall,\n                )?;\n                s.exact.wire = Some(presentation.clone());\n                s.exact.phase = 65;\n                Ok(true)\n            }\n            Packet::SignPrepared { data, .. } => {\n                data.validate()?;\n                let t = &mut s.read;\n                let p = t\n                    .wire\n', 'restore': '                let d = s\n                    .read\n                    .result\n                    .as_ref()\n                    .ok_or_else(|| rejected("relay Exact before actual prepared"))?;\n                if s.read.phase != 64 || !s.read.reported || !exact_matches(presentation, rp, d) {\n                    return Err(rejected("relay Exact changed prepared source"));\n                }\n                relay_clock(\n                    presentation,\n                    deadline,\n                    writer,\n                    self.clocks,\n                    &mut slot.last_wall,\n                )?;\n                s.exact.wire = Some(presentation.clone());\n                s.exact.phase = 65;\n                Ok(true)\n            }\n            Packet::SignPrepared { data, .. } => {\n                data.validate()?;\n                let t = &mut s.read;\n                let p = t\n                    .wire\n'}, {'remove': '                    return Ok(false);\n                }\n                if s.read.wire.is_some()\n                    || presentation.actor != a.actor\n                    || !same_original(presentation, &w, &r, service_ceiling, writer_ceiling)\n                {\n                    return Err(rejected("sign relay display predecessor"));\n                }\n                relay_clock(\n                    presentation,\n                    deadline,\n                    writer,\n                    writer_wall,\n                    self.clocks,\n                    &mut slot.last_wall,\n                )?;\n                s.read.wire = Some(presentation.clone());\n                s.read.phase = 62;\n                Ok(true)\n            }\n            Packet::SignExactDisplay { presentation } => {\n                if self.restricted {\n                    return Ok(false);\n                }\n                if s.exact.wire.is_some()\n', 'restore': '                    return Ok(false);\n                }\n                if s.read.wire.is_some()\n                    || presentation.actor != a.actor\n                    || !same_original(presentation, &w, &r, service_ceiling, writer_ceiling)\n                {\n                    return Err(rejected("sign relay display predecessor"));\n                }\n                relay_clock(\n                    presentation,\n                    deadline,\n                    writer,\n                    self.clocks,\n                    &mut slot.last_wall,\n                )?;\n                s.read.wire = Some(presentation.clone());\n                s.read.phase = 62;\n                Ok(true)\n            }\n            Packet::SignExactDisplay { presentation } => {\n                if self.restricted {\n                    return Ok(false);\n                }\n                if s.exact.wire.is_some()\n'}, {'remove': '                s.terminal = true;\n                self.core.phase.revoke();\n                Ok(CoordinatorFinancialEventV1::SignFailed { role, data })\n            }\n            _ => Err(rejected("wrong sign event")),\n        }\n    }\n}\nfn relay_clock<P: Presentation>(\n    p: &P,\n    service: Instant,\n    writer: Instant,\n    writer_wall: Instant,\n    clocks: FullWorkflowClocksV1,\n    last: &mut u64,\n) -> Result<()> {\n    p.validate()?;\n    let now = Instant::now();\n    clocks.restrict_received(PROFILE, p.ceiling(), service.min(writer).min(writer_wall), now)?;\n    let wall = state::wall_ms()?;\n    let (a, b) = p.times();\n    if wall < *last || wall < a || wall >= b {\n        return Err(rejected("sign relay action expired"));\n    }\n    *last = wall;\n    Ok(())\n}\nimpl HostFinancialWorkflowRelayV1 {\n    pub(in crate::financial_workflow_origin) fn down_sign(&mut self, p: &Packet) -> Result<()> {\n        if self.restricted {\n            return Err(rejected("sign relay after R"));\n        }\n        let role = p.target()?.ok_or_else(|| rejected("sign relay role"))?;\n        let slot = self.slots[role.index()]\n            .as_mut()\n            .ok_or_else(|| rejected("sign relay missing source"))?;\n        let (_, _, service, writer) = slot.activate.wallet_predecessor()?;\n        let writer_wall = slot.activate.retained_wall_deadline()?;\n        let deadline = service.deadline;\n        let s = &mut slot.activate.wallet.sign;\n        if s.terminal {\n            return Err(rejected("sign relay terminal"));\n        }\n        match p {\n            Packet::SignReadFinal {\n                presentation_digest,\n                ..\n            } => {\n                let t = &mut s.read;\n                let p = t\n                    .wire\n                    .as_ref()\n                    .ok_or_else(|| rejected("sign relay before display"))?;\n                if t.phase != 62 || presentation_digest != &p.presentation_digest {\n                    return Err(rejected("sign relay Final mismatch/replay"));\n                }\n                relay_clock(p, deadline, writer, writer_wall, self.clocks, &mut slot.last_wall)?;\n                t.phase = 63;\n                Ok(())\n            }\n            Packet::SignExactFinal {\n                presentation_digest,\n                ..\n            } => {\n                let t = &mut s.exact;\n                let p = t\n                    .wire\n                    .as_ref()\n                    .ok_or_else(|| rejected("sign relay before display"))?;\n                if t.phase != 65 || presentation_digest != &p.presentation_digest {\n                    return Err(rejected("sign relay Final mismatch/replay"));\n                }\n                relay_clock(p, deadline, writer, writer_wall, self.clocks, &mut slot.last_wall)?;\n                t.phase = 66;\n                Ok(())\n            }\n            _ => Err(rejected("wrong sign relay command")),\n        }\n    }\n    pub(in crate::financial_workflow_origin) fn up_sign(\n        &mut self,\n        role: Target,\n        p: &Packet,\n    ) -> Result<bool> {\n        let slot = self.slots[role.index()]\n            .as_mut()\n            .ok_or_else(|| rejected("sign relay missing source"))?;\n        let (a, _, service, writer) = slot.activate.wallet_predecessor()?;\n        let writer_wall = slot.activate.retained_wall_deadline()?;\n        let service_ceiling = service.correlation().service_ceiling_ms;\n        let deadline = service.deadline;\n        let writer_ceiling = self\n            .clocks\n            .restrictive_offset(writer, self.clocks.supervision())?;\n        let (w, r) = slot.activate.wallet.sign_predecessor()?;\n        let w = w.clone();\n        let r = r.clone();\n        let a = a.clone();\n        let s = &mut slot.activate.wallet.sign;\n        if s.terminal {\n            return Err(rejected("sign relay terminal"));\n', 'restore': '                s.terminal = true;\n                self.core.phase.revoke();\n                Ok(CoordinatorFinancialEventV1::SignFailed { role, data })\n            }\n            _ => Err(rejected("wrong sign event")),\n        }\n    }\n}\nfn relay_clock<P: Presentation>(\n    p: &P,\n    service: Instant,\n    writer: Instant,\n    clocks: FullWorkflowClocksV1,\n    last: &mut u64,\n) -> Result<()> {\n    p.validate()?;\n    let now = Instant::now();\n    clocks.restrict_received(PROFILE, p.ceiling(), service.min(writer), now)?;\n    let wall = state::wall_ms()?;\n    let (a, b) = p.times();\n    if wall < *last || wall < a || wall >= b {\n        return Err(rejected("sign relay action expired"));\n    }\n    *last = wall;\n    Ok(())\n}\nimpl HostFinancialWorkflowRelayV1 {\n    pub(in crate::financial_workflow_origin) fn down_sign(&mut self, p: &Packet) -> Result<()> {\n        if self.restricted {\n            return Err(rejected("sign relay after R"));\n        }\n        let role = p.target()?.ok_or_else(|| rejected("sign relay role"))?;\n        let slot = self.slots[role.index()]\n            .as_mut()\n            .ok_or_else(|| rejected("sign relay missing source"))?;\n        let (_, _, service, writer) = slot.activate.wallet_predecessor()?;\n        let deadline = service.deadline;\n        let s = &mut slot.activate.wallet.sign;\n        if s.terminal {\n            return Err(rejected("sign relay terminal"));\n        }\n        match p {\n            Packet::SignReadFinal {\n                presentation_digest,\n                ..\n            } => {\n                let t = &mut s.read;\n                let p = t\n                    .wire\n                    .as_ref()\n                    .ok_or_else(|| rejected("sign relay before display"))?;\n                if t.phase != 62 || presentation_digest != &p.presentation_digest {\n                    return Err(rejected("sign relay Final mismatch/replay"));\n                }\n                relay_clock(p, deadline, writer, self.clocks, &mut slot.last_wall)?;\n                t.phase = 63;\n                Ok(())\n            }\n            Packet::SignExactFinal {\n                presentation_digest,\n                ..\n            } => {\n                let t = &mut s.exact;\n                let p = t\n                    .wire\n                    .as_ref()\n                    .ok_or_else(|| rejected("sign relay before display"))?;\n                if t.phase != 65 || presentation_digest != &p.presentation_digest {\n                    return Err(rejected("sign relay Final mismatch/replay"));\n                }\n                relay_clock(p, deadline, writer, self.clocks, &mut slot.last_wall)?;\n                t.phase = 66;\n                Ok(())\n            }\n            _ => Err(rejected("wrong sign relay command")),\n        }\n    }\n    pub(in crate::financial_workflow_origin) fn up_sign(\n        &mut self,\n        role: Target,\n        p: &Packet,\n    ) -> Result<bool> {\n        let slot = self.slots[role.index()]\n            .as_mut()\n            .ok_or_else(|| rejected("sign relay missing source"))?;\n        let (a, _, service, writer) = slot.activate.wallet_predecessor()?;\n        let service_ceiling = service.correlation().service_ceiling_ms;\n        let deadline = service.deadline;\n        let writer_ceiling = self\n            .clocks\n            .restrictive_offset(writer, self.clocks.supervision())?;\n        let (w, r) = slot.activate.wallet.sign_predecessor()?;\n        let w = w.clone();\n        let r = r.clone();\n        let a = a.clone();\n        let s = &mut slot.activate.wallet.sign;\n        if s.terminal {\n            return Err(rejected("sign relay terminal"));\n'}, {'remove': '    fn new(a: Arc<ActivateReview>, p: P) -> Result<Arc<Self>> {\n        p.validate()?;\n        a.wallet_bounds()?;\n        let now = Instant::now();\n        let (t, e) = p.times();\n        let deadline = a\n            .read\n            .entry\n            .clocks\n            .restrict_received(\n                PROFILE,\n                p.ceiling(),\n                a.read.service.deadline.min(a.read.writer_deadline).min(a.read.writer_wall_deadline),\n                now,\n            )?\n            .min(wall_ceiling(now, state::wall_ms()?, t, e)?);\n        let b = Arc::new(Self {\n            activation: a,\n            p,\n            deadline,\n            last_wall: AtomicU64::new(state::wall_ms()?),\n        });\n        b.bounds()?;\n        Ok(b)\n    }\n', 'restore': '    fn new(a: Arc<ActivateReview>, p: P) -> Result<Arc<Self>> {\n        p.validate()?;\n        a.wallet_bounds()?;\n        let now = Instant::now();\n        let (t, e) = p.times();\n        let deadline = a\n            .read\n            .entry\n            .clocks\n            .restrict_received(\n                PROFILE,\n                p.ceiling(),\n                a.read.service.deadline.min(a.read.writer_deadline),\n                now,\n            )?\n            .min(wall_ceiling(now, state::wall_ms()?, t, e)?);\n        let b = Arc::new(Self {\n            activation: a,\n            p,\n            deadline,\n            last_wall: AtomicU64::new(state::wall_ms()?),\n        });\n        b.bounds()?;\n        Ok(b)\n    }\n'}]}, 'crates/wholepact-financial-coordinator-origin/src/signer_return_origin.rs': {'candidate_sha256': 'a99e518fcf05f2d9e332ceeb52f0e7e3668a67bc356fc39117ac9623e8092c76', 'baseline_sha256': '9a7528f83f7a8f8df0ab890148f39b6916f635a21b58433f43887be41b8d8374', 'exact_inverse': [{'remove': '        // Ordinary upstream immutable observations; no queued send or new authority.\n        if let Err(error) = crate::channel::require_time(original_deadline) {\n            self.core.phase.revoke();\n            return Err(error);\n        }\n        self.send(packet)\n    }\n}\n#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n    fn return_relay_enforces_retained_wall_cap_without_relabelling() {\n        // Inert time-only Presentation exercises the actual relay clock, not\n        // a wire grant or authority constructor. Unused identity calls panic.\n        #[derive(Clone)] struct ClockOnly;\n        impl Presentation for ClockOnly {\n            fn validate(&self)->Result<()> { Ok(()) }\n            fn original(&self)->&SignerWalletOriginalV1 { panic!("not a grant") }\n            fn observed(&self)->&SignerWalletObservedV1 { panic!("not a grant") }\n            fn actor(&self)->&FinancialActorContextV1 { panic!("not a grant") }\n            fn digest(&self)->&str { panic!("not a grant") }\n            fn ceiling(&self)->u64 { 60_000 }\n            fn times(&self)->(u64,u64) { (0,u64::MAX) }\n            fn service(&self)->u64 { panic!("not a grant") }\n            fn writer(&self)->u64 { panic!("not a grant") }\n            fn signed(&self)->&SignerSignCommittedV1 { panic!("not a grant") }\n            fn transport(&self)->(u64,u64,u64,u64) { (60_000,60_000,u64::MAX,u64::MAX) }\n        }\n        let epoch=Instant::now();\n        let clocks=FullWorkflowClocksV1::from_initial_epoch(epoch).unwrap();\n        let original=epoch+Duration::from_secs(60);\n        let future_cap=epoch+Duration::from_secs(30);\n        let mut last=0;\n        relay_clock(&ClockOnly,original,original,future_cap,clocks,&mut last).unwrap();\n        assert!(last>0);\n        let retained=last;\n        assert!(relay_clock(&ClockOnly,original,original,epoch,clocks,&mut last).is_err());\n        assert_eq!(last,retained);\n        assert_eq!(clocks.restrictive_offset(original,original).unwrap(),60_000);\n    }\n\n    #[test]\n    fn return_native_admissions_and_outbound_samples_deny_r_and_q() {\n        for (before, after) in [(68, 69), (71, 72)] {\n            let q = Phases::new();\n            q.step(0, 0, before).unwrap();\n            q.begin_quiescence(q.snapshot()).unwrap();\n            assert!(q.step(0, before, after).is_err());\n            assert!(q.source_send_restricted(0, before).is_err());\n            assert!(q.positive_send_restricted().is_err());\n            assert_eq!(q.phase(0), before);\n            let r = Phases::new();\n            r.step(0, 0, before).unwrap(); r.revoke();\n            assert!(r.step(0, before, after).is_err());\n', 'restore': '        // Ordinary upstream immutable observations; no queued send or new authority.\n        if let Err(error) = crate::channel::require_time(original_deadline) {\n            self.core.phase.revoke();\n            return Err(error);\n        }\n        self.send(packet)\n    }\n}\n#[cfg(test)]\nmod tests {\n    use super::*;\n    #[test]\n    fn return_native_admissions_and_outbound_samples_deny_r_and_q() {\n        for (before, after) in [(68, 69), (71, 72)] {\n            let q = Phases::new();\n            q.step(0, 0, before).unwrap();\n            q.begin_quiescence(q.snapshot()).unwrap();\n            assert!(q.step(0, before, after).is_err());\n            assert!(q.source_send_restricted(0, before).is_err());\n            assert!(q.positive_send_restricted().is_err());\n            assert_eq!(q.phase(0), before);\n            let r = Phases::new();\n            r.step(0, 0, before).unwrap(); r.revoke();\n            assert!(r.step(0, before, after).is_err());\n'}, {'remove': '                let d = s\n                    .read\n                    .result\n                    .as_ref()\n                    .ok_or_else(|| rejected("relay Exact before actual prepared"))?;\n                if s.read.phase != 70 || !s.read.reported || !exact_matches(presentation, rp, d) {\n                    return Err(rejected("relay Exact changed prepared source"));\n                }\n                relay_clock(\n                    presentation,\n                    deadline,\n                    writer,\n                    writer_wall,\n                    self.clocks,\n                    &mut slot.last_wall,\n                )?;\n                s.exact.wire = Some(presentation.clone());\n                s.exact.phase = 71;\n                Ok(true)\n            }\n            Packet::ReturnPrepared { data, .. } => {\n                data.validate()?;\n                let t = &mut s.read;\n                let p = t\n                    .wire\n', 'restore': '                let d = s\n                    .read\n                    .result\n                    .as_ref()\n                    .ok_or_else(|| rejected("relay Exact before actual prepared"))?;\n                if s.read.phase != 70 || !s.read.reported || !exact_matches(presentation, rp, d) {\n                    return Err(rejected("relay Exact changed prepared source"));\n                }\n                relay_clock(\n                    presentation,\n                    deadline,\n                    writer,\n                    self.clocks,\n                    &mut slot.last_wall,\n                )?;\n                s.exact.wire = Some(presentation.clone());\n                s.exact.phase = 71;\n                Ok(true)\n            }\n            Packet::ReturnPrepared { data, .. } => {\n                data.validate()?;\n                let t = &mut s.read;\n                let p = t\n                    .wire\n'}, {'remove': '                    return Err(rejected("Return relay changed transport"));\n                }\n                if s.read.wire.is_some()\n                    || presentation.actor != a.actor\n                    || !same_original(presentation, &w, &r, service_ceiling, writer_ceiling)\n                {\n                    return Err(rejected("sign relay display predecessor"));\n                }\n                relay_clock(\n                    presentation,\n                    deadline,\n                    writer,\n                    writer_wall,\n                    self.clocks,\n                    &mut slot.last_wall,\n                )?;\n                s.read.wire = Some(presentation.clone());\n                s.read.phase = 68;\n                Ok(true)\n            }\n            Packet::ReturnExactDisplay { presentation } => {\n                if self.restricted {\n                    return Ok(false);\n                }\n                let t = transport.ok_or_else(|| rejected("Return missing transport"))?;\n', 'restore': '                    return Err(rejected("Return relay changed transport"));\n                }\n                if s.read.wire.is_some()\n                    || presentation.actor != a.actor\n                    || !same_original(presentation, &w, &r, service_ceiling, writer_ceiling)\n                {\n                    return Err(rejected("sign relay display predecessor"));\n                }\n                relay_clock(\n                    presentation,\n                    deadline,\n                    writer,\n                    self.clocks,\n                    &mut slot.last_wall,\n                )?;\n                s.read.wire = Some(presentation.clone());\n                s.read.phase = 68;\n                Ok(true)\n            }\n            Packet::ReturnExactDisplay { presentation } => {\n                if self.restricted {\n                    return Ok(false);\n                }\n                let t = transport.ok_or_else(|| rejected("Return missing transport"))?;\n'}, {'remove': '                s.terminal = true;\n                self.core.phase.revoke();\n                Ok(CoordinatorFinancialEventV1::ReturnFailed { role, data })\n            }\n            _ => Err(rejected("wrong sign event")),\n        }\n    }\n}\nfn relay_clock<P: Presentation>(\n    p: &P,\n    service: Instant,\n    writer: Instant,\n    writer_wall: Instant,\n    clocks: FullWorkflowClocksV1,\n    last: &mut u64,\n) -> Result<()> {\n    p.validate()?;\n    let now = Instant::now();\n    clocks.restrict_received(PROFILE, p.ceiling(), service.min(writer).min(writer_wall), now)?;\n    let wall = state::wall_ms()?;\n    let (a, b) = p.times();\n    if wall < *last || wall < a || wall >= b || wall >= p.transport().2 || wall >= p.transport().3 {\n        return Err(rejected("sign relay action expired"));\n    }\n    *last = wall;\n    Ok(())\n}\nimpl HostFinancialWorkflowRelayV1 {\n    pub(in crate::financial_workflow_origin) fn down_return(&mut self, p: &Packet) -> Result<()> {\n        if self.restricted {\n            return Err(rejected("sign relay after R"));\n        }\n        let role = p.target()?.ok_or_else(|| rejected("sign relay role"))?;\n        let slot = self.slots[role.index()]\n            .as_mut()\n            .ok_or_else(|| rejected("sign relay missing source"))?;\n        let (_, _, service, writer) = slot.activate.wallet_predecessor()?;\n        let writer_wall = slot.activate.retained_wall_deadline()?;\n        let deadline = service.deadline;\n        let s = &mut slot.activate.wallet.sign.returning;\n        if s.terminal {\n            return Err(rejected("sign relay terminal"));\n        }\n        match p {\n            Packet::ReturnReadFinal {\n                presentation_digest,\n                ..\n            } => {\n                let t = &mut s.read;\n                let p = t\n                    .wire\n                    .as_ref()\n                    .ok_or_else(|| rejected("sign relay before display"))?;\n                if t.phase != 68 || presentation_digest != &p.presentation_digest {\n                    return Err(rejected("sign relay Final mismatch/replay"));\n                }\n                relay_clock(p, deadline, writer, writer_wall, self.clocks, &mut slot.last_wall)?;\n                t.phase = 69;\n                Ok(())\n            }\n            Packet::ReturnExactFinal {\n                presentation_digest,\n                ..\n            } => {\n                let t = &mut s.exact;\n                let p = t\n                    .wire\n                    .as_ref()\n                    .ok_or_else(|| rejected("sign relay before display"))?;\n                if t.phase != 71 || presentation_digest != &p.presentation_digest {\n                    return Err(rejected("sign relay Final mismatch/replay"));\n                }\n                relay_clock(p, deadline, writer, writer_wall, self.clocks, &mut slot.last_wall)?;\n                t.phase = 72;\n                Ok(())\n            }\n            _ => Err(rejected("wrong sign relay command")),\n        }\n    }\n    pub(in crate::financial_workflow_origin) fn up_return(\n        &mut self,\n        role: Target,\n        p: &Packet,\n    ) -> Result<bool> {\n        let transport = if matches!(\n            p,\n            Packet::ReturnReadDisplay { .. } | Packet::ReturnExactDisplay { .. }\n        ) && !self.restricted\n        {\n            Some(self.v3_entries[role.index()].return_transport_bounds(self.clocks)?)\n        } else {\n            None\n        };\n        let slot = self.slots[role.index()]\n            .as_mut()\n            .ok_or_else(|| rejected("sign relay missing source"))?;\n        let (a, _, service, writer) = slot.activate.wallet_predecessor()?;\n        let writer_wall = slot.activate.retained_wall_deadline()?;\n        let service_ceiling = service.correlation().service_ceiling_ms;\n        let deadline = service.deadline;\n        let writer_ceiling = self\n            .clocks\n            .restrictive_offset(writer, self.clocks.supervision())?;\n        let (w, r) = slot.activate.wallet.sign.return_predecessor()?;\n        let w = w.clone();\n        let r = r.clone();\n        let a = a.clone();\n        let s = &mut slot.activate.wallet.sign.returning;\n        if s.terminal {\n            return Err(rejected("sign relay terminal"));\n', 'restore': '                s.terminal = true;\n                self.core.phase.revoke();\n                Ok(CoordinatorFinancialEventV1::ReturnFailed { role, data })\n            }\n            _ => Err(rejected("wrong sign event")),\n        }\n    }\n}\nfn relay_clock<P: Presentation>(\n    p: &P,\n    service: Instant,\n    writer: Instant,\n    clocks: FullWorkflowClocksV1,\n    last: &mut u64,\n) -> Result<()> {\n    p.validate()?;\n    let now = Instant::now();\n    clocks.restrict_received(PROFILE, p.ceiling(), service.min(writer), now)?;\n    let wall = state::wall_ms()?;\n    let (a, b) = p.times();\n    if wall < *last || wall < a || wall >= b || wall >= p.transport().2 || wall >= p.transport().3 {\n        return Err(rejected("sign relay action expired"));\n    }\n    *last = wall;\n    Ok(())\n}\nimpl HostFinancialWorkflowRelayV1 {\n    pub(in crate::financial_workflow_origin) fn down_return(&mut self, p: &Packet) -> Result<()> {\n        if self.restricted {\n            return Err(rejected("sign relay after R"));\n        }\n        let role = p.target()?.ok_or_else(|| rejected("sign relay role"))?;\n        let slot = self.slots[role.index()]\n            .as_mut()\n            .ok_or_else(|| rejected("sign relay missing source"))?;\n        let (_, _, service, writer) = slot.activate.wallet_predecessor()?;\n        let deadline = service.deadline;\n        let s = &mut slot.activate.wallet.sign.returning;\n        if s.terminal {\n            return Err(rejected("sign relay terminal"));\n        }\n        match p {\n            Packet::ReturnReadFinal {\n                presentation_digest,\n                ..\n            } => {\n                let t = &mut s.read;\n                let p = t\n                    .wire\n                    .as_ref()\n                    .ok_or_else(|| rejected("sign relay before display"))?;\n                if t.phase != 68 || presentation_digest != &p.presentation_digest {\n                    return Err(rejected("sign relay Final mismatch/replay"));\n                }\n                relay_clock(p, deadline, writer, self.clocks, &mut slot.last_wall)?;\n                t.phase = 69;\n                Ok(())\n            }\n            Packet::ReturnExactFinal {\n                presentation_digest,\n                ..\n            } => {\n                let t = &mut s.exact;\n                let p = t\n                    .wire\n                    .as_ref()\n                    .ok_or_else(|| rejected("sign relay before display"))?;\n                if t.phase != 71 || presentation_digest != &p.presentation_digest {\n                    return Err(rejected("sign relay Final mismatch/replay"));\n                }\n                relay_clock(p, deadline, writer, self.clocks, &mut slot.last_wall)?;\n                t.phase = 72;\n                Ok(())\n            }\n            _ => Err(rejected("wrong sign relay command")),\n        }\n    }\n    pub(in crate::financial_workflow_origin) fn up_return(\n        &mut self,\n        role: Target,\n        p: &Packet,\n    ) -> Result<bool> {\n        let transport = if matches!(\n            p,\n            Packet::ReturnReadDisplay { .. } | Packet::ReturnExactDisplay { .. }\n        ) && !self.restricted\n        {\n            Some(self.v3_entries[role.index()].return_transport_bounds(self.clocks)?)\n        } else {\n            None\n        };\n        let slot = self.slots[role.index()]\n            .as_mut()\n            .ok_or_else(|| rejected("sign relay missing source"))?;\n        let (a, _, service, writer) = slot.activate.wallet_predecessor()?;\n        let service_ceiling = service.correlation().service_ceiling_ms;\n        let deadline = service.deadline;\n        let writer_ceiling = self\n            .clocks\n            .restrictive_offset(writer, self.clocks.supervision())?;\n        let (w, r) = slot.activate.wallet.sign.return_predecessor()?;\n        let w = w.clone();\n        let r = r.clone();\n        let a = a.clone();\n        let s = &mut slot.activate.wallet.sign.returning;\n        if s.terminal {\n            return Err(rejected("sign relay terminal"));\n'}, {'remove': '            return Err(rejected("Return replaced original transport/material"));\n        }\n        a.wallet_bounds()?;\n        let now = Instant::now();\n        let (t, e) = p.times();\n        let deadline = a\n            .read\n            .entry\n            .clocks\n            .restrict_received(\n                PROFILE,\n                p.ceiling(),\n                a.read.service.deadline.min(a.read.writer_deadline).min(a.read.writer_wall_deadline),\n                now,\n            )?\n            .min(wall_ceiling(now, state::wall_ms()?, t, e)?);\n        let b = Arc::new(Self {\n            activation: a,\n            p,\n            deadline,\n            read_deadline: deadline,\n            last_wall: AtomicU64::new(state::wall_ms()?),\n            transport,\n        });\n        b.bounds()?;\n', 'restore': '            return Err(rejected("Return replaced original transport/material"));\n        }\n        a.wallet_bounds()?;\n        let now = Instant::now();\n        let (t, e) = p.times();\n        let deadline = a\n            .read\n            .entry\n            .clocks\n            .restrict_received(\n                PROFILE,\n                p.ceiling(),\n                a.read.service.deadline.min(a.read.writer_deadline),\n                now,\n            )?\n            .min(wall_ceiling(now, state::wall_ms()?, t, e)?);\n        let b = Arc::new(Self {\n            activation: a,\n            p,\n            deadline,\n            read_deadline: deadline,\n            last_wall: AtomicU64::new(state::wall_ms()?),\n            transport,\n        });\n        b.bounds()?;\n'}]}}
def p85_restore(path,source):
    if path in P89_RESTORATION:source=p89_restore(path,source)
    pin=P85_RESTORATION[path]
    assert sha(source)==pin['candidate_sha256'],('P85 current source',path)
    for change in pin['exact_inverse']:
        assert source.count(change['remove'])==1,('P85 exact inverse occurrence',path)
        source=source.replace(change['remove'],change['restore'],1)
    assert sha(source)==pin['baseline_sha256'],('P85 baseline source',path)
    return source

# P77 source erasure is applied BEFORE the unchanged P75-to-P74 inverse.
P77_RESTORATION = {'crates/wholepact-financial-coordinator-origin/src/witness_retirement.rs': {'baseline_sha256': 'd1e408ff0b7b134bd721acd43e8e11d836ac88b6d5ab32b8927d97073d0330c4', 'exact_inverse': [{'remove': '    /// Disposed and the received, unadmitted Writer Read create this ticket.\n    /// While its automatic display is still in flight, retain ordinary receive\n    /// and the original W cleanup cutoff; do not enter exclusive grammar yet.\n    pub fn try_prepare_witness_retirement(&mut self,role:Target)->Result<Option<CoordinatorWitnessRetirementTicketV1>>{\n        self.core.check_action_restrictions()?;let phases=self.core.phase.snapshot();self.retirement_idle(phases,RetirementPurpose::FinancialContinuation,role)?;\n        let slot=self.slots[role.index()].as_ref().ok_or_else(||rejected("retirement Signer missing"))?;\n        if slot.wire_phase!=admit::AWAITING_NEXT_READ&&!slot.writer_acquire.signing_setup_pending(slot.wire_phase){return Err(rejected("retirement before exact S response"));}\n        let(p,committed)=slot.admission.retained_result()?;\n        let(instance,cutoff,outcome)=self.witnesses[role.index()].retirement_record()?;\n        match outcome{\n            FinancialWitnessOutcomeV1::Committed{presentation_digest:_,effect_commitment:_,head_sequence,head_digest}\n                if *head_sequence==committed.head_sequence&&head_digest==&committed.head_digest=>{},\n            _=>return Err(rejected("retirement S/W committed heads differ")),\n        }\n        self.witnesses[role.index()].retirement_matches_admit(p)?;\n        // Exclusive H traffic is shared by both original owners. A different\n        // owner can also have an automatic, not-yet-received display in flight.\n        if self.slots.iter().flatten().any(|s|matches!(s.wire_phase,SOURCE_RETAINED|AWAITING_ADMISSION|admit::AWAITING_NEXT_READ)) {\n            crate::channel::require_time(cutoff)?;\n            return Ok(None);\n        }\n        let request=RetirementRequest{profile:PROFILE.into(),coordinator:self.coordinator.clone(),session:self.session.clone(),target:role,purpose:RetirementPurpose::FinancialContinuation,binding_digest:p.presentation_digest.clone(),\n            witness_instance:instance.to_owned(),challenge:state::nonce()?,cleanup_ceiling_ms:self.clocks.cleanup_offset(cutoff)?,signing:None};\n        let cutoff=request.validate(self.clocks)?.min(cutoff);crate::channel::require_time(cutoff)?;\n        Ok(Some(CoordinatorWitnessRetirementTicketV1{core:Arc::clone(&self.core),entries:self.slots.iter().flatten().filter_map(|s|s.entry.as_ref().map(Arc::clone)).collect(),request,cutoff,\n            phases,consumed:false}))\n    }\n    pub fn prepare_signing_retirement(&mut self,role:Target)->Result<CoordinatorWitnessRetirementTicketV1>{\n        self.core.check_action_restrictions()?;\n        let phases=self.core.phase.snapshot();self.retirement_idle(phases,RetirementPurpose::FinancialSigning,role)?;\n        let slot=self.slots[role.index()].as_ref().ok_or_else(||rejected("Signing retirement Source absent"))?;\n        if slot.wire_phase!=67||!slot.activate.wallet.sign.selector_seen{return Err(rejected("Signing retirement before actual committed Sign and selector"));}\n', 'restore': '    /// Disposed create this fixed-purpose ticket. Other W purposes have no\n    /// conversion until their real source disposal adapter is joined.\n    pub fn prepare_witness_retirement(&mut self,role:Target)->Result<CoordinatorWitnessRetirementTicketV1>{\n        self.core.check_action_restrictions()?;let phases=self.core.phase.snapshot();self.retirement_idle(phases,RetirementPurpose::FinancialContinuation,role)?;\n        let slot=self.slots[role.index()].as_ref().ok_or_else(||rejected("retirement Signer missing"))?;\n        if slot.wire_phase!=admit::AWAITING_NEXT_READ&&!slot.writer_acquire.signing_setup_pending(slot.wire_phase){return Err(rejected("retirement before exact S response"));}\n        let(p,committed)=slot.admission.retained_result()?;\n        let(instance,cutoff,outcome)=self.witnesses[role.index()].retirement_record()?;\n        match outcome{\n            FinancialWitnessOutcomeV1::Committed{presentation_digest:_,effect_commitment:_,head_sequence,head_digest}\n                if *head_sequence==committed.head_sequence&&head_digest==&committed.head_digest=>{},\n            _=>return Err(rejected("retirement S/W committed heads differ")),\n        }\n        self.witnesses[role.index()].retirement_matches_admit(p)?;\n        let request=RetirementRequest{profile:PROFILE.into(),coordinator:self.coordinator.clone(),session:self.session.clone(),target:role,purpose:RetirementPurpose::FinancialContinuation,binding_digest:p.presentation_digest.clone(),\n            witness_instance:instance.to_owned(),challenge:state::nonce()?,cleanup_ceiling_ms:self.clocks.cleanup_offset(cutoff)?,signing:None};\n        let cutoff=request.validate(self.clocks)?.min(cutoff);crate::channel::require_time(cutoff)?;\n        Ok(CoordinatorWitnessRetirementTicketV1{core:Arc::clone(&self.core),entries:self.slots.iter().flatten().filter_map(|s|s.entry.as_ref().map(Arc::clone)).collect(),request,cutoff,\n            phases,consumed:false})\n    }\n    pub fn prepare_signing_retirement(&mut self,role:Target)->Result<CoordinatorWitnessRetirementTicketV1>{\n        self.core.check_action_restrictions()?;\n        let phases=self.core.phase.snapshot();self.retirement_idle(phases,RetirementPurpose::FinancialSigning,role)?;\n        let slot=self.slots[role.index()].as_ref().ok_or_else(||rejected("Signing retirement Source absent"))?;\n        if slot.wire_phase!=67{return Err(rejected("Signing retirement before actual committed Sign"));}\n'}]}, 'crates/wholepact-financial-coordinator-origin/src/financial_workflow_origin.rs': {'baseline_sha256': '5b5451dea6487806c9e73bb03cc1ace888eb1912c1f42f4d13fd3503926db3fa', 'exact_inverse': [{'remove': '                        if slot.phase!=67||!slot.activate.wallet.sign.selector_seen{return Err(rejected("Host Signing retirement before actual Sign and selector"));}\n                        let(_,signed)=slot.activate.wallet.sign.return_predecessor()?;\n                        let(_,_,service,_)=slot.writer_acquire.retained_result()?;\n                        let binding=request.signing.as_ref().ok_or_else(||rejected("Host Signing retirement lacks actual result"))?;\n                        if binding.signed!=*signed||binding.original_commitment!=service.correlation().original.commitment()?||request.witness_instance!=service.correlation().witness_instance||binding.commitment()?!=request.binding_digest{return Err(rejected("Host Signing retirement original/result mismatch"));}\n                    },\n                    crate::host_interstage::RetirementPurpose::FinancialContinuation=>{\n                        let(p,_)=slot.admission.retained_result()?;\n                        if !slot.writer_acquire.signing_setup_pending(slot.phase)\n                            ||self.slots.iter().flatten().any(|s|matches!(s.phase,SOURCE_RETAINED|AWAITING_ADMISSION|admit::AWAITING_NEXT_READ))\n                            ||request.binding_digest!=p.presentation_digest{return Err(rejected("Host retirement before actual admitted response"));}\n', 'restore': '                        if slot.phase!=67{return Err(rejected("Host Signing retirement before actual Sign"));}\n                        let(_,signed)=slot.activate.wallet.sign.return_predecessor()?;\n                        let(_,_,service,_)=slot.writer_acquire.retained_result()?;\n                        let binding=request.signing.as_ref().ok_or_else(||rejected("Host Signing retirement lacks actual result"))?;\n                        if binding.signed!=*signed||binding.original_commitment!=service.correlation().original.commitment()?||request.witness_instance!=service.correlation().witness_instance||binding.commitment()?!=request.binding_digest{return Err(rejected("Host Signing retirement original/result mismatch"));}\n                    },\n                    crate::host_interstage::RetirementPurpose::FinancialContinuation=>{\n                        let(p,_)=slot.admission.retained_result()?;\n                        if (slot.phase!=admit::AWAITING_NEXT_READ&&!slot.writer_acquire.signing_setup_pending(slot.phase))||request.binding_digest!=p.presentation_digest{return Err(rejected("Host retirement before actual admitted response"));}\n'}]}, 'crates/wholepact-financial-coordinator/src/financial_source_driver.rs': {'baseline_sha256': '1f562acd4f16cdbe7c93106ac5d2dc3d9197aa1e4af8389fc97f9ab95e3bda7b', 'exact_inverse': [{'remove': '                    // None retains ordinary receive for the automatic Writer\n                    // Read display, under the same original disposal cutoff.\n                    let Some(ticket) = endpoint.try_prepare_witness_retirement(role)? else {\n                        continue;\n                    };\n', 'restore': '                    let ticket = endpoint.prepare_witness_retirement(role)?;\n'}]}}
P77_ORIGIN='crates/wholepact-financial-coordinator-origin/src/'
P77_DRIVER='crates/wholepact-financial-coordinator/src/financial_source_driver.rs'
RETIREMENT_TEST_NAMES=(
 'old_prepare_rejects_late_display_at_both_strict_waits',
 'deferred_prepare_drains_actual_display_before_quiescence_both_roles',
 'all_three_automatic_frontiers_defer_either_owner_without_nonce',
 'pending_preserves_restriction_cancel_currentness_and_idle_denials',
 'pending_preserves_head_binding_disposal_and_missing_owner_denials',
 'pending_uses_original_cutoff_and_expiry_never_mints_nonce',
 'some_requires_existing_unadmitted_writer_read_predicate',
 'ordinary_display_rejects_wrong_owner_binding_duplicate_and_terminal',
 'strict_wait_rejects_mismatch_ordinary_traffic_restriction_and_expiry',
 'host_guard_requires_pending_target_and_no_any_owner_frontier',
 'actual_driver_role_continue_keeps_next_receive_and_host_pump_runnable',
 'signing_guards_require_received_selector_and_strict_wait_rejects_late_selector',
)
def p77_restore(path,source):
    if path in P85_RESTORATION:source=p85_restore(path,source)
    for change in P77_RESTORATION.get(path,{}).get('exact_inverse',[]):
        if source.count(change['remove'])!=1:raise AssertionError(('P77 inverse occurrence',path))
        source=source.replace(change['remove'],change['restore'],1)
    return source

def retirement_items():
    retirement=(ROOT/(P77_ORIGIN+'witness_retirement.rs')).read_text()
    writer=(ROOT/(P77_ORIGIN+'signer_writer_read_acquire_origin.rs')).read_text()
    relay=(ROOT/PATHS['relay']).read_text();driver=(ROOT/P77_DRIVER).read_text()
    old=p77_restore(P77_ORIGIN+'witness_retirement.rs',retirement)
    out={name:item(retirement,anchor) for name,anchor in {
        'try_prepare':'pub fn try_prepare_witness_retirement(',
        'idle':'fn retirement_idle(', 'bounds':'fn retirement_bounds(',
        'wait':'fn retirement_wait_host(', 'idle_mask':'fn idle_phase_snapshot('
    }.items()}
    out['old_prepare']=item(old,'pub fn prepare_witness_retirement(')
    out['c_pending']=item(writer,'pub(super) fn signing_setup_pending(&self, phase:u8)')
    out['h_pending']=item(writer,'pub(super) fn signing_setup_pending(&self,phase:u8)')
    receive=item(writer,'pub(super) fn receive_writer_acquire_event(')
    arm=item(receive,'Packet::WriterReadDisplay { data } =>',body_after_anchor=True)
    out['receive_head']=receive[:receive.index('Packet::WriterReadDisplay { data } =>')]
    out['receive_arm']=arm
    out['host_guard']=item(relay,'crate::host_interstage::RetirementPurpose::FinancialContinuation=>')
    out['c_sign_guard']=item(retirement,'if slot.wire_phase!=67||!slot.activate.wallet.sign.selector_seen')
    out['h_sign_guard']=item(relay,'if slot.phase!=67||!slot.activate.wallet.sign.selector_seen')
    selector=(ROOT/(P77_ORIGIN+'financial_selector_origin.rs')).read_text()
    out['c_selector_replay']=item(selector,'if slot.activate.wallet.sign.selector_seen {return Err(rejected("selector replay"))')
    out['h_selector_replay']=item(selector,'if slot.activate.wallet.sign.selector_seen {return Err(rejected("relay selector replay"))')
    out['driver_predicate']=item(driver,'fn may_retire_signing_predecessor(')
    start=driver.index('            // Both authenticated S completion and actual W disposal are necessary.')
    stop=driver.index('            // Genuine Signing tickets/Serving remain opaque through this driver.',start)
    out['driver_role_loop']=item(driver[start:stop],'for role in [Role::Signer1, Role::Signer2]')
    out['require_time']=item((ROOT/(P77_ORIGIN+'channel.rs')).read_text(),'pub(super) fn require_time(')
    specs={'source_constants':('financial_workflow_source.rs',('V3_HELD','SOURCE_RETAINED','HISTORY_RETAINED')),
           'continue_constant':('financial_workflow_continue.rs',('AWAITING_ADMISSION',)),
           'admit_constant':('signer_admit_origin.rs',('AWAITING_NEXT_READ',)),
           'writer_constants':('signer_writer_read_acquire_origin.rs',('WRITER_READ_REVIEW','WRITER_READ_ADMITTED')),
           'witness_constant':('financial_witness_coordinator.rs',('W_ADMITTED',)),
           'history_constants':('financial_history_coordinator.rs',('H_DONE','H_RETIRED'))}
    import re
    for key,(path,names) in specs.items():
        text=(ROOT/(P77_ORIGIN+path)).read_text();parts=[]
        for name in names:
            found=re.findall(r'pub\(super\) const '+name+r'\s*:\s*u8\s*=\s*\d+;',text)
            if len(found)!=1:raise AssertionError(('phase constant',path,name))
            parts.append(found[0])
        out[key]='\n'.join(parts)
    return out

def item(source, anchor, *, body_after_anchor=False):
    """Extract one selected Rust item without rewriting a byte of its body."""
    if source.count(anchor) != 1:
        raise AssertionError(('nonunique selected item', anchor))
    start = source.index(anchor)
    opening = source.index('{', start + len(anchor) if body_after_anchor else start)
    depth, block, quoted, escaped = 0, 0, False, False
    i = opening
    while i < len(source):
        if quoted:
            if escaped:
                escaped = False
            elif source[i] == '\\':
                escaped = True
            elif source[i] == '"':
                quoted = False
            i += 1
            continue
        if block:
            if source.startswith('/*', i):
                block += 1
                i += 2
            elif source.startswith('*/', i):
                block -= 1
                i += 2
            else:
                i += 1
            continue
        if source.startswith('//', i):
            end = source.find('\n', i)
            if end < 0:
                break
            i = end + 1
            continue
        if source.startswith('/*', i):
            block = 1
            i += 2
            continue
        c = source[i]
        if c == '"':
            quoted = True
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    raise AssertionError(('unbalanced selected item', anchor))

TEST_NAMES = (
 'pump_error_preserves_identity_and_pre_drop_order',
 'pump_ok_false_has_no_failure_side_effects',
 'pump_ok_true_has_no_failure_side_effects',
 'finish_incoming_error_preserves_identity_and_pre_drop_order',
 'normal_custody_drop_has_no_failure_fact_or_append',
 'existing_failure_survives_relay_pump_and_finish',
 'signer_wrapper_keeps_returned_error_not_first_category',
 'signer_wrapper_ok_does_not_classify_or_mark',
)

def sha(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def inputs():
    return {name:(ROOT/path).read_text() for name,path in PATHS.items()}

def unique_line(source, prefix):
    lines=[line for line in source.splitlines() if line.startswith(prefix)]
    if len(lines)!=1:raise AssertionError(('nonunique selected line',prefix))
    return lines[0]

def extracted_items():
    s=inputs()
    out={name:item(s[key],anchor) for name,(key,anchor) in ANCHORS.items()}
    out['owner_struct']=unique_line(s['lifecycle'],'pub(super) struct HostLifecycleOwner')
    out['stage_codes']=unique_line(s['diagnostic'],'codes!(Stage {')
    out['class_codes']=unique_line(s['diagnostic'],'codes!(Class {')
    return out

class SourceContracts(unittest.TestCase):
    def test_host_observation_erases_to_exact_P74_files(self):
        for path,record in RESTORATION.items():
            restored=p77_restore(path,(ROOT/path).read_text())
            for change in record['exact_inverse']:
                self.assertEqual(restored.count(change['remove']),1,path)
                restored=restored.replace(change['remove'],change['restore'],1)
            self.assertEqual(sha(restored),record['baseline_sha256'],path)
    def test_actual_destructors_and_host_field_order_are_source_bound(self):
        s=inputs();e=extracted_items()
        for name in ('relay_drop','owner_drop','owner_struct'):
            self.assertEqual(sha(e[name]),BASE_ITEM_SHA[name])
        host=item(s['bootstrap'],'pub struct HostOriginV1')
        self.assertEqual(sha(host),BASE_ITEM_SHA['host_origin_fields'])
        self.assertLess(host.index('lifecycle_owner:'),host.index('verifier_custody:'))
        self.assertLess(host.index('verifier_custody:'),host.index('signers:'))
    def test_source_items_are_copied_unchanged(self):
        generated,items=build_legacy_harness()
        for name,value in items.items():self.assertEqual(generated.count(value),1,name)
        self.assertIn('self.live.store(false, Ordering::Release);',items['custody_drop'])
        self.assertIn('drop(self.host.take());result',items['relay_finish'])
    def test_signer_wrapper_returns_original_kernel_category(self):
        wrapper=extracted_items()['signer_wrapper']
        self.assertIn('failure.returned_error()',wrapper)
        self.assertNotIn('failure.into_error()',wrapper)
        self.assertIn('failure.error(),callback',wrapper)
        self.assertEqual(wrapper.count('diagnostic::driver(stage,class);'),1)
    def test_harness_inventory_and_explicit_inert_scope(self):
        generated,_=build_legacy_harness()
        self.assertEqual(len(TEST_NAMES),8)
        for name in TEST_NAMES:self.assertEqual(generated.count('fn '+name+'()'),1,name)
        self.assertNotIn('struct HostOriginV1',generated)
        self.assertNotIn('Command::new',generated)
        self.assertNotIn('UnixStream',generated)

    def test_p77_exact_three_file_erasure_to_P76(self):
        for path,record in P77_RESTORATION.items():
            self.assertEqual(sha(p77_restore(path,(ROOT/path).read_text())),record['baseline_sha256'])
    def test_p77_selected_items_are_byte_exact_and_driver_order_is_bound(self):
        rust,items=build_retirement_harness()
        for name,value in items.items():self.assertEqual(rust.count(value),1,name)
        self.assertIn('=> {',items['receive_arm'])
        self.assertIn('SignerFinancialWriterReadTicketV1 {',items['receive_arm'])
        self.assertIn('slot.writer_acquire.read = Some(Arc::clone(&b));',items['receive_arm'])
        self.assertTrue(items['receive_arm'].endswith('\n            }'))
        driver=(ROOT/P77_DRIVER).read_text();loop=items['driver_role_loop']
        self.assertIn('else {\n                        continue;\n                    };',loop)
        self.assertLess(driver.index('endpoint.try_receive().inspect_err'),driver.index(loop))
        self.assertLess(driver.index(loop),driver.index('host.pump(&host_input'))
        self.assertNotIn('struct HostOriginV1',rust)
        self.assertNotIn('Command::new',rust)
        # Producer scheduling is source-bound only; no real worker is run.
        tail=(ROOT/'crates/wholepact-signer/src/native_ui/runtime/coordinated_financial_driver_v1/financial_tail_v1.rs').read_text()
        self.assertEqual(sha(tail),'ee9f7a52692593200ef2e85f6f4c13acefc01cf2fad3ff8663b2cb0d777a911b')
        for snippet in ['FinancialState::Opened(v)=>{\n                self.state=State::Financial(FinancialState::Opened(v));\n                self.origin.source_opened()?;', 'self.spawn_financial(move ||v.prepare_read().map(FinancialState::InitialPrepared))?;return Ok(())', 'FinancialState::InitialPrepared(v)=>FinancialState::InitialRead(v.offer(&mut self.origin)?),', 'self.spawn_financial(move ||PreparedCoordinatedAdmitRoleV1::inspect(actual,deadline).map(FinancialState::AdmitInspected))?;return Ok(())', 'FinancialState::AdmitInspected(v)=>FinancialState::AdmitReview(v.offer(&mut self.origin)?),', 'self.spawn_financial(move ||PreparedCoordinatedWriterReadRoleV1::prepare(actual,deadline).map(FinancialState::WriterPrepared))?;return Ok(())', 'let p=self.origin.offer_writer_read(v.facts().clone(),v.original_source_deadline(),v.original_read_deadline())?;', 'FinancialState::SignCommit(v)=>FinancialState::AwaitingReturn(v.into_result().map_err(|_|Error::Uncertain)?),', 'if let State::Financial(FinancialState::AwaitingReturn(actual))=&mut self.state {\n            // Actual owner is stored before any fallible metadata observation.\n            actual.report_result_selector(&mut self.origin)?;\n        }']:self.assertEqual(tail.count(snippet),1)
        pump=item((ROOT/PATHS['relay']).read_text(),'fn pump_inner(&mut self)')
        self.assertEqual(sha(pump),'29e147f61b505013b2f62d9c7758760b54b0e2a8d8c5bfa53328834ef6b7008e')
        self.assertLess(pump.index('self.retirement_observation()'),pump.index('for target in [Target::Signer1,Target::Signer2]'))
        self.assertLess(pump.index('for target in [Target::Signer1,Target::Signer2]'),pump.index('if forward{relay_boundary!(CoordinatorSend'))
    def test_p77_inventory_and_baseline_eight_remain(self):
        self.assertEqual(len(TEST_NAMES),8);self.assertEqual(len(RETIREMENT_TEST_NAMES),12)
        self.assertEqual(sha(RUST_TESTS),'b53b54d24f398dc6c3d4c7150e4ad228042630d4d8cc05cc5a6861d8e1607066')
        rust,_=build_retirement_harness()
        for name in RETIREMENT_TEST_NAMES:self.assertEqual(rust.count('fn '+name+'()'),1,name)

    def test_p80_terminal_producers_and_original_consumers_are_exact(self):
        for path,record in P80_RESTORATION.items():
            self.assertEqual(sha(p80_restore(path,(ROOT/path).read_text())),record['baseline_sha256'],path)
        rust,e=build_terminal_phase_harness()
        # Catch an unclosed inert helper before attempting the mandatory compiler.
        self.assertEqual(item(rust,'mod terminal_phase_harness {'),rust.strip())
        for name,value in e.items():self.assertEqual(rust.count(value),1,name)
        for owner,field in [('c','wire_phase'),('h','phase')]:
            for kind,to in [('sign',67),('return',73)]:
                key=owner+'_'+kind;arm=e[key]
                self.assertIn('=> {',arm);self.assertIn('data.validate()?;',arm)
                self.assertLess(arm.index('if t.reported'),arm.index('slot.'+field+' = '+str(to)+';'))
                self.assertLess(arm.index('t.phase = '+str(to)+';'),arm.index('slot.'+field+' = '+str(to)+';'))
                if owner=='c':self.assertLess(arm.index('received_workflow_progress('),arm.index('slot.'+field+' = '+str(to)+';'))
                self.assertEqual(arm.replace('                slot.'+field+' = '+str(to)+';\n','',1),e[key+'_old'])
        # The extracted arms do not authenticate packets. Bind the actual dispatch
        # and predecessor metadata so no inert carrier is mislabeled authority.
        workflow=(ROOT/PATHS['relay']).read_text()
        for suffix in ['return self.receive_return_event(packet).map(Some);}', 'return self.receive_sign_event(packet).map(Some);}', 'return self.up_return(target,packet);}', 'return self.up_sign(target,packet);}']:
            self.assertEqual(workflow.count(suffix),1)
        activation=(ROOT/(P77_ORIGIN+'signer_activate_wallet_origin.rs')).read_text()
        self.assertEqual(activation.count('pub(super) const AWAITING_WALLET_PREPARE: u8 = 55;'),1)
        for line in ['slot.wire_phase = AWAITING_WALLET_PREPARE;','slot.phase = AWAITING_WALLET_PREPARE;']:self.assertEqual(activation.count(line),1)
        self.assertIn('slot.wire_phase!=67||!slot.activate.wallet.sign.selector_seen',e['c_sign_guard'])
        self.assertIn('slot.phase!=67||!slot.activate.wallet.sign.selector_seen',e['h_sign_guard'])
        self.assertIn('slot.wire_phase!=73||slot.activate.wallet.sign.returning.actual_completed()?!=&notice.returned[i]',e['normal_guard'])
        self.assertIn('return Ok(false)',e['received_progress'])
        self.assertIn('original workflow restricted, quiescent or closing',e['action_restrictions'])
        legacy,_=build_legacy_harness()
        self.assertEqual(sha(legacy),P80_LEGACY_GENERATED_SHA)
        self.assertEqual(len(TEST_NAMES)+len(RETIREMENT_TEST_NAMES),20)
        self.assertEqual(len(TERMINAL_PHASE_TEST_NAMES),4)
        for name in TERMINAL_PHASE_TEST_NAMES:self.assertEqual(rust.count('fn '+name+'()'),1,name)

    def test_p80_resume_tail_preserves_custody_and_pre_poll_order(self):
        rust,e=build_resume_tail_harness()
        for name,value in e.items():self.assertEqual(rust.count(value),1,name)
        source=(ROOT/P80_UI).read_text()
        raw=item(source,'fn raw_input_hook(&mut self, ctx: &egui::Context, raw: &mut egui::RawInput)')
        self.assertLess(raw.index('self.check_current();'),raw.index('self.poll_driver(ctx);'))
        tail=e['tail']
        self.assertLess(tail.index('self.native.resume_after_witness_retirement(completion)?;'),tail.index('self.writer_flow.serving.take();'))
        self.assertLess(tail.index('self.writer_flow.serving.take();'),tail.index('self.retirement_paused = None;'))
        self.assertIn('if self.phase == Phase::SigningRetiring {\n                self.writer_flow.serving.take();\n            }',tail)
        custody=item(source,'Ok(Outcome::SigningResumed(custody)) =>')
        for guard in ['self.phase != Phase::SigningRetiring','self.active != Some(role)','self.retirement_paused.is_some()','self.history_resume_pending != Some(role)','self.sign_flow.committed.as_ref() != Some(custody.signed_result())','&p.original != custody.original_binding()','custody.check_current().is_err()']:
            self.assertIn(guard,custody)
        self.assertNotIn('self.sign_flow.retired = Some(custody);',tail)
        self.assertIn('self.sign_flow.retired = Some(custody);',custody)
        signing=(ROOT/(P77_ORIGIN+'financial_signing_coordinator.rs')).read_text()
        serving=item(item(signing,'impl FinancialSigningServingV1'),'pub fn check_current(')
        self.assertIn('self.binding.service_check()?;',serving)
        self.assertIn('signing_phase(self.binding.slot())!=G_SERVING',serving)
        self.assertEqual(signing.count('pub(super) const G_SERVING: u8 = 4;'),1)
        retirement=(ROOT/(P77_ORIGIN+'witness_retirement.rs')).read_text()
        self.assertEqual(retirement.count('RetirementPurpose::FinancialSigning=>self.core.phase.signing_retirement_step(i,5,6)?,'),1)
        self.assertEqual(len(RESUME_TAIL_TEST_NAMES),1)
        self.assertEqual(rust.count('fn '+RESUME_TAIL_TEST_NAMES[0]+'()'),1)
        # Whole UI inverse pins all remaining currentness/custody guards unchanged.
        self.assertEqual(sha(p80_restore(P80_UI,source)),P80_RESTORATION[P80_UI]['baseline_sha256'])

RUST_SUPPORT=r"""
use std::{cell::RefCell, fmt, io, sync::{Arc,atomic::{AtomicBool,Ordering}}, time::Instant};
type Result<T> = std::io::Result<T>;
#[derive(Default)] struct State {
 trace:Vec<&'static str>, live:Option<Arc<AtomicBool>>, poisoned:bool,
 pump_calls:usize, flush_calls:usize, append_calls:usize, child_drops:usize,
 detail_calls:usize, signer_marks:Vec<(DriverStage,Class)>,
}
thread_local! { static STATE:RefCell<State>=RefCell::new(State::default()); }
fn trace(event:&'static str){STATE.with(|s|s.borrow_mut().trace.push(event));}
fn setup(){STATE.with(|s|*s.borrow_mut()=State::default());financial_ci_host_diagnostics::reset();}
struct HostLifecycle;
impl HostLifecycle {fn poison(&self){STATE.with(|s|{let mut s=s.borrow_mut();
 let event=if s.poisoned{"poison_again"}else{"poison"};s.trace.push(event);s.poisoned=true;});}}
pub(crate) mod financial_observer {
 pub fn financial_ci_flush_host_failure_before_owned_drop(){
  super::STATE.with(|s|{let mut s=s.borrow_mut();s.flush_calls+=1;
   assert!(!s.live.as_ref().unwrap().load(super::Ordering::Acquire));
   s.trace.push("custody_live_false_observed");
   if super::financial_ci_host_diagnostics::selected().is_some(){
    assert!(s.poisoned);s.append_calls+=1;s.trace.push("append_attempt");
   }
  });
 }
}
struct InertChild;
impl Drop for InertChild {fn drop(&mut self){STATE.with(|s|{let mut s=s.borrow_mut();
 assert!(!s.live.as_ref().unwrap().load(Ordering::Acquire));
 s.child_drops+=1;s.trace.push("owned_child_drop");});}}
// An inert ownership aggregate, deliberately NOT HostOriginV1 or a native Final.
// SourceContracts binds the real Host declaration's relevant relative order.
struct InertOwnedFields {lifecycle_owner:HostLifecycleOwner,
 verifier_custody:Option<HostVerifierCustody>,signers:InertChild}
struct HostFinancialWorkflowRelayV1 {lifecycle:Arc<HostLifecycle>,host:Option<InertOwnedFields>,
 next:Option<Result<bool>>,cancel_seen:bool,disposed:[bool;2],cleanup:Option<Instant>}
impl HostFinancialWorkflowRelayV1 {
 fn new(next:Result<bool>)->Self{let lifecycle=Arc::new(HostLifecycle);let custody=HostVerifierCustody::new();
 STATE.with(|s|s.borrow_mut().live=Some(Arc::clone(&custody.live)));
 Self{lifecycle:Arc::clone(&lifecycle),host:Some(InertOwnedFields{
 lifecycle_owner:HostLifecycleOwner(lifecycle),verifier_custody:Some(custody),signers:InertChild}),
 next:Some(next),cancel_seen:false,disposed:[false;2],cleanup:None}}
 fn pump_inner(&mut self)->Result<bool>{STATE.with(|s|s.borrow_mut().pump_calls+=1);self.next.take().unwrap()}
 fn is_disposed(&self)->bool{self.disposed==[true;2]}
}
fn rejected(message:&str)->io::Error{io::Error::new(io::ErrorKind::PermissionDenied,message.to_owned())}
mod bootstrap {pub(super) fn finish_host_capped(_:super::InertOwnedFields,_:Option<super::Instant>)->super::Result<()>{panic!("not reached by incoming-Err trace")}}
#[derive(Debug)] struct IdentityError(Arc<()>);
impl fmt::Display for IdentityError {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{write!(f,"inert diagnostic sentinel")}}
impl std::error::Error for IdentityError {}
fn failure()->(io::Error,usize,Arc<()>){let token=Arc::new(());let error=io::Error::new(io::ErrorKind::PermissionDenied,IdentityError(Arc::clone(&token)));
 let address=error.get_ref().unwrap() as *const (dyn std::error::Error+Send+Sync) as *const () as usize;(error,address,token)}
fn assert_identity(error:&io::Error,address:usize,token:&Arc<()>){assert_eq!(error.kind(),io::ErrorKind::PermissionDenied);
 assert_eq!(error.get_ref().unwrap() as *const (dyn std::error::Error+Send+Sync) as *const () as usize,address);
 assert!(Arc::ptr_eq(&error.get_ref().unwrap().downcast_ref::<IdentityError>().unwrap().0,token));}
fn assert_order(){STATE.with(|s|{let s=s.borrow();let pos=|key|s.trace.iter().position(|x|*x==key).unwrap();
 assert!(pos("latch_attempt")<pos("poison"));assert!(pos("poison")<pos("custody_live_false_observed"));
 assert!(pos("custody_live_false_observed")<pos("append_attempt"));assert!(pos("append_attempt")<pos("owned_child_drop"));
 assert_eq!(s.append_calls,1);assert_eq!(s.child_drops,1);});}
// Explicit inert diagnostic carrier/classifier for the exact Signer wrapper.
#[derive(Clone,Copy,Debug,PartialEq,Eq)] enum DriverStage{AdmitTransport}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] enum Class{FirstPermission,CallbackMarker}
mod wholepact_authority {
 #[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum AuthorityError{Permission,Uncertain}
 pub type Result<T>=std::result::Result<T,AuthorityError>;
 pub mod transport {pub mod history_diagnostics_v1 {
  #[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum InertStage{Response}
  #[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum InertIo{Closed}
  pub struct CheckedHistoryFailureV1;
  impl CheckedHistoryFailureV1 {
   pub fn stage(&self)->InertStage{InertStage::Response}
   pub fn io_kind(&self)->Option<InertIo>{Some(InertIo::Closed)}
   pub fn error(&self)->super::super::AuthorityError{super::super::AuthorityError::Permission}
   pub fn returned_error(&self)->super::super::AuthorityError{super::super::AuthorityError::Uncertain}
   pub fn into_error(self)->super::super::AuthorityError{panic!("must not substitute first observed category")}
  }
 }}
}
fn admit_transport_detail(stage:wholepact_authority::transport::history_diagnostics_v1::InertStage,
 kind:Option<wholepact_authority::transport::history_diagnostics_v1::InertIo>,
 error:wholepact_authority::AuthorityError,callback:Option<Class>)->(DriverStage,Class){
 use wholepact_authority::transport::history_diagnostics_v1::{InertStage,InertIo};
 assert_eq!(stage,InertStage::Response);assert_eq!(kind,Some(InertIo::Closed));
 assert_eq!(error,wholepact_authority::AuthorityError::Permission);assert_eq!(callback,Some(Class::CallbackMarker));
 STATE.with(|s|s.borrow_mut().detail_calls+=1);(DriverStage::AdmitTransport,Class::FirstPermission)
}
mod diagnostic {pub(super) fn driver(stage:super::DriverStage,class:super::Class){super::STATE.with(|s|s.borrow_mut().signer_marks.push((stage,class)));}}
"""
RUST_DIAGNOSTIC_ADAPTER=r"""
thread_local! {static SLOTS:std::cell::RefCell<Slots>=std::cell::RefCell::new(Slots::new());}
pub(super) fn reset(){SLOTS.with(|s|{*s.borrow_mut()=Slots::new();s.borrow().enter(101,2);});}
pub fn latch_failure(stage:Stage,class:Class){super::trace("latch_attempt");SLOTS.with(|s|s.borrow().failure(101,stage,class));}
pub(super) fn selected()->Option<(&'static str,&'static str)>{SLOTS.with(|s|{
 let s=s.borrow();let value=s.failure.load(Ordering::Relaxed).checked_sub(1)?;
 Some((*Stage::NAMES.get((value&255)as usize)?,*Class::NAMES.get((value>>8)as usize)?))})}
"""
RUST_TESTS=r"""
#[test] fn pump_error_preserves_identity_and_pre_drop_order(){setup();let(error,address,token)=failure();let mut relay=HostFinancialWorkflowRelayV1::new(Err(error));
 let returned=relay.pump().unwrap_err();assert_identity(&returned,address,&token);assert_order();assert!(relay.host.is_none());
 assert_eq!(financial_ci_host_diagnostics::selected(),Some(("RelayPump","IoPermissionDenied")));STATE.with(|s|assert_eq!(s.borrow().pump_calls,1));
 drop(relay);STATE.with(|s|assert_eq!(s.borrow().trace.last(),Some(&"poison_again")));}
fn pump_ok_case(value:bool){setup();let mut relay=HostFinancialWorkflowRelayV1::new(Ok(value));assert_eq!(relay.pump().unwrap(),value);
 STATE.with(|s|{let s=s.borrow();assert_eq!(s.pump_calls,1);assert!(s.trace.is_empty());assert_eq!(s.flush_calls,0);assert_eq!(s.child_drops,0);assert!(s.live.as_ref().unwrap().load(Ordering::Acquire));});
 assert!(financial_ci_host_diagnostics::selected().is_none());assert!(relay.host.is_some());drop(relay);STATE.with(|s|assert_eq!(s.borrow().append_calls,0));}
#[test] fn pump_ok_false_has_no_failure_side_effects(){pump_ok_case(false);}
#[test] fn pump_ok_true_has_no_failure_side_effects(){pump_ok_case(true);}
#[test] fn finish_incoming_error_preserves_identity_and_pre_drop_order(){setup();let(error,address,token)=failure();let relay=HostFinancialWorkflowRelayV1::new(Ok(false));
 let returned=relay.finish(Err(error)).unwrap_err();assert_identity(&returned,address,&token);assert_order();
 assert_eq!(financial_ci_host_diagnostics::selected(),Some(("RelayFinish","IoPermissionDenied")));
 STATE.with(|s|{let s=s.borrow();assert_eq!(s.pump_calls,0);assert_eq!(s.trace.last(),Some(&"poison_again"));});}
#[test] fn normal_custody_drop_has_no_failure_fact_or_append(){setup();let custody=HostVerifierCustody::new();
 STATE.with(|s|s.borrow_mut().live=Some(Arc::clone(&custody.live)));drop(custody);
 assert!(financial_ci_host_diagnostics::selected().is_none());STATE.with(|s|{let s=s.borrow();assert!(!s.poisoned);assert_eq!(s.append_calls,0);assert_eq!(s.child_drops,0);assert_eq!(s.flush_calls,1);assert_eq!(s.trace,["custody_live_false_observed"]);});}
#[test] fn existing_failure_survives_relay_pump_and_finish(){for finish in [false,true]{setup();
 financial_ci_host_diagnostics::latch_failure(financial_ci_host_diagnostics::Stage::CommandsDecode,financial_ci_host_diagnostics::Class::Invalid);
 STATE.with(|s|s.borrow_mut().trace.clear());let(error,address,token)=failure();
 let returned=if finish {HostFinancialWorkflowRelayV1::new(Ok(false)).finish(Err(error)).unwrap_err()}else{
 let mut relay=HostFinancialWorkflowRelayV1::new(Err(error));let result=relay.pump().unwrap_err();drop(relay);result};
 assert_identity(&returned,address,&token);assert_order();assert_eq!(financial_ci_host_diagnostics::selected(),Some(("CommandsDecode","Invalid")));}}
#[test] fn signer_wrapper_keeps_returned_error_not_first_category(){setup();let result=admit_transport_diagnosed_result::<()>(Err(wholepact_authority::transport::history_diagnostics_v1::CheckedHistoryFailureV1),Some(Class::CallbackMarker));
 assert_eq!(result,Err(wholepact_authority::AuthorityError::Uncertain));STATE.with(|s|{let s=s.borrow();assert_eq!(s.detail_calls,1);assert_eq!(s.signer_marks,[(DriverStage::AdmitTransport,Class::FirstPermission)]);});}
#[test] fn signer_wrapper_ok_does_not_classify_or_mark(){setup();assert_eq!(admit_transport_diagnosed_result(Ok(47u8),Some(Class::CallbackMarker)),Ok(47));
 STATE.with(|s|{let s=s.borrow();assert_eq!(s.detail_calls,0);assert!(s.signer_marks.is_empty());});}
"""

def build_legacy_harness():
    e=extracted_items()
    diag='\n'.join(e[k] for k in ('codes_macro','stage_codes','class_codes','slots_struct','classify_io'))
    diag+='\nimpl Slots {\n'+'\n'.join(e[k] for k in ('slots_new','slots_enter','slots_active','slots_failure'))+'\n}\n'
    ownership='\n'.join(e[k] for k in ('owner_struct','owner_drop','custody_struct','custody_impl','custody_drop'))
    methods='impl HostFinancialWorkflowRelayV1 {\n'+e['relay_pump']+'\n'+e['relay_finish']+'\n}\n'+e['relay_drop']
    rust='#![allow(dead_code)]\nmod harness {\n'+RUST_SUPPORT+'\npub(crate) mod financial_ci_host_diagnostics {\nuse std::sync::atomic::{AtomicI32,AtomicU32,AtomicU8,Ordering};\n'+diag+RUST_DIAGNOSTIC_ADAPTER+'\n}\n'+ownership+'\n'+methods+'\n'+e['signer_wrapper']+'\n'+RUST_TESTS+'\n}\nuse harness::{financial_ci_host_diagnostics,financial_observer};\n'
    extra,items=build_retirement_harness()
    rust+=extra
    e.update({'p77_'+k:v for k,v in items.items()})
    return rust,e

def checked(command,timeout):
    result=subprocess.run(command,capture_output=True,text=True,timeout=timeout)
    if result.returncode:
        print(result.stdout,end='');print(result.stderr,end='')
        raise RuntimeError('cause trace command failed: '+command[0])
    return result.stdout

def native_tests():
    rustc=shutil.which('rustc')
    if rustc is None:raise RuntimeError('pinned rustc unavailable: Rust NOT RUN; default invocation cannot skip')
    version=checked([rustc,'--version'],15).strip()
    if version!=PINNED_RUSTC:raise RuntimeError('wrong rustc identity: '+version)
    generated,extracted=build_harness()
    with tempfile.TemporaryDirectory(prefix='p75-cause-trace-') as directory:
        root=Path(directory);src=root/'cause_trace.rs';binary=root/'cause_trace'
        src.write_text(generated)
        checked([rustc,'--edition=2021','--test','--cfg','wholepact_financial_rendered_host_semantic_ci','--cfg','feature="synthetic-qualification"','-C','opt-level=0',str(src),'-o',str(binary)],120)
        listing=checked([str(binary),'--list','--format','terse'],15)
        actual=sorted(line.removesuffix(': test') for line in listing.splitlines() if line.endswith(': test'))
        if actual!=sorted(['harness::'+name for name in TEST_NAMES]+['retirement_harness::'+name for name in RETIREMENT_TEST_NAMES]+['retirement_harness::terminal_phase_harness::'+name for name in TERMINAL_PHASE_TEST_NAMES]+['resume_tail_harness::'+name for name in RESUME_TAIL_TEST_NAMES]):raise AssertionError(('unexpected exact Rust test inventory',actual))
        output=checked([str(binary),'--test-threads=1'],60);print(output,end='')
        if f'test result: ok. {len(TEST_NAMES)+len(RETIREMENT_TEST_NAMES)+len(TERMINAL_PHASE_TEST_NAMES)+len(RESUME_TAIL_TEST_NAMES)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;' not in output:
            raise AssertionError('Rust test result missing/count mismatch')
    return dict(rust_harness_executed=True,rust_tests_passed=len(TEST_NAMES)+len(RETIREMENT_TEST_NAMES)+len(TERMINAL_PHASE_TEST_NAMES)+len(RESUME_TAIL_TEST_NAMES),legacy_cause_tests_passed=len(TEST_NAMES),retirement_tests_passed=len(RETIREMENT_TEST_NAMES),terminal_phase_tests_passed=len(TERMINAL_PHASE_TEST_NAMES),resume_tail_tests_passed=len(RESUME_TAIL_TEST_NAMES),rust_ignored=0,compiler=version)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-only',action='store_true',help='Static source checks only; Rust explicitly NOT RUN.')
    args=parser.parse_args()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(SourceContracts)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():raise SystemExit(1)
    generated,extracted=build_harness()
    evidence=dict(source_contract_tests_passed=result.testsRun,baseline=BASELINE,
        execution_kind='actual-source Host boundary/Drop/Slots, Signer result wrapper retirement ordering, terminal report arms and UI resume tail; inert ownership/I/O/custody/classifier/DTO adapters',
        native_actor_execution=False,native_authority_finals_created=False,actual_transport_executed=False,
        actual_reporter_or_writer_executed=False,full_native_qualification=False,
        generated_source_sha256=sha(generated),extracted_item_sha256={k:sha(v) for k,v in extracted.items()},
        expected_rust_tests=list(TEST_NAMES),retirement_expected_rust_tests=list(RETIREMENT_TEST_NAMES),terminal_phase_expected_rust_tests=list(TERMINAL_PHASE_TEST_NAMES),resume_tail_expected_rust_tests=list(RESUME_TAIL_TEST_NAMES),terminal_phase_dependencies='inert DTO validation/phase storage; actual arms, matching predicates and progress/restriction control; no production authentication',ui_resume_dependencies='inert typed completion/native resume and Serving adapters; actual tail and currentness predicate; real native phase and raw-hook order source-bound only',retirement_dependencies='inert custody/I/O/validation carriers; no actual Origin authority or native Final',producer_scheduling_evidence='source-bound only; no actual worker or Host pump execution',source_tree_written=False)
    if args.source_only:evidence.update(rust_harness_executed=False,rust_test_status='NOT RUN (explicit --source-only)')
    else:evidence.update(native_tests())
    print('P75_CAUSE_BOUNDARY_TRACE '+json.dumps(evidence,sort_keys=True))

P77_RUST_SUPPORT=r'''
// Inert std-only shape adapters. These are NOT production Core/Origin authority,
// permits, sockets, workers, authenticated DTOs, or real native Finals.
use std::{cell::{Cell,RefCell},collections::VecDeque,io,sync::{Arc,OnceLock,atomic::{AtomicBool,AtomicU64,Ordering}},time::{Duration,Instant}};
type Result<T>=io::Result<T>;
fn rejected(s:&str)->io::Error{io::Error::new(io::ErrorKind::PermissionDenied,s.to_owned())}
thread_local!{static NONCES:Cell<usize>=const{Cell::new(0)};static TRACE:RefCell<Vec<&'static str>>=const{RefCell::new(Vec::new())};}
fn mark(s:&'static str){TRACE.with(|x|x.borrow_mut().push(s));}
fn reset(){NONCES.with(|n|n.set(0));TRACE.with(|x|x.borrow_mut().clear());}
fn nonce_count()->usize{NONCES.with(Cell::get)}
// Counted deterministic labels, not a cryptographic-freshness claim.
mod state{pub(super) fn nonce()->super::Result<String>{let n=super::NONCES.with(|n|{n.set(n.get()+1);n.get()});Ok(format!("inert-nonce-{n}"))}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] enum Target{Signer1,Signer2}
impl Target{fn index(self)->usize{match self{Self::Signer1=>0,Self::Signer2=>1}}}
type Role=Target;fn index(role:Role)->usize{role.index()}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] pub(crate) enum RetirementPurpose{InitialHistory,FinancialContinuation,FinancialSigning}
pub(crate) mod host_interstage{pub(crate) use super::RetirementPurpose;}
const PROFILE:&str="inert-profile";
#[derive(Clone,Debug,PartialEq,Eq)] struct RetirementRequest{profile:String,coordinator:String,session:String,target:Target,purpose:RetirementPurpose,binding_digest:String,witness_instance:String,challenge:String,cleanup_ceiling_ms:u64,signing:Option<()>}
impl RetirementRequest{fn validate(&self,c:Clocks)->Result<Instant>{if self.profile!=PROFILE{return Err(rejected("inert request profile"));}Ok(c.epoch+Duration::from_millis(self.cleanup_ceiling_ms))}}
#[derive(Clone,Copy)] struct Clocks{epoch:Instant}
impl Clocks{
 fn cleanup_offset(self,cutoff:Instant)->Result<u64>{Ok(cutoff.checked_duration_since(self.epoch).ok_or_else(||rejected("inert cutoff"))?.as_millis()as u64)}
 fn restrict_received(self,_:&str,ms:u64,original:Instant,_:Instant)->Result<Instant>{let d=(self.epoch+Duration::from_millis(ms)).min(original);channel::require_time(d)?;Ok(d)}
}
#[derive(Default)] struct Phases{word:AtomicU64}
impl Phases{fn snapshot(&self)->u64{self.word.load(Ordering::Acquire)}fn phase(&self,i:usize)->u8{((self.snapshot()>>(i*8))&255)as u8}
 fn revoked(&self)->bool{self.snapshot()&(1<<30)!=0}fn quiescent(&self)->bool{true}
 fn set(&self,i:usize,p:u8){let w=self.snapshot();self.word.store((w&!(255<<(i*8)))|((p as u64)<<(i*8)),Ordering::Release);}
}
struct Core{phase:Phases,current:AtomicBool,action:AtomicBool,outbound:bool,witness_outbound:bool}
impl Core{fn check(&self)->Result<()>{if !self.current.load(Ordering::Acquire)||self.phase.revoked(){Err(rejected("inert original currentness"))}else{Ok(())}}
 fn check_action_restrictions(&self)->Result<()>{self.check()?;if !self.action.load(Ordering::Acquire){Err(rejected("inert action restriction"))}else{Ok(())}}
 fn check_retirement_other_roots(&self,_:usize)->Result<()>{self.check()}}
fn pending(c:&Core)->bool{c.outbound}
struct EntryReviewed{original_source:Instant,current:bool}
impl EntryReviewed{fn check_custody(&self)->Result<()>{if self.current{Ok(())}else{Err(rejected("inert custody"))}}fn retirement_clock_bounds(&self)->Result<()>{self.check_custody()?;channel::require_time(self.original_source)}}
#[derive(Clone)] struct Presentation{presentation_digest:String,role:Target}
#[derive(Clone)] struct Committed{head_sequence:u64,head_digest:String}
struct Admission{p:Presentation,c:Committed,retained:bool}
impl Admission{fn retained_result(&self)->Result<(&Presentation,&Committed)>{if !self.retained{return Err(rejected("inert admit not retained"));}Ok((&self.p,&self.c))}}
#[derive(Clone)] enum FinancialWitnessOutcomeV1{Committed{presentation_digest:String,effect_commitment:String,head_sequence:u64,head_digest:String},Failed}
struct Witness{instance:String,cutoff:Instant,outcome:FinancialWitnessOutcomeV1,binding:bool,disposed:bool,idle:bool,role:Target}
impl Witness{
 fn retirement_record(&self)->Result<(&str,Instant,&FinancialWitnessOutcomeV1)>{if !self.disposed{return Err(rejected("inert W not disposed"));}Ok((&self.instance,self.cutoff,&self.outcome))}
 fn retirement_matches_admit(&self,p:&Presentation)->Result<()>{if self.binding&&p.role==self.role{Ok(())}else{Err(rejected("inert W binding"))}}
 fn retirement_idle(&self)->bool{self.idle}
}
struct History{idle:bool}impl History{fn retirement_idle(&self,_:bool)->bool{self.idle}}
struct Retired;impl Retired{fn check(&self)->Result<()>{Ok(())}}
struct Signing{idle:bool}impl Signing{fn retirement_idle(&self)->bool{self.idle}fn normal_retirement_idle(&self)->bool{self.idle}fn retired_record(&self)->Option<&Retired>{None}}
#[derive(Clone)] struct Display{role:Target,valid:bool,binding:bool,read_ceiling_ms:u64}
impl Display{fn validate(&self)->Result<()>{if self.valid{Ok(())}else{Err(rejected("inert display shape"))}}}
struct WriterRead{service:OnceLock<()>}
impl WriterRead{fn from_bounds(_:Arc<EntryReviewed>,_:Display,_:Instant,_:())->Result<Arc<Self>>{Ok(Arc::new(Self{service:OnceLock::new()}))}}
struct SignerFinancialWriterReadTicketV1{binding:Arc<WriterRead>,consumed:bool}
enum CoordinatorFinancialEventV1{Restricted(Target),WriterReadDisplay(SignerFinancialWriterReadTicketV1)}
fn read_links_admit(d:&Display,p:&Presentation,_:&Committed)->bool{d.binding&&d.role==p.role}
fn expected_signing_original(_:&Presentation,_:&Committed)->Result<()>{Ok(())}
fn received_progress(p:&Phases,i:usize,from:u8,to:u8)->Result<bool>{if p.revoked(){return Ok(false)}if p.phase(i)!=from{return Err(rejected("inert phase mismatch"));}p.set(i,to);Ok(true)}
#[derive(Default)]struct CWritAcquire{terminal:bool,committed:Option<()>,read_wire:Option<Display>,read:Option<Arc<WriterRead>>,review:Option<()>,ready:Option<()>}
#[derive(Default)]struct HWritAcquire{read:Option<()>,read_forwarded:bool,service:Option<()>,wire:Option<()>,ready:Option<()>,terminal:bool,committed:Option<()>}
struct CSlot{wire_phase:u8,entry:Option<Arc<EntryReviewed>>,admission:Admission,writer_acquire:CWritAcquire,failed:bool}
struct SignState{selector_seen:bool}
struct Wallet{sign:SignState}
struct Activate{wallet:Wallet}
struct SignSlot{phase:u8,wire_phase:u8,activate:Activate}
struct HSlot{phase:u8,admission:Admission,writer_acquire:HWritAcquire}
struct HostGuard{slots:[Option<HSlot>;2]}
#[derive(Clone)] enum Packet{WriterReadDisplay{data:Display},FinancialResultSelector{role:Target},RetireQuiescent{request:RetirementRequest},RetireResumed{request:RetirementRequest},Other}
impl Packet{fn target(&self)->Result<Option<Target>>{Ok(match self{Self::WriterReadDisplay{data}=>Some(data.role),Self::FinancialResultSelector{role}=>Some(*role),_=>None})}}
struct Queue{packets:RefCell<VecDeque<Packet>>}
impl Queue{fn workflow_receive(&self)->Result<Option<Packet>>{mark("receive");Ok(self.packets.borrow_mut().pop_front())}}
struct Tree{queue:Queue}impl Tree{fn continue_host(&self)->Result<&Queue>{Ok(&self.queue)}}
// Nominal return shape only: cannot escape this test crate or grant authority.
struct CoordinatorWitnessRetirementTicketV1{core:Arc<Core>,entries:Vec<Arc<EntryReviewed>>,request:RetirementRequest,cutoff:Instant,phases:u64,consumed:bool}
struct CoordinatorFinancialEndpointV1{core:Arc<Core>,slots:[Option<CSlot>;2],witnesses:[Witness;2],histories:[History;2],signing_services:[Signing;2],retirement_resume:Option<Instant>,cancel_sent:bool,coordinator:String,session:String,clocks:Clocks,tree:Option<Tree>}
fn admission(role:Target)->Admission{Admission{p:Presentation{presentation_digest:"inert-admit".into(),role},c:Committed{head_sequence:7,head_digest:"inert-head".into()},retained:true}}
fn slot(role:Target,phase:u8,deadline:Instant)->CSlot{CSlot{wire_phase:phase,entry:Some(Arc::new(EntryReviewed{original_source:deadline,current:true})),admission:admission(role),writer_acquire:CWritAcquire::default(),failed:false}}
impl CoordinatorFinancialEndpointV1{
 fn fixture(role:Target)->Self{reset();let epoch=Instant::now();let cutoff=epoch+Duration::from_secs(60);let core=Arc::new(Core{phase:Phases::default(),current:AtomicBool::new(true),action:AtomicBool::new(true),outbound:false,witness_outbound:false});core.phase.set(role.index(),admit::AWAITING_NEXT_READ);
 let mut slots=[None,None];slots[role.index()]=Some(slot(role,admit::AWAITING_NEXT_READ,cutoff));
 Self{core,slots,witnesses:std::array::from_fn(|i|Witness{instance:format!("inert-W-{i}"),cutoff,outcome:FinancialWitnessOutcomeV1::Committed{presentation_digest:String::new(),effect_commitment:String::new(),head_sequence:7,head_digest:"inert-head".into()},binding:true,disposed:true,idle:true,role:if i==0{Target::Signer1}else{Target::Signer2}}),histories:[History{idle:true},History{idle:true}],signing_services:[Signing{idle:true},Signing{idle:true}],retirement_resume:None,cancel_sent:false,coordinator:"inert-C".into(),session:"inert-session".into(),clocks:Clocks{epoch},tree:Some(Tree{queue:Queue{packets:RefCell::new(VecDeque::new())}})}}
 fn enqueue(&self,p:Packet){self.tree.as_ref().unwrap().queue.packets.borrow_mut().push_back(p);}
 fn display(&self,role:Target)->Packet{Packet::WriterReadDisplay{data:Display{role,valid:true,binding:true,read_ceiling_ms:60_000}}}
 fn receive_one(&mut self)->Result<CoordinatorFinancialEventV1>{let p=self.tree.as_ref().unwrap().queue.workflow_receive()?.ok_or_else(||rejected("inert empty queue"))?;self.receive_writer_acquire_event(p)}
 fn make_pending(&mut self,role:Target){let packet=self.display(role);self.receive_writer_acquire_event(packet).unwrap();}
}
fn host_fixture(role:Target)->HostGuard{let mut slots=[None,None];slots[role.index()]=Some(HSlot{phase:writer_acquire::WRITER_READ_REVIEW,admission:admission(role),writer_acquire:HWritAcquire{read:Some(()),read_forwarded:true,..Default::default()}});HostGuard{slots}}
fn other(role:Target)->Target{if role==Target::Signer1{Target::Signer2}else{Target::Signer1}}
fn request(role:Target)->RetirementRequest{RetirementRequest{profile:PROFILE.into(),coordinator:"inert-C".into(),session:"inert-session".into(),target:role,purpose:RetirementPurpose::FinancialContinuation,binding_digest:"inert-admit".into(),witness_instance:"inert-W".into(),challenge:"inert-challenge".into(),cleanup_ceiling_ms:60_000,signing:None}}
fn retire_signing_predecessor_exclusively(endpoint:&mut CoordinatorFinancialEndpointV1,_:&(),_:&(),_:&AtomicBool,ticket:CoordinatorWitnessRetirementTicketV1)->Result<()>{mark("exclusive");endpoint.retirement_wait_host(&ticket.request,false,ticket.cutoff,Some(ticket.request.target.index()))}
'''
P77_RUST_TESTS=r'''
#[test]fn old_prepare_rejects_late_display_at_both_strict_waits(){for role in [Target::Signer1,Target::Signer2]{for resumed in [false,true]{let mut e=CoordinatorFinancialEndpointV1::fixture(role);let t=e.prepare_witness_retirement(role).unwrap();assert_eq!(nonce_count(),1);e.enqueue(e.display(role));assert_eq!(e.retirement_wait_host(&t.request,resumed,t.cutoff,Some(role.index())).unwrap_err().to_string(),"unexpected traffic during exclusive retirement");}}}
#[test]fn deferred_prepare_drains_actual_display_before_quiescence_both_roles(){for role in [Target::Signer1,Target::Signer2]{let mut e=CoordinatorFinancialEndpointV1::fixture(role);let original=e.witnesses[role.index()].cutoff;assert!(e.try_prepare_witness_retirement(role).unwrap().is_none());assert_eq!(nonce_count(),0);e.enqueue(e.display(role));assert!(matches!(e.receive_one().unwrap(),CoordinatorFinancialEventV1::WriterReadDisplay(_)));let t=e.try_prepare_witness_retirement(role).unwrap().unwrap();assert!(t.cutoff<=original);assert_eq!(nonce_count(),1);for resumed in [false,true]{e.enqueue(if resumed{Packet::RetireResumed{request:t.request.clone()}}else{Packet::RetireQuiescent{request:t.request.clone()}});e.retirement_wait_host(&t.request,resumed,t.cutoff,Some(role.index())).unwrap();}}}
#[test]fn all_three_automatic_frontiers_defer_either_owner_without_nonce(){for role in [Target::Signer1,Target::Signer2]{for phase in [SOURCE_RETAINED,AWAITING_ADMISSION,admit::AWAITING_NEXT_READ]{let mut e=CoordinatorFinancialEndpointV1::fixture(role);e.make_pending(role);let peer=other(role);let cutoff=e.witnesses[role.index()].cutoff;e.slots[peer.index()]=Some(slot(peer,phase,cutoff));e.core.phase.set(peer.index(),phase);assert!(e.try_prepare_witness_retirement(role).unwrap().is_none());assert_eq!(nonce_count(),0);assert_eq!(e.witnesses[role.index()].cutoff,cutoff);}}}
#[test]fn pending_preserves_restriction_cancel_currentness_and_idle_denials(){for role in [Target::Signer1,Target::Signer2]{for kind in 0..6{let mut e=CoordinatorFinancialEndpointV1::fixture(role);match kind{0=>e.core.action.store(false,Ordering::Release),1=>e.core.current.store(false,Ordering::Release),2=>e.cancel_sent=true,3=>{e.core.phase.word.fetch_or(1<<30,Ordering::AcqRel);},4=>{e.retirement_resume=Some(e.witnesses[role.index()].cutoff);},_=>e.core.phase.set(other(role).index(),writer_acquire::WRITER_READ_ADMITTED)};assert!(e.try_prepare_witness_retirement(role).is_err());assert_eq!(nonce_count(),0);}}}
#[test]fn pending_preserves_head_binding_disposal_and_missing_owner_denials(){for role in [Target::Signer1,Target::Signer2]{for kind in 0..5{let mut e=CoordinatorFinancialEndpointV1::fixture(role);match kind{0=>e.witnesses[role.index()].outcome=FinancialWitnessOutcomeV1::Failed,1=>e.witnesses[role.index()].binding=false,2=>e.witnesses[role.index()].disposed=false,3=>e.slots[role.index()]=None,_=>e.slots[role.index()].as_mut().unwrap().admission.c.head_sequence=8};assert!(e.try_prepare_witness_retirement(role).is_err());assert_eq!(nonce_count(),0);}}}
#[test]fn pending_uses_original_cutoff_and_expiry_never_mints_nonce(){for role in [Target::Signer1,Target::Signer2]{let mut e=CoordinatorFinancialEndpointV1::fixture(role);let original=e.witnesses[role.index()].cutoff;for _ in 0..3{assert!(e.try_prepare_witness_retirement(role).unwrap().is_none());assert_eq!(e.witnesses[role.index()].cutoff,original);}e.witnesses[role.index()].cutoff=Instant::now()-Duration::from_secs(1);assert!(e.try_prepare_witness_retirement(role).is_err());assert_eq!(nonce_count(),0);}}
#[test]fn some_requires_existing_unadmitted_writer_read_predicate(){for role in [Target::Signer1,Target::Signer2]{for kind in 0..5{let mut e=CoordinatorFinancialEndpointV1::fixture(role);e.make_pending(role);let s=e.slots[role.index()].as_mut().unwrap();match kind{0=>s.writer_acquire.read_wire=None,1=>{s.writer_acquire.read.as_ref().unwrap().service.set(()).unwrap();},2=>s.writer_acquire.review=Some(()),3=>s.writer_acquire.terminal=true,_=>s.writer_acquire.committed=Some(())};assert!(e.try_prepare_witness_retirement(role).is_err());assert_eq!(nonce_count(),0);}}}
#[test]fn ordinary_display_rejects_wrong_owner_binding_duplicate_and_terminal(){for role in [Target::Signer1,Target::Signer2]{let mut e=CoordinatorFinancialEndpointV1::fixture(role);assert!(e.receive_writer_acquire_event(e.display(other(role))).is_err());let mut bad=match e.display(role){Packet::WriterReadDisplay{data}=>data,_=>unreachable!()};bad.binding=false;assert!(e.receive_writer_acquire_event(Packet::WriterReadDisplay{data:bad}).is_err());e.make_pending(role);assert!(e.receive_writer_acquire_event(e.display(role)).is_err());let mut e=CoordinatorFinancialEndpointV1::fixture(role);e.slots[role.index()].as_mut().unwrap().failed=true;assert!(e.receive_writer_acquire_event(e.display(role)).is_err());}}
#[test]fn strict_wait_rejects_mismatch_ordinary_traffic_restriction_and_expiry(){for resumed in [false,true]{let e=CoordinatorFinancialEndpointV1::fixture(Target::Signer1);let req=request(Target::Signer1);let cutoff=e.witnesses[0].cutoff;let mut wrong=req.clone();wrong.target=Target::Signer2;e.enqueue(if resumed{Packet::RetireResumed{request:wrong}}else{Packet::RetireQuiescent{request:wrong}});assert!(e.retirement_wait_host(&req,resumed,cutoff,None).is_err());e.enqueue(if resumed{Packet::RetireQuiescent{request:req.clone()}}else{Packet::RetireResumed{request:req.clone()}});assert!(e.retirement_wait_host(&req,resumed,cutoff,None).is_err());e.core.current.store(false,Ordering::Release);assert!(e.retirement_wait_host(&req,resumed,cutoff,None).is_err());e.core.current.store(true,Ordering::Release);assert!(e.retirement_wait_host(&req,resumed,Instant::now()-Duration::from_secs(1),None).is_err());}}
#[test]fn host_guard_requires_pending_target_and_no_any_owner_frontier(){for role in [Target::Signer1,Target::Signer2]{let req=request(role);let h=host_fixture(role);h.continuation_guard(&req).unwrap();for phase in [SOURCE_RETAINED,AWAITING_ADMISSION,admit::AWAITING_NEXT_READ]{let mut h=host_fixture(role);let peer=other(role);h.slots[peer.index()]=Some(HSlot{phase,admission:admission(peer),writer_acquire:HWritAcquire::default()});assert!(h.continuation_guard(&req).is_err());}let mut h=host_fixture(role);h.slots[role.index()].as_mut().unwrap().writer_acquire.read_forwarded=false;assert!(h.continuation_guard(&req).is_err());let mut wrong=req.clone();wrong.binding_digest="wrong".into();assert!(host_fixture(role).continuation_guard(&wrong).is_err());}}
#[test]fn actual_driver_role_continue_keeps_next_receive_and_host_pump_runnable(){for role in [Target::Signer1,Target::Signer2]{let mut e=CoordinatorFinancialEndpointV1::fixture(role);let revoked=AtomicBool::new(false);let mut retired=[false;2];let mut closed=[false;2];let mut admitted=[false;2];admitted[role.index()]=true;let disposed=admitted;e.enqueue(e.display(role));driver_roles(&mut e,false,&revoked,admitted,disposed,&mut retired,&mut closed).unwrap();assert!(!retired[role.index()]);mark("host_pump");e.receive_one().unwrap();let mut expected=request(role);expected.witness_instance=e.witnesses[role.index()].instance.clone();expected.challenge="inert-nonce-1".into();expected.cleanup_ceiling_ms=e.clocks.cleanup_offset(e.witnesses[role.index()].cutoff).unwrap();e.enqueue(Packet::RetireQuiescent{request:expected});driver_roles(&mut e,false,&revoked,admitted,disposed,&mut retired,&mut closed).unwrap();assert!(retired[role.index()]&&closed[role.index()]);assert_eq!(nonce_count(),1);TRACE.with(|x|{let x=x.borrow();assert_eq!(x.iter().filter(|s|**s=="exclusive").count(),1);assert!(x.iter().position(|s|*s=="host_pump").unwrap()<x.iter().position(|s|*s=="exclusive").unwrap());});for(cancel,r,ad,d,done)in[(true,false,true,true,false),(false,true,true,true,false),(false,false,false,true,false),(false,false,true,false,false),(false,false,true,true,true)]{assert!(!may_retire_signing_predecessor(cancel,r,ad,d,done));}}}
#[test]fn signing_guards_require_received_selector_and_strict_wait_rejects_late_selector(){for role in [Target::Signer1,Target::Signer2]{for host in [false,true]{let mut slot=SignSlot{phase:67,wire_phase:67,activate:Activate{wallet:Wallet{sign:SignState{selector_seen:false}}}};assert!(c_sign_guard(&slot).is_err()&&h_sign_guard(&slot).is_err());assert!(accept_selector_after_inert_validation(&mut slot,false,host).is_err());assert!(!slot.activate.wallet.sign.selector_seen);accept_selector_after_inert_validation(&mut slot,true,host).unwrap();c_sign_guard(&slot).unwrap();h_sign_guard(&slot).unwrap();assert!(accept_selector_after_inert_validation(&mut slot,true,host).is_err());slot.phase=66;slot.wire_phase=66;assert!(c_sign_guard(&slot).is_err()&&h_sign_guard(&slot).is_err());}for resumed in [false,true]{let e=CoordinatorFinancialEndpointV1::fixture(role);e.enqueue(Packet::FinancialResultSelector{role});assert_eq!(e.retirement_wait_host(&request(role),resumed,e.witnesses[role.index()].cutoff,Some(role.index())).unwrap_err().to_string(),"unexpected traffic during exclusive retirement");}}}

'''

def build_retirement_harness():
    e=retirement_items()
    modules='pub(crate) mod channel {use super::{Instant,Result,rejected};\n'+e['require_time']+'\n}\n'
    modules+='mod admit {\n'+e['admit_constant']+'\n}\nmod writer_acquire {\n'+e['writer_constants']+'\n}\nuse writer_acquire::WRITER_READ_REVIEW;\n'
    modules+='mod witness {\n'+e['witness_constant']+'\npub(super) fn witness_pending(c:&super::Core)->bool{c.witness_outbound}\n}\nmod history {\n'+e['history_constants']+'\n}\n'
    modules+=e['source_constants']+'\n'+e['continue_constant']+'\n'
    methods='impl CoordinatorFinancialEndpointV1 {\n'+'\n'.join(e[k] for k in ('try_prepare','old_prepare','idle','bounds','wait'))+'\n'
    methods+=e['receive_head']+e['receive_arm']+'\n_=>Err(rejected("inert unselected ordinary packet")),\n}\n}\n}\n'
    guards='impl CWritAcquire {\n'+e['c_pending']+'\n}\nimpl HWritAcquire {\n'+e['h_pending']+'\n}\n'
    guards+='impl HostGuard {fn continuation_guard(&self,request:&RetirementRequest)->Result<()> {let slot=self.slots[request.target.index()].as_ref().ok_or_else(||rejected("inert missing Host owner"))?;match request.purpose{\n'+e['host_guard']+'\n_=>return Err(rejected("inert unselected purpose")),\n}Ok(())}}\n'
    guards+='fn c_sign_guard(slot:&SignSlot)->Result<()> {\n'+e['c_sign_guard']+'\nOk(())}\nfn h_sign_guard(slot:&SignSlot)->Result<()> {\n'+e['h_sign_guard']+'\nOk(())}\n'
    guards+='fn accept_selector_after_inert_validation(slot:&mut SignSlot,valid:bool,host:bool)->Result<()> {if !valid{return Err(rejected(\"inert selector dependency\"));}if host{\n'+e['h_selector_replay']+'\n}else{\n'+e['c_selector_replay']+'\n}slot.activate.wallet.sign.selector_seen=true;Ok(())}\n'
    driver=e['driver_predicate']+'\nfn driver_roles(mut endpoint:&mut CoordinatorFinancialEndpointV1,cancel_sent:bool,revoked:&AtomicBool,admission_retained:[bool;2],witness_disposed:[bool;2],predecessor_retired:&mut[bool;2],witness_close_sent:&mut[bool;2])->Result<()> {let input=();let output=();\n'+e['driver_role_loop']+'\nOk(())}\n'
    rust='\nmod retirement_harness {\n'+P77_RUST_SUPPORT+modules+e['idle_mask']+'\n'+methods+guards+driver+P77_RUST_TESTS+'\n}\nuse retirement_harness::{channel,host_interstage};\n'
    return rust,e


P80_LEGACY_GENERATED_SHA='2099a9d65c2706eefc68c4570ffd34522869aff851d456fd73f47a93fc884956'
P80_UI='crates/wholepact-financial-coordinator/src/financial_source_ui.rs'
P80_RESTORATION={'crates/wholepact-financial-coordinator-origin/src/signer_sign_origin.rs': {'baseline_sha256': 'a332e687211fab22484a169dd247814aace1e90da11e128588b3918893a68217', 'exact_inverse': [{'remove': '                slot.wire_phase = 67;\n', 'restore': ''}, {'remove': '                slot.phase = 67;\n', 'restore': ''}]}, 'crates/wholepact-financial-coordinator-origin/src/signer_return_origin.rs': {'baseline_sha256': '9f10b25fc99d47125d8557b6b245c81c5a06c85ef989b08497c14cd80353d5b6', 'exact_inverse': [{'remove': '                slot.wire_phase = 73;\n', 'restore': ''}, {'remove': '                slot.phase = 73;\n', 'restore': ''}]}, 'crates/wholepact-financial-coordinator/src/financial_source_ui.rs': {'baseline_sha256': '6ed6cea68e69fd6c2377ca8d86fa1182ca1f741835dc4c881be0fd0e92d1e82d', 'exact_inverse': [{'remove': '                        // Only this exact nominal custody permits parking. The\n                        // obsolete Serving observer was removed at typed resume.\n', 'restore': '                        // Only this exact nominal completion replaces the now-dead\n                        // Serving observer. Ordinary absence never permits parking.\n'}, {'remove': '                        self.transition(Phase::SignedRetired, ctx.cumulative_frame_nr());\n', 'restore': '                        self.writer_flow.serving.take();\n                        self.transition(Phase::SignedRetired, ctx.cumulative_frame_nr());\n'}, {'remove': '            // Actual Signing retirement ended this check-only Serving observer.\n            // Remove it before ordinary pre-poll currentness resumes; signed\n            // custody and parking still require the later SigningResumed event.\n            if self.phase == Phase::SigningRetiring {\n                self.writer_flow.serving.take();\n            }\n', 'restore': ''}]}}
def p80_restore(path,source):
    if path in P85_RESTORATION:source=p85_restore(path,source)
    if path==P80_UI:
        spec=importlib.util.spec_from_file_location('p81_held_selection_inverse',ROOT/'scripts/ci-financial-admit-read-source-audit.py')
        audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
        source=audit.restore_held_selection_ui(source)
    for change in P80_RESTORATION[path]['exact_inverse']:
        if source.count(change['remove'])!=1:raise AssertionError(('P80 exact inverse occurrence',path))
        source=source.replace(change['remove'],change['restore'],1)
    return source

TERMINAL_PHASE_TEST_NAMES=(
 'sign_committed_outer_phase_matches_both_original_consumers',
 'return_completed_outer_phase_reaches_normal_notice_after_sign',
 'invalid_or_replayed_reports_never_advance_outer_phase',
 'coordinator_progress_error_and_restriction_preserve_original_results',
)
RESUME_TAIL_TEST_NAMES=('typed_signing_resume_drops_only_obsolete_serving_before_pre_poll_check',)

def terminal_phase_items():
    sign=(ROOT/(P77_ORIGIN+'signer_sign_origin.rs')).read_text()
    ret=(ROOT/(P77_ORIGIN+'signer_return_origin.rs')).read_text()
    workflow=(ROOT/PATHS['relay']).read_text()
    state=(ROOT/(P77_ORIGIN+'signer_continue_state.rs')).read_text()
    normal=(ROOT/(P77_ORIGIN+'financial_normal_completion_origin.rs')).read_text()
    e={}
    for kind,source,anchor,variant,field,to in (
        ('c_sign',sign,'pub(in crate::financial_workflow_origin) fn receive_sign_event(', 'SignCommitted','wire_phase',67),
        ('h_sign',sign,'pub(in crate::financial_workflow_origin) fn up_sign(', 'SignCommitted','phase',67),
        ('c_return',ret,'pub(in crate::financial_workflow_origin) fn receive_return_event(', 'ReturnCompleted','wire_phase',73),
        ('h_return',ret,'pub(in crate::financial_workflow_origin) fn up_return(', 'ReturnCompleted','phase',73),
    ):
        method=item(source,anchor)
        arm=item(method,'Packet::'+variant+' { data, .. } =>',body_after_anchor=True)
        line='                slot.'+field+' = '+str(to)+';\n'
        if arm.count(line)!=1:raise AssertionError(('outer phase assignment',kind))
        e[kind]=arm;e[kind+'_old']=arm.replace(line,'',1)
    e['committed_matches']=item(sign,'fn committed_matches(')
    e['completed_matches']=item(ret,'fn completed_matches(')
    e['actual_completed']=item(ret,'pub(super) fn actual_completed(')
    e['received_progress']=item(workflow,'fn received_workflow_progress(')
    e['action_restrictions']=item(state,'pub(super) fn check_action_restrictions(')
    old=retirement_items()
    e['c_sign_guard']=old['c_sign_guard'];e['h_sign_guard']=old['h_sign_guard']
    e['normal_guard']=item(normal,'if slot.wire_phase!=73||')
    return e

def resume_tail_items():
    source=(ROOT/P80_UI).read_text()
    e={'tail':item(source,'fn history_retirement_tail(')}
    old=p80_restore(P80_UI,source)
    e['old_tail']=item(old,'fn history_retirement_tail(')
    anchor='self\n                .writer_flow\n                .serving\n                .as_ref()\n                .is_some_and(|t| t.check_current().is_err())'
    if source.count(anchor)!=1:raise AssertionError('Serving predicate moved')
    e['serving_predicate']=anchor
    return e

P80_RUST_SUPPORT=r'''
// Inert carrier/control adapters, NOT authenticated DTOs, Core/Origin custody,
// native Finals, permission grants, real workers, sockets, or production I/O.
use std::{cell::Cell,io,time::{Duration,Instant}};
type Result<T>=io::Result<T>;
fn rejected(s:&str)->io::Error{io::Error::new(io::ErrorKind::PermissionDenied,s.to_owned())}
macro_rules! boundary{($($t:tt)*)=>{{}}} macro_rules! actor_boundary{($($t:tt)*)=>{{}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] enum Target{Signer1,Signer2}
impl Target{fn index(self)->usize{match self{Self::Signer1=>0,Self::Signer2=>1}}}
#[derive(Clone,Debug,PartialEq,Eq)] struct Original{fixed_identity_digest:&'static str}
#[derive(Clone,Debug,PartialEq,Eq)] struct SignFacts{original:Original,authorization:&'static str,authorization_valid:bool}
impl SignFacts{fn expected_authorization_id(&self)->Result<&'static str>{if self.authorization_valid{Ok(self.authorization)}else{Err(rejected("inert authorization dependency"))}}}
#[derive(Clone,Debug,PartialEq,Eq)] struct SignerSignExactPresentationV1{presentation_digest:&'static str,facts:SignFacts}
#[derive(Clone,Debug,PartialEq,Eq)] struct SignerSignCommittedV1{sign_presentation_digest:&'static str,authorization_id:&'static str,fixed_identity_digest:&'static str,result_digest:&'static str,outbox_digest:&'static str,valid:bool}
impl SignerSignCommittedV1{fn validate(&self)->Result<()>{if self.valid{Ok(())}else{Err(rejected("inert DTO validation dependency"))}}}
#[derive(Clone,Debug,PartialEq,Eq)] struct ReturnReadFacts{signed:SignerSignCommittedV1}
#[derive(Clone,Debug,PartialEq,Eq)] struct ReturnRead{facts:ReturnReadFacts}
#[derive(Clone,Debug,PartialEq,Eq)] struct ReturnFacts{preview_digest:&'static str,read:ReturnRead}
#[derive(Clone,Debug,PartialEq,Eq)] struct SignerReturnExactPresentationV1{presentation_digest:&'static str,facts:ReturnFacts}
#[derive(Clone,Debug,PartialEq,Eq)] struct SignerReturnCompletedV1{return_presentation_digest:&'static str,preview_digest:&'static str,result_digest:&'static str,outbox_digest:&'static str,valid:bool}
impl SignerReturnCompletedV1{fn validate(&self)->Result<()>{if self.valid{Ok(())}else{Err(rejected("inert DTO validation dependency"))}}}
#[derive(Clone)] struct Slot<P,D>{wire:Option<P>,result:Option<D>,reported:bool,phase:u8}
#[derive(Clone)] struct ReturnSlots{exact:Slot<SignerReturnExactPresentationV1,SignerReturnCompletedV1>,terminal:bool}
#[derive(Clone)] struct SignSlots{exact:Slot<SignerSignExactPresentationV1,SignerSignCommittedV1>,returning:ReturnSlots,selector_seen:bool}
#[derive(Clone)] struct Wallet{sign:SignSlots}
#[derive(Clone)] struct Activate{wallet:Wallet}
#[derive(Clone)] struct CSlot{wire_phase:u8,activate:Activate}
#[derive(Clone)] struct HSlot{phase:u8,activate:Activate}
#[derive(Clone,Debug,PartialEq,Eq)] enum Packet{SignCommitted{role:Target,data:SignerSignCommittedV1},ReturnCompleted{role:Target,data:SignerReturnCompletedV1}}
#[derive(Clone,Debug,PartialEq,Eq)] enum CoordinatorFinancialEventV1{SignCommitted{role:Target,data:SignerSignCommittedV1},ReturnCompleted{role:Target,data:SignerReturnCompletedV1}}
// The actual received_workflow_progress helper executes below. Only its phase
// storage/currentness/error dependencies are inert deterministic adapters.
struct Phases{values:[Cell<u8>;2],restricted:Cell<bool>,step_error:Cell<bool>}
impl Phases{
 fn source_send_restricted(&self,i:usize,expected:u8)->Result<bool>{if self.values[i].get()!=expected{return Err(rejected("inert unexpected phase"));}Ok(self.restricted.get())}
 fn step(&self,i:usize,from:u8,to:u8)->Result<()>{if self.step_error.get(){return Err(rejected("inert original step error"));}if self.values[i].get()!=from{return Err(rejected("inert unexpected phase"));}self.values[i].set(to);Ok(())}
 fn revoked(&self)->bool{self.restricted.get()} fn quiescent(&self)->bool{false} fn normal_phase(&self)->u8{0} fn revoke(&self){self.restricted.set(true);}
}
struct Restriction;impl Restriction{fn check_current(&self)->Result<()>{Ok(())}}
struct Core{phase:Phases,session:Instant,signer_restriction:Option<Restriction>}
impl Core{fn check(&self)->Result<()>{Ok(())}}
struct CoordinatorFinancialEndpointV1{slots:[CSlot;2],core:Core}
struct HostFinancialWorkflowRelayV1{slots:[HSlot;2]}
struct Notice{returned:[SignerReturnCompletedV1;2]}
fn sign_data()->SignerSignCommittedV1{SignerSignCommittedV1{sign_presentation_digest:"sign",authorization_id:"authorization",fixed_identity_digest:"fixed",result_digest:"result",outbox_digest:"outbox",valid:true}}
fn return_data()->SignerReturnCompletedV1{SignerReturnCompletedV1{return_presentation_digest:"return",preview_digest:"preview",result_digest:"result",outbox_digest:"outbox",valid:true}}
fn activate()->Activate{Activate{wallet:Wallet{sign:SignSlots{
 exact:Slot{wire:Some(SignerSignExactPresentationV1{presentation_digest:"sign",facts:SignFacts{original:Original{fixed_identity_digest:"fixed"},authorization:"authorization",authorization_valid:true}}),result:None,reported:false,phase:66},
 returning:ReturnSlots{exact:Slot{wire:Some(SignerReturnExactPresentationV1{presentation_digest:"return",facts:ReturnFacts{preview_digest:"preview",read:ReturnRead{facts:ReturnReadFacts{signed:sign_data()}}}}),result:None,reported:false,phase:72},terminal:false},selector_seen:true}}}}
fn fixture()->(CoordinatorFinancialEndpointV1,HostFinancialWorkflowRelayV1){
 let c=CoordinatorFinancialEndpointV1{slots:std::array::from_fn(|_|CSlot{wire_phase:55,activate:activate()}),core:Core{phase:Phases{values:std::array::from_fn(|_|Cell::new(66)),restricted:Cell::new(false),step_error:Cell::new(false)},session:Instant::now()+Duration::from_secs(60),signer_restriction:None}};
 let h=HostFinancialWorkflowRelayV1{slots:std::array::from_fn(|_|HSlot{phase:55,activate:activate()})};(c,h)
}
fn set_inert_return_preconditions(c:&mut CoordinatorFinancialEndpointV1,h:&mut HostFinancialWorkflowRelayV1,role:Target){
 // Execute repaired Sign arms first. The omitted native Return preparation is
 // represented ONLY by the inert atomic72 input, never as an actual permission.
 assert!(matches!(c.c_sign(role,sign_data()).unwrap(),CoordinatorFinancialEventV1::SignCommitted{role:r,..} if r==role));
 assert!(h.h_sign(role,sign_data()).unwrap());c.core.phase.values[role.index()].set(72);
 assert_eq!(c.slots[role.index()].wire_phase,67);assert_eq!(h.slots[role.index()].phase,67);
}
'''

P80_RUST_TESTS=r'''
#[test]fn sign_committed_outer_phase_matches_both_original_consumers(){for role in [Target::Signer1,Target::Signer2]{
 let i=role.index();let(c0,h0)=fixture();let(mut old_c,mut old_h)=(c0,h0);
 assert_eq!(old_c.c_sign_old(role,sign_data()).unwrap(),CoordinatorFinancialEventV1::SignCommitted{role,data:sign_data()});assert!(old_h.h_sign_old(role,sign_data()).unwrap());
 assert_eq!(old_c.slots[i].wire_phase,55);assert_eq!(old_h.slots[i].phase,55);assert_eq!(old_c.slots[i].activate.wallet.sign.exact.phase,67);
 assert!(c_sign_guard(&old_c.core,&old_c.slots[i]).is_err());assert!(h_sign_guard(&old_h.slots[i]).is_err());
 let(mut c,mut h)=fixture();assert_eq!(c.c_sign(role,sign_data()).unwrap(),CoordinatorFinancialEventV1::SignCommitted{role,data:sign_data()});assert!(h.h_sign(role,sign_data()).unwrap());
 assert_eq!(c.slots[i].wire_phase,67);assert_eq!(h.slots[i].phase,67);assert!(c_sign_guard(&c.core,&c.slots[i]).is_ok());assert!(h_sign_guard(&h.slots[i]).is_ok());
 assert_eq!(c.slots[1-i].wire_phase,55);assert_eq!(h.slots[1-i].phase,55);
 c.slots[i].activate.wallet.sign.selector_seen=false;h.slots[i].activate.wallet.sign.selector_seen=false;assert!(c_sign_guard(&c.core,&c.slots[i]).is_err());assert!(h_sign_guard(&h.slots[i]).is_err());
}}
#[test]fn return_completed_outer_phase_reaches_normal_notice_after_sign(){for role in [Target::Signer1,Target::Signer2]{
 let i=role.index();let(mut old_c,mut old_h)=fixture();set_inert_return_preconditions(&mut old_c,&mut old_h,role);
 assert_eq!(old_c.c_return_old(role,return_data()).unwrap(),CoordinatorFinancialEventV1::ReturnCompleted{role,data:return_data()});assert!(old_h.h_return_old(role,return_data()).unwrap());
 assert_eq!(old_c.slots[i].wire_phase,67);assert_eq!(old_h.slots[i].phase,67);assert!(normal_guard(&old_c.core,&old_c.slots[i],i,&Notice{returned:[return_data(),return_data()]}).is_err());
 let(mut c,mut h)=fixture();set_inert_return_preconditions(&mut c,&mut h,role);assert_eq!(c.c_return(role,return_data()).unwrap(),CoordinatorFinancialEventV1::ReturnCompleted{role,data:return_data()});assert!(h.h_return(role,return_data()).unwrap());
 assert_eq!(c.slots[i].wire_phase,73);assert_eq!(h.slots[i].phase,73);assert!(normal_guard(&c.core,&c.slots[i],i,&Notice{returned:[return_data(),return_data()]}).is_ok());
 // Host normal completion consumes nested actual_completed; no invented outer73 guard.
 assert_eq!(h.slots[i].activate.wallet.sign.returning.actual_completed().unwrap(),&return_data());
 assert_eq!(c.slots[1-i].wire_phase,55);assert_eq!(h.slots[1-i].phase,55);
}}
#[test]fn invalid_or_replayed_reports_never_advance_outer_phase(){for role in [Target::Signer1,Target::Signer2]{for returned in [false,true]{for case in 0..9{
 let(mut c,mut h)=fixture();let i=role.index();if returned{set_inert_return_preconditions(&mut c,&mut h,role);}let prior=if returned{67}else{55};
 if returned{let mut d=return_data();let a=&mut c.slots[i].activate.wallet.sign.returning.exact;let b=&mut h.slots[i].activate.wallet.sign.returning.exact;
  match case{0=>d.valid=false,1=>{a.wire=None;b.wire=None;},2=>{a.reported=true;b.reported=true;},3=>{a.phase=73;b.phase=73;},4=>d.return_presentation_digest="crossed",5=>d.preview_digest="crossed",6=>d.result_digest="crossed",7=>d.outbox_digest="crossed",_=>{assert!(c.c_return(role,d.clone()).is_ok());assert!(h.h_return(role,d.clone()).is_ok());}}
  let before=if case==8{73}else{prior};assert!(c.c_return(role,d.clone()).is_err());assert!(h.h_return(role,d).is_err());assert_eq!(c.slots[i].wire_phase,before);assert_eq!(h.slots[i].phase,before);
 }else{let mut d=sign_data();let a=&mut c.slots[i].activate.wallet.sign.exact;let b=&mut h.slots[i].activate.wallet.sign.exact;
  match case{0=>d.valid=false,1=>{a.wire=None;b.wire=None;},2=>{a.reported=true;b.reported=true;},3=>{a.phase=67;b.phase=67;},4=>d.sign_presentation_digest="crossed",5=>d.authorization_id="crossed",6=>d.fixed_identity_digest="crossed",7=>{a.wire.as_mut().unwrap().facts.authorization_valid=false;b.wire.as_mut().unwrap().facts.authorization_valid=false;},_=>{assert!(c.c_sign(role,d.clone()).is_ok());assert!(h.h_sign(role,d.clone()).is_ok());}}
  let before=if case==8{67}else{prior};assert!(c.c_sign(role,d.clone()).is_err());assert!(h.h_sign(role,d).is_err());assert_eq!(c.slots[i].wire_phase,before);assert_eq!(h.slots[i].phase,before);
 }
 assert_eq!(c.slots[1-i].wire_phase,55);assert_eq!(h.slots[1-i].phase,55);
}}}}
#[test]fn coordinator_progress_error_and_restriction_preserve_original_results(){for role in [Target::Signer1,Target::Signer2]{for returned in [false,true]{for restricted in [false,true]{
 let(mut c,mut h)=fixture();let i=role.index();if returned{set_inert_return_preconditions(&mut c,&mut h,role);}let prior=if returned{67}else{55};let expected=if returned{73}else{67};
 c.core.phase.restricted.set(restricted);c.core.phase.step_error.set(!restricted);
 let result=if returned{c.c_return(role,return_data())}else{c.c_sign(role,sign_data())};
 let nested=if returned{&c.slots[i].activate.wallet.sign.returning.exact.reported}else{&c.slots[i].activate.wallet.sign.exact.reported};assert!(*nested);
 if restricted{
  // Original Ok(false) helper result was intentionally not an Err at these
  // report sites. Metadata still settles; the actual restriction guard denies.
  assert!(result.is_ok());assert_eq!(c.slots[i].wire_phase,expected);assert_eq!(c.core.phase.values[i].get(),if returned{72}else{66});
  assert!(c.core.check_action_restrictions().is_err());
  if returned{assert!(normal_guard(&c.core,&c.slots[i],i,&Notice{returned:[return_data(),return_data()]}).is_err());}else{assert!(c_sign_guard(&c.core,&c.slots[i]).is_err());}
 }else{let e=result.unwrap_err();assert_eq!(e.kind(),io::ErrorKind::PermissionDenied);assert_eq!(e.to_string(),"inert original step error");assert_eq!(c.slots[i].wire_phase,prior);}
}}}}
'''

P80_UI_SUPPORT=r'''
// Explicit inert UI/native/Serving carriers. No real Window, egui process,
// Origin, signed-result custody, permission, worker, or native Final exists.
use std::{cell::{Cell,RefCell},rc::Rc,io,time::{Duration,Instant},ops::{Deref,DerefMut}};
type Result<T>=io::Result<T>;fn rejected(s:&str)->io::Error{io::Error::new(io::ErrorKind::PermissionDenied,s.to_owned())}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] enum Phase{HistoryRetiring,RetirementBlocked,SigningRetiring,Other}
#[derive(Clone,Copy,Debug,PartialEq,Eq)] enum Role{One,Two}
struct Ticket{role:Role,cutoff:Instant}impl Ticket{fn role(&self)->Role{self.role}fn deadline(&self)->Instant{self.cutoff}}
struct Completion{role:Role,signing:bool}impl Completion{fn role(&self)->Role{self.role}}
struct Outbound;
struct Native{gate:Rc<Cell<u8>>,revoked:bool,fail_resume:bool}
impl Native{fn is_revoked(&self)->bool{self.revoked}fn pause_for_witness_retirement(&self,_:Ticket)->Result<Outbound>{Ok(Outbound)}fn resume_after_witness_retirement(&self,c:Completion)->Result<()>{if self.fail_resume{return Err(rejected("inert failed typed resume"));}if c.signing{self.gate.set(6);}Ok(())}}
struct Driver;impl Driver{fn send_signing_retirement(&mut self,_:Role,_:Outbound)->Result<()>{Ok(())}fn send_signing_predecessor_retirement(&mut self,_:Role,_:Outbound)->Result<()>{Ok(())}fn send_history_retirement(&mut self,_:Role,_:Outbound)->Result<()>{Ok(())}}
struct Serving{gate:Rc<Cell<u8>>,drops:Rc<Cell<usize>>}impl Serving{fn check_current(&self)->Result<()>{if self.gate.get()==4{Ok(())}else{Err(rejected("inert G4 observer after G6"))}}}impl Drop for Serving{fn drop(&mut self){self.drops.set(self.drops.get()+1);}}
struct WriterFlow{serving:Option<Serving>}
struct Ui{phase:Phase,focused_last:bool,native:Native,history_retirement:Option<Ticket>,active:Option<Role>,retirement_paused:Option<(Role,Instant)>,driver:RefCell<Driver>,history_retired:Option<Completion>,writer_flow:WriterFlow,history_resume_pending:Option<Role>}
struct LegacyUi{state:Ui}impl Deref for LegacyUi{type Target=Ui;fn deref(&self)->&Ui{&self.state}}impl DerefMut for LegacyUi{fn deref_mut(&mut self)->&mut Ui{&mut self.state}}
fn fixture(role:Role,phase:Phase)->(Ui,Rc<Cell<usize>>){let gate=Rc::new(Cell::new(4));let drops=Rc::new(Cell::new(0));(Ui{phase,focused_last:true,native:Native{gate:gate.clone(),revoked:false,fail_resume:false},history_retirement:None,active:Some(role),retirement_paused:Some((role,Instant::now()+Duration::from_secs(30))),driver:RefCell::new(Driver),history_retired:Some(Completion{role,signing:phase==Phase::SigningRetiring}),writer_flow:WriterFlow{serving:Some(Serving{gate,drops:drops.clone()})},history_resume_pending:None},drops)}
'''

P80_UI_TESTS=r'''
#[test]fn typed_signing_resume_drops_only_obsolete_serving_before_pre_poll_check(){for role in [Role::One,Role::Two]{
 let(state,old_drops)=fixture(role,Phase::SigningRetiring);let mut old=LegacyUi{state};old.history_retirement_tail().unwrap();assert!(old.retirement_paused.is_none());assert_eq!(old.native.gate.get(),6);assert!(old.serving_rejected());assert_eq!(old_drops.get(),0);
 let(mut ui,drops)=fixture(role,Phase::SigningRetiring);ui.history_retirement_tail().unwrap();assert!(ui.retirement_paused.is_none());assert_eq!(ui.history_resume_pending,Some(role));assert_eq!(ui.native.gate.get(),6);assert!(!ui.serving_rejected());assert_eq!(drops.get(),1);
 // Nothing here receives/constructs SigningResumed custody or parks a role.
 for phase in [Phase::HistoryRetiring,Phase::RetirementBlocked]{let(mut other,d)=fixture(role,phase);other.history_retirement_tail().unwrap();assert!(other.writer_flow.serving.is_some());assert_eq!(d.get(),0);assert!(!other.serving_rejected());}
 let(mut failed,d)=fixture(role,Phase::SigningRetiring);failed.native.fail_resume=true;assert!(failed.history_retirement_tail().is_err());assert!(failed.writer_flow.serving.is_some());assert!(failed.retirement_paused.is_some());assert!(failed.history_resume_pending.is_none());assert_eq!(d.get(),0);assert_eq!(failed.native.gate.get(),4);
 let(mut absent,d)=fixture(role,Phase::SigningRetiring);absent.history_retired=None;absent.history_retirement_tail().unwrap();assert!(absent.writer_flow.serving.is_some());assert_eq!(d.get(),0);assert!(absent.history_resume_pending.is_none());
 let(mut unpaused,d)=fixture(role,Phase::SigningRetiring);unpaused.retirement_paused=None;assert!(unpaused.history_retirement_tail().is_err());assert!(unpaused.writer_flow.serving.is_some());assert_eq!(d.get(),0);
 let(mut wrong,d)=fixture(role,Phase::SigningRetiring);wrong.history_retired=Some(Completion{role:if role==Role::One{Role::Two}else{Role::One},signing:true});assert!(wrong.history_retirement_tail().is_err());assert!(wrong.writer_flow.serving.is_some());assert!(wrong.retirement_paused.is_some());assert_eq!(d.get(),0);assert_eq!(wrong.native.gate.get(),4);
 for denied in 0..3{let(mut bad,d)=fixture(role,Phase::SigningRetiring);match denied{0=>bad.focused_last=false,1=>bad.native.revoked=true,_=>bad.phase=Phase::Other};assert!(bad.history_retirement_tail().is_err());assert!(bad.writer_flow.serving.is_some());assert_eq!(d.get(),0);}
}}
'''

def build_terminal_phase_harness():
    e=terminal_phase_items()
    rust='\nmod terminal_phase_harness {\n'+P80_RUST_SUPPORT
    rust+='\n'+e['committed_matches']+'\n'+e['completed_matches']+'\n'+e['received_progress']+'\nimpl Core {\n'+e['action_restrictions']+'\n}\nimpl ReturnSlots {\n'+e['actual_completed']+'\n}\n'
    for owner in ('c','h'):
        rust+='impl '+('CoordinatorFinancialEndpointV1' if owner=='c' else 'HostFinancialWorkflowRelayV1')+' {\n'
        for kind,variant,data_type in [('sign','SignCommitted','SignerSignCommittedV1'),('return','ReturnCompleted','SignerReturnCompletedV1')]:
            for suffix in ('','_old'):
                key=owner+'_'+kind+suffix
                rust+='fn '+key+'(&mut self,role:Target,data:'+data_type+')->Result<'+('CoordinatorFinancialEventV1' if owner=='c' else 'bool')+'> {let i=role.index();let slot=&mut self.slots[i];let s=&mut slot.activate.wallet.sign'+('.returning' if kind=='return' else '')+';let packet=Packet::'+variant+'{role,data};match '+('packet' if owner=='c' else '&packet')+' {\n'+e[key]+'\n_=>Err(rejected("inert unselected packet")),\n}}\n'
        rust+='}\n'
    rust+='fn c_sign_guard(core:&Core,slot:&CSlot)->Result<()> {core.check_action_restrictions()?;\n'+e['c_sign_guard']+'\nOk(())}\nfn h_sign_guard(slot:&HSlot)->Result<()> {\n'+e['h_sign_guard']+'\nOk(())}\n'
    rust+='fn normal_guard(core:&Core,slot:&CSlot,i:usize,notice:&Notice)->Result<()> {core.check_action_restrictions()?;\n'+e['normal_guard']+'\nOk(())}\n'+P80_RUST_TESTS+'\n}\n'
    return rust,e

def build_resume_tail_harness():
    e=resume_tail_items()
    rust='\nmod resume_tail_harness {\n'+P80_UI_SUPPORT+'\nimpl Ui {\n'+e['tail']+'\nfn serving_rejected(&self)->bool {\n'+e['serving_predicate']+'\n}\n}\nimpl LegacyUi {\n'+e['old_tail']+'\n}\n'+P80_UI_TESTS+'\n}\n'
    return rust,e

def build_harness():
    rust,e=build_legacy_harness()
    extra,items=build_terminal_phase_harness()
    anchor='\n}\nuse retirement_harness::{channel,host_interstage};\n'
    if not rust.endswith(anchor):raise AssertionError('legacy retirement module boundary moved')
    rust=rust[:-len(anchor)]+extra+anchor
    e.update({'p80_'+k:v for k,v in items.items()})
    extra,items=build_resume_tail_harness();rust+=extra;e.update({'p80_ui_'+k:v for k,v in items.items()})
    return rust,e

if __name__=='__main__':main()
