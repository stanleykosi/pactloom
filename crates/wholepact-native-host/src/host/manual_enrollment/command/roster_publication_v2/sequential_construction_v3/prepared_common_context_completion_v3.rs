//! Shared exact completion stages for the real retained all-observations owner.
//! The split permits an independent witness ceremony between the existing Host
//! disclosure and pending-file review. No DTO, callback or boolean constructs an
//! observed source, native approval, witness grant, claim or completion owner.
use super::*;
use crate::terminal::historical::{HistoricalApproval, HistoricalOutput};
use wholepact_authority::construction_transport_handoff_v1::SignedConstructionTransportPreauthorizationV1;

pub(super) struct DisclosedCommonContextGrantV3<'host> {
    host: &'host Host,
    participant: usize,
    authorization: SignedConstructionTransportPreauthorizationV1,
    disclosure: HistoricalApproval,
    output: HistoricalOutput,
}

pub(super) struct PreparedCommonContextCompletionV3<'host> {
    host: &'host Host,
    participant: usize,
    authorization: SignedConstructionTransportPreauthorizationV1,
    disclosure: HistoricalApproval,
    pending: PendingConstructionTransportGrantV1,
    digest: String,
    pair_approval: PublicationApproval,
    request_approval: PublicationApproval,
    operations: CompletionOperationIdsV1,
}

fn require_original(
    host: &Host,
    roster: &AllObservedCommonContextRosterV1<'_>,
    participant: usize,
    authorization: &SignedConstructionTransportPreauthorizationV1,
    disclosure: &HistoricalApproval,
) -> Result<()> {
    disclosure.check()?;
    roster.check_current(host)?;
    if roster.grant_request(host, participant)? != authorization {
        return Err(Error::Authentication);
    }
    disclosure.check()
}

pub(super) fn disclose_original<'host>(
    host: &'host Host,
    roster: &AllObservedCommonContextRosterV1<'_>,
    participant: usize,
) -> Result<DisclosedCommonContextGrantV3<'host>> {
    roster.check_current(host)?;
    let authorization = roster.grant_request(host, participant)?.clone();
    let disclosure = host.terminal.approve_historical(
            "Display this one exact original-owner signed handoff preauthorization for manual relay to its independent pinned native witness owner? ALL actual observations have been checked. It includes exact original account/session/read/plan commitments and creates no active credential or grant. Do not reuse it for another account or operation.",
        )?;
    let output = host.terminal.historical_output()?;
    disclosure
        .effect(&mut || output.json_checked(&authorization, || roster.check_current(host)))?;
    require_original(host, roster, participant, &authorization, &disclosure)?;
    Ok(DisclosedCommonContextGrantV3 {
        host,
        participant,
        authorization,
        disclosure,
        output,
    })
}

impl<'host> DisclosedCommonContextGrantV3<'host> {
    /// Read-only signed evidence only after the genuine foreground disclosure.
    /// The actual independent witness must still authenticate and review it.
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    pub(super) fn authorization(
        &self,
        roster: &AllObservedCommonContextRosterV1<'_>,
    ) -> Result<&SignedConstructionTransportPreauthorizationV1> {
        require_original(
            self.host,
            roster,
            self.participant,
            &self.authorization,
            &self.disclosure,
        )?;
        Ok(&self.authorization)
    }

    pub(super) fn review_pending(
        self,
        roster: &AllObservedCommonContextRosterV1<'_>,
        operations: CompletionOperationIdsV1,
    ) -> Result<PreparedCommonContextCompletionV3<'host>> {
        let Self {
            host,
            participant,
            authorization,
            disclosure,
            output,
        } = self;
        require_original(host, roster, participant, &authorization, &disclosure)?;
        host.terminal.message("Paste that exact authorization into the independent witness owner's 'One-use construction transport handoff' review. Save its resulting exact inert pending-grant display as a private JSON file. Select the exact original namespace/attempt and pending-grant digest in the purpose-limited Authority server. Neither a terminal acknowledgment nor the file proves native approval. Keep every original signer process open so its key-free completion remains available.\n")?;
        let shown: PendingGrantDisplayV1 = host.read_manual_private(
            "Exact native witness pending-grant DISPLAY JSON file (kind, notice, pending_grant): ",
            "binding the separately issued inert pending grant to this original actual observed owner",
        )?;
        let pending = shown.into_pending()?;
        if pending.grant.authorization != authorization {
            return Err(Error::Authentication);
        }
        roster.check_current(host)?;
        let pending_digest = pending.digest().map_err(|_| Error::Authentication)?;
        let selector_disclosure = host.terminal.approve_historical_reviewed(&disclosure,
            "Display the exact inert pending-grant digest and original attempt digest for selecting this one purpose-limited Authority server? Use the already retained original namespace, extension and server configuration. This metadata creates no credential or approval and cannot renew the original read or invocation clocks.")?;
        let selector = serde_json::json!({
            "kind": "inert_construction_transport_server_selector_v1",
            "pending_grant_digest": pending_digest,
            "original_attempt_digest": authorization.authorization.attempt_digest,
            "original_attempt_sequence": authorization.authorization.attempt_sequence,
        });
        selector_disclosure.effect(&mut || {
            output.json_checked(&selector, || {
                disclosure.check()?;
                roster.check_current(host)
            })
        })?;
        host.terminal.message("Configure serve-born-construction-transport-v1 with that exact pending_grant_digest and original_attempt.attempt_digest, preserving the original namespace, extension and pinned server configuration. Complete that selection before the fresh signer unlock below. Do not select the ordinary writer server.\n")?;
        let digest = wholepact_core::proposal::canonical_digest(
            "wholepact:host-common-context-exact-reentry-process:v1",
            &(
                &authorization,
                &pending_digest,
                &operations.reentry,
                &operations.construction,
            ),
        )
        .map_err(|_| Error::Invalid)?;
        let pair_approval = host.terminal.approve_publication_reviewed(&disclosure, &digest,
            "Wait for a genuinely fresh original-account completion unlock in the SAME still-running installed signer, then pair only that newly published endpoint. The original dormant owner and original read clocks remain mandatory; this approves no new account/session, read, input selection or general writer use.")?;
        let request_approval = host.terminal.approve_publication_reviewed(&disclosure, &digest,
            "Send one exact completion request using this pending grant and the actual fresh caller. The signer must separately approve original witness contact, then the exact fresh TLS-bound claim and permanent old-key fence, then the complete original proposal's Reserve/Consume. The construction request will be created only after actual reentry admission. All original observations and deadlines remain mandatory; uncertainty or failure cannot retry. No proof, transaction signature or dispatch is approved.")?;
        host.terminal.message("Now use the SAME original signer window's 'Unlock exact original account for admitted completion' control, complete fresh pairing, and remain there for the separate contact, TLS claim and full-proposal reviews. Do not use ordinary account unlock, explicit Lock or another signer process. The retained claim channel keeps its original ten-second limit, including both later native reviews.\n")?;
        require_original(host, roster, participant, &authorization, &disclosure)?;
        Ok(PreparedCommonContextCompletionV3 {
            host,
            participant,
            authorization,
            disclosure,
            pending,
            digest,
            pair_approval,
            request_approval,
            operations,
        })
    }
}

impl PreparedCommonContextCompletionV3<'_> {
    /// Restriction-only original bound. Calling this never renews any approval,
    /// observation, retained invocation or native transport claim.
    #[cfg(all(test, feature = "synthetic-born-joined-qualification"))]
    pub(super) fn original_deadline(&self) -> std::time::Instant {
        self.disclosure
            .deadline()
            .min(self.pair_approval.deadline())
            .min(self.request_approval.deadline())
    }

    pub(super) fn consume(self, roster: &mut AllObservedCommonContextRosterV1<'_>) -> Result<()> {
        let Self {
            host,
            participant,
            authorization,
            disclosure,
            pending,
            digest,
            pair_approval,
            request_approval,
            operations,
        } = self;
        roster_trace!(
            CompletionOriginal,
            require_original(host, roster, participant, &authorization, &disclosure)
        )?;
        let (roster, client) = roster_trace!(
            CompletionPairApproval,
            pair_approval.commit(
                &digest,
                || {
                    require_original(host, roster, participant, &authorization, &disclosure)?;
                    Ok(roster)
                },
                |roster| {
                    let client = roster.pair_owner_before(
                        host,
                        participant,
                        "wholepact-native-common-context-reentry-v1",
                    )?;
                    Ok((roster, client))
                },
            )
        )?;
        let request = roster_trace!(
            CompletionReentryRequest,
            roster.reentry_request(host, participant, &client, &pending, operations.reentry)
        )?;
        roster_trace!(
            CompletionRequestApproval,
            request_approval.commit(
                &digest,
                || {
                    require_original(host, roster, participant, &authorization, &disclosure)?;
                    Ok(roster)
                },
                |roster| {
                    roster.consume_owner_before(
                        host,
                        participant,
                        &client,
                        &pending,
                        &request,
                        operations.construction,
                    )?;
                    require_original(host, roster, participant, &authorization, &disclosure)
                },
            )
        )
    }
}
