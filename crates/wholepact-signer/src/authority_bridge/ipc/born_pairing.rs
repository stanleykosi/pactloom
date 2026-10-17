//! Initial purpose-bound born pairing only. The genuine native Pair and Status
//! ceremony is unchanged; caller deadlines/cancellation only restrict its I/O.
//! This is not a conversion from another client's grant or a token importer.
use super::super::born_ipc_io::{require_current, write_checked};
use super::*;

const PAIR_FRAME_LIMIT: usize = 16 * 1024;
const PAIR_PHASE_LIMIT: Duration = Duration::from_secs(120);

/// Owns the actual pending native channel, never reconstructible from a DTO.
/// The same installed provider, peer and original deadline survive both phases.
pub struct PendingBornHistoryPairV1 {
    provider: InstalledSignerProvider,
    socket: PathBuf,
    peer: PeerProcess,
    scope: PairScope,
    stream: UnixStream,
    started: Instant,
    original_deadline: Instant,
    pairing_deadline: Instant,
}
fn require_scope(scope: &PairScope) -> Result<()> {
    scope.validate().map_err(|_| BridgeError::Binding)?;
    if !scope.history_read || scope.authorization_export || scope.preconstruction_export {
        return Err(BridgeError::Permission);
    }
    Ok(())
}
fn grant_expiry(
    response: &PairResponse,
    started: Instant,
    original_deadline: Instant,
    now: Instant,
) -> Result<Instant> {
    if response.schema_version != 1
        || !response.accepted
        || response.reason_code != "LOCAL_PROCESS_REQUEST_SCOPE"
        || response.expires_in_seconds == 0
        || response.expires_in_seconds > 900
        || response.grant_id.len() != 64
        || response.token_hex.len() != 64
        || !response
            .grant_id
            .bytes()
            .chain(response.token_hex.bytes())
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BridgeError::Permission);
    }
    let expires = started
        .checked_add(Duration::from_secs(response.expires_in_seconds))
        .ok_or(BridgeError::Permission)?
        .min(original_deadline);
    if now >= expires {
        return Err(BridgeError::Permission);
    }
    Ok(expires)
}
fn connect_checked(
    provider: &InstalledSignerProvider,
    socket: &Path,
    expected: Option<&PeerProcess>,
    deadline: Instant,
    check_current: &impl Fn() -> Result<()>,
) -> Result<(UnixStream, PeerProcess)> {
    require_current(deadline, check_current)?;
    let stream = wholepact_signer_origin::connect_local_checked_until(socket, deadline, || {
        check_current().map_err(|_| wholepact_signer_origin::Error::Permission)
    })
    .map_err(|_| BridgeError::Ipc)?;
    require_current(deadline, check_current)?;
    crate::ipc::enable_credentials(stream.as_raw_fd()).map_err(|_| BridgeError::Ipc)?;
    require_current(deadline, check_current)?;
    let peer = provider.verify_server(&stream)?;
    require_current(deadline, check_current)?;
    if let Some(expected) = expected {
        expected
            .same_live_process(&peer)
            .map_err(|_| BridgeError::Permission)?;
    }
    peer.check_alive().map_err(|_| BridgeError::Permission)?;
    require_current(deadline, check_current)?;
    Ok((stream, peer))
}
fn read_checked(
    stream: &UnixStream,
    peer: &PeerProcess,
    deadline: Instant,
    check_current: &impl Fn() -> Result<()>,
) -> Result<Zeroizing<Vec<u8>>> {
    require_current(deadline, check_current)?;
    wholepact_signer_origin::framing::read_frame_capped_checked_until(
        stream,
        peer,
        PAIR_FRAME_LIMIT,
        deadline,
        || check_current().map_err(|_| wholepact_signer_origin::Error::Permission),
    )
    .map_err(|_| BridgeError::Ipc)
}
impl OriginalHistoryClient {
    /// Exact already-granted scope for correlation only, not currentness or a
    /// transferable grant. Each history/dispatch operation checks its own owner.
    pub fn pairing_scope(&self) -> &PairScope {
        &self.scope
    }

    /// Starts only the actual history-only born native ceremony. Keep the
    /// returned owner and finish while the signer's real native UI processes
    /// its exact Pair and local-record reviews. No second grant is needed later.
    /// `original_deadline` caps retained-client lifetime to the caller's already
    /// fixed source/scenario bound. A shorter native pairing-approval cutoff
    /// must also remain in `check_current` during BOTH begin and finish. The
    /// ceremony itself is always capped at 120 seconds from this initial call.
    /// No native source, writer session or financial permission is renewed.
    pub fn begin_born_pair_checked_until(
        provider: InstalledSignerProvider,
        socket: &Path,
        application_label: &str,
        scope: PairScope,
        original_deadline: Instant,
        check_current: impl Fn() -> Result<()>,
    ) -> Result<PendingBornHistoryPairV1> {
        require_scope(&scope)?;
        crate::review::validate_label(application_label).map_err(|_| BridgeError::Binding)?;
        let started = Instant::now();
        let pairing_deadline = original_deadline.min(
            started
                .checked_add(PAIR_PHASE_LIMIT)
                .ok_or(BridgeError::Permission)?,
        );
        let (mut stream, peer) =
            connect_checked(&provider, socket, None, pairing_deadline, &check_current)?;
        let current = || {
            check_current()?;
            peer.check_alive().map_err(|_| BridgeError::Permission)
        };
        write_checked(
            &mut stream,
            &serde_json::json!({
                "command":"request_pairing","schema_version":1,
                "application_label":application_label,"scope":scope,
            }),
            pairing_deadline,
            &current,
        )?;
        require_current(pairing_deadline, &current)?;
        Ok(PendingBornHistoryPairV1 {
            provider,
            socket: socket.into(),
            peer,
            scope,
            stream,
            started,
            original_deadline,
            pairing_deadline,
        })
    }
}
impl PendingBornHistoryPairV1 {
    /// Finishes the SAME request. Partial/error channels are consumed and
    /// dropped; callers cannot reuse a suffix or reconstruct a grant/token.
    pub fn finish_checked(
        self,
        check_current: impl Fn() -> Result<()>,
    ) -> Result<OriginalHistoryClient> {
        let current = || {
            check_current()?;
            self.peer.check_alive().map_err(|_| BridgeError::Permission)
        };
        let bytes = read_checked(&self.stream, &self.peer, self.pairing_deadline, &current)?;
        require_current(self.pairing_deadline, &current)?;
        let mut response: PairResponse =
            serde_json::from_slice(&bytes).map_err(|_| BridgeError::Permission)?;
        let expires = grant_expiry(
            &response,
            self.started,
            self.original_deadline,
            Instant::now(),
        )?;
        require_current(self.pairing_deadline, &current)?;
        let client = OriginalHistoryClient {
            provider: self.provider,
            socket: self.socket,
            peer: self.peer,
            scope: self.scope,
            grant: ClientGrant {
                grant_id: response.grant_id.clone(),
                token_hex: Zeroizing::new(std::mem::take(&mut response.token_hex)),
                expires,
            },
            active_leases: AtomicUsize::new(0),
            mode: PairingMode::Ordinary,
        };
        let deadline = self.pairing_deadline.min(client.grant.expires);
        let current = || {
            check_current()?;
            client
                .peer
                .check_alive()
                .map_err(|_| BridgeError::Permission)
        };
        // Exact token-possession probe is mandatory before the client escapes.
        let (mut stream, _) = connect_checked(
            &client.provider,
            &client.socket,
            Some(&client.peer),
            deadline,
            &current,
        )?;
        #[derive(Serialize)]
        struct Request<'a> {
            command: &'static str,
            schema_version: u16,
            grant_id: &'a str,
            token_hex: &'a str,
            request: serde_json::Value,
        }
        write_checked(
            &mut stream,
            &Request {
                command: "request",
                schema_version: 1,
                grant_id: &client.grant.grant_id,
                token_hex: client.grant.token_hex.as_str(),
                request: serde_json::json!({"operation":"status"}),
            },
            deadline,
            &current,
        )?;
        let bytes = read_checked(&stream, &client.peer, deadline, &current)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Accepted {
            accepted: bool,
            reason_code: String,
        }
        let accepted: Accepted = serde_json::from_slice(&bytes).map_err(|_| BridgeError::Ipc)?;
        if !accepted.accepted || accepted.reason_code != "REQUEST_ONLY" {
            return Err(BridgeError::Permission);
        }
        require_current(deadline, &current)?;
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> PairScope {
        PairScope {
            account_id: "account".into(),
            agreement_id: "agreement".into(),
            participant_id: "participant".into(),
            manifest_digest: "a".repeat(64),
            history_read: true,
            authorization_export: false,
            preconstruction_export: false,
        }
    }
    fn response() -> PairResponse {
        PairResponse {
            schema_version: 1,
            accepted: true,
            reason_code: "LOCAL_PROCESS_REQUEST_SCOPE".into(),
            grant_id: "a".repeat(64),
            token_hex: "b".repeat(64),
            expires_in_seconds: 900,
        }
    }
    #[test]
    fn born_initial_pair_scope_never_expands_history_to_export() {
        let wanted = scope();
        assert!(require_scope(&wanted).is_ok());
        let mut altered = wanted.clone();
        altered.authorization_export = true;
        assert!(require_scope(&altered).is_err());
        altered = wanted.clone();
        altered.preconstruction_export = true;
        assert!(require_scope(&altered).is_err());
        altered = wanted;
        altered.history_read = false;
        assert!(require_scope(&altered).is_err());
    }
    #[test]
    fn born_initial_pair_grant_preserves_original_deadline_and_wire_checks() {
        // Inert wire validation, not a peer/native grant constructor.
        let start = Instant::now();
        let original = start + Duration::from_secs(30);
        let mut r = response();
        assert_eq!(grant_expiry(&r, start, original, start).unwrap(), original);
        assert!(grant_expiry(&r, start, original, original).is_err());
        r.expires_in_seconds = 10;
        assert_eq!(
            grant_expiry(&r, start, original, start).unwrap(),
            start + Duration::from_secs(10)
        );
        for bad in [0, 901] {
            r.expires_in_seconds = bad;
            assert!(grant_expiry(&r, start, original, start).is_err());
        }
        r = response();
        r.token_hex = "B".repeat(64);
        assert!(grant_expiry(&r, start, original, start).is_err());
        r = response();
        r.accepted = false;
        assert!(grant_expiry(&r, start, original, start).is_err());
        r = response();
        r.reason_code = "REQUEST_ONLY".into();
        assert!(grant_expiry(&r, start, original, start).is_err());
    }
}
