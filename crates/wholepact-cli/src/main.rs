//! CLI for the same local API used by the workspace. No parallel policy engine.
#![forbid(unsafe_code)]
use clap::{Parser, Subcommand};
use futures_util::StreamExt;
use reqwest::{Client, Method, Url};
use serde_json::{json, Value};
use std::{error::Error, path::PathBuf, time::Duration};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_FILE: u64 = 262_144;

#[derive(Parser)]
#[command(
    name = "wholepact",
    version,
    about = "Private cooperative settlement: local draft and review client. Settlement is capability-gated."
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:4318", global = true)]
    server: String,
    #[arg(long, global = true)]
    json: bool,
    /// Use the public synthetic development credential. Never use for private data.
    #[arg(long, global = true)]
    development_fixture: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Health,
    Capabilities,
    #[command(subcommand)]
    Agreements(AgreementCommand),
    #[command(subcommand)]
    Intents(IntentCommand),
    #[command(subcommand)]
    Proposals(ProposalCommand),
    #[command(subcommand)]
    Candidates(CandidateCommand),
    #[command(subcommand)]
    Sponsors(SponsorCommand),
    #[command(subcommand)]
    Transport(TransportCommand),
    /// Read locally retained invitations without joining or authorizing anything.
    #[command(subcommand)]
    Invitations(InvitationCommand),
    Cancel {
        agreement: String,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Reconcile {
        agreement: String,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Recovery,
    Accounts,
    /// Queue a separately reviewed native journal audit or read its exact original result.
    #[command(subcommand)]
    AccountAudit(AccountAuditCommand),
    Authorizations,
    Records,
    Operation {
        id: String,
    },
    Events {
        #[arg(long, default_value_t = 0)]
        after: u64,
        #[arg(long)]
        follow: bool,
    },
}
#[derive(Subcommand)]
enum AccountAuditCommand {
    List { agreement:String },
    Show { agreement:String, request:String },
    Request { agreement:String, candidate:String, participant:String, #[arg(long)] revision:u64, #[arg(long)] idempotency_key:String },
    Withdraw { agreement:String, request:String, #[arg(long)] revision:u64, #[arg(long)] idempotency_key:String },
}
#[derive(Subcommand)]
enum AgreementCommand {
    List,
    Show {
        id: String,
    },
    Validate {
        file: PathBuf,
    },
    Create {
        file: PathBuf,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Revise unsigned terms using a complete AgreementDraft JSON file.
    Revise {
        agreement: String,
        /// Complete replacement draft, including the next terms revision.
        file: PathBuf,
        /// Expected journal revision from the agreement view, not the terms revision.
        #[arg(long, value_name = "JOURNAL_REVISION")]
        revision: u64,
        /// Reuse this key with the same file and journal revision when retrying.
        #[arg(long)]
        idempotency_key: String,
    },
}
#[derive(Subcommand)]
enum IntentCommand {
    /// Save an exact, nonbinding roster; the file contains selected_intent_ids.
    Select {
        agreement: String,
        file: PathBuf,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Add {
        agreement: String,
        file: PathBuf,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Withdraw {
        agreement: String,
        intent: String,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}
#[derive(Subcommand)]
enum ProposalCommand {
    /// Compare immutable terms snapshots from the same agreement.
    Compare {
        older: String,
        newer: String,
    },
    Create {
        agreement: String,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Show {
        id: String,
    },
    Verify {
        id: String,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    RequestAuthorization {
        id: String,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Submit {
        id: String,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum CandidateCommand {
    /// Compare exact unsigned candidate claims, including all input and output allocations.
    Compare {
        older: String,
        newer: String,
    },
    /// Read cached protected-job metadata, without starting or recovering a worker.
    ProofJobs {
        id: String,
    },
    /// Freeze an exact accounting manifest. This does not approve or sign it.
    Create {
        agreement: String,
        file: PathBuf,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Show {
        id: String,
    },
    /// Review immutable claimed accounting; no arbitrary verified flags accepted.
    Verify {
        id: String,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum SponsorCommand {
    List {
        agreement: String,
    },
    Show {
        agreement: String,
        policy: String,
    },
    Create {
        agreement: String,
        file: PathBuf,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    Update {
        agreement: String,
        policy: String,
        file: PathBuf,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    State {
        agreement: String,
        policy: String,
        file: PathBuf,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Evaluate exact stored candidate claims; this never verifies or authorizes a match.
    Preview {
        agreement: String,
        policy: String,
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum InvitationCommand {
    List,
    Show { handle: String },
}

#[derive(Subcommand)]
enum TransportCommand {
    /// Safe metadata from a separately injected protected native runtime.
    List {
        agreement: String,
    },
    Show {
        agreement: String,
        handle: String,
    },
    /// Import a previously authenticated nonbinding message. Use its issued key and revision.
    Import {
        agreement: String,
        handle: String,
        #[arg(long)]
        revision: u64,
        #[arg(long)]
        idempotency_key: String,
    },
}

struct Api {
    client: Client,
    base: Url,
    token: String,
    csrf: String,
}
impl Api {
    async fn open(args: &Args) -> Result<Self> {
        let mut base = Url::parse(&args.server)?;
        if base.scheme() != "http"
            || !matches!(base.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
        {
            return Err(
                "Server must be an HTTP loopback origin without a path, query, or credentials"
                    .into(),
            );
        }
        base.set_path("/");
        let bootstrap = if args.development_fixture {
            "wholepact-development-only-not-a-secret".to_owned()
        } else {
            std::env::var("WHOLEPACT_BOOTSTRAP_TOKEN").map_err(|_| "Set WHOLEPACT_BOOTSTRAP_TOKEN for an explicitly granted local client; credentials are not accepted in CLI arguments")?
        };
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(20))
            .build()?;
        let response = client
            .get(base.join("v1/session")?)
            .bearer_auth(&bootstrap)
            .send()
            .await?;
        let status = response.status();
        let value = bounded_json(response).await?;
        if !status.is_success() {
            return Err(format_error(&value).into());
        }
        let token = value["session_token"]
            .as_str()
            .ok_or("Service returned no session token")?
            .to_owned();
        let csrf = value["csrf_token"]
            .as_str()
            .ok_or("Service returned no CSRF token")?
            .to_owned();
        Ok(Self {
            client,
            base,
            token,
            csrf,
        })
    }
    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        revision: Option<u64>,
        key: Option<String>,
        mutation: bool,
    ) -> Result<Value> {
        let mut request = self
            .client
            .request(method, self.base.join(path)?)
            .bearer_auth(&self.token)
            .header("X-Request-Id", Uuid::new_v4().to_string());
        if let Some(body) = body {
            request = request.header("X-Wholepact-CSRF", &self.csrf).json(&body);
        }
        if let Some(revision) = revision {
            request = request.header("If-Match", format!("\"{revision}\""));
        }
        let idempotency = if mutation {
            Some(key.unwrap_or_else(|| Uuid::new_v4().to_string()))
        } else {
            None
        };
        if let Some(key) = &idempotency {
            request = request.header("Idempotency-Key", key);
        }
        let response = match request.send().await {
            Ok(r) => r,
            Err(error) => {
                if let Some(key) = &idempotency {
                    eprintln!("Request outcome may be unknown. Retry the same payload, revision and --idempotency-key {key}.");
                }
                return Err(error.into());
            }
        };
        let status = response.status();
        let operation_id = response
            .headers()
            .get("x-operation-id")
            .and_then(|h| h.to_str().ok())
            .filter(|id| {
                id.len() <= 128
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
            })
            .map(str::to_owned);
        if let Some(operation_id) = operation_id {
            eprintln!("Operation ID: {operation_id}");
        }
        let value = match bounded_json(response).await {
            Ok(value) => value,
            Err(error) => {
                if let Some(key) = &idempotency {
                    eprintln!("Response was interrupted or invalid; the request may have committed. Retry the same payload, revision and --idempotency-key {key}.");
                }
                return Err(error);
            }
        };
        if !status.is_success() {
            return Err(format_error(&value).into());
        }
        if let Some(key) = &idempotency {
            eprintln!("Idempotency key: {key}");
        }
        Ok(value)
    }
    async fn close(&self) {
        if let Ok(url) = self.base.join("v1/session/end") {
            let _ = self
                .client
                .post(url)
                .bearer_auth(&self.token)
                .header("X-Wholepact-CSRF", &self.csrf)
                .json(&json!({}))
                .timeout(Duration::from_secs(3))
                .send()
                .await;
        }
    }
    async fn get(&self, path: &str) -> Result<Value> {
        self.call(Method::GET, path, None, None, None, false).await
    }
    async fn post(
        &self,
        path: &str,
        body: Value,
        revision: Option<u64>,
        key: Option<String>,
    ) -> Result<Value> {
        self.call(Method::POST, path, Some(body), revision, key, true)
            .await
    }
    async fn events(&self, after: u64, follow: bool, json_output: bool) -> Result<()> {
        if !follow {
            let value = self
                .get(&format!("v1/events?after={after}&format=json"))
                .await?;
            print_value(value, json_output);
            return Ok(());
        }
        let response = self
            .client
            .get(self.base.join(&format!("v1/events?after={after}"))?)
            .bearer_auth(&self.token)
            .timeout(Duration::from_secs(1800))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(format_error(&bounded_json(response).await?).into());
        }
        let mut stream = response.bytes_stream();
        let mut decoder = EventDecoder::new(after);
        while let Some(chunk) = stream.next().await {
            for event in decoder.push(&chunk?)? {
                print_value(event, json_output);
            }
        }
        if !decoder.buffer.is_empty() {
            return Err("Event stream ended with an incomplete frame; reconnect from the last observed sequence".into());
        }
        Ok(())
    }
}

/// Decode complete bounded frames before UTF-8 decoding; HTTP chunks may split any codepoint.
struct EventDecoder {
    buffer: Vec<u8>,
    cursor: u64,
}
impl EventDecoder {
    fn new(cursor: u64) -> Self {
        Self {
            buffer: Vec::new(),
            cursor,
        }
    }
    fn push(&mut self, chunk: &[u8]) -> Result<Vec<Value>> {
        if self.buffer.len().saturating_add(chunk.len()) > 1_048_576 {
            return Err("Event stream frame exceeded the limit".into());
        }
        self.buffer.extend_from_slice(chunk);
        let mut events = Vec::new();
        loop {
            let end = self
                .buffer
                .windows(2)
                .position(|bytes| bytes == b"\n\n")
                .map(|index| (index, 2));
            let crlf = self
                .buffer
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .map(|index| (index, 4));
            let Some((end, delimiter)) =
                end.into_iter().chain(crlf).min_by_key(|(index, _)| *index)
            else {
                break;
            };
            let frame = std::str::from_utf8(&self.buffer[..end])?;
            let mut event_type = None;
            let mut data = Vec::new();
            for line in frame.lines() {
                if let Some(value) = line.strip_prefix("event:") {
                    event_type = Some(value.trim());
                }
                if let Some(value) = line.strip_prefix("data:") {
                    data.push(value.strip_prefix(' ').unwrap_or(value));
                }
            }
            if !data.is_empty() {
                match event_type {
                    Some("session_expired") => return Err("AUTHENTICATION_REQUIRED: Event-stream session expired; reconnect before relying on observations".into()),
                    Some("service_unavailable") => return Err("STORAGE_UNAVAILABLE: Durable event reads stopped; previously observed information may be stale".into()),
                    Some("wholepact") | None => {},
                    Some(_) => return Err("Unsupported event-stream message type".into()),
                }
                let event: Value = serde_json::from_str(&data.join("\n"))?;
                let sequence = event["sequence"]
                    .as_u64()
                    .ok_or("Malformed service event sequence")?;
                if !event["event_id"].is_string() || !event["kind"].is_string() {
                    return Err("Malformed service event identity".into());
                }
                if sequence > self.cursor {
                    self.cursor = sequence;
                    events.push(event);
                }
            }
            self.buffer.drain(..end + delimiter);
        }
        Ok(events)
    }
}

async fn bounded_json(response: reqwest::Response) -> Result<Value> {
    if response.content_length().is_some_and(|s| s > 4_194_304) {
        return Err("Service response exceeded the limit".into());
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len() + chunk.len() > 4_194_304 {
            return Err("Service response exceeded the limit".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn format_error(value: &Value) -> String {
    format!(
        "{}: {}",
        value["code"].as_str().unwrap_or("SERVICE_ERROR"),
        value["message"].as_str().unwrap_or("Request failed")
    )
}
fn id(value: &str) -> Result<&str> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
    {
        Err("Invalid resource ID".into())
    } else {
        Ok(value)
    }
}
fn read_json(path: &PathBuf) -> Result<Value> {
    if std::fs::metadata(path)?.len() > MAX_FILE {
        return Err("Input JSON exceeds 256 KiB".into());
    }
    Ok(wholepact_core::parse_json_unique(&std::fs::read(path)?)?)
}
fn print_value(value: Value, json_output: bool) {
    // All output is the canonical response. Human mode adds framing, never changes semantics.
    if !json_output {
        if let Some(kind) = value.get("kind").and_then(Value::as_str) {
            println!("{kind}");
        }
        if let Some(message) = value.get("message").and_then(Value::as_str) {
            println!("{message}");
        }
    }
    println!(
        "{}",
        if json_output {
            serde_json::to_string(&value).unwrap_or_default()
        } else {
            serde_json::to_string_pretty(&value).unwrap_or_default()
        }
    );
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("wholepact: {error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let args = Args::parse();
    let api = Api::open(&args).await?;
    let outcome = run_command(&api, args).await;
    api.close().await;
    outcome
}
async fn run_command(api: &Api, args: Args) -> Result<()> {
    let value = match args.command {
        Command::Health => api.get("v1/health").await?,
        Command::Capabilities => api.get("v1/capabilities").await?,
        Command::Agreements(c) => match c {
            AgreementCommand::List => api.get("v1/agreements").await?,
            AgreementCommand::Show { id: value } => {
                api.get(&format!("v1/agreements/{}", id(&value)?)).await?
            }
            AgreementCommand::Validate { file } => {
                api.call(
                    Method::POST,
                    "v1/agreements/validate",
                    Some(read_json(&file)?),
                    None,
                    None,
                    false,
                )
                .await?
            }
            AgreementCommand::Create {
                file,
                idempotency_key,
            } => {
                api.post("v1/agreements", read_json(&file)?, None, idempotency_key)
                    .await?
            }
            AgreementCommand::Revise {
                agreement,
                file,
                revision,
                idempotency_key,
            } => {
                api.post(
                    &format!("v1/agreements/{}/terms-revisions", id(&agreement)?),
                    read_json(&file)?,
                    Some(revision),
                    Some(idempotency_key),
                )
                .await?
            }
        },
        Command::Intents(c) => match c {
            IntentCommand::Select {
                agreement,
                file,
                revision,
                idempotency_key,
            } => {
                api.post(
                    &format!("v1/agreements/{}/roster-selection", id(&agreement)?),
                    read_json(&file)?,
                    Some(revision),
                    idempotency_key,
                )
                .await?
            }
            IntentCommand::Add {
                agreement,
                file,
                revision,
                idempotency_key,
            } => {
                api.post(
                    &format!("v1/agreements/{}/intents", id(&agreement)?),
                    read_json(&file)?,
                    Some(revision),
                    idempotency_key,
                )
                .await?
            }
            IntentCommand::Withdraw {
                agreement,
                intent,
                revision,
                idempotency_key,
            } => {
                api.post(
                    &format!(
                        "v1/agreements/{}/intents/{}/withdraw",
                        id(&agreement)?,
                        id(&intent)?
                    ),
                    json!({}),
                    Some(revision),
                    idempotency_key,
                )
                .await?
            }
        },
        Command::Proposals(c) => match c {
            ProposalCommand::Compare { older, newer } => {
                api.get(&format!(
                    "v1/proposals/{}/compare/{}",
                    id(&newer)?,
                    id(&older)?
                ))
                .await?
            }
            ProposalCommand::Create {
                agreement,
                revision,
                idempotency_key,
            } => {
                api.post(
                    &format!("v1/agreements/{}/proposals", id(&agreement)?),
                    json!({}),
                    Some(revision),
                    idempotency_key,
                )
                .await?
            }
            ProposalCommand::Show { id: value } => {
                api.get(&format!("v1/proposals/{}", id(&value)?)).await?
            }
            ProposalCommand::Verify {
                id: value,
                revision,
                idempotency_key,
            } => {
                api.post(
                    &format!("v1/proposals/{}/verify", id(&value)?),
                    json!({}),
                    Some(revision),
                    idempotency_key,
                )
                .await?
            }
            ProposalCommand::RequestAuthorization {
                id: value,
                revision,
                idempotency_key,
            } => {
                api.post(
                    &format!("v1/proposals/{}/authorization-requests", id(&value)?),
                    json!({}),
                    Some(revision),
                    idempotency_key,
                )
                .await?
            }
            ProposalCommand::Submit {
                id: value,
                revision,
                idempotency_key,
            } => {
                api.post(
                    &format!("v1/proposals/{}/submit", id(&value)?),
                    json!({}),
                    Some(revision),
                    idempotency_key,
                )
                .await?
            }
        },
        Command::Candidates(c) => match c {
            CandidateCommand::Compare { older, newer } => {
                api.get(&format!(
                    "v1/candidates/{}/compare/{}",
                    id(&newer)?,
                    id(&older)?
                ))
                .await?
            }
            CandidateCommand::ProofJobs { id: value } => {
                api.get(&format!("v1/candidates/{}/proof-jobs", id(&value)?))
                    .await?
            }
            CandidateCommand::Create {
                agreement,
                file,
                revision,
                idempotency_key,
            } => {
                api.post(
                    &format!("v1/agreements/{}/candidates", id(&agreement)?),
                    read_json(&file)?,
                    Some(revision),
                    idempotency_key,
                )
                .await?
            }
            CandidateCommand::Show { id: value } => {
                api.get(&format!("v1/candidates/{}", id(&value)?)).await?
            }
            CandidateCommand::Verify {
                id: value,
                revision,
                idempotency_key,
            } => {
                api.post(
                    &format!("v1/candidates/{}/verify", id(&value)?),
                    json!({}),
                    Some(revision),
                    idempotency_key,
                )
                .await?
            }
        },
        Command::Invitations(c) => match c {
            InvitationCommand::List => api.get("v1/invitations").await?,
            InvitationCommand::Show { handle } => {
                api.get(&format!("v1/invitations/{}", id(&handle)?)).await?
            }
        },
        Command::Transport(c) => match c {
            TransportCommand::List { agreement } => {
                api.get(&format!("v1/agreements/{}/transport", id(&agreement)?))
                    .await?
            }
            TransportCommand::Show { agreement, handle } => {
                api.get(&format!(
                    "v1/agreements/{}/transport/{}",
                    id(&agreement)?,
                    id(&handle)?
                ))
                .await?
            }
            TransportCommand::Import {
                agreement,
                handle,
                revision,
                idempotency_key,
            } => {
                api.post(
                    &format!(
                        "v1/agreements/{}/transport/{}/import",
                        id(&agreement)?,
                        id(&handle)?
                    ),
                    json!({}),
                    Some(revision),
                    Some(idempotency_key),
                )
                .await?
            }
        },
        Command::Sponsors(c) => match c {
            SponsorCommand::List { agreement } => {
                api.get(&format!(
                    "v1/agreements/{}/sponsor-policies",
                    id(&agreement)?
                ))
                .await?
            }
            SponsorCommand::Show { agreement, policy } => {
                api.get(&format!(
                    "v1/agreements/{}/sponsor-policies/{}",
                    id(&agreement)?,
                    id(&policy)?
                ))
                .await?
            }
            SponsorCommand::Create {
                agreement,
                file,
                revision,
                idempotency_key,
            } => {
                api.post(
                    &format!("v1/agreements/{}/sponsor-policies", id(&agreement)?),
                    read_json(&file)?,
                    Some(revision),
                    idempotency_key,
                )
                .await?
            }
            SponsorCommand::Update {
                agreement,
                policy,
                file,
                revision,
                idempotency_key,
            } => {
                api.post(
                    &format!(
                        "v1/agreements/{}/sponsor-policies/{}/versions",
                        id(&agreement)?,
                        id(&policy)?
                    ),
                    read_json(&file)?,
                    Some(revision),
                    idempotency_key,
                )
                .await?
            }
            SponsorCommand::State {
                agreement,
                policy,
                file,
                revision,
                idempotency_key,
            } => {
                api.post(
                    &format!(
                        "v1/agreements/{}/sponsor-policies/{}/state",
                        id(&agreement)?,
                        id(&policy)?
                    ),
                    read_json(&file)?,
                    Some(revision),
                    idempotency_key,
                )
                .await?
            }
            SponsorCommand::Preview {
                agreement,
                policy,
                file,
            } => {
                api.call(
                    Method::POST,
                    &format!(
                        "v1/agreements/{}/sponsor-policies/{}/preview",
                        id(&agreement)?,
                        id(&policy)?
                    ),
                    Some(read_json(&file)?),
                    None,
                    None,
                    false,
                )
                .await?
            }
        },
        Command::Cancel {
            agreement,
            revision,
            idempotency_key,
        } => {
            api.post(
                &format!("v1/agreements/{}/cancellation-requests", id(&agreement)?),
                json!({}),
                Some(revision),
                idempotency_key,
            )
            .await?
        }
        Command::Reconcile {
            agreement,
            revision,
            idempotency_key,
        } => {
            api.post(
                &format!("v1/agreements/{}/reconcile", id(&agreement)?),
                json!({}),
                Some(revision),
                idempotency_key,
            )
            .await?
        }
        Command::Recovery => api.get("v1/recovery").await?,
        Command::Accounts => api.get("v1/accounts").await?,
        Command::AccountAudit(command) => match command {
            AccountAuditCommand::List { agreement } => api.get(&format!("v1/agreements/{}/native-account-inspection-requests", id(&agreement)?)).await?,
            AccountAuditCommand::Show { agreement, request } => api.get(&format!("v1/agreements/{}/native-account-inspection-requests/{}", id(&agreement)?, id(&request)?)).await?,
            AccountAuditCommand::Request { agreement, candidate, participant, revision, idempotency_key } => {
                eprintln!("Metadata request only. Stop/drain service, then native-account-inspection-request requires separate signer review. Account-wide amounts remain unknown. Preserve the exact original key and revision on interruption.");
                api.post(&format!("v1/agreements/{}/native-account-inspection-requests", id(&agreement)?), json!({"candidate_id":id(&candidate)?,"participant_id":id(&participant)?}), Some(revision), Some(idempotency_key)).await?
            }
            AccountAuditCommand::Withdraw { agreement, request, revision, idempotency_key } => api.post(&format!("v1/agreements/{}/native-account-inspection-requests/{}/withdraw", id(&agreement)?, id(&request)?), json!({}), Some(revision), Some(idempotency_key)).await?,
        },
        Command::Authorizations => api.get("v1/authorizations").await?,
        Command::Records => api.get("v1/records").await?,
        Command::Operation { id: value } => {
            api.get(&format!("v1/operations/{}", id(&value)?)).await?
        }
        Command::Events { after, follow } => {
            api.events(after, follow, args.json).await?;
            return Ok(());
        }
    };
    print_value(value, args.json);
    Ok(())
}

#[cfg(test)]
mod command_tests {
    use super::*;
    #[test]
    fn agreement_revision_requires_explicit_journal_revision_and_retry_key() {
        let parsed = Args::try_parse_from([
            "wholepact",
            "agreements",
            "revise",
            "agreement:one",
            "revised-terms.json",
            "--revision",
            "18446744073709551615",
            "--idempotency-key",
            "synthetic-terms-revision-key-01",
        ])
        .unwrap();
        match parsed.command {
            Command::Agreements(AgreementCommand::Revise {
                agreement,
                file,
                revision,
                idempotency_key,
            }) => {
                assert_eq!(agreement, "agreement:one");
                assert_eq!(file, PathBuf::from("revised-terms.json"));
                assert_eq!(revision, u64::MAX);
                assert_eq!(idempotency_key, "synthetic-terms-revision-key-01");
            }
            _ => panic!("Expected agreement terms revision command"),
        }
        for flags in [
            vec!["--revision", "7"],
            vec!["--idempotency-key", "synthetic-terms-revision-key-01"],
        ] {
            let mut arguments = vec![
                "wholepact",
                "agreements",
                "revise",
                "agreement:one",
                "revised-terms.json",
            ];
            arguments.extend(flags);
            assert_eq!(
                Args::try_parse_from(arguments).err().unwrap().kind(),
                clap::error::ErrorKind::MissingRequiredArgument
            );
        }
    }

    #[test]
    fn events_decode_split_utf8_crlf_and_duplicate_replay() {
        let first =
            json!({"sequence": 1, "event_id":"one", "kind":"intent_recorded", "payload":"café"});
        let second = json!({"sequence": 2, "event_id":"two", "kind":"intent_withdrawn"});
        let frames = format!(": heartbeat\r\n\r\nevent: wholepact\r\ndata: {first}\r\n\r\ndata: {first}\n\ndata: {second}\n\n");
        let mut decoder = EventDecoder::new(0);
        let mut events = Vec::new();
        for byte in frames.as_bytes() {
            events.extend(decoder.push(&[*byte]).unwrap());
        }
        assert_eq!(events, vec![first, second]);
        assert_eq!(decoder.cursor, 2);
        assert!(decoder.buffer.is_empty());
        for control in ["session_expired", "service_unavailable"] {
            let mut decoder = EventDecoder::new(0);
            assert!(decoder
                .push(format!("event: {control}\ndata: {{}}\n\n").as_bytes())
                .is_err());
        }
    }
    #[test]
    fn planning_and_cached_job_commands_parse_without_narrowing_revisions() {
        let parsed = Args::try_parse_from([
            "wholepact",
            "intents",
            "select",
            "agreement:one",
            "roster.json",
            "--revision",
            "4294967297",
            "--idempotency-key",
            "synthetic-roster-key-01",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Intents(IntentCommand::Select {
                revision: 4_294_967_297,
                ..
            })
        ));
        assert!(matches!(
            Args::try_parse_from(["wholepact", "proposals", "compare", "old", "new"])
                .unwrap()
                .command,
            Command::Proposals(ProposalCommand::Compare { .. })
        ));
        assert!(matches!(
            Args::try_parse_from(["wholepact", "candidates", "proof-jobs", "candidate:one"])
                .unwrap()
                .command,
            Command::Candidates(CandidateCommand::ProofJobs { .. })
        ));
    }
}
