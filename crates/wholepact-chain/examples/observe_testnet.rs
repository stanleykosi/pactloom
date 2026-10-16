//! Public read-only observation only; no wallets, keys, note selection or broadcast.
use wholepact_chain::{ChainAdapter, NetworkPolicy};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://testnet.zec.rocks:443".into());
    let adapter = ChainAdapter::testnet(
        "configured-public-testnet",
        &endpoint,
        NetworkPolicy::default(),
    )?;
    let context = adapter.context().await?;
    let height = context.tip().height;
    let anchor = adapter.ironwood_anchor(&context, height).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "context": context,
            "ironwood_anchor": anchor,
            "wallet_or_transaction_queries_performed": false,
            "signing_or_submission_performed": false,
        }))?
    );
    Ok(())
}
