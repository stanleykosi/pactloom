//! Data-only codec regression using never-funded maintained scanned notes.
//! No network/IPC/native approval or authenticated capture is constructed.
use super::*;
use orchard::keys::Scope;
use sha2::{Digest, Sha256};
use wholepact_wallet::wallet::{
    WalletContribution, protected_sync::durable_construction_v1::HistoricalConstructionMaterialV1,
    synthetic_born_receiver_blocks_v1::SyntheticBornChainSpecV1,
};

fn mathematical_material(owner: &WalletContribution, info: &LightdInfo) -> serde_json::Value {
    let context = owner.context();
    let notes = owner.notes().iter().map(|selected| {
        // Preserve the maintained public outpoint convention. The production
        // decoder independently checks this exact display/protocol-order join.
        let mut fields = selected.input_id.split(':');
        assert!(fields.next() == Some("ironwood"));
        let mut txid = hex::decode(fields.next().expect("fixture txid")).unwrap();
        txid.reverse();
        let index: u16 = fields.next().expect("fixture index").parse().unwrap();
        assert!(fields.next().is_none());
        serde_json::json!({
            "input_id": selected.input_id,
            "txid_protocol": hex::encode(txid),
            "output_index": index,
            "recipient": hex::encode(selected.note.recipient().to_raw_address_bytes()),
            "value_zatoshis": selected.note.value().inner(),
            "rho": hex::encode(selected.note.rho().to_bytes()),
            "rseed": hex::encode(selected.note.rseed().as_bytes()),
            "nullifier": hex::encode(selected.note.nullifier(owner.fvk()).to_bytes()),
            "commitment": hex::encode(orchard::note::ExtractedNoteCommitment::from(selected.note.commitment()).to_bytes()),
            "position": selected.witness.position(),
            "authentication_path": selected.witness.auth_path().iter().map(|p| hex::encode(p.to_bytes())).collect::<Vec<_>>()
        })
    }).collect::<Vec<_>>();
    serde_json::json!({
        "version": 1,
        "account_id": wholepact_protocol::durable_proposal_v1::canonical_durable_account_id(owner.fvk()),
        "fvk_hex": hex::encode(owner.fvk().to_bytes()),
        "fvk_digest": hex::encode(Sha256::digest(owner.fvk().to_bytes())),
        "selected_zatoshis": owner.selected_zatoshis(),
        "requested_debit_zatoshis": owner.requested_debit_zatoshis(),
        "change_address": hex::encode(owner.change_address().to_raw_address_bytes()),
        "birthday_height": context.anchor_height,
        "context": {
            "tip_height": context.tip_height,
            "tip_hash_protocol": hex::encode(context.tip_hash_protocol),
            "anchor_height": context.anchor_height,
            "anchor_hash_protocol": hex::encode(context.anchor_hash_protocol),
            "anchor_root": hex::encode(context.anchor_root)
        },
        // Inert metadata expectations, not a fabricated ChainContext or source
        // permit. Only the actual downstream mathematical decoder is exercised.
        "source": {
            "source_id": "synthetic-durable-public-blocks",
            "endpoint": "https://component.invalid",
            "trust_profile": "single_tls_provider_report_not_consensus",
            "network": info.chain_name,
            "branch_id": format!("0x{}", info.consensus_branch_id),
            "lightwalletd_version": info.version,
            "backend_subversion": info.zcashd_subversion,
            "protocol_version": info.protocol_version,
            "request_started": 1_800_000_000u64,
            "observed_at": 1_800_000_001u64,
            "valid_until": 1_800_000_060u64
        },
        "notes": notes
    })
}

#[test]
fn durable_provider_metadata_satisfies_actual_material_decoder() {
    let (owners, _) = wholepact_wallet::wallet::synthetic_scanned_contributions().unwrap();
    let receivers = owners
        .iter()
        .map(|owner| {
            wholepact_protocol::review::encode_testnet_receiver(
                &owner.fvk().address_at(0u32, Scope::External),
            )
        })
        .collect::<Vec<_>>();
    let blocks = SyntheticBornReceiverBlocksV1::build(
        [&receivers[0], &receivers[1]],
        [155_000, 155_000],
        SyntheticBornChainSpecV1 {
            prior_height: 4_465_050,
            prior_hash_protocol: [73; 32],
            block_count: 1,
            timestamp: 1_800_000_000,
        },
    )
    .unwrap();
    let response = reply(&blocks, "GetLightdInfo", &Empty {}.encode_to_vec()).unwrap();
    assert!(response.len() >= 5 && response[0] == 0);
    let length = u32::from_be_bytes(response[1..5].try_into().unwrap()) as usize;
    assert!(response.len() == length + 5);
    let info: LightdInfo = exact(&response[5..]).unwrap();
    assert!(info.version == "synthetic-born-provider-v1");
    assert!(info.zcashd_subversion == "synthetic-no-zcashd-backend");
    assert!(info.protocol_version == "synthetic-compact-rpc-v1");
    assert!(info.chain_name == "test");
    assert!(info.sapling_activation_height == 280_000);
    assert!(info.consensus_branch_id == "77190ad9");
    assert!(info.block_height == blocks.blocks().last().unwrap().height);
    assert!(info.estimated_height == info.block_height);

    let original = mathematical_material(&owners[0], &info);
    let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&original).unwrap());
    assert!(HistoricalConstructionMaterialV1::decode(&encoded).is_ok());
    for field in [
        "lightwalletd_version",
        "backend_subversion",
        "protocol_version",
    ] {
        for rejected in [String::new(), "synthetic\ncontrol".into(), "x".repeat(2049)] {
            let mut changed = original.clone();
            changed["source"][field] = rejected.into();
            let encoded = zeroize::Zeroizing::new(serde_json::to_vec(&changed).unwrap());
            assert!(HistoricalConstructionMaterialV1::decode(&encoded).is_err());
        }
    }
}
