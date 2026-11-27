mod common;

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, Amount, Network, PublicKey};
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use common::TestNode;

/// An address no wallet of the node owns.
fn external_address(node: &TestNode) -> Address {
    let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
    let pk = PublicKey::new(secret.public_key(&Secp256k1::new()));
    node.client.get_new_address(pk, Network::Regtest).unwrap()
}

// Funding an address sends to it and mines one block, so the returned output is confirmed.
#[test]
fn fund_address_confirms_the_output() {
    let node = TestNode::start();
    let address = external_address(&node);
    let tip = node.tip();

    let (tx, vout) = node
        .client
        .fund_address(&address, Amount::from_sat(50_000))
        .unwrap();

    assert_eq!(node.tip(), tip + 1);
    let output = &tx.output[vout as usize];
    assert_eq!(output.value, Amount::from_sat(50_000));
    assert_eq!(output.script_pubkey, address.script_pubkey());
    assert_eq!(
        node.client
            .get_tx_confirmations(&tx.compute_txid())
            .unwrap(),
        Some(1)
    );
}

// Each mining method adds its blocks to the tip. An empty block leaves the mempool alone, and takes its time from the
// mock clock when one is set (0 goes back to the real clock).
#[test]
fn mining_extends_the_chain() {
    let node = TestNode::start();
    let client = &node.client;
    let address = external_address(&node);
    let tip = node.tip();

    client.mine_blocks(3).unwrap();
    assert_eq!(node.tip(), tip + 3);

    client.mine_blocks_to_address(2, &address).unwrap();
    assert_eq!(node.tip(), tip + 5);
    let block = client.get_block_by_height(&node.tip()).unwrap().unwrap();
    assert_eq!(
        block.txs[0].output[0].script_pubkey,
        address.script_pubkey()
    );

    let (txid, _) = node.send(50_000);
    let time = client.get_block_by_hash(&block.hash).unwrap().header.time as i64 + 86_400;
    client.set_mock_time(time).unwrap();
    let hash = client.mine_empty_block(&address).unwrap();
    let empty = client.get_block_by_hash(&hash).unwrap();
    assert_eq!(empty.txdata.len(), 1);
    assert_eq!(empty.header.time as i64, time);
    assert!(client.check_in_mempool(&txid).unwrap());
    client.set_mock_time(0).unwrap();
}

// Initializing an existing wallet only hands out a new address. A second wallet is reachable through its own URL.
#[test]
fn wallets_are_created_once() {
    let node = TestNode::start();
    let client = &node.client;
    let wallet = &node.rpc_config.wallet;
    assert!(client.get_balance().unwrap() > Amount::ZERO);
    assert_ne!(
        client.init_wallet(wallet).unwrap(),
        client.init_wallet(wallet).unwrap()
    );

    client.create_wallet_only("second_wallet").unwrap();
    client.create_wallet_only("second_wallet").unwrap();
    let mut wallets = client.list_wallets().unwrap();
    wallets.sort();
    assert_eq!(wallets, vec!["second_wallet".to_string(), wallet.clone()]);

    let config = &node.rpc_config;
    let second = BitcoinClient::new_with_wallet(
        &config.url,
        &config.username,
        &config.password,
        "second_wallet",
    )
    .unwrap();
    second.get_wallet_address().unwrap();
    assert_eq!(second.get_balance().unwrap(), Amount::ZERO);
}
