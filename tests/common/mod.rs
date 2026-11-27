#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, OutPoint, Transaction, Txid};
use bitcoind::{bitcoind::Bitcoind, config::BitcoindConfig};
use bitvmx_bitcoin_rpc::{
    bitcoin_client::{BitcoinClient, BitcoinClientApi},
    rpc_config::RpcConfig,
    types::BlockHeight,
};
use serde_json::json;

/// Blocks mined at start. Coinbase outputs need 100 confirmations to be spendable, so 101 leaves one mature coinbase.
pub const START_BLOCKS: u64 = 101;

/// Only one regtest container can run at a time, because the container name and the RPC port are fixed.
static NODE_LOCK: Mutex<()> = Mutex::new(());

/// A fresh regtest bitcoind in Docker with a funded wallet. The container is stopped when this value is dropped.
pub struct TestNode {
    pub rpc_config: RpcConfig,
    pub client: BitcoinClient,
    bitcoind: Bitcoind,
    _guard: MutexGuard<'static, ()>,
}

impl TestNode {
    /// Starts the node, creates its wallet and mines `START_BLOCKS` blocks to it.
    pub fn start() -> Self {
        let _guard = NODE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let config = json!({
            "network": "regtest",
            "url": "http://127.0.0.1:18443",
            "username": "foo",
            "password": "rpcpassword",
            "wallet": "test_wallet",
        });
        let rpc_config: RpcConfig = serde_json::from_value(config.clone()).unwrap();

        // Bitcoind takes the RpcConfig of the bitvmx-bitcoin-rpc copy it depends on.
        let bitcoind = Bitcoind::new(
            BitcoindConfig::default(),
            serde_json::from_value(config).unwrap(),
            None,
        );
        bitcoind
            .start()
            .expect("failed to start bitcoind, make sure Docker is running");

        let client = BitcoinClient::new_from_config(&rpc_config).unwrap();
        let miner = client.init_wallet(&rpc_config.wallet).unwrap();
        client.mine_blocks_to_address(START_BLOCKS, &miner).unwrap();

        Self {
            rpc_config,
            client,
            bitcoind,
            _guard,
        }
    }

    pub fn tip(&self) -> BlockHeight {
        self.client.get_tip_height().unwrap()
    }

    /// New address from the node's wallet.
    pub fn address(&self) -> Address {
        self.client.get_wallet_address().unwrap()
    }

    /// Mines `blocks` blocks to the wallet. They include whatever is in the mempool.
    pub fn mine(&self, blocks: u64) {
        self.client
            .mine_blocks_to_address(blocks, &self.address())
            .unwrap();
    }

    /// Sends `sats` to a wallet address and leaves the transaction in the mempool. Returns the txid and the output index.
    pub fn send(&self, sats: u64) -> (Txid, u32) {
        let address = self.address();
        let txid = self
            .client
            .send_to_address(&address, Amount::from_sat(sats))
            .unwrap();
        let tx = self.client.get_transaction(&txid).unwrap().unwrap();
        let vout = tx
            .output
            .iter()
            .position(|out| out.script_pubkey == address.script_pubkey())
            .unwrap();
        (txid, vout as u32)
    }

    /// Confirms a new output of `sats` to the wallet and locks it, so the wallet does not spend it by itself.
    pub fn fund_utxo(&self, sats: u64) -> OutPoint {
        let (tx, vout) = self
            .client
            .fund_address(&self.address(), Amount::from_sat(sats))
            .unwrap();
        let outpoint = OutPoint::new(tx.compute_txid(), vout);
        self.client.lock_unspent(&outpoint).unwrap();
        outpoint
    }

    /// A signed, not broadcast transaction spending `outpoint` into one output of `sats` to the wallet.
    pub fn spend(&self, outpoint: OutPoint, sats: u64) -> Transaction {
        let outputs = HashMap::from([(self.address().to_string(), Amount::from_sat(sats))]);
        self.client.sign_spend(&[outpoint], &outputs, &[]).unwrap()
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        let _ = self.bitcoind.stop();
    }
}

/// A txid no node knows.
pub fn unknown_txid() -> Txid {
    Txid::from_byte_array([0x11; 32])
}
