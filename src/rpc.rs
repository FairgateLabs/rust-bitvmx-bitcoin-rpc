//! Typed wrappers over the Bitcoin Core JSON-RPC calls this crate makes.
//!
//! This is the only module that writes RPC method names and JSON arguments. Each method sends one request through the
//! `jsonrpc` client and turns the answer into a `corepc-types` model type or a plain `bitcoin` type.

use std::time::Duration;

use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Address, Amount, Block, BlockHash, Transaction, Txid};
use corepc_types::model;
use corepc_types::v29 as node;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::errors::{invalid_response, BitcoinClientError};
use crate::reqwest_https::ReqwestHttpsTransport;

const TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) struct Rpc {
    client: jsonrpc::Client,
}

impl std::fmt::Debug for Rpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The URL can carry an API key, so it is not printed.
        f.write_str("Rpc")
    }
}

impl Rpc {
    // ================================
    //  Client
    // ================================

    /// Connects to `url` over HTTP or HTTPS. `auth` is the basic auth user and optional password, if any.
    pub fn new(
        url: &str,
        auth: Option<(String, Option<String>)>,
    ) -> Result<Self, BitcoinClientError> {
        let mut builder = ReqwestHttpsTransport::builder().url(url)?.timeout(TIMEOUT);
        if let Some((user, pass)) = auth {
            builder = builder.basic_auth(user, pass);
        }
        Ok(Self {
            client: jsonrpc::Client::with_transport(builder.build()),
        })
    }

    /// Sends `method` with positional `args` and deserializes the `result` field of the answer.
    pub fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        args: &[Value],
    ) -> Result<T, BitcoinClientError> {
        let raw = serde_json::value::to_raw_value(args).map_err(jsonrpc::Error::Json)?;
        Ok(self.client.call(method, Some(&raw))?)
    }

    // ================================
    //  Transactions
    // ================================

    /// Decoded transaction with its block data, from `getrawtransaction` verbose.
    pub fn get_raw_transaction_info(
        &self,
        txid: &Txid,
    ) -> Result<model::GetRawTransactionVerbose, BitcoinClientError> {
        let raw: node::GetRawTransactionVerbose =
            self.call("getrawtransaction", &[json!(txid), json!(true)])?;
        raw.into_model().map_err(invalid_response)
    }

    /// Transaction `txid` from the mempool or the transaction index.
    pub fn get_raw_transaction(&self, txid: &Txid) -> Result<Transaction, BitcoinClientError> {
        let raw: node::GetRawTransaction =
            self.call("getrawtransaction", &[json!(txid), json!(false)])?;
        Ok(raw.into_model().map_err(invalid_response)?.0)
    }

    /// Verbosity 2 answer (Bitcoin Core 25.0 or later), returned as untyped JSON.
    pub fn get_raw_transaction_verbosity_two(
        &self,
        txid: &Txid,
    ) -> Result<Value, BitcoinClientError> {
        self.call("getrawtransaction", &[json!(txid), json!(2), Value::Null])
    }

    /// Broadcasts `tx` and returns its txid.
    pub fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, BitcoinClientError> {
        let raw: node::SendRawTransaction =
            self.call("sendrawtransaction", &[json!(serialize_hex(tx))])?;
        Ok(raw.into_model().map_err(invalid_response)?.0)
    }

    /// Unspent output `txid:vout`, or None when it is not in the UTXO set.
    pub fn get_tx_out(
        &self,
        txid: &Txid,
        vout: u32,
        include_mempool: bool,
    ) -> Result<Option<model::GetTxOut>, BitcoinClientError> {
        let raw: Option<node::GetTxOut> = self.call(
            "gettxout",
            &[json!(txid), json!(vout), json!(include_mempool)],
        )?;
        raw.map(|raw| raw.into_model().map_err(invalid_response))
            .transpose()
    }

    // ================================
    //  Mempool
    // ================================

    /// Mempool data for `txid`.
    pub fn get_mempool_entry(
        &self,
        txid: &Txid,
    ) -> Result<model::GetMempoolEntry, BitcoinClientError> {
        let raw: node::GetMempoolEntry = self.call("getmempoolentry", &[json!(txid)])?;
        raw.into_model().map_err(invalid_response)
    }

    /// Txids of every transaction in the mempool.
    pub fn get_raw_mempool(&self) -> Result<Vec<Txid>, BitcoinClientError> {
        let raw: node::GetRawMempool = self.call("getrawmempool", &[])?;
        Ok(raw.into_model().map_err(invalid_response)?.0)
    }

    /// Conservative fee rate estimate to confirm within `conf_target` blocks.
    pub fn estimate_smart_fee(
        &self,
        conf_target: u32,
    ) -> Result<model::EstimateSmartFee, BitcoinClientError> {
        let raw: node::EstimateSmartFee = self.call(
            "estimatesmartfee",
            &[json!(conf_target), json!("CONSERVATIVE")],
        )?;
        raw.into_model().map_err(invalid_response)
    }

    // ================================
    //  Chain
    // ================================

    /// Chain name, height and sync state.
    pub fn get_blockchain_info(&self) -> Result<model::GetBlockchainInfo, BitcoinClientError> {
        let raw: node::GetBlockchainInfo = self.call("getblockchaininfo", &[])?;
        raw.into_model().map_err(invalid_response)
    }

    /// Height of the chain tip.
    pub fn get_block_count(&self) -> Result<u64, BitcoinClientError> {
        self.call("getblockcount", &[])
    }

    /// Hash of the block at `height` in the active chain.
    pub fn get_block_hash(&self, height: u64) -> Result<BlockHash, BitcoinClientError> {
        let raw: node::GetBlockHash = self.call("getblockhash", &[json!(height)])?;
        Ok(raw.into_model().map_err(invalid_response)?.0)
    }

    /// Full block `hash`.
    pub fn get_block(&self, hash: &BlockHash) -> Result<Block, BitcoinClientError> {
        let raw: node::GetBlockVerboseZero = self.call("getblock", &[json!(hash), json!(0)])?;
        Ok(raw.into_model().map_err(invalid_response)?.0)
    }

    /// Decoded header of block `hash`, with its height and confirmations.
    pub fn get_block_header_info(
        &self,
        hash: &BlockHash,
    ) -> Result<model::GetBlockHeaderVerbose, BitcoinClientError> {
        let raw: node::GetBlockHeaderVerbose =
            self.call("getblockheader", &[json!(hash), json!(true)])?;
        raw.into_model().map_err(invalid_response)
    }

    /// Marks block `hash` as invalid, so the node reorgs away from it.
    pub fn invalidate_block(&self, hash: &BlockHash) -> Result<(), BitcoinClientError> {
        let _: Value = self.call("invalidateblock", &[json!(hash)])?;
        Ok(())
    }

    /// Untyped `getindexinfo` answer: an empty object when no index is active.
    pub fn get_index_info(&self) -> Result<Value, BitcoinClientError> {
        self.call("getindexinfo", &[])
    }

    // ================================
    //  Wallet
    // ================================

    /// Sends `amount` from the loaded wallet to `address`.
    pub fn send_to_address(
        &self,
        address: &Address,
        amount: Amount,
    ) -> Result<Txid, BitcoinClientError> {
        let raw: node::SendToAddress = self.call(
            "sendtoaddress",
            &[json!(address.to_string()), json!(amount.to_btc())],
        )?;
        Ok(raw.into_model().map_err(invalid_response)?.txid)
    }

    /// Wallet view of a transaction, including watch-only details.
    pub fn get_transaction(
        &self,
        txid: &Txid,
    ) -> Result<model::GetTransaction, BitcoinClientError> {
        let raw: node::GetTransaction = self.call("gettransaction", &[json!(txid), json!(true)])?;
        raw.into_model().map_err(invalid_response)
    }

    /// Mines `blocks` blocks paying to `address`.
    pub fn generate_to_address(
        &self,
        blocks: u64,
        address: &Address,
    ) -> Result<Vec<BlockHash>, BitcoinClientError> {
        let raw: node::GenerateToAddress = self.call(
            "generatetoaddress",
            &[json!(blocks), json!(address.to_string())],
        )?;
        Ok(raw.into_model().map_err(invalid_response)?.0)
    }

    /// Names of the loaded wallets.
    pub fn list_wallets(&self) -> Result<Vec<String>, BitcoinClientError> {
        self.call("listwallets", &[])
    }

    /// Creates and loads the wallet `name`.
    pub fn create_wallet(&self, name: &str) -> Result<(), BitcoinClientError> {
        let _: Value = self.call("createwallet", &[json!(name)])?;
        Ok(())
    }

    /// New address from the loaded wallet, of the node's default type.
    pub fn get_new_address(&self) -> Result<Address<NetworkUnchecked>, BitcoinClientError> {
        let raw: node::GetNewAddress = self.call("getnewaddress", &[])?;
        Ok(raw.into_model().map_err(invalid_response)?.0)
    }
}

// ================================
//  Testing
// ================================

#[cfg(feature = "testing")]
impl Rpc {
    /// Balance of the loaded wallet.
    pub fn get_balance(&self) -> Result<Amount, BitcoinClientError> {
        let raw: node::GetBalance = self.call("getbalance", &[])?;
        Ok(raw.into_model().map_err(invalid_response)?.0)
    }

    /// Private key of a legacy wallet `address`.
    pub fn dump_private_key(
        &self,
        address: &Address,
    ) -> Result<bitcoin::PrivateKey, BitcoinClientError> {
        let raw: node::DumpPrivKey = self.call("dumpprivkey", &[json!(address.to_string())])?;
        Ok(raw.into_model().map_err(invalid_response)?.0)
    }

    /// Mines one block to `address` holding exactly `txs` plus the coinbase.
    pub fn generate_block(
        &self,
        address: &Address,
        txs: &[Transaction],
    ) -> Result<BlockHash, BitcoinClientError> {
        let raw_txs: Vec<String> = txs.iter().map(serialize_hex).collect();
        let raw: node::GenerateBlock = self.call(
            "generateblock",
            &[json!(address.to_string()), json!(raw_txs)],
        )?;
        Ok(raw.into_model().map_err(invalid_response)?.hash)
    }

    /// Sets the node's clock to `timestamp` (0 goes back to the real clock).
    pub fn set_mock_time(&self, timestamp: i64) -> Result<(), BitcoinClientError> {
        let _: Value = self.call("setmocktime", &[json!(timestamp)])?;
        Ok(())
    }

    /// Undoes `invalidate_block` for block `hash`.
    pub fn reconsider_block(&self, hash: &BlockHash) -> Result<(), BitcoinClientError> {
        let _: Value = self.call("reconsiderblock", &[json!(hash)])?;
        Ok(())
    }

    /// Locks (`unlock` false) or unlocks (`unlock` true) wallet outputs. An empty list with `unlock` true unlocks all.
    pub fn lock_unspent(
        &self,
        unlock: bool,
        outpoints: &[bitcoin::OutPoint],
    ) -> Result<bool, BitcoinClientError> {
        let outpoints: Vec<Value> = outpoints
            .iter()
            .map(|outpoint| json!({ "txid": outpoint.txid, "vout": outpoint.vout }))
            .collect();
        let mut args = vec![json!(unlock)];
        if !outpoints.is_empty() {
            args.push(json!(outpoints));
        }
        self.call("lockunspent", &args)
    }

    /// Hash of the chain tip.
    pub fn get_best_block_hash(&self) -> Result<BlockHash, BitcoinClientError> {
        let raw: node::GetBestBlockHash = self.call("getbestblockhash", &[])?;
        Ok(raw.into_model().map_err(invalid_response)?.0)
    }

    /// Makes miners treat `txid` as paying `fee_delta_sats` more (or less) fee.
    pub fn prioritise_transaction(
        &self,
        txid: &Txid,
        fee_delta_sats: i64,
    ) -> Result<bool, BitcoinClientError> {
        // The second argument is a deprecated priority delta that must be 0.
        self.call(
            "prioritisetransaction",
            &[json!(txid), json!(0), json!(fee_delta_sats)],
        )
    }

    /// Unsigned transaction spending `inputs` into `outputs` (address to amount).
    pub fn create_raw_transaction(
        &self,
        inputs: &[bitcoin::OutPoint],
        outputs: &std::collections::HashMap<String, Amount>,
    ) -> Result<Transaction, BitcoinClientError> {
        let inputs: Vec<Value> = inputs
            .iter()
            .map(|outpoint| json!({ "txid": outpoint.txid, "vout": outpoint.vout }))
            .collect();
        let outputs: serde_json::Map<String, Value> = outputs
            .iter()
            .map(|(address, amount)| (address.clone(), json!(amount.to_btc())))
            .collect();
        let raw: node::CreateRawTransaction =
            self.call("createrawtransaction", &[json!(inputs), json!(outputs)])?;
        Ok(raw.into_model().map_err(invalid_response)?.0)
    }

    /// Signs `tx` with the loaded wallet. `prevouts` describes inputs the wallet cannot find by itself.
    pub fn sign_raw_transaction_with_wallet(
        &self,
        tx: &Transaction,
        prevouts: &[(bitcoin::OutPoint, bitcoin::TxOut)],
    ) -> Result<model::SignRawTransaction, BitcoinClientError> {
        let mut args = vec![json!(serialize_hex(tx))];
        if !prevouts.is_empty() {
            let prevouts: Vec<Value> = prevouts
                .iter()
                .map(|(outpoint, txout)| {
                    json!({
                        "txid": outpoint.txid,
                        "vout": outpoint.vout,
                        "scriptPubKey": txout.script_pubkey.to_hex_string(),
                        "amount": txout.value.to_btc(),
                    })
                })
                .collect();
            args.push(json!(prevouts));
        }
        let raw: node::SignRawTransactionWithWallet =
            self.call("signrawtransactionwithwallet", &args)?;
        raw.into_model().map_err(invalid_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_node_is_reported_as_unreachable() {
        // Port 0 never accepts connections.
        let rpc = Rpc::new("http://127.0.0.1:0", None).unwrap();
        let error = rpc.get_block_count().unwrap_err();
        assert!(error.is_node_unreachable(), "got {error:?}");
    }

    #[test]
    fn debug_does_not_print_the_url() {
        let rpc = Rpc::new("https://node.example/secret-key", None).unwrap();
        assert_eq!(format!("{rpc:?}"), "Rpc");
    }
}
