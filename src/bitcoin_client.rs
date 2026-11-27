use std::str::FromStr;

use crate::errors::BitcoinClientError;
use crate::rpc::Rpc;
use crate::rpc_config::{mask_url_secrets, RpcConfig};
use crate::types::{BlockHeight, BlockInfo};
use bitcoin::{
    Address, Amount, Block, BlockHash, CompressedPublicKey, Network, PublicKey, Transaction, Txid,
};
use corepc_types::model::{
    GetBlockHeaderVerbose, GetBlockchainInfo, GetMempoolEntry, GetRawTransactionVerbose, GetTxOut,
};
use mockall::automock;
use redact::Secret;
use tracing::{debug, error, info, warn};

#[derive(Debug)]
pub struct BitcoinClient {
    client: Rpc,
}

impl BitcoinClient {
    /// Connects to the node at `url`. Empty `user` or `pass` means no credentials are sent.
    pub fn new(
        url: &Secret<String>,
        user: &Secret<String>,
        pass: &Secret<String>,
    ) -> Result<Self, BitcoinClientError> {
        let pass = match pass.expose_secret().is_empty() {
            true => None,
            false => Some(pass),
        };

        let auth = (!user.expose_secret().is_empty()).then(|| {
            (
                user.expose_secret().to_owned(),
                pass.map(|p| p.expose_secret().to_owned()),
            )
        });
        let client = Rpc::new(url.expose_secret(), auth)?;

        info!(
            "[BitcoinClient] Initialized for url: {}",
            mask_url_secrets(url.expose_secret())
        );

        Ok(Self { client })
    }

    /// Connects using the url and credentials of `config`.
    pub fn new_from_config(config: &RpcConfig) -> Result<Self, BitcoinClientError> {
        Self::new(&config.url, &config.username, &config.password)
    }

    /// Connects to the wallet `wallet_name` of the node. An empty name connects to the node itself.
    pub fn new_with_wallet(
        url: &Secret<String>,
        user: &Secret<String>,
        pass: &Secret<String>,
        wallet_name: &str,
    ) -> Result<Self, BitcoinClientError> {
        let url = if !wallet_name.is_empty() {
            if !wallet_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(BitcoinClientError::InvalidWalletName {
                    wallet_name: wallet_name.to_string(),
                });
            }

            format!("{}/wallet/{}", url.expose_secret(), wallet_name)
        } else {
            url.expose_secret().to_string()
        };

        Self::new(&Secret::new(url), user, pass)
    }
}

#[automock]
pub trait BitcoinClientApi {
    // ================================
    //  Chain
    // ================================

    /// Height of the chain tip.
    fn get_tip_height(&self) -> Result<BlockHeight, BitcoinClientError>;

    /// Block at `height` in the active chain, with its hash and the hash of its parent.
    fn get_block_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<BlockInfo>, BitcoinClientError>;

    /// Hash of the block at `height` in the active chain.
    fn get_block_id_by_height(&self, height: &BlockHeight)
        -> Result<BlockHash, BitcoinClientError>;

    /// Full block `hash`.
    fn get_block_by_hash(&self, hash: &BlockHash) -> Result<Block, BitcoinClientError>;

    /// Header of the block with this hash, via `getblockheader`: its height and confirmations among other fields,
    /// without downloading the block.
    fn get_block_header_info(
        &self,
        hash: &BlockHash,
    ) -> Result<GetBlockHeaderVerbose, BitcoinClientError>;

    /// Chain name, height and sync state.
    fn get_blockchain_info(&self) -> Result<GetBlockchainInfo, BitcoinClientError>;

    /// True iff the node has the transaction index (`-txindex`) enabled, via `getindexinfo`.
    fn is_txindex_enabled(&self) -> Result<bool, BitcoinClientError>;

    /// Marks block `hash` as invalid so the node reorgs away from it. Regtest only.
    fn invalidate_block(&self, hash: &BlockHash) -> Result<(), BitcoinClientError>;

    // ================================
    //  Transactions
    // ================================

    /// True if the node knows the transaction, in the mempool or through the transaction index.
    fn tx_exists(&self, tx_id: &Txid) -> bool;

    /// Transaction `txid`, or `None` when the node cannot return it.
    fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, BitcoinClientError>;

    /// Verbose `getrawtransaction`. `None` when the node does not know the transaction. Any other failure is returned as an error.
    fn get_raw_transaction_info(
        &self,
        tx_id: &Txid,
    ) -> Result<Option<GetRawTransactionVerbose>, BitcoinClientError>;

    /// Verbosity 2 `getrawtransaction` (Bitcoin Core 25.0 or later), returned as untyped JSON.
    fn get_raw_transaction_verbosity_two(
        &self,
        tx_id: &Txid,
    ) -> Result<serde_json::Value, BitcoinClientError>;

    /// Live `getrawtransaction` confirmation probe (requires `-txindex`). Returns:
    /// - `None` => the tx is neither in the mempool nor in the active chain. This covers a tx the node does not
    ///   know, and a tx the txindex still finds in a block a reorg disconnected (stale `blockhash`),
    /// - `Some(0)` => in the mempool, unconfirmed,
    /// - `Some(n>=1)` => confirmed in the active chain with `n` confirmations.
    ///
    /// Any failure other than the node answering "not found" is returned as an error, so an unreachable node is never
    /// mistaken for a dropped tx.
    fn get_tx_confirmations(&self, tx_id: &Txid) -> Result<Option<u32>, BitcoinClientError>;

    /// Confirmed unspent output `txid:vout`. An error when it is not in the chain UTXO set.
    fn get_tx_out(&self, txid: &Txid, vout: u32) -> Result<GetTxOut, BitcoinClientError>;

    /// Real-time `gettxout` check. Returns true iff the output is not in the node's UTXO set. With `include_mempool`
    /// true that set is the mempool view (spends in the mempool count, outputs created in the mempool exist), with it
    /// false only the chain UTXO set is consulted.
    ///
    /// "Not in the UTXO set" is wider than "spent". It is also true for an output that never existed (unknown txid or
    /// vout out of range), for one whose creating tx was dropped or orphaned by a reorg, and, with `include_mempool`
    /// false, for one whose creating tx is still unconfirmed. A caller that needs to tell these apart must check the
    /// creating tx itself.
    fn is_utxo_spent(
        &self,
        txid: &Txid,
        vout: u32,
        include_mempool: bool,
    ) -> Result<bool, BitcoinClientError>;

    /// Broadcasts `tx` and returns its txid.
    fn send_transaction(&self, tx: &Transaction) -> Result<Txid, BitcoinClientError>;

    // ================================
    //  Mempool
    // ================================

    /// Conservative fee rate in sat/vB to confirm in the next block. Falls back to 1 sat/vB when the node has no
    /// estimate.
    fn estimate_smart_fee(&self) -> Result<u64, BitcoinClientError>;

    /// Mempool entry for `txid`, or `None` when the transaction is not in the mempool. Any other failure (transport,
    /// RPC or parsing) is returned as an error.
    fn get_mempool_entry(&self, txid: &Txid)
        -> Result<Option<GetMempoolEntry>, BitcoinClientError>;

    /// Txids of every transaction in the mempool.
    fn get_raw_mempool(&self) -> Result<Vec<Txid>, BitcoinClientError>;

    /// True if the transaction is in the mempool. Any failure other than "not in the mempool" is returned as an error.
    fn check_in_mempool(&self, txid: &Txid) -> Result<bool, BitcoinClientError>;

    // ================================
    //  Wallet and mining
    // ================================

    /// Sends `amount` to `address` from the loaded wallet and mines one block. Returns the funding tx and the output
    /// index. Regtest only.
    fn fund_address(
        &self,
        address: &Address,
        amount: Amount,
    ) -> Result<(Transaction, u32), BitcoinClientError>;

    /// Mines `block_num` blocks to an address no wallet owns, so no balance changes. Regtest only.
    fn mine_blocks(&self, block_num: u64) -> Result<(), BitcoinClientError>;

    /// Mines `block_num` blocks paying to `address`. Regtest only.
    fn mine_blocks_to_address(
        &self,
        block_num: u64,
        address: &Address,
    ) -> Result<(), BitcoinClientError>;

    /// P2WPKH address of `pk` on `network`. Computed locally, the node is not called.
    fn get_new_address(
        &self,
        pk: PublicKey,
        network: Network,
    ) -> Result<Address, BitcoinClientError>;

    /// Creates the wallet `wallet_name` if it does not exist and returns a new address from it.
    fn init_wallet(&self, wallet_name: &str) -> Result<Address, BitcoinClientError>;

    /// Creates the wallet `wallet_name` if it does not exist.
    fn create_wallet_only(&self, wallet_name: &str) -> Result<(), BitcoinClientError>;

    // ================================
    //  Testing
    // ================================

    /// Height of the chain tip, as the node reports it.
    #[cfg(feature = "testing")]
    fn get_block_count(&self) -> Result<u64, BitcoinClientError>;

    /// Balance of the loaded wallet.
    #[cfg(feature = "testing")]
    fn get_balance(&self) -> Result<Amount, BitcoinClientError>;

    /// Names of the loaded wallets.
    #[cfg(feature = "testing")]
    fn list_wallets(&self) -> Result<Vec<String>, BitcoinClientError>;

    /// Private key of a legacy wallet `address`, in WIF.
    #[cfg(feature = "testing")]
    fn dump_privkey(&self, address: &Address) -> Result<String, BitcoinClientError>;

    /// Mines a single block to `address` containing no mempool transactions.
    #[cfg(feature = "testing")]
    fn mine_empty_block(&self, address: &Address) -> Result<BlockHash, BitcoinClientError>;

    /// Mines a block to `address` containing exactly `txs` plus the coinbase.
    #[cfg(feature = "testing")]
    fn generate_block_with_txs(
        &self,
        address: &Address,
        txs: &[Transaction],
    ) -> Result<BlockHash, BitcoinClientError>;

    /// Sets the node's mock clock (`setmocktime`).
    #[cfg(feature = "testing")]
    fn set_mock_time(&self, timestamp: i64) -> Result<(), BitcoinClientError>;

    /// Sends `amount` to `address` from the loaded wallet. Returns the txid.
    #[cfg(feature = "testing")]
    fn send_to_address(
        &self,
        address: &Address,
        amount: Amount,
    ) -> Result<Txid, BitcoinClientError>;

    /// Undoes `invalidate_block`, letting the node consider the block for the active chain again.
    #[cfg(feature = "testing")]
    fn reconsider_block(&self, hash: &BlockHash) -> Result<(), BitcoinClientError>;

    /// Locks a wallet output so the wallet does not spend it.
    #[cfg(feature = "testing")]
    fn lock_unspent(&self, outpoint: &bitcoin::OutPoint) -> Result<(), BitcoinClientError>;

    /// Unlocks every wallet output locked with `lock_unspent`.
    #[cfg(feature = "testing")]
    fn unlock_unspent_all(&self) -> Result<(), BitcoinClientError>;

    /// New address from the loaded wallet, checked against the node's network.
    #[cfg(feature = "testing")]
    fn get_wallet_address(&self) -> Result<Address, BitcoinClientError>;

    /// Hash of the chain tip.
    #[cfg(feature = "testing")]
    fn get_best_block_hash(&self) -> Result<BlockHash, BitcoinClientError>;

    /// Raises the fee the node's mempool counts for `txid` by `fee_delta_sats`, without changing the transaction.
    #[cfg(feature = "testing")]
    fn prioritise_transaction(
        &self,
        txid: &Txid,
        fee_delta_sats: i64,
    ) -> Result<(), BitcoinClientError>;

    /// Builds a transaction spending `inputs` to `outputs` (address to amount) and signs it with the loaded wallet,
    /// without broadcasting it. `prevouts` describes inputs the wallet cannot find by itself, such as an output of an
    /// unconfirmed parent. Pass an empty slice when spending confirmed outputs.
    #[cfg(feature = "testing")]
    fn sign_spend(
        &self,
        inputs: &[bitcoin::OutPoint],
        outputs: &std::collections::HashMap<String, Amount>,
        prevouts: &[(bitcoin::OutPoint, bitcoin::TxOut)],
    ) -> Result<Transaction, BitcoinClientError>;
}

impl BitcoinClientApi for BitcoinClient {
    // ================================
    //  Chain
    // ================================

    fn get_tip_height(&self) -> Result<BlockHeight, BitcoinClientError> {
        let block_height = self.client.get_block_count()?;
        debug!("Best block height: {}", block_height);
        Ok(block_height as u32)
    }

    fn get_block_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<BlockInfo>, BitcoinClientError> {
        let block_hash = self.get_block_id_by_height(height)?;

        let block = self.get_block_by_hash(&block_hash)?;

        let block_info = BlockInfo {
            hash: block_hash,
            height: *height,
            prev_hash: block.header.prev_blockhash,
            txs: block.txdata.clone(),
        };
        debug!("Block at height {}: hash={}", height, block_hash);
        Ok(Some(block_info))
    }

    fn get_block_id_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<BlockHash, BitcoinClientError> {
        let block_hash = self.client.get_block_hash(u64::from(*height))?;
        debug!("Block hash at height {}: {}", height, block_hash);
        Ok(block_hash)
    }

    fn get_block_by_hash(&self, hash: &BlockHash) -> Result<Block, BitcoinClientError> {
        let block = self.client.get_block(hash)?;
        debug!("Block for hash {}: loaded", hash);
        Ok(block)
    }

    fn get_block_header_info(
        &self,
        hash: &BlockHash,
    ) -> Result<GetBlockHeaderVerbose, BitcoinClientError> {
        let header = self.client.get_block_header_info(hash)?;
        debug!(
            "Block header for hash {}: height={}, confirmations={}",
            hash, header.height, header.confirmations
        );
        Ok(header)
    }

    fn get_blockchain_info(&self) -> Result<GetBlockchainInfo, BitcoinClientError> {
        let blockchain_info = self.client.get_blockchain_info()?;
        debug!(
            "Blockchain info: height={}, chain={}",
            blockchain_info.blocks, blockchain_info.chain
        );
        Ok(blockchain_info)
    }

    fn is_txindex_enabled(&self) -> Result<bool, BitcoinClientError> {
        // getindexinfo returns {} when no indices are active, or a map containing a "txindex" entry
        // when -txindex is on.
        let info = self.client.get_index_info()?;
        Ok(info.get("txindex").is_some())
    }

    fn invalidate_block(&self, hash: &BlockHash) -> Result<(), BitcoinClientError> {
        let blockchain_info = self.get_blockchain_info()?;

        if blockchain_info.chain != Network::Regtest {
            return Err(BitcoinClientError::InvalidNetwork);
        }

        self.client.invalidate_block(hash).map_err(|e| {
            error!("Failed to invalidate block {}: {:?}", hash, e);
            BitcoinClientError::FailedToInvalidateBlock {
                error: e.to_string(),
            }
        })?;
        info!("Invalidated block: {}", hash);
        Ok(())
    }

    // ================================
    //  Transactions
    // ================================

    fn tx_exists(&self, tx_id: &Txid) -> bool {
        let tx = self.client.get_raw_transaction_info(tx_id);
        let exists = tx.is_ok();
        debug!("tx_exists({}): {}", tx_id, exists);
        exists
    }

    fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, BitcoinClientError> {
        let tx = self.client.get_raw_transaction(txid).ok();
        debug!("get_transaction({}) -> found: {}", txid, tx.is_some());
        Ok(tx)
    }

    fn get_raw_transaction_info(
        &self,
        tx_id: &Txid,
    ) -> Result<Option<GetRawTransactionVerbose>, BitcoinClientError> {
        match self.client.get_raw_transaction_info(tx_id) {
            Ok(tx) => {
                debug!("get_raw_transaction_info({}) -> found", tx_id);
                Ok(Some(tx))
            }
            Err(e) if e.is_not_found() => {
                debug!("get_raw_transaction_info({}) -> not found", tx_id);
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    fn get_raw_transaction_verbosity_two(
        &self,
        tx_id: &Txid,
    ) -> Result<serde_json::Value, BitcoinClientError> {
        // See https://bitcoincore.org/en/doc/25.0.0/rpc/rawtransactions/getrawtransaction/
        let tx = self.client.get_raw_transaction_verbosity_two(tx_id)?;
        debug!(
            "get_raw_transaction_verbosity_two({}) -> found: {}",
            tx_id,
            tx.get("txid")
                .is_some_and(|v| v.as_str() == Some(&tx_id.to_string()))
        );
        Ok(tx)
    }

    fn get_tx_confirmations(&self, tx_id: &Txid) -> Result<Option<u32>, BitcoinClientError> {
        // getrawtransaction returns RPC error -5 for an unknown txid. Only that answer means "not found", any other
        // error is returned so a node outage does not read as a dropped tx.
        match self.client.get_raw_transaction_info(tx_id) {
            // The node checks the mempool before the txindex, so a missing blockhash means the tx is in the mempool. A
            // blockhash with zero or missing confirmations is a block outside the active chain: the txindex keeps entries
            // of disconnected blocks, so the tx is in neither the mempool nor the chain.
            Ok(info) => match (info.block_hash, info.confirmations) {
                (Some(_), Some(confs)) if confs >= 1 => {
                    debug!("get_tx_confirmations({}) -> Some({})", tx_id, confs);
                    let confs: u32 =
                        u32::try_from(confs).map_err(crate::errors::invalid_response)?;
                    Ok(Some(confs))
                }
                (Some(block_hash), _) => {
                    debug!(
                        "get_tx_confirmations({}) -> None (block {} is not in the active chain)",
                        tx_id, block_hash
                    );
                    Ok(None)
                }
                (None, _) => {
                    debug!("get_tx_confirmations({}) -> Some(0)", tx_id);
                    Ok(Some(0))
                }
            },
            Err(e) if e.is_not_found() => {
                debug!("get_tx_confirmations({}) -> None (not found)", tx_id);
                Ok(None)
            }
            Err(e) => {
                error!("get_tx_confirmations({}) failed: {:?}", tx_id, e);
                Err(e)
            }
        }
    }

    fn get_tx_out(&self, txid: &Txid, vout: u32) -> Result<GetTxOut, BitcoinClientError> {
        let tx_out_result = self.client.get_tx_out(txid, vout, false)?;
        debug!(
            "get_tx_out({}, {}) -> found: {}",
            txid,
            vout,
            tx_out_result.is_some()
        );
        tx_out_result.ok_or(BitcoinClientError::FailedToGetTxOutput {
            error: "Tx output not found".to_string(),
        })
    }

    fn is_utxo_spent(
        &self,
        txid: &Txid,
        vout: u32,
        include_mempool: bool,
    ) -> Result<bool, BitcoinClientError> {
        let tx_out_result = self.client.get_tx_out(txid, vout, include_mempool)?;
        debug!(
            "is_utxo_spent({}, {}, include_mempool={}) -> {}",
            txid,
            vout,
            include_mempool,
            tx_out_result.is_none()
        );
        Ok(tx_out_result.is_none())
    }

    fn send_transaction(&self, tx: &Transaction) -> Result<Txid, BitcoinClientError> {
        let result = self.client.send_raw_transaction(tx);

        match &result {
            Ok(txid) => info!("TX sent: {} (txid: {})", tx.compute_txid(), txid),
            Err(e) => error!("Failed to send TX: {} - {:?}", tx.compute_txid(), e),
        }

        result.map_err(|e| BitcoinClientError::FailedToSendTransaction {
            error: e.to_string(),
        })
    }

    // ================================
    //  Mempool
    // ================================

    fn estimate_smart_fee(&self) -> Result<u64, BitcoinClientError> {
        const DEFAULT_FEE_RATE: u64 = 1; // 1 sat/vB

        let estimate_fee = self.client.estimate_smart_fee(1);

        match estimate_fee {
            Ok(estimate) => {
                match estimate.fee_rate {
                    Some(fee_rate) => {
                        // The node answers in BTC/kvB and corepc turns it into a typed FeeRate, rounded down here to
                        // whole sat/vB.
                        let fee_rate = fee_rate.to_sat_per_vb_floor();
                        debug!("Estimated smart fee: {} sat/vB", fee_rate);
                        Ok(fee_rate)
                    }
                    None => {
                        debug!(
                            "Estimated smart fee not available, using default: {} sat/vB",
                            DEFAULT_FEE_RATE
                        );
                        Ok(DEFAULT_FEE_RATE)
                    }
                }
            }
            Err(error) => {
                error!("Error estimating smart fee: {:?}", error);
                Err(error)
            }
        }
    }

    fn get_mempool_entry(
        &self,
        txid: &Txid,
    ) -> Result<Option<GetMempoolEntry>, BitcoinClientError> {
        match self.client.get_mempool_entry(txid) {
            Ok(entry) => {
                debug!("getmempoolentry({}) -> height: {}", txid, entry.0.height);
                Ok(Some(entry))
            }

            Err(e) if e.is_not_found() => {
                debug!("Transaction {} not in mempool", txid);
                Ok(None)
            }

            Err(e) => {
                error!("Error getmempoolentry for {}: {:?}", txid, e);
                Err(e)
            }
        }
    }

    fn get_raw_mempool(&self) -> Result<Vec<Txid>, BitcoinClientError> {
        let txids = self.client.get_raw_mempool().map_err(|e| {
            error!("Error get_raw_mempool: {:?}", e);
            e
        })?;

        debug!("Raw mempool size: {}", txids.len());
        Ok(txids)
    }

    fn check_in_mempool(&self, txid: &Txid) -> Result<bool, BitcoinClientError> {
        // Uses getmempoolentry, and falls back to getrawmempool when the RPC endpoint does not support that method.
        match self.get_mempool_entry(txid) {
            Ok(entry) => Ok(entry.is_some()),
            Err(e) => {
                let err_str = e.to_string();

                if err_str.contains("Unsupported method") || err_str.contains("-32600") {
                    warn!(
                    "RPC endpoint does not support getmempoolentry; falling back to getrawmempool"
                );
                    Ok(self.get_raw_mempool()?.contains(txid))
                } else {
                    error!("Failed to determine mempool status for {}: {:?}", txid, e);
                    Err(e)
                }
            }
        }
    }

    // ================================
    //  Wallet and mining
    // ================================

    fn fund_address(
        &self,
        address: &Address,
        amount: Amount,
    ) -> Result<(Transaction, u32), BitcoinClientError> {
        let blockchain_info = self.get_blockchain_info()?;

        if blockchain_info.chain != Network::Regtest {
            return Err(BitcoinClientError::InvalidNetwork);
        }

        let txid = self.client.send_to_address(address, amount).map_err(|e| {
            BitcoinClientError::FailedToFundAddress {
                error: e.to_string(),
            }
        })?;

        info!(
            "Funded address {:?} with {} sats (txid: {})",
            address,
            amount.to_sat(),
            txid
        );

        self.mine_blocks_to_address(1, address)?;

        let tx_info = self.client.get_transaction(&txid).map_err(|e| {
            BitcoinClientError::FailedToGetTransactionDetails {
                error: e.to_string(),
            }
        })?;

        let tx = tx_info.tx;

        let vout = tx_info
            .details
            .first()
            .ok_or(BitcoinClientError::FailedToGetTransactionDetails {
                error: "No transaction details found".to_string(),
            })?
            .vout;

        Ok((tx, vout))
    }

    fn mine_blocks(&self, block_num: u64) -> Result<(), BitcoinClientError> {
        // send to an empty address to avoid changing the balance of a wallet
        let address = Address::from_str("mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt")?
            .require_network(Network::Regtest)?;

        self.mine_blocks_to_address(block_num, &address)?;

        Ok(())
    }

    fn mine_blocks_to_address(
        &self,
        block_num: u64,
        address: &Address,
    ) -> Result<(), BitcoinClientError> {
        let before = self.client.get_block_count().unwrap_or(0);
        let blockchain_info = self.get_blockchain_info()?;

        if blockchain_info.chain != Network::Regtest {
            return Err(BitcoinClientError::InvalidNetwork);
        }

        self.client
            .generate_to_address(block_num, address)
            .map_err(|e| BitcoinClientError::FailedToMineBlocks {
                error: e.to_string(),
            })?;

        let after = self.client.get_block_count().unwrap_or(0);
        info!(
            "Mined {} blocks (height: {} -> {})",
            block_num, before, after
        );

        Ok(())
    }

    fn get_new_address(
        &self,
        pk: PublicKey,
        network: Network,
    ) -> Result<Address, BitcoinClientError> {
        let compressed = CompressedPublicKey::try_from(pk).map_err(|e| {
            BitcoinClientError::FailedToConvertPublicKey {
                error: e.to_string(),
            }
        })?;
        let address = Address::p2wpkh(&compressed, network).as_unchecked().clone();
        debug!("New address for network {:?}: {:?}", network, address);
        Ok(address.clone().require_network(network).unwrap())
    }

    fn init_wallet(&self, wallet_name: &str) -> Result<Address, BitcoinClientError> {
        let blockchain_info = self.get_blockchain_info()?;

        let wallets =
            self.client
                .list_wallets()
                .map_err(|e| BitcoinClientError::FailedToListWallets {
                    error: e.to_string(),
                })?;

        if !wallets.contains(&wallet_name.to_string()) {
            match self.client.create_wallet(wallet_name) {
                Ok(r) => {
                    info!("Created wallet: {}", wallet_name);
                    r
                }
                Err(e) => {
                    error!("Failed to create wallet {}: {:?}", wallet_name, e);
                    return Err(BitcoinClientError::FailedToCreateWallet {
                        error: e.to_string(),
                    });
                }
            };
        } else {
            info!("Wallet already exists: {}", wallet_name);
        }

        let address = self
            .client
            .get_new_address()
            .map_err(|e| BitcoinClientError::FailedToGetNewAddress {
                error: e.to_string(),
            })?
            .require_network(blockchain_info.chain)
            .map_err(|e| BitcoinClientError::FailedToGetNewAddress {
                error: e.to_string(),
            })?;

        info!("New address from wallet {}: {}", wallet_name, address);
        Ok(address)
    }

    fn create_wallet_only(&self, wallet_name: &str) -> Result<(), BitcoinClientError> {
        let wallets =
            self.client
                .list_wallets()
                .map_err(|e| BitcoinClientError::FailedToListWallets {
                    error: e.to_string(),
                })?;

        if !wallets.contains(&wallet_name.to_string()) {
            match self.client.create_wallet(wallet_name) {
                Ok(_) => {
                    info!("Created wallet: {}", wallet_name);
                }
                Err(e) => {
                    error!("Failed to create wallet {}: {:?}", wallet_name, e);
                    return Err(BitcoinClientError::FailedToCreateWallet {
                        error: e.to_string(),
                    });
                }
            };
        } else {
            info!("Wallet already exists: {}", wallet_name);
        }

        Ok(())
    }

    // ================================
    //  Testing
    // ================================

    #[cfg(feature = "testing")]
    fn get_block_count(&self) -> Result<u64, BitcoinClientError> {
        let count = self.client.get_block_count().map_err(|e| {
            error!("Error get_block_count: {:?}", e);
            e
        })?;
        debug!("Block count: {}", count);
        Ok(count)
    }

    #[cfg(feature = "testing")]
    fn get_balance(&self) -> Result<Amount, BitcoinClientError> {
        let balance = self.client.get_balance().map_err(|e| {
            error!("Error get_balance: {:?}", e);
            e
        })?;
        debug!("Wallet balance: {} BTC", balance.to_btc());
        Ok(balance)
    }

    #[cfg(feature = "testing")]
    fn list_wallets(&self) -> Result<Vec<String>, BitcoinClientError> {
        let wallets = self.client.list_wallets().map_err(|e| {
            error!("Error list_wallets: {:?}", e);
            e
        })?;
        debug!("Wallets: {:?}", wallets);
        Ok(wallets)
    }

    #[cfg(feature = "testing")]
    fn dump_privkey(&self, address: &Address) -> Result<String, BitcoinClientError> {
        let wif = self.client.dump_private_key(address).map_err(|e| {
            error!("Error dump_privkey: {:?}", e);
            e
        })?;
        debug!("Dump privkey for {:?}: {}", address, wif);
        Ok(wif.to_string())
    }

    #[cfg(feature = "testing")]
    fn mine_empty_block(&self, address: &Address) -> Result<BlockHash, BitcoinClientError> {
        self.generate_block_with_txs(address, &[])
    }

    #[cfg(feature = "testing")]
    fn generate_block_with_txs(
        &self,
        address: &Address,
        txs: &[Transaction],
    ) -> Result<BlockHash, BitcoinClientError> {
        let hash = self.client.generate_block(address, txs).map_err(|e| {
            BitcoinClientError::FailedToMineBlocks {
                error: e.to_string(),
            }
        })?;
        debug!("Generated block {} with {} tx(s)", hash, txs.len());
        Ok(hash)
    }

    #[cfg(feature = "testing")]
    fn set_mock_time(&self, timestamp: i64) -> Result<(), BitcoinClientError> {
        self.client.set_mock_time(timestamp)?;
        debug!("Set mock time to {}", timestamp);
        Ok(())
    }

    #[cfg(feature = "testing")]
    fn send_to_address(
        &self,
        address: &Address,
        amount: Amount,
    ) -> Result<Txid, BitcoinClientError> {
        let txid = self.client.send_to_address(address, amount)?;
        debug!("Sent {} to {} -> {}", amount, address, txid);
        Ok(txid)
    }

    #[cfg(feature = "testing")]
    fn reconsider_block(&self, hash: &BlockHash) -> Result<(), BitcoinClientError> {
        self.client.reconsider_block(hash)
    }

    #[cfg(feature = "testing")]
    fn lock_unspent(&self, outpoint: &bitcoin::OutPoint) -> Result<(), BitcoinClientError> {
        self.client
            .lock_unspent(false, std::slice::from_ref(outpoint))?;
        Ok(())
    }

    #[cfg(feature = "testing")]
    fn unlock_unspent_all(&self) -> Result<(), BitcoinClientError> {
        self.client.lock_unspent(true, &[])?;
        Ok(())
    }

    #[cfg(feature = "testing")]
    fn get_wallet_address(&self) -> Result<Address, BitcoinClientError> {
        let network = self.client.get_blockchain_info()?.chain;
        let address = self.client.get_new_address()?.require_network(network)?;
        Ok(address)
    }

    #[cfg(feature = "testing")]
    fn get_best_block_hash(&self) -> Result<BlockHash, BitcoinClientError> {
        self.client.get_best_block_hash()
    }

    #[cfg(feature = "testing")]
    fn prioritise_transaction(
        &self,
        txid: &Txid,
        fee_delta_sats: i64,
    ) -> Result<(), BitcoinClientError> {
        self.client.prioritise_transaction(txid, fee_delta_sats)?;
        Ok(())
    }

    #[cfg(feature = "testing")]
    fn sign_spend(
        &self,
        inputs: &[bitcoin::OutPoint],
        outputs: &std::collections::HashMap<String, Amount>,
        prevouts: &[(bitcoin::OutPoint, bitcoin::TxOut)],
    ) -> Result<Transaction, BitcoinClientError> {
        let unsigned = self.client.create_raw_transaction(inputs, outputs)?;
        let signed = self
            .client
            .sign_raw_transaction_with_wallet(&unsigned, prevouts)?;
        if !signed.complete {
            return Err(BitcoinClientError::FailedToSendTransaction {
                error: format!("signing incomplete: {:?}", signed.errors),
            });
        }
        Ok(signed.tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    /// A client on port 0, which never accepts connections, so every call to the node fails.
    fn offline_client() -> BitcoinClient {
        let empty = Secret::new(String::new());
        BitcoinClient::new(
            &Secret::new("http://127.0.0.1:0".to_string()),
            &empty,
            &empty,
        )
        .unwrap()
    }

    // A node that cannot be reached is an error, never a "not found" answer such as None or false. The exceptions are
    // tx_exists and get_transaction, whose contract is to answer false and None whenever the node cannot return the tx.
    #[test]
    fn unreachable_node_is_an_error() {
        let client = offline_client();
        let txid = Txid::from_str(&"11".repeat(32)).unwrap();
        let hash = BlockHash::from_str(&"22".repeat(32)).unwrap();
        let address = Address::from_str("mkHS9ne12qx9pS9VojpwU5xtRd4T7X7ZUt")
            .unwrap()
            .assume_checked();
        let outpoint = bitcoin::OutPoint::new(txid, 0);

        assert!(client
            .get_tx_confirmations(&txid)
            .unwrap_err()
            .is_node_unreachable());
        assert!(client.get_raw_transaction_info(&txid).is_err());
        assert!(client.get_mempool_entry(&txid).is_err());
        assert!(client.check_in_mempool(&txid).is_err());
        assert!(!client.tx_exists(&txid));
        assert!(client.get_transaction(&txid).unwrap().is_none());

        assert!(client.get_tip_height().is_err());
        assert!(client.get_block_by_height(&1).is_err());
        assert!(client.get_block_header_info(&hash).is_err());
        assert!(client.is_txindex_enabled().is_err());
        assert!(client.invalidate_block(&hash).is_err());
        assert!(client.get_raw_transaction_verbosity_two(&txid).is_err());
        assert!(client.get_tx_out(&txid, 0).is_err());
        assert!(client.is_utxo_spent(&txid, 0, true).is_err());
        assert!(matches!(
            client.send_transaction(&bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            }),
            Err(BitcoinClientError::FailedToSendTransaction { .. })
        ));
        assert!(client.estimate_smart_fee().is_err());
        assert!(client.get_raw_mempool().is_err());
        assert!(client.fund_address(&address, Amount::ONE_SAT).is_err());
        assert!(client.mine_blocks(1).is_err());
        assert!(client.init_wallet("test_wallet").is_err());
        assert!(matches!(
            client.create_wallet_only("test_wallet"),
            Err(BitcoinClientError::FailedToListWallets { .. })
        ));

        assert!(client.get_block_count().is_err());
        assert!(client.get_balance().is_err());
        assert!(client.list_wallets().is_err());
        assert!(client.dump_privkey(&address).is_err());
        assert!(client.mine_empty_block(&address).is_err());
        assert!(client.set_mock_time(0).is_err());
        assert!(client.send_to_address(&address, Amount::ONE_SAT).is_err());
        assert!(client.reconsider_block(&hash).is_err());
        assert!(client.lock_unspent(&outpoint).is_err());
        assert!(client.unlock_unspent_all().is_err());
        assert!(client.get_wallet_address().is_err());
        assert!(client.get_best_block_hash().is_err());
        assert!(client.prioritise_transaction(&txid, 1).is_err());
        assert!(client
            .sign_spend(&[outpoint], &Default::default(), &[])
            .is_err());
    }

    // A wallet name goes into the URL path, so only letters, digits, '_' and '-' are accepted. An empty name means no wallet.
    #[test]
    fn new_with_wallet_validates_the_name() {
        let url = Secret::new("http://127.0.0.1:0".to_string());
        let empty = Secret::new(String::new());
        assert!(BitcoinClient::new_with_wallet(&url, &empty, &empty, "test_wallet-1").is_ok());
        assert!(BitcoinClient::new_with_wallet(&url, &empty, &empty, "").is_ok());
        assert!(matches!(
            BitcoinClient::new_with_wallet(&url, &empty, &empty, "../other"),
            Err(BitcoinClientError::InvalidWalletName { .. })
        ));
    }

    // The address is the P2WPKH of the key, computed locally. P2WPKH needs a compressed key, so an uncompressed one fails.
    #[test]
    fn get_new_address_is_p2wpkh() {
        let secret = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let pk = PublicKey::new(secret.public_key(&Secp256k1::new()));
        let expected = Address::p2wpkh(
            &CompressedPublicKey::try_from(pk).unwrap(),
            Network::Regtest,
        );

        let client = offline_client();
        assert_eq!(
            client.get_new_address(pk, Network::Regtest).unwrap(),
            expected
        );
        assert!(matches!(
            client.get_new_address(PublicKey::new_uncompressed(pk.inner), Network::Regtest),
            Err(BitcoinClientError::FailedToConvertPublicKey { .. })
        ));
    }
}
