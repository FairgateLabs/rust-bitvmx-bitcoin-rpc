use std::str::FromStr;

use crate::errors::BitcoinClientError;
use crate::rpc::Rpc;
use crate::rpc_config::RpcConfig;
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

    pub fn new_from_config(config: &RpcConfig) -> Result<Self, BitcoinClientError> {
        Self::new(&config.url, &config.username, &config.password)
    }

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
    fn get_tip_height(&self) -> Result<BlockHeight, BitcoinClientError>;

    fn get_block_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<BlockInfo>, BitcoinClientError>;

    fn get_block_id_by_height(&self, height: &BlockHeight)
        -> Result<BlockHash, BitcoinClientError>;

    fn get_block_by_hash(&self, hash: &BlockHash) -> Result<Block, BitcoinClientError>;

    /// Header of the block with this hash, via `getblockheader`: its height and confirmations among other fields,
    /// without downloading the block.
    fn get_block_header_info(
        &self,
        hash: &BlockHash,
    ) -> Result<GetBlockHeaderVerbose, BitcoinClientError>;

    fn get_blockchain_info(&self) -> Result<GetBlockchainInfo, BitcoinClientError>;

    fn tx_exists(&self, tx_id: &Txid) -> bool;

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

    fn fund_address(
        &self,
        address: &Address,
        amount: Amount,
    ) -> Result<(Transaction, u32), BitcoinClientError>;

    fn send_transaction(&self, tx: &Transaction) -> Result<Txid, BitcoinClientError>;

    fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, BitcoinClientError>;

    /// Verbose `getrawtransaction`. `None` when the node does not know the transaction. Any other failure is returned as an error.
    fn get_raw_transaction_info(
        &self,
        tx_id: &Txid,
    ) -> Result<Option<GetRawTransactionVerbose>, BitcoinClientError>;

    /// Live `getrawtransaction` confirmation probe (requires `-txindex`). Returns:
    /// - `None` => the tx is neither in the mempool nor in the active chain. This covers a tx the node does not
    ///   know, and a tx the txindex still finds in a block a reorg disconnected (stale `blockhash`),
    /// - `Some(0)` => in the mempool, unconfirmed,
    /// - `Some(n>=1)` => confirmed in the active chain with `n` confirmations.
    ///
    /// Any failure other than the node answering "not found" is returned as an error, so an unreachable node is never
    /// mistaken for a dropped tx.
    fn get_tx_confirmations(&self, tx_id: &Txid) -> Result<Option<u32>, BitcoinClientError>;

    /// True iff the node has the transaction index (`-txindex`) enabled, via `getindexinfo`.
    fn is_txindex_enabled(&self) -> Result<bool, BitcoinClientError>;

    fn get_raw_transaction_verbosity_two(
        &self,
        tx_id: &Txid,
    ) -> Result<serde_json::Value, BitcoinClientError>;

    fn mine_blocks(&self, block_num: u64) -> Result<(), BitcoinClientError>;

    fn mine_blocks_to_address(
        &self,
        block_num: u64,
        address: &Address,
    ) -> Result<(), BitcoinClientError>;

    fn get_new_address(
        &self,
        pk: PublicKey,
        network: Network,
    ) -> Result<Address, BitcoinClientError>;

    fn init_wallet(&self, wallet_name: &str) -> Result<Address, BitcoinClientError>;

    fn create_wallet_only(&self, wallet_name: &str) -> Result<(), BitcoinClientError>;

    fn invalidate_block(&self, hash: &BlockHash) -> Result<(), BitcoinClientError>;

    fn estimate_smart_fee(&self) -> Result<u64, BitcoinClientError>;

    fn get_mempool_entry(&self, txid: &Txid)
        -> Result<Option<GetMempoolEntry>, BitcoinClientError>;

    fn get_raw_mempool(&self) -> Result<Vec<Txid>, BitcoinClientError>;

    /// True if the transaction is in the mempool. Any failure other than "not in the mempool" is returned as an error.
    fn check_in_mempool(&self, txid: &Txid) -> Result<bool, BitcoinClientError>;

    #[cfg(feature = "testing")]
    fn get_block_count(&self) -> Result<u64, BitcoinClientError>;

    #[cfg(feature = "testing")]
    fn get_balance(&self) -> Result<Amount, BitcoinClientError>;

    #[cfg(feature = "testing")]
    fn list_wallets(&self) -> Result<Vec<String>, BitcoinClientError>;

    #[cfg(feature = "testing")]
    fn dump_privkey(&self, address: &Address) -> Result<String, BitcoinClientError>;

    /// Mine a single block to `address` containing no mempool transactions. Regtest/test only.
    #[cfg(feature = "testing")]
    fn mine_empty_block(&self, address: &Address) -> Result<BlockHash, BitcoinClientError>;

    /// Mine a block to `address` containing exactly `txs` plus the coinbase. Regtest/test only.
    #[cfg(feature = "testing")]
    fn generate_block_with_txs(
        &self,
        address: &Address,
        txs: &[Transaction],
    ) -> Result<BlockHash, BitcoinClientError>;

    /// Set the node's mock clock (`setmocktime`). Regtest/test only.
    #[cfg(feature = "testing")]
    fn set_mock_time(&self, timestamp: i64) -> Result<(), BitcoinClientError>;

    /// Send `amount` to `address` from the loaded wallet. Returns the txid.
    #[cfg(feature = "testing")]
    fn send_to_address(
        &self,
        address: &Address,
        amount: Amount,
    ) -> Result<Txid, BitcoinClientError>;
}

#[automock]
impl BitcoinClientApi for BitcoinClient {
    fn estimate_smart_fee(&self) -> Result<u64, BitcoinClientError> {
        const DEFAULT_FEE_RATE: u64 = 1; // 1 sat/vB

        let estimate_fee = self.client.estimate_smart_fee(1);

        match estimate_fee {
            Ok(estimate) => {
                match estimate.fee_rate {
                    Some(fee_rate) => {
                        // The node answers in BTC/kvB and corepc turns it into a typed FeeRate. Rounding down to
                        // whole sat/vB gives the same value as the previous (BTC_per_kvB * 100_000_000) / 1_000.
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

    fn tx_exists(&self, tx_id: &Txid) -> bool {
        let tx = self.client.get_raw_transaction_info(tx_id);
        let exists = tx.is_ok();
        debug!("tx_exists({}): {}", tx_id, exists);
        exists
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

    fn is_txindex_enabled(&self) -> Result<bool, BitcoinClientError> {
        // getindexinfo returns {} when no indices are active, or a map containing a "txindex" entry
        // when -txindex is on.
        let info = self.client.get_index_info()?;
        Ok(info.get("txindex").is_some())
    }

    fn get_raw_transaction_verbosity_two(
        &self,
        tx_id: &Txid,
    ) -> Result<serde_json::Value, BitcoinClientError> {
        // Requires Bitcoin Core 25.0.0 or higher.
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

    fn get_blockchain_info(&self) -> Result<GetBlockchainInfo, BitcoinClientError> {
        let blockchain_info = self.client.get_blockchain_info()?;
        debug!(
            "Blockchain info: height={}, chain={}",
            blockchain_info.blocks, blockchain_info.chain
        );
        Ok(blockchain_info)
    }

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

    fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, BitcoinClientError> {
        let tx = self.client.get_raw_transaction(txid).ok();
        debug!("get_transaction({}) -> found: {}", txid, tx.is_some());
        Ok(tx)
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

    /// Returns the mempool entry for `txid` if the transaction is currently in the node's mempool.
    ///
    /// Returns:
    /// - `Ok(Some(entry))` if the transaction is present in the mempool.
    /// - `Ok(None)` if the transaction is not present in the mempool.
    /// - `Err(...)` for transport, RPC, serialization, or other unexpected errors.
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

    /// Returns the list of transaction IDs currently in the node's mempool.
    fn get_raw_mempool(&self) -> Result<Vec<Txid>, BitcoinClientError> {
        let txids = self.client.get_raw_mempool().map_err(|e| {
            error!("Error get_raw_mempool: {:?}", e);
            e
        })?;

        debug!("Raw mempool size: {}", txids.len());
        Ok(txids)
    }

    /// Returns `true` if the transaction is currently in the mempool.
    ///
    /// Uses `getmempoolentry` as the primary mechanism. If the RPC endpoint does
    /// not support that method, falls back to checking membership via `getrawmempool`.
    fn check_in_mempool(&self, txid: &Txid) -> Result<bool, BitcoinClientError> {
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
}

/// Regtest helpers for the test suites of dependent crates.
#[cfg(feature = "testing")]
impl BitcoinClient {
    /// Undoes `invalidate_block`, letting the node consider the block for the active chain again.
    pub fn reconsider_block(&self, hash: &BlockHash) -> Result<(), BitcoinClientError> {
        self.client.reconsider_block(hash)
    }

    /// Locks a wallet output so the wallet does not spend it.
    pub fn lock_unspent(&self, outpoint: &bitcoin::OutPoint) -> Result<(), BitcoinClientError> {
        self.client
            .lock_unspent(false, std::slice::from_ref(outpoint))?;
        Ok(())
    }

    /// Unlocks every wallet output locked with `lock_unspent`.
    pub fn unlock_unspent_all(&self) -> Result<(), BitcoinClientError> {
        self.client.lock_unspent(true, &[])?;
        Ok(())
    }

    /// New address from the loaded wallet, checked against the node's network.
    pub fn get_wallet_address(&self) -> Result<Address, BitcoinClientError> {
        let network = self.client.get_blockchain_info()?.chain;
        let address = self.client.get_new_address()?.require_network(network)?;
        Ok(address)
    }

    pub fn get_best_block_hash(&self) -> Result<BlockHash, BitcoinClientError> {
        self.client.get_best_block_hash()
    }

    /// Raises the fee the node's mempool counts for `txid` by `fee_delta_sats`, without changing the transaction.
    pub fn prioritise_transaction(
        &self,
        txid: &Txid,
        fee_delta_sats: i64,
    ) -> Result<(), BitcoinClientError> {
        self.client.prioritise_transaction(txid, fee_delta_sats)?;
        Ok(())
    }

    /// Builds a transaction spending `inputs` to `outputs` (address to amount) and signs it with the loaded wallet,
    /// without broadcasting it. `prevouts` describes inputs the wallet cannot find by itself, such as an output of an
    /// unconfirmed parent. Pass an empty slice when spending confirmed outputs.
    pub fn sign_spend(
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

/// Masks potential secrets in URLs by replacing high-entropy strings with asterisks
fn mask_url_secrets(url: &str) -> String {
    let mut masked_url = url.to_string();

    // Split the URL into parts to avoid masking legitimate parts like hostnames
    let parts: Vec<&str> = url.split(&['/', '?', '&', '=', ':', '@'][..]).collect();

    for part in parts {
        // Check if this part looks like a secret (high entropy string)
        if is_potential_secret(part) {
            // Replace the secret with asterisks of the same length
            let asterisks = "*".repeat(part.len());
            masked_url = masked_url.replace(part, &asterisks);
        }
    }

    masked_url
}

/// Determines if a string might be a secret based on entropy characteristics
fn is_potential_secret(s: &str) -> bool {
    // Skip very short strings and common words
    if s.len() < 16 {
        return false;
    }

    // Skip common URL components
    if matches!(
        s.to_lowercase().as_str(),
        "http" | "https" | "localhost" | "127.0.0.1" | "wallet" | "bitcoin" | "rpc" | "api"
    ) {
        return false;
    }

    // Check for hexadecimal patterns (common in secrets/tokens)
    let hex_chars = s.chars().filter(|c| c.is_ascii_hexdigit()).count();
    let total_chars = s.len();

    // If more than 80% of characters are hex and string is long enough, likely a secret
    if hex_chars as f64 / total_chars as f64 > 0.8 && total_chars >= 16 {
        return true;
    }

    // Check for base64-like patterns (alphanumeric with some special chars)
    let alphanum_chars = s.chars().filter(|c| c.is_alphanumeric()).count();
    if alphanum_chars as f64 / total_chars as f64 > 0.9 && total_chars >= 20 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_url_secrets() {
        // Test URL with hex secret
        let url_with_secret = "http://user:7822107bcd2054574934586c276a46f0d3eca5e2@localhost:8332";
        let masked = mask_url_secrets(url_with_secret);
        assert!(masked.contains("****************************************"));
        assert!(!masked.contains("7822107bcd2054574934586c276a46f0d3eca5e2"));

        // Test normal URL without secrets
        let normal_url = "http://localhost:8332/wallet/test";
        let masked_normal = mask_url_secrets(normal_url);
        assert_eq!(masked_normal, normal_url);

        // Test URL with query parameter secret
        let url_with_query_secret =
            "http://localhost:8332?token=abc123def456789012345678901234567890abcd";
        let masked_query = mask_url_secrets(url_with_query_secret);
        assert!(!masked_query.contains("abc123def456789012345678901234567890abcd"));
        assert!(masked_query.contains("*"));
    }

    #[test]
    fn test_is_potential_secret() {
        // Test hex secret (like the example in the prompt)
        assert!(is_potential_secret(
            "7822107bcd2054574934586c276a46f0d3eca5e2"
        ));

        // Test base64-like secret
        assert!(is_potential_secret(
            "YWJjMTIzZGVmNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkw"
        ));

        // Test normal words/components
        assert!(!is_potential_secret("localhost"));
        assert!(!is_potential_secret("bitcoin"));
        assert!(!is_potential_secret("wallet"));
        assert!(!is_potential_secret("8332"));
        assert!(!is_potential_secret("test"));

        // Test short strings
        assert!(!is_potential_secret("abc123"));
    }

    // Only the node's "not found" answer is not found. Any other RPC error, or a failure to reach the node, is not.
    #[test]
    fn test_is_not_found() {
        let rpc_error = |code| {
            BitcoinClientError::RpcError(jsonrpc::Error::Rpc(jsonrpc::error::RpcError {
                code,
                message: "error".to_string(),
                data: None,
            }))
        };

        assert!(rpc_error(-5).is_not_found());
        // Invalid parameter, and the node still warming up.
        assert!(!rpc_error(-8).is_not_found());
        assert!(!rpc_error(-28).is_not_found());

        let unreachable = BitcoinClientError::RpcError(jsonrpc::Error::Transport(Box::new(
            std::io::Error::other("connection refused"),
        )));
        assert!(!unreachable.is_not_found());
    }

    // Only a failure to reach the node counts as unreachable. A node that answers with an error is reachable.
    #[test]
    fn test_is_node_unreachable() {
        let unreachable = BitcoinClientError::RpcError(jsonrpc::Error::Transport(Box::new(
            std::io::Error::other("connection refused"),
        )));
        assert!(unreachable.is_node_unreachable());

        let rejected =
            BitcoinClientError::RpcError(jsonrpc::Error::Rpc(jsonrpc::error::RpcError {
                code: -8,
                message: "rejected".to_string(),
                data: None,
            }));
        assert!(!rejected.is_node_unreachable());
    }

    // A node that cannot be reached is an error, not a tx the node does not know.
    #[test]
    fn test_get_tx_confirmations_unreachable_node() {
        // Bind to a free port and release it, so nothing is listening there and the connection is refused.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let bitcoin_client = BitcoinClient::new(
            &Secret::new(format!("http://127.0.0.1:{port}")),
            &Secret::new("foo".to_string()),
            &Secret::new("rpcpassword".to_string()),
        )
        .unwrap();

        let tx_id = Txid::from_str(&"11".repeat(32)).unwrap();
        let result = bitcoin_client.get_tx_confirmations(&tx_id);
        assert!(
            matches!(result, Err(BitcoinClientError::RpcError(_))),
            "expected an RPC error, got {result:?}"
        );
    }

    #[test]
    #[ignore]
    fn mine_blocks_to_address_test() {
        let bitcoin_client = BitcoinClient::new(
            &Secret::new("http://127.0.0.1:18443".to_string()),
            &Secret::new("foo".to_string()),
            &Secret::new("rpcpassword".to_string()),
        )
        .unwrap();

        let blocks = bitcoin_client.get_tip_height().unwrap();
        println!("Blocks: {:?}", blocks);
        let wallet = bitcoin_client.init_wallet("test_wallet").unwrap();
        bitcoin_client.mine_blocks_to_address(1, &wallet).unwrap();

        let blocks = bitcoin_client.get_tip_height().unwrap();
        println!("Blocks: {:?}", blocks);
    }

    #[test]
    #[ignore]
    fn test_init_wallet() -> Result<(), BitcoinClientError> {
        let bitcoin_client = BitcoinClient::new(
            &Secret::new("http://127.0.0.1:18443".to_string()),
            &Secret::new("foo".to_string()),
            &Secret::new("rpcpassword".to_string()),
        )
        .unwrap();

        // Use a unique wallet name to avoid collisions
        let wallet_name = format!("test_wallet");

        // Attempt to initialize the wallet
        let result_address = bitcoin_client.init_wallet(&wallet_name);

        println!("Result address: {:?}", result_address);
        assert!(result_address.is_ok());
        let address = result_address.unwrap();
        println!("Address: {:?}", address);

        // Attempt to initialize the wallet
        let result_address_2 = bitcoin_client.init_wallet(&wallet_name);

        assert!(result_address_2.is_ok());
        let address_2 = result_address_2.unwrap();
        assert_ne!(address, address_2);
        println!("Address 2: {:?}", address_2);

        // Init wallet with different name
        let result_address_3 = bitcoin_client.init_wallet(&format!("test_wallet_2"));

        println!("Result address 3: {:?}", result_address_3);
        assert!(result_address_3.is_ok());
        let address_3 = result_address_3.unwrap();
        println!("Address 3: {:?}", address_3);

        // Init wallet with different name
        let result_address_3 = bitcoin_client.init_wallet(&format!("test_wallet_2"));

        println!("Result address 3: {:?}", result_address_3);
        assert!(result_address_3.is_ok());
        let address_3 = result_address_3.unwrap();
        println!("Address 3: {:?}", address_3);

        // Init wallet with different name
        let result_address_3 = bitcoin_client.init_wallet(&format!("test_wallet_2"));

        println!("Result address 3: {:?}", result_address_3);
        assert!(result_address_3.is_ok());
        let address_3 = result_address_3.unwrap();
        println!("Address 3: {:?}", address_3);

        Ok(())
    }
}
