use crate::errors::BitcoinClientError;
use crate::reqwest_https::ReqwestHttpsTransport;
use crate::rpc_config::RpcConfig;
use crate::types::{BlockHeight, BlockInfo};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{
    Address, Amount, Block, BlockHash, CompressedPublicKey, Network, PublicKey, Transaction, Txid,
};
use bitcoincore_rpc::json::{EstimateMode, GetBlockchainInfoResult};
use bitcoincore_rpc::json::{GetRawTransactionResult, GetTxOutResult};
use bitcoincore_rpc::{jsonrpc, Client, RpcApi};
use mockall::automock;

#[derive(Debug)]
pub struct BitcoinClient {
    pub client: Client,
}

impl BitcoinClient {
    pub fn new(url: &str, user: &str, pass: &str) -> Result<Self, BitcoinClientError> {
        let pass = match pass.is_empty() {
            true => None,
            false => Some(pass.to_owned()),
        };

        let transport = if user != "" {
            ReqwestHttpsTransport::builder()
                .url(url)?
                .basic_auth(user.to_owned(), pass)
                .build()
        } else {
            ReqwestHttpsTransport::builder().url(url)?.build()
        };

        let from_jsonrpc = jsonrpc::client::Client::with_transport(transport);
        let client = Client::from_jsonrpc(from_jsonrpc);

        println!("[BitcoinClient] Initialized for url: {}", url);

        Ok(Self { client })
    }

    pub fn new_from_config(config: &RpcConfig) -> Result<Self, BitcoinClientError> {
        Self::new(&config.url, &config.username, &config.password)
    }

    pub fn new_with_wallet(
        url: &str,
        user: &str,
        pass: &str,
        wallet_name: &str,
    ) -> Result<Self, BitcoinClientError> {
        let url = if !wallet_name.is_empty() {
            format!("{}/wallet/{}", url.to_string(), wallet_name)
        } else {
            url.to_string()
        };

        Self::new(&url, &user, &pass)
    }
}

#[automock]
pub trait BitcoinClientApi {
    fn get_best_block(&self) -> Result<BlockHeight, BitcoinClientError>;

    fn get_block_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<Option<BlockInfo>, BitcoinClientError>;

    fn get_block_id_by_height(&self, height: &BlockHeight)
        -> Result<BlockHash, BitcoinClientError>;

    fn get_block_by_hash(&self, hash: &BlockHash) -> Result<Block, BitcoinClientError>;

    fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResult, BitcoinClientError>;

    fn tx_exists(&self, tx_id: &Txid) -> bool;

    fn get_tx_out(&self, txid: &Txid, vout: u32) -> Result<GetTxOutResult, BitcoinClientError>;

    fn fund_address(
        &self,
        address: &Address,
        amount: Amount,
    ) -> Result<(Transaction, u32), BitcoinClientError>;

    fn send_transaction(&self, tx: &Transaction) -> Result<Txid, BitcoinClientError>;

    fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, BitcoinClientError>;

    fn get_raw_transaction_info(
        &self,
        tx_id: &Txid,
    ) -> Result<GetRawTransactionResult, BitcoinClientError>;

    fn mine_blocks_to_address(
        &self,
        block_num: u64,
        address: &Address,
    ) -> Result<(), BitcoinClientError>;

    fn get_new_address(&self, pk: PublicKey, network: Network) -> Address;

    fn init_wallet(&self, wallet_name: &str) -> Result<Address, BitcoinClientError>;

    fn invalidate_block(&self, hash: &BlockHash) -> Result<(), BitcoinClientError>;

    fn estimate_smart_fee(&self) -> Result<u64, BitcoinClientError>;

    fn get_raw_mempool(&self) -> Result<Vec<Txid>, BitcoinClientError>;

    fn get_block_count(&self) -> Result<u64, BitcoinClientError>;

    fn get_balance(&self) -> Result<Amount, BitcoinClientError>;

    fn list_wallets(&self) -> Result<Vec<String>, BitcoinClientError>;

    fn dump_privkey(&self, address: &Address) -> Result<String, BitcoinClientError>;
}

#[automock]
impl BitcoinClientApi for BitcoinClient {
    fn estimate_smart_fee(&self) -> Result<u64, BitcoinClientError> {
        const DEFAULT_FEE_RATE: u64 = 1; // 1 sat/vB

        let estimate_fee = self
            .client
            .estimate_smart_fee(1, Some(EstimateMode::Conservative));

        match estimate_fee {
            Ok(estimate) => {
                match estimate.fee_rate {
                    Some(fee_rate) => {
                        let fee_rate = (fee_rate.to_sat() / 1_000) as u64;
                        println!("[BitcoinClient] Estimated smart fee: {} sat/vB", fee_rate);
                        return Ok(fee_rate);
                    }
                    None => {
                        println!("[BitcoinClient] Estimated smart fee not available, using default: {} sat/vB", DEFAULT_FEE_RATE);
                        return Ok(DEFAULT_FEE_RATE);
                    }
                }
            }
            Err(error) => {
                println!("[BitcoinClient] Error estimating smart fee: {:?}", error);
                return Err(BitcoinClientError::RpcError(error));
            }
        }
    }

    fn tx_exists(&self, tx_id: &Txid) -> bool {
        let tx = self.client.get_raw_transaction_info(tx_id, None);
        let exists = tx.is_ok();
        println!("[BitcoinClient] tx_exists({}): {}", tx_id, exists);
        exists
    }

    fn get_raw_transaction_info(
        &self,
        tx_id: &Txid,
    ) -> Result<GetRawTransactionResult, BitcoinClientError> {
        let tx = self.client.get_raw_transaction_info(tx_id, None)?;
        println!("[BitcoinClient] get_raw_transaction_info({}) -> found: {}", tx_id, tx.txid == *tx_id);
        Ok(tx)
    }

    fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResult, BitcoinClientError> {
        let blockchain_info = self.client.get_blockchain_info()?;
        println!("[BitcoinClient] Blockchain info: height={}, chain={}", blockchain_info.blocks, blockchain_info.chain);
        Ok(blockchain_info)
    }

    fn get_best_block(&self) -> Result<BlockHeight, BitcoinClientError> {
        let block_height = self.client.get_block_count()?;
        println!("[BitcoinClient] Best block height: {}", block_height);
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
        println!("[BitcoinClient] Block at height {}: hash={}", height, block_hash);
        Ok(Some(block_info))
    }

    fn get_block_id_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<BlockHash, BitcoinClientError> {
        let block_hash = self.client.get_block_hash(u64::from(*height))?;
        println!("[BitcoinClient] Block hash at height {}: {}", height, block_hash);
        Ok(block_hash)
    }

    fn get_block_by_hash(&self, hash: &BlockHash) -> Result<Block, BitcoinClientError> {
        let block = self.client.get_by_id(hash)?;
        println!("[BitcoinClient] Block for hash {}: loaded", hash);
        Ok(block)
    }

    fn get_tx_out(&self, txid: &Txid, vout: u32) -> Result<GetTxOutResult, BitcoinClientError> {
        let tx_out_result = self.client.get_tx_out(txid, vout, Some(false))?;
        println!("[BitcoinClient] get_tx_out({}, {}) -> found: {}", txid, vout, tx_out_result.is_some());
        tx_out_result.ok_or(BitcoinClientError::FailedToGetTxOutput {
            error: "Tx output not found".to_string(),
        })
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

        let txid = self
            .client
            .send_to_address(address, amount, None, None, None, None, None, None)
            .map_err(|e| BitcoinClientError::FailedToFundAddress {
                error: e.to_string(),
            })?;

        println!("[BitcoinClient] Funded address {:?} with {} sats (txid: {})", address, amount.to_sat(), txid);

        self.mine_blocks_to_address(1, address)?;

        let tx_info = self
            .client
            .get_transaction(&txid, Some(true))
            .map_err(|e| BitcoinClientError::FailedToGetTransactionDetails {
                error: e.to_string(),
            })?;

        let tx = tx_info.transaction().map_err(|e| {
            BitcoinClientError::FailedToGetTransactionDetails {
                error: e.to_string(),
            }
        })?;

        let vout = tx_info
            .details
            .first()
            .expect("No details found for transaction")
            .vout;

        Ok((tx, vout))
    }

    fn send_transaction(&self, tx: &Transaction) -> Result<Txid, BitcoinClientError> {
        let serialized_tx = serialize_hex(&tx);

        let result = self.client.send_raw_transaction(serialized_tx);

        match &result {
            Ok(txid) => println!("[BitcoinClient] TX sent: {} (txid: {})", tx.txid(), txid),
            Err(e) => println!("[BitcoinClient] Failed to send TX: {} - {:?}", tx.txid(), e),
        }

        result.map_err(|e| BitcoinClientError::FailedToSendTransaction {
            error: e.to_string(),
        })
    }

    fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, BitcoinClientError> {
        let tx = self.client.get_raw_transaction(txid, None).ok();
        println!("[BitcoinClient] get_transaction({}) -> found: {}", txid, tx.is_some());
        Ok(tx)
    }

    fn mine_blocks_to_address(
        &self,
        block_num: u64,
        address: &Address,
    ) -> Result<(), BitcoinClientError> {
        let before = self.get_block_count().unwrap_or(0);
        let blockchain_info = self.get_blockchain_info()?;

        if blockchain_info.chain != Network::Regtest {
            return Err(BitcoinClientError::InvalidNetwork);
        }

        self.client
            .generate_to_address(block_num, address)
            .map_err(|e| BitcoinClientError::FailedToMineBlocks {
                error: e.to_string(),
            })?;

        let after = self.get_block_count().unwrap_or(0);
        println!("[BitcoinClient] Mined {} blocks (height: {} -> {})", block_num, before, after);

        Ok(())
    }

    fn get_new_address(&self, pk: PublicKey, network: Network) -> Address {
        let compressed = CompressedPublicKey::try_from(pk).unwrap();
        let address = Address::p2wpkh(&compressed, network).as_unchecked().clone();
        println!("[BitcoinClient] New address for network {:?}: {:?}", network, address);
        address.clone().require_network(network).unwrap()
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
            match self
                .client
                .create_wallet(wallet_name, None, None, None, None)
            {
                Ok(r) => {
                    println!("[BitcoinClient] Created wallet: {}", wallet_name);
                    r
                }
                Err(e) => {
                    println!("[BitcoinClient] Failed to create wallet {}: {:?}", wallet_name, e);
                    return Err(BitcoinClientError::FailedToCreateWallet {
                        error: e.to_string(),
                    })
                }
            };
        } else {
            println!("[BitcoinClient] Wallet already exists: {}", wallet_name);
        }

        let address = self
            .client
            .get_new_address(None, None)
            .map_err(|e| BitcoinClientError::FailedToGetNewAddress {
                error: e.to_string(),
            })?
            .require_network(blockchain_info.chain)
            .map_err(|e| BitcoinClientError::FailedToGetNewAddress {
                error: e.to_string(),
            })?;

        println!("[BitcoinClient] New address from wallet {}: {}", wallet_name, address);
        Ok(address)
    }

    fn invalidate_block(&self, hash: &BlockHash) -> Result<(), BitcoinClientError> {
        let blockchain_info = self.get_blockchain_info()?;

        if blockchain_info.chain != Network::Regtest {
            return Err(BitcoinClientError::InvalidNetwork);
        }

        self.client.invalidate_block(hash).map_err(|e| {
            println!("[BitcoinClient] Failed to invalidate block {}: {:?}", hash, e);
            BitcoinClientError::FailedToInvalidateBlock {
                error: e.to_string(),
            }
        })?;
        println!("[BitcoinClient] Invalidated block: {}", hash);
        Ok(())
    }

    fn get_raw_mempool(&self) -> Result<Vec<Txid>, BitcoinClientError> {
        let txids = self.client.get_raw_mempool()
            .map_err(|e| {
                println!("[BitcoinClient] Error get_raw_mempool: {:?}", e);
                BitcoinClientError::RpcError(e)
            })?;
        println!("[BitcoinClient] Raw mempool: {:?}", txids);
        Ok(txids)
    }

    fn get_block_count(&self) -> Result<u64, BitcoinClientError> {
        let count = self.client.get_block_count()
            .map_err(|e| {
                println!("[BitcoinClient] Error get_block_count: {:?}", e);
                BitcoinClientError::RpcError(e)
            })?;
        println!("[BitcoinClient] Block count: {}", count);
        Ok(count)
    }

    fn get_balance(&self) -> Result<Amount, BitcoinClientError> {
        let balance = self.client.get_balance(None, None)
            .map_err(|e| {
                println!("[BitcoinClient] Error get_balance: {:?}", e);
                BitcoinClientError::RpcError(e)
            })?;
        println!("[BitcoinClient] Wallet balance: {} BTC", balance.to_btc());
        Ok(balance)
    }

    fn list_wallets(&self) -> Result<Vec<String>, BitcoinClientError> {
        let wallets = self.client.list_wallets()
            .map_err(|e| {
                println!("[BitcoinClient] Error list_wallets: {:?}", e);
                BitcoinClientError::RpcError(e)
            })?;
        println!("[BitcoinClient] Wallets: {:?}", wallets);
        Ok(wallets)
    }

    fn dump_privkey(&self, address: &Address) -> Result<String, BitcoinClientError> {
        let wif = self.client.dump_private_key(address)
            .map_err(|e| {
                println!("[BitcoinClient] Error dump_privkey: {:?}", e);
                BitcoinClientError::RpcError(e)
            })?;
        println!("[BitcoinClient] Dump privkey for {:?}: {}", address, wif);
        Ok(wif.to_string())
    }
}