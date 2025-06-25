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

    fn init_wallet(
        &self,
        network: Network,
        wallet_name: &str,
    ) -> Result<Address, BitcoinClientError>;

    fn invalidate_block(&self, hash: &BlockHash) -> Result<(), BitcoinClientError>;

    fn estimate_smart_fee(&self) -> Result<u64, BitcoinClientError>;
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
                // Returns estimate fee rate in BTC/vkB
                match estimate.fee_rate {
                    Some(fee_rate) => {
                        return Ok(fee_rate.to_sat());
                    }
                    None => {
                        return Ok(DEFAULT_FEE_RATE);
                    }
                }
            }
            Err(error) => {
                // Handle the error returned by estimate_smart_fee
                return Err(BitcoinClientError::RpcError(error));
            }
        }
    }

    fn tx_exists(&self, tx_id: &Txid) -> bool {
        let tx = self.client.get_raw_transaction_info(tx_id, None);
        tx.is_ok()
    }

    fn get_raw_transaction_info(
        &self,
        tx_id: &Txid,
    ) -> Result<GetRawTransactionResult, BitcoinClientError> {
        let tx = self.client.get_raw_transaction_info(tx_id, None)?;
        Ok(tx)
    }

    fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResult, BitcoinClientError> {
        let blockchain_info = self.client.get_blockchain_info()?;
        Ok(blockchain_info)
    }

    fn get_best_block(&self) -> Result<BlockHeight, BitcoinClientError> {
        let block_height = self.client.get_block_count()?;
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
            txs: block.txdata,
        };

        Ok(Some(block_info))
    }

    fn get_block_id_by_height(
        &self,
        height: &BlockHeight,
    ) -> Result<BlockHash, BitcoinClientError> {
        let block_hash = self.client.get_block_hash(u64::from(*height))?;
        Ok(block_hash)
    }

    fn get_block_by_hash(&self, hash: &BlockHash) -> Result<Block, BitcoinClientError> {
        let block = self.client.get_by_id(hash)?;
        Ok(block)
    }

    fn get_tx_out(&self, txid: &Txid, vout: u32) -> Result<GetTxOutResult, BitcoinClientError> {
        let tx_out_result = self.client.get_tx_out(txid, vout, Some(false))?;
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

        // send BTC to address
        let txid = self
            .client
            .send_to_address(address, amount, None, None, None, None, None, None)
            .map_err(|e| BitcoinClientError::FailedToFundAddress {
                error: e.to_string(),
            })?;

        // mine a block to confirm transaction
        self.mine_blocks_to_address(1, address)?;

        // get transaction details
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

        if let Err(e) = result {
            println!("Error: {:?}", e);
            return Err(BitcoinClientError::FailedToSendTransaction {
                error: e.to_string(),
            });
        }

        let txid = result.unwrap();

        Ok(txid)
    }

    fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, BitcoinClientError> {
        let tx = self.client.get_raw_transaction(txid, None).ok();
        Ok(tx)
    }

    fn mine_blocks_to_address(
        &self,
        block_num: u64,
        address: &Address,
    ) -> Result<(), BitcoinClientError> {
        let blockchain_info = self.get_blockchain_info()?;

        if blockchain_info.chain != Network::Regtest {
            return Err(BitcoinClientError::InvalidNetwork);
        }

        self.client
            .generate_to_address(block_num, address)
            .map_err(|e| BitcoinClientError::FailedToMineBlocks {
                error: e.to_string(),
            })?;

        Ok(())
    }

    fn get_new_address(&self, pk: PublicKey, network: Network) -> Address {
        let compressed = CompressedPublicKey::try_from(pk).unwrap();
        let address = Address::p2wpkh(&compressed, network).as_unchecked().clone();
        address.clone().require_network(network).unwrap()
    }

    fn init_wallet(
        &self,
        network: Network,
        wallet_name: &str,
    ) -> Result<Address, BitcoinClientError> {
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
                Ok(r) => r,
                Err(e) => {
                    return Err(BitcoinClientError::FailedToCreateWallet {
                        error: e.to_string(),
                    })
                }
            };
        }

        let wallet = self
            .client
            .get_new_address(None, None)
            .map_err(|e| BitcoinClientError::FailedToGetNewAddress {
                error: e.to_string(),
            })?
            .require_network(network)
            .map_err(|e| BitcoinClientError::FailedToGetNewAddress {
                error: e.to_string(),
            })?;

        Ok(wallet)
    }

    fn invalidate_block(&self, hash: &BlockHash) -> Result<(), BitcoinClientError> {
        let blockchain_info = self.get_blockchain_info()?;

        if blockchain_info.chain != Network::Regtest {
            return Err(BitcoinClientError::InvalidNetwork);
        }

        self.client.invalidate_block(hash).map_err(|e| {
            BitcoinClientError::FailedToInvalidateBlock {
                error: e.to_string(),
            }
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    #[ignore]
    fn mine_blocks_to_address_test() {
        let bitcoin_client =
            BitcoinClient::new("http://127.0.0.1:18443", "foo", "rpcpassword").unwrap();

        let blocks = bitcoin_client.get_best_block().unwrap();
        println!("Blocks: {:?}", blocks);
        let wallet = bitcoin_client
            .init_wallet(Network::Regtest, "test_wallet")
            .unwrap();
        bitcoin_client.mine_blocks_to_address(1, &wallet).unwrap();

        let blocks = bitcoin_client.get_best_block().unwrap();
        println!("Blocks: {:?}", blocks);
    }
}
