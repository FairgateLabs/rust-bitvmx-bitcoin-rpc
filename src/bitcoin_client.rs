use crate::errors::BitcoinClientError;
use crate::rpc_config::RpcConfig;
use crate::types::{BlockHeight, BlockInfo};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{
    Address, Amount, Block, BlockHash, CompressedPublicKey, Network, PublicKey, Transaction, Txid,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use mockall::automock;

#[derive(Debug)]
pub struct BitcoinClient {
    pub client: Client,
}

impl BitcoinClient {
    pub fn new(url: &str, user: &str, pass: &str) -> Result<Self, BitcoinClientError> {
        let auth = Auth::UserPass(user.to_owned(), pass.to_owned());
        let client = Client::new(url, auth).map_err(BitcoinClientError::NewClientError)?;

        Ok(Self { client })
    }

    pub fn new_from_config(config: &RpcConfig) -> Result<Self, BitcoinClientError> {
        Self::new(&config.url, &config.username, &config.password)
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

    fn get_blockchain_info(&self) -> Result<String, BitcoinClientError>;

    fn tx_exists(&self, tx_id: &Txid) -> bool;

    fn fund_address(
        &self,
        address: &Address,
        amount: Amount,
    ) -> Result<(Transaction, u32), BitcoinClientError>;

    fn send_transaction(&self, tx: Transaction) -> Result<Txid, BitcoinClientError>;

    fn get_transaction(&self, txid: &Txid) -> Result<Option<Transaction>, BitcoinClientError>;

    fn mine_blocks(&self, block_num: u64) -> Result<(), BitcoinClientError>;

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
}

#[automock]
impl BitcoinClientApi for BitcoinClient {
    fn tx_exists(&self, tx_id: &Txid) -> bool {
        let tx = self.client.get_raw_transaction_info(tx_id, None);
        tx.is_ok()
    }

    fn get_blockchain_info(&self) -> Result<String, BitcoinClientError> {
        let network = self.client.get_blockchain_info()?.chain;
        Ok(network.to_string().to_uppercase())
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
        let block_hash = self
            .client
            .get_block_hash(u64::from(*height))
            .map_err(BitcoinClientError::ClientError)?;
        Ok(block_hash)
    }

    fn get_block_by_hash(&self, hash: &BlockHash) -> Result<Block, BitcoinClientError> {
        let block = self
            .client
            .get_by_id(hash)
            .map_err(BitcoinClientError::ClientError)?;
        Ok(block)
    }

    fn fund_address(
        &self,
        address: &Address,
        amount: Amount,
    ) -> Result<(Transaction, u32), BitcoinClientError> {
        let network = self.get_blockchain_info()?;

        if network != "REGTEST" {
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

    fn send_transaction(&self, tx: Transaction) -> Result<Txid, BitcoinClientError> {
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

    fn mine_blocks(&self, block_num: u64) -> Result<(), BitcoinClientError> {
        let network = self.get_blockchain_info()?;

        if network != "REGTEST" {
            return Err(BitcoinClientError::InvalidNetwork);
        }

        self.client.generate(block_num, None).map_err(|e| {
            BitcoinClientError::FailedToMineBlocks {
                error: e.to_string(),
            }
        })?;

        Ok(())
    }

    fn mine_blocks_to_address(
        &self,
        block_num: u64,
        address: &Address,
    ) -> Result<(), BitcoinClientError> {
        let network = self.get_blockchain_info()?;

        if network != "REGTEST" {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;

    #[test]
    #[ignore]
    fn test_mine_blocks() {
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
