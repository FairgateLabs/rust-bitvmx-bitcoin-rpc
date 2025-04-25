use bitcoin::hex::HexToArrayError;
use thiserror::Error;

use crate::reqwest_https;

#[derive(Error, Debug)]
pub enum BitcoinClientError {
    #[error("Invalid block height")]
    InvalidHeight,

    #[error("Error creating client {0}")]
    NewClientError(#[from] reqwest_https::Error),

    #[error("Rpc error {0}")]
    RpcError(#[from] bitcoincore_rpc::Error),

    #[error("Invalid block hash {0}")]
    InvalidBlockHash(#[from] HexToArrayError),

    #[error("Failed to fund address")]
    FailedToFundAddress { error: String },

    #[error("Failed to get transaction details")]
    FailedToGetTransactionDetails { error: String },

    #[error("Failed to get tx output")]
    FailedToGetTxOutput { error: String },

    #[error("Failed to send transaction")]
    FailedToSendTransaction { error: String },

    #[error("Failed to mine blocks")]
    FailedToMineBlocks { error: String },

    #[error("Failed to create wallet")]
    FailedToCreateWallet { error: String },

    #[error("Failed to list wallets")]
    FailedToListWallets { error: String },

    #[error("Failed to get new address")]
    FailedToGetNewAddress { error: String },

    #[error("Invalid network")]
    InvalidNetwork,

    #[error("Failed to load wallet")]
    FailedToLoadWallet { error: String },

    #[error("Failed to invalidate block")]
    FailedToInvalidateBlock { error: String },
}
