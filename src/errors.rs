use bitcoin::hex::HexToArrayError;
use thiserror::Error;

use crate::reqwest_https;

#[derive(Error, Debug)]
pub enum BitcoinClientError {
    #[error("Invalid block height")]
    InvalidHeight,

    #[error("Error parsing address {0}")]
    ParseAddressError(#[from] bitcoin::address::ParseError),

    #[error("Error creating client {0}")]
    NewClientError(#[from] reqwest_https::Error),

    #[error("Rpc error {0}")]
    RpcError(#[from] bitcoincore_rpc::Error),

    #[error("Invalid block hash {0}")]
    InvalidBlockHash(#[from] HexToArrayError),

    #[error("Failed to fund address {error}")]
    FailedToFundAddress { error: String },

    #[error("Failed to get transaction details {error} ")]
    FailedToGetTransactionDetails { error: String },

    #[error("Failed to get tx output {error}")]
    FailedToGetTxOutput { error: String },

    #[error("Failed to send transaction {error} ")]
    FailedToSendTransaction { error: String },

    #[error("Failed to mine blocks {error}")]
    FailedToMineBlocks { error: String },

    #[error("Failed to create wallet {error}")]
    FailedToCreateWallet { error: String },

    #[error("Failed to list wallets {error}")]
    FailedToListWallets { error: String },

    #[error("Failed to get new address {error}")]
    FailedToGetNewAddress { error: String },

    #[error("Invalid network")]
    InvalidNetwork,

    #[error("Failed to load wallet {error}")]
    FailedToLoadWallet { error: String },

    #[error("Failed to invalidate block {error}")]
    FailedToInvalidateBlock { error: String },
}
