use thiserror::Error;

#[derive(Error, Debug)]
pub enum BitcoinClientError {
    #[error("Invalid block height")]
    InvalidHeight,

    #[error("Error creating client")]
    NewClientError(#[from] bitcoincore_rpc::Error),

    #[error("Error getting blockchain info")]
    ClientError(bitcoincore_rpc::Error),

    #[error("Failed to fund address")]
    FailedToFundAddress { error: String },

    #[error("Failed to get transaction details")]
    FailedToGetTransactionDetails { error: String },

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
}
