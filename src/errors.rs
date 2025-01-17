use thiserror::Error;

#[derive(Error, Debug)]
pub enum BitcoinClientError {
    #[error("Invalid block height")]
    InvalidHeight,

    #[error("Error creating client")]
    NewClientError(#[from] bitcoincore_rpc::Error),

    #[error("Error getting blockchain info")]
    ClientError(bitcoincore_rpc::Error),
}
